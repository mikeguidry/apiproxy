/*
so we will inject this DLL into a process and it will takeover all threads...
it will listen on a tcp/ip connection for queues for API calls from these threads..
this is intended to be called directly after PIDDump.. it will allow the emulator to
function properly without writing new functions for all of the win32 API


*/
#include <windows.h>
#include <Winternl.h>
#include "tlhelp32.h"
#include <stdio.h>
#include "gerente.h"
#include "../client/client_structures.h"
#include "../client/customheap.h"
#include "../crc.h"
#include "../structures.h"


#define OUR_SIZE 1024*1024*100

// some procs we have to declare..
char *comm_process(char *pkt, int size, int *ret_size) ;
int ListenLoop();

// global variables
CRITICAL_SECTION CS_ThreadData;
DWORD_PTR tlsDataIndex = 0;
ThreadData *thread_data_list = NULL;
ClientThreadInfo *cinfo = NULL;

typedef struct _our_regions {
	struct _our_regions *next;
	DWORD_PTR Address;
	DWORD_PTR Size;
} OurRegions;

OurRegions *ourregions = NULL;

// lets allocate 100 megabytes at a time
DWORD_PTR OurNew() {
	DWORD_PTR Address = (DWORD_PTR)VirtualAlloc(0, OUR_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!Address) return NULL;

	OurRegions *optr = (OurRegions *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OurRegions));
	if (optr == NULL) {
		__asm int 3
		ExitProcess(0);
	}
	optr->Address = Address;
	optr->Size = OUR_SIZE;

	optr->next = ourregions;
	ourregions = optr;

	return Address;
}


// our allocators so we can drop in replace in IAT
BOOL __stdcall myHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
	return CustomHeapFree(cinfo, (DWORD_PTR)lpMem);
}
LPVOID __stdcall myHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
	return CustomHeapAlloc(cinfo,dwBytes);
}

CustomHeapArea *CustomArea_init(ClientThreadInfo *tinfo, DWORD_PTR RangeStart, DWORD_PTR Size) {
	
	CustomHeapArea *aptr = (CustomHeapArea *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CustomHeapArea));
	if (aptr == NULL) {
		__asm int 3
			ExitProcess(0);
	}
	
	
	aptr->next = (CustomHeapArea *)tinfo->memory_areas;
	tinfo->memory_areas = (void *)aptr;
	
	//LeaveCriticalSection(&tinfo->CSmemory);
	
	return aptr;
}




// separate our memory for usage within the application
void SetupMemory(ClientThreadInfo *tinfo, DWORD_PTR RangeStart, DWORD_PTR Size) {

	CustomHeapArea *aptr = CustomArea_init(tinfo, RangeStart, Size);
	// setup base for all memory..
	if (aptr == NULL) {
		__asm int 3
		ExitProcess(0);
	}

	// set stack to start 32kb under the high part of the memory.. no real reason..for the 32kb
	tinfo->StackHigh = (RangeStart + Size) - (1024 * 32);
	// lets give it 5 megabytes.. we should split this up later for multiple threads.. maybe separate heap/stack
	tinfo->StackLow = tinfo->StackHigh - (1024 * 1024 * 5);

	// lets spray stack with the BP just in case something leaks or fails ..we can see how/why (maybe)
	//DWORD_PTR StackEndBP = (DWORD_PTR)&break_stack_end;
/*	DWORD_PTR *Set = (DWORD_PTR *)tinfo->StackHigh;
	while ((DWORD_PTR)Set > (DWORD_PTR)tinfo->StackLow) {
		*Set = StackEndBP;
	}
*/
	// now for heap...
	aptr->HeapMax = tinfo->StackLow - (1024 * 32);
	aptr->HeapBase = RangeStart;
	// new!
	aptr->HeapLast = 0;

	ShadowRegion *rptr = (ShadowRegion *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ShadowRegion));
	if (rptr != NULL) {
		rptr->address = RangeStart;
		rptr->size = Size;
		rptr->verify = 1;
		tinfo->ShadowMem = rptr;

		rptr->next = tinfo->ShadowList;
		tinfo->ShadowList = rptr;
	}
	else {
		__asm int 3
		ExitProcess(0);
	}

	//LeaveCriticalSection(&tinfo->CSmemory);
}



// adds a thread into linked list
ThreadData *ThreadInsert(DWORD_PTR ID, HANDLE hThread) {
	ThreadData *dptr = (ThreadData *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ThreadData));
	if (dptr != NULL) {
		InitializeCriticalSection(&dptr->CS);

		dptr->hThread = hThread;
		dptr->ThreadID = ID;

		EnterCriticalSection(&CS_ThreadData);
		dptr->next = thread_data_list;
		thread_data_list = dptr;
		LeaveCriticalSection(&CS_ThreadData);
	}

	return dptr;
}



// finds a thread in the linked list
ThreadData *ThreadFind(DWORD_PTR ID) {
	ThreadData *dptr = NULL, *ret = NULL;

	// first check if it exists in TLS...
	DWORD_PTR tlsData = (DWORD_PTR)TlsGetValue(tlsDataIndex);
	if (GetLastError() == NO_ERROR)
		dptr = (ThreadData *)tlsData;

	// if it wasnt in TLS... lets loop and find it..
	if (dptr == NULL) {
		dptr = thread_data_list;
		EnterCriticalSection(&CS_ThreadData);

		while (dptr != NULL) {
			if (dptr->ThreadID == ID) {
				ret = dptr;
				break;
			}
			dptr = dptr->next;
		}

		LeaveCriticalSection(&CS_ThreadData);
	}

	return ret;
}





/*
thread queue needs to handle proxied API calls and then return the information & loop

  *** FIX.. Move this to Mutex so theres no sleeping/waiting (for speed)...
	  or completed multithread/multiplex / change to zeromq/nanomsg
*/
int ThreadLoop(void *param) {
	HANDLE hThread = GetCurrentThread();

	
	ThreadData *dptr = ThreadFind(GetCurrentThreadId());

	if (!dptr) {
		// find some way to report the error?
		OutputDebugString("BAD no thread data pointer");
		__asm int 3
	}

	while (1) {
		if (!InterlockedExchangeAdd(&dptr->inqueue, 0)) {
			Sleep(50);

			continue;
		}

		EnterCriticalSection(&dptr->CS);

		dptr->output_buf = comm_process(dptr->input_buf, dptr->input_size, &dptr->output_size);
		
		InterlockedExchange(&dptr->inqueue, 0);
		InterlockedIncrement(&dptr->outqueue);
		LeaveCriticalSection(&dptr->CS);
		
	}

	ExitThread(0);
	return 0;
}

// Sets a threads TLS Value
int SetThreadTlsValue(HANDLE hThread, CONTEXT *ctx, DWORD_PTR Index, DWORD_PTR Value) {
	LDT_ENTRY ldtSel;

	if (!GetThreadSelectorEntry(hThread, ctx->SegFs, &ldtSel)) {
		return 0;
	}

	// this isn't FS BASE.. its TIB base!
	DWORD_PTR TIB = (ldtSel.HighWord.Bits.BaseHi << 24 ) | ( ldtSel.HighWord.Bits.BaseMid << 16 ) | ( ldtSel.BaseLow );

	// find TEB from TIB...
	DWORD_PTR TEBAddr = (DWORD_PTR)*(DWORD_PTR *)((DWORD_PTR)TIB + (DWORD_PTR)0x18);
	
	// now we have to get the TLS value...
	// implement checking if its in expansion slot later..
	PTEB teb = (PTEB)TEBAddr;

	// Set Value in TLS Slot Index on hThread
	teb->TlsSlots[Index] = (void *)Value;


	return 1;
}

void PushStack(DWORD_PTR **_ESP, DWORD_PTR Value) {
	DWORD *ESP = *_ESP;
	ESP -= sizeof(DWORD_PTR);
	*ESP = Value;
	*_ESP = ESP;
}

int RedirectAndProxyThread(HANDLE hThread, DWORD_PTR ThreadID) {
	HMODULE kern = LoadLibrary("kernel32");
	DWORD_PTR _exitaddr = (DWORD_PTR)GetProcAddress(kern, "ExitThread");
	//DWORD_PTR ThreadID = GetThreadId(hThread);

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);

	
	// create a thread data structure for keeping information regarding this thread...
	ThreadData *dptr = ThreadInsert(ThreadID, hThread);

	// set that information inside of the other threads TLS...
	// (i dont know why we are doing this since we already did a linked list. but we can remove the linked list now
	// and use TLS and itll be quicker without the EnterCriticalSection,etc... but not sure if speed matters for this,
	// however for converting normal apps to HPC.. it will)
	SetThreadTlsValue(hThread, &ctx, tlsDataIndex, (DWORD_PTR)dptr);


	// keep original thread information for later..
	CopyMemory(&dptr->OriginalCtx, &ctx, sizeof(CONTEXT));

	// now we must create a new location for our 'new' stack for this thread
	// this 'new' stack will have exitthread as the parent... and itll call our loop
	// otherwise its blank and frabricated...
	// we wont bother the old stack since we may need it to unload, and want the memory
	// as close as posible to the original when the emulator proceeds to continue using
	// the snapshot
	DWORD_PTR StackSize = 1024*1024;
	DWORD_PTR StackLow = (DWORD_PTR)VirtualAlloc(0, StackSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (StackLow == NULL) {
		printf("Couldnt allocate memory for a new stack!");
		exit(-1);
	}

	// calculate high of the stack (really the 'low' or initial starting point)
	DWORD_PTR StackHigh = (StackLow + StackSize);

	// get that stack area ready for use in ESP
	DWORD_PTR *ESP = (DWORD_PTR *)StackHigh;

	// put exitthread at top (even though it should never reach.. its proper)
	PushStack(&ESP, _exitaddr);
	
	// put the parameter (its not used yet, but the structure information for the thread)
	PushStack(&ESP, (DWORD_PTR)dptr);

	// now put the return address
	PushStack(&ESP, _exitaddr);

	// make EIP the start of our threadloop function...
	ctx.Eip = (DWORD_PTR)&ThreadLoop;

	// replace the original stack with our new stack region..
	// this means we wont corrupt the original stack in any way whatsoever...
	// we are setting EBP because we dont really have a frame setup.. its irrelevant
	ctx.Esp = ctx.Ebp = (DWORD_PTR)ESP;

	// push the changes to the thread...
	SetThreadContext(hThread, &ctx);

	return 1;
}



// pause all threads in the current process loading this DLL except the current
BOOL PauseThreads(unsigned long pid, bool bResumeThread) {
    HANDLE        hThreadSnap = NULL; 
    BOOL          bRet        = FALSE; 
    THREADENTRY32 te32        = {0}; 
	DWORD CurrentProcID = GetCurrentProcessId();
	DWORD CurrentThreadID = GetCurrentThreadId();
	
	if (pid == 0) pid = CurrentProcID;
	
    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32); 
	// Take a snapshot of all threads currently in the system. 
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid); 
    // Walk the thread snapshot to find all threads of the process. 
    // If the thread belongs to the process, add its information 
    // to the display list.
    if (Thread32First(hThreadSnap, &te32)) { 
        do { 
            if (te32.th32OwnerProcessID == pid)  {
				if (te32.th32ThreadID != CurrentThreadID) {
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
					if (bResumeThread) {
						ResumeThread(hThread);
					} else {
						SuspendThread(hThread);
					}
					CloseHandle(hThread);
				}
            } 
        } while (Thread32Next(hThreadSnap, &te32)); 
        bRet = TRUE; 
    } 
    else 
        bRet = FALSE;          // could not walk the list of threads 
	
    // Do not forget to clean up the snapshot object. 
    CloseHandle (hThreadSnap); 
	
    return (bRet); 
} 


int EnumerateTreadsAndHijack() {
	HANDLE        hThreadSnap = NULL; 
	BOOL          bRet        = FALSE; 
	THREADENTRY32 te32        = {0}; 
	DWORD_PTR pid = 0;
	DWORD CurrentProcID = GetCurrentProcessId();
	DWORD CurrentThreadID = GetCurrentThreadId();
	
	if (pid == 0) pid = CurrentProcID;
	
	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32); 
	// Take a snapshot of all threads currently in the system. 
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid); 
	// Walk the thread snapshot to find all threads of the process. 
	// If the thread belongs to the process, add its information 
	// to the display list.
	if (Thread32First(hThreadSnap, &te32)) { 
		do { 
			if (te32.th32OwnerProcessID == pid)  {
				if (te32.th32ThreadID != CurrentThreadID) {
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);


					// we were able to open the thread all access.. now hijack and redirect so we can proxy
					// using the original function calls for the functions being fuzzed...
					// they should be saved & simulated for distribution & future fuzzing

					RedirectAndProxyThread(hThread, te32.th32ThreadID);
					
					CloseHandle(hThread);
				}
			} 
		} while (Thread32Next(hThreadSnap, &te32)); 
		bRet = TRUE; 
	} 
	else 
		bRet = FALSE;          // could not walk the list of threads 
	
	// Do not forget to clean up the snapshot object. 
	CloseHandle (hThreadSnap); 
	
	return (bRet); 
}


/*
this will initialize the DLL injected thread redirection by pausing all threads..
and then redirecting each into a specific loop that will check for queued jobs.
it will perform each job given for each thread...
this allows us to use the same exact threads the emulator loads the fuzzing instructions for
 */



int Thread_InitProxy(void *param) {

	chksum_crc32gentab();
	
	InitializeCriticalSection(&CS_ThreadData);

	// our 'client' structure used this.. so we have to allocate so we can keep the same code base
	// *** FIX when this gets merged together due to us having to hook all API for simulation
	// protocol logs... figure out another way
	cinfo = (ClientThreadInfo *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ClientThreadInfo));
	if (cinfo == NULL) {
		ExitProcess(0);
	}

	DWORD_PTR RangeStart = OurNew();
	if (!RangeStart) {
		ExitProcess(0);
	}
	SetupMemory(cinfo, RangeStart, OUR_SIZE);
	
	
	WSADATA wsaData;
	
	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
		ExitProcess(0);
    }
	
	// get a TLS index where we will have saved information for each hijacked (emulation proxy) thread
	tlsDataIndex = TlsAlloc();


	// pause all threads
	PauseThreads(0, 0);

	// hijack the threads
	EnumerateTreadsAndHijack();
	
	// resume the threads *** FIX (figure out why we have to do this twice)
	PauseThreads(0, 1);
	PauseThreads(0, 1);

	// listen on TCP/IP port for proxied Win32 API and direct to the particular thread necessary
	if (ListenLoop() == -1)
		ExitProcess(0);

	ExitThread(0);
}




BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
		case DLL_PROCESS_ATTACH:
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) Thread_InitProxy, (void *)NULL, 0, NULL);

			break;
	}
	return true;
}