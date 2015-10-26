/*
so we will inject this DLL into a process and it will takeover all threads...
it will listen on a tcp/ip connection for queues for API calls from these threads..
this is intended to be called directly after PIDDump.. it will allow the emulator to
function properly without writing new functions for all of the win32 API


*/
#include <windows.h>
#include "tlhelp32.h"
#include "../crc.h"

CRITICAL_SECTION CS_ThreadData;
char *comm_process(char *pkt, int size, int *ret_size) ;

typedef struct _thread_data {
	struct _thread_data *next;

	CRITICAL_SECTION CS;

	long inqueue;
	long outqueue;

	HANDLE hThread;
	DWORD_PTR ThreadID;

	char *input_buf;
	int input_size;
	char *output_buf;
	int output_size;

	long count;

} ThreadData;


ThreadData *thread_data_list = NULL;

int ListenLoop();


int ThreadInsert(DWORD_PTR ID, HANDLE hThread) {
	ThreadData *dptr = (ThreadData *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ThreadData));
	if (dptr != NULL) {
		InitializeCriticalSection(&dptr->CS);

		dptr->hThread = hThread;
		dptr->ThreadID = ID;

		EnterCriticalSection(&CS_ThreadData);
		dptr->next = dptr;
		thread_data_list = dptr;
		LeaveCriticalSection(&CS_ThreadData);
	}

	return -1;
}

ThreadData *ThreadFind(DWORD_PTR ID) {
	EnterCriticalSection(&CS_ThreadData);
	ThreadData *dptr = thread_data_list, *ret = NULL;

	while (dptr != NULL) {
		if (dptr->ThreadID == ID) {
			ret = dptr;
			break;
		}
	}

	LeaveCriticalSection(&CS_ThreadData);

	return ret;
}





/*
thread queue needs to handle proxied API calls and then return the information & loop
*/
int ThreadLoop(void *param) {
	HANDLE hThread = GetCurrentThread();

	ThreadInsert(GetCurrentThreadId(), GetCurrentThread());
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




int RedirectAndProxyThread(HANDLE hThread) {
	HMODULE kern = LoadLibrary("kernel32");
	DWORD_PTR _exitaddr = (DWORD_PTR)GetProcAddress(kern, "ExitThread");

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);


	ctx.Esp -= 4;
	DWORD_PTR *_param = (DWORD_PTR *)(ctx.Esp);
	// we arent using param right now so set to 0
	*_param = 0;

	// put address of exitthread as return address... (if the func ever returns.. it shouldnt)
	ctx.Esp -= 4;
	DWORD_PTR *_retaddr = (DWORD_PTR *)(ctx.Esp);
	*_retaddr = _exitaddr;
	
	// make EIP the start of our threadloop function...
	ctx.Eip = (DWORD_PTR)&ThreadLoop;

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
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
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
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 
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

					RedirectAndProxyThread(hThread);
					
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
	
	
	WSADATA wsaData;
	
	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
		ExitProcess(0);
    }
	
	if (ListenLoop() == -1)
		ExitProcess(0);
	


	PauseThreads(0, 0);
	EnumerateTreadsAndHijack();
	PauseThreads(0, 1);
	
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