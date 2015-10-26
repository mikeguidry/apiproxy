/*

*** we need a total rewrite after we are done prototyping.... maybe client side in C++..
server side can be very very basic in C or ASM.. maybe extra checking/etc for fuzzer but not backdoor


psykoosi local client...

to test the system we will load a module into memory using a DLL and then proxy all of its API remotely (in this case locally to start) and have it execute on another system...

  * goals: create a reverse client as well that runs the current software on a remote (linux) box and then sends API only locally, or to another machine
    this should cover all scenarios for fuzzing, and possibly HPC.. to offload tasks like SQL servers.. and allow even threads to be on diff systems/cores/etc on a remote machine

  also create an exe version that can start a suspended process, and/or inject into a stub and then open the process, inject communications, and redirect IAT using
  whatever configuration

  add hooking to hook GetProcAddress (dynamically loaded API..)
  since we are starting with IAT
  add better erreor checking around API calls.. 1 failure destroys the app
*/
#include <windows.h>
#include <shlwapi.h>
#include "memorymodule.h"
#include <winsock.h>

#include "../file.h"
#include "../structures.h"
#include "../commands.h"
#include "hooking.h"
#include "x86_emulate.h"
#include "../memverify.h"
#include "../crc.h"
#include "client_structures.h"

#include "customheap.h"

#include "remote_commands.h"


#pragma comment(lib, "shlwapi.lib")



HANDLE hProcess = NULL;

DWORD tlsThreadID = 0;


ClientThreadInfo *MainThread = NULL;
ClientThreadInfo *ThreadList = NULL;


ClientThreadInfo *TrickFindThread() {
	ClientThreadInfo *tptr = (ClientThreadInfo *)TlsGetValue(tlsThreadID);
	return tptr;
}


int FindFunctionParamSize(FARPROC FuncAddr);



/*
Our current trick for execution is to shadow the memory (stack, heap, etc) across both processes....
this needs to be replaced with perfectly calculated and pushed memory using the emulator later :)
this is safe & quick for now and should cover some issues if the emulator doesnt recognize for some odd reason
(possibly kernel, etc)
*/



// how much space do we believe our entire app will take (heap/stack/data/etc simul)
#define REGION_SIZE 1024 * 1024 * 16


// our allocators so we can drop in replace in IAT
BOOL __stdcall myHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
	return CustomHeapFree(MainThread, (DWORD_PTR)lpMem);
}
LPVOID __stdcall myHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
	return CustomHeapAlloc(MainThread,dwBytes);
}

LPVOID __stdcall myVirtualAlloc(LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect) {
	return CustomHeapAlloc(MainThread,dwSize);
}

BOOL __stdcall myVirtualFree(LPVOID lpAddress,SIZE_T dwSize,DWORD dwFreeType) {
	return CustomHeapFree(MainThread,(DWORD_PTR)lpAddress);
}


BOOL __stdcall myVirtualProtect(LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect) {
	return 1;
}


ClientThreadInfo *Thread_New() {
	ClientThreadInfo *cptr = (ClientThreadInfo *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ClientThreadInfo));
	if (cptr == NULL) {
		__asm int 3
		ExitProcess(0);
	}

	

	return cptr;
}



CONTEXT ctxBefore;
// we want these in global so its not affected by ESP/EBP (itll be in global data section)
DWORD_PTR backup_ebp = 0, backup_esp = 0;


__declspec(naked) void break_stack_end() {
	__asm {
		int 3
		int 3
		int 3
		int 3
	}
}

// prepare stack with our custom shadow areas....
// hack for now.. but we should start a new thread and setup the new thread to use the shadow... and let it exit quietly
// this needs to setup the stack.. and call a function (maybe the module's entry point..) and have it return right back, to get fixed and move on
int TrickStackExec(ClientThreadInfo *tinfo,void *code, void *func) {
	int ret = 0;
	
	//CONTEXT ctxAfter;
	
	TlsSetValue(tlsThreadID, (void *)tinfo);

	// trick to do int3 if it messes up for now...
	DWORD_PTR *_StackHigh = (DWORD_PTR *)tinfo->StackHigh;
	DWORD_PTR StackEndBP = (DWORD_PTR)&break_stack_end;
	*_StackHigh-- = StackEndBP;
	*_StackHigh-- = StackEndBP;
	*_StackHigh-- = StackEndBP;
	*_StackHigh-- = StackEndBP;
	//DWORD_PTR *A = (DWORD_PTR *)(StackHigh - sizeof(DWORD_PTR));
	//*A-- = StackHigh; *A-- = StackHigh; *A-- = StackHigh; *A-- = StackHigh;

	DWORD_PTR StartStack = (DWORD_PTR)((DWORD_PTR)tinfo->StackHigh - (sizeof(DWORD_PTR) * 4));
	RtlCaptureContext(&ctxBefore);
	__asm {
		//int 3
		mov ebx, code
		mov ecx, func

		mov backup_ebp, ebp
		mov backup_esp, esp

		mov esp, StartStack;
		mov ebp, StartStack;

		//int 3
		push 0
		push 1
		push ebx

		call ecx

		mov ret, eax

		add esp, 12

		mov ebp, backup_ebp
		mov esp, backup_esp

		//int 3

	}
	//RtlCaptureContext(&ctxAfter);
	/*__asm {
		mov esp, ctxBefore.Esp;
		mov ebp, ctxBefore.Ebp;
	}*/
	return ret;
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
	DWORD_PTR StackEndBP = (DWORD_PTR)&break_stack_end;
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


int shadow_add(ClientThreadInfo *tinfo, DWORD_PTR Start, DWORD_PTR Size, int verify) {
	ShadowRegion *rptr = (ShadowRegion *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ShadowRegion));
	if (rptr == NULL) return 0;
	rptr->address = Start;
	rptr->size = Size;
	rptr->verify = verify;

	rptr->next = tinfo->ShadowList;
	tinfo->ShadowList = rptr;
	return 1;
}


CRITICAL_SECTION CS_redirect;
Redirect *redirect_list = NULL;
long first_redirect = 0;

int proxy_sock = 0;

// we want to have a global flag to enable/disable redirecting.. this will be useful for backdoors, or other utilities
// that need to completely disable redirecting after loading a foreign file/etc
// then to be able to write locally...
// move to TLS later for each thread
long redirect_enabled = 0;

// we use gettib to get the high and low of the stack region for the current thread..
// this is used to go backwards until we find the return addresses ebp.. this allows us to calcualte how much stack
// is required to pass as arguments..
// for now we wont use.. we will universally go with 64 bytes (for any DLL exported function it is more than enough)
void *getTib()
{
    void *pTib = 0;

	__asm {
		mov eax, fs:[0x18]
		mov pTib, eax
	}

    return pTib;
}

// addr in stack is good for detecting the size (to lower the amount from 64 bytes once we need more speed)
int AddrInStack(DWORD_PTR addr) {
	// check to determine if this address is in the heap or not
	unsigned char *_teb = (unsigned char *)getTib();

	DWORD_PTR ThreadStackBase = (DWORD_PTR)(*(DWORD_PTR *)((unsigned char *)_teb + 4));
	DWORD_PTR ThreadStackHigh = (DWORD_PTR)(*(DWORD_PTR *)((unsigned char *)_teb + 8));

	if ((addr >= ThreadStackBase) && (addr < ThreadStackHigh)) return 1;

	return 0;
}


// finds a function's redirect (so we have the real name, and library)
Redirect *redirect_search(DWORD_PTR func) {
	Redirect *ret = NULL;


	char ebuf[1024];
	//wsprintf(ebuf, "searhc %p\r\n", func);
	//OutputDebugString(ebuf);
	EnterCriticalSection(&CS_redirect);

	Redirect *rptr = redirect_list;
	while (rptr != NULL) {
		if (rptr->addr == func) {
			//wsprintf(ebuf, "found %p", rptr->addr);
			//OutputDebugString(ebuf);

			ret = rptr;
			break;
		}
		rptr = rptr->next;
	}

	LeaveCriticalSection(&CS_redirect);

	return ret;
}


// add a function to the linked list so we can find its module name and function name for passing on to the remote end
// this should be hashed and cached for each remote connection later so it saves space
Redirect *redirect_add(DWORD_PTR func, char *module_name, char *function_name) {
	Redirect *rptr = NULL;

	// first ensure we arent duplicating.. (maybe such as GetProcAddress/IAT)
	if ((rptr = redirect_search(func)) != NULL) {
		return rptr;
	}

	// alloc memory for the structure
	if ((rptr = (Redirect *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Redirect))) == NULL)
		return NULL;

	rptr->addr = func;
	rptr->function = StrDup(function_name);
	rptr->module = StrDup(module_name);
	/*rptr->cleanup = FindFunctionParamSize((FARPROC)func);
	char ebuf[1024];
	wsprintf(ebuf, "redirect %s [%s] -> %p [%d]\r\n", rptr->function, rptr->module, rptr->addr, rptr->cleanup);
	OutputDebugString(ebuf);
*/
	
	if (rptr->function && rptr->module) {
		// add to linked list
		EnterCriticalSection(&CS_redirect);
		rptr->next = redirect_list;
		redirect_list = rptr;
		LeaveCriticalSection(&CS_redirect);
	}

	return rptr;
}

//Parameters *param_list = NULL, *param_last = NULL;

// we should send over stack usnig relative addresses.. so if we copy 64 bytes of the stack and some addresses are relative.. itll fix that on the other side
// using the real stack addresses


/*
// insert param into list
void param_insert(Parameters *pptr) {
	if (param_last == NULL) {
		param_last = param_list = pptr;
	} else {
		param_last->next = pptr;
	}
}

// count parameters in list
int count_param() {
	Parameters *pptr = NULL;
	int parameters_count = 0;

	for (pptr = param_list; pptr != NULL; pptr = pptr->next)
		parameters_count++;

	return parameters_count;
}

// free the parameter list
void free_param() {
	Parameters *pptr = NULL, *pptr2 = NULL;

	for (pptr = param_list; pptr != NULL; ) {

		if (pptr->heap_data != NULL)
			HeapFree(GetProcessHeap(), 0, pptr->heap_data);

		HeapFree(GetProcessHeap(), 0, pptr);

		pptr2 = pptr->next;
	}

}
// add a parameter from stack
// only supports string arguments now.. add unicode & other data from the emulator's read logs! (use as a DLL so it stays out of this)
int add_param(DWORD_PTR addr) {
	Parameters *pptr = NULL;
	int parameters_count = count_param();

	if ((pptr = (Parameters *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,sizeof(Parameters))) == NULL) {
		__asm int 3
		ExitProcess(0);
	}
	pptr->location = parameters_count;


		pptr->parameter = addr;
		pptr->size = 4;

	param_insert(pptr);

	return 0;
}


*/


int remote_handle(DWORD_PTR func,DWORD_PTR *stack_ptr, DWORD_PTR orig_esp, DWORD_PTR orig_ebp, DWORD_PTR *ret_fix) {
	int ret = 0;
	Redirect *rptr = NULL;
	char *buf = NULL;
	ExecPkt *pkt = NULL;
	int i = 0;
	Parameters *pptr = NULL;
	char ebuf[1024];
	ShadowRegion *sptr = NULL;
	ClientThreadInfo *tinfo = TrickFindThread();
	RtlCaptureContext(&tinfo->ctx);

	DWORD_PTR *_orig_ebp = (DWORD_PTR *)orig_ebp;
	DWORD_PTR orig_local_size = *_orig_ebp - orig_ebp;

	
	if ((orig_ebp > tinfo->StackHigh) || (*_orig_ebp > tinfo->StackHigh) || (orig_local_size < 0)) {
		orig_local_size = 0;
	}

	//if (orig_local_size == 4676) orig_local_size = 1024;


	

	wsprintf(ebuf, "func %p stack_ptr %p orig_ebp %p orig_esp %p ret_fix %p orig local size %d", func, stack_ptr, orig_ebp, orig_esp, ret_fix, orig_local_size);
	OutputDebugString(ebuf);
	// calculate space for caller local stack..
	
	
	// we dont know if this space is zero.. so lets fix
	*ret_fix = 0;

	if ((rptr = redirect_search(func)) == NULL) {
		__asm int 3
		return 0;
	}
	/*
	for (sptr = ShadowList; sptr != NULL; sptr = sptr->next) {
		wsprintf(ebuf, "range %p %d\r\n", sptr->address, sptr->size);
		OutputDebugString(ebuf);
		//PushRegion(sptr->address, sptr->size);
	}
	*/


#ifdef SYNC_ALWAYS
	for (sptr = tinfo->ShadowList; sptr != NULL; sptr = sptr->next) {
		//wsprintf(ebuf, "push %p %d\r\n", sptr->address, sptr->size);
		//OutputDebugString(ebuf);
		if (!sptr->pushed || !sptr->LastSync) {
			PushRegion(sptr);
		} else {
			// if we already pushed once.. we should only push the difference since our last call
				(sptr->LastSync, NULL, 1);
		}
	}
#else
	for (sptr = tinfo->ShadowList; sptr != NULL; sptr = sptr->next) {
		//wsprintf(ebuf, "push %p %d\r\n", sptr->address, sptr->size);
		//OutputDebugString(ebuf);
		
		PushRegion(sptr);
	}
#endif

	PushData(orig_ebp, orig_local_size);

	int func_len = lstrlen(rptr->function) + 1;
	int mod_len = lstrlen(rptr->module) + 1;
	int arg_size = 64;

	if ((buf = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(CallInfo) + arg_size + mod_len + func_len + 1)) != NULL) {

		ZmqHdr *hdr = (ZmqHdr *)(buf);
		hdr->len = sizeof(CallInfo) + sizeof(ZmqPkt) + arg_size + mod_len + func_len;
	

		ZmqPkt *zpkt = (ZmqPkt *)(buf + sizeof(ZmqHdr));
		zpkt->cmd = CALL_FUNC;
		zpkt->len = sizeof(CallInfo) + arg_size + mod_len + func_len + sizeof(ZmqPkt);
		zpkt->thread_id = 0;

		CallInfo *cinfo = (CallInfo *)(buf + sizeof(ZmqHdr) + sizeof(ZmqPkt));

		//cinfo->addr = 0;
		cinfo->func_len = func_len;
		cinfo->module_len = mod_len;
		cinfo->arg_len = arg_size;
		cinfo->ESP = tinfo->ctx.Esp;
		cinfo->EBP = tinfo->ctx.Ebp;
		cinfo->Region = tinfo->ShadowMem->address;
		cinfo->Region_Size = tinfo->ShadowMem->size;

		wsprintf(ebuf, "remote_call %s param: region %p region size %d\r\n", rptr->function, cinfo->Region, cinfo->Region_Size);
		OutputDebugString(ebuf);

		// copy information to newly allocated pkt.. behind it.. stack args, module, and func
		char *ptr = (char *)((char *)buf + sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(CallInfo));
		CopyMemory(ptr, rptr->module, mod_len);
		ptr += mod_len;
		CopyMemory(ptr, rptr->function, func_len);
		ptr += func_len;
		//__asm int 3
		CopyMemory(ptr, stack_ptr, arg_size);
		ptr += arg_size;


		// calculate total packet size..
		int plen = hdr->len + sizeof(ZmqHdr);// +sizeof(ZmqPkt) + sizeof(CallInfo);
		//OutputDebugString("sending pkt\r\n");

		// send to the proxy socket..
		if (send(proxy_sock,(const char *) buf, plen, 0) != plen) {
			__asm int 3
		}

		int max_ret_size = sizeof(ZmqRet) + (sizeof(DWORD_PTR) * 2);
		max_ret_size +=	sizeof(DWORD_PTR) * 2 * ((cinfo->Region_Size / sizeof(unsigned int)) + 1);

		// allocate space to get the return packet.. (fix these sizes later.. read the DWORD of the size, allocate, and then read it back.. or keep this for a small system)
		char *remoteret = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, max_ret_size * 2 + 1);
		if (remoteret == NULL) {
			__asm int 3
		}

		// receive the packet
		int rlen = 0;
		if ((rlen = recv(proxy_sock, remoteret, sizeof(ZmqRet), 0)) < sizeof(ZmqRet)) {
			__asm int 3
		}


		// check to get its return (eax) / etc
		ZmqRet *rpkt = (ZmqRet *)remoteret;
		if (rpkt->extra_len < (sizeof(DWORD_PTR) * 2)) {
			__asm int 3
		}

		int pktsize = 0;
		while (pktsize < rpkt->extra_len && (pktsize + (sizeof(DWORD_PTR)*2)) < max_ret_size) {
			rlen = recv(proxy_sock, remoteret + sizeof(ZmqRet) + pktsize,  rpkt->extra_len - pktsize, 0);
			if (rlen <= 0) {
				return 0;
				__asm int 3
				ExitProcess(0);
			}

			pktsize += rlen;
		}


		//wsprintf(ebuf, "pkt recv size %d [max %d]\r\n", pktsize, max_ret_size);
		//OutputDebugString(ebuf);
		DWORD_PTR *rval = (DWORD_PTR *)(remoteret + sizeof(ZmqRet));
		DWORD_PTR *rfix = (DWORD_PTR *)(remoteret + sizeof(ZmqRet) + sizeof(DWORD_PTR));
		
		// lets send back the return (from eax)
		ret = *rval;
		*ret_fix = *rfix;

		wsprintf(ebuf, "remote_exec return func %s ret %p ret_fix %d\r\n", rptr->function, ret, *ret_fix);
		OutputDebugString(ebuf);

		// now lets process any modified memory...

		DWORD_PTR MemoryModCount = (rpkt->extra_len - (sizeof(DWORD_PTR)*2)) / (sizeof(DWORD_PTR) + REGION_BLOCK);

		wsprintf(ebuf, "MemorymodCount %d\r\n", MemoryModCount);
		OutputDebugString(ebuf);

		
		char *memptr = (char *)((char *)remoteret + sizeof(ZmqRet) + (sizeof(DWORD_PTR)*2));

		for (int j = 0; j < MemoryModCount; j++) {
			DWORD_PTR *rAddr = (DWORD_PTR *)memptr;
			memptr += sizeof(DWORD_PTR);
			DWORD_PTR *rData = (DWORD_PTR *)memptr;
			memptr += REGION_BLOCK;

			// local address is direct (since we're shadowing..)
			DWORD_PTR *lAddr = (DWORD_PTR *)*rAddr;

			//wsprintf(ebuf, "laddr %p\r\n", lAddr);
			//OutputDebugString(ebuf);

			//DWORD_PTR lData_old = *lAddr;

			// for now we only allow changes that are in our heap....
			//if (CustomHeapIsValidHeap(MainThread,(LPVOID)lAddr)) {
			*lAddr = *rData;

				//CopyMemory(lAddr, rData, REGION_BLOCK);
				//if ((*rAddr < ctx.Esp) && ((*rAddr < (DWORD_PTR)remoteret) && (*rAddr > ((DWORD_PTR)((char *)remoteret+max_ret_size))))) {
				//*lAddr = *rData;
		
				//wsprintf(ebuf, "[%p] data %X\r\n", lAddr, *rData);
				//OutputDebugString(ebuf);
			}

			/*if (*rAddr > (ctx.Esp)) {
				OutputDebugString("breaking on stack data\r\n");
				break;
			}*/
		}

		PullRegion(orig_ebp, orig_local_size);

#ifdef SYNC_ALWAYS
		//if (MemoryModCount) {
			for (sptr = tinfo->ShadowList; sptr != NULL; sptr = sptr->next) {

				if (sptr->LastSync != NULL) {
					RegionFree(&sptr->LastSync);
				}
				sptr->LastSync = CRC_Region(sptr->address, sptr->size);
			}
		//}
#endif

		//OutputDebugString("done api proxy\r\n");
		
		// free our temp space for the outgoing packet..
		//HeapFree(GetProcessHeap(), 0, buf);
		// free our return packet space
		//HeapFree(GetProcessHeap(), 0, remoteret);
		
		//remoteret = 0;
		//pkt = 0;
	}


	/*
	for (sptr = ShadowList; sptr != NULL; sptr = sptr->next) {
		if (!sptr->verify) continue;

		wsprintf(ebuf, "pull %p %d\r\n", sptr->address, sptr->size);
		OutputDebugString(ebuf);
		PullRegion(sptr->address, sptr->size);
	}*/


	return ret;
}



// mabye emulate locally on two diff threads/areas of memory using relative ^^^ and verify the code is working to fix faster rather than socket

__declspec(naked) void RedirectFunction_help(void) {
	__asm {
		// ecx has ebp
		// edx has esp
		// move the variables in place for pushing the information
		// across to the other side so that we get the data back
		// if local variables are modified

		push edx
		push ecx


		// now move address of function (or its 'identitfier) into ebx
		// its already in EBX.. maybe remove this later...
		mov ebx, [esp + 12]

		// normal opening..
		push ebp
		mov ebp, esp

		// we need space for the variable to retrieve from called function (remote helper) the amoutn of bytes the stack needs fixed during return
		sub esp, 0x4

		// put that address in edx for use in the next function
		mov edx, esp
		//sub edx, 4
		mov dword ptr [edx], 0

		// give us some stack space
		sub esp, 64
		// copy all of the stack (after the identifier/func address) to new stack space..
		mov esi, ebp
		// ebp = stack after push of ebp, so has.. ebp, ret, function identifier.. so +12 to get to the real arguments
		add esi, 20
		//int 3
		// we want to put that information at the current stack (with 64 bytes space)
		// stack grows down so we give the start of it
		mov edi, esp

		// ecx = counter of 64 bytes for the move
		mov ecx, 64
		// finally copy
		rep movsb
		// push address to store return cleanup
		// this is at the end of the copied bytes from earlier.. fix later.. ensure it has separate space for whne we
		// buckle down and detect the bytes if we need optimizations
		push edx

		// push origial ebp and esp.. so we can calculate the local stack of the prior function
		// start at ebp now..
		mov edx, ebp
		// add past our push ebp
		add edx, 4
		push edx
		// add past esp (so finally the original ebp)
		add edx, 4
		push edx

		// push stack space (64bytes)
		mov edx, esp
		add edx, 12
		push edx

		// push func addresss from earlier that we retrieved from the stack before our function initializer
		push ebx

		//int 3
		// call function which does communications/processing
		call remote_handle

		//int 3
		// fix our pushes (func, stack, and ret cleanup)
		// 16 now 24 for esp,ebp
		add esp, 24

		// put in ecx amount of bytes changed..
		mov ebx, [ebp - 4]

		// fix the extra space for amount of bytes changed...
		//add esp, 4

		// normal cleanup
		mov esp, ebp
		pop ebp

		add esp, 8

		//mov esp, ebp
		//add esp, 4

		// get return address...
		mov ecx, [esp]
		add esp, 4

		// now we need to get stack back to normal
		add esp, ebx

		jmp ecx
		/*
		// put the return address into ecx and increase stack since we wont need it there anymore (replicating ret with our own code/jmp)
		mov ecx, [esp]
		add esp, 4

		// increase by amount of bytes changed
		add esp, ebx

		// finally jmp to the return address (same as ret now)
		// ret = eax / should be intact
		jmp ecx */
	}
}


// we have to determine if the argument being passed if a pointer, or an absolute value
// if its a pointer then we have to try to detetrmine its size (later we should emulate to determine the size, and cache the size) or
// wait for the next variable since a lot of the times the size is the next argument... we can easily determine strings
// but must check unicode sizes as well and consider unicode
/*void stack_add(DWORD_PTR addr) {

	int size = DetermineSizeBadRead(addr, sizeof(DWORD_PTR));
	if (size == 0);

	// if size/isbad didnt return anything then its probably an absolute value.. *check for relative pointers later

}*/


unsigned char redirect_stub_raw[] = "\xCC\x8B\xCD\x8B\xD4\x8B\x1C\x24\x83\xEC\x04\x89\x1C\x24\xBB\xDD\xCC\xBB\xAA\x89\x5C\x24\x04\x68\xAD\xDE\xEF\xBE\xC3";

/*
void WINAPI PrintDebugRedir(void *func) {

	Redirect *rptr = (Redirect *)redirect_search((DWORD_PTR)func);
		if (rptr != NULL) {
			char ebuf[1024];
			wsprintf(ebuf, "redir mod %s func %s addr %p\r\n", rptr->module, rptr->function, rptr->addr);
			OutputDebugString(ebuf);
		} else {
			OutputDebugString("redir mod not found\r\n");
		}
}

__declspec(naked) void printhelper() {
	__asm push ebx
	__asm call PrintDebugRedir
}
*/
// builds a redirector stub.. puts in the redirect actual function that gets called from above (which calls the original function)
// and puts the original function address as an argument to our function above so that we have all of the information required..
// source is below
// make 64bit version of stub & this later...
char *RedirectStub_Build(DWORD_PTR Addr, DWORD_PTR Redirect_Addr, int debug) {
	int stub_size = sizeof(redirect_stub_raw);
	char *ptr = NULL;
	DWORD_PTR *Set = NULL;

	if ((ptr = (char *)HeapAlloc(GetProcessHeap(), 0, stub_size)) == NULL)
		return NULL;

	CopyMemory(ptr, redirect_stub_raw,stub_size);

	Set = (DWORD_PTR *)(ptr + 15);
	*Set = Addr;
	Set = (DWORD_PTR *)(ptr + 24);
	*Set = Redirect_Addr;

	if (debug == 1)
		ptr[0] = 0xCC;
	else ptr[0] = 0x90;


	return ptr;
}


__declspec(naked) void redirect_stub() {
	
	__asm int 3
	__asm nop
	// rather than treating this function as a separate function from 'call_helper'.. lets use registers..
	__asm mov ecx, ebp
	__asm mov edx, esp

	// add extra space we can insert a new argument to proxy the function call
	__asm mov ebx, [esp]
	__asm sub esp, 4

	// push eax to stack so we can save it
	//__asm push eax
	// copy return address to eax
	
	// copy the return address from eax to the new space added
	__asm mov [esp], ebx

	// put our identifier (for now just the original memory address) in eax
	__asm mov ebx, 0xAABBCCDD
	// move that address from eax into the original place where the return address was
	__asm mov [esp + 4], ebx
	// restore eax
	//__asm pop eax

	// now push the function address of our proxy function..
	__asm _emit 0x68
	__asm _emit 0xAD
	__asm _emit 0xDE
	__asm _emit 0xEF
	__asm _emit 0xBE
	// and finally ret to that function.. (which gets the new parameter from its stack, and then continues normally)
	__asm ret
}





/*
// ZeroPKT command for transmitting
char *zmqpkt_send(int type, int *_len, void *extra, int extra_size) {
    ZeroPkt *pkthdr;
    char *ret = NULL;
    int msg_sock = 0;
    int len = 0;
    void *data = NULL;
    void *out_data = NULL;
    int out_size = 0;
    char *ptr;
    int value=2000;
    int prio=1;
    char ipc[1024];
    void *context = NULL;
    void *requester = NULL;
    zmq_msg_t omsg, imsg;
    int lfd;
    char *cur_dir = NULL;
    int good = 0;
    

    // this next bit of logic is for when we have multiple child processes, or
    // in NGINX itself we use the pid to determine the IPC for this specific pid
    // we will usually fork() before getting to this point, and just in case
    // we didn't.. we initialize a new ZeroMQ context for this pid
	if (!InterlockedExchangeAdd(&socket_opened, 1)) {
        zmq_context_id = getpid();
        if ((zmq_context = zmq_ctx_new()) == NULL)
            return NULL;

    }
    
    // initialize output msg using ZMQ API
    if (zmq_msg_init_size(&omsg, sizeof(ZeroPkt) + extra_size) != 0) return NULL;
    // find a ptr to the raw memory location to fill with our data
    ptr = zmq_msg_data(&omsg);
    // error?
    if (ptr == NULL) return NULL;
    
    // setup packet header pointer.. (sanity stuff.. so we verify corruption, correct response for our request, etc)
    pkthdr = (ZeroPkt *)ptr;
    ptr += sizeof(ZeroPkt);
    
    // set packet header type
    pkthdr->type = type;
    // set length
    pkthdr->len = sizeof(ZeroPkt) + extra_size;
    
    // if theres extra size (not just empty packet header.. I had use for an empty one in past..)
    if (extra_size) {
        // copy data behind packet header
        memcpy(ptr, extra, extra_size);
        ptr += extra_size;
    }
    
    // calculate the size (using the ptr minus original memory location)
    out_size = ptr - (char *)out_data;
    
    
    // allocate a ZMSG for incoming (response) from this packet
    zmq_msg_init (&imsg);
    
    // allocate a socket of ZMQ_REQ type for this transaction
    if ((requester =  zmq_socket (zmq_context, ZMQ_REQ)) == NULL) goto end;
    
    // timeout is useful if we expect errors.. i may turn it on before release.. but i doubt there will be
    // any need.. things have been very stable with 50 million transactions in a day for a distributed CPU sharing framework
    // i needed these using ZeroMQ's sister nanomsg (it's in alpha stages... and unstable)
    zmq_setsockopt(requester, ZMQ_RCVTIMEO, &value, sizeof(int));
    zmq_setsockopt(requester, ZMQ_SNDTIMEO, &value, sizeof(int));
    sprintf(ipc, "ipc:///tmp/%d.ipc", getpid());
    if (zmq_connect (requester, ipc) != 0) goto end;
    // send out our request...
    if (zmq_sendmsg(requester, &omsg, 0) == -1) goto end;
    // receive the response back
    if (zmq_recvmsg(requester, &imsg, 0) == -1) goto end;
    // get the length
    len = zmq_msg_size(&imsg);
    
    // if it's more than 0..
    if (len > 0) {
        // obtain pointer to the incoming packet's infrmation
        ptr = zmq_msg_data(&imsg);
        // lets allocate a pointer to return
        ret = malloc(len + 1);
        if (ret == NULL) {
            printf("memory allocation error.. fatal\n");
            exit(-1);
        }
        
        // copy data and set the length
        memcpy(ret, ptr, len);
        *_len = len;
        
    }
    good++;
end:;
    // cleanup the incoming/outgoing zmq msg types
    zmq_msg_close(&imsg);
    zmq_msg_close(&omsg);
    // close the requester socket
    if (requester != NULL) zmq_close(requester);
    if (good == 0) {
    	zmq_context_id = 0;
    	__sync_val_compare_and_swap(&lock, 1, 0, 0);    	
    }
    // return ret (pointer to data)
    return ret;
}
*/

/*
BOOL __stdcall myHeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
LPVOID __stdcall myHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
%FUNC_REDIR

  we need some generic tests for determining if functions should stay local/remote
  also we need to rebase the stack.. or work better with local variables being transferred (which would
  have a very close address.. therefore our space copying would affect it)
*/
struct _func_redirect {
	int debug;
	char *module_name;
	char *func_name;
	void *func_addr;
	
} FuncRedirect[] = {
	// functions that need to use custom heap..
	{0,"kernel32",	"HeapAlloc", (void *)&myHeapAlloc },
	{0,"kernel32",	"HeapFree", (void *)&myHeapFree },
	{0,"kernel32",	"VirtualAlloc", (void *)&myHeapAlloc },
	{0,"kernel32",	"VirtualFree", (void *)&myHeapFree },
	{0,"kernel32",	"VirtualProtect", (void *)&myVirtualProtect },
	//{0,"kernel32",	"GetVersion", (void *)0 },
	{0,"kernel32",	"GetVersionEx", (void *)0 },
	// customs we want locally for testing.. we should expand this to a wide variety...
	// somehow automate the process to determine if its a string function, or something requiring of system
	// maybe emulating functions and caching whether it goes on to using other DLLs.. if not then we can do locally
	{0,"kernel32",	"heap", 0 },
	{0,"kernel32",	"multibyte", 0 },
	{1,"kernel32",	"environmentstr", 0 },
	{1,"kernel32",	"startupinfo", 0 },
	{1,"kernel32",	"getcommand", 0 },
	
	{1,"kernel32",	"sethandle", 0 },
	{1,"kernel32",	"getstdhandle", 0 },
	
	{1,"kernel32",	"getfiletype", 0 },
	{1,"kernel32",	"getacp", 0 },
	{1,"kernel32",	"getcpinfo", 0 },
	{1,"kernel32",	"getstring", 0 },
	{1,"kernel32",	"lcmapstring", 0 },
	{1,"kernel32",	"getmodule", 0 }, 
	
	//{"kernel32",	"exitproc", 0 },
	//{"kernel32",	"exitthread", 0 },
	
	//{"user",		"wsprint", 0 },

	
	{ NULL, NULL, NULL }
};

FARPROC RedirGetAddr(char *module, char *function, int *found, int *debug) {
	char ebuf[1024];

	// enum list
	for (int i = 0; FuncRedirect[i].func_name != NULL; i++) {
		// check moduile name
		if (StrStrI(module, FuncRedirect[i].module_name) != NULL) {
			// check func name
			if (StrStrI(function, FuncRedirect[i].func_name) || (StrCmpA(function, FuncRedirect[i].func_name) == 0)) {
				// if we found it.. we consider skip (meaning skip building a stub)
				*found = 1;

				if (FuncRedirect[i].debug==1) *debug = 1;
				// if we have our own version.. use it
				if ((FuncRedirect[i].func_addr != 0) && (FuncRedirect[i].func_addr != (void *)1)) {
					wsprintf(ebuf, "Returning redirected (remote) %s [%s] -> %p\r\n", function, module, FuncRedirect[i].func_addr);
					OutputDebugString(ebuf);

					return (FARPROC)FuncRedirect[i].func_addr;
				} else {
					if (FuncRedirect[i].func_addr == (void *)1) *found = 0;
					// return the normal
					wsprintf(ebuf, "Returning original function (locally) %s\r\n", function);
					OutputDebugString(ebuf);

					return (FARPROC)GetProcAddress(GetModuleHandle(module), function);
				}
			}
		}
	}

	return 0;
}


// we need to create a structure for the redirections since each one will allocate 64k bytes.. or just ignore it
FARPROC RedirectStub(char *name, HMODULE handle, char *function, int debug) {
	FARPROC ret_addr = 0;
	char ebuf[1024];
/*
	  wsprintf(ebuf, "name %s function %s handle %p", name, function, handle);
	  MessageBox(0,ebuf,"hmm",0);
*/
	void *addr = VirtualAlloc(0, sizeof(redirect_stub_raw), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	FARPROC func_addr = GetProcAddress(handle, function);

	// copy stub to our newly allocated space using virtualprotect so its rw+exec
	char *stub = RedirectStub_Build((DWORD_PTR)func_addr,(DWORD_PTR) &RedirectFunction_help, debug);
	CopyMemory(addr, stub, sizeof(redirect_stub_raw));

	redirect_add((DWORD_PTR)func_addr, name, function);

//	__asm int 3

	// return this stub to be used in IAT..
	return (FARPROC)addr;
}

FARPROC RedirectProcAddress(char *name, HMODULE handle, char *function) {
	int found = 0;
	int debug = 0;
	FARPROC	addr = RedirGetAddr(name, function, &found, &debug);
	// skip == 1 (means we have an address.. but we want to return it since we want it on this side (not remote)
	if (found == 1) {
		return addr;
	}


	return RedirectStub(name, handle, function, debug);
}

//   Matt Pietrek's function
PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
    unsigned int i;
	DWORD size;
   
    for ( i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ ) {
		size = section->Misc.VirtualSize;
		if (size == 0)
			size = section->SizeOfRawData;
         
        // Is the RVA within this section?
        if ( (rva >= section->VirtualAddress) &&
             (rva < (section->VirtualAddress + size)))
            return section;
    }
   
    return 0;
}

int ProxyConnect();


//   This function is also Pietrek's
void *GetPtrFromRVA(DWORD rva, IMAGE_NT_HEADERS *pNTHeader, PBYTE imageBase ) {
   PIMAGE_SECTION_HEADER pSectionHdr;
   INT delta;
     
   pSectionHdr = GetEnclosingSectionHeader( rva, pNTHeader );
   if (!pSectionHdr)
      return 0;
 
   delta = (INT)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);

   return (PVOID) ( imageBase + rva - delta );
}

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD)(ptr) + (DWORD)(addValue))



#define GET_HEADER_DICTIONARY(module, idx)	&(module)->headers->OptionalHeader.DataDirectory[idx]
long first_a = 0;


int BuildImportTable2(PMEMORYMODULE module)
{
	int result=1;
	unsigned char *codeBase = module->codeBase;
	char ebuf[1024];



	PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (directory->Size > 0) {
		PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR) (codeBase + directory->VirtualAddress);
		for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++) {
			DWORD_PTR *thunkRef;
			FARPROC *funcRef;
			char *name = (char *)(codeBase + importDesc->Name);
			HMODULE handle = LoadLibrary((LPCSTR) name);
			module->modules = (HMODULE *)realloc(module->modules, (module->numModules+1)*(sizeof(HMODULE)));
			if (module->modules == NULL) {
				//__asm int 3
				result = 0;
				break;
			}

			module->modules[module->numModules++] = handle;
			if (importDesc->OriginalFirstThunk) {
				thunkRef = (DWORD_PTR *) (codeBase + importDesc->OriginalFirstThunk);
				funcRef = (FARPROC *) (codeBase + importDesc->FirstThunk);
			} else {
				// no hint table
				thunkRef = (DWORD_PTR *) (codeBase + importDesc->FirstThunk);
				funcRef = (FARPROC *) (codeBase + importDesc->FirstThunk);
			}
			for (; *thunkRef; thunkRef++, funcRef++) {
				if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
					char *fname = (char *)IMAGE_ORDINAL(*thunkRef);
					if (StrStrI(fname, "MessageBoxA") != NULL || 1==1) {
						*funcRef = (FARPROC)RedirectProcAddress(name,handle, (char *)IMAGE_ORDINAL(*thunkRef));
					} else {
						//OutputDebugString("\r\nHook CHK\r\n");
						FARPROC a = (FARPROC)GetProcAddress(handle, fname);
						*funcRef = a;
					}
				} else {
					PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME) (codeBase + (*thunkRef));
					char *fname = (char *)(&thunkData->Name);
					if (StrStrI(fname, "MessageBoxA") != NULL || 1==1) {
						//OutputDebugString(fname);
						//OutputDebugString("\r\nHook\r\n");
						*funcRef = (FARPROC)RedirectProcAddress(name,handle, (char *)&thunkData->Name);
					} else {
						//OutputDebugString("\r\nHook CHK\r\n");
						FARPROC a = (FARPROC)GetProcAddress(handle, fname);
						*funcRef = a;
					}
				}
				if (*funcRef == 0) {
					//__asm int 3
					result = 0;
					break;
				}
			}

			if (!result) {
				break;
			}
		}
	}

	return result;
}





typedef struct _allocated_regions {
	struct _allocated_regions *next;
	DWORD_PTR Address;
	DWORD_PTR Size;
	int _virtual;
} AllocatedRegions;


AllocatedRegions *allocated_list = NULL;

// free all allocated regions on the remote side...
void FreeAllocatedRegions() {
	int i = 0;
	int pkt_len = sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(MemTransfer);

	char *ptr = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pkt_len + 1);
	if (ptr == NULL) return;

	char *retptr = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ZmqRet));
	if (retptr == NULL) return;

	// setup our command structure for the remote side...
	ZmqHdr *hdr = (ZmqHdr *)(ptr);
	ZmqPkt *pkt = (ZmqPkt *)((char *)ptr+sizeof(ZmqHdr));
	MemTransfer *minfo = (MemTransfer *)((char *)ptr+sizeof(ZmqHdr)+sizeof(ZmqPkt));

	hdr->len = sizeof(ZmqPkt) + sizeof(MemTransfer);
	pkt->len = sizeof(ZmqPkt) + sizeof(MemTransfer);
	pkt->cmd = MEM_DEALLOC;
	hdr->type = MEM_DEALLOC;
	minfo->cmd = MEM_DEALLOC;
	minfo->_virtual = 1;

	for (AllocatedRegions *arptr = allocated_list; arptr != NULL; arptr = arptr->next) {
		// memory information required to allocate remotely..
		minfo->addr = (void *)arptr->Address;
		minfo->len = arptr->Size;

		if ((i = send(proxy_sock, ptr, pkt_len, 0)) < pkt_len) {
			// we need some global fatal variables..
			__asm int 3
			return;
		}
		
		if ((i = recv(proxy_sock, retptr, sizeof(ZmqRet), 0)) < sizeof(ZmqRet)) {
			// we need some global fatal variables..
			__asm int 3
			return;
		}

		ZmqRet *rethdr = (ZmqRet *)retptr;
		if (rethdr->response != 1) break;

		//OutputDebugString("freed\r\n");
	}
}


/*

This function will allocate a particular amount of space in this process, and then send over a command to the API proxy server to allocate the same
amount of space at the same address... this will allow us to transparently handle a lot of circumstances (IE: data on heap, stack, etc)
We can move all of our data and then ensure they are equal before/after calls... it will loop until it successfully allocates an area...
this should be rewrote later when we have a better API system

*/
DWORD_PTR pref = 0x5A000000;

DWORD_PTR PreferredAddress() {
	DWORD_PTR ret = pref;
	pref += 0x01000000;
	if (pref > 0x70000000) return 0;
	return ret;
}


DWORD_PTR AllocateCopyRegion(int size) {
	int r = 0;
	DWORD_PTR ret = 0;
	int count = 1000;
	// lets allocate space for stack on the remote side (so we can allocate the same address here.. so we can remove a lot of inconsistencies or manipulating/analysis of every
	// execution's instructions and read/write memory addresses.. this should work for *most*
	// this is going to also be our space for HEAP!.. lets do 16 megabytes.. put stack at bottom, and heap at top...
	// lets do a very basic heap allocator for now... we dont want it to resolve frees and move shit around till later

	int done = 0;
	while (!done && --count >= 0) {
		int newstack_size = size * 4;
		void *allocaddr = VirtualAlloc((void *)PreferredAddress(), newstack_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (allocaddr == NULL) {
			// if we cannot allocate the space using 0.. it means we are out of memory... no way to fix that
			continue;
		}

		// create a function for creating request to proxy and then send over the memory alloc
		int pkt_len = sizeof(ZmqHdr) + sizeof(ZmqPkt) + sizeof(MemTransfer);
		char *ptr = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pkt_len + 1);
		if (ptr == NULL) {
			// same as above.. out of memory!
			return -1;
		}

		// setup our command structure for the remote side...
		ZmqHdr *hdr = (ZmqHdr *)(ptr);
		ZmqPkt *pkt = (ZmqPkt *)((char *)ptr+sizeof(ZmqHdr));
		MemTransfer *minfo = (MemTransfer *)((char *)ptr+sizeof(ZmqHdr)+sizeof(ZmqPkt));

		hdr->len = sizeof(ZmqPkt) + sizeof(MemTransfer);
		hdr->type = MEM_ALLOC;
		pkt->len = sizeof(ZmqPkt) + sizeof(MemTransfer);
		pkt->cmd = MEM_ALLOC;



		// memory information required to allocate remotely..
		minfo->addr = allocaddr;
		minfo->len = newstack_size;
		// we are allocating memory..
		minfo->cmd = MEM_ALLOC;
		// this tells it to use VirtualAlloc...
		minfo->_virtual = 1;



		char fbuf[1024];
		wsprintf(fbuf, "trying to allocate %p size %d\r\n", allocaddr, newstack_size);
		OutputDebugString(fbuf);
		if ((r = send(proxy_sock, ptr, pkt_len, 0)) < pkt_len) {
			// we need some global fatal variables..
			return -1;
		}

		if ((r = recv(proxy_sock, ptr, pkt_len, 0)) < sizeof(ZmqRet)) {
			// we need some global fatal variables..
			return -1;
		}

		ZmqRet *retpkt = (ZmqRet *)ptr;
		if (retpkt->response == 1) {
			DWORD_PTR *checkaddr = (DWORD_PTR *)(ptr + sizeof(ZmqRet));
			if (*checkaddr != (DWORD_PTR)allocaddr) {
				__asm int 3
				//ExitProcess(0);
			}
			else {
				done = 1;
				ret = (DWORD_PTR)allocaddr;

				AllocatedRegions *arptr = (AllocatedRegions *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AllocatedRegions));

				if (arptr != NULL) {
					arptr->Address = (DWORD_PTR)allocaddr;
					arptr->Size = newstack_size;
					arptr->_virtual = 1;

					arptr->next = allocated_list;
					allocated_list = arptr;
				}
			}
		}
		else {
			// if we couldnt allocate exact space on remote side.. lets remove on local
			VirtualFree(allocaddr, newstack_size, 0);
		}
		HeapFree(GetProcessHeap(), 0, ptr);
	}

	return ret;
}


int ProxyConnect() {
    struct sockaddr_in proxy_addr;

	if ((proxy_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) return -1;

	proxy_addr.sin_family = AF_INET;                
    proxy_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	//proxy_addr.sin_addr.s_addr = inet_addr("192.168.1.160");
    proxy_addr.sin_port = htons(5555);

	if (connect(proxy_sock,(const struct sockaddr *) &proxy_addr, sizeof(struct sockaddr_in)) != 0) {
		closesocket(proxy_sock);
		return -1;
	}
	//OutputDebugString("connected\r\n");

	MainThread = Thread_New();


	// allocate space for our functionality...
	DWORD_PTR memrange = AllocateCopyRegion(REGION_SIZE);

	if (memrange != 0) {
		SetupMemory(MainThread, memrange, REGION_SIZE);
	}

	return memrange != 0;
}




// redirect all imports to redirector function
int RedirectImportTable(char *module_path) {
	int result=1;
	unsigned char *codeBase = NULL;
	unsigned long codeSize = 0;

	codeBase =(unsigned char *) FileGetContents(module_path, &codeSize);
	if (codeBase == NULL) {
		__asm int 3
		return -1;
	}
	
	IMAGE_DOS_HEADER *dosHd = MakePtr(IMAGE_DOS_HEADER *, codeBase, 0);
	IMAGE_NT_HEADERS *ntHd = MakePtr(IMAGE_NT_HEADERS *, codeBase, dosHd->e_lfanew);
	IMAGE_NT_HEADERS *ntHd2 = MakePtr(IMAGE_NT_HEADERS *, GetModuleHandle(0), dosHd->e_lfanew);

	IMAGE_IMPORT_DESCRIPTOR *impDesc	=(IMAGE_IMPORT_DESCRIPTOR *)GetPtrFromRVA(
      (DWORD)(ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
      ntHd, (PBYTE)codeBase);
	IMAGE_IMPORT_DESCRIPTOR *impDesc2	=(IMAGE_IMPORT_DESCRIPTOR *)GetPtrFromRVA(
      (DWORD)(ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
      ntHd2, (PBYTE)codeBase);

	if (impDesc == NULL) {
		__asm int 3
		return 0;
	}


   IMAGE_THUNK_DATA *itd, *itd2;

   char *module_name = NULL;
   //Loop through all the required modules
   while((module_name = (char *)GetPtrFromRVA((DWORD)(impDesc->Name), ntHd, (PBYTE)codeBase))) {
      //If the library is already loaded(like kernel32.dll or ntdll.dll) LoadLibrary will
      //just return the handle to that module.
        HMODULE localMod = LoadLibrary(module_name);

      //If the module isn't loaded in the remote process, we recursively call the
      //module mapping code.  This has the added benefit of ensuring that any of
      //the current modules dependencies will be just as invisble as this one.
		// I disagree... since we do not handle functions that forward....
		// then we have a problem because we dont handle it below :)
		// so we will have to use the normal loader for any dependencies
      //Lookup the first import thunk for this module
      //NOTE: It is possible this module could forward functions...which is something
      //that I really should handle.  Maybe i'll add support for forwared functions
      //a little bit later.
      itd =
         (IMAGE_THUNK_DATA *)GetPtrFromRVA((DWORD)(impDesc->FirstThunk), ntHd, (PBYTE)codeBase);

      //itd2 = (IMAGE_THUNK_DATA *)((DWORD_PTR)GetModuleHandle(0) + (DWORD_PTR)((DWORD_PTR)itd - (DWORD_PTR)codeBase));

      while(itd->u1.AddressOfData) {
         IMAGE_IMPORT_BY_NAME *iibn;
         iibn = (IMAGE_IMPORT_BY_NAME *)GetPtrFromRVA((DWORD)(itd->u1.AddressOfData),
			 ntHd, (PBYTE)codeBase);

		 DWORD_PTR faddr = (DWORD_PTR)MakePtr(DWORD_PTR, RedirectProcAddress(module_name,GetModuleHandle(module_name), (char *)iibn->Name), 0);

		 /*
		 
		 if (!InterlockedExchangeAdd(&first_a, 1)) {
			 char ebuf[1024];
			wsprintf(ebuf, "itd %p itd2 %p new hoop %p iat entry %p", itd, itd2, faddr, &itd2->u1.Function);
			MessageBox(0,ebuf,"hmm",0);
		 }*/
		


		 //VirtualProtect(&itd2->u1.Function, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &old);
             itd->u1.Function = faddr;
			 //if (itd->u1.Function == 0) MessageBox(0,"fail","hmm",0);
		//	 VirtualProtect(&itd2->u1.Function, sizeof(DWORD_PTR), old, &old);

		//	 FlushInstructionCache(GetCurrentProcess(),&itd2->u1.Function, sizeof(DWORD_PTR));

         itd++;
		 itd2++;
      }       
      impDesc++;
   }

	return result;
}


// add for when we're doing imports so its adds by section (will only add to main...)
void WINAPI addregi(DWORD_PTR Address, DWORD_PTR Size) {
	shadow_add(MainThread, Address, Size, 0);
}





//int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("usage: %s <process id>\n", argv[0]);
		exit(-1);
	}

	// which process to attach the debugger to?
	pid = atoi(argv[1]);

	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid)) == NULL) {
		printf("Couldnt open process %d\n", pid);
		exit(-1);
	}

	printf("Opened process %d - HANDLE %X\n", pid, hProcess);

	chksum_crc32gentab();
	char ebuf[1024];
	InitializeCriticalSection(&CS_redirect);
	/*
		HMODULE mod_emu;
		mod_emu=LoadLibrary("x86emu");
		void *func = (void *)GetProcAddress(mod_emu, "x86_emulate");
		wsprintf(ebuf, "emu %p func %p", mod_emu, func);
		MessageBox(0,ebuf,"hmm",0);
		ExitProcess(0);
	*/
	WSADATA wsaData;
	char *dll = "e:\\msg2.dll";

	tlsThreadID = TlsAlloc();

	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
		ExitProcess(0);
    }

	// attempt to connect to the apiproxy server...
	// we can still bail if it fails.. or etc..
	if (ProxyConnect() != 1) {
		return -1;
	}

	char *cmdline = GetCommandLine();

	char *sptr = NULL;
	if ((sptr = StrStrI(cmdline, " ")) != NULL) {
		dll = ++sptr;
	}


	HMEMORYMODULE Mblah;
	unsigned long a = 0;
	char *dllbuf = FileGetContents(dll, &a);
	if (dllbuf == NULL) {
		ExitProcess(0);
	}
	void *code = NULL;
	void *func = NULL;
	// first we get the size of the code.. so we can allocate the same address on both processes (for thingsin the data section)
	DWORD_PTR CodeSize = MemorySizeNeeded(dllbuf);
	char buf[1024];
	wsprintf(buf, "CodeSize %d\r\n", CodeSize);
	OutputDebugString(buf);
	if (CodeSize == NULL) {
		__asm int 3
		ExitProcess(0);
	}
	DWORD_PTR force_base = AllocateCopyRegion(CodeSize);
	//wsprintf(buf, "force base %p size %d\r\n", force_base, CodeSize);
	//OutputDebugString(buf);
	if (force_base == NULL) {
		__asm int 3
		ExitProcess(0);
	}
	// add so it gets pushed to the other process
	//shadow_add(force_base, CodeSize, 0);
	// now load the code into that base
	Mblah = MemoryLoadLibrary(dllbuf,(void *)force_base,  (DWORD_PTR)&BuildImportTable2,0,(unsigned char **) &code, &func, &addregi);
	
	// fix.. later we need to figure this out... and see why its using a section with probably 0 raw and virtual..
	// prob just the last section thats not really being allocated
	MainThread->ShadowList = MainThread->ShadowList->next;

	TrickStackExec(MainThread, code, func);

	FreeAllocatedRegions();

	//void *blah =(void *)&redirect_stub;
	//GetModuleFileName(GetModuleHandle(0), buf, 1024);
	//BuildImportTable2(Mblah);
	//MessageBox(0,"test","hmm",0);
	return 0;
}
