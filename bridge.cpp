#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <shlwapi.h>
#include "structures.h"
#include "commands.h"
#include "memverify.h"
#include "file.h"
#include "crc.h"

#pragma comment(lib, "shlwapi.lib")


/*

Parameters *Parameters_by_Location(Parameters **param_list, int location) {
	Parameters *pptr = *param_list;

	for (; pptr != NULL; pptr = pptr->next) {
		if (pptr->location == location)
			return pptr;
	}

	return NULL;
}


// free our 'virtual stack'
int stack_free(Parameters **param_list) {
	Parameters *pptr = *param_list, *pnext = NULL;

	while (pptr != NULL) {
		pnext = pptr->next;
		HeapFree(GetProcessHeap(), 0, pptr);
		pptr = pnext;
	}

	*param_list = NULL;
	return 0;
}

// push to a virtual stack
Parameters *stack_push(Parameters **param_list, DWORD_PTR laddr) {
	int parameters_count = 0;
	Parameters *pptr  = NULL;

	for (pptr = *param_list; pptr != NULL; pptr = pptr->next) 
	{
		parameters_count++;
	}

	pptr = *param_list;
	Parameters *paramnew = NULL;
	Parameters *last = NULL;

	if ((paramnew = (Parameters *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Parameters))) == NULL) 
		return 0;
/*
	// lets check if the last is there.. and its in_heap.. then we check if this variable is the SIZE of the last one..
	// we should emulate the function locally later to verify which addresses its reading/writing:) +unicorn/psykoosi.. for now
	// this should suffice for most that arent strings
	last = *param_list;

	// this will work for <1mb
	// allocate space for the size (and copy the data since its the prior parameter)
	if ((laddr < (1024*1024)) && (last != NULL) && last->heap) {
		if (last->heap_data && lstrlenA(last->heap_data) < laddr) {
			char *newdata = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, laddr + 1);
			if (newdata != NULL) {
				CopyMemory(newdata, last->laddr, laddr);
				HeapFree(GetProcessHeap(), 0, last->heap_data);
				last->heap_data = newdata;
			}
			

		}
	}
* -- /
	// LIFO = has to be because of the way we copy on to stack later

	// if we detect this parameter is a string.. then we have to allocate it into the heap
	// also if this parameter is not on the stack.. then we can check the next variable if its a size, or not..
	// this might show if someone is doing WriteFile ( char *, int size )
	// or other...
	
	
	paramnew->parameter = laddr;

	paramnew->next = *param_list;
	paramnew->location = parameters_count;
	*param_list = paramnew;


	return paramnew;
}

*/


DWORD_PTR call_helper(ThreadInfo *tinfo, FARPROC func_addr, DWORD_PTR proxyesp, DWORD_PTR proxyebp, DWORD_PTR *cleanup, DWORD_PTR Region, DWORD_PTR Region_Size, DWORD_PTR *RegionRet, DWORD_PTR *RegionRetSize, int *error) {
	DWORD_PTR callret = 0;
	Parameters *pptr = NULL;
	DWORD_PTR ret = 0;
	int parameters_count = 0;
	int parameters_size = tinfo->param_data_size;
	unsigned char *ptr = NULL;
	unsigned char *temp_space = NULL;
	DWORD_PTR saved_esp = 0;
	DWORD_PTR backup_esp = 0;
	DWORD_PTR backup_ebp = 0;
	char ebuf[1024];
	DWORD_PTR _cleanup = 0;
	RegionCRC *RegionVerify=NULL;


	//OutputDebugString("call helper\r\n");
	//__asm int 3
	if (func_addr == NULL)
		return 0;

	
	/*
	for (pptr = *param_list; pptr != NULL; pptr = pptr->next) {
		parameters_count++;
	}

	parameters_size = sizeof(DWORD_PTR) * parameters_count;
	*/

	proxyesp -= parameters_size;
	
	ptr = (unsigned char *)(proxyesp);// - parameters_size);
	/*
	// now we have to have a place for our parameters (temporary)
	if ((temp_space = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, parameters_size + 1)) == NULL) {
		if (error != NULL) *error = 1;

		return 0;
	} else {
		ptr = (unsigned char *)temp_space;
	}
	*/

#ifndef _WIN64
	/*
	// copy our parameters in order to 'temp_space'
	for (pptr = *param_list; pptr != NULL; pptr = pptr->next) {
		CopyMemory(ptr, &pptr->parameter, sizeof(DWORD_PTR));
		ptr += sizeof(DWORD_PTR);
	}*/
	CopyMemory(ptr, tinfo->param_data, tinfo->param_data_size);


	RegionVerify = CRC_Region(Region, Region_Size);

	__asm 
	{
		// push flags, and registers on to stack
//		pushfd
//	pusha

		//__asm int 3
		mov backup_esp, esp
		mov esp, proxyesp
		// make space for parameters
		//sub esp, parameters_size
		
		/*
		// copy parameters from temp space
		mov esi, temp_space
		mov edi, esp
		mov ecx, parameters_size
		rep movsb
		*/
		// keep the stack in edx so we can compare later just in case the callee cleans up
		//__asm int 3

		// ... this bellow was calculated.. its faulty for all API..!
		//add esp, 48

		mov saved_esp, esp
		// call function
		mov backup_ebp, ebp
		//mov ebp, proxyebp

		add esp, 20

		//int 3
		call func_addr

		sub esp, 20

		mov ebp, backup_ebp
		// if the function cleaned up the stack.. lets get it fixed so we can popa/popfd and return correctly...
		

		//__asm int 3
		// calculate cleanup..
		mov ebx, esp
		sub ebx, saved_esp

		// fix to our backed up esp (not virtual)
		mov esp, backup_esp

		// put that cleanup count in cleanup
		mov _cleanup, ebx
		add esp, ebx
	
		// get return address
		mov callret, eax

		mov esp, backup_esp
		// get stack back to normal before we pushed the parameters
		//add esp, parameters_size

		
		// retrieve registers, and flags
		//__asm int 3
		//popa
		//popfd
	}
	ret = callret;
	*cleanup = _cleanup;
	*RegionRet = (DWORD_PTR)CRC_Verify(RegionVerify, RegionRetSize, 0);


	RegionFree(&RegionVerify);

#else
	typedef void (*tCallHelper)();
	tCallHelper call64_helper = ( tCallHelper )func_addr;
	CONTEXT64 sContext, sContext_after, sContext_shadow, sContext_before;

	ZeroMemory(&sContext, sizeof(CONTEXT64));
	ZeroMemory(&sContext_shadow, sizeof(CONTEXT64));
	ZeroMemory(&sContext_after, sizeof(CONTEXT64));
	ZeroMemory(&sContext_before, sizeof(CONTEXT64));
	
	sContext.ContextFlags = CONTEXT_CONTROL;
	sContext_shadow.ContextFlags = CONTEXT_CONTROL;
	sContext_after.ContextFlags = CONTEXT_CONTROL;
	sContext_before.ContextFlags = CONTEXT_CONTROL;
	RtlCaptureContext((PCONTEXT)&sContext);
	CopyMemory(&sContext_shadow, &sContext, sizeof(CONTEXT64));

	if ((pptr = Parameters_by_Location(0)) != NULL) {
		sContext.Rcx = pptr->parameter;
	}
	if ((pptr = Parameters_by_Location(1)) != NULL) {
		sContext.Rdx = pptr->parameter;
	}
	if ((pptr = Parameters_by_Location(2)) != NULL) {
		sContext.R8 = pptr->parameter;
	}
	if ((pptr = Parameters_by_Location(3)) != NULL) {
		sContext.R9 = pptr->parameter;
	}

	if (parameters_count > 4) {
		unsigned char *ptr2 = ptr = temp_space;
		// pptr should still be the 4th param.... lets get 5th and do the rest...
		for (pptr = pptr->next; pptr != NULL; pptr = pptr->next) {
			CopyMemory((void *)ptr2, &pptr->parameter, sizeof(DWORD_PTR));
			ptr2 += sizeof(DWORD_PTR);
		}

		parameters_size = (ptr2 - ptr);
		sContext.Rsp -= parameters_size;
		CopyMemory((void *)sContext.Rsp, (void *)temp_space, parameters_size);
	}


	RtlCaptureContext((PCONTEXT)&sContext_before);
	// Start #1 - 0x21 is a calculation from EIP (in the context saved from above)
	sContext.Rip = sContext_before.Rip + 0x21;
	RtlRestoreContext((PCONTEXT)&sContext, NULL);

	// End #1 - This is the end of the calculation.. so 0x21 from above is from there until here (in a disassembler)
	call64_helper();

	RtlCaptureContext((PCONTEXT)&sContext_after);
	// Start #2 - 0x31 is a calculation from EIP (in the context saved from above)
	callret = sContext_after.Rax;
	sContext_shadow.Rip = sContext_after.Rip + 0x31;
	RtlRestoreContext((PCONTEXT)&sContext_shadow, NULL);

	// End #1 - This is the end of the calculation.. so 0x21 from above is from there until here (in a disassembler)
	// this ret = ret was just so i could calculate the placement.. you COULD remove it but i'd rather keep it for later...
	ret = callret;

#endif

	HeapFree(GetProcessHeap(), 0, temp_space);


	return ret;
}



//int call_export(Parameters **param_list, const char *module, const char *function, DWORD_PTR ESP, DWORD_PTR EBP, DWORD_PTR *ret_fix,  int *error) {
int call_export(ThreadInfo *tinfo, const char *module, const char *function, DWORD_PTR ESP, DWORD_PTR EBP, DWORD_PTR *ret_fix, DWORD_PTR Region, DWORD_PTR Region_Size, DWORD_PTR *RegionRet, DWORD_PTR *RegionRetSize, int *error) {
	DWORD_PTR ret = 0;
	//int called = 0;
	HMODULE mod_module = NULL;
	FARPROC func_addr = NULL;

	if ((mod_module = LoadLibraryA(module)) != NULL) {
		if ((func_addr = (FARPROC)GetProcAddress(mod_module, function)) != NULL) {
			ret = call_helper(tinfo, func_addr, ESP, EBP, ret_fix,  Region,Region_Size, RegionRet,RegionRetSize,error);
		}
	}
	
	// error if called isnt 1 and we have an error pointer..
	// we can check for error here using called.. but removing since we push it to call_helper..
	//if (error != NULL) *error = (called != 1);

	return ret;
}




//ThreadInfo *tinfo, 
char *remote_call(ThreadInfo *t, char *_ptr, int pkt_len, int *ret_size) {
	char *ret = NULL;
	char *module_name = NULL;
	char *func_name = NULL;
	CallInfo *cinfo = (CallInfo *)(_ptr + sizeof(ZmqPkt));
	char *ptr = (char *)_ptr;
	int error = 0;
	DWORD_PTR callret = NULL;
	int args = 0;
	DWORD_PTR *arg_element = NULL;
	ThreadInfo tinfo;
	char ebuf[1024];
	int i = 0;
	DWORD_PTR RegionRet = 0, RegionRetSize = 0;

	ZeroMemory(&tinfo, sizeof(ThreadInfo));

	ptr += sizeof(ZmqPkt);

	// make sure packet size has call info
	if (pkt_len < sizeof(CallInfo))
		return gen_response(0,ret_size,0);


	// make sure packet size is big enough to hold the data call info states (normal sanity)
/*	if (pkt_len < (int)(sizeof(CallInfo) + cinfo->arg_size + cinfo->func_len + cinfo->module_len))
		return gen_response(0,ret_size,0);
*/	
	// inc ptr past the call info structure
	ptr += sizeof(CallInfo);

	// if we dont have an address to call.. then we must dynamically load the API from a DLL
	if (cinfo->addr == NULL) {
		if ((module_name = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cinfo->module_len + 2)) == NULL)
			return gen_response(0,ret_size,0);

		CopyMemory(module_name, ptr, cinfo->module_len);

	}
	ptr += cinfo->module_len;

	if (cinfo->addr == NULL) {
		if ((func_name = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cinfo->func_len + 2)) == NULL)
			return gen_response(0,ret_size,0);

		CopyMemory(func_name, ptr, cinfo->func_len);

		if (StrStrI(func_name, "Heap") != NULL) {
			__asm int 3
		}
	
	}
	//__asm int 3
	ptr += cinfo->func_len;
	
	// ** maybe just copy the args directly to stack and execute.. instead of this virtual push shit here.. 
	// now we calculate how many arguments we have to push to stack..
	// this goes into the virtual stack before calling our function
	// this allows us to not have to create prototypes for every call
	// we want to do
	
	if ((tinfo.param_data = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cinfo->arg_len + 1)) == NULL) {
		__asm int 3
		ExitProcess(0);
	}
	CopyMemory(tinfo.param_data, ptr, cinfo->arg_len);
	ptr += cinfo->arg_len;

	/*
	args = cinfo->arg_len / sizeof(DWORD_PTR);
	
	tinfo.param_list = NULL;

	for (i = 0; i < args; i++) {
		// cast to current argument and push it to stack
		arg_element = (DWORD_PTR *)ptr;
		stack_push(&tinfo.param_list, *arg_element);

		// setup for next..
		ptr += sizeof(DWORD_PTR);
	}

	*/


	wsprintf(ebuf, "remote_call module %s func_name %s\r\n", module_name, func_name);
	OutputDebugString(ebuf);

	DWORD_PTR ret_fix = 0;

	// if we have an address from the caller.. then we use it.. otherwise we have to pass the function name/module name
	if (cinfo->addr == NULL) {
		callret = call_export(&tinfo, module_name, func_name, cinfo->ESP, cinfo->EBP, &ret_fix, cinfo->Region,cinfo->Region_Size, &RegionRet, &RegionRetSize, &error);
	} else {
		callret = call_helper(&tinfo, (FARPROC)cinfo->addr, cinfo->ESP, cinfo->EBP,  &ret_fix,  cinfo->Region,cinfo->Region_Size, &RegionRet, &RegionRetSize, &error);
	}


	HeapFree(GetProcessHeap(), 0, tinfo.param_data);

	// free virtual stack so things are ready for our next call..
	//stack_free(&tinfo.param_list);

	//wsprintf(ebuf, "remote_ret RegionRet %p Region Ret Size %d\r\n", RegionRet, RegionRetSize);
	//OutputDebugString(ebuf);

	// generate a response stating we are successful
	ret = gen_response(1, ret_size, (sizeof(DWORD_PTR) * 2) + RegionRetSize);

	// return the eax/rax from the result of the API at the end of the response packet
	CopyMemory((char *)((char *)ret + sizeof(ZmqRet)), &callret, sizeof(DWORD_PTR));
	CopyMemory((char *)((char *)ret + sizeof(ZmqRet) + sizeof(DWORD_PTR)), &ret_fix, sizeof(DWORD_PTR));
	if (RegionRetSize) {
		CopyMemory((char *)((char *)ret + sizeof(ZmqRet) + (sizeof(DWORD_PTR)*2)), (void *)RegionRet, RegionRetSize);
	}
	
	
	return ret;
}

