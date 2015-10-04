#include <windows.h>
#include <winbase.h>
#include <Tlhelp32.h>
#include <psapi.h>
#include "hooking.h"
#include <shlwapi.h>
#include "udis86/udis86.h"

Tramp *tramp_list = NULL;

#pragma comment(lib, "psapi.lib")

CRITICAL_SECTION CS_tramps;
long t_init = 0;
// declarations (move to headers)

// PE information
#define GET_HEADER_DIRECTORY(module, idx) &nt_header->OptionalHeader.DataDirectory[idx]

// how many bytes do we disassemble per loop?
#define BYTES_PER_DISASM_LOOP 13

// dyn loaded functions
typedef DWORD (WINAPI *tGetModuleFileNameEx)(HANDLE hProcess,HMODULE hModule,LPTSTR lpFilename,DWORD nSize);
extern tGetModuleFileNameEx fGetModuleFileNameEx;



// get the size of a function by disassembling it until the return
int FindFunctionSize(HANDLE Process, FARPROC FuncAddr, DWORD_PTR ModuleEnd) {
	int size = 0;

	// initialize disassembler
	ud_t ud_obj;
	ud_init(&ud_obj);
	unsigned char data[BYTES_PER_DISASM_LOOP];

#ifndef _WIN64
	ud_set_mode(&ud_obj, 32);
#else
	ud_set_mode(&ud_obj, 64);
#endif
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	
	unsigned char *Data = (unsigned char *)FuncAddr;

	DWORD_PTR Addr = (DWORD_PTR)FuncAddr;
	int len = 0;
	int bytes_to_disasm = BYTES_PER_DISASM_LOOP;

	while (1) {
		bytes_to_disasm = (DWORD_PTR)ModuleEnd - (DWORD_PTR)FuncAddr;
		if (bytes_to_disasm > BYTES_PER_DISASM_LOOP) bytes_to_disasm = 
#ifndef _WIN64
		13;
#else
		26;
#endif
		if (Addr >= ModuleEnd || bytes_to_disasm+Addr >= ModuleEnd) { size = 0; break; }

		ud_set_pc(&ud_obj, (unsigned __int64)Addr);

		// copy the instruction at Data (13 bytes max.. found this constant somewhere.. maybe up to ~21 on some 64bit, or vm-capable code)
		CopyMemory(&data, Data, BYTES_PER_DISASM_LOOP);
		ud_set_input_buffer(&ud_obj, (uint8_t*)data, BYTES_PER_DISASM_LOOP);
	
		// disassemble and turn into ascii
		if ((len = ud_disassemble(&ud_obj)) <= 0) { size = 0; break; }
		char *asm_text = (char *)ud_insn_asm(&ud_obj);

		size += len;
		if (StrStrI(asm_text, "ret") != NULL) break;

		Data += size; Addr += size;
	}

	return size;
}

/*

  For WinAPI (32bit).. Each function cleans itself up.. so lets find the return and look for how much stack space its cleaning up by!


*/
int FindFunctionParamSize(FARPROC FuncAddr) {
	int size = 0;
	int ret = 0;

	// initialize disassembler
	ud_t ud_obj;
	ud_init(&ud_obj);
	unsigned char data[BYTES_PER_DISASM_LOOP];

#ifndef _WIN64
	ud_set_mode(&ud_obj, 32);
#else
	ud_set_mode(&ud_obj, 64);
#endif
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	
	unsigned char *Data = (unsigned char *)FuncAddr;

	DWORD_PTR Addr = (DWORD_PTR)FuncAddr;
	int len = 0;
	int bytes_to_disasm = BYTES_PER_DISASM_LOOP;

	while (1) {
		bytes_to_disasm = 1024;
		if (bytes_to_disasm > BYTES_PER_DISASM_LOOP) bytes_to_disasm = 
#ifndef _WIN64
		13;
#else
		26;
#endif
		/*if (Addr >= ((DWORD_PTR)FuncAddr+4096) || bytes_to_disasm+Addr >= ((DWORD_PTR)FuncAddr+4096)) { 
			__asm int 3
			size = 0; break; 
		}*/

		ud_set_pc(&ud_obj, (unsigned __int64)Addr);

		if (IsBadReadPtr(Data, BYTES_PER_DISASM_LOOP) != 0) {
			__asm int 3
			return 0;
		}

		// copy the instruction at Data (13 bytes max.. found this constant somewhere.. maybe up to ~21 on some 64bit, or vm-capable code)
		CopyMemory(&data, Data, BYTES_PER_DISASM_LOOP);

		ud_set_input_buffer(&ud_obj, (uint8_t*)data, BYTES_PER_DISASM_LOOP);
	
		// disassemble and turn into ascii
		if ((len = ud_disassemble(&ud_obj)) <= 0) {
			__asm int 3
			size = 0; break;
		}
		char *asm_text = (char *)ud_insn_asm(&ud_obj);

		size += len;
		if (StrStrI(asm_text, "ret") != NULL) {
			if (len == 1)  {
				ret = 0;
			} else {
				signed short *rsize = (signed short *)((char *)(Data) + 1);
				ret = *rsize;
				break;
			}
			break;
		}

		Data += size; Addr += size;
	}

	char ebuf[1024];
	wsprintf(ebuf, "size %d ret %d\r\n", size, ret);

	return ret;
}



/* Hijack Functions via Detouring...

	This is kinda like the Microsoft Detours Library.  This is although created to be small,
	and injected as a DLL.  This means it doesn't have any external dependencies.

	It doesn't by far have as much support for error checking, and a lack of other things as well.

	This version uses udis86.. it has not been tested or finished for 64bit though!
	--$

*/
#pragma comment(lib, "shlwapi.lib")


long hijacked_init = 0;

typedef struct _hijacks {
	struct _hijacks *next;
	char *filename;
	PVOID module_base;
	void *orig_addr;
	void *tramp_addr;
	int tramp_size;
	char *orig_data;
	char *new_data;
	int data_size;
} Hijacks;

Hijacks *hijack_list = NULL;
CRITICAL_SECTION CS_hijack;
	

void Hijack_Init() {
	if (!InterlockedExchangeAdd(&hijacked_init, 1)) {
		InitializeCriticalSection(&CS_hijack);
		InitializeCriticalSection(&CS_tramps);
	}
}
	
/* Sets up a eip jump using:
	jmp (e9) [+imm32]

	returns the size of the modification
*/
#ifdef WIN32
#define JMP_CODE_SIZE 5
#define BYTES_PER_DISASM_LOOP 13
#else
#define JMP_CODE_SIZE 18
#define BYTES_PER_DISASM_LOOP 26
#endif

int SetupJump(unsigned char *_ptr, unsigned char *addr) {
	unsigned char *ptr = _ptr;

#ifdef WIN32

	// jmp [addr]
	*ptr++ = 0xE9;	
	*((long*&)ptr)++ = (long)(addr - (_ptr + JMP_CODE_SIZE));

#else

	// jmp [rip+addr]
	*ptr++ = 0xFF; *ptr++ = 0x25;

	// addr = 0
	*((DWORD *) ptr) = 0;
	ptr += sizeof(DWORD);

	// addr to jump to
	*((ULONG_PTR *)ptr) = addr;
	ptr += sizeof(ULONG_PTR);

#endif

	return (int)(ptr - _ptr);
}


// setup a call at a specific place (shellcode, location in memory, etc)
// ** this must be live in the same process since the destination address must be calculate
int SetupCall(unsigned char *_ptr, unsigned char *addr) {
	unsigned char *ptr = _ptr;
#ifdef WIN32

	// call [addr]
	*ptr++ = 0xE8;	
	*((long*&)ptr)++ = (long)(addr - (_ptr + JMP_CODE_SIZE));
#else
fail: finish me;
#endif

	return (int)(ptr - _ptr);
}



// find the size of the instructions we have to copy over to our trampoline that we corrupt inside the function that we are hooking
int FindSizeForTrampoline(FARPROC FuncAddr) {
	int size = 0;

	// initialize disassembler
	ud_t ud_obj;
	ud_init(&ud_obj);
	unsigned char data[BYTES_PER_DISASM_LOOP+1];

#ifdef WIN32
	ud_set_mode(&ud_obj, 32);
#else
	ud_set_mode(&ud_obj, 64);
#endif
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	

	unsigned char *Data = (unsigned char *)FuncAddr;

	DWORD_PTR Addr = (DWORD_PTR)FuncAddr;
	int len = 0;
	int bytes_to_disasm = BYTES_PER_DISASM_LOOP;

	while (1) {
		if (size >= (JMP_CODE_SIZE)) break;
		if (Data >= (unsigned char *)((unsigned char *)FuncAddr + (BYTES_PER_DISASM_LOOP*3))) { size = 0; break; }

		// copy the instruction at Data (13 bytes max.. found this constant somewhere.. maybe up to ~21 on some 64bit, or vm-capable code)
		CopyMemory(&data, Data, BYTES_PER_DISASM_LOOP);
		ud_set_input_buffer(&ud_obj, (uint8_t *)data, BYTES_PER_DISASM_LOOP);
		ud_set_pc(&ud_obj, (unsigned __int64)Addr);	

		if ((len = ud_disassemble(&ud_obj)) <= 0) {  size = 0; break; }
		char *asm_text = (char *)ud_insn_asm(&ud_obj);
		size += len;

		// if we see return.. it means that we are at the end of the function and we didnt get the size we need
		// for our jump. so we dont want to hook this
		if (StrStrI(asm_text, "ret") != NULL) return 0;

		Data += len; Addr += len;
	}

	return size;	
}


extern long enabled;



int IsAddrTramp(DWORD_PTR addr);
long hooked = 0;


int IsAddrTramp(DWORD_PTR addr) {
	int ret = 0;
	//printf("IsAddrTramp: %p\n", addr);
	Tramp *trptr;
	EnterCriticalSection(&CS_tramps);
	for (trptr = tramp_list; trptr != NULL; trptr = trptr->next) {
		//printf("tramp %p addr %p size %d\n", trptr, trptr->addr, trptr->size);
		if ((addr >= trptr->addr) && ((DWORD_PTR)addr < (DWORD_PTR)((DWORD_PTR)trptr->addr + (DWORD_PTR)trptr->size))) {
			ret = 1;
			break;
		}
	}
	LeaveCriticalSection(&CS_tramps);

	if (ret != 1) {
		//printf("couldnt find %p in our tramp addresses\n", addr);
	} else {
		//printf("Found adddr %p in our tramp addresses\n", addr);
	}
	return ret;
}

typedef HMODULE (WINAPI *tLoadLibrary)(LPCTSTR lpFileName);
tLoadLibrary fLoadLibrary = NULL;
tLoadLibrary origLoadLibrary = NULL;


// hook any new modules being loaded
HMODULE myLoadLibrary(LPCTSTR lpFileName) {
	OutputDebugString("myLoadLibrary");
	HMODULE ret = LoadLibrary(lpFileName);

	//if (ret != NULL)
	//	Module_EnumerateandHookExports(ret,(char *) lpFileName);

	return ret;
}




// Hijacks a function.. you give it the original function and it returns a trampoline address to use if you need to call the original
// the other parameter is your new function to replace it with..
int HijackFunc(void **_orig, void *func) {
	unsigned char *tramp, *orig;
	DWORD prot;
	int len = 0;
	int total_len = 0;
	int ret = 0;
	unsigned char *ptr = NULL;

	//OutputDebugString("HijackFunc");

	if ((_orig == NULL) || (func == NULL)) return -1;

	// get the original function pointer...
	orig = (unsigned char *)*_orig;

	total_len = FindSizeForTrampoline((FARPROC) orig);
	if (total_len <= 0) return -1;

	
	// allocate space for the trampoline
	if ((tramp = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 16 + total_len + 1)) == NULL) goto end;

	// set it read/write/exec
	if (VirtualProtect(tramp, 16+total_len, PAGE_EXECUTE_READWRITE, &prot) == 0) goto end;

	// start with all NOPs
	memset(tramp, 0x90, 16 + total_len);

	// copy the amount of data from the original function required to put the jump code
	CopyMemory(tramp, orig, total_len);

	// setup a jump back into the real function at the end of the trampoline
	SetupJump(tramp+total_len, (unsigned char *)(orig + total_len));

	// set read/write/exec on the original function so we can modify it
	if (VirtualProtect(orig, total_len + 16, PAGE_EXECUTE_READWRITE, &prot) == 0) goto end;
	ptr = (unsigned char *)orig;

	// put a jump to our trampoline in the original function
	ptr += SetupJump(ptr, (unsigned char *)func);

	// flush CPU cache for the instructions at this address
	FlushInstructionCache(GetCurrentProcess(), orig, total_len);

	// set the permissions back..
	if (VirtualProtect(orig, 16, prot, &prot) == 0) {
		// if we fail for some reason.. let's undo our changes to the code
		CopyMemory(orig, tramp, total_len);
		goto end;
	}
	// give the caller the trampoline function in case they need to call the original...
	*_orig = tramp;

	ret = 1;

end:;
	
	// cleanup
	if (!ret) {
		if (tramp != NULL) HeapFree(GetProcessHeap(), 0, tramp);
	}

	return ret;
}



