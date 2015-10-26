

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock.h> 
#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include "gerente.h"

CRITICAL_SECTION CS_Threads;

SOCKET sock;


long thread_cur = 0;
int HandleTCPClient(int sock);

unsigned int crc_tab[256];

/* chksum_crc() -- to a given block, this one calculates the
 *				crc32-checksum until the length is
 *				reached. the crc32-checksum will be
 *				the result.
 */
unsigned int chksum_crc32 (unsigned char *block, unsigned int length)
{
   register unsigned long crc;
   unsigned long i;

   crc = 0xFFFFFFFF;
   for (i = 0; i < length; i++)
   {
      crc = ((crc >> 8) & 0x00FFFFFF) ^ crc_tab[(crc ^ *block++) & 0xFF];
   }
   return (crc ^ 0xFFFFFFFF);
}

/* chksum_crc32gentab() --      to a global crc_tab[256], this one will
 *				calculate the crcTable for crc32-checksums.
 *				it is generated to the polynom [..]
 */

void chksum_crc32gentab ()
{
   unsigned long crc, poly;
   int i, j;

   poly = 0xEDB88320L;
   for (i = 0; i < 256; i++)
   {
      crc = i;
      for (j = 8; j > 0; j--)
      {
	 if (crc & 1)
	 {
	    crc = (crc >> 1) ^ poly;
	 }
	 else
	 {
	    crc >>= 1;
	 }
      }
      crc_tab[i] = crc;
   }
}


char *FileGetContents(char *name, unsigned long *size) {
	char *ptr = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	unsigned long rw_count = 0;
	unsigned long f_size = 0;
	
	if ((hFile = CreateFile(name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE)
		return NULL;
	
	f_size = GetFileSize(hFile, NULL);
	
	if ((ptr = (char *)HeapAlloc(GetProcessHeap(), 0, f_size + 1)) == NULL)
		goto err;
	
	if (ReadFile(hFile, ptr, f_size, &rw_count, 0) == 0)
		goto err;
	
	if (rw_count != f_size)
		goto err;
	
	*size = rw_count;
	
	goto ok;
err: ;
	 
	 if (ptr != NULL) {
		 HeapFree(GetProcessHeap(), 0, ptr);
		 ptr = NULL;
	 }
	 
ok: ;
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
	
	return ptr;
}



int FilePutContents(char *name, char *data, int data_size, int append) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	unsigned long rw_count = 0;
	int ret = 1;
	
	// sanity check
	//if (IsBadReadPtr(data, data_size) != 0) return -1;
	
	SECURITY_ATTRIBUTES secAttr;
    char secDesc[ SECURITY_DESCRIPTOR_MIN_LENGTH ];
    secAttr.nLength = sizeof(secAttr);
    secAttr.bInheritHandle = FALSE;
    secAttr.lpSecurityDescriptor = &secDesc;
    InitializeSecurityDescriptor(secAttr.lpSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(secAttr.lpSecurityDescriptor, TRUE, 0, FALSE);
	
	if ((hFile = CreateFile(name, GENERIC_WRITE|GENERIC_READ, FILE_SHARE_READ, &secAttr, append ? OPEN_ALWAYS : CREATE_NEW, 0, 0)) == INVALID_HANDLE_VALUE)
		return -1;
	
	
	// if we are appending data.. we go to the end of the file
	if (append)
		SetFilePointer(hFile, 0, 0, FILE_END);
	
	if (WriteFile(hFile, data, data_size, &rw_count, 0) == 0)
		ret = -1;
	
	if (rw_count != (DWORD)data_size)
		ret = -1;
	
	CloseHandle(hFile);
	
	if (ret == -1)
		DeleteFile(name);
	
	return ret;
}



char *cmd_dll(char *ptr, int pkt_len, int *ret_size);
char *cmd_mem_transfer(void *,char *_ptr, int pkt_len, int *ret_size);
char *cmd_thread_kill(char *_ptr, int pkt_len, int *ret_size);
char *cmd_ping(void *,char *_ptr, int pkt_len, int *ret_size);
char *cmd_thread_new(char *_ptr, int pkt_len, int *ret_size);
char *gen_response(int response, int *size, int additional);
char *file_cmd(void *, char *_ptr, int pkt_len, int *ret_size);
char *cmd_exit(char *_ptr, int pkt_len, int *ret_size);
char *gen_response(int response, int *size, int additional);

// command IDs for proxy
enum {
	CMD_START,		// place holder showing start of commands..
		PROC_EXIT,		// *exitprocess() on proxy.. maybe shutdown and let logging file know? or respond back with soem random information.. we'll see
		
		THREAD_START,	// *CreateThread to a stub that starts a new zeromq socket so we can control it
		// maybe use a linked list as a queue for instructions for a thread.. having the thread respond with results (slower than zeromq)
		// but will for doing a small tcp/ip stub or backdoor
		THREAD_END,		// *kill a particular thread
		
		FILE_WRITE,		// *write a complete file
		FILE_READ,		// *read a complete file
		FILE_DELETE,	// *delete a file
		
		//FILE_EXEC,		// maybe allow executing a program and then injecting a DLL for proxying data backwards
		
		LOAD_DLL,		// *load a DLL (loadlibrary) support loading into memory using our own memory laoder later for further manipulations if necessary
		UNLOAD_DLL,		// *freeloadlib
		CALL_FUNC,		// *call a particular function (requires its arguments to be behind it)
		// *each argument needs ability to give memory as an argument if its a pointer..
		
		
		MEM_PUSH,		// *write to memory a range of data
		MEM_PEEK,		// *read from the memory
		MEM_ALLOC,		// *allocate on heap
		MEM_DEALLOC,	// *free heap
		MEM_ZERO,
		
		// do these later
		//TLS_READ,		// maybe just respond with the entire TLS instead of wasting time disasembling or knowing the particular address/length
		//TLS_WRITE,		// write a value to tls -- maybe add segment selection to normal memory functions
		
		//LOG_ON,			// turn on logging (writing all requests/responses to a data file)
		//LOG_OFF,		// turn logging off
		
		//REDIRECT_BACKWARDS_FUNC,
		// maybe allow proxying backwards for specific API that is called from OTHER API
		//EXCEPTION_SET,	// set a particular thing to happen on exception
		
		//LASTERROR_MODE, // mode to determine if we need to report backwards GetLastError every call so the client can have it ready
		PING,
		GET_DLL_HANDLE,
		GET_MODULE_FILENAME,
		CMD_DONE		// just placeholder for the end
		
};

typedef struct _region_crc {
	DWORD_PTR Addr;
	unsigned int *crc;
	DWORD_PTR Size;
} RegionCRC;

#define REGION_BLOCK sizeof(DWORD_PTR)

RegionCRC *CRC_Region(DWORD_PTR Addr, DWORD_PTR Size);
char *CRC_Verify(RegionCRC *region, DWORD_PTR *Size, int);
void RegionFree(RegionCRC **rptr);





int PushData(DWORD_PTR start, DWORD_PTR size);

RegionCRC *CRC_Region(DWORD_PTR Addr, DWORD_PTR Size) {
	RegionCRC *cptr = NULL;
	int crc_count = Size / REGION_BLOCK;
	
	char ebuf[1024];
	wsprintf(ebuf, "Region Verify crc Addr %X Size %d count %d\r\n", Addr, Size, crc_count);
	OutputDebugString(ebuf);
	
	cptr = (RegionCRC *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RegionCRC));
	if (cptr == NULL) {
		__asm int 3
			return NULL;
	}
	
	cptr->Size = Size;
	cptr->crc = (unsigned int *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(unsigned int) * (crc_count + 1) + 1);
	if (cptr->crc == NULL) {
		__asm int 3
			return NULL;
	}
	cptr->Addr = Addr;
	
	for (int i = 0; i < crc_count; i++) {
		unsigned char *ptr = (unsigned char *)((unsigned char *)Addr + (i * REGION_BLOCK));
		
		cptr->crc[i] = chksum_crc32(ptr, REGION_BLOCK);
		//wsprintf(ebuf, "crc %X\r\n", cptr->crc[i]);
		//OutputDebugString(ebuf);
	}
	
	
	return cptr;
}

// optimize this later! no need to do the crc checks twice.. tired and lazy tonight
char *CRC_Verify(RegionCRC *region, DWORD_PTR *Size, int to_push) {
	int crc_count = region->Size / REGION_BLOCK;
	int modified = 0;
	char *ret = NULL;
	unsigned char *ptr = NULL;
	char ebuf[1024];
	
	for (int i = 0; i < crc_count; i++) {
		ptr = (unsigned char *)((unsigned char *)region->Addr + (i * REGION_BLOCK));
		unsigned int chk = chksum_crc32(ptr, REGION_BLOCK);
		if (chk != region->crc[i]) modified++;
	}
	
	
	wsprintf(ebuf, "Region check crc Addr %X Size %d count %d modified = %d\r\n", region->Addr, region->Size, crc_count, modified);
	OutputDebugString(ebuf);
	
	
	if (modified > 0) {
		char *mptr = NULL, *ret = NULL;
	
		if (!to_push) {
			mptr = ret = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (((sizeof(DWORD_PTR) * modified) + (REGION_BLOCK * modified))) + 1);
			if (ret == NULL) return NULL;
		}
		for (int i = 0; i < crc_count; i++) {
			ptr = (unsigned char *)((unsigned char *)region->Addr + (i * REGION_BLOCK));
			
			unsigned int chk = chksum_crc32((unsigned char *)ptr, REGION_BLOCK);
			if (chk != region->crc[i]) {
				if (!to_push) {
					// copy the data a dword at a time starting with the address to be returned to the caller...
					DWORD_PTR *mAddr = (DWORD_PTR *)mptr;
					mptr += sizeof(DWORD_PTR);
					DWORD_PTR *mData = (DWORD_PTR *)mptr;
					mptr += REGION_BLOCK;
					
					// copy this block of data
					*mAddr = (DWORD_PTR)ptr;
					//CopyMemory(mData, ptr, REGION_BLOCK);
					*mData = *(DWORD_PTR *)(ptr);				
				} else {
#ifdef APICLIENT
					PushData((DWORD_PTR)ptr, REGION_BLOCK);
#endif
				}
			}
		}
		
		//wsprintf(ebuf, "DATA MODS: %d\r\n", modified);
		//OutputDebugString(ebuf);
		
		if (!to_push) {
#ifdef APISERVER
			*Size = (DWORD_PTR)((char *)mptr - ret);
#endif
		}
		return ret;
	} else {
		//OutputDebugString("NO MODS\r\n");
	}
	//*Size = 0;
	return NULL;
}

void RegionFree(RegionCRC **rptr) {
	if (*rptr != NULL) {
		RegionCRC *_rptr = *rptr;
		HeapFree(GetProcessHeap(), 0, _rptr->crc);
		HeapFree(GetProcessHeap(), 0, _rptr);
		*rptr = NULL;
	}
}





// 0mq packet of incoming...
#pragma pack(push)
#pragma pack(1)
typedef struct _zero_pkt {
    int type;
    int len;
	DWORD_PTR ThreadID;
} ZmqHdr;


typedef struct _zmq_pkt {
	unsigned int crc;
	int thread_id; // 0 for global
	int cmd;
	int len; // len of cmd after pkt
} ZmqPkt;

// our response packet
typedef struct _zmq_ret {
	int response;		// return code
	int extra_len;		// how much data after packet header...
} ZmqRet;


// information for functions..

// transfer of memory
typedef struct _mem_info {
	int len;			// len of data after packet
	int _virtual;
	int cmd;  // MEM_PUSH, or MEM_PEEK
	void *addr;			// address

} MemTransfer;

// header of each transferparam.. put the data immediately after
typedef struct _transfer_param {
	int size;

	// if heap.. we allocate on heap and drop the address in its place (strings, data, etc)
	int heap;
} TransferParam;

// information given when needing to call API
typedef struct call_info {
	void *addr;
	int module_len;
	int func_len;

	DWORD_PTR ESP;
	DWORD_PTR EBP;
	DWORD_PTR Region;
	DWORD_PTR Region_Size;
	// how many TransferParams come next..
	int arg_len;
} CallInfo;

// information given when needing to read/write files
typedef struct _file_info {
	int cmd;
	int name_len;
	int data_len;
	int overwrite;
	int perms;
} FileInfo;


// API queued for execution per thread (maybe move this into diff system later.. either without per thread, or doing simul using channels)
typedef struct _exec_queue {
	struct _exec_queue *next;

	CRITICAL_SECTION CS;

	char *pkt;
	int pkt_len;

	char *ret;
	int ret_size;

	int ts;
	int ts_complete;

	int done;
} ExecQueue;

// virtual stack (for calling API) parameter linked list.. 
// for launching using push/pop (has to be in a linked list until it gets used
// otherwise the other functions in C will mess up the stack )
typedef struct _parameters {
	struct _parameters *next;
	DWORD_PTR parameter;
	int location;
	// we do allocate space in the heap for this parameter? and replace the slot with the address?
	int heap;
	char *heap_data;
	int size;
} Parameters;


// thread configuration structure.. for our loop main or for queuing API
typedef struct _thread_info {
	struct _thread_info *next;
	int thread_id;
	unsigned long tid;
	void *connection;
	HANDLE handle;
	long commands_processed;
	int dead;
	ExecQueue *queue;
	Parameters *param_list;
	char *param_data;
	int param_data_size;
	CRITICAL_SECTION CS;
	CRITICAL_SECTION QCS;
} ThreadInfo;

#pragma pack(pop)
#pragma comment(lib, "shlwapi.lib")

// global linked lists
ThreadInfo *thread_list = NULL;


// uses an external (sent to client) thread ID to find an internal thread structure
ThreadInfo *thread_search(int id, unsigned long tid) {
	ThreadInfo *tptr = NULL;
	ThreadInfo *ret = NULL;
	EnterCriticalSection(&CS_Threads);
	for (tptr = thread_list; tptr != NULL; tptr = tptr->next) {
		//if (((id && tptr->thread_id == id) || 
		
		if ((id == tptr->thread_id) || (tid && tptr->tid == tid)) {
			EnterCriticalSection(&tptr->CS);
			ret = tptr;
			break;
		}
	}
	LeaveCriticalSection(&CS_Threads);
	return ret;
}

// create a new thread and initialize its structure
ThreadInfo *thread_new() {
	// create thread here.. return the info into tptr...
	HANDLE thread_handle = NULL;
	int thread_created = 0;
	unsigned long tid = 0;
	ThreadInfo *tptr = NULL;
	
	// alloc space for the new thread structure
	if ((tptr = (ThreadInfo *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ThreadInfo))) == NULL)
		return NULL;
	
	// ensure we can create the thread
//	if ((thread_handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) Thread_Loop, (void *)NULL, 0, &tid)) == NULL)
//		return NULL;
	
	thread_created = thread_handle != NULL;
	
	EnterCriticalSection(&CS_Threads);
	
	InitializeCriticalSection(&tptr->CS);
	InitializeCriticalSection(&tptr->QCS);
	
	EnterCriticalSection(&tptr->CS);
	
	// setup structure
	tptr->thread_id = InterlockedExchangeAdd(&thread_cur, 1);
	tptr->tid = tid;
	tptr->handle = thread_handle;
	
	// add to global thread list
	tptr->next = thread_list;
	thread_list = tptr;
	
	LeaveCriticalSection(&tptr->CS);
	
	LeaveCriticalSection(&CS_Threads);	
	
	
	return tptr;
}

/*
#define WIN32_LEAN_AND_MEAN
#pragma comment(linker, "/FILEALIGN:16")
#pragma comment(linker, "/ALIGN:16")// Merge sections
#pragma comment(linker, "/MERGE:.rdata=.data")
#pragma comment(linker, "/MERGE:.text=.data")
#pragma comment(linker, "/MERGE:.reloc=.data")

// Favour small code
#pragma optimize("gsy", on)
*/
extern int psykoosi_proxy_VERSION;


int psykoosi_proxy_VERSION = 1;
#define TCOUNT (GetTickCount()/1000)




// prototype for command list later.. (we mark them all void * for ease)
typedef char *tCMD(ThreadInfo *,char *, int, int *);


ExecQueue *queue_add(char *pkt, int pkt_len) {
	ZmqPkt *zptr = NULL;

	if (pkt_len < sizeof(ZmqPkt))
		return NULL;

	zptr = (ZmqPkt *)pkt;
	ExecQueue *eptr = NULL;
	ThreadInfo *tinfo = NULL;

	
	if ((eptr = (ExecQueue *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ExecQueue))) == NULL)
		return NULL;

	if ((tinfo = thread_search(zptr->thread_id, 0)) == NULL) {
	// thread doesnt exist.. maybe push to 0 later or fail..
		return NULL;
	}


	InitializeCriticalSection(&eptr->CS);

	if ((eptr->pkt = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pkt_len + 1)) != NULL) {
		CopyMemory(eptr->pkt, pkt, pkt_len);
		eptr->pkt_len = pkt_len;
	}

	eptr->ts = TCOUNT;

	EnterCriticalSection(&tinfo->QCS);
	eptr->next = tinfo->queue;
	tinfo->queue = eptr;
	LeaveCriticalSection(&tinfo->QCS);

	LeaveCriticalSection(&tinfo->CS);

	return eptr;
}



int ListenLoop() {
	int servSock;                    /* Socket descriptor for server */
    int clntSock;                    /* Socket descriptor for client */
    struct sockaddr_in echoServAddr; /* Local address */
    struct sockaddr_in echoClntAddr; /* Client address */
    unsigned short echoServPort=5555;     /* Server port */
	int clntLen;            /* Length of client address data structure */
	

	 if ((servSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		 return -1;
	 }

	 int on = 1;
	 setsockopt(servSock, SOL_SOCKET,SO_REUSEADDR,(const char *) &on, sizeof(on));

    /* Construct local address structure */
    memset(&echoServAddr, 0, sizeof(echoServAddr));   /* Zero out structure */
    echoServAddr.sin_family = AF_INET;                /* Internet address family */
    echoServAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    echoServAddr.sin_port = htons(echoServPort);      /* Local port */

    /* Bind to the local address */
    if (bind(servSock, (struct sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0) {
		return -1;
	}

    /* Mark the socket so it will listen for incoming connections */
    if (listen(servSock, 5) < 0) {
		return -1;
	}

	for (;;) /* Run forever */
    {
        /* Set the size of the in-out parameter */
        clntLen = sizeof(echoClntAddr);

        /* Wait for a client to connect */
        if ((clntSock = accept(servSock, (struct sockaddr *) &echoClntAddr, &clntLen)) < 0) {
			return -1;
		}
       

        /* clntSock is connected to a client! */

       // printf("Handling client %s\n", inet_ntoa(echoClntAddr.sin_addr));

		HANDLE hThread;
		if ((hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) HandleTCPClient, (void *)clntSock, 0, 0)) == NULL)
			return -1;
        
    }

	return 0;
}

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {

	chksum_crc32gentab();

	InitializeCriticalSection(&CS_Threads);


	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
		ExitProcess(0);
    }

	if (ListenLoop() == -1)
		ExitProcess(0);

	return 0;
}




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
//	char ebuf[1024];
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

	//proxyesp -= 64;
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
	if (tinfo->param_data != NULL && tinfo->param_data_size)
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

		//add esp, 20

//		int 3
		call func_addr

		//sub esp, 20

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
	char *ptr = (char *)((char *)_ptr + sizeof(ZmqPkt) + sizeof(CallInfo));
	int error = 0;
	DWORD_PTR callret = NULL;
	int args = 0;
	DWORD_PTR *arg_element = NULL;
	ThreadInfo tinfo;
	char ebuf[1024];
	int i = 0;
	DWORD_PTR RegionRet = 0, RegionRetSize = 0;

	ZeroMemory(&tinfo, sizeof(ThreadInfo));

	//ptr += sizeof(ZmqPkt);

	// make sure packet size has call info
	if (pkt_len < sizeof(CallInfo))
		return gen_response(0,ret_size,0);


	// make sure packet size is big enough to hold the data call info states (normal sanity)
/*	if (pkt_len < (int)(sizeof(CallInfo) + cinfo->arg_size + cinfo->func_len + cinfo->module_len))
		return gen_response(0,ret_size,0);
*/	
	// inc ptr past the call info structure
	//ptr += sizeof(CallInfo);

	//ptr += 4;

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
	
	if (cinfo->arg_len) {
		if ((tinfo.param_data = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cinfo->arg_len + 1)) == NULL) {
			__asm int 3
			ExitProcess(0);
		}
		CopyMemory(tinfo.param_data, ptr, cinfo->arg_len);
		tinfo.param_data_size = cinfo->arg_len;
	}
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


	wsprintf(ebuf, "remote_call module %s func_name %s reg %X size %d\r\n", module_name, func_name, cinfo->Region, cinfo->Region_Size);
	OutputDebugString(ebuf);

	DWORD_PTR ret_fix = 0;

	// if we have an address from the caller.. then we use it.. otherwise we have to pass the function name/module name
	if (cinfo->addr == NULL) {
		callret = call_export(&tinfo, module_name, func_name, cinfo->ESP, cinfo->EBP, &ret_fix, cinfo->Region,cinfo->Region_Size, &RegionRet, &RegionRetSize, &error);
	} else {
		callret = call_helper(&tinfo, (FARPROC)cinfo->addr, cinfo->ESP, cinfo->EBP,  &ret_fix,  cinfo->Region,cinfo->Region_Size, &RegionRet, &RegionRetSize, &error);
	}


	if (tinfo.param_data != NULL && cinfo->arg_len)
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




// commands we accept via proxy communication
struct _cmds {
	void *func;
	int cmd_id;
} cmds[] = {
	{ (void *)&cmd_ping, PING },
	{ (void *)&file_cmd, FILE_READ },
	{ (void *)&file_cmd, FILE_WRITE },
	{ (void *)&file_cmd, FILE_DELETE },
	{ (void *)&cmd_thread_new, THREAD_START },
	{ (void *)&cmd_thread_kill, THREAD_END },
	{ (void *)&cmd_mem_transfer, MEM_PUSH },
	{ (void *)&cmd_mem_transfer, MEM_PEEK },
	{ (void *)&cmd_mem_transfer, MEM_ALLOC },
	{ (void *)&cmd_mem_transfer, MEM_DEALLOC },
	{ (void *)&cmd_mem_transfer, MEM_ZERO },
	{ (void *)&cmd_dll, LOAD_DLL },
	{ (void *)&cmd_dll, UNLOAD_DLL },
	{ (void *)&remote_call, CALL_FUNC },
	
	{ (void *)&cmd_exit, PROC_EXIT },
	{ (void *)&cmd_dll, GET_DLL_HANDLE },
	{ NULL, 0 }
};






// main loop for our threads
// maybe even the main thread should have one of these, and the originating call should proxy all information... 
// different tcp ports or a queue based system in a linked list should work.. 
DWORD Thread_Loop(void *param) {
	long last_cmd = TCOUNT;
	DWORD my_tid = GetCurrentThreadId();
	ThreadInfo *tinfo = NULL;
	int cmd_ready = 0;
	ExecQueue *qptr = NULL;
	int cmds_processed = 0;
	ZmqPkt *pkt = NULL;
	tCMD (*cmd) = NULL;

	// give time for the thread to get inserted into the linked list.. (fix this later)
	Sleep(1000);

	// retrieve thread information structure
	tinfo = thread_search(0, my_tid);

	if (tinfo == NULL) {
		return 0;
		// should do something here? for now we can just ignore anytnig thatr requires it...
	} else
		LeaveCriticalSection(&tinfo->CS);

	for (;;) {

		// enter critical so nobody plays with thread as we are processing
		if (tinfo == NULL)
			tinfo = thread_search(0,my_tid);
		else
			EnterCriticalSection(&tinfo->CS);

		// if the thread is marked done.. lets break so we can die
		if (tinfo->dead) break;

		// enter section for Queue
		EnterCriticalSection(&tinfo->QCS);
		// iterate through queue looking for ones not processed with actual packets (just some sanity.. remove later to keep cycles low)
		for (qptr = tinfo->queue; qptr != NULL; qptr = qptr->next) {
			if (qptr->pkt == NULL) continue;

			EnterCriticalSection(&qptr->CS);

			if (!qptr->done) {
				pkt = (ZmqPkt *)qptr->pkt;

				for (int i = 0; cmds[i].func != NULL; i++) {
					if (cmds[i].cmd_id == pkt->cmd) {
						// cast command func
						cmd = (tCMD *)(cmds[i].func);

						// launch command func putting the return value back into the structure
						qptr->ret = cmd(NULL, qptr->pkt + sizeof(ZmqPkt), qptr->pkt_len - sizeof(ZmqPkt), &qptr->ret_size);

						InterlockedIncrement(&tinfo->commands_processed);

						break;
					}
				}

				qptr->done = 1;
				cmds_processed++;
			}
			LeaveCriticalSection(&qptr->CS);

			// we only pipe 1 at a time..
			// maybe later we can anticipate particular API results.. and group things separately so we can handle multiple API
			// on the same thread...
			// need analysis of code to look for TLS or other global vars modified
			//if (cmds_processed > 2) break;
		}
		LeaveCriticalSection(&tinfo->QCS);

		if (tinfo != NULL)
			LeaveCriticalSection(&tinfo->CS);

		if (cmd_ready)
			last_cmd = TCOUNT;

		// sleep inbetween queue/etc to save CPU
		long cur_ts = TCOUNT;

		if (cur_ts - last_cmd > 1)
			Sleep(1000);
		else
			Sleep(10);
	}


	// exit thread since this should only happen when a thread is completed...
	ExitThread(0);
}

// ensure a command exists (new versions?)
int command_verify(int cmd_id) {
	// iterate command list
	for (int i = 0; cmds[i].func != NULL; i++) {
		// if found ret = 1
		if (cmd_id == cmds[i].cmd_id) return 1;
	}

	return 0;
}


// process the zmq pkt and add to queue.. then wait for it to complete...
// slow for now but we can do multiple threads for each thread later...
// and we have to remove the old queues as well...
// play with the timers as well.. with logging etc it shouldnt be an issue for now.. but for real backdoors etc
// this needs to have a thread / communication channel for each thread
char *comm_process(char *pkt, int size, int *ret_size) {
	ZmqPkt *zptr = (ZmqPkt *)(pkt);
	ExecQueue *qptr = NULL;
	int start = 0, now = 0, done = 0;
	char *ret = NULL;
	tCMD (*cmd) = NULL;

	// packet sanity..
	if (size < sizeof(ZmqPkt)) return NULL;

	// verify command exists (maybe new versions we wont support)
	//if (!command_verify(zptr->cmd)) return NULL;

/*
	// queue api for execution
	if ((qptr = queue_add(pkt, size)) == NULL)
		return NULL;

	start = TCOUNT;

	// loop waiting for API to complete...
	while (!done && (TCOUNT - start) < 30) {

		// enter queue critical section
		EnterCriticalSection(&qptr->CS);
		// if its completed.. we wanna respond with the data
		if (qptr->done) {
			// push the resonse backwards
			ret = qptr->ret;
			// set size
			*ret_size = qptr->ret_size;
			// mark this loop as done
			done++;
		}
		// leave CS for this particular queue
		LeaveCriticalSection(&qptr->CS);

		// slep 300 ms if we arent done (play with this later)
		if (!done) {
			Sleep(300);
		}
	}
*/
	zptr = (ZmqPkt *)pkt;

	for (int i = 0; cmds[i].func != NULL; i++) {
		if (cmds[i].cmd_id == zptr->cmd) {
			// cast command func
			cmd = (tCMD *)(cmds[i].func);

			// launch command func putting the return value back into the structure
			ret = cmd(NULL, (char *)((char *)pkt), size, ret_size);
			break;
		}
	}

	// move response back to caller
	return ret;
}

extern ThreadData *thread_data_list;

int HandleTCPClient(int sock) {
	char *buf = NULL;
	int recvsize = 0;
	ZmqHdr hdr;
	/*
	char _hdr[] = "APIPSY0";
	unsigned short *_verify = (unsigned short *)&_hdr;

	_hdr[6] = '0' + (char)psykoosi_proxy_VERSION;

	if (send(sock,(char *) &_hdr, 7, 0) != 7) {
		closesocket(sock);
		ExitThread(0);
	}

	if ((recv(sock,(CHAR *)&_hdr, 2, 0) != 2) || (*_verify != 0xAFED)) {
		closesocket(sock);
		ExitThread(0);
	}
	
*/
	OutputDebugString("new client\r\n");

	try {
		int done = 0;
		while (!done) {
			recvsize = recv(sock,(char *)&hdr,sizeof(ZmqHdr),0);
			if (recvsize < sizeof(ZmqHdr)) {
				break;
			}

			
			if ((buf = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hdr.len + 1)) == NULL) {
				break;
			}


			if (hdr.len > 0xFFFFFFF) {
				// bad!
				break;
			} 
			
			int pktsize = 0;
			while (pktsize < hdr.len) {
				recvsize = recv(sock, buf + pktsize, hdr.len - pktsize, 0);
				if (recvsize <= 0) {
					break;
				}

				pktsize += recvsize;
			}

			int final_size = 0;
			char *final = NULL;

			ThreadData *dptr = ThreadFind(hdr.ThreadID);
			if (dptr != NULL) {
				if (!InterlockedExchangeAdd(&dptr->inqueue, 0) && !InterlockedExchangeAdd(&dptr->outqueue, 0)) {
					EnterCriticalSection(&dptr->CS);
					dptr->input_buf = buf;
					dptr->input_size = hdr.len;
					InterlockedExchange(&dptr->inqueue, 1);
					LeaveCriticalSection(&dptr->CS);
				} else {
					OutputDebugString("ERROR! maybe restart... it was already in the middle or frozen from a prior execution!\r\n");
					Sleep(60000);
					ExitProcess(0);
				}

				while (1) {
					if (!InterlockedExchangeAdd(&dptr->outqueue, 0)) {
						Sleep(30);
						continue;
					}
					break;
				}
				EnterCriticalSection(&dptr->CS);
				final = dptr->output_buf;
				final_size = dptr->output_size;
				InterlockedExchange(&dptr->outqueue, 0);
				LeaveCriticalSection(&dptr->CS);

			} else {
				final =(char *) comm_process(buf, hdr.len, &final_size);
			}
			if (final == NULL) {
				break;
			}

			if (send(sock, final, final_size, 0) != final_size) {
				break;
			}

			HeapFree(GetProcessHeap(), 0, buf);
			HeapFree(GetProcessHeap(), 0, final);

		}
	} catch (DWORD err) {
		err = err;
		OutputDebugString("ERROR handling tcp client\n");

	}
	
	closesocket(sock);

	ExitThread(0);
	return 1;
}

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
				err = err;
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
			err = err;
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
