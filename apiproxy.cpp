#define WIN32_LEAN_AND_MEAN
#pragma comment(linker, "/FILEALIGN:16")
#pragma comment(linker, "/ALIGN:16")// Merge sections
#pragma comment(linker, "/MERGE:.rdata=.data")
#pragma comment(linker, "/MERGE:.text=.data")
#pragma comment(linker, "/MERGE:.reloc=.data")

// Favour small code
#pragma optimize("gsy", on)

/* 

  PSYKOOSI - WIN32 API PROXY
  

   For fuzzing so we can proxy from xeon PHI -> wine or a real windows machine...
   each socket connection should fork and support another PID.. so the software being fuzzed can do real tasks
   as if its running on a machine...
   it might be a bit of high overhead to begin but its much bett3er than supporting lots of API from scratch
   itll also be easier to save the responses and manipulate later..

  it needs to determine if a particular response, or input variable is also a memory address.. if so it needs to be copied along side

  so we need
  alloc,free
  push/peek memory
  string alloc
  string conversion
  call type detection (maybe.. might note ven require this at all.. it should just push them as its detected)
  write, read file (to push over data files, etc if necessary
  call
  maybe UI manipulation to support entries.. UI should work perfectly during proxy :)

  def do some caching on functions... 
  also allow pipelining of data from psykoosi for keeping the memory in the proxy process the same as psykoosi as it executes
  also see about doing copy on write (for threads) so one thread can be replciated + all process memory to a new process
  for a particular branch, or another thread/execution/fuzz session while the orig is untouched and functions properly

  this could also be used backwards with wine to allow an applications tasks to be performed remotely for security, etc
  and could also allow proxying specific functions like UI which would allow to run things split
  wine on PHI on specific core + UI on windows box
 
  very simple but allows a lot of things to happen :)

  Heap may need to be replicated for each call (so maybe detect changes since last push)
  anything with advanced pointer of pointer should be detected.. prob just skip anything like this that doesnt function properly..
  maybe auto connect to secondary tcp/ip on another app so if it crashes, it can just restart.. also for allowing numerous connections
  it will also be useful depending on how the linear fuzzing (natively without psykoosi) works

  maybe do the same with linux and LD and OSX+its loader

  create a generic protocol for this to be used for offloading applications in general to the PHI
  check into windows 2003 source code, and other modules to see about doing it on kernel level with shared memory/RDMA
  
	recursively scan all windows DLLs using psykoosi and dump databases of all API functions... try to classify, or analyze using psykoosi
	to determine if emulated if they touch particular memory addresses,etc (to get an idea of ones that will crash ahead, and then we can work on
	emulating those specifically, or just ignoring and returning whatever a real app uses once)

  log all results in beginning to a file + subsequent calls to any API using the same addresses (so if something uses the same handle, we should log its results)
  so we can just shutdown the API proxy if we have responses for everything that isnt app specific like checking particular data etc
  this should be able to be verified using the emulator and seeing if read/writes happen at particular addresses and/or changes using diff or modified handles..
  maybe give a false handle to see if it still returns the same

  try using zeromq first.. 

  maybe use as a proxy for a backdoor to perform particular commands on a host with only a stub existing on the machine..
  if small enough it could just be injected into another task and have the server/service look for a particular tag
  the stub can perform all API however the real virus code exists on another machine so literally nothing would give info about what its doing

  support multiple threads maybe with zeromq.. so definitely have queueing on both sides.. and maybe understanding threads at least
  + TLS needs to be supported in the beginning..

  ZeroMQ pkts

  <thread id><cmd><args>

  cmds:
  start thread - creates a new zeromq port for a new thread (start address) and returns and keeps internal in a structure.. responds with TID
  push tls, pop tls - has to be supported for some API..
  push file, get file - for data files
  push,peek data to/from memory  - should be buffered.. check biggest amount in zeromq
  list all mem address ranges.. 
  dump all mem addresses (stream them to the client)
  write stream of ranges of memory to memory
  turn on/off logging
  kill thread - exitthread...
  loadlibrary
  call func
  alloc string
  free mem
  kill proc


  also allow on win32 to hijack any specifi range of win32 DLL using GetProcAddress or IAT to redirect certain API to another machine for security, or just
  to offload.. so 3 machines could do diff tasks from an APP.. the machine running the majority of the API would be the heavy one..
  and the user one can be for UI, and 3rd could be for file saving,etc.. even one could be WINE using the same system
  if API doesnt exist (newer) just send to the next machine



  can load a virus module into memory using in memory DLL injection and then redirect all of its IAT,GetProcAddress to a proxied system
  to allow a particular DLL to handle all Win32 API on a remote machine without the machine having any of the code itself outside of the small STUB
  can compress code and inject it and modify another legit app and resign/manipulate windows signing to get it persistent
  put the system into hypervisor so only the small stub is on a tcp/ip connection.. so it can literally be used to run any code on the machine forever
  or in a firmware.. see how small it can be wrote in ASM with tcp/ip alone instead of zeromq


  ** try to emulate 64bit to 32bit and vice-versa... this can allow proxying from one to the other for a system...

  need to develop a way to reverse load code across zeromq or the communication channel.. so the proxy can load and run stuff on both sides
  kinda like vcpu but virtualizing execution.. maybe allow connecting to a new proxy and give it all code/data it needs to execute having it
  communicate backwards only specific API for UI etc.. and check into wine,cygwin as a way for cross platform
  
  create a p2p system that auto senses network nodes with CPU cycles to waste.. so high task stuff can be offloaded on to neighbors or designating
  particular machines on the node to store all files, or specific nodes to handle all tcp/ip traffic.. like a web gateway but handling all non local traffic via
  the system...
  
  try to detect loops whether using vtune output at first, or automated later to offload particular loops without requiring pragmas
  
  further investigate icc output and see if its easy to rewrite binary to do it without the compiler and auto detecting hot spots and auto offloading/arranging threads


  for a backdoor to work properly with all API we need a local copy of the code so we can ensure any memory read/writes are replicated back through if its
  necessary by the app.. generally wont be necessary unless writing a file etc
  need to emulate the called function locally to get that list.. if the API for the calls were created properly it shouldnt be necessary
  but useful to automate


TODO: add zeromq communication from nginx adserver module.. and implement client into psykoosi and ready for testing.. make some generic test using basic API..
or generate a DLL and hijack all IAT or a secondary list for the DLL to go to zeromq and test like that

  this side of thingse can be very 'stupid' .. so a backdoor can be small.. but the client side has to do the most work determining if
  data is being passed or should be allocated, etc.... it can have extra error correction on this side maybe using x86_emulate.c cross compiled but
  not worth it

  replacing IAT of heap allocation functions are a way to log all writes easily on the api proxy without a large amount of code so we can transfer the data backwards to the client


  for backdoor version remove region verification.. do all push/pull on client and use emulation to check hot spots of memory to sync
  encode/obf the call_helper

*/
#include <windows.h>
#include "structures.h"
#include "commands.h"
#include "threads.h"
#include "bridge.h"
#include <winsock.h> 
#include "crc.h"

int psykoosi_proxy_VERSION = 1;
#define TCOUNT (GetTickCount()/1000)



extern CRITICAL_SECTION CS_Threads;

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

	if ((tinfo = thread_search(zptr->thread_id, 0)) == NULL)
	// thread doesnt exist.. maybe push to 0 later or fail..
		return NULL;


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




// commands we accept via proxy communication
struct _cmds {
	void *func;
	int cmd_id;
} cmds[] = {
	//{ (void *)&file_cmd, FILE_READ },
	//{ (void *)&file_cmd, FILE_WRITE },
	//{ (void *)&file_cmd, FILE_DELETE },
	{ (void *)&cmd_thread_new, THREAD_START },
	{ (void *)&cmd_thread_kill, THREAD_END },
	{ (void *)&cmd_mem_transfer, MEM_PUSH },
	{ (void *)&cmd_mem_transfer, MEM_PEEK },
	{ (void *)&cmd_mem_transfer, MEM_ALLOC },
	{ (void *)&cmd_mem_transfer, MEM_DEALLOC },
	{ (void *)&cmd_mem_transfer, MEM_ZERO },
	//{ (void *)&cmd_dll, LOAD_DLL },
	//{ (void *)&cmd_dll, UNLOAD_DLL },
	{ (void *)&remote_call, CALL_FUNC },
	{ (void *)&cmd_ping, PING },
	{ (void *)&cmd_exit, PROC_EXIT },
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

int HandleTCPClient(int sock) {
	char *buf = NULL;
	int recvsize = 0;
	ZmqHdr hdr;


	int done = 0;
	while (!done) {
		recvsize = recv(sock,(char *)&hdr,sizeof(ZmqHdr),0);
		if (recvsize < sizeof(ZmqHdr)) {
			break;
		}

		
		if ((buf = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hdr.len + 1)) == NULL) {
			__asm int 3
			ExitProcess(0);
		}

		
		int pktsize = 0;
		while (pktsize < hdr.len) {
			recvsize = recv(sock, buf + pktsize, hdr.len - pktsize, 0);
			if (recvsize <= 0) {
				return 0;
				__asm int 3
				ExitProcess(0);
			}

			pktsize += recvsize;
		}/*
		// now we read the full packet length
		recvsize = recv(sock, buf, hdr.len, 0);

		if (recvsize < hdr.len) {
			__asm int 3
			ExitProcess(0);
		}*/

		int final_size = 0;
		char *final = comm_process(buf, hdr.len, &final_size);

		if (final == NULL) {
			return 0;
			__asm int 3
			ExitProcess(0);
		}

		if (send(sock, final, final_size, 0) != final_size) {
			return 0;
			__asm int 3
			ExitProcess(0);
		}

		HeapFree(GetProcessHeap(), 0, buf);
		HeapFree(GetProcessHeap(), 0, final);

	}
	
	return sock;
}

int bindport() {
 int servSock;                    /* Socket descriptor for server */
    int clntSock;                    /* Socket descriptor for client */
    struct sockaddr_in echoServAddr; /* Local address */
    struct sockaddr_in echoClntAddr; /* Client address */
    unsigned short echoServPort=5555;     /* Server port */
     int clntLen;            /* Length of client address data structure */
 /* Create socket for incoming connections */
    if ((servSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
__asm int 3

    /* Construct local address structure */
    memset(&echoServAddr, 0, sizeof(echoServAddr));   /* Zero out structure */
    echoServAddr.sin_family = AF_INET;                /* Internet address family */
    echoServAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    echoServAddr.sin_port = htons(echoServPort);      /* Local port */

    /* Bind to the local address */
    if (bind(servSock, (struct sockaddr *) &echoServAddr, sizeof(echoServAddr)) < 0)
		__asm int 3

    /* Mark the socket so it will listen for incoming connections */
    if (listen(servSock, 5) < 0)
        __asm int 3

		 for (;;) /* Run forever */
    {
        /* Set the size of the in-out parameter */
        clntLen = sizeof(echoClntAddr);

        /* Wait for a client to connect */
        if ((clntSock = accept(servSock, (struct sockaddr *) &echoClntAddr, &clntLen)) < 0)
			__asm int 3
       

        /* clntSock is connected to a client! */

       // printf("Handling client %s\n", inet_ntoa(echoClntAddr.sin_addr));

        HandleTCPClient(clntSock);
    }

	return 0;
}

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {

	chksum_crc32gentab();

	InitializeCriticalSection(&CS_Threads);


	WSADATA wsaData;                 /* Structure for WinSock setup communication */

	if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
		ExitProcess(0);
    }

	bindport();
	ExitProcess(0);

	return 0;
}




/*
// main function with main loop
int Communications_Loop() {
    void *data = NULL;
    int r_len = 0;
    int timeout = 2000;
    unsigned char *s_data = NULL;
    int s_len = 0;
    int s;
    int a;
    int len;
    int querylen;
    void *context = NULL;
    void *responder = NULL;
    zmq_msg_t omsg, imsg;
    int flags = 0;
    int t=0;

 
	// allow changing ports later
    sprintf(ipc, "tcp://*:2500");

    // initialize zeromq stuff...
   if ((context =  zmq_ctx_new()) == NULL) {
		__asm int 3
		ExitProcess(0);
    }

    // create a new rep socket for (req/rep)
    if ((responder = zmq_socket(context, ZMQ_REP)) == NULL) {
		__asm int 3
		ExitProcess(0);
    }

    // send and receieve timeout.. better for everyone
    zmq_setsockopt(responder, ZMQ_RCVTIMEO, &timeout, sizeof(int));
    zmq_setsockopt(responder, ZMQ_SNDTIMEO, &timeout, sizeof(int));

    // bind zeromq ipc
    if (zmq_bind(responder, ipc) != 0) {
		__asm int 3
		ExitProcess(0);
    }

    // for timers...
    _time = time(0);

    // main loop
    while (1) {
        // zero out some variables...
        s_len = 0;
        s_data = NULL;
        found_command=0;

        _now=time(0);

        if (zmq_msg_init (&imsg) != 0) {
			__asm int 3
			ExitProcess(0);
        }

        // check for a msg
        if (zmq_msg_recv(&imsg, responder, 0) == -1) {
                if (errno != EAGAIN) break;

                // if no traffic within 5 seconds, then we sleep a bit longer...
                if ((_now - _last) > 5)
					Sleep(500);
				else
					Sleep(100);

        } else {

                // obtain length and ptr to the packet data
                len = zmq_msg_size(&imsg);
                data = zmq_msg_data(&imsg);
        
        	// if the ptr is NULL, or length is less than our own packet header..bad packet... (shouldnt happen)
        	if (data && ((unsigned)len >= (unsigned)sizeof(ZeroPkt))) {
        		// do whatever with data here... always be sure to set s_data, and s_len
        		ZeroPkt *pkthdr = (ZeroPkt *)data;
                        
        		
				// find the specific ZMQ command which this is for
        		for (i = 0; Commands[i].func != NULL; i++) {
        			if (pkthdr->type == Commands[i].type) {
        				// run that specific function with pointers to our own variables for responding later
        				(*Commands[i].func)((unsigned char *)data, len, &s_data, &s_len);
        				// did we find this command? (should we expect output variables to be filled)
        				found_command=1;
        				break;
        			}
        		}
            
        		// initialize an outgoing zeromq message of X len
        		if (zmq_msg_init_size(&omsg, (s_len > 0 ? s_len : 4)) == -1) break;
        		// get a pointer to the data section of it
        		data = zmq_msg_data(&omsg);
            
        		// if we didn't find the command, or something went wrong with the return data..
        		// we have to send something through otherwise the ZMQ will be locked up...
        		if (!found_command || s_data == NULL || !s_len) {
        			CopyMemory(data, null_str, 4);
        			// send off a NULL msg just so we dont block/lockup the ZMQ IPC
        			if (zmq_sendmsg(responder, &omsg, 0) == -1) break;
        		} else {
        			// initialize an outgoing message of X len
        			//zmq_msg_init_size(&omsg, s_len);
        			// obtain function pointer to it..
        			//data = zmq_msg_data(&omsg);
        			// copy outgoing data
        			CopyMemory(data, s_data, s_len);
        			// send off....
        			if (zmq_sendmsg(responder, &omsg, 0) == -1) break;
                
        			// you don't have to free s_data because it happens to get free'd by zeromq due to some zerocopy code
        			HeapFree(GetProcessHeap(), 0, _data);                
        		}
        		
        		data = NULL;
            
        		// deconstruct the outgoing message
        		zmq_msg_close(&omsg);

        	}
        
        } // end of if recv == -1
        
        // deconstruct the outgoing message
        zmq_msg_close(&imsg);
	}

    
    // close the responder (IPC)
    if (responder != NULL) zmq_close(responder);
    
    // destroy main zmq context...
    if (context != NULL) zmq_ctx_destroy(context);
}

*/

