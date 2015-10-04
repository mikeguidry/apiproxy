char *cmd_dll(char *ptr, int pkt_len, int *ret_size);
char *cmd_mem_transfer(void *,char *_ptr, int pkt_len, int *ret_size);
char *cmd_thread_kill(char *_ptr, int pkt_len, int *ret_size);
char *cmd_thread_new(char *_ptr, int pkt_len, int *ret_size);
char *gen_response(int response, int *size, int additional);
char *file_cmd(char *_ptr, int pkt_len, int *ret_size);
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
	CMD_DONE		// just placeholder for the end
	
};

