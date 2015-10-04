// 0mq packet of incoming...
#pragma pack(1)
typedef struct _zero_pkt {
    int type;
    int len;
} ZmqHdr;
#pragma pack(pop)

typedef struct _zmq_pkt {
	unsigned int crc;
	int thread_id; // 0 for global
	unsigned char cmd;
	unsigned short len; // len of cmd after pkt
} ZmqPkt;

// our response packet
typedef struct _zmq_ret {
	int response;		// return code
	int extra_len;		// how much data after packet header...
} ZmqRet;


// information for functions..

// transfer of memory
typedef struct _mem_info {
	int _virtual;
	unsigned char cmd;  // MEM_PUSH, or MEM_PEEK
	void *addr;			// address
	int len;			// len of data after packet
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
	unsigned char cmd;
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

#define REGION_BLOCK sizeof(unsigned int)