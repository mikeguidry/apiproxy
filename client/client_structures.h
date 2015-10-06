

// linked list of all shadow regions (memory that is to be the same across both processes)
typedef struct _shadow_region {
	struct _shadow_region *next;
	DWORD_PTR address;
	SIZE_T size;
	// constantly determine if it has changed between calls and reupload modifications
	// using checksums on smaller amount of bytes
	int verify;
	// for non verify to only push once
	int pushed;
	RegionCRC *LastSync;
} ShadowRegion;

// a thread + all of its information required
typedef struct _client_thread_info {
	struct _client_thread_info *next;
	DWORD_PTR StackLow;
	DWORD_PTR StackHigh;
	void *memory_areas;
	CRITICAL_SECTION CSmemory;
	CRITICAL_SECTION CSshadow;
	ShadowRegion *ShadowList;
	ShadowRegion *ShadowMem;
	CONTEXT ctx;

} ClientThreadInfo;


typedef struct _redirects {
	struct _redirects *next;
	DWORD_PTR addr;
	char *module;
	char *function;
	int cleanup;
} Redirect;

typedef struct _pkt {
	int module_len;
	int func_len;
	int arg_size;
} ExecPkt;


