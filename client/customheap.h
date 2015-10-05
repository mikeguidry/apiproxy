typedef struct _custom_heap {
	struct _custom_heap *next;
	DWORD_PTR address;
	SIZE_T size;
	int free;
}CustomHeap;

typedef struct _custom_heap_area {
	struct _custom_heap_area *next;
	DWORD_PTR HeapBase;
	DWORD_PTR HeapLast;
	DWORD_PTR HeapMax;
	CustomHeap *HeapList;
} CustomHeapArea;

BOOL CustomHeapFree(ClientThreadInfo *, DWORD_PTR address);
BOOL CustomHeapIsValidHeap(ClientThreadInfo *,LPVOID address);
LPVOID CustomHeapAlloc(ClientThreadInfo *,SIZE_T size);


