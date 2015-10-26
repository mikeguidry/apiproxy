#ifndef GERENTE_H
#define GERENTE_H
typedef struct _thread_data {
	struct _thread_data *next;
	
	CRITICAL_SECTION CS;
	
	long inqueue;
	long outqueue;
	
	HANDLE hThread;
	DWORD_PTR ThreadID;
	
	char *input_buf;
	int input_size;
	char *output_buf;
	int output_size;
	
	long count;
	
} ThreadData;

ThreadData *ThreadFind(DWORD_PTR ID);
int ThreadInsert(DWORD_PTR ID, HANDLE hThread);
#endif