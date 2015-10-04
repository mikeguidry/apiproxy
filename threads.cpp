#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include "structures.h"
#include "file.h"
#include "commands.h"


// declarations
DWORD Thread_Loop(void *param);

// global CSs
CRITICAL_SECTION CS_Threads;

// global linked lists
ThreadInfo *thread_list = NULL;

// global variables
long thread_cur = 0;
long thread_active = 0;


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
	if ((thread_handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) Thread_Loop, (void *)NULL, 0, &tid)) == NULL)
		return NULL;

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


