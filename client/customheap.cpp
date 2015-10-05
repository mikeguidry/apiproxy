#define CUSTOMHEAP_CPP
#include <Windows.h>
#include "../structures.h"
#include "../memverify.h"

#include "client_structures.h"

#include "customheap.h"

// allocate space in the heap region using a custom allocator...
// do not move any heap around once we have given out the address....
// if a free occurs, zero the memory and find the closest length for the next allocation in 
// free'd or give new and increase the region
LPVOID CustomHeapAlloc(ClientThreadInfo *tinfo, SIZE_T size) {
	char ebuf[1024];
	//wsprintf(ebuf, "CustomHeapAlloc %d\r\n", size);
	//OutputDebugString(ebuf);
	CustomHeapArea *aptr = NULL;
	CustomHeap *hptr = NULL;

	for (aptr = (CustomHeapArea *)tinfo->memory_areas; aptr != NULL; aptr = aptr->next) {
		DWORD_PTR SpaceLeft = aptr->HeapMax - aptr->HeapLast;

		if (SpaceLeft <= 0) {
			for (hptr = aptr->HeapList; hptr != NULL; hptr = hptr->next) {
				// if free'd heap.. can we take this place??
				if (hptr->free && size <= hptr->size) {

					DWORD_PTR SizeLeft = (hptr->size - size);
					// if the size left after we give out this block again is more than 16k..
					// lets put it up for grabs..
					if (SizeLeft > (1024 * 16)) {
						CustomHeap *leftover = (CustomHeap *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CustomHeap));
						if (leftover != NULL) {
							leftover->address = hptr->address + size;
							leftover->size = SizeLeft;

							leftover->next = aptr->HeapList;
							aptr->HeapList = leftover;
						}
					}
					hptr->size = size;

		
					wsprintf(ebuf, "CustomHeapAlloc [%d] returning %p\r\n", size, hptr->address);
					OutputDebugString(ebuf);

					return (void *) hptr->address;
				}

			}

			continue;
			// we ran out of space... 
			//return NULL;
		}
	}

	aptr = NULL;
	hptr = NULL;

	for (aptr = (CustomHeapArea *)tinfo->memory_areas; aptr != NULL; aptr = aptr->next) {
		DWORD_PTR SpaceLeft = aptr->HeapMax - aptr->HeapLast;
		
		if (SpaceLeft <= 0) continue;

		if ((hptr = (CustomHeap *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CustomHeap))) == NULL) {
				wsprintf(ebuf, "CustomHeapAlloc FATAL was asking for %d\r\n", size);
				OutputDebugString(ebuf);

				// fatal!
				return 0;
		}

		hptr->size = size;

		if (aptr->HeapLast == 0) {
			hptr->address = aptr->HeapBase;
		} else {
			hptr->address = aptr->HeapLast;
		}

		aptr->HeapLast = hptr->address + size;

		// ensure we free the space.. fuzzing = fine.. but backdoors. we dont want that memory getting transferred during shadow copy/sync
		ZeroMemory((void *)hptr->address, size);

		hptr->next = aptr->HeapList;
		aptr->HeapList = hptr;
		break;
	}

	wsprintf(ebuf, "CustomHeapAlloc [%d] returning %p [aptr %p hptr %p]\r\n", size, hptr->address, aptr, hptr);
	OutputDebugString(ebuf);

//	__asm int 3
	return (void *)hptr->address;
}

BOOL CustomHeapIsValidHeap(ClientThreadInfo *tinfo, LPVOID address) {
	CustomHeap *hptr = NULL;
	for (CustomHeapArea *aptr = (CustomHeapArea *)tinfo->memory_areas; aptr != NULL; aptr = aptr->next) {
		for (hptr = aptr->HeapList; hptr != NULL; hptr = hptr->next) {
			if (!hptr->free && ((DWORD_PTR)address >= hptr->address) && ((DWORD_PTR)address < (hptr->address + hptr->size))) {
				return true;
			}
		}
	}
	if (hptr == NULL)
		return false;

	return false;
}


BOOL CustomHeapFree(ClientThreadInfo *tinfo, DWORD_PTR address) {
	CustomHeap *hptr = NULL;
	char ebuf[1024];

	wsprintf(ebuf, "CustomHeapFree %p\r\n", address);
	OutputDebugString(ebuf);

	for (CustomHeapArea *aptr = (CustomHeapArea *)tinfo->memory_areas; aptr != NULL; aptr = aptr->next) {
		for (hptr = aptr->HeapList; hptr != NULL; hptr = hptr->next) {
			if (!hptr->free && hptr->address == (DWORD_PTR)address) {
				break;
			}
		}
	}
	if (hptr == NULL) return false;
	hptr->free = 1;
	// lets free.. in case we sync the shadow memory
	//ZeroMemory((void *)hptr->address, hptr->size);
	//maybe tell the remote side to zero memory here too!
	return true;
}
