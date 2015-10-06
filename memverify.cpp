#include <windows.h>
#include "memverify.h"
#include "crc.h"

int PushData(DWORD_PTR start, DWORD_PTR size);

RegionCRC *CRC_Region(DWORD_PTR Addr, DWORD_PTR Size) {
	RegionCRC *cptr = NULL;
	int crc_count = Size / REGION_BLOCK;
	
	char ebuf[1024];
	//wsprintf(ebuf, "Region Verify crc Addr %d Size %d count %d\r\n", Addr, Size, crc_count);
	//OutputDebugString(ebuf);
	
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
	
	
	//wsprintf(ebuf, "Region check crc Addr %d Size %d count %d modified = %d\r\n", region->Addr, region->Size, crc_count, modified);
	//OutputDebugString(ebuf);
	
	
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
					CopyMemory(mData, ptr, REGION_BLOCK);
					//*mData = *(DWORD_PTR *)(ptr);				
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
