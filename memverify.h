typedef struct _region_crc {
	DWORD_PTR Addr;
	unsigned int *crc;
	DWORD_PTR Size;
} RegionCRC;

#define REGION_BLOCK 128

RegionCRC *CRC_Region(DWORD_PTR Addr, DWORD_PTR Size);
char *CRC_Verify(RegionCRC *region, DWORD_PTR *Size, int);
void RegionFree(RegionCRC **rptr);