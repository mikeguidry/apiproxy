#define WIN32_LEAN_AND_MEAN


#include <windows.h>
#include "file.h"

char *FileGetContents(char *name, unsigned long *size) {
	char *ptr = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	unsigned long rw_count = 0;
	unsigned long f_size = 0;

	if ((hFile = CreateFile(name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE)
		return NULL;

	f_size = GetFileSize(hFile, NULL);

	if ((ptr = (char *)HeapAlloc(GetProcessHeap(), 0, f_size + 1)) == NULL)
		goto err;

	if (ReadFile(hFile, ptr, f_size, &rw_count, 0) == 0)
		goto err;

	if (rw_count != f_size)
		goto err;

	*size = rw_count;

	goto ok;
err: ;

	if (ptr != NULL) {
		HeapFree(GetProcessHeap(), 0, ptr);
		ptr = NULL;
	}

ok: ;
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

	return ptr;
}



int FilePutContents(char *name, char *data, int data_size, int append) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	unsigned long rw_count = 0;
	int ret = 1;

	// sanity check
	//if (IsBadReadPtr(data, data_size) != 0) return -1;

	SECURITY_ATTRIBUTES secAttr;
    char secDesc[ SECURITY_DESCRIPTOR_MIN_LENGTH ];
    secAttr.nLength = sizeof(secAttr);
    secAttr.bInheritHandle = FALSE;
    secAttr.lpSecurityDescriptor = &secDesc;
    InitializeSecurityDescriptor(secAttr.lpSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(secAttr.lpSecurityDescriptor, TRUE, 0, FALSE);

	if ((hFile = CreateFile(name, GENERIC_WRITE|GENERIC_READ, FILE_SHARE_READ, &secAttr, append ? OPEN_ALWAYS : CREATE_NEW, 0, 0)) == INVALID_HANDLE_VALUE)
		return -1;


	// if we are appending data.. we go to the end of the file
	if (append)
		SetFilePointer(hFile, 0, 0, FILE_END);

	if (WriteFile(hFile, data, data_size, &rw_count, 0) == 0)
		ret = -1;

	if (rw_count != (DWORD)data_size)
			ret = -1;

	CloseHandle(hFile);

	if (ret == -1)
		DeleteFile(name);

	return ret;
}
