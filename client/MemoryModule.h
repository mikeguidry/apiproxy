/*
 * Memory DLL loading code
 * Version 0.0.3
 *
 * Copyright (c) 2004-2012 by Joachim Bauch / mail@joachim-bauch.de
 * http://www.joachim-bauch.de
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.h
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Joachim Bauch are Copyright (C) 2004-2012
 * Joachim Bauch. All Rights Reserved.
 *
 */

#ifndef __MEMORY_MODULE_HEADER
#define __MEMORY_MODULE_HEADER

#include <Windows.h>

typedef struct {
	PIMAGE_NT_HEADERS headers;
	unsigned char *codeBase;
	HMODULE *modules;
	int numModules;
	int initialized;
	DWORD_PTR ImportReplace;
	void *data_segment;
	int data_size;
} MEMORYMODULE, *PMEMORYMODULE;

typedef void (WINAPI *tAddRegion)(DWORD_PTR Addr, DWORD_PTR Size);

typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

typedef PMEMORYMODULE HMEMORYMODULE;

#ifdef __cplusplus
extern "C" {
#endif

	SIZE_T MemorySizeNeeded(const void *data);
//HMEMORYMODULE MemoryLoadLibrary(const void *, DWORD_PTR);
	HMEMORYMODULE MemoryLoadLibrary(const void *data, void *force_base, DWORD_PTR ImportReplace, int exec, unsigned char **code_addr, void **func, tAddRegion addreg);

FARPROC MemoryGetProcAddress(HMEMORYMODULE, const char *);

void MemoryFreeLibrary(HMEMORYMODULE);

#ifdef __cplusplus
}
#endif

#endif  // __MEMORY_MODULE_HEADER
