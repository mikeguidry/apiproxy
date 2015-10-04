int HijackFuncSecurity(void *_orig, int importance, HMODULE base);
int HijackFunc(void **_orig, void *func);
void Unhijack_Funcs(void **_orig, void *func);
int Secure_Myself();
typedef struct _tramp {
	struct _tramp *next;
	DWORD_PTR addr;
	int size;
} Tramp;
