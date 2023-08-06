#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#pragma comment(lib, "winmm.lib")
#include <excpt.h>
#include <string>

using namespace std;



#define skCrypt(str) skCrypt_key(str, __TIME__[4], __TIME__[7])
#define skCrypt_key(str, key1, key2) []() { \
			constexpr static auto crypted = skc::skCrypter \
				<sizeof(str) / sizeof(str[0]), key1, key2, skc::clean_type<decltype(str[0])>>((skc::clean_type<decltype(str[0])>*)str); \
					return crypted; }()


void hide_string(string& str) {
	/*
	This function takes a string as input and replaces each character with a null character.
	This is useful for hiding sensitive information from being displayed in the debugger.

	Parameters:
	str (string): The string to be hidden

	Returns:
	None
	*/
	for (int i = 0; i < str.length(); i++) {
		str[i] = '\0';
	}
}

char* hide_string1(const char* str) {
	/*
	This function takes a string and returns a pointer to a char array with the same content.
	The returned char array is allocated on the heap and must be freed by the caller.
	This function is useful for hiding strings from debuggers.

	Parameters:
	str (const char*): The string to be hidden

	Returns:
	char*: A pointer to a char array with the same content as the input string
	*/
	size_t len = strlen(str);
	char* hidden = new char[len + 1];
	for (size_t i = 0; i < len; i++) {
		hidden[i] = str[i] ^ 0xFF; // XOR each character with 0xFF to hide it
	}
	hidden[len] = '\0';
	return hidden;
}

BOOL NtClose_InvalideHandle()
{
	// Function Pointer Typedef for NtClose
	typedef NTSTATUS(WINAPI* pNtClose)(HANDLE);

	// We have to import the function
	pNtClose NtClose_ = NULL;

	HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
	if (hNtdll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}

	NtClose_ = (pNtClose)GetProcAddress(hNtdll, "NtClose");
	if (NtClose_ == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}

	__try {
		// Time to finally make the call
		NtClose_((HANDLE)0x99999999);
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	return FALSE;

}

BOOL CloseHandle_InvalideHandle()
{
	// Let's try first with user mode API: CloseHandle
	__try {
		CloseHandle((HANDLE)0x99999999);
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	// Direct call to NtClose to bypass user mode hooks
	if (NtClose_InvalideHandle())
		return TRUE;
	else
		return FALSE;
}

BOOL anti_debug1(SYSTEMTIME s_time1, FILETIME f_time1)
{
	SYSTEMTIME s_time2;
	FILETIME f_time2;
	GetSystemTime(&s_time2);
	SystemTimeToFileTime(&s_time2, &f_time2);
	if ((f_time2.dwLowDateTime - f_time1.dwLowDateTime) / 10000 > 1000) {
		return 1;
	}
	
}

BOOL anti_debug2(DWORD count1)
{
	DWORD count2;
	count2 = GetTickCount();
	if ((count2 - count1) > 0x10) {
		return 1;
	}
	
}

BOOL anti_debug3()
{
	BOOL result = FALSE;

	CONTEXT ct;
	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	GetThreadContext(GetCurrentThread(), &ct);

	if (ct.Dr0 || ct.Dr1 || ct.Dr2 || ct.Dr3)
		result = TRUE;
	return result;
}












