#include <string>
#include <WinBase.h>
#include <wininet.h>
#include "lazy.h"
using namespace std;
#include "enc.h"
#include <tchar.h>
#include <ostream>
#include <iostream>
#include <thread>
#include <vector>
#include <iostream>
#include <vector>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <TlHelp32.h>
#include <wininet.h>
#include <winternl.h>
#include "udmanmapper/intel_driver.hpp"
#include "udmanmapper/udmanmapper.hpp"
#include "drivers/drivers.h"
#include <malloc.h>
#include <iomanip>
#include <iomanip>
#include <conio.h>
#include <intrin.h>
#include <comdef.h>
#include <Iphlpapi.h>

#define skCrypt(str) skCrypt_key(str, __TIME__[4], __TIME__[7])
#define skCrypt_key(str, key1, key2) []() { \
			constexpr static auto crypted = skc::skCrypter \
				<sizeof(str) / sizeof(str[0]), key1, key2, skc::clean_type<decltype(str[0])>>((skc::clean_type<decltype(str[0])>*)str); \
					return crypted; }()

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "urlmon.lib")

bool macaddress;
bool volumeid;
bool serials;
bool internet;

bool macdone;
bool serialdone;
bool internetdone;
bool volumeiddone;
HWND taskbarWnd = FindWindow("Shell_TrayWnd", NULL);

int counter = 60;

void slow_print(std::string message, int delay) {

	for (char c : message) {
		std::cout << skCrypt ("c") << std::flush;
		std::this_thread::sleep_for(std::chrono::milliseconds(delay));
	}
}

void text(std::string textt)
{
	LI_FN(SetConsoleTextAttribute)(GetStdHandle(STD_OUTPUT_HANDLE), 7);
	printf(E("["));
	LI_FN(SetConsoleTextAttribute)(GetStdHandle(STD_OUTPUT_HANDLE), 1);
	printf(E("+"));
	LI_FN(SetConsoleTextAttribute)(GetStdHandle(STD_OUTPUT_HANDLE), 7);
	printf(E("] "));

	printf(textt.c_str());
}



void AntiAttach()
{
	HMODULE hNtdll = GetModuleHandleA(TEXT("\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C"));
	if (!hNtdll)
		return;

	FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, TEXT(E("DbgBreakPoint")));
	if (!pDbgBreakPoint)
		return;

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return;

	*(PBYTE)pDbgBreakPoint = (BYTE)0xC3;
	
}

typedef NTSTATUS(CALLBACK* NtSetInformationThreadPtr)(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);

void StopDebegger()
{
	HMODULE hModule = LoadLibraryA(TEXT("\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C"));
	NtSetInformationThreadPtr NtSetInformationThread = (NtSetInformationThreadPtr)GetProcAddress(hModule, TEXT(E("NtSetInformationThread")));

	NtSetInformationThread(OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId()), (THREADINFOCLASS)0x11, 0, 0);
}

void adbg_ProcessFileName(void)
{
	const wchar_t* debuggersFilename[45] =
	{
		E(L"cheatengine-x86_64.exe"),
		E(L"ollydbg.exe"),
		E(L"ida.exe"),
		E(L"KsDumper.exe"),
		E(L"createdump.exe"),
		E(L"HTTPDebuggerSvc.exe"),
		E(L"cheatengine-i386.exe"),
		E(L"Cheat Engine.exe"),
		E(L"cheatengine-i386.exe"),
		E(L"Fiddler.exe"),
		E(L"sniff_hit.exe"),
		E(L"windbg.exe"),
		E(L"sysAnalyzer.exe"),
		E(L"proc_analyzer.exe"),
		E(L"dumpcap.exe"),
		E(L"HookExplorer.exe"),
		E(L"Dump-Fixer.exe"),
		E(L"kdstinker.exe"),
		E(L"Vmwareuser.exe"),
		E(L"LordPE.exe"),
		E(L"PETools.exe"),
		E(L"ImmunityDebugger.exe"),
		E(L"radare2.exe"),
		E(L"x64dbg.exe"),
		E(L"WinDbgFrameClass"),
		E(L"OLLYDBG"),
		E(L"IDA"),
		E(L"IDA64"),
		E(L"ida64.exe"),
		E(L"cheatengine-x86_64.exe"),
		E(L"cheatengine-x86_64-SSE4-AVX2.exe"),
		E(L"Cheat Engine"),
		E(L"ida.exe"),
		E(L"MugenJinFuu-x86_64-SSE4-AVX2.exe"),
		E(L"Mugen JinFuu.exe"),
		E(L"MugenJinFuu-i386.exe"),
		E(L"MugenJinFuu-x86_64.exe"),
		E(L"idaq64.exe"),
		E(L"KsDumper"),
		E(L"x64dbg"),
		E(L"The Wireshark Network Analyzer"),
		E(L"Progress Telerik Fiddler Web Debugger"),
		E(L"dnSpy"),
		E(L"IDA v7.0.170914"),
		E(L"ImmunityDebugger")
	};

	wchar_t* processName;
	PROCESSENTRY32W processInformation{ sizeof(PROCESSENTRY32W) };
	HANDLE processList;

	processList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	processInformation = { sizeof(PROCESSENTRY32W) };
	if (!(Process32FirstW(processList, &processInformation)))
		printf(TEXT(""));
	else
	{
		do
		{
			for (const wchar_t* debugger : debuggersFilename)
			{
				processName = processInformation.szExeFile;
				if (_wcsicmp(debugger, processName) == 0)
				{
					LI_FN(exit)(0);
				}
			}
		} while (Process32NextW(processList, &processInformation));
	}
	CloseHandle(processList);
}

const wchar_t* ProcessBlacklist[45] =
{
	E(L"WinDbgFrameClass"),
	E(L"OLLYDBG"),
	E(L"IDA"),
	E(L"IDA64"),
	E(L"ida64.exe"),
	E(L"cheatengine-x86_64.exe"),
	E(L"cheatengine-x86_64-SSE4-AVX2.exe"),
	E(L"Cheat Engine"),
	E(L"ida.exe"),
	E(L"MugenJinFuu-x86_64-SSE4-AVX2.exe"),
	E(L"Mugen JinFuu.exe"),
	E(L"MugenJinFuu-i386.exe"),
	E(L"MugenJinFuu-x86_64.exe"),
	E(L"cheatengine-x86_64.exe"),
	E(L"cheatengine-i386.exe"),
	E(L"Cheat Engine.exe"),
	E(L"cheatengine-i386.exe"),
	E(L"idaq64.exe"),
	E(L"KsDumper"),
	E(L"x64dbg"),
	E(L"The Wireshark Network Analyzer"),
	E(L"Progress Telerik Fiddler Web Debugger"),
	E(L"dnSpy"),
	E(L"IDA v7.0.170914"),
	E(L"ImmunityDebugger"),
	E(L"ollydbg.exe"),
	E(L"ida.exe"),
	E(L"KsDumper.exe"),
	E(L"createdump.exe"),
	E(L"HTTPDebuggerSvc.exe"),
	E(L"Fiddler.exe"),
	E(L"sniff_hit.exe"),
	E(L"windbg.exe"),
	E(L"sysAnalyzer.exe"),
	E(L"proc_analyzer.exe"),
	E(L"dumpcap.exe"),
	E(L"HookExplorer.exe"),
	E(L"Dump-Fixer.exe"),
	E(L"kdstinker.exe"),
	E(L"Vmwareuser.exe"),
	E(L"LordPE.exe"),
	E(L"PETools.exe"),
	E(L"ImmunityDebugger.exe"),
	E(L"radare2.exe"),
	E(L"x64dbg.exe")
};

const wchar_t* FileBlacklist[] =
{
	E(L"CEHYPERSCANSETTINGS"),
};

void ScanBlacklist()
{
	for (auto& Process : ProcessBlacklist)
	{
		if (FindWindowW((LPCWSTR)Process, NULL))
		{
			LI_FN(exit)(0);
		}
	}

	for (auto& File : FileBlacklist)
	{
		if (OpenFileMappingW(FILE_MAP_READ, false, (LPCWSTR)File))
		{
			LI_FN(exit)(0);
		}
	}
}

void driverdetect()
{
	const TCHAR* devices[] =
	{
		(E(("\\\\.\\kdstinker"))),
		(E(("\\\\.\\NiGgEr"))),
		(E(("\\\\.\\KsDumper")))
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		TCHAR msg[256] = ("");
		if (hFile != INVALID_HANDLE_VALUE)
		{
			LI_FN(system)(E("start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO KsDumper Detected. && TIMEOUT 10 >nul"));
			LI_FN(exit)(0);
		}
		else
		{
		}
	}
}

void IsDebuggerPresentPatched()
{
	HMODULE hKernel32 = GetModuleHandleA(TEXT("\x6B\x65\x72\x6E\x65\x6C\x33\x32\x2E\x64\x6C\x6C"));
	if (!hKernel32) {}

	FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, TEXT(E("IsDebuggerPresent")));
	if (!pIsDebuggerPresent) {}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
	}

	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapshot, &ProcessEntry))
	{
	}

	bool bDebuggerPresent = false;
	HANDLE hProcess = NULL;
	DWORD dwFuncBytes = 0;
	const DWORD dwCurrentPID = GetCurrentProcessId();
	do
	{
		__try
		{
			if (dwCurrentPID == ProcessEntry.th32ProcessID)
				continue;

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
			if (NULL == hProcess)
				continue;

			if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
				continue;

			if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent)
			{
				bDebuggerPresent = true;
				LI_FN(exit)(0);
				break;
			}
		}
		__finally
		{
			if (hProcess)
				CloseHandle(hProcess);
			else
			{
			}
		}
	} while (Process32NextW(hSnapshot, &ProcessEntry));

	if (hSnapshot)
		CloseHandle(hSnapshot);
}

void CheckProcessDebugFlags()
{
	typedef int (WINAPI* pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD NoDebugInherit = 0;
	int Status;

	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle((TEXT("\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C"))), TEXT(E("NtQueryInformationProcess")));

	Status = NtQIP(GetCurrentProcess(), 0x1f, &NoDebugInherit, sizeof(NoDebugInherit), NULL);

	if (Status != 0x00000000) {}

	if (NoDebugInherit == FALSE)
	{
		LI_FN(exit)(0);
	}
	else {}
}

void Debugkor()
{
	__try
	{
		LI_FN(DebugBreak)();
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
	}
}
void CheckProcessDebugPort()
{
	typedef int (WINAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD_PTR DebugPort = 0;
	ULONG ReturnSize = 0;
	int Status;
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle((TEXT("\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C"))), TEXT(E("NtQueryInformationProcess")));

	Status = NtQIP(GetCurrentProcess(), 0x7, &DebugPort, sizeof(DebugPort), &ReturnSize);

	if (Status != 0x00000000) {}

	if (DebugPort)
	{
		LI_FN(exit)(0);
	}

	else {}
}


void CheckProcessDebugObjectHandle()
{
	typedef int (WINAPI* pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD_PTR DebugHandle = 0;
	int Status;
	ULONG ReturnSize = 0;

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle((TEXT("\x6E\x74\x64\x6C\x6C\x2E\x64\x6C\x6C"))), TEXT(E("NtQueryInformationProcess")));

	Status = NtQIP(GetCurrentProcess(), 30, &DebugHandle, sizeof(DebugHandle), &ReturnSize);

	if (Status != 0x00000000)
	{
	}

	if (DebugHandle)
	{
		CloseHandle((HANDLE)DebugHandle);
		LI_FN(exit)(0);
	}
	else {}
}

void CheckDevices()
{
	const char DebuggingDrivers[9][20] =
	{
		"\\\\.\\EXTREM", "\\\\.\\ICEEXT",
		"\\\\.\\NDBGMSG.VXD", "\\\\.\\RING0",
		"\\\\.\\SIWVID", "\\\\.\\SYSER",
		"\\\\.\\TRW", "\\\\.\\SYSERBOOT",
		"\0"
	};

	for (int i = 0; DebuggingDrivers[i][0] != '\0'; i++) {
		HANDLE h = CreateFileA(DebuggingDrivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
		if (h != INVALID_HANDLE_VALUE)
		{
			CloseHandle(h);
			LI_FN(exit)(0);
		}
		CloseHandle(h);
	}
}

void adbg_CheckRemoteDebuggerPresent(void)
{
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	BOOL found = FALSE;

	hProcess = LI_FN(GetCurrentProcess)();
	LI_FN(CheckRemoteDebuggerPresent)(hProcess, &found);

	if (found)
	{
		LI_FN(exit)(0);
	}
}

void adbg_CheckWindowName(void)
{
	BOOL found = FALSE;
	HANDLE hWindow = NULL;
	const wchar_t* WindowNameOlly = E(L"OllyDbg - [CPU]");
	const wchar_t* WindowNameImmunity = E(L"Immunity Debugger - [CPU]");

	hWindow = FindWindowW(NULL, WindowNameOlly);
	if (hWindow)
	{
		found = TRUE;
	}
	hWindow = FindWindowW(NULL, WindowNameImmunity);
	if (hWindow)
	{
		found = TRUE;
	}

	if (found)
	{
		LI_FN(exit)(0);
	}
}

void adbg_CrashOllyDbg(void)
{
	__try {
		LI_FN(OutputDebugStringA)((TEXT(E("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"))));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { ; }
}


void free_console() {
	/*
	This function frees the console window.
	*/
	FreeConsole();
}


void spoofgame(BYTE* rawData)
{
	HANDLE iqvw64e_device_handle = intel_driver::Load();

	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		
		MessageBoxA(NULL, E("Error with loading driver"), E("TABEX"), MB_OK);

	}

	if (!kdmapper::MapDriver(iqvw64e_device_handle, rawData))
	{
		intel_driver::Unload(iqvw64e_device_handle);
	}

	intel_driver::Unload(iqvw64e_device_handle);
}




void ErasePEHeaderFromMemory()
{
	DWORD OldProtect = 0;
	char* pBaseAddr = (char*)GetModuleHandle(NULL);
	VirtualProtect(pBaseAddr, 4096, PAGE_READWRITE, &OldProtect);
	ZeroMemory(pBaseAddr, 4096);
}

string random_string()
{
	string str = E("QWERTYUIOPASDFGHJKLZXCVBNM").decrypt();
	string newstr;
	int pos;
	while (newstr.size() != 15)
	{
		pos = ((rand() % (str.size() + 1)));
		newstr += str.substr(pos, 1);
	}
	return newstr + "";
}

void changetitle()
{
	while (true)
	{
		std::string consoleTitle = (std::string)E("") + random_string();
		LI_FN(SetConsoleTitleA)(consoleTitle.c_str());
	}
}

std::string replaceAll(std::string subject, const std::string& search, const std::string& replace) {
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != std::string::npos) {
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
	return subject;
}

string DownloadString(string URL) {
	HINTERNET interwebs = InternetOpenA(E("Mozilla/5.0"), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
	HINTERNET urlFile;
	string rtn;
	if (interwebs) {
		urlFile = InternetOpenUrlA(interwebs, URL.c_str(), NULL, NULL, NULL, NULL);
		if (urlFile) {
			char buffer[2000];
			DWORD bytesRead;
			do {
				InternetReadFile(urlFile, buffer, 2000, &bytesRead);
				rtn.append(buffer, bytesRead);
				memset(buffer, 0, 2000);
			} while (bytesRead);
			InternetCloseHandle(interwebs);
			InternetCloseHandle(urlFile);
			string p = replaceAll(rtn, (std::string)E("|n"), "\r\n");
			return p;
		}
	}
	InternetCloseHandle(interwebs);
	string p = replaceAll(rtn, (std::string)E("|n"), "\r\n");
	return p;
}

std::string pcusername()
{
	char acUserName[100];
	DWORD nUserName = sizeof(acUserName);
	GetUserNameA(acUserName, &nUserName);
	return static_cast<std::string>(acUserName);
}

//char* getMAC()
//{
//	PIP_ADAPTER_INFO AdapterInfo;
//	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
//	char* mac_addr = (char*)malloc(18);
//
//	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
//	if (AdapterInfo == NULL) {
//		free(mac_addr);
//		return NULL;
//	}
//	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
//		free(AdapterInfo);
//		AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
//		if (AdapterInfo == NULL) {
//			free(mac_addr);
//			return NULL;
//		}
//	}
//	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
//		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
//		do {
//				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
//				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
//				pAdapterInfo->Address[4], pAdapterInfo->Address[5];
//			pAdapterInfo = pAdapterInfo->Next;
//		} while (pAdapterInfo);
//	}
//	free(AdapterInfo);
//	return mac_addr;
//}

bool CheckVTBlacklist(std::string id, std::string rawlinktoblacklist)
{
	std::string blacklistedcontents = DownloadString(rawlinktoblacklist);
	if (blacklistedcontents.find(id) != std::string::npos)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void checkDebugger()
{
	while (true)
	{
		adbg_CrashOllyDbg();
		adbg_CheckRemoteDebuggerPresent();
		AntiAttach();
		adbg_ProcessFileName();
		adbg_CheckWindowName();
		StopDebegger();
		CheckDevices();
		CheckProcessDebugObjectHandle();
		CheckProcessDebugPort();
		Debugkor();
		CheckProcessDebugFlags();
		IsDebuggerPresentPatched();
		driverdetect();

		if (IsDebuggerPresent())
		{
			std::cout << "Debugger detected!" << std::endl;
			exit(0);

		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Check every second
	}
}

void check()
{
	while (true)
	{
		if (LI_FN(IsDebuggerPresent)())
		{
			LI_FN(exit)(0);
		}

		BOOL debugged = LI_FN(IsDebuggerPresent)();
		if (debugged)
		{
			LI_FN(exit)(0);
		}

		adbg_CrashOllyDbg();
		adbg_CheckRemoteDebuggerPresent();
		AntiAttach();
		adbg_ProcessFileName();
		adbg_CheckWindowName();
		StopDebegger();
		CheckDevices();
		CheckProcessDebugObjectHandle();
		CheckProcessDebugPort();
		Debugkor();
		CheckProcessDebugFlags();
		IsDebuggerPresentPatched();
		driverdetect();
		ScanBlacklist();
		LI_FN(Sleep)(1500);
	}
}

namespace integrity {
	class check {
	public:
		check(const char* module = nullptr) {
			if (this->module = reinterpret_cast<std::uintptr_t>(GetModuleHandle(module)))
				this->sections = this->retrieve_sections(); // Cache all sections
		}

	private:
		std::uintptr_t module = std::uintptr_t();

	private:
		static const std::uint32_t crc32(void* data, std::size_t size) noexcept {
			std::uint32_t result = 0;

			for (std::size_t index = 0; index < size; ++index)
				result = _mm_crc32_u8(result, reinterpret_cast<std::uint8_t*>(data)[index]);

			return result;
		}

	public:
		struct section {
			std::uint8_t* name;
			void* address;
			std::size_t size;
			std::size_t characteristics;
			std::uint32_t checksum;

			section() : name(nullptr), address(nullptr), size(std::size_t()), characteristics(std::size_t()), checksum(std::uint32_t()) {}

			section(std::uint8_t* name, void* address, std::size_t size, std::size_t characteristics) : name(name), address(address), size(size), characteristics(characteristics) {
				this->checksum = check::crc32(this->address, this->size);
			}
		};

		/// <summary>
		/// Retrieve all non-writable sections from specified module
		/// </summary>
		std::vector<section> retrieve_sections() const noexcept {
			std::vector<section> result = {};

			PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(this->module + reinterpret_cast<PIMAGE_DOS_HEADER>(this->module)->e_lfanew);
			if (nt_headers == nullptr) return result;

			PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
			for (std::uint16_t index = 0; index < nt_headers->FileHeader.NumberOfSections; index++, section++)
				if ((section->Characteristics & IMAGE_SCN_MEM_WRITE) == false)
					result.push_back({ section->Name, reinterpret_cast<void*>(this->module + section->VirtualAddress), section->Misc.VirtualSize, section->Characteristics });

			return result;
		}

		/// <summary>
		/// Compare CRC32 checksum of cached sections with another sections
		/// </summary>
		/// <returns>If there is a change in sections, returns changed sections</returns>
		std::vector<section> compare_checksums(const std::vector<section>& sections) const noexcept {
			std::vector<section> result = {};

			for (std::size_t index = 0; index < this->sections.size(); index++)
				if (this->sections[index].checksum != sections[index].checksum)
					result.push_back(sections[index]);

			return result;
		}

	private:
		std::vector<section> sections = {};
	};
}

std::string ReadFromFile(std::string path)
{
	std::string contents;
	std::ifstream file(path, std::ios::in);
	std::getline(file, contents);
	return contents;
}

__forceinline std::int32_t mempatch() {
	integrity::check check = integrity::check();

	while (true) {
		const std::vector<integrity::check::section>& sections = check.compare_checksums(check.retrieve_sections());

		if (sections.size() == std::size_t())
			std::printf("");

		for (const integrity::check::section& section : sections)
			LI_FN(exit)(0);

		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
}
HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);

const char* colorwhite()
{
	SetConsoleTextAttribute(h, 15);
	return "";
}
const char* colorgray()
{
	SetConsoleTextAttribute(h, 8);
	return "";
}
const char* colorcyan()
{
	SetConsoleTextAttribute(h, 13);
	return "";
}
const char* colorred()
{
	SetConsoleTextAttribute(h, 4);
	return "";
}

const char* colorgreen()
{
	SetConsoleTextAttribute(h, 2);
	return "";
}

void clear()
{
	system(("cls"));
}

//2
const char* coloraqua()
{
	SetConsoleTextAttribute(h, 5);
	return "";
}

const char* colorpenmis()
{
	SetConsoleTextAttribute(h, 51);
	return "";
}
