#include <Windows.h>
#include <iostream>

#define IMPORT_TABLE_OFFSET 1

PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE hInstance)
{
	PIMAGE_DOS_HEADER dosHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;
	PIMAGE_NT_HEADERS ntHeader;
	IMAGE_DATA_DIRECTORY dataDirectory;

	dosHeader = (PIMAGE_DOS_HEADER)hInstance;
	ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)dosHeader + dosHeader->e_lfanew);	optionalHeader = (IMAGE_OPTIONAL_HEADER)(ntHeader->OptionalHeader);
	dataDirectory = (IMAGE_DATA_DIRECTORY)(optionalHeader.DataDirectory[IMPORT_TABLE_OFFSET]);
	return (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hInstance + dataDirectory.VirtualAddress);}


bool rewriteThunk(PIMAGE_THUNK_DATA pThunk, void* newFunc)
{
	DWORD CurrentProtect;
	DWORD junk;
	VirtualProtect(pThunk, 4096, PAGE_READWRITE, &CurrentProtect);
	DWORD sourceAddr = pThunk->u1.Function;
	pThunk->u1.Function = (DWORD)newFunc;
	VirtualProtect(pThunk, 4096, CurrentProtect, &junk);
	return true;}


BOOL
WINAPI
MyFindNextFileW(
	_In_ HANDLE hFindFile,
	_Out_ LPWIN32_FIND_DATAW lpFindFileData
)
{
	SetLastError(ERROR_NO_MORE_FILES);
	return FALSE;
}


void patchIAT()
{
	HMODULE currentProcessImage = GetModuleHandleA(NULL);
	PIMAGE_IMPORT_DESCRIPTOR importedModule;
	PIMAGE_THUNK_DATA pFirstThunk, pOriginalFirstThunk;
	PIMAGE_IMPORT_BY_NAME pFuncData;
	importedModule = getImportTable(currentProcessImage);
	while (*(WORD*)importedModule != 0)
	{
		//std::cout << (char*)((PBYTE)currentProcessImage + importedModule->Name) << std::endl;

		pFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)currentProcessImage + importedModule->FirstThunk);
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)currentProcessImage + importedModule ->OriginalFirstThunk);
		pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)currentProcessImage + pOriginalFirstThunk ->u1.AddressOfData);

		while (*(WORD*)pFirstThunk != 0 && *(WORD*)pOriginalFirstThunk != 0)
		{
			//printf("%X %s\n", pFirstThunk->u1.Function, pFuncData->Name);

			if (strcmp("FindNextFileW", (char*)pFuncData->Name) == 0)
			{
				printf("%X %s\n", pFirstThunk->u1.Function, pFuncData->Name);
				printf("Hooking... \n");
								if (rewriteThunk(pFirstThunk, MyFindNextFileW))
					printf("Hooked %s successfully :)\n", "FindNextFileW");
				
			}
			
			pOriginalFirstThunk++;
			pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)currentProcessImage + pOriginalFirstThunk ->u1.AddressOfData);
			pFirstThunk++;
		}
		importedModule++; //next module (DLL)
	}
	
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	patchIAT();
	return TRUE;
}
