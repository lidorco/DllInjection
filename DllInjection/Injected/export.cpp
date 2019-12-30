#include <Windows.h>

BOOL CALLBACK changeWindowTitle(
	_In_ HWND   hwnd, 
	_In_ LPARAM lParam
) {
	DWORD outputPid = NULL;
	GetWindowThreadProcessId(hwnd, &outputPid);
	auto pidToSet = *(PDWORD(lParam));
	if (outputPid == pidToSet) {
		SetWindowText(hwnd, "NOTEPAD is PWNED by Lidor and Neriya!");
	}

	return TRUE;
}

BOOL APIENTRY DllMain(
	_In_ HINSTANCE hInst,
	_In_ DWORD     reason,
	_In_ LPVOID    reserved
) {
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		DWORD currentPid = GetCurrentProcessId();
		LONG currentPidArg = static_cast<LONG>(currentPid);
		EnumWindows(changeWindowTitle, LPARAM(&currentPid));
	}
	
	return TRUE;
}
