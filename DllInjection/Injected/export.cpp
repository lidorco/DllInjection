#include <Windows.h>


typedef BOOL (WINAPI *ENUMWINDOWSTYPE)(_In_ WNDENUMPROC lpEnumFunc,
								_In_ LPARAM lParam);

BOOL CALLBACK EnumWindowsProc(
	_In_ HWND   hwnd,
	_In_ LPARAM lParam
)
{
	DWORD outputPid = NULL;
	GetWindowThreadProcessId(hwnd, &outputPid);

	auto pidToSet = *(PDWORD(lParam));
	if (outputPid == pidToSet)
	{
		SetWindowText(hwnd, "NOTEPAD is PWNED by Lidor and Neriya!");
	}

	return TRUE;
}

void changeWindowTitle()
{
	DWORD currentPid = GetCurrentProcessId();
	LONG currentPidArg = static_cast<LONG>(currentPid);

	HMODULE User32Module = GetModuleHandleA("User32.dll");
	if (NULL == User32Module)
	{
		User32Module = LoadLibraryA("User32.dll");
		if (NULL == User32Module)
		{
			return;
		}
	}
	
	ENUMWINDOWSTYPE myEnumWindows = (ENUMWINDOWSTYPE)GetProcAddress(User32Module, "EnumWindows");
	if (myEnumWindows) {
		myEnumWindows(EnumWindowsProc, LPARAM(&currentPid));
	}
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
)
{
	changeWindowTitle();
	return TRUE;
}
