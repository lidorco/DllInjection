#include <Windows.h>
#include <iostream>


LPVOID writeStringToProcess(std::string str, HANDLE process) {
	LPVOID remoteAddress = VirtualAllocEx(process, NULL, (SIZE_T)(str.size() + 1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (0 == remoteAddress)
	{
		std::cout << "VirtualAllocEx failed : " << GetLastError() << std::endl;
		return NULL;
	};

	SIZE_T bytesWritten = 0;
	if (0 == WriteProcessMemory(process, remoteAddress, str.c_str(), str.size(), &bytesWritten)) {
		std::cout << "WriteProcessMemory failed : " << GetLastError() << std::endl;
		return NULL;
	}

	if (bytesWritten != str.size()) {
		std::cout << "WriteProcessMemory wrote only " << bytesWritten <<" bytes instead of " << str.size() << std::endl;
		return NULL;
	}

	return remoteAddress;
}

void dllInjection(int pid) {

	HANDLE  process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (NULL == process) {
		std::cout << "OpenProcess failed : " << GetLastError() << std::endl;
		return;
	}

	LPTHREAD_START_ROUTINE loadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"),
		"LoadLibraryA");
	LPVOID injectDllNameRemoteAddress = writeStringToProcess(std::string("C:\\Injected.dll"), process);

	if (injectDllNameRemoteAddress) {
		CreateRemoteThread(process, NULL, 0, loadLibraryAddress, injectDllNameRemoteAddress, 0, NULL);
	}
	
	CloseHandle(process);
}


int main(int argc, char **argv) {
	if (2 != argc) {
		std::cout << "Usage: " << argv[0] << " <pid>" << std::endl;
		return 0;
	}

	std::cout << "injecting to pid " << argv[1] << std::endl;
	dllInjection(atoi(argv[1]));
	return 0;
}