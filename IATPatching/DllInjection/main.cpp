#include <Windows.h>
#include <iostream>


LPVOID writeStringToProcess(const std::string& str, const HANDLE process) {
	const auto remoteAddress = VirtualAllocEx(process, nullptr, static_cast<SIZE_T>(str.size() + 1),
	                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (nullptr == remoteAddress)
	{
		std::cout << "VirtualAllocEx failed : " << GetLastError() << std::endl;
		return nullptr;
	};

	SIZE_T bytesWritten = 0;
	if (0 == WriteProcessMemory(process, remoteAddress, str.c_str(), str.size(), &bytesWritten)) {
		std::cout << "WriteProcessMemory failed : " << GetLastError() << std::endl;
		return nullptr;
	}

	if (bytesWritten != str.size()) {
		std::cout << "WriteProcessMemory wrote only " << bytesWritten <<" bytes instead of " << str.size() << std::endl;
		return nullptr;
	}

	return remoteAddress;
}

void dllInjection(const int pid) {
	const HANDLE  processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (nullptr == processHandle) {
		std::cout << "OpenProcess failed : " << GetLastError() << std::endl;
		return;
	}

	const auto kernel32Handle = GetModuleHandle("kernel32.dll");
	if (nullptr == kernel32Handle) {
		std::cout << "GetModuleHandle failed : " << GetLastError() << std::endl;
		return;
	}

	const auto loadLibraryAddress = static_cast<LPVOID>(GetProcAddress(kernel32Handle, "LoadLibraryA"));
	if (nullptr == loadLibraryAddress) {
		std::cout << "GetProcAddress failed : " << GetLastError() << std::endl;
		return;
	}

	const auto injectDllNameRemoteAddress = writeStringToProcess(std::string("C:\\injected-2.dll"), processHandle);
	if (nullptr == injectDllNameRemoteAddress) {
		return;
	}

	const auto threadId = CreateRemoteThread(processHandle, nullptr, 0,
		static_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress), injectDllNameRemoteAddress, 0, nullptr);
	if (nullptr == threadId) {
		std::cout << "CreateRemoteThread failed : " << GetLastError() << std::endl;
		return;
	}

	CloseHandle(processHandle);
}


int main(int argc, char **argv)
{
	if (2 != argc) {
		std::cout << "Usage: " << argv[0] << " <pid>" << std::endl;
		return 0;
	}

	std::cout << "injecting to pid " << argv[1] << std::endl;
	dllInjection(atoi(argv[1]));
	return 0;
}