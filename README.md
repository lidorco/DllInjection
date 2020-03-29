# DllInjection
This repository is an exercise at Windows internals code injections. The exercise was given during malicious code course which delivered at Ben Gurion University. 
## The Exercise
This exercise contains 2 parts:
### DLL Injection
In this part we wrote a DLL which change the title of the current process. Then we wrote an executeable which inject this DLL to process with PID given.

### IAT Patching
In this part we wrote a DLL which patch the Import Address Table of the current process. We found common SSH client process, that if we replace  `RegSetValueExW` WinApi with our code, we can get the hashed passwords which the user use to connect to SSH servers! Then we wrote an executeable which inject this DLL to the SSH client process.