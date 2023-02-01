# anticheat-poc
In pursuit of a deeper understanding of low-level programming and reverse engineering, I took to the development of a program that functions as a basic form of an anti-cheat or anti-virus that could be used in the context of not only ensured gameplay integrity but also general security and protection against malicious code for a specific process. Initially, this project began as a test bed to evaluate the detection vectors triggered by methods used in my own memory-hacking program. Through independent research, I studied techniques used by well-known industry-level anti-cheats and incorporated similar procedures into my application. Some aspects of my code drew inspiration from the reversed, decompiled IDA output of the aforementioned software binaries.
# DLL component
There is also a [dynamic link library (DLL) component](https://github.com/thetuh/anticheat-dll-example) created specifically for this program to showcase how certain hooks are triggered and how they can also be circumvented using various techniques.
# Features
* DLL inject detection (LoadLibrary)
* Return address integrity checks on various Windows API / Native API function exports via detour hooks
* Kernel-level return address integrity checks on all syscalls via instrumentation callbacks
# Planned
* Compute and cache all valid module base and end addresses on startup by walking the PEB
* Scan all opened handles to our process
* Restructure/reorganize project
* Clean/Optimize code
# Resources
https://github.com/TsudaKageyu/minhook
