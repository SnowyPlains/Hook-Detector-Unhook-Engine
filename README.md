# User-Mode API Inline Hook Detector & Unhooking Engine
#### A forensic security utility written in pure C utilizing the Win32 API to inspect, detect, and remediate user-mode inline hooks inside running Windows processes.

#### Designed as an on-demand auditing engine, this tool analyzes target memory spaces, parses Portable Executable (PE) headers across different memory contexts, maps clean disk references, and safely restores compromised system libraries without disrupting host application stability.

#### Date: 26 October 2026

## Core Problem Space:
Traditional user-mode applications operate under an assumption of absolute trust regarding their underlying system libraries. This engine directly addresses three primary security challenges:
1) **Blind Trust in Process Memory:** Applications blindly trust that system DLLs such as ntdll.dll loaded into their memory space are unmodified. Because user-mode memory is writable or remapped, co-privileged processes or malicious payloads can quietly tamper with libraries.
2) **Stealthy Function Hijacks (Inline Hooks):** Rootkits or security products frequently overwrite the first few bytes of critical system functions with jump instructions, creating hidden execution trapdoors without altering basic OS-level process queries.
3) **The Safe Remediation Dilemma:** System libraries are locked down as read-only (PAGE_EXECUTE_READ). Simply overwriting corrupted memory causes access violations. Fixing a hook requires a precise multi-step sequence:
    - unlocking memory protections
    - writing pristine bytes from a trusted disk source
    - re-locking memory
    - flushing CPU instruction caches.

## Architecture & Execution Flow:
Unlike active runtime security agents like EDRs that intercept system calls on the fly, this software acts as a forensic auditor:
1) **Target Attachment:** Opens a secure handle to a target Process ID (PID) with specific memory query, read, write, and operation privileges.
2) **Clean Reference Mapping:** Opens `C:\Windows\System32\ntdll.dll` from disk and maps it as a pristine reference image (SEC_IMAGE).
3) **Remote Module Discovery:** Locates the base address of ntdll.dll inside the target process memory space using module enumeration snapshots.
4) **PE Parsing & EAT Walking:** Traverses DOS headers, NT headers, optional headers, and section headers to isolate the .text code section and parse the Export Address Table (EAT).
5) **Prologue Auditing:** Iterates through every exported function, calculates its absolute virtual address, reads its prologue bytes via ReadProcessMemory, and compares them against the clean disk blueprint using memcmp.
6) **Self-Healing Remediation:** If a hook or mismatch is detected inside the executable .text section:
    - Temporarily adjusts page protection to PAGE_EXECUTE_READWRITE via VirtualProtectEx.
    - Overwrites the modified bytes with pristine reference bytes via WriteProcessMemory.
    - Restores original page protection (PAGE_EXECUTE_READ).
    - Flushes the CPU instruction cache using FlushInstructionCache to prevent stale pre-fetched pipeline executions.
7) **Comprehensive Reporting:** Outputs a granular scan summary detailing total elements checked, data structures skipped, clean functions, active hooks detected, and successful remediations.

## Technical Implementation Highlights:
- **Pure C & Win32 Native:** Written without heavy framework dependencies, utilizing raw Windows systems programming primitives.
- **Dual-Context PE Parsing:** Simultaneously handles local disk-mapped files and remote process virtual memory layouts.
- **False-Positive Filtering:** Automatically validates export offsets against section header boundaries (.text), gracefully skipping non-executable data exports.
- **Robust Input Validation:** Safe command-line argument parsing and strict numeric bounds-checking for PIDs using strtol.

## Compilation & Usage:
**Prerequisites:**  
- Any C standard compliant compiler such as gcc, clang, ...

**Build Instructions Example Using GCC:**
- gcc -Wall -Wextra -O3 main.c -o HookDetector

*HookDetector is the name of the program, you can name it anything you want

**Execution Examples:**
- **General Syntax:** .\HookDetector.exe \<pid\>
- **Example:** .\HookDetector.exe 4188

## Sample Output:
```
=============================================================================================
                   User-Mode API Inline Hook Detector & Unhooking Engine                    
=============================================================================================

General Info
---------------------------
PID to Scan: 4188
Getting Process File Info..
    Process File Information Gathered Successfully!
    Process File Size: 90.29 KB (92455 Bytes)
Loading On-Disk ntdll.dll into Memory..
    Opened the DLL Successfully!
    Created a File Map Successfully!
    Map View Succeeded!
    ntdll.dll Loaded into Memory Successfully!
Locating ntdll.dll in the Target Process..
    ntdll.dll found in the Target Process at Base Address: 0x7FFEA0680000

DOS HEADERS
-------------------------------
Magic Signature: 0x5A4D (Valid)
e_lfanew: 0xE0 (Valid)

NT HEADERS
-------------------------------
NT Signature: 0x4550 (Valid)
Target Architecture: AMD64
Compiled Time: 1607703045 (Fri Dec 11 16:10:45 2020 UTC)
Number of Sections: 15
Characteristics: 0x2022 (EXECUTABLE_IMAGE, LARGE_ADDRESS_AWARE, DLL)

Optional Headers
-------------------------------
Target Architecture: PE32+ (64-bit)
Entry Point: 0x00000000
Image Base: 0x7FFEA0680000
Section Alignment: 4096 Bytes
File Alignment: 4096 Bytes
Subsystem: Windows CUI (Console)
Size of Image: 2464.00 KB
Size of Headers: 4096 Bytes

Section Headers
-------------------------------
Locating the .text Section..
    .text Section Found: Starting Addess RVA: 0x1000 | Ending Address RVA: 0x16C03C

Export Address Table (EAT)
-------------------------------
Getting the Real Address of the EAT..
    Done! EAT Real Address is at: 0x7FFEA08391C0
Scanning all Functions..
    Scanning Function #1: A_SHAFinal (Real Address: 0x7FFEA0793490)..
    Function is Clean!

    Scanning Function #2: A_SHAInit (Real Address: 0x7FFEA0793000)..
    Function is Clean!

    Scanning Function #3: A_SHAUpdate (Real Address: 0x7FFEA0793750)..
    Function is Clean!

    Scanning Function #4: AlpcAdjustCompletionListConcurrencyCount (Real Address: 0x7FFEA078F910)..
    Function is Clean!

    Scanning Function #5: AlpcFreeCompletionListMessage (Real Address: 0x7FFEA0757E60)..
    Function is Clean!

    Scanning Function #6: AlpcGetCompletionListLastMessageInformation (Real Address: 0x7FFEA07B8CC0)..
    Function is Clean!

    Scanning Function #7: AlpcGetCompletionListMessageAttributes (Real Address: 0x7FFEA07B8CE0)..
    Function is Clean!

    ...

    Scanning Function #2515: wcspbrk (Real Address: 0x7FFEA07AB050)..
    Function is Clean!

    Scanning Function #2516: wcsrchr (Real Address: 0x7FFEA07AB0B0)..
    Function is Clean!

    Scanning Function #2517: wcsspn (Real Address: 0x7FFEA07AB170)..
    Function is Clean!

    Scanning Function #2518: wcsstr (Real Address: 0x7FFEA07AB1E0)..
    Function is Clean!

    Scanning Function #2519: wcstok_s (Real Address: 0x7FFEA07B1670)..
    Function is Clean!

    Scanning Function #2520: wcstol (Real Address: 0x7FFEA07AB630)..
    Function is Clean!

    Scanning Function #2521: wcstombs (Real Address: 0x7FFEA07AB6D0)..
    Function is Clean!

    Scanning Function #2522: wcstoul (Real Address: 0x7FFEA07AB690)..
    Function is Clean!

Scan Complete!

Scan Summary
-------------------------------
Total Number of Elements Checked: 2522 Elements
Total Number of Elements Skipped: 13 Elements
Total Number of Functions Scanned: 2509 Functions
Total Number of Clean Functions: 2509 Functions
Total Number of Functions Hooked: 0 Functions
Total Number of Functions Fixed: 0 Functions
Total Number of Unfixed Functions: 0 Functions

Exiting..
```

## Notes:
This project is intended for educational, research, and defensive security engineering purposes.

## References:
1) [strtol](https://www.tutorialspoint.com/c_standard_library/c_function_strtol.htm)
2) [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
3) [CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
4) [CreateFileMappingA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)
5) [MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
6) [EnumProcessModules](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules)
7) [GetModuleBaseNameA](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulebasenamea)
8) [_stricmp](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/stricmp-wcsicmp-mbsicmp-stricmp-l-wcsicmp-l-mbsicmp-l?view=msvc-170)
9) [QueryFullProcessImageNameW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew)
10) [GetFileAttributesExW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesexw)
11) [IMAGE_NT_HEADERS32](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32)
12) [IMAGE_FILE_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header)
13) [IMAGE_OPTIONAL_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)
14) [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)
15) [memcpy](https://www.geeksforgeeks.org/cpp/memcpy-in-cc/)
16) [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
17) [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
18) [FlushInstructionCache](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache)