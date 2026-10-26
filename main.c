#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

struct FlagMap {
    WORD flag;
    const char* name;
};

const struct FlagMap FileCharacteristicsTable[] = {
    { IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED" },
    { IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE" },
    { IMAGE_FILE_LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED" },
    { IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED" },
    { IMAGE_FILE_AGGRESIVE_WS_TRIM, "AGGRESIVE_WS_TRIM" },
    { IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE" },
    { IMAGE_FILE_BYTES_REVERSED_LO, "BYTES_REVERSED_LO" },
    { IMAGE_FILE_32BIT_MACHINE, "32BIT_MACHINE" },
    { IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED" },
    { IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP" },
    { IMAGE_FILE_NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP" },
    { IMAGE_FILE_SYSTEM, "SYSTEM" },
    { IMAGE_FILE_DLL, "DLL" },
    { IMAGE_FILE_UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY" },
    { IMAGE_FILE_BYTES_REVERSED_HI, "BYTES_REVERSED_HI" }
};

BYTE* GetModuleBaseAddress(HANDLE processHandle, const char* moduleName);
bool FormatTime(char* formattedTime, size_t stringSize, DWORD originalTime);
void PrintFileCharacteristics(WORD fileCharacteristics, int characteristicsTableSize);
void PrintSubSystem(WORD subSystem);

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Please provide a PID to scan!\n");

        return -1;
    }

    if (argc > 2) {
        printf("Too Many Arguments!\nPlease Provide 1 PID to scan!\n");

        return -1;
    }

    char* endPtr;
    errno = 0;

    long pid = strtol(argv[1], &endPtr, 10);

    if (endPtr == argv[1]) {
        printf("PID should be a number!\n");

        return -1;
    }

    if (*endPtr != '\0') {
        printf("Characters were found with the PID! PID is a full number\n");

        return -1;
    }

    if (errno == ERANGE) {
        printf("PID is too large to process!\n");

        return -1;
    }

    if (pid < 0) {
        printf("PID should be a positive number!\n");

        return -1;
    }

    printf("\n=============================================================================================\n");
    printf("                   User-Mode API Inline Hook Detector & Unhooking Engine                    \n");
    printf("=============================================================================================\n");

    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (processHandle == NULL) {
        printf("Couldn't get a handle to the process with PID: %ld | Error Code: %lu\n", pid, GetLastError());

        return -1;
    }

    printf("\nGeneral Info\n");
    printf("---------------------------\n");
    printf("PID to Scan: %ld\n", pid);

    printf("Getting Process File Info..\n");
    wchar_t processPath[MAX_PATH];
    DWORD processPathSize = MAX_PATH;

    ULARGE_INTEGER processFileSize;
    if (QueryFullProcessImageNameW(processHandle, 0, processPath, &processPathSize)) {
        WIN32_FILE_ATTRIBUTE_DATA processFileInfo;
        if (GetFileAttributesExW(processPath, GetFileExInfoStandard, &processFileInfo)) {
            processFileSize.LowPart = processFileInfo.nFileSizeLow;
            processFileSize.HighPart = processFileInfo.nFileSizeHigh;
        } else {
            printf("    Couldn't Read File Attributes on Disk! Error Code: %lu\n", GetLastError());
        }
    } else {
        printf("    Couldn't Retrieve Process Executable Path! Error Code: %lu\n", GetLastError());
    }
    printf("    Process File Information Gathered Successfully!\n");
    printf("    Process File Size: %.2f KB (%llu Bytes)\n", (double)processFileSize.QuadPart / 1024.0, processFileSize.QuadPart);

    printf("Loading On-Disk ntdll.dll into Memory..\n");

    char* ntdllFilePath = "C:\\Windows\\System32\\ntdll.dll";
    HANDLE ntDllFileHandle = CreateFileA(ntdllFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (ntDllFileHandle == INVALID_HANDLE_VALUE) {
        printf("    Couldn't Open the DLL! Error Code: %lu\n", GetLastError());

        CloseHandle(processHandle);

        return -1;
    }
    printf("    Opened the DLL Successfully!\n");

    HANDLE ntDllFileMappingHandle = CreateFileMappingA(ntDllFileHandle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);

    if (ntDllFileMappingHandle == NULL) {
        printf("    Couldn't Create a File Mapping Handle! Error Code: %lu\n", GetLastError());

        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);

        return -1;
    }
    printf("    Created a File Map Successfully!\n");

    LPVOID mapViewPointer = MapViewOfFile(ntDllFileMappingHandle, FILE_MAP_READ, 0, 0, 0);

    if (mapViewPointer == NULL) {
        printf("    Map View Failed! Error Code: %lu\n", GetLastError());

        CloseHandle(ntDllFileMappingHandle);
        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);

        return -1;
    }
    printf("    Map View Succeeded!\n");
    printf("    ntdll.dll Loaded into Memory Successfully!\n");

    printf("Locating ntdll.dll in the Target Process..\n");

    BYTE* baseAddressPointer = GetModuleBaseAddress(processHandle, "ntdll.dll");

    if (baseAddressPointer == NULL) {
        printf("    Couldn't find ntdll.dll in the Target Process!\n");

        mapViewPointer = NULL;
        CloseHandle(ntDllFileMappingHandle);
        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);

        return -1;
    }
    printf("    ntdll.dll found in the Target Process at Base Address: 0x%llX\n", (uintptr_t)baseAddressPointer);

    printf("\nDOS HEADERS\n");
    printf("-------------------------------\n");
    PIMAGE_DOS_HEADER dosHeaderPointer = (PIMAGE_DOS_HEADER)baseAddressPointer;

    printf("Magic Signature: ");
    if (dosHeaderPointer->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("0x%X (Invalid)\n", dosHeaderPointer->e_magic);
    
        dosHeaderPointer = NULL;
        baseAddressPointer = NULL;
        mapViewPointer = NULL;
        CloseHandle(ntDllFileMappingHandle);
        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);

        return -1;
    }
    printf("0x%X (Valid)\n", dosHeaderPointer->e_magic);

    printf("e_lfanew: ");

    if (dosHeaderPointer->e_lfanew < 64) {
        printf("0x%lX (Invalid - Smaller than 64)\n", dosHeaderPointer->e_lfanew);

        dosHeaderPointer = NULL;
        baseAddressPointer = NULL;
        mapViewPointer = NULL;
        CloseHandle(ntDllFileMappingHandle);
        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);

        return -1;
    } else if ((dosHeaderPointer->e_lfanew % 4) != 0) {
        printf("0x%lX (Invalid - Not aligned to 4)\n", dosHeaderPointer->e_lfanew);

        dosHeaderPointer = NULL;
        baseAddressPointer = NULL;
        mapViewPointer = NULL;
        CloseHandle(ntDllFileMappingHandle);
        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);

        return -1;
    } else if (dosHeaderPointer->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > UINT32_MAX) {
        printf("0x%lX (Invalid - Overflow)\n", dosHeaderPointer->e_lfanew);

        dosHeaderPointer = NULL;
        baseAddressPointer = NULL;
        mapViewPointer = NULL;
        CloseHandle(ntDllFileMappingHandle);
        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);

        return -1;
    } else if (dosHeaderPointer->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > processFileSize.QuadPart) {
        printf("0x%lX (Invalid - Larger than the file itself)\n", dosHeaderPointer->e_lfanew);
    
        dosHeaderPointer = NULL;
        baseAddressPointer = NULL;
        mapViewPointer = NULL;
        CloseHandle(ntDllFileMappingHandle);
        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);

        return -1;
    }
    printf("0x%lX (Valid)\n", dosHeaderPointer->e_lfanew);

    printf("\nNT HEADERS\n");
    printf("-------------------------------\n");
    PIMAGE_NT_HEADERS32 ntHeadersPointer = (PIMAGE_NT_HEADERS32)(baseAddressPointer + dosHeaderPointer->e_lfanew);

    printf("NT Signature: ");
    if (ntHeadersPointer->Signature != 0x4550) {
        printf("0x%lX (Invalid)\n", ntHeadersPointer->Signature);
        
        ntHeadersPointer = NULL;
        dosHeaderPointer = NULL;
        baseAddressPointer = NULL;
        mapViewPointer = NULL;
        CloseHandle(ntDllFileMappingHandle);
        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);
    
        return -1;
    }
    printf("0x%lX (Valid)\n", ntHeadersPointer->Signature);

    printf("Target Architecture: ");
    if (ntHeadersPointer->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        printf("I386\n");
    } else if (ntHeadersPointer->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        printf("AMD64\n");
    } else if (ntHeadersPointer->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64) {
        printf("ARM64\n");
    } else {
        printf("Unknown\n");

        ntHeadersPointer = NULL;
        dosHeaderPointer = NULL;
        baseAddressPointer = NULL;
        mapViewPointer = NULL;
        CloseHandle(ntDllFileMappingHandle);
        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);
    
        return -1;
    }

    printf("Compiled Time: ");
    char formattedTimeStamp[64];
    if (FormatTime(formattedTimeStamp, sizeof(formattedTimeStamp), ntHeadersPointer->FileHeader.TimeDateStamp)) {
        printf("%ld (%s)\n", ntHeadersPointer->FileHeader.TimeDateStamp, formattedTimeStamp);
    } else {
        printf("%ld\n", ntHeadersPointer->FileHeader.TimeDateStamp);
    }

    printf("Number of Sections: %d\n", ntHeadersPointer->FileHeader.NumberOfSections);

    printf("Characteristics: ");
    int characteristicsTableSize = 15;
    PrintFileCharacteristics(ntHeadersPointer->FileHeader.Characteristics, characteristicsTableSize);

    printf("\nOptional Headers\n");
    printf("-------------------------------\n");

    IMAGE_DATA_DIRECTORY exportData;
    printf("Target Architecture: ");
    if (ntHeadersPointer->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("PE32 (32-bit)\n");
        printf("Entry Point: 0x%08lX\n", ntHeadersPointer->OptionalHeader.AddressOfEntryPoint);
        printf("Image Base: 0x%lX\n", ntHeadersPointer->OptionalHeader.ImageBase);
        printf("Section Alignment: %ld Bytes\n", ntHeadersPointer->OptionalHeader.SectionAlignment);
        printf("File Alignment: %ld Bytes\n", ntHeadersPointer->OptionalHeader.FileAlignment);
        printf("Subsystem: ");
        PrintSubSystem(ntHeadersPointer->OptionalHeader.Subsystem);
        printf("Size of Image: %.2lf KB\n", (double)ntHeadersPointer->OptionalHeader.SizeOfImage / 1024);
        printf("Size of Headers: %ld Bytes\n", ntHeadersPointer->OptionalHeader.SizeOfHeaders);
    
        exportData = ntHeadersPointer->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else if (ntHeadersPointer->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("PE32+ (64-bit)\n");
        
        PIMAGE_NT_HEADERS64 ntHeaders64Pointer = (PIMAGE_NT_HEADERS64)ntHeadersPointer;
        printf("Entry Point: 0x%08lX\n", ntHeaders64Pointer->OptionalHeader.AddressOfEntryPoint);
        printf("Image Base: 0x%llX\n", ntHeaders64Pointer->OptionalHeader.ImageBase);
        printf("Section Alignment: %ld Bytes\n", ntHeaders64Pointer->OptionalHeader.SectionAlignment);
        printf("File Alignment: %ld Bytes\n", ntHeaders64Pointer->OptionalHeader.FileAlignment);
        printf("Subsystem: ");
        PrintSubSystem(ntHeaders64Pointer->OptionalHeader.Subsystem);
        printf("Size of Image: %.2lf KB\n", (double)ntHeaders64Pointer->OptionalHeader.SizeOfImage / 1024);
        printf("Size of Headers: %ld Bytes\n", ntHeaders64Pointer->OptionalHeader.SizeOfHeaders);

        exportData = ntHeaders64Pointer->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else {
        printf("Unknown! Exiting..\n");

        ntHeadersPointer = NULL;
        dosHeaderPointer = NULL;
        baseAddressPointer = NULL;
        mapViewPointer = NULL;
        CloseHandle(ntDllFileMappingHandle);
        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);

        return -1;
    }

    printf("\nSection Headers\n");
    printf("-------------------------------\n");
    printf("Locating the .text Section..\n");
    PIMAGE_SECTION_HEADER sectionHeaderPointer = IMAGE_FIRST_SECTION(ntHeadersPointer);

    DWORD textSectionAddressRVA;
    DWORD textSectionEndAddressRVA;
    BOOL textSectionFound = FALSE;
    for (int i = 0; i < ntHeadersPointer->FileHeader.NumberOfSections; i++) {
        char sectionName[9] = {0};
        memcpy(sectionName, sectionHeaderPointer->Name, 8);

        if (strcmp(sectionName, ".text") == 0) {
            printf("    .text Section Found: ");

            textSectionAddressRVA = sectionHeaderPointer->VirtualAddress;
            textSectionEndAddressRVA = sectionHeaderPointer->VirtualAddress + sectionHeaderPointer->Misc.VirtualSize;
            printf("Starting Addess RVA: 0x%lX | Ending Address RVA: 0x%lX\n", textSectionAddressRVA, textSectionEndAddressRVA);
        
            textSectionFound = TRUE;
            break;
        }

        sectionHeaderPointer++;
    }

    if (!textSectionFound) {
        printf("    Couldn't find .text Section!\n");

        sectionHeaderPointer = NULL;
        ntHeadersPointer = NULL;
        dosHeaderPointer = NULL;
        baseAddressPointer = NULL;
        mapViewPointer = NULL;
        CloseHandle(ntDllFileMappingHandle);
        CloseHandle(ntDllFileHandle);
        CloseHandle(processHandle);

        return -1;
    }

    printf("\nExport Address Table (EAT)\n");
    printf("-------------------------------\n");
    printf("Getting the Real Address of the EAT..\n");
    PIMAGE_EXPORT_DIRECTORY exportDirectoryPointer = (PIMAGE_EXPORT_DIRECTORY)(baseAddressPointer + exportData.VirtualAddress);
    printf("    Done! EAT Real Address is at: 0x%llX\n", (uintptr_t)exportDirectoryPointer);

    printf("Scanning all Functions..\n");
    DWORD* functionNameArrayRVA = (DWORD*)(baseAddressPointer + exportDirectoryPointer->AddressOfNames);
    WORD* addressOfNameOrdinalRVA = (WORD*)(baseAddressPointer + exportDirectoryPointer->AddressOfNameOrdinals);
    DWORD* addressOfFunctionsRVA = (DWORD*)(baseAddressPointer + exportDirectoryPointer->AddressOfFunctions);
    
    unsigned int skippedElements = 0;
    unsigned int cleanFunctions = 0;
    unsigned int hookedFunctions = 0;
    unsigned int fixedFunctions = 0;
    unsigned int unfixedFunctions = 0;

    for (long unsigned int i = 0; i < exportDirectoryPointer->NumberOfNames; i++) {
        char* functionName = (char*)(baseAddressPointer + functionNameArrayRVA[i]);
        WORD functionOrdinal = addressOfNameOrdinalRVA[i];
        DWORD functionAddressRVA = addressOfFunctionsRVA[functionOrdinal];
        uintptr_t realFunctionAddress = (uintptr_t)(baseAddressPointer + functionAddressRVA);
        
        printf("    Scanning Function #%ld: %s (Real Address: 0x%llX)..\n", i + 1, functionName, realFunctionAddress);
        
        BOOL isFunction = FALSE;
        if (functionAddressRVA >= textSectionAddressRVA && functionAddressRVA <= textSectionEndAddressRVA) {
            isFunction = TRUE;
        }

        if (!isFunction) {
            printf("    %s is not a Function! Skipping..\n\n", functionName);
            skippedElements++;

            continue;
        }

        BYTE targetFunctionBytes[16] = { 0 };
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(processHandle, (LPCVOID)realFunctionAddress, targetFunctionBytes, sizeof(targetFunctionBytes), &bytesRead)) {
            printf("    ERROR: Couldn't Read the Function's Data from the Target Process!\n");

            continue;
        }

        BYTE* cleanFunctionAddress = (BYTE*)mapViewPointer + functionAddressRVA;
        BYTE cleanFunctionBytes[16] = { 0 };

        memcpy(cleanFunctionBytes, cleanFunctionAddress, sizeof(cleanFunctionBytes));

        if (memcmp(targetFunctionBytes, cleanFunctionBytes, sizeof(cleanFunctionBytes)) != 0) {
            hookedFunctions++;
            printf("    ALERT! Function is Hooked!\n");
            printf("    Fixing..\n");

            DWORD oldProtect = 0;
            if (!VirtualProtectEx(processHandle, (LPVOID)realFunctionAddress, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                unfixedFunctions++;
                printf("    ERROR: Couldn't change the Page Protection Level!\n\n");

                continue;
            }

            SIZE_T bytesWritten = 0;
            if (!WriteProcessMemory(processHandle, (LPVOID)realFunctionAddress, cleanFunctionBytes, 16, &bytesWritten)) {
                unfixedFunctions++;
                printf("    ERROR: Couldn't Write Clean Data in the Page!\n\n");

                continue;
            }

            DWORD tempProtect = 0;
            if (!VirtualProtectEx(processHandle, (LPVOID)realFunctionAddress, 16, oldProtect, &tempProtect)) {
                unfixedFunctions++;
                printf("    ERROR: Couldn't Restore Page's Protection!\n\n");

                continue;
            }

            FlushInstructionCache(processHandle, (LPVOID)realFunctionAddress, 16);

            printf("    Function has been Restored!\n");
            fixedFunctions++;
        } else {
            printf("    Function is Clean!\n");
            cleanFunctions++;
        }
        printf("\n");
    }
    printf("Scan Complete!\n");

    printf("\nScan Summary\n");
    printf("-------------------------------\n");
    printf("Total Number of Elements Checked: %lu Elements\n", exportDirectoryPointer->NumberOfNames);
    printf("Total Number of Elements Skipped: %u Elements\n", skippedElements);
    printf("Total Number of Functions Scanned: %lu Functions\n", exportDirectoryPointer->NumberOfNames - skippedElements);
    printf("Total Number of Clean Functions: %u Functions\n", cleanFunctions);
    printf("Total Number of Functions Hooked: %u Functions\n", hookedFunctions);
    printf("Total Number of Functions Fixed: %u Functions\n", fixedFunctions);
    printf("Total Number of Unfixed Functions: %u Functions\n", unfixedFunctions);

    printf("\nExiting..\n");
    sectionHeaderPointer = NULL;
    ntHeadersPointer = NULL;
    dosHeaderPointer = NULL;
    baseAddressPointer = NULL;
    mapViewPointer = NULL;
    CloseHandle(ntDllFileMappingHandle);
    CloseHandle(ntDllFileHandle);
    CloseHandle(processHandle);

    return 0;
}

BYTE* GetModuleBaseAddress(HANDLE processHandle, const char* moduleName) {
    HMODULE modulesHandle[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(processHandle, modulesHandle, sizeof(modulesHandle), &cbNeeded)) {
        int numberOfModules = cbNeeded / sizeof(HMODULE);

        for (int i = 0; i < numberOfModules; i++) {
            char modName[MAX_PATH];

            if (GetModuleBaseNameA(processHandle, modulesHandle[i], modName, sizeof(modName) / sizeof(char))) {
                if (_stricmp(modName, moduleName) == 0) {
                    return (BYTE*)modulesHandle[i];
                }
            }
        }
    }

    return NULL;
}

bool FormatTime(char* formattedTime, size_t stringSize, DWORD originalTime) {
    time_t rawTime = (time_t)originalTime;
    struct tm *utc_time;

    utc_time = gmtime(&rawTime);

    if (utc_time == NULL) {
        printf("Couldn't format the date!\n");

        return false;
    }

    size_t result = strftime(formattedTime, stringSize, "%a %b %d %H:%M:%S %Y UTC", utc_time);
    
    if (result == 0) {
        return false;
    }

    return true;
}

void PrintFileCharacteristics(WORD fileCharacteristics, int characteristicsTableSize) {
    BOOL isFirst = TRUE;

    printf("0x%X (", fileCharacteristics);
    for (int i = 0; i < characteristicsTableSize; i++) {
        if ((fileCharacteristics & FileCharacteristicsTable[i].flag) == FileCharacteristicsTable[i].flag) {
            if (!isFirst) {
                printf(", ");
            }

            printf("%s", FileCharacteristicsTable[i].name);
            isFirst = FALSE;
        }
    }

    if (isFirst) {
        printf("None");
    }
    printf(")\n");
}

void PrintSubSystem(WORD subSystem) {
    if (subSystem == IMAGE_SUBSYSTEM_UNKNOWN) {
        printf("Unknown\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_NATIVE) {
        printf("Device Driver / Native System Process\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
       printf("Windows GUI\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
        printf("Windows CUI (Console)\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_OS2_CUI) {
        printf("OS/2 CUI\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_POSIX_CUI) {
        printf("POSIX CUI\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_CE_GUI) {
        printf("Windows CE System\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_APPLICATION) {
        printf("EFI Application\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) {
        printf("EFI Driver with Boot Services\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
        printf("EFI Driver with Run-Time Services\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_EFI_ROM) {
        printf("EFI ROM Image\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_XBOX) {
        printf("Xbox System\n");
    } else if (subSystem == IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION) {
        printf("Windows Boot Application\n");
    }
}