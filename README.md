# Process Memory Reserved Region Scanner

A Windows utility to analyze reserved memory regions (`MEM_RESERVE`) in target processes, providing critical insights for memory optimization and debugging.

## Key Features
- Scans all reserved memory regions in a specified process
- Sorts regions by contiguous page count (descending)
- Reports memory type (`Private`/`Mapped`/`Image`) and protection attributes
- Human-readable formatted output with base addresses, sizes, and metadata

## Build Requirements
- Windows SDK (10.0.19041.0 or higher)
- Visual Studio 2019+ (supports C++17)
- Administrator privileges for process access

## Usage
```bash
MemoryScanner.exe [process_name.exe]
```
Default target: `VMX-Sentinel.exe`  
*Example:*  
`MemoryScanner.exe notepad.exe`

## Sample Output
```
基地址                    连续页数量       区域大小(KB)    类型        权限      
--------------------------------------------------------------------------------
0x00007FF4F6630000      1048608        4194432.00     Private     NOACCESS
0x00007FF5F6650000      8192           32768.00       Image       NOACCESS
0x000001F7DC936000      4859           19436.00       Mapped      NOACCESS
...
```

## Critical Notes
1. **Administrator rights required**: Memory scanning requires `SeDebugPrivilege`
2. **Reserved vs. committed memory**:  
   - `MEM_RESERVE` regions show `NOACCESS` protection (no physical storage allocated)
   - Large reserved regions (e.g., 4GB) are **normal** for heap managers (.NET/Unity/Unreal)
3. **Address interpretation**:
   - `7FFx` prefixes: System-reserved high memory (loader heap)
   - Low addresses (`0x000001xx`): Application-managed private/mapped regions

## Validation Tools
Verify results with Microsoft Sysinternals utilities:
- [VMMap](https://learn.microsoft.com/en-us/sysinternals/downloads/vmmap): Detailed memory region analysis
- [Process Hacker](https://processhacker.sourceforge.io/): Real-time memory type/permission inspection

> **Warning**: Modifying PTEs directly requires kernel-mode drivers and triggers Windows PatchGuard. Use `VirtualAlloc(MEM_COMMIT)` for safe physical memory allocation. This tool is for diagnostic purposes only.
<img width="1979" height="846" alt="image" src="https://github.com/user-attachments/assets/e5740dce-bd0a-4603-8bf0-2275ce6da02a" />

