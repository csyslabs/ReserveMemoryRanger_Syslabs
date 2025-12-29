#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <vector>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <cstdint>

#pragma comment(lib, "Psapi.lib")

// 结构体：存储连续保留页区域信息
struct ReservedRegion {
    void* baseAddress;  // 区域基地址
    size_t pageCount;   // 连续页数量
};

// 比较函数：按页数量降序排序
bool CompareRegionsBySize(const ReservedRegion& a, const ReservedRegion& b) {
    return a.pageCount > b.pageCount;
}

// 通过进程名获取进程ID
DWORD GetProcessIdByName(const wchar_t* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "创建进程快照失败. 错误代码: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
    DWORD processId = 0;

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (wcscmp(processEntry.szExeFile, processName) == 0) {
                processId = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return processId;
}

int main() {
    const wchar_t* targetProcessName = L"VMX-Sentinel.exe";
    DWORD processId = GetProcessIdByName(targetProcessName);

    if (processId == 0) {
        std::cerr << "未找到进程: " << targetProcessName << std::endl;
        getchar();
        return EXIT_FAILURE;
    }

    // 以必要权限打开目标进程
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        processId
    );

    if (!hProcess) {
        std::cerr << "打开进程失败. 错误代码: " << GetLastError() << std::endl;
        getchar();
        return EXIT_FAILURE;
    }

    std::vector<ReservedRegion> reservedRegions;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const DWORD pageSize = sysInfo.dwPageSize;
    uintptr_t currentAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
    uintptr_t maxAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);

    // 遍历整个进程地址空间
    while (currentAddress < maxAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T bytesRead = VirtualQueryEx(
            hProcess,
            reinterpret_cast<LPCVOID>(currentAddress),
            &mbi,
            sizeof(mbi)
        );

        if (bytesRead == 0) {
            currentAddress += pageSize;  // 跳过无效区域
            continue;
        }

        // 检查保留状态的内存区域（无PTE映射）
        if (mbi.State == MEM_RESERVE) {
            size_t pageCount = mbi.RegionSize / pageSize;
            reservedRegions.push_back({
                mbi.BaseAddress,
                pageCount
                });
        }

        // 移动到下一个内存区域
        currentAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }

    // 按连续页数量降序排序
    std::sort(reservedRegions.begin(), reservedRegions.end(), CompareRegionsBySize);

    // 输出结果
    std::cout << std::left
        << std::setw(24) << "基地址"        // 列宽增至24
        << std::setw(15) << "连续页数量"
        << std::setw(15) << "区域大小(KB)"
        << std::endl;
    std::cout << std::string(55, '-') << std::endl;

    for (const auto& region : reservedRegions) {
        double regionSizeKB = static_cast<double>(region.pageCount * pageSize) / 1024.0;
        // 关键修复：用临时字符串缓冲基地址
        char addrBuf[24];
        snprintf(addrBuf, sizeof(addrBuf), "0x%016llX", (unsigned long long)region.baseAddress);

        std::cout << std::left
            << std::setw(24) << addrBuf     // 固定24字符宽度
            << std::setw(15) << region.pageCount
            << std::fixed << std::setprecision(2)
            << std::setw(15) << regionSizeKB
            << std::endl;
    }

    CloseHandle(hProcess);
    getchar();
    return EXIT_SUCCESS;
}