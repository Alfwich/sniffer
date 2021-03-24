#include "Memory.h"

#include <iostream>
#include <vector>
#include <sstream>
#include <thread>
#include <mutex>
#include "Windows.h"
#include "memoryapi.h"
#include "tlhelp32.h"
#include "errhandlingapi.h"
#include "winnt.h"
#include "securitybaseapi.h"
#include "processthreadsapi.h"
#include <stdio.h>

class ProfileTimer
{
    const char * label;
    long long start, end;
    bool started = true;

    long long getCurrentMicroseconds()
    {
        auto now = std::chrono::system_clock::now();
        auto time = now.time_since_epoch().count();
        return std::chrono::microseconds(time).count();
    }

    void report()
    {
        std::cout << label << " took " << (end - start) / 10000.0 << "(ms)" << std::endl;
    }

public:
    ProfileTimer() : label(0), start(getCurrentMicroseconds()) {}
    ProfileTimer(const char * label) : label(label), start(getCurrentMicroseconds()) {}
    ~ProfileTimer() { stop(); }

    void stop()
    {
        if (started)
        {
            end = getCurrentMicroseconds();
            started = false;

            report();
        }
    }
};

typedef uint64_t PID;
class MemoryRegionRecord {
public:
    PID associated_pid;
    uint64_t base_ptr;
    uint64_t size;
};

class MemoryRegionCopy {
public:
    std::vector<char> bytes;
};

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    LUID luid;
    BOOL bRet = FALSE;

    if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;
        //
        //  Enable the privilege or disable all privileges.
        //
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        {
            //
            //  Check to see if you have proper access.
            //  You may get "ERROR_NOT_ALL_ASSIGNED".
            //
            bRet = (GetLastError() == ERROR_SUCCESS);
        }
    }
    return bRet;
}

std::vector<DWORD> FindProcessId(const std::wstring & processName)
{
    std::vector<DWORD> result;
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return result;
    }

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        result.push_back(processInfo.th32ProcessID);
            
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            result.push_back(processInfo.th32ProcessID);
        }
    }

    CloseHandle(processesSnapshot);
    return result;
}

void GetAllProcesses(std::vector<std::wstring> & out_vec) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    Process32First(processesSnapshot, &processInfo);
    out_vec.push_back(processInfo.szExeFile);

    while (Process32Next(processesSnapshot, &processInfo))
    {
        out_vec.push_back(processInfo.szExeFile);
    }

    CloseHandle(processesSnapshot);
}

const uint64_t CHUNK_SIZE = 8 * 1024;

void setDebugPriv() {
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hToken;

    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
        CloseHandle(hToken);
    }
}


std::vector<std::wstring> getOpenProcesses() {
    std::vector<std::wstring> output;
    GetAllProcesses(output);
    return output;
}

std::vector<MemoryRegionRecord> getAllMemoryRegionsForPID(PID pid)
{
    auto result = std::vector<MemoryRegionRecord>();
    const auto proc_handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
        false,
        (DWORD) pid
    );

    auto memory_basic_info = MEMORY_BASIC_INFORMATION();
    auto addr = unsigned long long(0);
    while (true)
    {
        auto num_bytes_vq_ex_written = VirtualQueryEx(
            proc_handle,
            (LPVOID) addr,
            (PMEMORY_BASIC_INFORMATION) & memory_basic_info,
            sizeof(memory_basic_info)
        );

        if (num_bytes_vq_ex_written == 0) {
            break;
        }

        std::stringstream ss;
        auto mem_region = MemoryRegionRecord();
        mem_region.associated_pid = pid;
        mem_region.base_ptr = (uint64_t)memory_basic_info.BaseAddress;
        mem_region.size = memory_basic_info.RegionSize;
        result.push_back(mem_region);
        addr += memory_basic_info.RegionSize;
    }

    CloseHandle(proc_handle);

    return result;
}

std::vector<DWORD> getPIDSForProcessName(std::wstring proc_name)
{
    return FindProcessId(proc_name);
}

void getMemoryRegionCopyForMemoryRegionRecord(const MemoryRegionRecord & record, MemoryRegionCopy & out_region)
{
    if (record.size == 0 || record.base_ptr == 0) return;

    const auto proc_handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        false,
        (DWORD)record.associated_pid
    );

    out_region.bytes.clear();
    char buffer[CHUNK_SIZE];

    SIZE_T num_bytes_read = 0;

    auto chunk_factor = CHUNK_SIZE;
    auto start = record.base_ptr;
    auto end = start + record.size;
    auto i = 0;
    while (start < end) {

        auto rpm_result = ReadProcessMemory(
            proc_handle,
            (LPVOID) start,
            (LPVOID) buffer,
            min(chunk_factor, end - start),
            &num_bytes_read
        );

        if (rpm_result != 0 && chunk_factor < CHUNK_SIZE) {
            chunk_factor = min(chunk_factor * 4, CHUNK_SIZE);
        }

        if (rpm_result == 0 && chunk_factor > 1) {
            chunk_factor = min(chunk_factor / 4, 1);
            ZeroMemory(buffer, CHUNK_SIZE);
            continue;
        }
        else if (rpm_result == 0) {
            break;
        }

        for (i = 0; i < num_bytes_read; ++i) {
            out_region.bytes.push_back(buffer[i]);
        }

        start += num_bytes_read;
    }

    CloseHandle(proc_handle);
}

void setByteAtLocationForMemoryRegionRecord(const MemoryRegionRecord & record, uint64_t byte_offset, char byte_to_set)
{
    if (record.size == 0 || record.base_ptr == 0) return;

    const auto proc_handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
        false,
        (DWORD)record.associated_pid
    );

    DWORD oldprotect;
    LPVOID dst = (LPVOID) (record.base_ptr + byte_offset);
    VirtualProtectEx(proc_handle, dst, 1, PAGE_EXECUTE_READWRITE, &oldprotect);
    SIZE_T num_bytes_written = 0;
    char byte_to_write = byte_to_set;
    auto wpm_result = WriteProcessMemory(
        proc_handle,
        (LPVOID) (record.base_ptr + byte_offset),
        (LPVOID) & byte_to_write,
        1,
        &num_bytes_written
    );
    VirtualProtectEx(proc_handle, dst, 1, oldprotect, &oldprotect);

    CloseHandle(proc_handle);
}

#define NUM_THREADS 6

class shared_memory {
public:
    std::mutex lock;
    size_t thread_edits[NUM_THREADS] = { 0 };
    size_t thread_bytes[NUM_THREADS] = { 0 };
    size_t current_job = 0;
    size_t getNextJob() {
        lock.lock();
        auto result = current_job++;
        lock.unlock();
        return result;
    }
    std::string value_to_replace;
    std::string value_to_set;
    std::vector<MemoryRegionRecord> records;
};

void do_replaces(int id, shared_memory * shared_memory) {
    auto mem_region_copy = MemoryRegionCopy();
    for (auto i = shared_memory->getNextJob(); i < shared_memory->records.size(); i = shared_memory->getNextJob()) {
        const auto & region_record = shared_memory->records[i];
        getMemoryRegionCopyForMemoryRegionRecord(region_record, mem_region_copy);
        shared_memory->thread_bytes[id] += mem_region_copy.bytes.size();
        for (uint64_t i = 0; i < mem_region_copy.bytes.size(); ++i) {
            bool match = true;
            for (uint64_t j = 0; j < shared_memory->value_to_replace.size(); ++j) {
                if (mem_region_copy.bytes[i + j] != shared_memory->value_to_replace.at(j)) {
                    match = false;
                    break;
                }
            }

            if (match) {
                shared_memory->thread_edits[id]++;
                for (auto j = 0; j < shared_memory->value_to_set.size() && j < shared_memory->value_to_replace.size(); ++j) {
                    setByteAtLocationForMemoryRegionRecord(region_record, i + j, shared_memory->value_to_set[j]);
                }
            }
        }
    }
}

int main()
{
    setDebugPriv();
    ProfileTimer timer("main");

    shared_memory mem;

    const auto executable_to_consider = L"atom.exe";
    const auto pids_to_consider = getPIDSForProcessName(L"firefox.exe");
    mem.value_to_replace = "Liberal Hivemind";
    mem.value_to_set = "Crying Clown";

    for (auto i = 0; i < pids_to_consider.size(); ++i) {
        const auto records_for_pid = getAllMemoryRegionsForPID(pids_to_consider[i]);
        mem.records.insert(mem.records.end(), records_for_pid.begin(), records_for_pid.end());
    }

    std::vector<std::thread> threads;
    for (auto i = 0; i < NUM_THREADS; ++i) {
        threads.push_back(std::thread(do_replaces, i, &mem));
    }

    while (!threads.empty()) {
        threads.back().join();
        threads.pop_back();
    }

    size_t total_bytes_considered = 0;
    size_t total_replacements = 0;

    for (auto i = 0; i < NUM_THREADS; ++i) {
        total_bytes_considered += mem.thread_bytes[i];
        total_replacements += mem.thread_edits[i];
    }

    std::cout << 
        "Found and replaced " << total_replacements << 
        " instances of \"" << mem.value_to_replace << 
        "\" to \"" << mem.value_to_set << 
        "\" across " << pids_to_consider.size() << 
        " processes for executable name \"" << executable_to_consider << "\"" << std::endl;

    return 0;
}
