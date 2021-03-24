#include "Memory.h"

#include <iostream>
#include <vector>
#include <sstream>
#include <thread>
#include <mutex>
#include <codecvt>
#include <locale>
#include <fstream>
#include <unordered_map>
#include "Windows.h"
#include "memoryapi.h"
#include "tlhelp32.h"
#include "errhandlingapi.h"
#include "winnt.h"
#include "securitybaseapi.h"
#include "processthreadsapi.h"
#include <stdio.h>

constexpr auto NUM_THREADS = 6;
constexpr auto SNIFF_FILE_DELIM = "|";
constexpr auto RPM_INITI_CHUNK_READ_SIZE = 8 * 1024;

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

class MemoryRegionRecord : public MEMORY_BASIC_INFORMATION {
public:
    MemoryRegionRecord(DWORD pid, MEMORY_BASIC_INFORMATION & info) {
        AssociatedPid = pid;
        BaseAddress = info.BaseAddress;
        AllocationBase = info.AllocationBase;
        AllocationProtect = info.AllocationProtect;
        RegionSize = info.RegionSize;
        State = info.State;
        Protect = info.Protect;
        Type = info.Type;
    }
    DWORD AssociatedPid;
};

class MemoryRegionCopy {
public:
    std::vector<char> bytes;
};

class SniffRecord {
public:
    uint64_t pid;
    uint64_t location;
    std::string type;
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

std::vector<MemoryRegionRecord> getAllMemoryRegionsForPID(DWORD pid)
{
    auto result = std::vector<MemoryRegionRecord>();
    const auto proc_handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
        false,
        pid
    );

    auto memory_basic_info = MEMORY_BASIC_INFORMATION();
    auto addr = unsigned long long(0);
    while (true)
    {
        auto num_bytes_vq_ex_written = VirtualQueryEx(
            proc_handle,
            (LPVOID)addr,
            (PMEMORY_BASIC_INFORMATION)&memory_basic_info,
            sizeof(memory_basic_info)
        );

        if (num_bytes_vq_ex_written == 0) {
            break;
        }

        result.push_back(MemoryRegionRecord(pid, memory_basic_info));
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
    if (record.RegionSize == 0 || record.BaseAddress == 0) return;

    const auto proc_handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        false,
        record.AssociatedPid
    );

    out_region.bytes.clear();
    char buffer[RPM_INITI_CHUNK_READ_SIZE];

    SIZE_T num_bytes_read = 0;

    auto chunk_factor = RPM_INITI_CHUNK_READ_SIZE;
    auto start = (SIZE_T)record.BaseAddress;
    auto end = start + record.RegionSize;
    auto i = 0;
    while (start < end) {

        auto rpm_result = ReadProcessMemory(
            proc_handle,
            (LPVOID)start,
            (LPVOID)buffer,
            min(chunk_factor, end - start),
            &num_bytes_read
        );

        if (rpm_result != 0 && chunk_factor < RPM_INITI_CHUNK_READ_SIZE) {
            chunk_factor = min(chunk_factor * 4, RPM_INITI_CHUNK_READ_SIZE);
        }

        if (rpm_result == 0 && chunk_factor > 1) {
            chunk_factor = min(chunk_factor / 4, 1);
            ZeroMemory(buffer, RPM_INITI_CHUNK_READ_SIZE);
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
    if (record.RegionSize == 0 || record.BaseAddress == 0) return;

    const auto proc_handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
        false,
        record.AssociatedPid
    );

    DWORD oldprotect;
    LPVOID dst = (LPVOID)((SIZE_T)record.BaseAddress + byte_offset);
    VirtualProtectEx(proc_handle, dst, 1, PAGE_EXECUTE_READWRITE, &oldprotect);
    SIZE_T num_bytes_written = 0;
    char byte_to_write = byte_to_set;
    auto wpm_result = WriteProcessMemory(
        proc_handle,
        dst,
        (LPVOID)&byte_to_write,
        1,
        &num_bytes_written
    );
    VirtualProtectEx(proc_handle, dst, 1, oldprotect, &oldprotect);

    CloseHandle(proc_handle);
}


class SharedMemory {
    size_t current_job = 0;
public:
    SharedMemory(const std::unordered_map<std::string, std::string> & args, const std::unordered_map<int64_t, SniffRecord> sniffs) : args(args), sniffs(sniffs) {}
    std::mutex lock;
    size_t thread_edits[NUM_THREADS] = { 0 };
    size_t thread_bytes[NUM_THREADS] = { 0 };
    std::vector<SniffRecord> thread_sniffs[NUM_THREADS];
    size_t getNextJob() {
        lock.lock();
        auto result = current_job++;
        lock.unlock();
        return result;
    }
    std::vector<MemoryRegionRecord> records;
    const std::unordered_map<std::string, std::string> & args;
    const std::unordered_map<int64_t, SniffRecord> & sniffs;
};

std::unordered_map<std::string, std::string> getArguments(int argc, char * argv[]) {
    std::unordered_map<std::string, std::string> result;
    int arg_pos = 2;
    result["path"] = std::string(argv[0]);
    result["action"] = std::string(argv[1]);

    while (arg_pos < argc) {
        if (argv[arg_pos][0] == '-' && arg_pos + 1 < argc) {
            auto key = std::string(argv[arg_pos++]);
            key.erase(0, 1);
            auto value = std::string(argv[arg_pos++]);
            result[key] = value;
        }
        else {
            arg_pos++;
        }
    }

    return result;
}


SniffRecord getSniffRecordFromLine(std::string & str) {
    SniffRecord result;
    size_t last = 0, next = 0;

    for (auto i = 0; i < 3; ++i) {
        next = str.find(SNIFF_FILE_DELIM, last);
        switch (i) {
        case 0:
            result.pid = std::stoll(str.substr(last, next));
            break;
        case 1:
            result.location = std::stoll(str.substr(last, next));
            break;
        case 2:
            result.type = str.substr(last, next);
            break;
        }
        last = next + 1;
    }

    return result;
}

std::unordered_map<int64_t, SniffRecord> getSniffsForProcess(std::string & exec_name) {
    std::unordered_map<int64_t, SniffRecord> result;
    std::ifstream sniff_file("." + exec_name + ".sniff");
    if (sniff_file.is_open()) {
        std::string line;
        while (true) {
            std::getline(sniff_file, line);
            if (line.empty()) break;
            SniffRecord record = getSniffRecordFromLine(line);
            result[record.location] = record;
        }

    }
    return result;
}

void writeSniffsToSniffFile(const std::string & exec_name, const std::vector<SniffRecord *> & sniff_records) {
    std::ofstream sniff_file("." + exec_name + ".sniff");
    if (sniff_file.is_open()) {
        for (auto record : sniff_records) {
            sniff_file << record->pid << SNIFF_FILE_DELIM << record->location << SNIFF_FILE_DELIM << record->type << std::endl;
        }
    }
}

// TODO: Refactor to drive from SniffRecords
void do_replaces(int id, SharedMemory * sm) {
    auto mem_region_copy = MemoryRegionCopy();
    auto replace_type = sm->args.at("type");
    for (auto i = sm->getNextJob(); i < sm->records.size(); i = sm->getNextJob()) {
        const auto & region_record = sm->records[i];
        getMemoryRegionCopyForMemoryRegionRecord(region_record, mem_region_copy);
        sm->thread_bytes[id] += mem_region_copy.bytes.size();
        for (uint64_t i = 0; i < mem_region_copy.bytes.size(); ++i) {
            bool match = true;
            if (i + sm->args.at("set").size() < mem_region_copy.bytes.size() && replace_type == "str") {
                std::string value_to_replace = sm->args.at("find");
                for (uint64_t j = 0; j < value_to_replace.size(); ++j) {
                    if (mem_region_copy.bytes[i + j] != value_to_replace.at(j)) {
                        match = false;
                        break;
                    }
                }
            }
            else if (i + 3 < mem_region_copy.bytes.size() && replace_type == "i32") {
                char i32_bytes[] = {
                    mem_region_copy.bytes[i],
                    mem_region_copy.bytes[i + 1],
                    mem_region_copy.bytes[i + 2],
                    mem_region_copy.bytes[i + 3]
                };
                match = *((int32_t *)i32_bytes) == std::stoi(sm->args.at("find"));
            }
            else if (i + 3 < mem_region_copy.bytes.size() && replace_type == "f32") {
                char f32_bytes[] = {
                    mem_region_copy.bytes[i],
                    mem_region_copy.bytes[i + 1],
                    mem_region_copy.bytes[i + 2],
                    mem_region_copy.bytes[i + 3]
                };
                float val = *(float*)f32_bytes;
                match = val == std::stof(sm->args.at("find"));
            }

            if (match) {
                sm->thread_edits[id]++;
                if (replace_type == "str") {
                    for (auto j = 0; j < sm->args.at("set").size() && j < sm->args.at("find").size(); ++j) {
                        setByteAtLocationForMemoryRegionRecord(region_record, i + j, sm->args.at("set")[j]);
                    }
                }
                else if (replace_type == "i32") {
                    int32_t value = std::stoi(sm->args.at("set"));
                    char * value_byte_ptr = (char *)&value;
                    for (auto j = 0; j < 4; ++j) {
                        setByteAtLocationForMemoryRegionRecord(region_record, i + j, *(value_byte_ptr + j));
                    }
                }
                else if (replace_type == "f32") {
                    float value = std::stof(sm->args.at("set"));
                    char * value_byte_ptr = (char *)&value;
                    for (auto j = 0; j < 4; ++j) {
                        setByteAtLocationForMemoryRegionRecord(region_record, i + j, *(value_byte_ptr + j));
                    }
                }
            }

        }
    }
}

void do_sniffs(int id, SharedMemory * sm) {
    auto mem_region_copy = MemoryRegionCopy();
    auto replace_type = sm->args.at("type");
    auto is_resniff = sm->args.at("action") == "resniff";


    for (auto i = sm->getNextJob(); i < sm->records.size(); i = sm->getNextJob()) {
        const auto & region_record = sm->records[i];
        getMemoryRegionCopyForMemoryRegionRecord(region_record, mem_region_copy);
        sm->thread_bytes[id] += mem_region_copy.bytes.size();
        for (uint64_t i = 0; i < mem_region_copy.bytes.size(); ++i) {
            bool match = false;
            if (i + sm->args.at("find").size() < mem_region_copy.bytes.size() && replace_type == "str") {
                std::string value_to_replace = sm->args.at("find");
                for (uint64_t j = 0; j < value_to_replace.size(); ++j) {
                    match = mem_region_copy.bytes[i + j] == value_to_replace.at(j);
                    if (!match) break;
                }
            }
            else if (i + 3 < mem_region_copy.bytes.size() && replace_type == "i32") {
                char i32_bytes[] = {
                    mem_region_copy.bytes[i],
                    mem_region_copy.bytes[i + 1],
                    mem_region_copy.bytes[i + 2],
                    mem_region_copy.bytes[i + 3]
                };
                int32_t val = *(int32_t *)i32_bytes;
                match = val == std::stoi(sm->args.at("find"));
            }
            else if (i + 3 < mem_region_copy.bytes.size() && replace_type == "f32") {
                char f32_bytes[] = {
                    mem_region_copy.bytes[i],
                    mem_region_copy.bytes[i + 1],
                    mem_region_copy.bytes[i + 2],
                    mem_region_copy.bytes[i + 3]
                };
                match = *((float *)f32_bytes) == std::stof(sm->args.at("find"));
            }

            if (match) {
                SniffRecord record;
                record.pid = region_record.AssociatedPid;
                record.location = ((uint64_t) region_record.BaseAddress) + i;
                record.type = replace_type;
                sm->thread_sniffs[id].push_back(record);
            }
        }
    }
}


int main(int argc, char * argv[])
{
    float var_to_sniff = 123456.23;

    auto args = getArguments(argc, argv);

    static std::unordered_map <std::string, std::vector<std::string> > required = {
        { "action", { "sniff", "replace", "resniff" } },
        { "type", { "i32", "f32", "str" } },
        { "find", { "*" } },
    };

    for (const auto & required_pair : required) {
        const auto & key = required_pair.first;
        const auto & value_array = required_pair.second;

        bool has_match = false;
        for (const auto & test_value : value_array) {
            has_match = test_value == "*" || has_match || args[key] == test_value;
        }

        if (!has_match) {
            std::cout << "Expected usage ./sniffer.exe [sniff|resniff|replace] -pname 'process_name' -sniff-pred [gt|eq|lt] -type [i32|f32|str] -find 'value_to_replace' -set 'value_to_set'" << std::endl;
            return 0;
        }
    }

    auto sniffs = getSniffsForProcess(args["pname"]);

    setDebugPriv();
    ProfileTimer timer("sniffer");

    SharedMemory mem(args, sniffs);

    const auto executable_to_consider = args["pname"];
    const auto executable_to_consider_wstring = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(executable_to_consider);
    const auto pids_to_consider = getPIDSForProcessName(executable_to_consider_wstring);

    for (auto i = 0; i < pids_to_consider.size(); ++i) {
        const auto records_for_pid = getAllMemoryRegionsForPID(pids_to_consider[i]);
        mem.records.insert(mem.records.end(), records_for_pid.begin(), records_for_pid.end());
    }

    std::vector<std::thread> threads;
    if (args["action"] == "replace") {
        for (auto i = 0; i < NUM_THREADS; ++i) {
            threads.push_back(std::thread(do_replaces, i, &mem));
        }
    }
    else if (args["action"] == "sniff" || args["action"] == "resniff") {
        for (auto i = 0; i < NUM_THREADS; ++i) {
            threads.push_back(std::thread(do_sniffs, i, &mem));
        }
    }

    while (!threads.empty()) {
        threads.back().join();
        threads.pop_back();
    }

    size_t total_bytes_considered = 0;
    size_t total_replacements = 0;
    size_t total_sniffs = 0;
    std::vector<SniffRecord *> sniff_records;
    std::vector<float *> debug_ptrs;
    float * ptr_to_find = &var_to_sniff;

    for (auto i = 0; i < NUM_THREADS; ++i) {
        total_bytes_considered += mem.thread_bytes[i];
        total_replacements += mem.thread_edits[i];
        total_sniffs += mem.thread_sniffs[i].size();
        for (auto & record : mem.thread_sniffs[i]) {
            sniff_records.push_back(&record);
            debug_ptrs.push_back((float *)record.location);
        }
    }

    writeSniffsToSniffFile(executable_to_consider, sniff_records);

    std::cout <<
        "Found and replaced " << total_replacements <<
        " instances of \"" << mem.args.at("find") <<
        "\" to \"" << (mem.args.count("set") > 0 ? mem.args.at("set").c_str() : "") <<
        "\" across " << pids_to_consider.size() << " processes and " << mem.records.size() << " mem regions considering " << total_bytes_considered << " total bytes" <<
        " for " << executable_to_consider << std::endl;

    return 0;
}
