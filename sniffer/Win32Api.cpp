#include "Win32Api.h"

#include <string>
#include <set>
#include <unordered_map>
#include <fstream>

#include "processthreadsapi.h"
#include "errhandlingapi.h"
#include "winnt.h"
#include "securitybaseapi.h"
#include <stdint.h>

#include "Params.h"

namespace win_api {
    BOOL setPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
        LUID luid;
        BOOL bRet = FALSE;

        if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
            TOKEN_PRIVILEGES tp;

            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;
            //
            //  Enable the privilege or disable all privileges.
            //
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
                //
                //  Check to see if you have proper access.
                //  You may get "ERROR_NOT_ALL_ASSIGNED".
                //
                bRet = (GetLastError() == ERROR_SUCCESS);
            }
        }
        return bRet;
    }

    void getAllProcesses(std::vector<PROCESSENTRY32> & out_vec) {
        PROCESSENTRY32 processInfo;
        processInfo.dwSize = sizeof(processInfo);

        HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        if (processesSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        Process32First(processesSnapshot, &processInfo);
        out_vec.push_back(processInfo);

        while (Process32Next(processesSnapshot, &processInfo)) {
            out_vec.push_back(processInfo);
        }

        CloseHandle(processesSnapshot);
    }

    void setDebugPriv() {
        HANDLE hProcess = GetCurrentProcess();
        HANDLE hToken;

        if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
            setPrivilege(hToken, SE_DEBUG_NAME, TRUE);
            CloseHandle(hToken);
        }
    }

    std::vector<PROCESSENTRY32> getOpenProcesses() {
        std::vector<PROCESSENTRY32> output;
        getAllProcesses(output);
        return output;
    }

    std::vector<DWORD> findProcessId(const std::wstring & processName) {
        std::vector<DWORD> result;
        const auto & all_procs = getOpenProcesses();

        for (const auto proc : all_procs) {
            if (processName.compare(proc.szExeFile) == 0) {
                result.push_back(proc.th32ProcessID);
            }
        }

        return result;
    }

    std::set<uint64_t> getAllLivePIDs() {
        std::set<uint64_t> output;
        const auto all_procs = getOpenProcesses();

        for (const auto & proc : all_procs) {
            output.insert(proc.th32ProcessID);
        }

        return output;
    }

    std::vector<MemoryRegionRecord> getAllMemoryRegionsForPID(DWORD pid) {
        auto result = std::vector<MemoryRegionRecord>();
        const auto proc_handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
            false,
            pid
        );

        auto memory_basic_info = MEMORY_BASIC_INFORMATION();
        auto addr = unsigned long long(0);
        while (true) {
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

    std::vector<DWORD> getPIDSForProcessName(std::wstring proc_name) {
        return findProcessId(proc_name);
    }

    void getMemoryRegionCopyForMemoryRegionRecord(const MemoryRegionRecord & record, MemoryRegionCopy & out_region) {
        if (record.RegionSize == 0 || record.BaseAddress == 0) return;

        const auto proc_handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
            false,
            record.AssociatedPid
        );

        out_region.bytes.clear();
        char buffer[RPM_INIT_CHUNK_READ_SIZE];

        SIZE_T num_bytes_read = 0;

        auto chunk_factor = RPM_INIT_CHUNK_READ_SIZE;
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

            if (rpm_result != 0 && chunk_factor < RPM_INIT_CHUNK_READ_SIZE) {
                chunk_factor = min(chunk_factor * 4, RPM_INIT_CHUNK_READ_SIZE);
            }

            if (rpm_result == 0 && chunk_factor > 1) {
                chunk_factor = min(chunk_factor / 4, 1);
                ZeroMemory(buffer, RPM_INIT_CHUNK_READ_SIZE);
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

    void getMemoryForSniffRecord(SniffRecord & record, MemoryRegionCopy & out_region) {
        const auto proc_handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
            false,
            (DWORD)record.pid
        );

        out_region.bytes.clear();
        uint64_t read_size = record.type == SniffType::str ? record.value.asString().size() : 8;
        char * buffer = new char[read_size];

        SIZE_T num_bytes_read = 0;

        auto rpm_result = ReadProcessMemory(
            proc_handle,
            (LPVOID)record.location,
            (LPVOID)buffer,
            read_size,
            &num_bytes_read
        );

        for (uint64_t i = 0; i < num_bytes_read && i < read_size; ++i) {
            out_region.bytes.push_back(buffer[i]);
        }

        delete[] buffer;

        CloseHandle(proc_handle);
    }

    void setByteAtLocationForPidAndLocation(uint64_t pid, uint64_t location, char byte_to_set) {
        if (pid == 0 || location == 0) return;

        const auto proc_handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
            false,
            (DWORD)pid
        );

        DWORD oldprotect;
        LPVOID dst = (LPVOID)((SIZE_T)location);
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

    const char * getSniffTypeStrForType(SniffType type) {
        switch (type) {
        case SniffType::str: return "str";
        case SniffType::i8: return "i8";
        case SniffType::i32: return "i32";
        case SniffType::i64: return "i64";
        case SniffType::u8: return "u8";
        case SniffType::u32: return "u32";
        case SniffType::u64: return "u64";
        case SniffType::f32: return "f32";
        case SniffType::f64: return "f64";
        default:
        case SniffType::unknown: return "unknown";
        }
    }

    SniffRecord getSniffRecordFromLine(std::string & str) {
        SniffRecord result;
        size_t last = 0, next = 0;

        for (auto i = 0; i < 4; ++i) {
            next = str.find(SNIFF_FILE_DELIM, last);
            switch (i) {
            case 0:
                result.pid = std::stoll(str.substr(last, next - last));
                break;
            case 1:
                result.location = std::stoll(str.substr(last, next - last));
                break;
            case 2:
            {
                std::string type_str = str.substr(last, next - last);
                result.type = getSniffTypeForStr(type_str);
                break;
            }
            case 3:
            {
                std::string value_str = str.substr(last, next - last);
                result.value.setValue(value_str);
                break;
            }

            }
            last = next + strlen(SNIFF_FILE_DELIM);
        }

        return result;
    }

    std::unordered_map<std::string, std::vector<SniffRecord>> getSniffsForProcess(const std::string & sniff_file_name) {
        std::unordered_map<std::string, std::vector<SniffRecord>> result;
        std::string current_context;
        std::ifstream sniff_file(sniff_file_name);
        const auto live_pids = getAllLivePIDs();

        if (sniff_file.is_open()) {
            std::string line;
            while (true) {
                std::getline(sniff_file, line);
                if (line.find("ctx|") == 0) {
                    current_context = line.substr(4);
                    auto _tmp = result[current_context];
                    continue;
                }
                if (line.empty()) break;
                auto sniff = getSniffRecordFromLine(line);
                if (live_pids.count(sniff.pid) > 0) {
                    result.at(current_context).push_back(sniff);
                }
            }
        }

        return result;
    }

    void writeSniffsToSniffFile(const std::string & sniff_file_name, std::vector<SniffRecord> & sniff_records, std::ofstream & sniff_file) {
        if (sniff_file.is_open()) {
            for (auto & record : sniff_records) {
                sniff_file << record.pid << SNIFF_FILE_DELIM << record.location << SNIFF_FILE_DELIM << getSniffTypeStrForType(record.type);
                switch (record.type) {
                case SniffType::i8:
                    sniff_file << SNIFF_FILE_DELIM << record.value.asI8() << std::endl;
                    break;
                case SniffType::i32:
                    sniff_file << SNIFF_FILE_DELIM << record.value.asI32() << std::endl;
                    break;
                case SniffType::i64:
                    sniff_file << SNIFF_FILE_DELIM << record.value.asI64() << std::endl;
                    break;
                case SniffType::u8:
                    sniff_file << SNIFF_FILE_DELIM << record.value.asU8() << std::endl;
                    break;
                case SniffType::u32:
                    sniff_file << SNIFF_FILE_DELIM << record.value.asU32() << std::endl;
                    break;
                case SniffType::u64:
                    sniff_file << SNIFF_FILE_DELIM << record.value.asU64() << std::endl;
                    break;
                case SniffType::f32:
                    sniff_file << SNIFF_FILE_DELIM << record.value.asF32() << std::endl;
                    break;
                case SniffType::f64:
                    sniff_file << SNIFF_FILE_DELIM << record.value.asF64() << std::endl;
                    break;
                case SniffType::str:
                    sniff_file << SNIFF_FILE_DELIM << record.value.asString() << std::endl;
                    break;
                default:
                    sniff_file << SNIFF_FILE_DELIM << std::endl;
                }
            }
        }
    }

    SniffType getSniffTypeForStr(const std::string & type_str) {
        if (type_str == "str") {
            return SniffType::str;
        }
        else if (type_str == "i8") {
            return SniffType::i8;
        }
        else if (type_str == "i32") {
            return SniffType::i32;
        }
        else if (type_str == "i64") {
            return SniffType::i64;
        }
        else if (type_str == "u8") {
            return SniffType::u8;
        }
        else if (type_str == "u32") {
            return SniffType::u32;
        }
        else if (type_str == "u64") {
            return SniffType::u64;
        }
        else if (type_str == "f32") {
            return SniffType::f32;
        }
        else if (type_str == "f64") {
            return SniffType::f64;
        }

        return SniffType::unknown;
    }
}
