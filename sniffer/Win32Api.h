#pragma once

#include <string>
#include <codecvt>
#include <locale>
#include <set>

#include <vector>

namespace win_api {

#include "Windows.h"
#include "tlhelp32.h"

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

    enum class SniffType {
        unknown,
        str,
        i32,
        f32
    };

    class SniffRecord {
    public:
        SniffRecord() : pid(0), pname(""), location(0), type(SniffType::unknown) {};
        SniffRecord(uint64_t pid, const char * pname, uint64_t location, SniffType type) : pid(pid), pname(pname), location(location), type(type) {};
        uint64_t pid;
        std::string pname;
        uint64_t location;
        SniffType type;
    };

    BOOL setPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
    void getAllProcesses(std::vector<PROCESSENTRY32> & out_vec);
    void setDebugPriv();
    std::vector<PROCESSENTRY32> getOpenProcesses();
    std::vector<DWORD> findProcessId(const std::wstring & processName);
    std::set<uint64_t> getAllLivePIDs();
    std::vector<MemoryRegionRecord> getAllMemoryRegionsForPID(DWORD pid);
    std::vector<DWORD> getPIDSForProcessName(std::wstring proc_name);
    void getMemoryRegionCopyForMemoryRegionRecord(const MemoryRegionRecord & record, MemoryRegionCopy & out_region);
    void setByteAtLocationForPidAndLocation(uint64_t pid, uint64_t location, char byte_to_set);
    const char * getSniffTypeStrForType(SniffType type);
    SniffRecord getSniffRecordFromLine(std::string & str);
    std::vector<SniffRecord> getSniffsForProcess(std::string & exec_name);
    void writeSniffsToSniffFile(const std::string & exec_name, const std::vector<const SniffRecord *> & sniff_records);
    SniffType getSniffTypeForStr(std::string & type_str);
}
