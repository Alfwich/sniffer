#pragma once

#pragma warning( disable : 4624 4615 )

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
        i8,
        i32,
        i64,
        u8,
        u32,
        u64,
        f32,
        f64
    };

    class SniffValue {
        std::string str_value = "";
        std::string old_str_value = "";
        std::int64_t int_value = 0;
        std::uint64_t uint_value = 0;
        std::double_t fp_value = 0.0;
        win_api::SniffType ref_type = SniffType::unknown;
        uint64_t ref_bytes = 999;
        bool primed = false;

        void prime() {
            if (!primed) {
                switch (ref_type) {
                case SniffType::i8:
                case SniffType::i32:
                case SniffType::i64:
                    str_value = std::to_string(int_value);
                    fp_value = static_cast<double_t>(int_value);
                    uint_value = static_cast<uint64_t>(int_value);
                    break;
                case SniffType::u8:
                case SniffType::u32:
                case SniffType::u64:
                    str_value = std::to_string(uint_value);
                    fp_value = static_cast<double_t>(uint_value);
                    int_value = static_cast<int64_t>(uint_value);
                    break;
                case SniffType::f32:
                case SniffType::f64:
                    str_value = std::to_string(fp_value);
                    int_value = static_cast<int64_t>(fp_value);
                    uint_value = static_cast<uint64_t>(fp_value);
                    break;
                case SniffType::str:
                    try {
                        int_value = std::stol(str_value);
                        uint_value = std::stoull(str_value);
                        fp_value = std::stod(str_value);

                        if (uint_value <= 0xFFu) {
                            ref_bytes = 1;
                        }
                        else if (uint_value <= 0xFFFFFFFFu) {
                            ref_bytes = 4;
                        }
                        else {
                            ref_bytes = 8;
                        }
                    }
                    catch (...) {
                        int_value = 0;
                        uint_value = 0;
                        fp_value = 0.0;
                        ref_bytes = 999;
                    }
                }

                primed = true;
            }
        }

    public:
        SniffValue() {}
        SniffValue(const char * value) : str_value(value), ref_type(SniffType::str) {}

        void updateStringValue() {
            std::string new_value;

            switch (ref_type) {
            case SniffType::i8:
            case SniffType::i32:
            case SniffType::i64:
                new_value = std::to_string(int_value);
                break;
            case SniffType::u8:
            case SniffType::u32:
            case SniffType::u64:
                new_value = std::to_string(uint_value);
                break;
            case SniffType::f32:
            case SniffType::f64:
                new_value = std::to_string(fp_value);
                break;
            case SniffType::str:
                new_value = str_value;
                break;
            }

            str_value = new_value;
        }

        bool compare_i(uint64_t test_int) {
            switch (ref_type) {
            case SniffType::i8:
            case SniffType::i32:
            case SniffType::i64:
            case SniffType::u8:
            case SniffType::u32:
            case SniffType::u64:
                return test_int == int_value;
            }

            return false;
        }

        bool compare_s(std::string & test_str) {
            switch (ref_type) {
            case SniffType::str:
                return test_str == str_value;
            }

            return false;
        }

        bool compare_f(double_t test_fp) {
            switch (ref_type) {
            case SniffType::f32:
            case SniffType::f64:
                return test_fp == fp_value;
            }

            return false;
        }

        void setValue(const std::string & value) {
            this->str_value = value;
            ref_type = SniffType::str;
            ref_bytes = 0;
        }

        void setOldValue(const std::string & old_value) {
            old_str_value = old_value;
        }

        void setValue(int8_t value) {
            int_value = value;
            ref_type = SniffType::i8;
            ref_bytes = 1;
        }

        void setValue(int32_t value) {
            int_value = value;
            ref_type = SniffType::i32;
            ref_bytes = 4;
        }

        void setValue(int64_t value) {
            int_value = value;
            ref_type = SniffType::i64;
            ref_bytes = 8;
        }

        void setValue(uint8_t value) {
            uint_value = value;
            ref_type = SniffType::u8;
            ref_bytes = 1;
        }

        void setValue(uint32_t value) {
            uint_value = value;
            ref_type = SniffType::u32;
            ref_bytes = 4;
        }

        void setValue(uint64_t value) {
            uint_value = value;
            ref_type = SniffType::u64;
            ref_bytes = 8;
        }

        void setValue(float value) {
            fp_value = value;
            ref_type = SniffType::f32;
            ref_bytes = 4;
        }

        void setValue(double value) {
            fp_value = value;
            ref_type = SniffType::f64;
            ref_bytes = 8;
        }

        const std::string & asString() {
            prime();
            return str_value;
        }

        const std::string & getOldStringValue() {
            return old_str_value;
        }

        const int8_t asI8() {
            prime();
            return static_cast<int8_t>(int_value);
        }

        const int32_t asI32() {
            prime();
            return static_cast<int32_t>(int_value);
        }

        const int64_t asI64() {
            prime();
            return int_value;
        }

        const uint8_t asU8() {
            prime();
            return static_cast<uint8_t>(uint_value);
        }

        const uint32_t asU32() {
            prime();
            return static_cast<uint32_t>(uint_value);
        }

        const uint64_t asU64() {
            prime();
            return int_value;
        }

        const float_t asF32() {
            prime();
            return static_cast<float>(fp_value);
        }

        const double_t asF64() {
            prime();
            return fp_value;
        }

        uint64_t num_ref_bytes() {
            return ref_bytes;
        }

        SniffValue & operator=(const SniffValue & other) {
            str_value = other.str_value;
            int_value = other.int_value;
            uint_value = other.uint_value;
            fp_value = other.fp_value;
            ref_type = other.ref_type;
            primed = other.primed;
            return *this;
        }
    };

    class SniffRecord {
    public:
        SniffRecord() : pid(0), pname(""), location(0), type(SniffType::unknown) {};
        SniffRecord(uint64_t pid, const char * pname, uint64_t location, SniffType type) : pid(pid), pname(pname), location(location), type(type) {};
        uint64_t pid;
        std::string pname;
        uint64_t location;
        SniffType type;
        SniffValue value;
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
    void getMemoryForSniffRecord(SniffRecord & record, MemoryRegionCopy & out_region);
    void setByteAtLocationForPidAndLocation(uint64_t pid, uint64_t location, char byte_to_set);
    const char * getSniffTypeStrForType(SniffType type);
    SniffRecord getSniffRecordFromLine(const std::string & str);
    std::vector<SniffRecord> getSniffsForProcess(const std::string & exec_name);
    void writeSniffsToSniffFile(const std::string & exec_name, std::vector<SniffRecord> & sniff_records);
    SniffType getSniffTypeForStr(const std::string & type_str);
}
