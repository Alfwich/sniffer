#include <iostream>
#include <iomanip>
#include <vector>
#include <sstream>
#include <thread>
#include <mutex>
#include <codecvt>
#include <locale>
#include <fstream>
#include <set>
#include <regex>
#include <unordered_map>
#include <stdio.h>

#include "Params.h"
#include "ProfileTimer.h"
#include "Win32Api.h"
#include "Utils.h"

class SharedMemory {
    size_t current_job = 0;
    std::mutex lock;
    uint32_t num_threads;
public:
    SharedMemory(const std::unordered_map<std::string, std::string> & args, std::vector<win_api::SniffRecord> * sniffs, std::vector<win_api::MemoryRegionRecord> & records, uint32_t num_threads) : args(args), sniffs(sniffs), records(records), num_threads(num_threads) {
        thread_edits.resize(num_threads);
        thread_bytes.resize(num_threads);
        thread_sniffs.resize(num_threads);
        thread_resniffs.resize(num_threads);
    }

    std::vector<size_t> thread_edits;
    std::vector<size_t> thread_bytes;
    std::vector<std::vector<win_api::SniffRecord>> thread_sniffs;
    std::vector<std::set<size_t>> thread_resniffs;
    void resetMultiThreadState() {
        std::lock_guard<std::mutex> stack_lock(lock);
        current_job = 0;
    }
    size_t getNextJob() {
        std::lock_guard<std::mutex> stack_lock(lock);
        return current_job++;
    }
    size_t getCurrentJobIndex() {
        std::lock_guard<std::mutex> stack_lock(lock);
        return current_job;
    }
    std::vector<win_api::MemoryRegionRecord> & records;
    std::vector<win_api::SniffRecord> * sniffs;
    const std::unordered_map<std::string, std::string> & args;
};

void do_sniff_mem_replace(win_api::SniffRecord & sniff, win_api::SniffValue & value_to_set) {
    switch (sniff.type) {
    case win_api::SniffType::str: {
        for (auto j = 0; j < value_to_set.asString().size(); ++j) {
            win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, value_to_set.asString()[j]);
        }
        sniff.value.setOldValue(sniff.value.asString());
        sniff.value.setValue(value_to_set.asString());
    } break;

    case win_api::SniffType::i8: {
        int8_t value = value_to_set.asI8();
        char * value_byte_ptr = (char *)&value;
        for (auto j = 0; j < 1; ++j) {
            win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
        }
        sniff.value.setOldValue(std::to_string(sniff.value.asI64()));
        sniff.value.setValue(value);
    } break;
    case win_api::SniffType::i32: {
        int32_t value = value_to_set.asI32();
        char * value_byte_ptr = (char *)&value;
        for (auto j = 0; j < 4; ++j) {
            win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
        }
        sniff.value.setOldValue(std::to_string(sniff.value.asI64()));
        sniff.value.setValue(value);
    } break;
    case win_api::SniffType::i64: {
        int64_t value = value_to_set.asI64();
        char * value_byte_ptr = (char *)&value;
        for (auto j = 0; j < 8; ++j) {
            win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
        }
        sniff.value.setOldValue(std::to_string(sniff.value.asI64()));
        sniff.value.setValue(value);
    } break;

    case win_api::SniffType::u8: {
        uint8_t value = value_to_set.asU8();
        char * value_byte_ptr = (char *)&value;
        for (auto j = 0; j < 1; ++j) {
            win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
        }
        sniff.value.setOldValue(std::to_string(sniff.value.asU64()));
        sniff.value.setValue(value);
    } break;
    case win_api::SniffType::u32: {
        uint32_t value = value_to_set.asU32();
        char * value_byte_ptr = (char *)&value;
        for (auto j = 0; j < 4; ++j) {
            win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
        }
        sniff.value.setOldValue(std::to_string(sniff.value.asU64()));
        sniff.value.setValue(value);
    } break;
    case win_api::SniffType::u64: {
        uint64_t value = value_to_set.asU64();
        char * value_byte_ptr = (char *)&value;
        for (auto j = 0; j < 8; ++j) {
            win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
        }
        sniff.value.setOldValue(std::to_string(sniff.value.asU64()));
        sniff.value.setValue(value);
    } break;

    case win_api::SniffType::f32: {
        float_t value = value_to_set.asF32();
        char * value_byte_ptr = (char *)&value;
        for (auto j = 0; j < 4; ++j) {
            win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
        }
        sniff.value.setOldValue(std::to_string(sniff.value.asF64()));
        sniff.value.setValue(value);
    } break;

    case win_api::SniffType::f64: {
        double_t value = value_to_set.asF64();
        char * value_byte_ptr = (char *)&value;
        for (auto j = 0; j < 8; ++j) {
            win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
        }
        sniff.value.setOldValue(std::to_string(sniff.value.asF64()));
        sniff.value.setValue(value);
    } break;
    }
}

void do_replaces(int id, SharedMemory * sm) {
    auto value_to_set = win_api::SniffValue(sm->args.at("set").c_str());

    for (size_t job_id = sm->getNextJob(); job_id < sm->sniffs->size(); job_id = sm->getNextJob()) {
        auto & sniff = sm->sniffs->at(job_id);

        do_sniff_mem_replace(sniff, value_to_set);
    }
}

void do_sniffs(int id, SharedMemory * sm) {
    auto value_to_find = win_api::SniffValue(sm->args.at("find").c_str());
    auto mem_region_copy = win_api::MemoryRegionCopy();
    win_api::SniffRecord record;
    bool match = false;
    std::vector<win_api::SniffType> type_matches;
    for (size_t job_id = sm->getNextJob(); job_id < sm->records.size(); job_id = sm->getNextJob()) {
        const auto & region_record = sm->records[job_id];
        getMemoryRegionCopyForMemoryRegionRecord(region_record, mem_region_copy);
        sm->thread_bytes[id] += mem_region_copy.bytes.size();
        for (uint64_t i = 0; i < mem_region_copy.bytes.size(); ++i) {
            match = false;
            type_matches.clear();

            record.pid = region_record.AssociatedPid;
            //record.pname = sm->args.at("pname");
            record.location = (uint64_t)(region_record.BaseAddress) + i;

            if (i + sm->args.at("find").size() < mem_region_copy.bytes.size()) {
                for (uint64_t j = 0; j < value_to_find.asString().size(); ++j) {
                    match = mem_region_copy.bytes[i + j] == value_to_find.asString().at(j);
                    if (!match) break;
                }

                if (match) {
                    record.type = win_api::SniffType::str;
                    record.value.setValue(value_to_find.asString());
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.asU8() != 0 && value_to_find.num_ref_bytes() == 1) {
                uint8_t val = *(uint8_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asU8();

                if (match) {
                    record.type = win_api::SniffType::u8;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.asU32() != 0 && value_to_find.num_ref_bytes() <= 4 && i + 3 < mem_region_copy.bytes.size()) {
                uint32_t val = *(uint32_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asU32();

                if (match) {
                    record.type = win_api::SniffType::u32;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.asU64() != 0 && value_to_find.num_ref_bytes() <= 8 && i + 7 < mem_region_copy.bytes.size()) {
                uint64_t val = *(uint64_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asU64();

                if (match) {
                    record.type = win_api::SniffType::u64;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.asI8() != 0 && value_to_find.num_ref_bytes() == 1) {
                int8_t val = *(int8_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asI8();

                if (match) {
                    record.type = win_api::SniffType::i8;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.asI32() != 0 && value_to_find.num_ref_bytes() <= 4 && i + 3 < mem_region_copy.bytes.size()) {
                int32_t val = *(int32_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asI32();

                if (match) {
                    record.type = win_api::SniffType::i32;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.asI64() != 0 && value_to_find.num_ref_bytes() <= 8 && i + 7 < mem_region_copy.bytes.size()) {
                int64_t val = *(int64_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asI64();

                if (match) {
                    record.type = win_api::SniffType::i64;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.asF32() != 0.0f && value_to_find.num_ref_bytes() <= 8 && i + 3 < mem_region_copy.bytes.size()) {
                float_t val = *(float_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asF32();

                if (match) {
                    record.type = win_api::SniffType::f32;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);

                }
            }

            if (value_to_find.asF64() != 0.0 && value_to_find.num_ref_bytes() <= 8 && i + 7 < mem_region_copy.bytes.size()) {
                double_t val = *(double_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asF64();

                if (match) {
                    record.type = win_api::SniffType::f64;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }
        }
    }
}

bool resniff_cmp_i(std::string & pred, uint64_t a, uint64_t b) {
    if (pred == "lt") {
        return a < b;
    }
    else if (pred == "gt") {
        return a > b;
    }
    else if (pred == "eq") {
        return a == b;
    }
    else if (pred == "ne") {
        return a != b;
    }

    return false;
}

bool resniff_cmp_f(std::string & pred, double_t a, double_t b) {
    if (pred == "lt") {
        return a < b;
    }
    else if (pred == "gt") {
        return a > b;
    }
    else if (pred == "eq") {
        return a == b;
    }
    else if (pred == "ne") {
        return a != b;
    }

    return false;
}

void do_resniffs(int id, SharedMemory * sm) {
    auto is_update_resniff = sm->args.at("action") == "update";
    auto resniff_pred_str = sm->args.count("spred") > 0 ? sm->args.at("spred") : "eq";
    auto resniff_type_pred_str = sm->args.count("stype") > 0 ? sm->args.at("stype") : "";
    auto resniff_type_pred = win_api::getSniffTypeForStr(resniff_type_pred_str);
    auto resniff_value_pred_str = sm->args.count("find") > 0 ? sm->args.at("find") : "";
    auto resniff_value_pred = win_api::SniffValue(resniff_value_pred_str.c_str());
    auto mem_region_copy = win_api::MemoryRegionCopy();
    for (size_t job_id = sm->getNextJob(); job_id < sm->sniffs->size(); job_id = sm->getNextJob()) {
        auto & sniff = sm->sniffs->at(job_id);
        bool match = false;
        win_api::getMemoryForSniffRecord(sniff, mem_region_copy);

        if (!is_update_resniff && resniff_type_pred != win_api::SniffType::unknown) {
            if (sniff.type != resniff_type_pred) {
                sm->thread_resniffs[id].insert(job_id);
                continue;
            }
        }

        if (sniff.type == win_api::SniffType::str) {
            const auto cmp_str =
                resniff_value_pred_str.empty() ? sniff.value.asString() : resniff_value_pred.asString();

            for (uint64_t j = 0; j < sniff.value.asString().size(); ++j) {
                match = resniff_cmp_i(resniff_pred_str, mem_region_copy.bytes[j], cmp_str.at(j));

                if (!match) break;
            }

            if (is_update_resniff || match) {
                sniff.value.setValue(cmp_str);
            }
        }
        else if (sniff.type == win_api::SniffType::i8) {
            int8_t val = *(int8_t *)&mem_region_copy.bytes[0];

            if (resniff_value_pred_str.empty()) {
                match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asI8());
            }
            else {
                match = resniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asI8());
            }

            if (is_update_resniff || match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::i32) {
            int32_t val = *(int32_t *)&mem_region_copy.bytes[0];

            if (resniff_value_pred_str.empty()) {
                match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asI32());
            }
            else {
                match = resniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asI32());
            }

            if (is_update_resniff || match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::i64) {
            int64_t val = *(int64_t *)&mem_region_copy.bytes[0];

            if (resniff_value_pred_str.empty()) {
                match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asI64());
            }
            else {
                match = resniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asI64());
            }

            if (is_update_resniff || match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::u8) {
            uint8_t val = *(uint8_t *)&mem_region_copy.bytes[0];

            if (resniff_value_pred_str.empty()) {
                match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asU8());
            }
            else {
                match = resniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asU8());
            }

            if (is_update_resniff || match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::u32) {
            uint32_t val = *(uint32_t *)&mem_region_copy.bytes[0];

            if (resniff_value_pred_str.empty()) {
                match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asU32());
            }
            else {
                match = resniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asU32());
            }

            if (is_update_resniff || match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::u64) {
            uint64_t val = *(uint64_t *)&mem_region_copy.bytes[0];

            if (resniff_value_pred_str.empty()) {
                match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asU64());
            }
            else {
                match = resniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asU64());
            }

            if (is_update_resniff || match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::f32) {
            float_t val = *(float_t *)&mem_region_copy.bytes[0];

            if (resniff_value_pred_str.empty()) {
                match = resniff_cmp_f(resniff_pred_str, val, sniff.value.asF32());
            }
            else {
                match = resniff_cmp_f(resniff_pred_str, val, resniff_value_pred.asF32());
            }

            if (is_update_resniff || match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::f64) {
            double_t val = *(double_t *)&mem_region_copy.bytes[0];

            if (resniff_value_pred_str.empty()) {
                match = resniff_cmp_f(resniff_pred_str, val, sniff.value.asF64());
            }
            else {
                match = resniff_cmp_f(resniff_pred_str, val, resniff_value_pred.asF64());
            }

            if (is_update_resniff || match) {
                sniff.value.setValue(val);
            }
        }


        if (!is_update_resniff && !match) {
            sm->thread_resniffs[id].insert(job_id);
        }
    }
}

bool check_args(const std::unordered_map<std::string, std::string> & args) {
    static std::unordered_map <std::string, std::vector<std::string> > required = {
        { "action", { "sniff", "replace", "resniff", "update", "interactive", "list" } },
        { "pname", { "*" } },
    };

    for (const auto & required_pair : required) {
        const auto & key = required_pair.first;
        const auto & value_array = required_pair.second;

        bool has_match = false;
        for (const auto & test_value : value_array) {
            has_match = test_value == "*" || has_match || (args.count(key) > 0 && args.at(key) == test_value);
        }

        if (!has_match) {
            return false;
        }
    }

    return true;
}

std::unordered_map<std::string, std::string> getArguments(int argc, char * argv[]) {
    std::unordered_map<std::string, std::string> result;
    if (argc <= 2) {
        return result;
    }

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

    if (!check_args(result)) {
        result.clear();
    }

    return result;
}

std::vector<void (*)(int, SharedMemory *)> getActionsForArgsAndSharedMem(const std::unordered_map<std::string, std::string> & args, const SharedMemory & mem) {
    auto result = std::vector<void (*)(int, SharedMemory *)>();
    if (args.at("action") == "sniff") {
        if (args.count("find") == 0) {
            std::cout << "Expected -find to be provided when doing a sniff operation" << std::endl;
            result.clear();
            return result;
        }

        result.push_back(do_sniffs);
    }
    else if (args.at("action") == "replace") {
        if (mem.sniffs->empty()) {
            if (args.count("find") == 0) {
                std::cout << "Expected -find to be provided when doing a replace operation without sniff file" << std::endl;
                result.clear();
                return result;
            }

            std::cout << "No sniff records located - doing sniff before replace" << std::endl;
            result.push_back(do_sniffs);
        }

        if (args.count("set") == 0) {
            std::cout << "Expected -set to be provided when using action replace" << std::endl;
            result.clear();
            return result;
        }

        result.push_back(do_replaces);
    }
    else if (args.at("action") == "resniff" || args.at("action") == "update") {
        if (mem.sniffs->size() == 0) {
            std::cout << "Expected to find cached sniffs when using action resniff/update - run sniff to generate a starting sniff file" << std::endl;
            result.clear();
            return result;
        }

        result.push_back(do_resniffs);
    }

    return result;
}

uint32_t getNumThreads(std::unordered_map<std::string, std::string> & args) {
    auto arg_threads = args.count("j") > 0 ? std::stoi(args["j"]) : DEFAULT_THREADS;
    return max(arg_threads, 1);
}

std::vector<win_api::SniffRecord> processResniffsIfNeeded(SharedMemory & mem) {
    std::vector<win_api::SniffRecord> result;
    std::set<size_t> sniffs_to_exclude;
    for (const auto & resniff : mem.thread_resniffs) {
        for (const auto index_to_exclude : resniff) {
            sniffs_to_exclude.insert(index_to_exclude);
        }

    }

    std::vector<win_api::SniffRecord> new_records;
    for (auto i = 0; i < mem.sniffs->size(); ++i) {
        if (sniffs_to_exclude.count(i) == 0) {
            new_records.push_back(mem.sniffs->at(i));
        }
    }

    if (!sniffs_to_exclude.empty()) {
        result = *mem.sniffs;
    }
    *mem.sniffs = new_records;

    return result;
}

void dumpSniffs(const SharedMemory & mem, uint32_t offset = 0) {
    uint32_t i = 0;
    bool has_offset_output = false;
    for (auto & record : *mem.sniffs) {
        if (i++ < offset) {
            has_offset_output = true;
            continue;
        }
        else if (has_offset_output) {
            std::cout << "\t ... [" << (i - 1) << " previous records] ..." << std::endl;
            has_offset_output = false;
        }

        record.value.updateStringValue();

        std::cout << "\t SniffRecord (id=" << i << ", pid=" << record.pid << ", location=";
        std::cout << "0x" << std::setw(16) << std::setfill('0') << std::hex << record.location << std::dec;
        std::cout << ", type=" << win_api::getSniffTypeStrForType(record.type) << ", value=" << record.value.asString();

        if (!record.value.getOldStringValue().empty()) {
            std::cout << ", old_value=" << record.value.getOldStringValue();
        }
        std::cout << ")" << std::endl;

        if (i - offset == 20) {
            std::cout << "\t ... [" << mem.sniffs->size() - i - 20 << " more records] ..." << std::endl;
            break;
        }
    }
}

std::vector<std::string> splitArgStringIntoWords(const std::string args_string) {
    std::vector<std::string> result;
    std::string word;

    for (auto i = 0; i < args_string.size(); ++i) {
        if (args_string[i] == ' ') {
            if (!word.empty()) {
                if (word[0] == '-') {
                    word.erase(word.begin());
                }
                result.push_back(word);
            }
            word = "";
        }
        else {
            word.push_back(args_string[i]);
        }
    }

    if (!word.empty()) {
        if (word[0] == '-') {
            word.erase(word.begin());
        }
        result.push_back(word);
    }

    return result;
}

static inline void ltrim(std::string & s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

static inline void rtrim(std::string & s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

static inline void trim(std::string & s) {
    ltrim(s);
    rtrim(s);
}

void parseArgStringIntoArgsMap(const std::string args_string, std::unordered_map<std::string, std::string> & args) {
    const auto words = splitArgStringIntoWords(args_string);
    if (!words.empty()) {
        args["action"] = words[0];
    }

    for (size_t i = 1; (i + 1) < words.size(); i += 2) {
        args[words[i]] = words[i + 1];
    }

    if (args.count(words.back()) == 0) {
        args[words.back()] = "";
    }
}

static const char * help_text = "[sniff|resniff|replace|update|interactive] -pname \"process_name\" -spred [gt|lt|eq|ne] -stype [i8|i32|i64|u8|u32|u64|f32|f64|str] -find \"value_to_sniff_or_resniff_on\" -set \"value_to_set\" -j [num threads to use] -sf \"out_file_name\"";
static const char * interactive_help_text = "[list|undo|clear|context]";

bool updateArgsForInteractiveMode(std::unordered_map<std::string, std::string> & args, std::string & current_context, size_t num_records) {
    if (num_records > 0) {
        std::cout << current_context << "(" << num_records << ")> ";
    }
    else {
        std::cout << current_context << "> ";
    }
    std::string line;
    std::getline(std::cin, line);
    trim(line);
    if (line == "exit" || line == "quit" || line == "q") {
        args.clear();
    }
    else if (line.empty() || line == "help" || line == "?") {
        std::cout << "\t Help: " << help_text << std::endl;
        return false;
    }
    else {
        parseArgStringIntoArgsMap(line, args);
    }

    return true;
}

static std::mutex replace_thread_mutex;
static std::vector<std::pair<win_api::SniffRecord, win_api::SniffValue>> repeat_replace;
static bool replace_thread_is_running = true;

void replace_thread_proc() {
    while (replace_thread_is_running) {
        {
            std::lock_guard<std::mutex> lock_guard(replace_thread_mutex);
            for (auto & record_and_value : repeat_replace) {
                do_sniff_mem_replace(record_and_value.first, record_and_value.second);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

int main(int argc, char * argv[]) {
    auto args = getArguments(argc, argv);

    if (args.empty()) {
        std::cout << "Expected usage ./sniffer.exe " << help_text << std::endl;
        return 0;
    }

    win_api::setDebugPriv();
    auto replace_thread = std::thread(replace_thread_proc);
    auto sniffs_eliminated = std::unordered_map<std::string, std::vector<win_api::SniffRecord>>();
    const auto executable_to_consider = args["pname"];
    const auto executable_to_consider_wstring = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(executable_to_consider);
    const auto pids_to_consider = win_api::getPIDSForProcessName(executable_to_consider_wstring);

    const auto sniff_file_name = args.count("sf") > 0 ? (args.at("sf") + ".sniff") : executable_to_consider + ".sniff";
    auto sniff_context_to_sniffs = win_api::getSniffsForProcess(sniff_file_name);
    auto current_sniff_context = args.count("context") > 0 ? args.at("context") : SNIFF_GLOBAL_CONTEXT;
    if (sniff_context_to_sniffs.count(SNIFF_GLOBAL_CONTEXT) == 0) {
        auto _tmp = sniff_context_to_sniffs[SNIFF_GLOBAL_CONTEXT];
    }
    if (sniff_context_to_sniffs.count(current_sniff_context) == 0) {
        auto _tmp = sniff_context_to_sniffs[current_sniff_context];
    }
    std::vector<win_api::SniffRecord> * sniffs = &sniff_context_to_sniffs.at(current_sniff_context);
    if (args.at("action") == "sniff") sniffs->clear();
    const auto is_interactive = args.at("action") == "interactive";

    std::vector<win_api::MemoryRegionRecord> records;
    for (auto i = 0; i < pids_to_consider.size(); ++i) {
        const auto records_for_pid = win_api::getAllMemoryRegionsForPID(pids_to_consider[i]);
        records.insert(records.end(), records_for_pid.begin(), records_for_pid.end());
    }

    const auto num_threads = getNumThreads(args);

    do {
        if (is_interactive) {
            args.clear();

            while (true) {
                if (updateArgsForInteractiveMode(args, current_sniff_context, sniff_context_to_sniffs.at(current_sniff_context).size())) {
                    break;
                }
            }

            if (args.size() == 0) {
                break;
            }

            if (args.at("action") == "sniff" && !sniffs->empty()) {
                sniffs_eliminated[current_sniff_context] = *sniffs;
                sniffs->clear();
            }

            if (args.at("action") == "undo") {
                if (sniffs_eliminated[current_sniff_context].empty()) {
                    std::cout << "No history of sniffs to undo" << std::endl;
                }
                else {
                    std::cout << "Returned " << sniffs_eliminated[current_sniff_context].size() << " records into the working sniff set" << std::endl;
                    std::vector<win_api::SniffRecord> old_records = *sniffs;
                    for (auto & record : sniffs_eliminated[current_sniff_context]) {
                        sniffs->push_back(record);
                    }
                    sniffs_eliminated.clear();
                    sniffs_eliminated[current_sniff_context] = old_records;
                }
            }

            if (args.at("action") == "clear" && !sniffs->empty()) {
                std::cout << "Clearing all " << sniffs->size() << " sniff records" << std::endl;
                sniffs_eliminated[current_sniff_context] = *sniffs;
                sniffs->clear();
            }

            if (args.at("action") == "context") {
                if (args.count("set") > 0) {
                    std::cout << "Switching context to " << args.at("set") << std::endl;
                    if (sniff_context_to_sniffs.count(args.at("set")) == 0) {
                        auto _tmp = sniff_context_to_sniffs[args.at("set")];
                    }
                    sniffs = &sniff_context_to_sniffs.at(args.at("set"));
                    current_sniff_context = args.at("set");
                }
                else if (args.count("list") > 0) {
                    std::cout << "Registered Contexts:" << std::endl;
                    for (const auto & context_to_sniffs : sniff_context_to_sniffs) {
                        if (context_to_sniffs.first == current_sniff_context) {
                            std::cout << "\t" << context_to_sniffs.first << "(" << context_to_sniffs.second.size() << ") [current]" << std::endl;
                        }
                        else {
                            std::cout << "\t" << context_to_sniffs.first << "(" << context_to_sniffs.second.size() << ")" << std::endl;
                        }
                    }
                }
                else if (args.count("delete") > 0 && !args.at("delete").empty()) {
                    if (sniff_context_to_sniffs.count(args.at("delete")) == 0) {
                        std::cout << "Context " << args.at("delete") << " cannot be deleted because it does not exist" << std::endl;
                    }
                    else if (args.at("delete") == SNIFF_GLOBAL_CONTEXT) {
                        std::cout << "Cannot delete global context" << std::endl;
                    }
                    else {
                        std::cout << "Deleting sniff context " << args.at("delete") << std::endl;
                        sniff_context_to_sniffs.erase(args.at("delete"));
                        if (current_sniff_context == args.at("delete")) {
                            current_sniff_context = SNIFF_GLOBAL_CONTEXT;
                            sniffs = &sniff_context_to_sniffs.at(current_sniff_context);
                        }
                    }
                }
                else if (args.count("clone") && !args.at("clone").empty()) {
                    if (sniff_context_to_sniffs.count(args.at("clone")) != 0) {
                        std::cout << "Cannot clone to new context " << args.at("clone") << " as it already exists" << std::endl;
                    }
                    else {
                        std::cout << "Cloning current context to new context " << args.at("clone") << std::endl;
                        sniff_context_to_sniffs[args.at("clone")] = sniff_context_to_sniffs.at(current_sniff_context);
                        current_sniff_context = args.at("clone");
                    }
                }
            }

            if (args.at("action") == "sniff") {
                if (args.count("find") == 0) {
                    std::cout << "\texpect find <token>" << std::endl;
                    continue;
                }
                std::cout << "Searching attached process for " << args.at("find") << " ..." << std::endl;
            }

            if (args.at("action") == "remove" || args.at("action") == "rm") {
                try {
                    if (args.count("id") > 0) {
                        size_t id_to_remove = std::stoul(args.at("id"));
                        if (id_to_remove < sniffs->size()) {
                            std::cout << "\tErasing record with id " << id_to_remove << std::endl;
                            auto record = *sniffs->erase(sniffs->begin() + id_to_remove);
                            sniffs_eliminated[current_sniff_context].clear();
                            sniffs_eliminated[current_sniff_context].push_back(record);
                        }
                    }
                }
                catch (...) {
                    // NO OP
                }
            }

            if (args.at("action") == "repeat") {
                if (args.count("list") > 0) {
                    std::cout << "Current replace repeats" << std::endl;
                    {
                        std::lock_guard<std::mutex> lock(replace_thread_mutex);
                        size_t i = 1;
                        for (auto & record_to_value : repeat_replace) {
                            record_to_value.second.updateStringValue();
                            std::cout << "\t RepeatReplace (id=" << i << ", type=" << win_api::getSniffTypeStrForType(record_to_value.first.type) << ", location=" << std::setw(16) << std::hex << record_to_value.first.location << std::dec << ", value_to_set=" << record_to_value.second.asString() << ")" << std::endl;
                        }
                    }
                }
                else if (args.count("set") > 0) {
                    std::cout << "Setting repeat replaces" << std::endl;
                    auto value_to_set = win_api::SniffValue(args.at("set").c_str());
                    if (!value_to_set.asString().empty()) {
                        if (args.count("id") > 0) {
                            try {
                                std::lock_guard<std::mutex> lock(replace_thread_mutex);
                                const auto id = std::stoul(args.at("id"));
                                if (id - 1 < sniffs->size()) {
                                    repeat_replace.push_back(std::make_pair(sniffs->at(id - 1), value_to_set));
                                }
                            }
                            catch (...) {
                                // NO OP
                            }

                        }
                        else {
                            std::lock_guard<std::mutex> lock(replace_thread_mutex);
                            for (auto & sniff : *sniffs) {
                                repeat_replace.push_back(std::make_pair(sniff, value_to_set));
                            }
                        }
                    }
                }
                else if (args.count("remove") > 0) {
                    try {
                        std::lock_guard<std::mutex> lock(replace_thread_mutex);
                        const auto id = std::stoul(args.at("remove"));
                        if (id > 0 && id - 1 < repeat_replace.size()) {
                            repeat_replace.erase(repeat_replace.begin() + (id - 1));
                        }
                    }
                    catch (...) {
                        // NO OP
                    }
                }
                else if (args.count("clear") > 0) {
                    std::cout << "Clearing repeat replaces" << std::endl;
                    std::lock_guard<std::mutex> lock(replace_thread_mutex);
                    repeat_replace.clear();
                }
            }

        }

        ProfileTimer timer("sniffer command");

        SharedMemory mem(args, sniffs, records, num_threads);
        const auto actions = getActionsForArgsAndSharedMem(args, mem);
        for (const auto action : actions) {
            std::vector<std::thread> threads;
            for (uint32_t i = 0; i < num_threads; ++i) {
                threads.push_back(std::thread(action, i, &mem));
            }

            auto max_jobs = args.at("action") == "sniff" ? records.size() : sniffs->size();

            while (mem.getCurrentJobIndex() < max_jobs + 1) {
                std::cout << "\r\t Starting " << args.at("action") << " job " << mem.getCurrentJobIndex() << " / " << max_jobs << " ... ";
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
            }
            std::cout << "\r\t Starting " << args.at("action") << " job " << max_jobs << " / " << max_jobs << " ... done" << std::endl;;

            std::cout << "\t Waiting for jobs to finish ...";
            while (!threads.empty()) {
                threads.back().join();
                threads.pop_back();
            }
            std::cout << " done" << std::endl;

            size_t total_records = 0;
            for (uint32_t i = 0; i < num_threads; ++i) {
                total_records += mem.thread_sniffs[i].size();
            }

            if (total_records > 0) {
                std::chrono::milliseconds ms_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
                uint32_t current_record = 1;
                for (uint32_t i = 0; i < num_threads; ++i) {
                    for (auto & sniff : mem.thread_sniffs[i]) {
                        const auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch() - ms_timestamp).count();
                        if (diff > 250) {
                            ms_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
                            std::cout << "\r\t Processing new record " << (current_record++) << " / " << total_records << " ... ";
                        }
                        mem.sniffs->push_back(sniff);
                    }
                    mem.thread_sniffs[i].clear();
                }
                std::cout << "\r\t Processing new record " << total_records << " / " << total_records << " ... done" << std::endl;
            }

            mem.resetMultiThreadState();
        }

        size_t total_bytes_considered = 0;
        size_t total_replacements = 0;
        auto new_eliminated_sniffs = processResniffsIfNeeded(mem);
        if (!new_eliminated_sniffs.empty()) {
            sniffs_eliminated[current_sniff_context] = new_eliminated_sniffs;
        }

        for (uint32_t i = 0; i < num_threads; ++i) {
            total_bytes_considered += mem.thread_bytes[i];
            total_replacements += mem.thread_edits[i];
        }

        if (args.at("action") == "replace") {
            std::cout <<
                "Found and replaced " << total_replacements <<
                " instances to '" << getMapValueOrDefault(mem.args, "set") << "'" <<
                " across " << pids_to_consider.size() << " processes and " << mem.records.size() << " mem regions for " << executable_to_consider << std::endl;
            dumpSniffs(mem);
        }
        else if (args.at("action") == "sniff") {
            std::cout << "Found " << mem.sniffs->size() << " records: " << std::endl;
            dumpSniffs(mem);
        }
        else if (args.at("action") == "resniff") {
            std::cout << "Filtered " << new_eliminated_sniffs.size() << " records which ! " << getMapValueOrDefault(args, "spred", "eq") << " " << (mem.args.count("find") == 0 ? "the original value" : mem.args.at("find")) << ". Remaining records: " << std::endl;
            dumpSniffs(mem);
        }
        else if (args.at("action") == "list" || args.at("action") == "ls") {
            std::cout << "Working with " << mem.sniffs->size() << " sniffs:" << std::endl;
            try {
                dumpSniffs(mem, args.count("offset") > 0 ? std::stoul(args.at("offset")) : 0);
            }
            catch (...) {
                dumpSniffs(mem);
            }
        }
        else if (args.at("action") == "update") {
            std::cout << "Updated sniffs with existing values in the process(s)" << std::endl;
            dumpSniffs(mem);
        }
        else if (args.at("action") == "undo") {
            // NO-OP
        }
        else if (args.at("action") == "context") {
            // NO-OP
        }
        else if (args.at("action") == "clear") {
            // NO-OP
        }
        else if (args.at("action") == "remove" || args.at("action") == "rm") {
            // NO-OP
        }
        else if (args.at("action") == "repeat") {
            // NO-OP
        }
        else {
            std::cout << "Unknown command \"" << args.at("action") << "\"" << std::endl;
        }
    } while (is_interactive);

    std::ofstream sniff_file(sniff_file_name);
    if (sniff_file.is_open()) {
        for (auto & sniff_context_to_sniff : sniff_context_to_sniffs) {
            if (!sniff_context_to_sniff.second.empty()) {
                sniff_file << "ctx|" << sniff_context_to_sniff.first << std::endl;
                writeSniffsToSniffFile(sniff_file_name, sniff_context_to_sniff.second, sniff_file);
            }
        }
    }

    replace_thread_is_running = false;
    replace_thread.join();

    return 0;
}
