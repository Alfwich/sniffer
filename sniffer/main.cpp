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
public:
    SharedMemory(const std::unordered_map<std::string, std::string> & args, std::vector<win_api::SniffRecord> & sniffs, std::vector<win_api::MemoryRegionRecord> & records, uint32_t num_threads) : args(args), sniffs(sniffs), records(records) {
        thread_edits.resize(num_threads);
        thread_bytes.resize(num_threads);
        thread_sniffs.resize(num_threads);
        thread_resniffs.resize(num_threads);
    }

    std::vector<size_t> thread_edits;
    std::vector<size_t> thread_bytes;
    std::vector<std::vector<win_api::SniffRecord>> thread_sniffs;
    std::vector<std::set<size_t>> thread_resniffs;
    void resetJobCounter() {
        std::lock_guard<std::mutex> stack_lock(lock);
        current_job = 0;
    }
    size_t getNextJob() {
        std::lock_guard<std::mutex> stack_lock(lock);
        return current_job++;
    }
    std::vector<win_api::MemoryRegionRecord> & records;
    std::vector<win_api::SniffRecord> & sniffs;
    const std::unordered_map<std::string, std::string> & args;
};

void do_replaces(int id, SharedMemory * sm) {
    auto value_to_set = win_api::SniffValue(sm->args.at("set").c_str());

    for (size_t job_id = sm->getNextJob(); job_id < sm->sniffs.size(); job_id = sm->getNextJob()) {
        const auto & sniff = sm->sniffs.at(job_id);

        switch (sniff.type) {
        case win_api::SniffType::str: {
            sm->thread_edits[id]++;
            for (auto j = 0; j < value_to_set.asString().size(); ++j) {
                win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, value_to_set.asString()[j]);
            }
        } break;
        case win_api::SniffType::i32: {
            sm->thread_edits[id]++;
            int32_t value = value_to_set.asI32();
            char * value_byte_ptr = (char *)&value;
            for (auto j = 0; j < 4; ++j) {
                win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
            }
        } break;
        case win_api::SniffType::f32: {
            sm->thread_edits[id]++;
            float value = value_to_set.asF32();
            char * value_byte_ptr = (char *)&value;
            for (auto j = 0; j < 4; ++j) {
                win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
            }
        } break;
        }
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
            record.pname = sm->args.at("pname");
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

            if (value_to_find.num_ref_bytes() == 1) {
                uint8_t val = *(uint8_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asU8();

                if (match) {
                    record.type = win_api::SniffType::u8;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.num_ref_bytes() <= 4 && i + 3 < mem_region_copy.bytes.size()) {
                uint32_t val = *(uint32_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asU32();

                if (match) {
                    record.type = win_api::SniffType::u32;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.num_ref_bytes() <= 8 && i + 7 < mem_region_copy.bytes.size()) {
                uint64_t val = *(uint64_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asU64();

                if (match) {
                    record.type = win_api::SniffType::u64;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.num_ref_bytes() == 1) {
                int8_t val = *(int8_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asI8();

                if (match) {
                    record.type = win_api::SniffType::i8;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.num_ref_bytes() <= 4 && i + 3 < mem_region_copy.bytes.size()) {
                int32_t val = *(int32_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asI32();

                if (match) {
                    record.type = win_api::SniffType::i32;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (value_to_find.num_ref_bytes() <= 8 && i + 7 < mem_region_copy.bytes.size()) {
                int64_t val = *(int64_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asI64();

                if (match) {
                    record.type = win_api::SniffType::i64;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);
                }
            }

            if (i + 3 < mem_region_copy.bytes.size()) {
                float_t val = *(float_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asF32();

                if (match) {
                    record.type = win_api::SniffType::f32;
                    record.value.setValue(val);
                    sm->thread_sniffs[id].push_back(record);

                }
            }

            if (i + 7 < mem_region_copy.bytes.size()) {
                double_t val = *(double_t *)&mem_region_copy.bytes[i];
                match = val == value_to_find.asF32();

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

    return false;
}

void do_resniffs(int id, SharedMemory * sm) {
    auto resniff_pred_str = sm->args.at("spred");
    auto mem_region_copy = win_api::MemoryRegionCopy();
    for (size_t job_id = sm->getNextJob(); job_id < sm->sniffs.size(); job_id = sm->getNextJob()) {
        auto & sniff = sm->sniffs.at(job_id);
        bool match = false;
        win_api::getMemoryForSniffRecord(sniff, mem_region_copy);

        if (sniff.type == win_api::SniffType::str) {
            for (uint64_t j = 0; j < sniff.value.asString().size(); ++j) {
                match = mem_region_copy.bytes[j] == sniff.value.asString().at(j);
                if (!match) break;
            }
        }
        else if (sniff.type == win_api::SniffType::i8) {
            int8_t val = *(int8_t *)&mem_region_copy.bytes[0];
            match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asI8());

            if (match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::i32) {
            int32_t val = *(int32_t *)&mem_region_copy.bytes[0];
            match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asI32());

            if (match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::i64) {
            int64_t val = *(int64_t *)&mem_region_copy.bytes[0];
            match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asI64());

            if (match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::u8) {
            uint8_t val = *(uint8_t *)&mem_region_copy.bytes[0];
            match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asU8());

            if (match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::u32) {
            uint32_t val = *(uint32_t *)&mem_region_copy.bytes[0];
            match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asU32());

            if (match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::u64) {
            uint64_t val = *(uint64_t*)&mem_region_copy.bytes[0];
            match = resniff_cmp_i(resniff_pred_str, val, sniff.value.asU64());

            if (match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::f32) {
            float_t val = *(float_t *)&mem_region_copy.bytes[0];
            match = resniff_cmp_f(resniff_pred_str, val, sniff.value.asF32());
            if (match) {
                sniff.value.setValue(val);
            }
        }
        else if (sniff.type == win_api::SniffType::f64) {
            double_t val = *(double_t *)&mem_region_copy.bytes[0];
            match = resniff_cmp_f(resniff_pred_str, val, sniff.value.asF64());
            if (match) {
                sniff.value.setValue(val);
            }
        }


        if (!match) {
            sm->thread_resniffs[id].insert(job_id);
        }
    }
}

bool check_args(const std::unordered_map<std::string, std::string> & args) {
    static std::unordered_map <std::string, std::vector<std::string> > required = {
        { "action", { "sniff", "replace", "resniff" } },
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
        if (mem.sniffs.empty()) {
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
    else if (args.at("action") == "resniff") {
        if (mem.sniffs.size() == 0) {
            std::cout << "Expected to find cached sniffs when using action resniff - run sniff to generate a starting sniff file" << std::endl;
            result.clear();
            return result;
        }

        if (args.count("spred") == 0) {
            std::cout << "Expected to have resniff predicate compare [lt|gt|eq] to compare existing records against is in process memory" << std::endl;
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

size_t processResniffsIfNeeded(SharedMemory & mem) {
    std::set<size_t> sniffs_to_exclude;
    for (const auto & resniff : mem.thread_resniffs) {
        for (const auto index_to_exclude : resniff) {
            sniffs_to_exclude.insert(index_to_exclude);
        }

    }

    std::vector<win_api::SniffRecord> new_records;
    for (auto i = 0; i < mem.sniffs.size(); ++i) {
        if (sniffs_to_exclude.count(i) == 0) {
            new_records.push_back(mem.sniffs.at(i));
        }
    }

    mem.sniffs = new_records;

    return sniffs_to_exclude.size();
}

void dumpSniffs(const SharedMemory & mem) {
    auto i = 0;
    for (auto record : mem.sniffs) {
        i++;
        std::cout << "\t SniffRecord(pname='" << record.pname << "', pid=" << record.pid << ", location=";
        std::cout << "0x" << std::setw(16) << std::setfill('0') << std::hex << record.location << std::dec;
        std::cout << ", type=" << win_api::getSniffTypeStrForType(record.type) << ", value=";
        switch (record.type) {
        case win_api::SniffType::i8:
            std::cout << record.value.asI8();
            break;
        case win_api::SniffType::i32:
            std::cout << record.value.asI32();
            break;
        case win_api::SniffType::i64:
            std::cout << record.value.asI64();
            break;
        case win_api::SniffType::u8:
            std::cout << record.value.asU8();
            break;
        case win_api::SniffType::u32:
            std::cout << record.value.asU32();
            break;
        case win_api::SniffType::u64:
            std::cout << record.value.asU64();
            break;
        case win_api::SniffType::f32:
            std::cout << record.value.asF32();
            break;
        case win_api::SniffType::f64:
            std::cout << record.value.asF64();
            break;
        case win_api::SniffType::str:
            std::cout << record.value.asString();
            break;
        default:
            std::cout << "???";
        }
        std::cout << ")" << std::endl;

        if (i == 20) {
            std::cout << "\t\t ... [" << mem.sniffs.size() - 20 << " more records - see sniff file] ..." << std::endl;
            break;
        }
    }
}

int main(int argc, char * argv[]) {
    auto args = getArguments(argc, argv);

    if (args.empty()) {
        std::cout << "Expected usage ./sniffer.exe [sniff|resniff|replace] -pname 'process_name' -spred [gt|eq|lt] -find 'value_to_replace' -set 'value_to_set' -j [num threads to use]" << std::endl;
        return 0;
    }

    auto sniffs = win_api::getSniffsForProcess(args.at("pname"));
    if (args.at("action") == "sniff") sniffs.clear();

    win_api::setDebugPriv();
    ProfileTimer timer("sniffer");

    const auto executable_to_consider = args["pname"];
    const auto executable_to_consider_wstring = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(executable_to_consider);
    const auto pids_to_consider = win_api::getPIDSForProcessName(executable_to_consider_wstring);

    std::vector<win_api::MemoryRegionRecord> records;
    for (auto i = 0; i < pids_to_consider.size(); ++i) {
        const auto records_for_pid = win_api::getAllMemoryRegionsForPID(pids_to_consider[i]);
        records.insert(records.end(), records_for_pid.begin(), records_for_pid.end());
    }

    const auto num_threads = getNumThreads(args);
    SharedMemory mem(args, sniffs, records, num_threads);
    const auto actions = getActionsForArgsAndSharedMem(args, mem);
    if (actions.empty()) return 0;
    for (const auto action : actions) {
        std::vector<std::thread> threads;
        for (uint32_t i = 0; i < num_threads; ++i) {
            threads.push_back(std::thread(action, i, &mem));
        }

        while (!threads.empty()) {
            threads.back().join();
            threads.pop_back();
        }

        for (uint32_t i = 0; i < num_threads; ++i) {
            for (auto & sniff : mem.thread_sniffs[i]) {
                mem.sniffs.push_back(sniff);
            }
            mem.thread_sniffs[i].clear();
        }

        mem.resetJobCounter();
    }

    size_t total_bytes_considered = 0;
    size_t total_replacements = 0;
    size_t total_sniffs_eliminated = processResniffsIfNeeded(mem);

    for (uint32_t i = 0; i < num_threads; ++i) {
        total_bytes_considered += mem.thread_bytes[i];
        total_replacements += mem.thread_edits[i];
    }

    if (args.at("action") == "replace") {
        std::cout <<
            "Found and replaced " << total_replacements <<
            " instances to '" << unwrap_or_default(mem.args, "set") << "'" <<
            " across " << pids_to_consider.size() << " processes and " << mem.records.size() << " mem regions considering " << total_bytes_considered << " total bytes" <<
            " for " << executable_to_consider << std::endl;
        std::cout << "Old sniff records:" << std::endl;
        dumpSniffs(mem);
    }
    else if (args.at("action") == "sniff") {
        std::cout << "Found " << mem.sniffs.size() << " records: " << std::endl;
        dumpSniffs(mem);
    }
    else if (args.at("action") == "resniff") {
        std::cout << "Filtered " << total_sniffs_eliminated << " records. Remaining records: " << std::endl;
        dumpSniffs(mem);
    }

    writeSniffsToSniffFile(executable_to_consider, mem.sniffs);

    return 0;
}
