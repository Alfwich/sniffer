#include <iostream>
#include <vector>
#include <sstream>
#include <thread>
#include <mutex>
#include <codecvt>
#include <locale>
#include <fstream>
#include <set>
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
            char * value_byte_ptr = (char *)value_to_set.asI32Ptr();
            for (auto j = 0; j < 4; ++j) {
                win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
            }
        } break;
        case win_api::SniffType::f32: {
            sm->thread_edits[id]++;
            char * value_byte_ptr = (char *)value_to_set.asF32Ptr();
            for (auto j = 0; j < 4; ++j) {
                win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
            }
        } break;
        }
    }
}

void do_sniffs(int id, SharedMemory * sm) {
    auto replace_type_str = sm->args.at("type");
    auto replace_type = win_api::getSniffTypeForStr(replace_type_str);
    auto value_to_find = win_api::SniffValue(sm->args.at("find").c_str());
    auto mem_region_copy = win_api::MemoryRegionCopy();
    for (size_t job_id = sm->getNextJob(); job_id < sm->records.size(); job_id = sm->getNextJob()) {
        const auto & region_record = sm->records[job_id];
        getMemoryRegionCopyForMemoryRegionRecord(region_record, mem_region_copy);
        sm->thread_bytes[id] += mem_region_copy.bytes.size();
        for (uint64_t i = 0; i < mem_region_copy.bytes.size(); ++i) {
            bool match = false;
            if (i + sm->args.at("find").size() < mem_region_copy.bytes.size() && replace_type == win_api::SniffType::str) {
                for (uint64_t j = 0; j < value_to_find.asString().size(); ++j) {
                    match = mem_region_copy.bytes[i + j] == value_to_find.asString().at(j);
                    if (!match) break;
                }
            }
            else if (i + 3 < mem_region_copy.bytes.size() && replace_type == win_api::SniffType::i32) {
                int32_t val = *(int32_t *)&mem_region_copy.bytes[i];
                match = val == *value_to_find.asI32Ptr();
            }
            else if (i + 3 < mem_region_copy.bytes.size() && replace_type == win_api::SniffType::f32) {
                float val = *(float *)&mem_region_copy.bytes[i];
                match = val == *value_to_find.asF32Ptr();
            }

            if (match) {
                sm->thread_sniffs[id].emplace_back(region_record.AssociatedPid, "", (uint64_t)(region_record.BaseAddress) + i, replace_type);
            }
        }
    }
}

bool resniff_cmp(std::string & pred, int32_t a, int32_t b) {
    if (pred == "lt") {
        return a < b;
    }
    else if (pred == "gt") {
        return a > b;
    }
    else if (pred == "eq") {
        return a == b;
    }
}

bool resniff_cmp(std::string & pred, float a, float b) {
    if (pred == "lt") {
        return a < b;
    }
    else if (pred == "gt") {
        return a > b;
    }
    else if (pred == "eq") {
        return a == b;
    }
}

void do_resniffs(int id, SharedMemory * sm) {
    auto resniff_type_str = sm->args.at("type");
    auto resniff_pred_str = sm->args.at("sniff-pred");
    auto resniff_type = win_api::getSniffTypeForStr(resniff_type_str);
    auto value_to_find = win_api::SniffValue(sm->args.at("find").c_str());
    auto mem_region_copy = win_api::MemoryRegionCopy();
    for (size_t job_id = sm->getNextJob(); job_id < sm->sniffs.size(); job_id = sm->getNextJob()) {
        const auto & sniff = sm->sniffs.at(job_id);
        bool match = false;
        win_api::getMemoryForSniffRecord(sniff, mem_region_copy);

        if (job_id + sm->args.at("find").size() < mem_region_copy.bytes.size() && resniff_type == win_api::SniffType::str) {
            for (uint64_t j = 0; j < value_to_find.asString().size(); ++j) {
                match = mem_region_copy.bytes[j] == value_to_find.asString().at(j);
                if (!match) break;
            }
        }
        else if (job_id + 3 < mem_region_copy.bytes.size() && resniff_type == win_api::SniffType::i32) {
            int32_t val = *(int32_t *)&mem_region_copy.bytes[0];
            match = resniff_cmp(resniff_pred_str, val, *value_to_find.asI32Ptr());
        }
        else if (job_id + 3 < mem_region_copy.bytes.size() && resniff_type== win_api::SniffType::f32) {
            float val = *(float *)&mem_region_copy.bytes[0];
            match = resniff_cmp(resniff_pred_str, val, *value_to_find.asF32Ptr());
        }

        if (!match) {
            sm->thread_resniffs[id].insert(job_id);
        }
    }
}

bool check_args(const std::unordered_map<std::string, std::string> & args) {
    static std::unordered_map <std::string, std::vector<std::string> > required = {
        { "action", { "sniff", "replace", "resniff" } },
        { "type", { "i32", "f32", "str" } }
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

std::vector<void (*)(int, SharedMemory *)> get_actions_for_args(const std::unordered_map<std::string, std::string> & args, const SharedMemory & mem) {
    auto result = std::vector<void (*)(int, SharedMemory *)>();
    if (args.at("action") == "sniff") {
        result.push_back(do_sniffs);
    }

    if (args.at("action") == "replace") {
        if (mem.sniffs.empty()) {
            std::cout << "No sniff records located - doing sniff before replace" << std::endl;
            result.push_back(do_sniffs);
        }

        if (args.count("set") == 0) {
            std::cout << "Expected -set to be provided when using action replace" << std::endl;
            result.clear();
            return result;
        }
        else {
            result.push_back(do_replaces);
        }
    }

    if (args.at("action") == "resniff") {
        if (mem.sniffs.size() == 0) {
            std::cout << "Expected to find cached sniffs when using action resniff - run sniff to generate a starting sniff file" << std::endl;
            result.clear();
            return result;
        }

        if (args.count("sniff-pred") == 0) {
            std::cout << "Expected to have resniff predicate compare [lt|gt|eq] to compare existing records against" << std::endl;
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

void processResniffsIfNeeded(SharedMemory & mem) {
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
}

int main(int argc, char * argv[]) {
    auto args = getArguments(argc, argv);

    if (args.empty()) {
        std::cout << "Expected usage ./sniffer.exe [sniff|resniff|replace] -pname 'process_name' -sniff-pred [gt|eq|lt] -type [i32|f32|str] -find 'value_to_replace' -set 'value_to_set' -j [num threads to use]" << std::endl;
        return 0;
    }

    auto sniffs = win_api::getSniffsForProcess(args["pname"], win_api::getSniffTypeForStr(args["type"]));

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
    const auto actions = get_actions_for_args(args, mem);
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
    size_t total_sniffs = 0;

    for (uint32_t i = 0; i < num_threads; ++i) {
        total_bytes_considered += mem.thread_bytes[i];
        total_replacements += mem.thread_edits[i];
        total_sniffs += mem.thread_sniffs[i].size();
    }

    processResniffsIfNeeded(mem);
    writeSniffsToSniffFile(executable_to_consider, mem.sniffs);

    std::cout <<
        "Found and replaced " << total_replacements <<
        " instances of \"" << unwrap_or_default(mem.args, "find") <<
        "\" to \"" << unwrap_or_default(mem.args, "set") <<
        "\" across " << pids_to_consider.size() << " processes and " << mem.records.size() << " mem regions considering " << total_bytes_considered << " total bytes" <<
        " for " << executable_to_consider << std::endl;

    return 0;
}
