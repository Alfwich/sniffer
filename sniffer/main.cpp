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

class SharedMemory {
    size_t current_job = 0;
    std::mutex lock;
public:
    SharedMemory(const std::unordered_map<std::string, std::string> & args, std::vector<win_api::SniffRecord> & sniffs, std::vector<win_api::MemoryRegionRecord> & records, uint32_t num_threads) : args(args), sniffs(sniffs), records(records) {
        thread_edits.resize(num_threads);
        thread_bytes.resize(num_threads);
        thread_sniffs.resize(num_threads);
    }

    std::vector<size_t> thread_edits;
    std::vector<size_t> thread_bytes;
    std::vector<std::vector<win_api::SniffRecord>> thread_sniffs;
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
    int32_t i32_replace;
    float f32_replace;
    std::string str_replace;

    auto replace_type_str = sm->args.at("type");
    auto replace_type = win_api::getSniffTypeForStr(replace_type_str);
    switch (replace_type) {
    case win_api::SniffType::str: str_replace = sm->args.at("set"); break;
    case win_api::SniffType::i32: i32_replace = std::stoi(sm->args.at("set")); break;
    case win_api::SniffType::f32: f32_replace = std::stof(sm->args.at("set")); break;
    default: return; // Unknown type - bail
    };

    for (auto i = sm->getNextJob(); i < sm->sniffs.size(); i = sm->getNextJob()) {
        const auto & sniff = sm->sniffs.at(i);

        switch (sniff.type) {
        case win_api::SniffType::str: {
            sm->thread_edits[id]++;
            for (auto j = 0; j < str_replace.size(); ++j) {
                win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, str_replace[j]);
            }
        } break;
        case win_api::SniffType::i32: {
            sm->thread_edits[id]++;
            char * value_byte_ptr = (char *)&i32_replace;
            for (auto j = 0; j < 4; ++j) {
                win_api::setByteAtLocationForPidAndLocation(sniff.pid, sniff.location + j, *(value_byte_ptr + j));
            }
        } break;
        case win_api::SniffType::f32: {
            sm->thread_edits[id]++;
            char * value_byte_ptr = (char *)&f32_replace;
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

    int32_t i32_find = 0xDEADBEEF;
    float f32_find = (float)0xDEADBEEF;
    std::string str_find = "0xDEADBEEF";

    switch (replace_type) {
    case win_api::SniffType::str: str_find = sm->args.at("find"); break;
    case win_api::SniffType::i32: i32_find = std::stoi(sm->args.at("find")); break;
    case win_api::SniffType::f32: f32_find = std::stof(sm->args.at("find")); break;
    default: return; // Unknown type - bail
    };

    auto mem_region_copy = win_api::MemoryRegionCopy();
    for (auto i = sm->getNextJob(); i < sm->records.size(); i = sm->getNextJob()) {
        const auto & region_record = sm->records[i];
        getMemoryRegionCopyForMemoryRegionRecord(region_record, mem_region_copy);
        sm->thread_bytes[id] += mem_region_copy.bytes.size();
        for (uint64_t i = 0; i < mem_region_copy.bytes.size(); ++i) {
            bool match = false;
            if (i + sm->args.at("find").size() < mem_region_copy.bytes.size() && replace_type == win_api::SniffType::str) {
                for (uint64_t j = 0; j < str_find.size(); ++j) {
                    match = mem_region_copy.bytes[i + j] == str_find.at(j);
                    if (!match) break;
                }
            }
            else if (i + 3 < mem_region_copy.bytes.size() && replace_type == win_api::SniffType::i32) {
                int32_t val = *(int32_t *)&mem_region_copy.bytes[i];
                match = val == i32_find;
            }
            else if (i + 3 < mem_region_copy.bytes.size() && replace_type == win_api::SniffType::f32) {
                float val = *(float *)&mem_region_copy.bytes[i];
                match = val == f32_find;
            }

            if (match) {
                sm->thread_sniffs[id].emplace_back(region_record.AssociatedPid, "", (uint64_t)(region_record.BaseAddress) + i, replace_type);
            }
        }
    }
}

void do_resniff(int id, SharedMemory * sm) {
    // TODO: Loop over sniffs and validate/invalidate 
}

bool check_args(const std::unordered_map<std::string, std::string> & args) {
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
            has_match = test_value == "*" || has_match || args.at(key) == test_value;
        }

        if (!has_match) {
            return false;
        }
    }

    return true;
}

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

    if (!check_args(result)) {
        result.clear();
    }

    return result;
}

std::vector<void (*)(int, SharedMemory *)> get_actions_for_args(const std::unordered_map<std::string, std::string> & args, const SharedMemory & mem) {
    auto result = std::vector<void (*)(int, SharedMemory *)>();
    if (args.at("action") == "sniff" || mem.sniffs.empty()) {
        result.push_back(do_sniffs);
    }

    if (args.at("action") == "replace") {
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
        result.push_back(do_resniff);
    }

    return result;
}

uint32_t getNumThreads(std::unordered_map<std::string, std::string> & args) {
    auto arg_threads = args.count("j") > 0 ? std::stoi(args["j"]) : DEFAULT_THREADS;
    return max(arg_threads, 1);
}

int32_t test_int = 13371337;
float test_float = 13371337.13f;
const char * test_string = "Hello World!";

int main(int argc, char * argv[]) {
    auto args = getArguments(argc, argv);

    if (args.empty()) {
        std::cout << "Expected usage ./sniffer.exe [sniff|resniff|replace] -pname 'process_name' -sniff-pred [gt|eq|lt] -type [i32|f32|str] -find 'value_to_replace' -set 'value_to_set' -j [num threads to use]" << std::endl;
        return 0;
    }

    auto sniffs = win_api::getSniffsForProcess(args["pname"]);

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
    std::vector<const win_api::SniffRecord *> sniff_records;

    for (const auto record : mem.sniffs) {
        sniff_records.push_back(&record);
    }

    for (uint32_t i = 0; i < num_threads; ++i) {
        total_bytes_considered += mem.thread_bytes[i];
        total_replacements += mem.thread_edits[i];
        total_sniffs += mem.thread_sniffs[i].size();
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
