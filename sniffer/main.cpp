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

class JobIndexs {
public:
	uint64_t start_index = 0;
	uint64_t end_index = 0;
};

class SharedMemory {
	size_t current_job = 0;
	uint64_t job_spread;
	std::mutex lock;
	uint32_t num_threads;
public:
	SharedMemory(const SnifferArgs & args, std::vector<win_api::SniffRecord> * sniffs, std::vector<win_api::MemoryRegionRecord> & records, uint32_t num_threads, uint64_t job_spread)
		: args(args), sniffs(sniffs), records(records), num_threads(num_threads), job_spread(job_spread) {
		thread_resniffs.resize(num_threads);
		thread_sniffs.resize(num_threads);
	}

	std::vector<std::set<size_t>> thread_resniffs;
	std::vector<std::vector<win_api::SniffRecord>> thread_sniffs;
	void resetMultiThreadState() {
		std::lock_guard<std::mutex> stack_lock(lock);
		current_job = 0;
	}

	void getNextJob(JobIndexs & job_index) {
		std::lock_guard<std::mutex> stack_lock(lock);
		job_index.start_index = current_job;
		current_job += job_spread;
		job_index.end_index = current_job++;
	}

	size_t getCurrentJobIndex() {
		std::lock_guard<std::mutex> stack_lock(lock);
		return current_job;
	}

	std::vector<win_api::MemoryRegionRecord> & records;
	std::vector<win_api::SniffRecord> * sniffs;
	const SnifferArgs & args;
};

void do_sniff_mem_replace(win_api::SniffRecord & sniff, win_api::SniffValue & value_to_set) {
	switch (sniff.type) {
	case win_api::SniffType::str: {
		const auto value = value_to_set.asString();
		win_api::setBytesAtLocationForPidAndLocation(sniff.pid, sniff.location, (uint8_t *) &value[0], value.size());
		sniff.value.setOldValue(sniff.value.asString());
		sniff.value.setValue(value_to_set.asString());
	} break;

	case win_api::SniffType::i8: {
		int8_t value = value_to_set.asI8();
		win_api::setBytesAtLocationForPidAndLocation(sniff.pid, sniff.location, (uint8_t *)&value, 1);
		sniff.value.setOldValue(std::to_string(sniff.value.asI64()));
		sniff.value.setValue(value);
	} break;
	case win_api::SniffType::i32: {
		int32_t value = value_to_set.asI32();
		win_api::setBytesAtLocationForPidAndLocation(sniff.pid, sniff.location, (uint8_t *)&value, 4);
		sniff.value.setOldValue(std::to_string(sniff.value.asI64()));
		sniff.value.setValue(value);
	} break;
	case win_api::SniffType::i64: {
		int64_t value = value_to_set.asI64();
		win_api::setBytesAtLocationForPidAndLocation(sniff.pid, sniff.location, (uint8_t *)&value, 8);
		sniff.value.setOldValue(std::to_string(sniff.value.asI64()));
		sniff.value.setValue(value);
	} break;

	case win_api::SniffType::u8: {
		uint8_t value = value_to_set.asU8();
		win_api::setBytesAtLocationForPidAndLocation(sniff.pid, sniff.location, &value, 8);
		sniff.value.setOldValue(std::to_string(sniff.value.asU64()));
		sniff.value.setValue(value);
	} break;
	case win_api::SniffType::u32: {
		uint32_t value = value_to_set.asU32();
		win_api::setBytesAtLocationForPidAndLocation(sniff.pid, sniff.location, (uint8_t *)&value, 4);
		sniff.value.setOldValue(std::to_string(sniff.value.asU64()));
		sniff.value.setValue(value);
	} break;
	case win_api::SniffType::u64: {
		uint64_t value = value_to_set.asU64();
		win_api::setBytesAtLocationForPidAndLocation(sniff.pid, sniff.location, (uint8_t *)&value, 8);
		sniff.value.setOldValue(std::to_string(sniff.value.asU64()));
		sniff.value.setValue(value);
	} break;

	case win_api::SniffType::f32: {
		float_t value = value_to_set.asF32();
		win_api::setBytesAtLocationForPidAndLocation(sniff.pid, sniff.location, (uint8_t *)&value, 4);
		sniff.value.setOldValue(std::to_string(sniff.value.asF64()));
		sniff.value.setValue(value);
	} break;

	case win_api::SniffType::f64: {
		double_t value = value_to_set.asF64();
		win_api::setBytesAtLocationForPidAndLocation(sniff.pid, sniff.location, (uint8_t *)&value, 8);
		sniff.value.setOldValue(std::to_string(sniff.value.asF64()));
		sniff.value.setValue(value);
	} break;
	}
}

void do_replaces(int id, SharedMemory * sm) {
	auto value_to_set = win_api::SniffValue(sm->args.getContext());

	JobIndexs indexs;
	for (sm->getNextJob(indexs); indexs.start_index < sm->sniffs->size(); sm->getNextJob(indexs)) {
		for (uint64_t i = indexs.start_index; i < indexs.end_index && i < sm->sniffs->size(); ++i) {
			auto & sniff = sm->sniffs->at(i);
			do_sniff_mem_replace(sniff, value_to_set);
		}
	}
}

bool inline stype_is_type_or_none(win_api::SniffType a, win_api::SniffType b) {
	return a == b || a == win_api::SniffType::unknown;
}

bool sniff_cmp_i(std::string & pred, uint64_t a, uint64_t b) {
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

bool sniff_cmp_f(std::string & pred, double_t a, double_t b) {
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

std::set<uint8_t> getFirstBytes(win_api::SniffValue & value) {

	std::set<uint8_t> first_bytes;
	const auto str = value.asString();
	first_bytes.insert(str[0]);

	first_bytes.insert(value.asI8());
	first_bytes.insert(value.asU8());

	const auto i32 = value.asI32();
	first_bytes.insert(*(uint8_t *)&i32);

	const auto i64 = value.asI64();
	first_bytes.insert(*(uint8_t *)&i64);

	const auto u32 = value.asU32();
	first_bytes.insert(*(uint8_t *)&u32);

	const auto u64 = value.asU64();
	first_bytes.insert(*(uint8_t *)&u64);

	const auto f32 = value.asF32();
	first_bytes.insert(*(uint8_t *)&f32);

	const auto f64 = value.asF32();
	first_bytes.insert(*(uint8_t *)&f64);

	return first_bytes;
}

void find_next_sniff_loc(uint64_t & i, win_api::MemoryRegionCopy & region, uint64_t & num_zeros) {
	if (num_zeros > 0) {
		num_zeros--;
		++i;
	}
	else {
		i++;
		uint64_t num_zeros_skipped = 0;
		while (region[i] == '\0' && i < region.size() && region.is_good()) {
			++i;
			num_zeros_skipped++;
		}
		i = i - min(8, num_zeros_skipped);
		num_zeros = min(8, num_zeros_skipped);
	}
}


void do_sniffs(int id, SharedMemory * sm) {
	auto sniff_pred_str = sm->args.at("spred", "eq");
	auto sniff_type_pred_str = sm->args.at("stype");
	auto sniff_type_pred = win_api::getSniffTypeForStr(sniff_type_pred_str);
	const auto value_string_to_find = sm->args.at("ctx_param").empty() ? sm->args.getArgAtIndex(1) : sm->args.at("ctx_param");
	auto value_to_find = win_api::SniffValue(value_string_to_find.c_str());
	auto first_bytes = getFirstBytes(value_to_find);
	win_api::SniffRecord record;
	bool match = false;
	std::vector<win_api::SniffType> type_matches;
	uint8_t bound_bytes[8] = { 0 };
	uint8_t * non_str_bytes;
	auto mem_region_copy = win_api::MemoryRegionCopy();
	JobIndexs indexs;
	for (sm->getNextJob(indexs); indexs.start_index < sm->records.size(); sm->getNextJob(indexs)) {
		ProfileTimer thread_job_timer(id + 1);
		const auto & region_record = sm->records[indexs.start_index];
		mem_region_copy.reset(
			region_record.AssociatedPid,
			region_record.BaseAddress,
			region_record.RegionSize,
			region_record.is_split_record && !region_record.is_end_record
		);
		uint64_t num_zeros = 8;
		for (uint64_t i = 0; mem_region_copy.is_good() && i < mem_region_copy.size(); find_next_sniff_loc(i, mem_region_copy, num_zeros)) {
			match = false;
			type_matches.clear();

			record.pid = region_record.AssociatedPid;
			record.location = (uint64_t)(region_record.BaseAddress) + i;

			if (first_bytes.count(mem_region_copy[i]) == 0) {
				continue;
			}

			if (mem_region_copy.index_is_boundary(i)) {
				for (auto j = 0; j < 8 && i + j < mem_region_copy.size(); ++j) {
					bound_bytes[j] = mem_region_copy[i + j];
				}
				non_str_bytes = bound_bytes;
			}
			else {
				non_str_bytes = &mem_region_copy[i];
			}

			if (stype_is_type_or_none(sniff_type_pred, win_api::SniffType::str) && i + value_string_to_find.size() < mem_region_copy.size()) {
				for (uint64_t j = 0; j < value_to_find.asString().size(); ++j) {
					match = mem_region_copy[i + j] == value_to_find.asString().at(j);
					if (!match) break;
				}

				if (match) {
					record.type = win_api::SniffType::str;
					record.value.setValue(value_to_find.asString());
					sm->thread_sniffs[id].push_back(record);
				}
			}

			if (stype_is_type_or_none(sniff_type_pred, win_api::SniffType::u8) && value_to_find.asU8() != 0 && value_to_find.num_ref_bytes() == 1) {
				match = sniff_cmp_i(sniff_pred_str, *non_str_bytes, value_to_find.asU8());

				if (match) {
					record.type = win_api::SniffType::u8;
					record.value.setValue(*non_str_bytes);
					sm->thread_sniffs[id].push_back(record);
				}
			}

			if (stype_is_type_or_none(sniff_type_pred, win_api::SniffType::u32) && value_to_find.asU32() != 0 && value_to_find.num_ref_bytes() <= 4 && i + 3 < mem_region_copy.size()) {
				uint32_t val = *(uint32_t *)non_str_bytes;
				match = sniff_cmp_i(sniff_pred_str, val, value_to_find.asU32());

				if (match) {
					record.type = win_api::SniffType::u32;
					record.value.setValue(val);
					sm->thread_sniffs[id].push_back(record);
				}
			}

			if (stype_is_type_or_none(sniff_type_pred, win_api::SniffType::u64) && value_to_find.asU64() != 0 && value_to_find.num_ref_bytes() <= 8 && i + 7 < mem_region_copy.size()) {
				uint64_t val = *(uint64_t *)non_str_bytes;
				match = sniff_cmp_i(sniff_pred_str, val, value_to_find.asU64());

				if (match) {
					record.type = win_api::SniffType::u64;
					record.value.setValue(val);
					sm->thread_sniffs[id].push_back(record);
				}
			}

			if (stype_is_type_or_none(sniff_type_pred, win_api::SniffType::i8) && value_to_find.asI8() != 0 && value_to_find.num_ref_bytes() == 1) {
				int8_t val = *(int8_t *)non_str_bytes;
				match = sniff_cmp_i(sniff_pred_str, val, value_to_find.asI8());

				if (match) {
					record.type = win_api::SniffType::i8;
					record.value.setValue(val);
					sm->thread_sniffs[id].push_back(record);
				}
			}

			if (stype_is_type_or_none(sniff_type_pred, win_api::SniffType::i32) && value_to_find.asI32() != 0 && value_to_find.num_ref_bytes() <= 4 && i + 3 < mem_region_copy.size()) {
				int32_t val = *(int32_t *)non_str_bytes;
				match = sniff_cmp_i(sniff_pred_str, val, value_to_find.asI32());

				if (match) {
					record.type = win_api::SniffType::i32;
					record.value.setValue(val);
					sm->thread_sniffs[id].push_back(record);
				}
			}

			if (stype_is_type_or_none(sniff_type_pred, win_api::SniffType::i64) && value_to_find.asI64() != 0 && value_to_find.num_ref_bytes() <= 8 && i + 7 < mem_region_copy.size()) {
				int64_t val = *(int64_t *)non_str_bytes;
				match = sniff_cmp_i(sniff_pred_str, val, value_to_find.asI64());

				if (match) {
					record.type = win_api::SniffType::i64;
					record.value.setValue(val);
					sm->thread_sniffs[id].push_back(record);
				}
			}

			if (stype_is_type_or_none(sniff_type_pred, win_api::SniffType::f32) && value_to_find.asF32() != 0.0f && value_to_find.num_ref_bytes() <= 8 && i + 3 < mem_region_copy.size()) {
				float_t val = *(float_t *)non_str_bytes;
				match = sniff_cmp_f(sniff_pred_str, val, value_to_find.asF32());

				if (match) {
					record.type = win_api::SniffType::f32;
					record.value.setValue(val);
					sm->thread_sniffs[id].push_back(record);
				}
			}

			if (stype_is_type_or_none(sniff_type_pred, win_api::SniffType::f64) && value_to_find.asF64() != 0.0 && value_to_find.num_ref_bytes() <= 8 && i + 7 < mem_region_copy.size()) {
				double_t val = *(double_t *)non_str_bytes;
				match = sniff_cmp_f(sniff_pred_str, val, value_to_find.asF64());

				if (match) {
					record.type = win_api::SniffType::f64;
					record.value.setValue(val);
					sm->thread_sniffs[id].push_back(record);
				}
			}
		}
	}
}

void do_resniffs(int id, SharedMemory * sm) {
	auto is_update_resniff = sm->args.getAction() == "update";
	auto resniff_pred_str = sm->args.at("spred", "eq");
	auto resniff_type_pred_str = sm->args.at("stype");
	auto resniff_type_pred = win_api::getSniffTypeForStr(resniff_type_pred_str);
	auto resniff_value_pred_str = sm->args.at("ctx_param");
	auto resniff_value_pred = win_api::SniffValue(resniff_value_pred_str.c_str());
	auto mem_region_copy = win_api::MemoryRegionCopy();
	JobIndexs indexs;
	for (sm->getNextJob(indexs); indexs.start_index < sm->sniffs->size(); sm->getNextJob(indexs)) {
		for (uint64_t i = indexs.start_index; i < indexs.end_index && i < sm->sniffs->size(); ++i) {
			auto & sniff = sm->sniffs->at(i);
			bool match = false;

			mem_region_copy.reset(
				(win_api::DWORD)sniff.pid,
				(win_api::LPVOID) sniff.location,
				sniff.type == win_api::SniffType::str ? sniff.value.asString().size() : 8,
				false
			);
			if (!is_update_resniff && resniff_type_pred != win_api::SniffType::unknown) {
				if (sniff.type != resniff_type_pred) {
					sm->thread_resniffs[id].insert(i);
					continue;
				}
			}

			if (sniff.type == win_api::SniffType::str) {
				const auto cmp_str =
					resniff_value_pred_str.empty() ? sniff.value.asString() : resniff_value_pred.asString();

				for (uint64_t j = 0; j < sniff.value.asString().size(); ++j) {
					match = sniff_cmp_i(resniff_pred_str, mem_region_copy[j], cmp_str.at(j));

					if (!match) break;
				}

				if (is_update_resniff || match) {
					sniff.value.setValue(cmp_str);
				}
			}
			else if (sniff.type == win_api::SniffType::i8) {
				int8_t val = *(int8_t *)&mem_region_copy[0];

				if (resniff_value_pred_str.empty()) {
					match = sniff_cmp_i(resniff_pred_str, val, sniff.value.asI8());
				}
				else {
					match = sniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asI8());
				}

				if (is_update_resniff || match) {
					sniff.value.setValue(val);
				}
			}
			else if (sniff.type == win_api::SniffType::i32) {
				int32_t val = *(int32_t *)&mem_region_copy[0];

				if (resniff_value_pred_str.empty()) {
					match = sniff_cmp_i(resniff_pred_str, val, sniff.value.asI32());
				}
				else {
					match = sniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asI32());
				}

				if (is_update_resniff || match) {
					sniff.value.setValue(val);
				}
			}
			else if (sniff.type == win_api::SniffType::i64) {
				int64_t val = *(int64_t *)&mem_region_copy[0];

				if (resniff_value_pred_str.empty()) {
					match = sniff_cmp_i(resniff_pred_str, val, sniff.value.asI64());
				}
				else {
					match = sniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asI64());
				}

				if (is_update_resniff || match) {
					sniff.value.setValue(val);
				}
			}
			else if (sniff.type == win_api::SniffType::u8) {
				uint8_t val = *(uint8_t *)&mem_region_copy[0];

				if (resniff_value_pred_str.empty()) {
					match = sniff_cmp_i(resniff_pred_str, val, sniff.value.asU8());
				}
				else {
					match = sniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asU8());
				}

				if (is_update_resniff || match) {
					sniff.value.setValue(val);
				}
			}
			else if (sniff.type == win_api::SniffType::u32) {
				uint32_t val = *(uint32_t *)&mem_region_copy[0];

				if (resniff_value_pred_str.empty()) {
					match = sniff_cmp_i(resniff_pred_str, val, sniff.value.asU32());
				}
				else {
					match = sniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asU32());
				}

				if (is_update_resniff || match) {
					sniff.value.setValue(val);
				}
			}
			else if (sniff.type == win_api::SniffType::u64) {
				uint64_t val = *(uint64_t *)&mem_region_copy[0];

				if (resniff_value_pred_str.empty()) {
					match = sniff_cmp_i(resniff_pred_str, val, sniff.value.asU64());
				}
				else {
					match = sniff_cmp_i(resniff_pred_str, val, resniff_value_pred.asU64());
				}

				if (is_update_resniff || match) {
					sniff.value.setValue(val);
				}
			}
			else if (sniff.type == win_api::SniffType::f32) {
				float_t val = *(float_t *)&mem_region_copy[0];

				if (resniff_value_pred_str.empty()) {
					match = sniff_cmp_f(resniff_pred_str, val, sniff.value.asF32());
				}
				else {
					match = sniff_cmp_f(resniff_pred_str, val, resniff_value_pred.asF32());
				}

				if (is_update_resniff || match) {
					sniff.value.setValue(val);
				}
			}
			else if (sniff.type == win_api::SniffType::f64) {
				double_t val = *(double_t *)&mem_region_copy[0];

				if (resniff_value_pred_str.empty()) {
					match = sniff_cmp_f(resniff_pred_str, val, sniff.value.asF64());
				}
				else {
					match = sniff_cmp_f(resniff_pred_str, val, resniff_value_pred.asF64());
				}

				if (is_update_resniff || match) {
					sniff.value.setValue(val);
				}
			}

			if (!is_update_resniff && !match) {
				sm->thread_resniffs[id].insert(i);
			}
		}
	}
}

SnifferArgs getArguments(int argc, char * argv[]) {
	if (argc <= 2) {
		return SnifferArgs();
	}

	std::unordered_map<std::string, std::string> result_args;
	int arg_pos = 2;
	result_args["path"] = std::string(argv[0]);
	result_args["action"] = std::string(argv[1]);

	while (arg_pos < argc) {
		if (argv[arg_pos][0] == '-' && arg_pos + 1 < argc) {
			auto key = std::string(argv[arg_pos++]);
			key.erase(0, 1);
			auto value = std::string(argv[arg_pos++]);
			result_args[key] = value;
		}
		else {
			arg_pos++;
		}
	}

	SnifferArgs result(result_args);
	if (!result.checkArgs()) {
		return SnifferArgs();
	}

	return result;
}

std::vector<void (*)(int, SharedMemory *)> getActionsForArgsAndSharedMem(const SnifferArgs & args, const SharedMemory & mem) {
	auto result = std::vector<void (*)(int, SharedMemory *)>();
	if (args.actionIs("find")) {
		if (args.getContext().empty()) {
			std::cout << "Expected token after find (ie: 'find 450') to be provided when doing a find operation" << std::endl;
			result.clear();
			return result;
		}

		result.push_back(do_sniffs);
	}
	else if (args.actionIsOneOf({ "replace", "r" })) {
		if (args.getContext().empty()) {
			std::cout << "Expected token after find (id: replace 1337) to be provided when using action replace" << std::endl;
			result.clear();
			return result;
		}

		if (mem.sniffs->empty()) {
			std::cout << "Have no sniffs to replace - run 'find' to find some memory locations" << std::endl;
			result.clear();
			return result;
		}

		result.push_back(do_replaces);
	}
	else if (args.actionIsOneOf({ "filter", "update" })) {
		if (mem.sniffs->size() == 0) {
			std::cout << "Expected to find cached sniffs when using action resniff/update - run 'find' to get records" << std::endl;
			result.clear();
			return result;
		}

		result.push_back(do_resniffs);
	}

	return result;
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

		std::cout << "\t SniffRecord (id=" << i - 1 << ", pid=" << record.pid << ", location=";
		std::cout << "0x" << std::setw(16) << std::setfill('0') << std::hex << record.location << std::dec;
		std::cout << ", type=" << win_api::getSniffTypeStrForType(record.type) << ", value=" << record.value.asString();

		if (!record.value.getOldStringValue().empty()) {
			std::cout << ", old_value=" << record.value.getOldStringValue();
		}
		std::cout << ")" << std::endl;

		if (i - offset == 20) {
			if ((mem.sniffs->size() - i) != 0) {
				std::cout << "\t ... [" << mem.sniffs->size() - i << " more records] ..." << std::endl;
			}
			break;
		}
	}
}

std::vector<std::string> splitArgStringIntoWords(const std::string args_string) {
	std::vector<std::string> result;
	std::string word;
	bool in_quote = false;

	for (auto i = 0; i < args_string.size(); ++i) {
		if (args_string[i] == '"') in_quote = !in_quote;
		if (args_string[i] == ' ' && !in_quote) {
			if (!word.empty()) {
				if (word[0] == '-') {
					word.erase(word.begin());
				}
				result.push_back(word);
			}
			word = "";
		}
		else {
			if (args_string[i] != '"') {
				word.push_back(args_string[i]);
			}
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

SnifferArgs parseArgStringIntoArgsMap(const std::string args_string) {
	auto args = std::unordered_map<std::string, std::string>();
	const auto words = splitArgStringIntoWords(args_string);
	if (!words.empty()) {
		args["action"] = words[0];
	}

	if (words.size() > 1) {
		args["ctx_param"] = words[1];
	}

	for (size_t i = 2; (i + 1) < words.size(); i += 2) {
		args[words[i]] = words[i + 1];
	}

	return SnifferArgs(args, words);
}

SnifferArgs updateArgsForInteractiveMode(std::string & current_context, size_t num_records) {
	if (num_records > 0) {
		std::cout << current_context << "(" << num_records << ")> ";
	}
	else {
		std::cout << current_context << "> ";
	}
	std::string line;
	std::getline(std::cin, line);
	trim(line);
	if (line.empty() || line == "help" || line == "?") {
		std::cout << "\t Sniff memory for attached process and populate sniff records:" << std::endl;
		std::cout << "\t\t <find, f> \"VALUE\" <stype <i8|u8|i32|u32|i64|u64|f32|f64|str>> <spred <gt|lt|eq|ne>>" << std::endl;
		std::cout << "\t\t <list, ls>" << std::endl;
		std::cout << "\t Modify existing sniff records:" << std::endl;
		std::cout << "\t\t <filter> \"VALUE\" <stype <i8|u8|i32|u32|i64|u64|f32|f64|str>> <spred <gt|lt|eq|ne>>" << std::endl;
		std::cout << "\t\t <take> <index|range>" << std::endl;
		std::cout << "\t\t <remove, rm> <id|range>" << std::endl;
		std::cout << "\t\t <update>" << std::endl;
		std::cout << "\t\t <undo>" << std::endl;
		std::cout << "\t Replace all values in memory:" << std::endl;
		std::cout << "\t\t <replace, r> \"VALUE\"" << std::endl;
		std::cout << "\t Replace values in memory continuously:" << std::endl;
		std::cout << "\t\t <repeat> \"VALUE\" <<id|range>>" << std::endl;
		std::cout << "\t\t <repeat> <list, ls>" << std::endl;
		std::cout << "\t\t <repeat> <remove, rm> <id|range>" << std::endl;
		std::cout << "\t\t <repeat> <clear>" << std::endl;
		std::cout << "\t Contexts to allow multiple sniff sessions at once:" << std::endl;
		std::cout << "\t\t <context, ctx> \"NEW_CONTEXT\"" << std::endl;
		std::cout << "\t\t <context, ctx> <list, ls>" << std::endl;
		std::cout << "\t\t <context, ctx> <remove, rm> \"CONTEXT_NAME\"" << std::endl;
		std::cout << "\t\t <context, ctx> <clone> \"NEW_CONTEXT\"" << std::endl;
		std::cout << "\t Exit sniffer and save sniff file:" << std::endl;
		std::cout << "\t\t <quit, exit, q>" << std::endl;
		std::cout << "\t Display help info:" << std::endl;
		std::cout << "\t\t <\"\", ?, help>" << std::endl;
	}

	return parseArgStringIntoArgsMap(line);
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

class IndexRange {
public:
	IndexRange(uint64_t min_index, uint64_t max_index, bool is_good, bool is_multiple) : min_index(min_index), max_index(max_index), is_good(is_good), is_multiple(is_multiple) {};
	const bool is_good = true;
	const bool is_multiple = false;
	const uint64_t min_index = 0;
	const uint64_t max_index = 0;
};

IndexRange getIndexRangeFromArgument(const std::string & arg) {
	uint64_t min = 0;
	uint64_t max = 0;
	bool is_good = true;
	bool is_multiple = false;

	try {
		if (arg.find(':') == std::string::npos) {
			min = std::stoull(arg);
			max = min;
		}
		else {
			auto col_pos = arg.find(':');
			min = std::stoull(arg.substr(0, col_pos));
			max = std::stoull(arg.substr(col_pos + 1));
			is_good = min <= max;
			is_multiple = min != max;
		}
	}
	catch (...) {
		min = 0;
		max = 0;
		is_good = false;
		is_multiple = false;
	}

	return IndexRange(min, max, is_good, is_multiple);
}

int main(int argc, char * argv[]) {
	auto args = getArguments(argc, argv);

	if (args.empty()) {
		std::cout << "Expected usage ./sniffer.exe " << HELP_TEXT << std::endl;
		return 0;
	}

	win_api::setDebugPriv();
	auto replace_thread = std::thread(replace_thread_proc);
	auto sniffs_eliminated = std::unordered_map<std::string, std::vector<win_api::SniffRecord>>();
	const auto executable_to_consider = args.at("pname");
	const auto executable_to_consider_wstring = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(executable_to_consider);

	const auto sniff_file_name = args.at("st", (executable_to_consider + ".sniff").c_str());
	auto sniff_context_to_sniffs = win_api::getSniffsForProcess(sniff_file_name);
	auto current_sniff_context = args.at("context", SNIFF_GLOBAL_CONTEXT);
	if (sniff_context_to_sniffs.count(SNIFF_GLOBAL_CONTEXT) == 0) {
		auto _tmp = sniff_context_to_sniffs[SNIFF_GLOBAL_CONTEXT];
	}
	if (sniff_context_to_sniffs.count(current_sniff_context) == 0) {
		auto _tmp = sniff_context_to_sniffs[current_sniff_context];
	}
	std::vector<win_api::SniffRecord> * sniffs = &sniff_context_to_sniffs.at(current_sniff_context);
	if (args.actionIs("find")) sniffs->clear();
	const auto is_interactive = args.getAction() == "interactive";

	const auto num_threads = std::stoul(args.at("j", win_api::getNumSystemCores()));

	do {
		if (is_interactive) {
			args = updateArgsForInteractiveMode(current_sniff_context, sniff_context_to_sniffs.at(current_sniff_context).size());

			if (args.actionIsOneOf({ "exit", "quit", "q" })) {
				break;
			}
			else if (args.actionIs("undo")) {
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
				}
			}
			else if (args.actionIsOneOf({ "clear" }) && !sniffs->empty()) {
				std::cout << "Clearing all " << sniffs->size() << " sniff records" << std::endl;
				sniffs_eliminated[current_sniff_context] = *sniffs;
				sniffs->clear();
			}
			else if (args.getAction() == "context" || args.getAction() == "ctx") {
				if (args.contextIsOneOf({ "list", "ls" }) || args.size() == 1) {
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
				else if (args.contextIsOneOf({ "rm", "remove" })) {
					const auto context_to_remove = args.at("id", args.getArgAtIndex(2).c_str());
					if (sniff_context_to_sniffs.count(context_to_remove) == 0) {
						std::cout << "Context " << args.at("remove") << " cannot be removed because it does not exist" << std::endl;
					}
					else if (context_to_remove == SNIFF_GLOBAL_CONTEXT) {
						std::cout << "Cannot delete global context" << std::endl;
					}
					else {
						std::cout << "Removing sniff context " << context_to_remove << std::endl;
						sniff_context_to_sniffs.erase(context_to_remove);
						if (current_sniff_context == context_to_remove) {
							current_sniff_context = SNIFF_GLOBAL_CONTEXT;
							sniffs = &sniff_context_to_sniffs.at(current_sniff_context);
						}
					}
				}
				else if (args.contextIs("clone")) {
					const auto context_to_clone_into = args.at("id", args.getArgAtIndex(2).c_str());
					if (sniff_context_to_sniffs.count(context_to_clone_into) != 0) {
						std::cout << "Cannot clone to new context " << context_to_clone_into << " as it already exists" << std::endl;
					}
					else {
						std::cout << "Cloning current context to new context " << context_to_clone_into << std::endl;
						sniff_context_to_sniffs[context_to_clone_into] = sniff_context_to_sniffs.at(current_sniff_context);
						current_sniff_context = context_to_clone_into;
						sniffs = &sniff_context_to_sniffs.at(current_sniff_context);
					}
				}
				else {
					const auto new_context = args.getContext();
					std::cout << "Switching context to " << new_context << std::endl;
					if (sniff_context_to_sniffs.count(new_context) == 0) {
						auto _tmp = sniff_context_to_sniffs[new_context];
					}
					sniffs = &sniff_context_to_sniffs.at(new_context);
					current_sniff_context = new_context;
				}
			}
			else if (args.actionIsOneOf({ "find", "f" })) {
				if (!sniffs->empty()) {
					sniffs_eliminated[current_sniff_context] = *sniffs;
					sniffs->clear();
				}

				const auto token_to_search_for = args.getContext();

				if (token_to_search_for.empty()) {
					std::cout << "\texpect find <token>" << std::endl;
					continue;
				}

				std::cout << "Searching attached process for " << token_to_search_for << " ..." << std::endl;
			}
			else if (args.actionIsOneOf({ "remove", "rm", "r" })) {
				try {
					const auto ids = getIndexRangeFromArgument(args.getContext());
					if (ids.is_multiple) {
						std::cout << "\tErasing records " << ids.min_index << ":" << (ids.max_index >= sniffs->size() ? sniffs->size() : ids.max_index) << std::endl;
					}
					else {
						std::cout << "\tErasing record " << ids.min_index << std::endl;
					}
					if (ids.is_good && ids.min_index < sniffs->size()) {
						sniffs_eliminated[current_sniff_context].clear();
						if (ids.is_multiple) {
							auto max_index = ids.max_index >= sniffs->size() ? sniffs->size() : ids.max_index + 1;
							for (size_t i = ids.min_index; i < max_index; ++i) {
								sniffs_eliminated[current_sniff_context].push_back(sniffs->at(i));
							}
							sniffs->erase(sniffs->begin() + ids.min_index, sniffs->begin() + max_index);
						}
						else {
							sniffs_eliminated[current_sniff_context].push_back(sniffs->at(ids.min_index));
							sniffs->erase(sniffs->begin() + ids.min_index);
						}
					}
					else {
						std::cout << "Could not erase indexs that do not exist" << std::endl;
					}
				}
				catch (...) {
					// NO OP
				}
			}
			else if (args.getAction() == "repeat") {
				if (args.contextIsOneOf({ "list", "ls" }) || args.size() == 1) {
					std::cout << "Current replace repeats" << std::endl;
					{
						std::lock_guard<std::mutex> lock(replace_thread_mutex);
						size_t i = 1;
						for (auto & record_to_value : repeat_replace) {
							record_to_value.second.updateStringValue();
							std::cout << "\t RepeatReplace (id=" << (i++) << ", type=" << win_api::getSniffTypeStrForType(record_to_value.first.type) << ", location=" << std::setw(16) << std::hex << record_to_value.first.location << std::dec << ", value_to_set=" << record_to_value.second.asString() << ")" << std::endl;
						}
					}
				}
				else if (args.contextIsOneOf({ "remove", "rm" })) {
					try {
						std::lock_guard<std::mutex> lock(replace_thread_mutex);
						const auto ids = getIndexRangeFromArgument(args.at("id", args.getArgAtIndex(2).c_str()));
						if (ids.is_good && ids.min_index < repeat_replace.size() && ids.max_index < repeat_replace.size()) {
							if (ids.is_multiple) {
								auto max_index = ids.max_index == repeat_replace.size() ? ids.max_index : ids.max_index + 1;
								repeat_replace.erase(repeat_replace.begin() + ids.min_index, repeat_replace.begin() + max_index);
							}
							else {
								repeat_replace.erase(repeat_replace.begin() + ids.min_index);
							}
						}
					}
					catch (...) {
						// NO OP
					}
				}
				else if (args.contextIs("clear")) {
					std::cout << "Clearing repeat replaces" << std::endl;
					std::lock_guard<std::mutex> lock(replace_thread_mutex);
					repeat_replace.clear();
				}
				else {
					std::cout << "Setting repeat replaces" << std::endl;
					auto value_to_set = win_api::SniffValue(args.getContext());
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

			}
			else if (args.actionIsOneOf({ "take" }) && !args.getContext().empty()) {
				try {
					const auto ids = getIndexRangeFromArgument(args.getContext());
					if (ids.is_good) {
						if (ids.is_multiple) {
							std::cout << "Taking sniff set in range " << ids.min_index << " to " << ids.max_index << std::endl;
							const auto max_index = ids.max_index >= sniffs->size() ? sniffs->size() : ids.max_index + 1;
							const auto new_sniffs = std::vector<win_api::SniffRecord>(sniffs->begin() + ids.min_index, sniffs->begin() + max_index);
							sniffs->erase(sniffs->begin() + ids.min_index, sniffs->begin() + max_index);
							sniffs_eliminated[current_sniff_context] = *sniffs;
							*sniffs = new_sniffs;

						}
						else {
							std::cout << "Taking sniff value at index " << ids.min_index << std::endl;
							const auto new_sniff = std::vector<win_api::SniffRecord>{ sniffs->at(ids.min_index) };
							sniffs->erase(sniffs->begin() + ids.min_index);
							sniffs_eliminated[current_sniff_context] = *sniffs;
							*sniffs = new_sniff;
						}
					}
				}
				catch (...) {
					/* NO OP */
				}
			}
		}

		const auto pids_to_consider = win_api::getPIDSForProcessName(executable_to_consider_wstring);
		auto records = std::vector<win_api::MemoryRegionRecord>();
		for (auto i = 0; i < pids_to_consider.size(); ++i) {
			const auto records_for_pid = win_api::getAllMemoryRegionsForPID(pids_to_consider[i]);
			records.insert(records.end(), records_for_pid.begin(), records_for_pid.end());
		}

		ProfileTimer timer("sniffer command");

		std::vector<win_api::MemoryRegionRecord> split_records;
		const auto SPLIT_SIZE = 1024 * 1024 * 100;
		for (auto it = records.begin(); it != records.end();) {
			if ((*it).RegionSize > SPLIT_SIZE) {
				const auto record_to_split = (*it);
				const auto max_mem_location_of_split = (uint64_t)record_to_split.BaseAddress + record_to_split.RegionSize;
				std::cout << record_to_split.BaseAddress << " size: " << record_to_split.RegionSize << std::endl;
				for (uint64_t i = (uint64_t)record_to_split.BaseAddress, max = (uint64_t)record_to_split.BaseAddress + record_to_split.RegionSize; i < max; i += SPLIT_SIZE) {
					auto cpy = win_api::MemoryRegionRecord(record_to_split);
					cpy.BaseAddress = (win_api::PVOID) i;
					cpy.RegionSize = (i + SPLIT_SIZE) > max ? max - i : SPLIT_SIZE;
					split_records.push_back(cpy);
					split_records.back().is_split_record = true;
					split_records.back().is_end_record = false;
				}
				split_records.back().is_end_record = true;
				it = records.erase(it);
			}
			else {
				++it;
			}
		}

		for (const auto & split_record : split_records) {
			records.push_back(split_record);
		}

		uint64_t job_spread = args.actionIs("find") ? 1 : 1024;
		SharedMemory mem(args, sniffs, records, num_threads, job_spread);
		const auto actions = getActionsForArgsAndSharedMem(args, mem);
		for (const auto action : actions) {
			std::vector<std::thread> threads;
			for (uint32_t i = 0; i < num_threads; ++i) {
				threads.push_back(std::thread(action, i, &mem));
			}

			auto max_jobs = args.actionIsOneOf({ "find", "f" }) ? records.size() : sniffs->size();

			while (mem.getCurrentJobIndex() < max_jobs + 1) {
				std::cout << "\r\t Starting " << args.getAction() << " job " << mem.getCurrentJobIndex() << " / " << max_jobs << " ... ";
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
			}
			std::cout << "\r\t Starting " << args.getAction() << " job " << max_jobs << " / " << max_jobs << " ... done" << std::endl;;

			std::cout << "\t Waiting for jobs to finish ...";
			while (!threads.empty()) {
				threads.back().join();
				threads.pop_back();
			}
			std::cout << " done" << std::endl;

			for (const auto & records_vec : mem.thread_sniffs) {
				for (const auto & record : records_vec) {
					mem.sniffs->emplace_back(record);
				}
			}

			ProfileTimer::ReportAllContexts();

			mem.resetMultiThreadState();
		}

		auto new_eliminated_sniffs = processResniffsIfNeeded(mem);
		if (!new_eliminated_sniffs.empty()) {
			sniffs_eliminated[current_sniff_context] = new_eliminated_sniffs;
		}

		if (args.actionIsOneOf({ "replace", "r" })) {
			std::cout <<
				"Found and replaced " << mem.sniffs->size() <<
				" instances to '" << args.getContext() << "'" <<
				" across " << pids_to_consider.size() << " processes and " << mem.records.size() << " mem regions for " << executable_to_consider << std::endl;
			dumpSniffs(mem);
		}
		else if (args.actionIsOneOf({ "find", "f" })) {
			std::cout << "Found " << mem.sniffs->size() << " records: " << std::endl;
			dumpSniffs(mem);
		}
		else if (args.actionIs("filter")) {
			std::cout << "Filtered " << new_eliminated_sniffs.size() << " records which ! " << args.at("spred", "eq") << " " << args.at("ctx_param", "the original value") << ". Remaining records: " << std::endl;
			dumpSniffs(mem);
		}
		else if (args.actionIsOneOf({ "list", "ls", "l" })) {
			std::cout << "Working with " << mem.sniffs->size() << " sniffs:" << std::endl;
			try {
				const auto offset = std::stoul(args.getContext("0"));
				dumpSniffs(mem, offset);
			}
			catch (...) {
				dumpSniffs(mem);
			}
		}
		else if (args.actionIs("update")) {
			std::cout << "Updated sniffs with existing values in the process(s)" << std::endl;
			dumpSniffs(mem);
		}
		else if (args.actionIsOneOf({ "undo", "context", "ctx", "clear", "remove", "rm", "repeat" })) {
			// NO-OP
		}
		else {
			std::cout << "Unknown command \"" << args.getAction() << "\"" << std::endl;
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

	win_api::clear_open_handles();

	return 0;
}
