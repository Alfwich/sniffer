#include "sniffer.h"

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

#include "profile_timer.h"
#include "utils.h"
#include "sniffer_cmds.h"

namespace sniffer {

	bool do_sniff_mem_replace(uint64_t pid, uint64_t mem_location, w32::sniff_type_e type, w32::sniff_value_t & value_to_set) {
		switch (type) {
		case w32::sniff_type_e::str: {
			const auto value = value_to_set.as_string();
			w32::set_bytes_at_location_for_pid(pid, mem_location, (uint8_t *)&value[0], value.size());
		} break;

		case w32::sniff_type_e::i8: {
			auto value = value_to_set.as_int<int8_t>();
			w32::set_bytes_at_location_for_pid(pid, mem_location, (uint8_t *)&value, 1);
		} break;
		case w32::sniff_type_e::i32: {
			auto value = value_to_set.as_int<int32_t>();
			w32::set_bytes_at_location_for_pid(pid, mem_location, (uint8_t *)&value, 4);
		} break;
		case w32::sniff_type_e::i64: {
			auto value = value_to_set.as_int<int64_t>();
			w32::set_bytes_at_location_for_pid(pid, mem_location, (uint8_t *)&value, 8);
		} break;

		case w32::sniff_type_e::u8: {
			auto value = value_to_set.as_uint<uint8_t>();
			w32::set_bytes_at_location_for_pid(pid, mem_location, &value, 8);
		} break;
		case w32::sniff_type_e::u32: {
			auto value = value_to_set.as_uint<uint32_t>();
			w32::set_bytes_at_location_for_pid(pid, mem_location, (uint8_t *)&value, 4);
		} break;
		case w32::sniff_type_e::u64: {
			auto value = value_to_set.as_uint<uint64_t>();
			w32::set_bytes_at_location_for_pid(pid, mem_location, (uint8_t *)&value, 8);
		} break;

		case w32::sniff_type_e::f32: {
			auto value = value_to_set.as_float<float_t>();
			w32::set_bytes_at_location_for_pid(pid, mem_location, (uint8_t *)&value, 4);
		} break;

		case w32::sniff_type_e::f64: {
			auto value = value_to_set.as_float<double_t>();
			w32::set_bytes_at_location_for_pid(pid, mem_location, (uint8_t *)&value, 8);
		} break;

		case w32::sniff_type_e::unknown:
		default:
			return false;
			break;
		}

		return true;
	}

	void do_set(int id, shared_memory_t * sm) {
		auto value_to_set = w32::sniff_value_t(sm->args->context());

		jobs_indicies_t indexs;
		for (sm->get_next_job(indexs); indexs.start_index < sm->work_units.size(); sm->get_next_job(indexs)) {
			auto & work_unit = sm->work_units.at(indexs.start_index);
			do_sniff_mem_replace(work_unit.pid, work_unit.mem_location, work_unit.type, value_to_set);
		}
	}

	bool inline type_is_type_or_none(w32::sniff_type_e a, w32::sniff_type_e b) {
		return a == b || a == w32::sniff_type_e::unknown;
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

	std::set<uint8_t> getFirstBytes(w32::sniff_value_t & value) {

		std::set<uint8_t> first_bytes;
		const auto str = value.as_string();
		first_bytes.insert(str[0]);

		first_bytes.insert(value.as_uint<uint8_t>());
		first_bytes.insert(value.as_int<int8_t>());

		const auto i32 = value.as_int<int32_t>();
		first_bytes.insert(*((uint8_t *)&i32));

		const auto i64 = value.as_int<int64_t>();
		first_bytes.insert(*(uint8_t *)&i64);

		const auto u32 = value.as_int<uint32_t>();
		first_bytes.insert(*(uint8_t *)&u32);

		const auto u64 = value.as_int<uint64_t>();
		first_bytes.insert(*(uint8_t *)&u64);

		const auto f32 = value.as_float<float_t>();
		first_bytes.insert(*(uint8_t *)&f32);

		const auto f64 = value.as_float<double_t>();
		first_bytes.insert(*(uint8_t *)&f64);

		return first_bytes;
	}

	void find_next_sniff_loc(uint64_t & i, w32::memory_region_copy_t & region, uint64_t & num_zeros) {
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


	void do_find(int id, shared_memory_t * sm) {
		auto find_pred_str = sm->args->at("pred", "eq");
		auto find_type_pred_str = sm->args->at("type");
		auto find_type_pred = w32::get_sniff_type_for_str(find_type_pred_str);
		const auto value_string_to_find = sm->args->at("ctx_param").empty() ? sm->args->arg_at_index(1) : sm->args->at("ctx_param");
		auto value_to_find = w32::sniff_value_t(value_string_to_find.c_str());
		auto first_bytes = getFirstBytes(value_to_find);
		bool match = false;
		std::vector<w32::sniff_type_e> type_matches;
		uint8_t bound_bytes[8] = { 0 };
		uint8_t * non_str_bytes;
		auto min_num_int_bytes = value_to_find.min_num_int_bytes();
		auto mem_region_copy = w32::memory_region_copy_t();
		jobs_indicies_t indexs;
		for (sm->get_next_job(indexs); indexs.start_index < sm->records->size(); sm->get_next_job(indexs)) {
			const auto & region_record = sm->records->at(indexs.start_index);
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

				uint64_t location = (uint64_t)(region_record.BaseAddress) + i;

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

				if (type_is_type_or_none(find_type_pred, w32::sniff_type_e::str) && i + value_string_to_find.size() < mem_region_copy.size()) {
					for (uint64_t j = 0; j < value_to_find.as_string().size(); ++j) {
						match = mem_region_copy[i + j] == value_to_find.as_string().at(j);
						if (!match) break;
					}

					if (match) {
						sm->sniff_record->setLocation(w32::sniff_type_e::str, region_record.AssociatedPid, location);
					}
				}

				if (min_num_int_bytes <= 1 && type_is_type_or_none(find_type_pred, w32::sniff_type_e::u8)) {
					match = sniff_cmp_i(find_pred_str, *non_str_bytes, value_to_find.as_uint<uint8_t>());

					if (match) {
						sm->sniff_record->setLocation(w32::sniff_type_e::u8, region_record.AssociatedPid, location);
					}
				}

				if (min_num_int_bytes <= 4 && type_is_type_or_none(find_type_pred, w32::sniff_type_e::u32)) {
					uint32_t val = *(uint32_t *)non_str_bytes;
					match = sniff_cmp_i(find_pred_str, val, value_to_find.as_uint<uint32_t>());

					if (match) {
						sm->sniff_record->setLocation(w32::sniff_type_e::u32, region_record.AssociatedPid, location);
					}
				}

				if (min_num_int_bytes <= 8 && type_is_type_or_none(find_type_pred, w32::sniff_type_e::u64)) {
					uint64_t val = *(uint64_t *)non_str_bytes;
					match = sniff_cmp_i(find_pred_str, val, value_to_find.as_uint<uint64_t>());

					if (match) {
						sm->sniff_record->setLocation(w32::sniff_type_e::u64, region_record.AssociatedPid, location);
					}
				}

				if (min_num_int_bytes <= 1 && type_is_type_or_none(find_type_pred, w32::sniff_type_e::i8)) {
					int8_t val = *(int8_t *)non_str_bytes;
					match = sniff_cmp_i(find_pred_str, val, value_to_find.as_int<int8_t>());

					if (match) {
						sm->sniff_record->setLocation(w32::sniff_type_e::i8, region_record.AssociatedPid, location);
					}
				}

				if (min_num_int_bytes <= 4 && type_is_type_or_none(find_type_pred, w32::sniff_type_e::i32)) {
					int32_t val = *(int32_t *)non_str_bytes;
					match = sniff_cmp_i(find_pred_str, val, value_to_find.as_int<int32_t>());

					if (match) {
						sm->sniff_record->setLocation(w32::sniff_type_e::i32, region_record.AssociatedPid, location);
					}
				}

				if (min_num_int_bytes <= 8 && type_is_type_or_none(find_type_pred, w32::sniff_type_e::i64)) {
					int64_t val = *(int64_t *)non_str_bytes;
					match = sniff_cmp_i(find_pred_str, val, value_to_find.as_int<int64_t>());

					if (match) {
						sm->sniff_record->setLocation(w32::sniff_type_e::i64, region_record.AssociatedPid, location);
					}
				}

				if (type_is_type_or_none(find_type_pred, w32::sniff_type_e::f32)) {
					float_t val = *(float_t *)non_str_bytes;
					match = sniff_cmp_f(find_pred_str, val, value_to_find.as_float<float_t>());

					if (match) {
						sm->sniff_record->setLocation(w32::sniff_type_e::f32, region_record.AssociatedPid, location);
					}
				}

				if (type_is_type_or_none(find_type_pred, w32::sniff_type_e::f64)) {
					double_t val = *(double_t *)non_str_bytes;
					match = sniff_cmp_f(find_pred_str, val, value_to_find.as_float<double_t>());

					if (match) {
						sm->sniff_record->setLocation(w32::sniff_type_e::f64, region_record.AssociatedPid, location);
					}
				}
			}
		}
	}

	void do_filter(int id, shared_memory_t * sm) {
		auto filter_pred_str = sm->args->at("pred", "eq");
		auto filter_type_pred_str = sm->args->at("type");
		auto filter_type_pred = w32::get_sniff_type_for_str(filter_type_pred_str);
		auto filter_value_pred_str = sm->args->context();
		auto filter_value_pred = w32::sniff_value_t(filter_value_pred_str.c_str());
		auto mem_region_copy = w32::memory_region_copy_t();
		jobs_indicies_t indexs;
		for (sm->get_next_job(indexs); indexs.start_index < sm->work_units.size(); sm->get_next_job(indexs)) {
			for (uint64_t i = indexs.start_index; i < indexs.end_index && i < sm->work_units.size(); ++i) {
				auto & work_unit = sm->work_units.at(i);
				bool match = false;

				mem_region_copy.reset(
					(w32::DWORD)work_unit.pid,
					(w32::LPVOID)work_unit.mem_location,
					work_unit.type == w32::sniff_type_e::str ? sm->sniff_record->value.as_string().size() : 8,
					false
				);
				if (filter_type_pred != w32::sniff_type_e::unknown) {
					if (work_unit.type != filter_type_pred) {
						sm->thread_resniffs[id].insert(std::make_tuple(work_unit.type, work_unit.pid, work_unit.mem_location));
						continue;
					}
				}

				if (work_unit.type == w32::sniff_type_e::str) {
					const auto cmp_str =
						filter_value_pred_str.empty() ? sm->sniff_record->value.as_string() : filter_value_pred.as_string();

					for (uint64_t j = 0; j < sm->sniff_record->value.as_string().size(); ++j) {
						match = sniff_cmp_i(filter_pred_str, mem_region_copy[j], cmp_str.at(j));

						if (!match) break;
					}
				}
				else if (work_unit.type == w32::sniff_type_e::i8) {
					int8_t val = *(int8_t *)&mem_region_copy[0];

					if (filter_value_pred_str.empty()) {
						match = sniff_cmp_i(filter_pred_str, val, sm->sniff_record->value.as_int<int8_t>());
					}
					else {
						match = sniff_cmp_i(filter_pred_str, val, filter_value_pred.as_int<int8_t>());
					}
				}
				else if (work_unit.type == w32::sniff_type_e::i32) {
					int32_t val = *(int32_t *)&mem_region_copy[0];

					if (filter_value_pred_str.empty()) {
						match = sniff_cmp_i(filter_pred_str, val, sm->sniff_record->value.as_int<int32_t>());
					}
					else {
						match = sniff_cmp_i(filter_pred_str, val, filter_value_pred.as_int<int32_t>());
					}
				}
				else if (work_unit.type == w32::sniff_type_e::i64) {
					int64_t val = *(int64_t *)&mem_region_copy[0];

					if (filter_value_pred_str.empty()) {
						match = sniff_cmp_i(filter_pred_str, val, sm->sniff_record->value.as_int<int64_t>());
					}
					else {
						match = sniff_cmp_i(filter_pred_str, val, filter_value_pred.as_int<int64_t>());
					}
				}
				else if (work_unit.type == w32::sniff_type_e::u8) {
					uint8_t val = *(uint8_t *)&mem_region_copy[0];

					if (filter_value_pred_str.empty()) {
						match = sniff_cmp_i(filter_pred_str, val, sm->sniff_record->value.as_uint<uint8_t>());
					}
					else {
						match = sniff_cmp_i(filter_pred_str, val, filter_value_pred.as_uint<uint8_t>());
					}
				}
				else if (work_unit.type == w32::sniff_type_e::u32) {
					uint32_t val = *(uint32_t *)&mem_region_copy[0];

					if (filter_value_pred_str.empty()) {
						match = sniff_cmp_i(filter_pred_str, val, sm->sniff_record->value.as_uint<uint32_t>());
					}
					else {
						match = sniff_cmp_i(filter_pred_str, val, filter_value_pred.as_uint<uint32_t>());
					}
				}
				else if (work_unit.type == w32::sniff_type_e::u64) {
					uint64_t val = *(uint64_t *)&mem_region_copy[0];

					if (filter_value_pred_str.empty()) {
						match = sniff_cmp_i(filter_pred_str, val, sm->sniff_record->value.as_uint<uint64_t>());
					}
					else {
						match = sniff_cmp_i(filter_pred_str, val, filter_value_pred.as_uint<uint64_t>());
					}
				}
				else if (work_unit.type == w32::sniff_type_e::f32) {
					float_t val = *(float_t *)&mem_region_copy[0];

					if (filter_value_pred_str.empty()) {
						match = sniff_cmp_f(filter_pred_str, val, sm->sniff_record->value.as_float<float_t>());
					}
					else {
						match = sniff_cmp_f(filter_pred_str, val, filter_value_pred.as_float<float_t>());
					}

				}
				else if (work_unit.type == w32::sniff_type_e::f64) {
					double_t val = *(double_t *)&mem_region_copy[0];

					if (filter_value_pred_str.empty()) {
						match = sniff_cmp_f(filter_pred_str, val, sm->sniff_record->value.as_float<double_t>());
					}
					else {
						match = sniff_cmp_f(filter_pred_str, val, filter_value_pred.as_float<double_t>());
					}
				}

				if (!match) {
					sm->thread_resniffs[id].insert(std::make_tuple(work_unit.type, work_unit.pid, work_unit.mem_location));
				}
			}
		}
	}

	sniffer_args_t get_arguments(int argc, char * argv[]) {
		if (argc <= 2) {
			return sniffer_args_t();
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

		sniffer_args_t result(result_args);
		if (!result.checkArgs()) {
			return sniffer_args_t();
		}

		return result;
	}

	std::vector<void (*)(int, shared_memory_t *)> get_actions_for_ctx(sniffer_context_t & ctx) {
		auto result = std::vector<void (*)(int, shared_memory_t *)>();
		if (ctx.args.action_is(sniffer_cmd_e::find)) {
			if (ctx.args.context().empty()) {
				std::cout << "Expected token after find (ie: 'find 450') to be provided when doing a find operation" << std::endl;
				result.clear();
				return result;
			}

			result.push_back(do_find);
		}
		else if (ctx.args.action_is(sniffer_cmd_e::set)) {
			if (ctx.args.context().empty()) {
				std::cout << "Expected token after set (ie: set 1337) to be provided when using action set" << std::endl;
				result.clear();
				return result;
			}

			if (ctx.state.sniffs->empty()) {
				std::cout << "Have no sniffs to replace - run 'find' to find some memory locations" << std::endl;
				result.clear();
				return result;
			}

			result.push_back(do_set);
		}
		else if (ctx.args.action_is(sniffer_cmd_e::filter)) {
			if (ctx.state.sniffs->empty()) {
				std::cout << "Expected to find cached sniffs when using action filter - run 'find' to get records" << std::endl;
				result.clear();
				return result;
			}

			result.push_back(do_filter);
		}

		return result;
	}

	std::vector<w32::sniff_record_set_t> filter_sniffs(sniffer_context_t & ctx) {
		std::vector<w32::sniff_record_set_t> result;
		std::set<std::tuple<w32::sniff_type_e, size_t, uint64_t>> sniffs_to_exclude;
		for (const auto & resniff : ctx.mem.thread_resniffs) {
			for (const auto index_to_exclude : resniff) {
				sniffs_to_exclude.insert(index_to_exclude);
			}

		}

		for (auto & type_to_locations : ctx.state.sniffs->getLocations()) {
			for (auto it = type_to_locations.second.begin(); it != type_to_locations.second.end();) {
				if (sniffs_to_exclude.count(*it) == 1) {
					it = type_to_locations.second.erase(it);
				}
				else {
					++it;
				}
			}
		}

		return result;
	}

	void dump_sniffs(w32::sniff_record_set_t * record, uint32_t offset = 0) {
		uint32_t i = 0;
		bool has_offset_output = false;
		auto mem_region_copy = w32::memory_region_copy_t();
		for (auto & type_to_location : record->getLocations()) {
			for (const auto mem_location : type_to_location.second) {

				if (i++ < offset) {
					has_offset_output = true;
					continue;
				}
				else if (has_offset_output) {
					std::cout << "\t ... [" << (i - 1) << " previous records] ..." << std::endl;
					has_offset_output = false;
				}

				const auto size = std::get<0>(mem_location) == w32::sniff_type_e::str ? record->value.as_string().size() : 8;
				mem_region_copy.reset(
					(w32::DWORD)std::get<1>(mem_location),
					(w32::LPVOID)std::get<2>(mem_location),
					size,
					false
				);
				std::cout << "\t SniffRecord (id=" << i - 1 << ", pid=" << std::get<1>(mem_location) << ", location=";
				std::cout << "0x" << std::setw(16) << std::setfill('0') << std::hex << std::get<2>(mem_location) << std::dec;
				std::cout << ", type=" << w32::get_sniff_type_str_for_type(type_to_location.first) << ", value=" << data_to_string(type_to_location.first, &mem_region_copy[0], size);
				std::cout << ")" << std::endl;

				if (i - offset == 20) {
					break;
				}
			}

			if (i - offset == 20) {
				if ((record->size() - i) != 0) {
					std::cout << "\t ... [" << record->size() - i << " more records] ..." << std::endl;
				}
				break;
			}

		}
	}

	std::vector<std::string> split_args_into_words(const std::string args_string) {
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

	sniffer_args_t parse_arg_string_into_args_map(const std::string args_string) {
		auto args = std::unordered_map<std::string, std::string>();
		const auto words = split_args_into_words(args_string);
		if (!words.empty()) {
			args["action"] = words[0];
		}

		if (words.size() > 1) {
			args["ctx_param"] = words[1];
		}

		for (size_t i = 2; (i + 1) < words.size(); i += 2) {
			args[words[i]] = words[i + 1];
		}

		return sniffer_args_t(args, words);
	}

	sniffer_args_t update_args_for_interactive_mode(sniffer_context_t & ctx) {
		if (ctx.state.sniffs->empty()) {
			std::cout << ctx.state.current_context << "> ";
		}
		else {
			std::cout << ctx.state.current_context << "(" << ctx.state.sniffs->size() << ")> ";
		}
		std::string line;
		std::getline(std::cin, line);
		trim(line);
		// TODO: Make this help output generated from sniffer_cmds
		if (line.empty() || line == "help" || line == "?") {
			std::cout << "\t Sniff memory for attached process and populate sniff records:" << std::endl;
			std::cout << "\t\t <find, f> \"VALUE\" <type <i8|u8|i32|u32|i64|u64|f32|f64|str>> <pred <gt|lt|eq|ne>>" << std::endl;
			std::cout << "\t\t <list, ls>" << std::endl;
			std::cout << "\t Modify existing sniff records:" << std::endl;
			std::cout << "\t\t <filter> \"VALUE\" <type <i8|u8|i32|u32|i64|u64|f32|f64|str>> <pred <gt|lt|eq|ne>>" << std::endl;
			std::cout << "\t\t <take> <index|range>" << std::endl;
			std::cout << "\t\t <remove, rm> <id|range>" << std::endl;
			std::cout << "\t\t <undo>" << std::endl;
			std::cout << "\t\t <profile>" << std::endl;
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
			std::cout << "\t\t <?, help>" << std::endl;
		}

		return parse_arg_string_into_args_map(line);
	}


	void replace_thread_proc(sniffer_context_t * ctx) {
		while (ctx->state.replace_thread_is_running) {
			{
				std::lock_guard<std::mutex> lock_guard(ctx->state.replace_thread_mutex);
				for (auto & sniff_record_to_sniff_value : ctx->state.repeat_replace) {
					for (const auto & type_to_locations : sniff_record_to_sniff_value.first.getLocations()) {
						for (const auto & pid_and_mem_location : type_to_locations.second) {
							if (do_sniff_mem_replace(std::get<2>(pid_and_mem_location), std::get<1>(pid_and_mem_location), type_to_locations.first, sniff_record_to_sniff_value.second)) {
							}
						}
					}
				}
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
	}

	class index_range_t {
	public:
		index_range_t(uint64_t min_index, uint64_t max_index, bool is_good, bool is_multiple) : min_index(min_index), max_index(max_index), is_good(is_good), is_multiple(is_multiple) {};
		const bool is_good = true;
		const bool is_multiple = false;
		const uint64_t min_index = 0;
		const uint64_t max_index = 0;
	};

	index_range_t getIndexRangeFromArgument(const std::string & arg) {
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

		return index_range_t(min, max, is_good, is_multiple);
	}

	// Returns false when we should end interactive execution
	bool update_interactive_arg(sniffer_context_t & ctx) {

		ctx.args = update_args_for_interactive_mode(ctx);

		return !ctx.args.action_is(sniffer_cmd_e::quit);
	}

	void do_pre_workload(sniffer_context_t & ctx) {
		profile_timer_t timer(ctx.state.profile, __FUNCTION__);
		if (ctx.args.action_is(sniffer_cmd_e::undo)) {
			/* TODO: Refactor undo
			if (sniffs_eliminated[current_sniff_context].empty()) {
				std::cout << "No history of sniffs to undo" << std::endl;
			}
			else {
				std::cout << "Returned " << sniffs_eliminated[current_sniff_context].size() << " records into the working sniff set" << std::endl;
				std::vector<win_api::SniffRecordSet> old_records = *sniffs;
				for (auto & record : sniffs_eliminated[current_sniff_context]) {
					sniffs->push_back(record);
				}
				sniffs_eliminated.clear();
			}
			*/
		}
		else if (ctx.args.action_is(sniffer_cmd_e::clear) && !ctx.state.sniffs->empty()) {
			std::cout << "Clearing all " << ctx.state.sniffs->size() << " sniff records" << std::endl;
			ctx.state.sniffs->clear();
			/* TODO: Refactor undo
			sniffs_eliminated[current_sniff_context] = *sniffs;
			*/
		}
		else if (ctx.args.action_is(sniffer_cmd_e::context)) {
			if (ctx.args.context_is(sniffer_cmd_e::context_list) || ctx.args.size() == 1) {
				std::cout << "Registered Contexts:" << std::endl;
				for (const auto & context_to_sniffs : ctx.state.context_to_sniffs) {
					if (context_to_sniffs.first == ctx.state.current_context) {
						std::cout << "\t" << context_to_sniffs.first << "(" << context_to_sniffs.second.size() << ") [current]" << std::endl;
					}
					else {
						std::cout << "\t" << context_to_sniffs.first << "(" << context_to_sniffs.second.size() << ")" << std::endl;
					}
				}
			}
			else if (ctx.args.context_is(sniffer_cmd_e::context_remove)) {
				const auto context_to_remove = ctx.args.at("id", ctx.args.arg_at_index(2).c_str());
				if (ctx.state.context_to_sniffs.count(context_to_remove) == 0) {
					std::cout << "Context " << ctx.args.at("remove") << " cannot be removed because it does not exist" << std::endl;
				}
				else if (context_to_remove == SNIFF_GLOBAL_CONTEXT) {
					std::cout << "Cannot delete global context" << std::endl;
				}
				else {
					std::cout << "Removing sniff context " << context_to_remove << std::endl;
					ctx.state.context_to_sniffs.erase(context_to_remove);
					if (ctx.state.current_context == context_to_remove) {
						ctx.state.current_context = SNIFF_GLOBAL_CONTEXT;
						ctx.state.sniffs = &ctx.state.context_to_sniffs.at(ctx.state.current_context);
					}
				}
			}
			else if (ctx.args.context_is(sniffer_cmd_e::context_clone)) {
				const auto context_to_clone_into = ctx.args.at("id", ctx.args.arg_at_index(2).c_str());
				if (ctx.state.context_to_sniffs.count(context_to_clone_into) != 0) {
					std::cout << "Cannot clone to new context " << context_to_clone_into << " as it already exists" << std::endl;
				}
				else {
					std::cout << "Cloning current context to new context " << context_to_clone_into << std::endl;
					ctx.state.context_to_sniffs[context_to_clone_into] = ctx.state.context_to_sniffs.at(ctx.state.current_context);
					ctx.state.current_context = context_to_clone_into;
					ctx.state.sniffs = &ctx.state.context_to_sniffs.at(ctx.state.current_context);
				}
			}
			else {
				const auto new_context = ctx.args.context();
				std::cout << "Switching context to " << new_context << std::endl;
				if (ctx.state.context_to_sniffs.count(new_context) == 0) {
					auto _tmp = ctx.state.context_to_sniffs[new_context];
				}
				ctx.state.sniffs = &ctx.state.context_to_sniffs.at(new_context);
				ctx.state.current_context = new_context;
			}
		}
		else if (ctx.args.action_is(sniffer_cmd_e::find)) {
			if (!ctx.state.sniffs->empty()) {
				ctx.state.sniffs->clear();
			}

			const auto token_to_search_for = ctx.args.context();

			std::cout << "Searching attached process for " << token_to_search_for << " ..." << std::endl;
			ctx.state.sniffs->value.set_value(token_to_search_for);
		}
		else if (ctx.args.action_is(sniffer_cmd_e::remove)) {
			try {
				const auto ids = getIndexRangeFromArgument(ctx.args.context());
				if (ids.is_multiple) {
					std::cout << "\tErasing records " << ids.min_index << ":" << (ids.max_index >= ctx.state.sniffs->size() ? ctx.state.sniffs->size() : ids.max_index) << std::endl;
				}
				else {
					std::cout << "\tErasing record " << ids.min_index << std::endl;
				}
				if (ids.is_good && ids.min_index < ctx.state.sniffs->size()) {
					/* TODO: Add rm
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
					*/
				}
				else {
					std::cout << "Could not erase indexs that do not exist" << std::endl;
				}
			}
			catch (...) {
				// NO OP
			}
		}
		else if (ctx.args.action_is(sniffer_cmd_e::profile)) {
			std::cout << "Turning " << (ctx.state.profile ? "off" : "on") << " profile output" << std::endl;
			ctx.state.profile = !ctx.state.profile;
		}
		else if (ctx.args.action_is(sniffer_cmd_e::repeat)) {
			if (ctx.args.context_is(sniffer_cmd_e::repeat_list) || ctx.args.size() == 1) {
				std::cout << "Current replace repeats" << std::endl;
				{
					std::lock_guard<std::mutex> lock(ctx.state.replace_thread_mutex);
					size_t i = 1;
					for (auto & record_to_value : ctx.state.repeat_replace) {
						for (auto & type_to_locations : record_to_value.first.getLocations()) {
							for (auto & mem_location : type_to_locations.second) {
								record_to_value.second.update_string_value();
								std::cout
									<< "\t RepeatReplace (id=" << (i++)
									<< ", type=" << w32::get_sniff_type_str_for_type(type_to_locations.first)
									<< ", location=" << std::setw(16) << std::hex << std::get<2>(mem_location) << std::dec
									<< ", value_to_set=" << record_to_value.second.as_string() << ")" << std::endl;
							}
						}
					}
				}
			}
			else if (ctx.args.context_is(sniffer_cmd_e::context_remove)) {
				try {
					std::lock_guard<std::mutex> lock(ctx.state.replace_thread_mutex);
					const auto ids = getIndexRangeFromArgument(ctx.args.at("id", ctx.args.arg_at_index(2).c_str()));
					if (ids.is_good && ids.min_index < ctx.state.repeat_replace.size() && ids.max_index < ctx.state.repeat_replace.size()) {
						if (ids.is_multiple) {
							auto max_index = ids.max_index == ctx.state.repeat_replace.size() ? ids.max_index : ids.max_index + 1;
							ctx.state.repeat_replace.erase(ctx.state.repeat_replace.begin() + ids.min_index, ctx.state.repeat_replace.begin() + max_index);
						}
						else {
							ctx.state.repeat_replace.erase(ctx.state.repeat_replace.begin() + ids.min_index);
						}
					}
				}
				catch (...) {
					// NO OP
				}
			}
			else if (ctx.args.context_is(sniffer_cmd_e::repeat_clear)) {
				std::cout << "Clearing repeat replaces" << std::endl;
				std::lock_guard<std::mutex> lock(ctx.state.replace_thread_mutex);
				ctx.state.repeat_replace.clear();
			}
			else {
				/* TODO: Fix Repeat
				std::cout << "Setting repeat replaces" << std::endl;
				auto value_to_set = win_api::SniffValue(ctx.args.getContext());
				if (!value_to_set.asString().empty()) {
					if (ctx.args.count("id") > 0) {
						try {
							std::lock_guard<std::mutex> lock(replace_thread_mutex);
							const auto id = std::stoul(ctx.args.at("id"));
							if (id - 1 < sniffs->size()) {
								repeat_replace.push_back(std::make_pair(*sniffs, value_to_set));
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
				*/
			}

		}
		else if (ctx.args.action_is(sniffer_cmd_e::take) && !ctx.args.context().empty()) {
			try {
				/* TODO: Fix take
				const auto ids = getIndexRangeFromArgument(ctx.args.getContext());
				if (ids.is_good) {
					if (ids.is_multiple) {
						std::cout << "Taking sniff set in range " << ids.min_index << " to " << ids.max_index << std::endl;
						const auto max_index = ids.max_index >= sniffs->size() ? sniffs->size() : ids.max_index + 1;
						const auto new_sniffs = std::vector<win_api::SniffRecordSet>(sniffs->begin() + ids.min_index, sniffs->begin() + max_index);
						sniffs->erase(sniffs->begin() + ids.min_index, sniffs->begin() + max_index);
						sniffs_eliminated[current_sniff_context] = *sniffs;
						*sniffs = new_sniffs;

					}
					else {
						std::cout << "Taking sniff value at index " << ids.min_index << std::endl;
						const auto new_sniff = std::vector<win_api::SniffRecordSet>{ sniffs->at(ids.min_index) };
						sniffs->erase(sniffs->begin() + ids.min_index);
						sniffs_eliminated[current_sniff_context] = *sniffs;
						*sniffs = new_sniff;
					}
				}
				*/
			}
			catch (...) {
				/* NO OP */
			}
		}
	}

	void split_large_records(std::vector<w32::memory_region_record_t> & records) {
		std::vector<w32::memory_region_record_t> split_records;
		const auto SPLIT_SIZE = 1024 * 1024 * 100;
		for (auto it = records.begin(); it != records.end();) {
			if ((*it).RegionSize > SPLIT_SIZE) {
				const auto record_to_split = (*it);
				const auto max_mem_location_of_split = (uint64_t)record_to_split.BaseAddress + record_to_split.RegionSize;
				for (uint64_t i = (uint64_t)record_to_split.BaseAddress, max = (uint64_t)record_to_split.BaseAddress + record_to_split.RegionSize; i < max; i += SPLIT_SIZE) {
					auto cpy = w32::memory_region_record_t(record_to_split);
					cpy.BaseAddress = (w32::PVOID) i;
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
	}

	void create_sniff_work_units_for_context(sniffer_context_t & ctx) {
		ctx.mem.work_units.clear();
		for (auto & sniff_type_to_sniffs : ctx.state.sniffs->getLocations()) {
			for (const auto & mem_location : sniff_type_to_sniffs.second) {
				ctx.mem.work_units.emplace_back(std::get<1>(mem_location), std::get<2>(mem_location), sniff_type_to_sniffs.first);
			}
		}
	}

	void do_workload(sniffer_context_t & ctx) {
		const auto pids_to_consider = w32::get_all_pids_for_process_name(ctx.state.executable_to_consider_wstring);
		auto records = std::vector<w32::memory_region_record_t>();
		for (auto pid : pids_to_consider) {
			const auto records_for_pid = w32::get_all_memory_regions_for_pid(pid);
			records.insert(records.end(), records_for_pid.begin(), records_for_pid.end());
		}

		split_large_records(records);

		ctx.mem.update_mem_state(&ctx.args, ctx.state.sniffs, &records, ctx.state.num_threads, 1);
		if (ctx.args.action_is_one({ sniffer_cmd_e::set, sniffer_cmd_e::filter })) {
			create_sniff_work_units_for_context(ctx);
		}
		const auto actions = get_actions_for_ctx(ctx);
		profile_timer_t timer(ctx.state.profile, __FUNCTION__);
		for (const auto action : actions) {
			std::vector<std::thread> threads;
			for (uint32_t i = 0; i < ctx.state.num_threads; ++i) {
				threads.push_back(std::thread(action, i, &ctx.mem));
			}

			auto max_jobs = ctx.args.action_is(sniffer_cmd_e::find) ? records.size() : ctx.mem.work_units.size();

			while (ctx.mem.get_current_job_index() < max_jobs + 1) {
				std::cout << "\r\tStarting " << ctx.args.action() << " job " << ctx.mem.get_current_job_index() << " / " << max_jobs << " ... ";
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
			}
			std::cout << "\r\tStarting " << ctx.args.action() << " job " << max_jobs << " / " << max_jobs << " ... done" << std::endl;;

			std::cout << "\tWaiting for jobs to finish ...";
			while (!threads.empty()) {
				threads.back().join();
				threads.pop_back();
			}
			std::cout << " done" << std::endl;

			ctx.mem.reset_thread_work_state();
		}
	}

	void do_post_workload(sniffer_context_t & ctx) {
		profile_timer_t timer(ctx.state.profile, __FUNCTION__);
		if (ctx.args.action_is(sniffer_cmd_e::filter)) {
			filter_sniffs(ctx);
		}
	}

	void report_operation_side_effects(sniffer_context_t & ctx) {
		if (ctx.args.action_is(sniffer_cmd_e::set)) {
			std::cout << "Found and set " << ctx.state.sniffs->size() << " sniff records" << std::endl;
			dump_sniffs(ctx.state.sniffs);
		}
		else if (ctx.args.action_is(sniffer_cmd_e::find)) {
			std::cout << "Found " << ctx.state.sniffs->size() << " records: " << std::endl;
			dump_sniffs(ctx.state.sniffs);
		}
		else if (ctx.args.action_is(sniffer_cmd_e::filter)) {
			size_t filter_count = 0;
			for (const auto & thread_resniff : ctx.mem.thread_resniffs) {
				filter_count += thread_resniff.size();
			}
			std::cout << "Filtered " << filter_count << " records which ! " << ctx.args.at("pred", "eq") << " " << ctx.args.at("ctx_param", "the original value") << ". Remaining records: " << std::endl;
			dump_sniffs(ctx.state.sniffs);
		}
		else if (ctx.args.action_is(sniffer_cmd_e::list)) {
			std::cout << "Working with " << ctx.state.sniffs->size() << " sniffs:" << std::endl;
			try {
				const auto offset = std::stoul(ctx.args.context("0"));
				dump_sniffs(ctx.state.sniffs, offset);
			}
			catch (...) {
				dump_sniffs(ctx.state.sniffs);
			}
		}
	}

	bool init(int argc, char * argv[], sniffer_context_t & ctx) {
		ctx.args = get_arguments(argc, argv);

		if (ctx.args.empty()) {
			return false;
		}

		w32::set_debug_priv();

		return true;
	}

	bool setup_sniffer_state(sniffer_context_t & ctx) {
		ctx.state.replace_thread = std::thread(replace_thread_proc, &ctx);
		ctx.state.executable_to_consider = ctx.args.at("pname");
		ctx.state.executable_to_consider_wstring = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(ctx.state.executable_to_consider);
		ctx.state.sniff_file_name = ctx.args.at("st", (ctx.state.executable_to_consider + ".sniff").c_str());
		ctx.state.current_context = ctx.args.at("context", SNIFF_GLOBAL_CONTEXT);

		// Setup global and current contexts
		auto global_state = ctx.state.context_to_sniffs[SNIFF_GLOBAL_CONTEXT];
		auto currernt_context = ctx.state.context_to_sniffs[ctx.state.current_context];
		ctx.state.sniffs = &ctx.state.context_to_sniffs.at(ctx.state.current_context);
		ctx.state.is_interactive = ctx.args.action() == "interactive";
		ctx.state.num_threads = std::stoul(ctx.args.at("j", w32::get_num_system_cores()));
		ctx.state.profile = !ctx.args.at("profile").empty();

#ifdef _DEBUG
		ctx.state.profile = true;
#endif // _DEBUG

		return true;
	}

	void cleanup_sniffer_state(sniffer_context_t & ctx) {
		ctx.state.replace_thread_is_running = false;
		ctx.state.replace_thread.join();
		w32::clear_open_handles(w32::get_all_pids_for_process_name(ctx.state.executable_to_consider_wstring));
	}
}
