#include "pch.h"
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

	bool do_mem_replace(uint64_t pid, uint64_t mem_location, w32::sniff_type_e type, w32::sniff_value_t & value_to_set) {
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

		indicies_t indexs;
		for (sm->get_next_job(indexs); indexs.start_index < sm->work_units.size(); sm->get_next_job(indexs)) {
			auto & work_unit = sm->work_units.at(indexs.start_index);
			do_mem_replace(work_unit.pid, work_unit.mem_location, work_unit.type, value_to_set);
		}
	}

	bool inline type_is_type(uint32_t a, w32::sniff_type_e b) {
		return a == (a | (uint32_t)b);
	}

	bool inline type_is_type_or_none(uint32_t a, w32::sniff_type_e b) {
		return type_is_type(a, b) || a == 0;
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

		return std::move(first_bytes);
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
		const auto value_string_to_find = sm->args->context().empty() ? sm->args->arg_at_index(1) : sm->args->context();
		auto value_to_find = w32::sniff_value_t(value_string_to_find.c_str());
		auto first_bytes = getFirstBytes(value_to_find);
		bool match = false;
		std::vector<w32::sniff_type_e> type_matches;
		uint8_t bound_bytes[8] = { 0 };
		uint8_t * non_str_bytes;
		auto min_num_int_bytes = value_to_find.min_num_int_bytes();
		auto mem_region_copy = w32::memory_region_copy_t();
		indicies_t indexs;
		for (sm->get_next_job(indexs); indexs.start_index < sm->records->size(); sm->get_next_job(indexs)) {
			const auto & region_record = sm->records->at(indexs.start_index);
			mem_region_copy.reset(
				region_record.AssociatedPid,
				region_record.BaseAddress,
				region_record.RegionSize,
				region_record.is_split_record && !region_record.is_end_record,
				max(value_to_find.as_string().size() + 1, 8)
			);
			uint64_t num_zeros = 8;
			for (uint64_t i = 0; mem_region_copy.is_good() && i < mem_region_copy.size(); find_next_sniff_loc(i, mem_region_copy, num_zeros)) {
				match = false;
				type_matches.clear();

				uint64_t location = (uint64_t)(region_record.BaseAddress) + i;

				if (first_bytes.count(mem_region_copy[i]) == 0) {
					continue;
				}

				if (mem_region_copy.index_lies_on_boundary(i)) {
					for (auto j = 0; j < 8 && i + j < mem_region_copy.size(); ++j) {
						bound_bytes[j] = mem_region_copy[i + j];
					}
					non_str_bytes = bound_bytes;
				}
				else {
					non_str_bytes = &mem_region_copy[i];
				}

				if (type_is_type(find_type_pred, w32::sniff_type_e::str)) {
					bool is_allowed_to_go_past_bounds = region_record.is_split_record && !region_record.is_end_record;
					if (is_allowed_to_go_past_bounds || i + value_to_find.as_string().size() < mem_region_copy.size()) {
						for (uint64_t j = 0; j < value_to_find.as_string().size(); ++j) {
							match = mem_region_copy[i + j] == value_to_find.as_string().at(j);

							if (!match) {
								break;
							}
						}

						if (match) {
							sm->thread_sniffs.at(id).emplace_back(w32::sniff_type_e::str, region_record.AssociatedPid, location);
						}
					}
				}

				if (min_num_int_bytes <= 1 && value_to_find.uint_good() && type_is_type(find_type_pred, w32::sniff_type_e::u8)) {
					match = sniff_cmp_i(find_pred_str, *non_str_bytes, value_to_find.as_uint<uint8_t>());

					if (match) {
						sm->thread_sniffs.at(id).emplace_back(w32::sniff_type_e::u8, region_record.AssociatedPid, location);
					}
				}

				if (min_num_int_bytes <= 4 && value_to_find.uint_good() && type_is_type_or_none(find_type_pred, w32::sniff_type_e::u32)) {
					uint32_t val = *(uint32_t *)non_str_bytes;
					match = sniff_cmp_i(find_pred_str, val, value_to_find.as_uint<uint32_t>());

					if (match) {
						sm->thread_sniffs.at(id).emplace_back(w32::sniff_type_e::u32, region_record.AssociatedPid, location);
					}
				}

				if (min_num_int_bytes <= 8 && value_to_find.uint_good() && type_is_type_or_none(find_type_pred, w32::sniff_type_e::u64)) {
					uint64_t val = *(uint64_t *)non_str_bytes;
					match = sniff_cmp_i(find_pred_str, val, value_to_find.as_uint<uint64_t>());

					if (match) {
						sm->thread_sniffs.at(id).emplace_back(w32::sniff_type_e::u64, region_record.AssociatedPid, location);
					}
				}

				if (min_num_int_bytes <= 1 && value_to_find.int_good() && type_is_type(find_type_pred, w32::sniff_type_e::i8)) {
					int8_t val = *(int8_t *)non_str_bytes;
					match = sniff_cmp_i(find_pred_str, val, value_to_find.as_int<int8_t>());

					if (match) {
						sm->thread_sniffs.at(id).emplace_back(w32::sniff_type_e::i8, region_record.AssociatedPid, location);
					}
				}

				if (min_num_int_bytes <= 4 && value_to_find.int_good() && type_is_type_or_none(find_type_pred, w32::sniff_type_e::i32)) {
					int32_t val = *(int32_t *)non_str_bytes;
					match = sniff_cmp_i(find_pred_str, val, value_to_find.as_int<int32_t>());

					if (match) {
						sm->thread_sniffs.at(id).emplace_back(w32::sniff_type_e::i32, region_record.AssociatedPid, location);
					}
				}

				if (min_num_int_bytes <= 8 && value_to_find.int_good() && type_is_type_or_none(find_type_pred, w32::sniff_type_e::i64)) {
					int64_t val = *(int64_t *)non_str_bytes;
					match = sniff_cmp_i(find_pred_str, val, value_to_find.as_int<int64_t>());

					if (match) {
						sm->thread_sniffs.at(id).emplace_back(w32::sniff_type_e::i64, region_record.AssociatedPid, location);
					}
				}

				if (value_to_find.float_good() && type_is_type_or_none(find_type_pred, w32::sniff_type_e::f32)) {
					float_t val = *(float_t *)non_str_bytes;
					match = sniff_cmp_f(find_pred_str, val, value_to_find.as_float<float_t>());

					if (match) {
						sm->thread_sniffs.at(id).emplace_back(w32::sniff_type_e::f32, region_record.AssociatedPid, location);
					}
				}

				if (value_to_find.float_good() && type_is_type_or_none(find_type_pred, w32::sniff_type_e::f64)) {
					double_t val = *(double_t *)non_str_bytes;
					match = sniff_cmp_f(find_pred_str, val, value_to_find.as_float<double_t>());

					if (match) {
						sm->thread_sniffs.at(id).emplace_back(w32::sniff_type_e::f64, region_record.AssociatedPid, location);
					}
				}
			}
		}
	}

	void do_filter(int id, shared_memory_t * sm) {
		auto filter_pred_str = sm->args->at("pred", "ne");
		auto filter_type_pred_str = sm->args->at("type");
		auto filter_type_pred = w32::get_sniff_type_for_str(filter_type_pred_str);
		auto filter_value_pred_str = sm->args->context(sm->sniff_record->value.as_string());
		auto filter_value_pred = w32::sniff_value_t(filter_value_pred_str.c_str());
		auto mem_region_copy = w32::memory_region_copy_t();
		indicies_t indexs;
		for (sm->get_next_job(indexs); indexs.start_index < sm->work_units.size(); sm->get_next_job(indexs)) {
			for (uint64_t i = indexs.start_index; i < indexs.end_index && i < sm->work_units.size(); ++i) {
				auto & work_unit = sm->work_units.at(i);
				bool match = false;

				mem_region_copy.reset(
					(w32::DWORD)work_unit.pid,
					(w32::LPVOID)work_unit.mem_location,
					work_unit.type == w32::sniff_type_e::str ? sm->sniff_record->value.as_string().size() : 8,
					false,
					0
				);
				if (filter_type_pred != 0) {
					if (((uint32_t)work_unit.type & filter_type_pred) == 0) {
						sm->thread_resniffs[id].insert(std::make_tuple(work_unit.type, work_unit.pid, work_unit.mem_location));
						continue;
					}
				}

				if (work_unit.type == w32::sniff_type_e::str) {
					for (uint64_t j = 0; j < filter_value_pred.as_string().size(); ++j) {
						match = sniff_cmp_i(filter_pred_str, filter_value_pred.as_string().at(j), mem_region_copy[j]);

						if (!match) break;
					}
				}
				else if (work_unit.type == w32::sniff_type_e::i8) {
					int8_t val = *(int8_t *)&mem_region_copy[0];

					match = sniff_cmp_i(filter_pred_str, filter_value_pred.as_int<int8_t>(), val);
				}
				else if (work_unit.type == w32::sniff_type_e::i32) {
					int32_t val = *(int32_t *)&mem_region_copy[0];

					match = sniff_cmp_i(filter_pred_str, filter_value_pred.as_int<int32_t>(), val);
				}
				else if (work_unit.type == w32::sniff_type_e::i64) {
					int64_t val = *(int64_t *)&mem_region_copy[0];

					match = sniff_cmp_i(filter_pred_str, filter_value_pred.as_int<int64_t>(), val);
				}
				else if (work_unit.type == w32::sniff_type_e::u8) {
					uint8_t val = *(uint8_t *)&mem_region_copy[0];

					match = sniff_cmp_i(filter_pred_str, filter_value_pred.as_uint<uint8_t>(), val);
				}
				else if (work_unit.type == w32::sniff_type_e::u32) {
					uint32_t val = *(uint32_t *)&mem_region_copy[0];

					match = sniff_cmp_i(filter_pred_str, filter_value_pred.as_uint<uint32_t>(), val);
				}
				else if (work_unit.type == w32::sniff_type_e::u64) {
					uint64_t val = *(uint64_t *)&mem_region_copy[0];

					match = sniff_cmp_i(filter_pred_str, filter_value_pred.as_uint<uint64_t>(), val);
				}
				else if (work_unit.type == w32::sniff_type_e::f32) {
					float_t val = *(float_t *)&mem_region_copy[0];

					match = sniff_cmp_f(filter_pred_str, filter_value_pred.as_float<float_t>(), val);
				}
				else if (work_unit.type == w32::sniff_type_e::f64) {
					double_t val = *(double_t *)&mem_region_copy[0];

					match = sniff_cmp_f(filter_pred_str, filter_value_pred.as_float<double_t>(), val);
				}

				if (match) {
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
				ctx.out_stream << "Expected token after find (ie: 'find 450') to be provided when doing a find operation" << std::endl;
				result.clear();
				return result;
			}

			result.push_back(do_find);
		}
		else if (ctx.args.action_is(sniffer_cmd_e::set)) {
			if (ctx.args.context().empty()) {
				ctx.out_stream << "Expected token after set (ie: set 1337) to be provided when using action set" << std::endl;
				result.clear();
				return result;
			}

			if (ctx.state.sniffs->empty()) {
				ctx.out_stream << "Have no sniffs to set - run 'find' to find some memory locations" << std::endl;
				result.clear();
				return result;
			}

			result.push_back(do_set);
		}
		else if (ctx.args.action_is(sniffer_cmd_e::filter)) {
			if (ctx.state.sniffs->empty()) {
				ctx.out_stream << "Expected to find cached sniffs when using action filter - run 'find' to get records" << std::endl;
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

		uint64_t i = 0;
		std::set<uint64_t> sniffs_to_remove;
		for (const auto & type_to_locations : ctx.state.sniffs->get_locations()) {
			for (const auto & sniff : type_to_locations.second) {
				if (sniffs_to_exclude.count(sniff) == 1) {
					sniffs_to_remove.insert(i);
				}
				i++;
			}
		}

		ctx.state.sniffs->remove(sniffs_to_remove);
		ctx.state.in_process_scratch_pad["num_sniffs_removed"] = std::to_string(sniffs_to_exclude.size());

		return result;
	}

	void dump_sniffs(sniffer_context_t & ctx, uint32_t offset = 0, const char * header_prefix = "") {
		uint32_t i = 0;
		bool has_offset_output = false;
		auto mem_region_copy = w32::memory_region_copy_t();
		if (!ctx.state.sniffs->empty()) {
			std::stringstream preamble;
			preamble << header_prefix << " " << ctx.state.sniffs->size() << " records";
			for (auto & type_to_location : ctx.state.sniffs->get_locations()) {
				if (!type_to_location.second.empty()) {
					preamble << " " << w32::get_sniff_type_str_for_type(type_to_location.first) << "=" << type_to_location.second.size();
				}
			}
			ctx.out_stream << preamble.str() << std::endl;
			preamble.str("");
			for (auto & type_to_location : ctx.state.sniffs->get_locations()) {
				for (const auto mem_location : type_to_location.second) {

					if (i++ < offset) {
						has_offset_output = true;
						continue;
					}
					else if (has_offset_output) {
						ctx.out_stream << "\t ... [" << (i - 1) << " previous records] ..." << std::endl;
						has_offset_output = false;
					}

					const auto size = std::get<0>(mem_location) == w32::sniff_type_e::str ? ctx.state.sniffs->value.as_string().size() : 8;
					mem_region_copy.reset(
						(w32::DWORD)std::get<1>(mem_location),
						(w32::LPVOID)std::get<2>(mem_location),
						size,
						false,
						0
					);
					ctx.out_stream << "\tSniffRecord (id=" << i - 1 << ", pid=" << std::get<1>(mem_location) << ", location=";
					ctx.out_stream << "0x" << std::setw(16) << std::setfill('0') << std::hex << std::get<2>(mem_location) << std::dec;
					ctx.out_stream << ", type=" << w32::get_sniff_type_str_for_type(type_to_location.first) << ", value=" << data_to_string(type_to_location.first, &mem_region_copy[0], size);
					ctx.out_stream << ")" << std::endl;

					if (i - offset == 20) {
						break;
					}
				}

				if (i - offset == 20) {
					if ((ctx.state.sniffs->size() - i) != 0) {
						ctx.out_stream << "\t ... [" << ctx.state.sniffs->size() - i << " more records] ..." << std::endl;
					}
					break;
				}

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
			args["___ctx_param"] = words[1];
		}

		for (size_t i = 2; (i + 1) < words.size(); i += 2) {
			args[words[i]] = words[i + 1];
		}

		return sniffer_args_t(args, words);
	}

	sniffer_args_t update_args_for_interactive_mode(sniffer_context_t & ctx, std::string & input) {
		// TODO: Make this help output generated from sniffer_cmds
		if (input.empty() || input == "help" || input == "?") {
			ctx.out_stream << "\tSniff memory for attached process and populate sniff records:" << std::endl;
			ctx.out_stream << "\t\t<load> \"EXEC_NAME\"" << std::endl;
			ctx.out_stream << "\t\t<find, f> \"VALUE\" <type <i8|u8|i32|u32|i64|u64|f32|f64|str>> <pred <gt|lt|eq|ne>>" << std::endl;
			ctx.out_stream << "\t\t<list, ls>" << std::endl;
			ctx.out_stream << "\tModify existing sniff records:" << std::endl;
			ctx.out_stream << "\t\t<filter> \"VALUE\" <type <i8|u8|i32|u32|i64|u64|f32|f64|str>> <pred <gt|lt|eq|ne>>" << std::endl;
			ctx.out_stream << "\t\t<pick> <index|range>" << std::endl;
			ctx.out_stream << "\t\t<remove, rm> <id|range>" << std::endl;
			ctx.out_stream << "\t\t<undo>" << std::endl;
			ctx.out_stream << "\t\t<profile>" << std::endl;
			ctx.out_stream << "\tReplace all values in memory:" << std::endl;
			ctx.out_stream << "\t\t<set> \"VALUE\"" << std::endl;
			ctx.out_stream << "\tReplace values in memory continuously:" << std::endl;
			ctx.out_stream << "\t\t<repeat> \"VALUE\" <<id|range>>" << std::endl;
			ctx.out_stream << "\t\t<repeat> <list, ls>" << std::endl;
			ctx.out_stream << "\t\t<repeat> <remove, rm> <id|range>" << std::endl;
			ctx.out_stream << "\t\t<repeat> <clear>" << std::endl;
			ctx.out_stream << "\tContexts to allow multiple sniff sessions at once:" << std::endl;
			ctx.out_stream << "\t\t<context, ctx> \"NEW_CONTEXT\"" << std::endl;
			ctx.out_stream << "\t\t<context, ctx> <list, ls>" << std::endl;
			ctx.out_stream << "\t\t<context, ctx> <remove, rm> \"CONTEXT_NAME\"" << std::endl;
			ctx.out_stream << "\t\t<context, ctx> <clone> \"NEW_CONTEXT\"" << std::endl;
			ctx.out_stream << "\tSniff file load/save:" << std::endl;
			ctx.out_stream << "\t\t<sniff> <load>" << std::endl;
			ctx.out_stream << "\t\t<sniff> <save>" << std::endl;
			ctx.out_stream << "\tExit sniffer:" << std::endl;
			ctx.out_stream << "\t\t<quit, exit, q>" << std::endl;
			ctx.out_stream << "\tDisplay help info:" << std::endl;
			ctx.out_stream << "\t\t<threads, j> # set num threads" << std::endl;
			ctx.out_stream << "\t\t<info>" << std::endl;
			ctx.out_stream << "\t\t<?, help>" << std::endl;
		}

		return parse_arg_string_into_args_map(input);
	}


	void replace_thread_proc(sniffer_context_t * ctx) {
		while (ctx->state.replace_thread_is_running) {
			{
				std::lock_guard<std::mutex> lock_guard(ctx->state.replace_thread_mutex);
				for (auto & replace_record : ctx->state.repeat_replace) {
					do_mem_replace(replace_record.pid, replace_record.location, replace_record.type, replace_record.value);
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

	index_range_t get_index_range_from_argument(const std::string & arg) {
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

	void split_large_records(std::vector<w32::memory_region_record_t> & records, uint64_t split_size) {
		std::vector<w32::memory_region_record_t> split_records;
		for (auto it = records.begin(); it != records.end();) {
			if ((*it).RegionSize > split_size) {
				const auto record_to_split = (*it);
				const auto max_mem_location_of_split = (uint64_t)record_to_split.BaseAddress + record_to_split.RegionSize;
				for (uint64_t i = (uint64_t)record_to_split.BaseAddress, max = (uint64_t)record_to_split.BaseAddress + record_to_split.RegionSize; i < max; i += split_size) {
					auto cpy = w32::memory_region_record_t(record_to_split);
					cpy.BaseAddress = (w32::PVOID) i;
					cpy.RegionSize = (i + split_size) > max ? max - i : split_size;
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

	// Returns false when we should end interactive execution
	bool update_interactive_args(sniffer_context_t & ctx) {

		if (ctx.state.sniffs->empty()) {
			ctx.out_stream << ctx.state.current_context << "> ";
		}
		else {
			ctx.out_stream << ctx.state.current_context << "(" << ctx.state.sniffs->size() << ")> ";
		}
		std::string line;
		std::getline(std::cin, line);

		trim(line);

		ctx.args = update_args_for_interactive_mode(ctx, line);

		return !ctx.args.action_is(sniffer_cmd_e::quit);
	}

	bool update_interactive_args_with_input(sniffer_context_t & ctx, std::string input) {
		ctx.args = update_args_for_interactive_mode(ctx, input);

		return !ctx.args.action_is(sniffer_cmd_e::quit);
	}

	void create_sniff_work_units_for_context(sniffer_context_t & ctx) {
		ctx.mem.work_units.clear();
		for (auto & sniff_type_to_sniffs : ctx.state.sniffs->get_locations()) {
			for (const auto & mem_location : sniff_type_to_sniffs.second) {
				ctx.mem.work_units.emplace_back(std::get<1>(mem_location), std::get<2>(mem_location), sniff_type_to_sniffs.first);
			}
		}
	}

	void do_pre_workload(sniffer_context_t & ctx) {
		profile_timer_t timer(ctx.state.profile, __FUNCTION__);

		// Save sniff state if needed
		if (ctx.args.action_is_one({ sniffer_cmd_e::find, sniffer_cmd_e::filter, sniffer_cmd_e::remove, sniffer_cmd_e::pick })) {
			ctx.state.sniffs->commit();
		}

		// Configure memory regions to work from
		const auto pids_to_consider = w32::get_all_pids_for_process_name(ctx.state.executable_to_consider_wstring);
		ctx.state.memory_records.clear();
		for (auto pid : pids_to_consider) {
			const auto records_for_pid = w32::get_all_memory_regions_for_pid(pid);
			ctx.state.memory_records.insert(
				ctx.state.memory_records.end(),
				records_for_pid.begin(),
				records_for_pid.end());
		}

		split_large_records(ctx.state.memory_records);

		if (ctx.args.action_is_one({ sniffer_cmd_e::set, sniffer_cmd_e::filter })) {
			create_sniff_work_units_for_context(ctx);
		}

		if (ctx.state.memory_records.empty()) {
			ctx.out_stream << "Could not acquire memory regions for process \"" << ctx.state.executable_to_consider << "\"- is it still running?" << std::endl;
		}

		if (ctx.args.action_is(sniffer_cmd_e::undo)) {
			if (ctx.state.sniffs->revert()) {
				ctx.out_stream << "Reverted to previous sniff state " << std::endl;
			}
			else {
				ctx.out_stream << "No previous state to undo" << std::endl;
			}
		}
		else if (ctx.args.action_is(sniffer_cmd_e::clear) && !ctx.state.sniffs->empty()) {
			ctx.out_stream << "Clearing all " << ctx.state.sniffs->size() << " sniff records" << std::endl;
			ctx.state.sniffs->clear();
		}
		else if (ctx.args.action_is(sniffer_cmd_e::context)) {
			if (ctx.args.context_is(sniffer_cmd_e::context_list) || ctx.args.size() == 1) {
				ctx.out_stream << "Registered Contexts:" << std::endl;
				for (const auto & context_to_sniffs : ctx.state.context_to_sniffs) {
					if (context_to_sniffs.first == ctx.state.current_context) {
						ctx.out_stream << "\t" << context_to_sniffs.first << "(" << context_to_sniffs.second.size() << ") [current]" << std::endl;
					}
					else {
						ctx.out_stream << "\t" << context_to_sniffs.first << "(" << context_to_sniffs.second.size() << ")" << std::endl;
					}
				}
			}
			else if (ctx.args.context_is(sniffer_cmd_e::context_remove)) {
				const auto context_to_remove = ctx.args.at("id", ctx.args.arg_at_index(2).c_str());
				if (ctx.state.context_to_sniffs.count(context_to_remove) == 0) {
					ctx.out_stream << "Context " << ctx.args.at("remove") << " cannot be removed because it does not exist" << std::endl;
				}
				else if (context_to_remove == SNIFF_GLOBAL_CONTEXT) {
					ctx.out_stream << "Cannot delete global context" << std::endl;
				}
				else {
					ctx.out_stream << "Removing sniff context " << context_to_remove << std::endl;
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
					ctx.out_stream << "Cannot clone to new context " << context_to_clone_into << " as it already exists" << std::endl;
				}
				else {
					ctx.out_stream << "Cloning current context to new context " << context_to_clone_into << std::endl;
					ctx.state.context_to_sniffs[context_to_clone_into] = ctx.state.context_to_sniffs.at(ctx.state.current_context);
					ctx.state.current_context = context_to_clone_into;
					ctx.state.sniffs = &ctx.state.context_to_sniffs.at(ctx.state.current_context);
				}
			}
			else {
				const auto new_context = ctx.args.context();
				ctx.out_stream << "Switching context to " << new_context << std::endl;
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

			ctx.out_stream << "Searching attached process for " << token_to_search_for << " ..." << std::endl;
			ctx.state.sniffs->value.set_value(token_to_search_for);
		}
		else if (ctx.args.action_is(sniffer_cmd_e::remove)) {
			try {
				const auto ids = get_index_range_from_argument(ctx.args.context());
				if (ids.is_good) {
					if (ids.is_multiple) {
						ctx.out_stream << "\tErasing records " << ids.min_index << ":" << (ids.max_index >= ctx.state.sniffs->size() ? ctx.state.sniffs->size() : ids.max_index) << std::endl;
					}
					else {
						ctx.out_stream << "\tErasing record " << ids.min_index << std::endl;
					}
					indicies_t indicies;
					indicies.start_index = ids.min_index;
					indicies.end_index = ids.max_index;
					ctx.state.sniffs->remove(indicies);
				}
				else {
					ctx.out_stream << "Could not erase indexs that do not exist" << std::endl;
				}
			}
			catch (...) {
				// NO OP
			}
		}
		else if (ctx.args.action_is(sniffer_cmd_e::profile)) {
			ctx.out_stream << "Turning " << (ctx.state.profile ? "off" : "on") << " profile output" << std::endl;
			ctx.state.profile = !ctx.state.profile;
		}
		else if (ctx.args.action_is(sniffer_cmd_e::repeat)) {
			if (ctx.args.context_is(sniffer_cmd_e::repeat_list) || ctx.args.size() == 1) {
				ctx.out_stream << "Current replace repeats" << std::endl;
				{
					std::lock_guard<std::mutex> lock(ctx.state.replace_thread_mutex);
					size_t i = 0;
					for (auto & repeat_record : ctx.state.repeat_replace) {
						ctx.out_stream
							<< "\t RepeatReplace (id=" << (i++)
							<< ", type=" << w32::get_sniff_type_str_for_type(repeat_record.type)
							<< ", pid=" << std::setw(16) << repeat_record.pid
							<< ", location=" << std::setw(16) << std::hex << repeat_record.location << std::dec
							<< ", value_to_set=" << repeat_record.value.as_string() << ")" << std::endl;
					}
				}
			}
			else if (ctx.args.context_is(sniffer_cmd_e::context_remove)) {
				try {
					std::lock_guard<std::mutex> lock(ctx.state.replace_thread_mutex);
					const auto ids = get_index_range_from_argument(ctx.args.at("id", ctx.args.arg_at_index(2).c_str()));
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
				ctx.out_stream << "Clearing repeat replaces" << std::endl;
				std::lock_guard<std::mutex> lock(ctx.state.replace_thread_mutex);
				ctx.state.repeat_replace.clear();
			}
			else {
				ctx.out_stream << "Setting repeat replaces" << std::endl;
				auto value_to_set = w32::sniff_value_t(ctx.args.context());
				if (!value_to_set.as_string().empty()) {
					if (ctx.args.count("id") > 0) {
						try {
							std::lock_guard<std::mutex> lock(ctx.state.replace_thread_mutex);
							const auto id = std::stoul(ctx.args.at("id"));
							const auto sniff = ctx.state.sniffs->sniff_for_index(id);
							if (std::get<0>(sniff) != w32::sniff_type_e::unknown) {
								repeat_record_t record;
								record.type = std::get<0>(sniff);
								record.pid = std::get<1>(sniff);
								record.location = std::get<2>(sniff);
								record.value = value_to_set;
								ctx.state.repeat_replace.push_back(record);
							}
						}
						catch (...) {
							// NO OP
						}

					}
					else {
						std::lock_guard<std::mutex> lock(ctx.state.replace_thread_mutex);
						for (const auto & type_to_locations : ctx.state.sniffs->get_locations()) {
							for (const auto & sniff : type_to_locations.second) {
								repeat_record_t record;
								record.type = type_to_locations.first;
								record.pid = std::get<1>(sniff);
								record.location = std::get<2>(sniff);
								record.value = value_to_set;
								ctx.state.repeat_replace.push_back(record);
							}
						}
					}
				}
			}

		}
		else if (ctx.args.action_is(sniffer_cmd_e::pick) && !ctx.args.context().empty()) {
			try {
				const auto ids = get_index_range_from_argument(ctx.args.context());
				if (ids.is_good) {
					if (ids.is_multiple) {
						ctx.out_stream << "Picking sniff set in range " << ids.min_index << " to " << ids.max_index << std::endl;
					}
					else {
						ctx.out_stream << "Picking sniff value at index " << ids.min_index << std::endl;
					}

					indicies_t indicies;
					indicies.start_index = ids.min_index;
					indicies.end_index = ids.max_index;
					ctx.state.sniffs->remove(indicies, false);
				}
			}
			catch (...) {
				/* NO OP */
			}
		}
		else if (ctx.args.action_is(sniffer_cmd_e::filter)) {
			if (ctx.args.context_is_one({ "type", "pred" })) {
				// Special case for `filter` where the value is ommited but we have type/pred arguments provided. 
				// In this case ignore the current context and use the existing values
				ctx.args.set_context(ctx.state.sniffs->value.as_string());
				for (auto it = ctx.args.get_args().begin(); it != ctx.args.get_args().end(); ++it) {
					if (*it == "type") {
						ctx.args.set_arg("type", *(++it));
					}

					if (*it == "pred") {
						ctx.args.set_arg("pred", *(++it));
					}
				}
			}
			else if (ctx.args.context().empty()) {
				ctx.args.set_context(ctx.state.sniffs->value.as_string());
			}
		}
		else if (ctx.args.action_is(sniffer_cmd_e::set_num_threads)) {
			try {
				auto num_threads = min(1, std::stol(ctx.args.context()));
				ctx.state.num_threads = num_threads;
			}
			catch (...) {
				// NO-OP
			}
		}
		else if (ctx.args.action_is(sniffer_cmd_e::set_active_process) && !ctx.args.context().empty()) {
			auto new_exec_name = ctx.args.context();
			auto new_exec_name_wstring = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(new_exec_name);
			auto test_pid_check = w32::get_all_pids_for_process_name(new_exec_name_wstring);

			if (!test_pid_check.empty()) {
				ctx.state.executable_to_consider = std::move(new_exec_name);
				ctx.state.executable_to_consider_wstring = std::move(new_exec_name_wstring);
			}
			else {
				ctx.out_stream << "Failed to set new executable \"" << new_exec_name << "\" as there are no active PIDs under this - is the name correct and are you running as admin?" << std::endl;
			}
		}
	}

	void do_workload(sniffer_context_t & ctx) {
		ctx.mem.update_mem_state(&ctx.args, ctx.state.sniffs, &ctx.state.memory_records, ctx.state.num_threads, 1);
		profile_timer_t timer(ctx.state.profile, __FUNCTION__);
		for (const auto action : get_actions_for_ctx(ctx)) {
			std::vector<std::thread> threads;
			for (uint32_t i = 0; i < ctx.state.num_threads; ++i) {
				threads.push_back(std::thread(action, i, &ctx.mem));
			}

			auto max_jobs = ctx.args.action_is(sniffer_cmd_e::find) ? ctx.state.memory_records.size() : ctx.mem.work_units.size();

			while (ctx.mem.get_current_job_index() < max_jobs + 1) {
				ctx.out_stream << "\r\tStarting " << ctx.args.action() << " job " << ctx.mem.get_current_job_index() << " / " << max_jobs << " ... ";
				std::this_thread::sleep_for(std::chrono::milliseconds(250));
			}
			ctx.out_stream << "\r\tStarting " << ctx.args.action() << " job " << max_jobs << " / " << max_jobs << " ... done" << std::endl;;

			ctx.out_stream << "\tWaiting for jobs to finish ...";
			while (!threads.empty()) {
				threads.back().join();
				threads.pop_back();
			}
			ctx.out_stream << " done" << std::endl;

			ctx.mem.reset_thread_work_state();
		}
	}

	void do_post_workload(sniffer_context_t & ctx) {
		profile_timer_t timer(ctx.state.profile, __FUNCTION__);
		if (ctx.args.action_is(sniffer_cmd_e::find)) {
			for (auto & sniffs : ctx.mem.thread_sniffs) {
				for (const auto & sniff : sniffs) {
					ctx.state.sniffs->set_location_unsafe(sniff);
				}
			}
			ctx.mem.thread_sniffs.clear();
		}
		else if (ctx.args.action_is(sniffer_cmd_e::filter)) {
			filter_sniffs(ctx);
			ctx.mem.thread_resniffs.clear();
		}
	}

	void report_operation_side_effects(sniffer_context_t & ctx) {
		profile_timer_t timer(ctx.state.profile, __FUNCTION__);
		if (ctx.args.action_is(sniffer_cmd_e::set)) {
			dump_sniffs(ctx, 0, "Set");
		}
		else if (ctx.args.action_is(sniffer_cmd_e::find)) {
			dump_sniffs(ctx, 0, "Found");
		}
		else if (ctx.args.action_is(sniffer_cmd_e::filter)) {
			std::stringstream prefix;
			prefix << "Filtered " << ctx.state.in_process_scratch_pad["num_sniffs_removed"] << " records " << ctx.args.at("pred", "ne") << " " << ctx.args.context("the original value");
			if (!ctx.args.get_arg("type").empty()) {
				prefix << " and not type " << ctx.args.get_arg("type");
			}
			prefix << "\nRemaining";
			dump_sniffs(ctx, 0, prefix.str().c_str());
		}
		else if (ctx.args.action_is(sniffer_cmd_e::list)) {
			try {
				const auto offset = std::stoul(ctx.args.context("0"));
				dump_sniffs(ctx, offset, "List");
			}
			catch (...) {
				/* NO OP */
			}
		}
		else if (ctx.args.action_is(sniffer_cmd_e::set_num_threads)) {
			ctx.out_stream << "Set number of job threads to " << ctx.state.num_threads << std::endl;
		}
		else if (ctx.args.action_is(sniffer_cmd_e::set_active_process)) {
			if (!ctx.args.context().empty()) {
				ctx.out_stream << "Set new executable to sniff \"" << ctx.state.executable_to_consider << "\"" << std::endl;
			}
			else {

			}
		}
		else if (ctx.args.action_is(sniffer_cmd_e::info)) {
			const auto pids_for_executable = w32::get_all_pids_for_process_name(ctx.state.executable_to_consider_wstring);
			uint64_t total_bytes = 0;
			for (const auto & pid : pids_for_executable) {
				for (const auto & mem_region : w32::get_all_memory_regions_for_pid(pid)) {
					total_bytes += mem_region.RegionSize;
				}
			}
			ctx.out_stream << "Working on executable name \"" << ctx.state.executable_to_consider << "\"" << std::endl;
			ctx.out_stream << "Number of active PIDs for executable " << pids_for_executable.size();
			for (const auto & pid : pids_for_executable) {
				ctx.out_stream << ' ' << pid;
			}
			ctx.out_stream << std::endl;
			ctx.out_stream << "Total bytes for all active pids MB" << total_bytes / 1000000.0 << std::endl;
			ctx.out_stream << "Number of threads to use for jobs " << ctx.state.num_threads << std::endl;
		}
	}

	bool init(int argc, char * argv[], sniffer_context_t & ctx) {
		w32::set_debug_priv();

		ctx.args = get_arguments(argc, argv);

		if (ctx.args.empty()) {
			return false;
		}

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
		ctx.state.num_threads = max(1, std::stoul(ctx.args.at("j", w32::get_num_system_cores())));
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
