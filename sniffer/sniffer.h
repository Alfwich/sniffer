#pragma once
#pragma once

#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_map>

#include "w32_api.h"

#include "sniffer_cmds.h"

namespace {
	const char * default_str = "";
}

namespace sniffer {

	class sniffer_work_unit_t {
	public:
		sniffer_work_unit_t(size_t pid, uint64_t mem_location, w32::sniff_type_e type) : pid(pid), mem_location(mem_location), type(type) {}
		const size_t pid;
		const uint64_t mem_location;
		const w32::sniff_type_e type;
	};

	class sniffer_args_t {
		std::unordered_map<std::string, std::string> arg_map;
		std::vector<std::string> arg_words;
	public:
		sniffer_args_t() {}
		sniffer_args_t(const std::unordered_map<std::string, std::string> & in_args) : arg_map(in_args) {}
		sniffer_args_t(const std::unordered_map<std::string, std::string> & in_args, const std::vector<std::string> & in_words) : arg_map(in_args), arg_words(in_words) {}
		bool checkArgs() {
			static std::unordered_map <std::string, std::vector<std::string> > required = {
				{ "action", { "sniff", "replace", "resniff", "update", "interactive", "list" } },
				{ "pname", { "*" } },
			};

			for (const auto & required_pair : required) {
				const auto & key = required_pair.first;
				const auto & value_array = required_pair.second;

				bool has_match = false;
				for (const auto & test_value : value_array) {
					has_match = test_value == "*" || has_match || (arg_map.count(key) > 0 && arg_map.at(key) == test_value);
				}

				if (!has_match) {
					return false;
				}
			}

			return true;
		}

		void update_arg_map_and_arg_words(std::unordered_map<std::string, std::string> & new_arg_map, std::vector<std::string> & new_arg_words) {
			arg_map = new_arg_map;
			arg_words = new_arg_words;
		}

		std::string get_arg(const char * key, const std::string & def = default_str) const {
			if (arg_map.count(key) > 0) {
				return arg_map.at(key);
			}

			return default_str;
		}

		std::string at(std::vector<std::string> args) const {
			return first_arg(args);
		}

		std::string at(const char * key) const {
			return get_arg(key);
		}

		std::string at(const char * key, const char * def) const {
			return count(key) > 0
				? at(key)
				: def;
		}

		std::string at(const char * key, std::string def) const {
			return at(key, def.c_str());
		}

		size_t size() const {
			return arg_map.size();
		}

		size_t count(const char * key) const {
			return at(key).size() > 0;
		}

		size_t count(std::vector<std::string> args) const {
			return first_arg(args).size() > 0;
		}

		bool empty() {
			return size() == 0;
		}

		std::string first_arg(std::vector<std::string> strs, const std::string & def = default_str) const {
			for (const auto key : strs) {
				if (arg_map.count(key) > 0) {
					return arg_map.at(key);
				}
			}

			return default_str;
		}

		std::string arg_at_index(uint32_t index) const {
			if (index < arg_words.size()) {
				return arg_words.at(index);
			}

			return default_str;
		}

		bool action_is(std::string action) const {
			return action_is_one({ action });
		}

		bool action_is(sniffer_cmd_e cmd) const {
			return action_is_one(sniffer_cmd_to_str.at(cmd));
		}

		bool action_is_one(const std::vector<sniffer_cmd_e> actions) const {
			bool result = false;

			for (const auto & action : actions) {
				result = result || action_is(action);
			}

			return result;
		}

		bool action_is_one(const std::vector<std::string> actions) const {
			bool result = false;
			const auto action_string = action();

			for (const auto & action : actions) {
				result = result || action == action_string;
			}

			return result;
		}

		bool context_is(std::string context) const {
			return context_is_one({ context });
		}

		bool context_is(sniffer_cmd_e ctx_cmd) const {
			return context_is_one(sniffer_cmd_to_str.at(ctx_cmd));
		}

		bool context_is_one(const std::vector<std::string> contexts) const {
			bool result = false;
			const auto context_string = context();

			for (const auto & context : contexts) {
				result = result || context == context_string;
			}

			return result;
		}

		std::string action() const {
			return at("action");
		}

		std::string context(std::string def = "") const {
			const auto result = at("ctx_param", arg_at_index(1));
			return result.empty() ? def : result;
		}
	};


	class jobs_indicies_t {
	public:
		uint64_t start_index = 0;
		uint64_t end_index = 0;
	};

	class global_state_t {
	public:
		std::thread replace_thread;
		std::string executable_to_consider;
		std::wstring executable_to_consider_wstring;
		std::string sniff_file_name;
		std::string current_context;
		std::unordered_map<std::string, w32::sniff_record_set_t> context_to_sniffs;
		w32::sniff_record_set_t * sniffs;
		bool is_interactive;
		uint64_t num_threads;

		std::mutex replace_thread_mutex;
		std::vector<std::pair<w32::sniff_record_set_t, w32::sniff_value_t>> repeat_replace;
		bool replace_thread_is_running = true;
	};

	class shared_memory_t {
		size_t current_job = 0;
		uint64_t job_spread;
		std::mutex lock;
		uint64_t num_threads;
	public:
		shared_memory_t(const sniffer_args_t & args, w32::sniff_record_set_t * sniff_record, std::vector<w32::memory_region_record_t> & records, uint64_t num_threads, uint64_t job_spread)
			: args(args), sniff_record(sniff_record), records(records), num_threads(num_threads), job_spread(job_spread) {
			thread_resniffs.resize(num_threads);
		}

		std::vector<std::set<std::pair<size_t, uint64_t>>> thread_resniffs;
		void resetMultiThreadState() {
			std::lock_guard<std::mutex> stack_lock(lock);
			current_job = 0;
		}

		void getNextJob(jobs_indicies_t & job_index) {
			std::lock_guard<std::mutex> stack_lock(lock);
			job_index.start_index = current_job;
			current_job += job_spread;
			job_index.end_index = current_job;
		}

		size_t getCurrentJobIndex() {
			std::lock_guard<std::mutex> stack_lock(lock);
			return current_job;
		}

		std::vector<w32::memory_region_record_t> & records;
		std::vector<sniffer_work_unit_t> work_units;
		const sniffer_args_t & args;
		w32::sniff_record_set_t * sniff_record;
	};

	class sniffer_context_t {
	public:
		sniffer_args_t args;
		global_state_t state;
	};

	bool init(int argc, char * argv[], sniffer_context_t & ctx);
	bool setup_sniffer_state(sniffer_context_t & ctx);
	void do_sync_workload(sniffer_context_t & ctx);
	void do_async_workload(sniffer_context_t & ctx);
	void do_post_workload(sniffer_context_t & ctx);
	bool update_interactive_arg(sniffer_context_t & ctx);
	void report_operation_side_effects(sniffer_context_t & ctx);
	void cleanup_sniffer_state(sniffer_context_t & ctx);
}
