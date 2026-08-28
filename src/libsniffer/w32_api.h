#pragma once

#pragma warning( disable : 4624 4615 )

#include <string>
#include <codecvt>
#include <locale>
#include <set>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>

#include "params.h"
#include "utils.h"

namespace w32 {

#include "Windows.h"
#include "tlhelp32.h"

	uint64_t get_system_page_size();

	class memory_region_record_t : public MEMORY_BASIC_INFORMATION {
	public:
		memory_region_record_t(DWORD pid, MEMORY_BASIC_INFORMATION & info) {
			AssociatedPid = pid;
			BaseAddress = info.BaseAddress;
			AllocationBase = info.AllocationBase;
			AllocationProtect = info.AllocationProtect;
			RegionSize = info.RegionSize;
			State = info.State;
			Protect = info.Protect;
			Type = info.Type;
		}

		memory_region_record_t(const memory_region_record_t & other) : MEMORY_BASIC_INFORMATION(other) {
			AssociatedPid = other.AssociatedPid;
			is_split_record = other.is_split_record;
			is_end_record = other.is_end_record;
		}

		DWORD AssociatedPid;
		bool is_split_record = false;
		bool is_end_record = true;
	};

	class memory_region_copy_t {
		std::vector<uint8_t> bytes;
		uint64_t max_loaded_mem_location = 0;
		uint64_t pid = 0;
		uint64_t base = 0;
		uint64_t region_size = 0;
		uint64_t page_size = 0;
		uint64_t additional_buffer = 0;
		void buffer_if_needed(uint64_t addr_from_base_to_load);
		uint64_t translate_index(uint64_t i);
		bool has_failed_load = false;
		bool refs_split_record = false;
	public:

		memory_region_copy_t() {
			page_size = get_system_page_size();
			bytes.resize(page_size * NUM_PAGES_TO_BUFFER);
		}

		void reset(w32::DWORD pid, w32::LPVOID location, w32::SIZE_T size, bool refs_split_record, uint64_t additional_buffer_needed = 8) {
			has_failed_load = false;
			max_loaded_mem_location = 0;
			this->pid = pid;
			base = (uint64_t)location;
			region_size = (uint64_t)size;
			this->refs_split_record = refs_split_record;
			additional_buffer = additional_buffer_needed;
			buffer_if_needed(0);
		}

		uint8_t & operator[](uint64_t i);

		uint64_t size() { return region_size; }

		bool is_good() { return !has_failed_load && region_size != 0 && base != 0; }
		bool index_lies_on_boundary(uint64_t i) { return translate_index(i) + 8 >= bytes.size(); }
	};

	enum class sniff_type_e {
		unknown = 0,
		str = 1,
		i8 = 2,
		i32 = 4,
		i64 = 8,
		u8 = 16,
		u32 = 32,
		u64 = 64,
		f32 = 128,
		f64 = 256
	};

	class sniff_value_t {
		std::string str_value = "";
		std::int64_t int_value = 0;
		std::uint64_t uint_value = 0;
		std::double_t fp_value = 0.0;
		w32::sniff_type_e ref_type = sniff_type_e::unknown;

		bool primed = false;
		bool int_load_failure = false;
		bool uint_load_failure = false;
		bool fp_load_failure = false;

		void prime() {
			if (!primed) {
				switch (ref_type) {
				case sniff_type_e::i8:
				case sniff_type_e::i32:
				case sniff_type_e::i64:
					str_value = std::to_string(int_value);
					fp_value = static_cast<double_t>(int_value);
					uint_value = static_cast<uint64_t>(int_value);
					break;
				case sniff_type_e::u8:
				case sniff_type_e::u32:
				case sniff_type_e::u64:
					str_value = std::to_string(uint_value);
					fp_value = static_cast<double_t>(uint_value);
					int_value = static_cast<int64_t>(uint_value);
					break;
				case sniff_type_e::f32:
				case sniff_type_e::f64:
					str_value = std::to_string(fp_value);
					int_value = static_cast<int64_t>(fp_value);
					uint_value = static_cast<uint64_t>(fp_value);
					break;
				case sniff_type_e::str:
					try {
						uint_value = std::stoull(str_value);
					}
					catch (...) {
						uint_load_failure = true;
					}

					try {
						int_value = std::stoll(str_value);
					}
					catch (...) {
						int_load_failure = true;
					}

					try {
						fp_value = std::stod(str_value);
					}
					catch (...) {
						fp_load_failure = true;
					}
					break;
				}

				primed = true;
			}
		}

	public:
		sniff_value_t() {}
		sniff_value_t(const sniff_value_t & other) { *this = other; }
		sniff_value_t(const char * value) : str_value(value), ref_type(sniff_type_e::str) {}
		sniff_value_t(std::string value) : str_value(value), ref_type(sniff_type_e::str) {}
		sniff_value_t(std::string & value) : str_value(value), ref_type(sniff_type_e::str) {}

		void update_string_value() {
			std::string new_value;

			switch (ref_type) {
			case sniff_type_e::i8:
			case sniff_type_e::i32:
			case sniff_type_e::i64:
				new_value = std::to_string(int_value);
				break;
			case sniff_type_e::u8:
			case sniff_type_e::u32:
			case sniff_type_e::u64:
				new_value = std::to_string(uint_value);
				break;
			case sniff_type_e::f32:
			case sniff_type_e::f64:
				new_value = std::to_string(fp_value);
				break;
			case sniff_type_e::str:
				new_value = str_value;
				break;
			}

			str_value = new_value;
		}

		bool int_good() {
			return !int_load_failure;
		}

		bool uint_good() {
			return !uint_load_failure;
		}

		bool float_good() {
			return !fp_load_failure;
		}

		std::string as_typed_str(sniff_type_e type) {
			prime();

			std::string result;

			switch (type) {
			case sniff_type_e::i8:
				result = std::to_string((int8_t)int_value);
				break;

			case sniff_type_e::i32:
				result = std::to_string((int32_t)int_value);
				break;

			case sniff_type_e::i64:
				result = std::to_string((int64_t)int_value);
				break;

			case sniff_type_e::u8:
				result = std::to_string((uint8_t)uint_value);
				break;

			case sniff_type_e::u32:
				result = std::to_string((uint32_t)uint_value);
				break;

			case sniff_type_e::u64:
				result = std::to_string((uint64_t)uint_value);
				break;

			case sniff_type_e::f32:
				result = std::to_string((float_t)fp_value);
				break;

			case sniff_type_e::f64:
				result = std::to_string((double_t)fp_value);
				break;

			case sniff_type_e::str:
			default:
				result = str_value;
				break;
			}

			return result;
		}

		bool compare_i(uint64_t test_int) {
			switch (ref_type) {
			case sniff_type_e::i8:
			case sniff_type_e::i32:
			case sniff_type_e::i64:
			case sniff_type_e::u8:
			case sniff_type_e::u32:
			case sniff_type_e::u64:
				return test_int == int_value;
			}

			return false;
		}

		bool compare_s(std::string & test_str) {
			switch (ref_type) {
			case sniff_type_e::str:
				return test_str == str_value;
			}

			return false;
		}

		bool compare_f(double_t test_fp) {
			switch (ref_type) {
			case sniff_type_e::f32:
			case sniff_type_e::f64:
				return test_fp == fp_value;
			}

			return false;
		}

		void set_value(const std::string & value) {
			this->str_value = value;
			ref_type = sniff_type_e::str;
		}

		void set_value(int8_t value) {
			int_value = value;
			ref_type = sniff_type_e::i8;
		}

		void set_value(int32_t value) {
			int_value = value;
			ref_type = sniff_type_e::i32;
		}

		void set_value(int64_t value) {
			int_value = value;
			ref_type = sniff_type_e::i64;
		}

		void set_value(uint8_t value) {
			uint_value = value;
			ref_type = sniff_type_e::u8;
		}

		void set_value(uint32_t value) {
			uint_value = value;
			ref_type = sniff_type_e::u32;
		}

		void set_value(uint64_t value) {
			uint_value = value;
			ref_type = sniff_type_e::u64;
		}

		void set_value(float_t value) {
			fp_value = value;
			ref_type = sniff_type_e::f32;
		}

		void set_value(double_t value) {
			fp_value = value;
			ref_type = sniff_type_e::f64;
		}

		const std::string & as_string() {
			prime();
			return str_value;
		}

		template <class T>
		const T as_int() {
			prime();
			return static_cast<T>(int_value);
		}

		template <class T>
		const T as_uint() {
			prime();
			return static_cast<T>(uint_value);
		}

		template <class T>
		const T as_float() {
			prime();
			return static_cast<T>(fp_value);
		}

		const size_t min_num_int_bytes() {
			prime();
			if (uint_value == 0 && str_value != "0") {
				// 9 to exclude searching for any int types on parse failures (ie: 'find "Hello World!"')
				return 9;
			}
			if (uint_value <= ((uint8_t)-1)) {
				return 1;
			}
			else if (uint_value <= ((uint32_t)-1)) {
				return 4;
			}
			else {
				return 8;
			}
		}

		sniff_value_t & operator=(const sniff_value_t & other) {
			str_value = other.str_value;
			int_value = other.int_value;
			uint_value = other.uint_value;
			fp_value = other.fp_value;
			primed = other.primed;
			int_load_failure = other.int_load_failure;
			uint_load_failure = other.uint_load_failure;
			fp_load_failure = other.fp_load_failure;
			return *this;
		}
	};

	class sniff_record_set_t {
		std::unordered_map<sniff_type_e, std::set<std::tuple<sniff_type_e, size_t, uint64_t>>> undo_locations;
		std::unordered_map<sniff_type_e, std::set<std::tuple<sniff_type_e, size_t, uint64_t>>> locations;
	public:
		sniff_record_set_t() : pid(0) {};
		sniff_record_set_t(uint64_t pid, std::vector<uint64_t> locations) : pid(pid) {};
		uint64_t pid;
		const std::unordered_map<sniff_type_e, std::set<std::tuple<sniff_type_e, size_t, uint64_t>>> & get_locations() { return locations; }
		const std::tuple<sniff_type_e, size_t, uint64_t> sniff_for_index(uint64_t index) {
			uint64_t i = 0;
			for (const auto & locations : get_locations()) {
				for (const auto & sniff : locations.second) {
					if (i++ == index) {
						return sniff;
					}
				}
			}

			return std::make_tuple<sniff_type_e, size_t, uint64_t>(sniff_type_e::unknown, 0, 0);
		}

		void set_location(sniff_type_e value_type, size_t pid, uint64_t location);
		void set_location_unsafe(const std::tuple<sniff_type_e, size_t, uint64_t> & tuple);

		void remove(std::set<uint64_t> & indicies) {
			uint64_t i = 0;
			for (auto & type_to_locations : locations) {
				for (auto it = type_to_locations.second.begin(); it != type_to_locations.second.end();) {
					if (indicies.count(i) == 1) {
						it = type_to_locations.second.erase(it);
					}
					else {
						++it;
					}
					++i;
				}
			}
		}

		void remove(indicies_t & indicies_range, bool inclusive = true) {
			uint64_t i = 0;
			for (auto & type_to_locations : locations) {
				for (auto it = type_to_locations.second.begin(); it != type_to_locations.second.end();) {
					auto in_range = i >= indicies_range.start_index && i <= indicies_range.end_index;
					if ((inclusive && in_range) || (!inclusive && !in_range)) {
						it = type_to_locations.second.erase(it);
					}
					else {
						++it;
					}
					++i;
				}
			}
		}

		bool empty() const {
			for (const auto & type_to_locations : locations) {
				if (!type_to_locations.second.empty()) {
					return false;
				}
			}

			return true;
		}

		size_t size() const {
			size_t size = 0;

			for (const auto & type_to_locations : locations) {
				size += type_to_locations.second.size();
			}

			return size;
		}

		void clear() {
			locations.clear();
		}

		void commit() {
			undo_locations = locations;
		}

		bool revert() {
			if (!undo_locations.empty()) {
				const auto tmp = locations;
				locations = undo_locations;
				undo_locations = tmp;
				return true;
			}

			return false;
		}

		sniff_value_t value;
	};

	BOOL set_privilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
	void get_all_processes(std::vector<PROCESSENTRY32> & out_vec);
	void set_debug_priv();
	std::vector<PROCESSENTRY32> get_open_processes();
	std::vector<DWORD> find_processId(const std::wstring & processName);
	std::set<uint64_t> get_all_live_pids();
	std::vector<memory_region_record_t> get_all_memory_regions_for_pid(DWORD pid);
	std::vector<DWORD> get_all_pids_for_process_name(std::wstring proc_name);
	void set_bytes_at_location_for_pid(uint64_t pid, uint64_t location, uint8_t * bytes, size_t size);
	const char * get_sniff_type_str_for_type(sniff_type_e type);
	uint32_t get_sniff_type_for_str(const std::string & type_str);
	std::string get_num_system_cores();
	void clear_open_handles(const std::vector<DWORD> pids);
	std::string data_to_string(sniff_type_e type, uint8_t * data, size_t size);
}
