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

#include "Params.h"

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
		void buffer_if_needed(uint64_t addr_from_base_to_load);
		uint64_t translate_index(uint64_t i);
		bool has_failed_load = false;
		bool refs_split_record = false;
	public:

		memory_region_copy_t() {
			page_size = get_system_page_size();
			bytes.resize(page_size * 1024);
		}

		void reset(w32::DWORD pid, w32::LPVOID location, w32::SIZE_T size, bool refs_split_record) {
			has_failed_load = false;
			max_loaded_mem_location = 0;
			this->pid = pid;
			base = (uint64_t)location;
			region_size = (uint64_t)size;
			this->refs_split_record = refs_split_record;
			buffer_if_needed(0);
		}

		uint8_t & operator[](uint64_t i);

		uint64_t size() { return region_size; }

		bool is_good() { return !has_failed_load && region_size != 0 && base != 0; }
		bool index_is_boundary(uint64_t i) { return translate_index(i) + 8 >= bytes.size(); }
	};

	enum class sniff_type_e {
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

	class sniff_value_t {
		std::string str_value = "";
		std::string old_str_value = "";
		std::int64_t int_value = 0;
		std::uint64_t uint_value = 0;
		std::double_t fp_value = 0.0;
		w32::sniff_type_e ref_type = sniff_type_e::unknown;
		uint64_t ref_bytes = 999;
		bool primed = false;

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
						uint_value = 0;
						ref_bytes = 999;
					}

					try {
						int_value = std::stoll(str_value);
					}
					catch (...) {
						int_value = 0;
					}

					try {
						fp_value = std::stod(str_value);
					}
					catch (...) {
						fp_value = 0.0;
					}

					if (int_value == 1 && str_value != "1") {
						int_value = 0;
					}

					if (uint_value == 1 && str_value != "1") {
						uint_value = 0;
					}
					break;
				}

				primed = true;
			}
		}

	public:
		sniff_value_t() {}
		sniff_value_t(const char * value) : str_value(value), ref_type(sniff_type_e::str) {}
		sniff_value_t(std::string value) : str_value(value), ref_type(sniff_type_e::str) {}
		sniff_value_t(std::string & value) : str_value(value), ref_type(sniff_type_e::str) {}

		void updateStringValue() {
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

		void setValue(const std::string & value) {
			this->str_value = value;
			ref_type = sniff_type_e::str;
			ref_bytes = 0;
		}

		void setOldValue(const std::string & old_value) {
			old_str_value = old_value;
		}

		void setValue(int8_t value) {
			int_value = value;
			ref_type = sniff_type_e::i8;
			ref_bytes = 1;
		}

		void setValue(int32_t value) {
			int_value = value;
			ref_type = sniff_type_e::i32;
			ref_bytes = 4;
		}

		void setValue(int64_t value) {
			int_value = value;
			ref_type = sniff_type_e::i64;
			ref_bytes = 8;
		}

		void setValue(uint8_t value) {
			uint_value = value;
			ref_type = sniff_type_e::u8;
			ref_bytes = 1;
		}

		void setValue(uint32_t value) {
			uint_value = value;
			ref_type = sniff_type_e::u32;
			ref_bytes = 4;
		}

		void setValue(uint64_t value) {
			uint_value = value;
			ref_type = sniff_type_e::u64;
			ref_bytes = 8;
		}

		void setValue(float_t value) {
			fp_value = value;
			ref_type = sniff_type_e::f32;
			ref_bytes = 4;
		}

		void setValue(double_t value) {
			fp_value = value;
			ref_type = sniff_type_e::f64;
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
			return uint_value;
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

		sniff_value_t & operator=(const sniff_value_t & other) {
			str_value = other.str_value;
			int_value = other.int_value;
			uint_value = other.uint_value;
			fp_value = other.fp_value;
			ref_type = other.ref_type;
			primed = other.primed;
			return *this;
		}
	};

	class sniff_record_set_t {
		std::unordered_map<sniff_type_e, std::set<std::pair<size_t, uint64_t>>> locations;
	public:
		sniff_record_set_t() : pid(0) {};
		sniff_record_set_t(uint64_t pid, std::vector<uint64_t> locations) : pid(pid) {};
		uint64_t pid;
		std::unordered_map<sniff_type_e, std::set<std::pair<size_t, uint64_t>>> & getLocations() { return locations; }
		void setLocation(sniff_type_e value_type, size_t pid, uint64_t location);

		bool empty() const {
			for (const auto type_to_locations : locations) {
				if (!type_to_locations.second.empty()) {
					return false;
				}
			}

			return true;
		}
		size_t size() const {
			size_t size = 0;

			for (const auto type_to_locations : locations) {
				size += type_to_locations.second.size();
			}

			return size;
		}

		void clear() {
			locations.clear();
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
	sniff_type_e get_sniff_type_for_str(const std::string & type_str);
	std::string get_num_system_cores();
	void clear_open_handles();
}
