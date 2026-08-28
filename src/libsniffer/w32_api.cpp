#include "w32_api.h"

#include <string>
#include <set>
#include <unordered_map>
#include <fstream>
#include <iostream>
#include <cstring>
#include <limits>
#include <algorithm>

#include "processthreadsapi.h"
#include "errhandlingapi.h"
#include "winnt.h"
#include "securitybaseapi.h"
#include <stdint.h>

#include "params.h"

namespace w32 {
	std::unordered_map<DWORD, HANDLE> open_handles;
	std::mutex open_handles_mutex;
	std::mutex memory_write_mutex;

	HANDLE open_process(DWORD pid) {
		std::lock_guard<std::mutex> lock(open_handles_mutex);
		if (open_handles.count(pid) == 0) {
			open_handles[pid] = OpenProcess(
				PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION,
				false,
				pid
			);
		}

		return open_handles.at(pid);
	}

	void clear_open_handles(const std::vector<DWORD> pids) {
		std::lock_guard<std::mutex> lock(open_handles_mutex);
		for (auto pid : pids) {
			if (open_handles.count(pid) != 0) {
				CloseHandle(open_handles.at(pid));
				open_handles.erase(pid);
			}
		}
	}

	BOOL set_privilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
		LUID luid;
		BOOL bRet = FALSE;

		if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
			TOKEN_PRIVILEGES tp;

			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;
			//
			//  Enable the privilege or disable all privileges.
			//
			if (AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
				//
				//  Check to see if you have proper access.
				//  You may get "ERROR_NOT_ALL_ASSIGNED".
				//
				bRet = (GetLastError() == ERROR_SUCCESS);
			}
		}
		return bRet;
	}

	void get_all_processes(std::vector<PROCESSENTRY32> & out_vec) {
		PROCESSENTRY32 processInfo;
		processInfo.dwSize = sizeof(processInfo);

		HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (processesSnapshot == INVALID_HANDLE_VALUE) {
			return;
		}

		if (!Process32First(processesSnapshot, &processInfo)) {
			CloseHandle(processesSnapshot);
			return;
		}
		out_vec.push_back(processInfo);

		while (Process32Next(processesSnapshot, &processInfo)) {
			out_vec.push_back(processInfo);
		}

		CloseHandle(processesSnapshot);
	}

	void set_debug_priv() {
		HANDLE hProcess = GetCurrentProcess();
		HANDLE hToken;

		if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
			set_privilege(hToken, SE_DEBUG_NAME, TRUE);
			CloseHandle(hToken);
		}
	}

	std::vector<PROCESSENTRY32> get_open_processes() {
		std::vector<PROCESSENTRY32> output;
		get_all_processes(output);
		return output;
	}

	std::vector<DWORD> find_processId(const std::wstring & processName) {
		std::vector<DWORD> result;
		const auto & all_procs = get_open_processes();

		for (const auto proc : all_procs) {
			if (processName.compare(proc.szExeFile) == 0) {
				result.push_back(proc.th32ProcessID);
			}
		}

		return result;
	}

	std::set<uint64_t> get_all_live_pids() {
		std::set<uint64_t> output;
		const auto all_procs = get_open_processes();

		for (const auto & proc : all_procs) {
			output.insert(proc.th32ProcessID);
		}

		return output;
	}

	std::vector<memory_region_record_t> get_all_memory_regions_for_pid(DWORD pid) {
		auto result = std::vector<memory_region_record_t>();
		const auto proc_handle = open_process(pid);
		auto memory_basic_info = MEMORY_BASIC_INFORMATION();
		auto addr = unsigned long long(0);
		while (true) {
			auto num_bytes_vq_ex_written = VirtualQueryEx(
				proc_handle,
				(LPVOID)addr,
				(PMEMORY_BASIC_INFORMATION)&memory_basic_info,
				sizeof(memory_basic_info)
			);

			if (num_bytes_vq_ex_written == 0) {
				break;
			}

			if (memory_basic_info.State != MEM_FREE) {
				result.push_back(memory_region_record_t(pid, memory_basic_info));
			}
			addr += memory_basic_info.RegionSize;
		}

		return result;
	}

	std::vector<DWORD> get_all_pids_for_process_name(std::wstring proc_name) {
		return find_processId(proc_name);
	}

	bool set_bytes_at_location_for_pid(uint64_t pid, uint64_t location, const uint8_t * bytes, size_t size) {
		if (pid == 0 || location == 0 || bytes == nullptr) return false;
		if (size == 0) return true;

		std::lock_guard<std::mutex> lock(memory_write_mutex);

		const auto proc_handle = open_process((w32::DWORD)pid);
		if (proc_handle == nullptr) return false;

		LPVOID dst = (LPVOID)((SIZE_T)location);
		SIZE_T num_bytes_written = 0;
		auto write_succeeded = WriteProcessMemory(
			proc_handle,
			dst,
			bytes,
			size,
			&num_bytes_written
		);
		if (write_succeeded && num_bytes_written == size) return true;

		DWORD old_protect = 0;
		if (!VirtualProtectEx(proc_handle, dst, size, PAGE_EXECUTE_READWRITE, &old_protect)) return false;

		num_bytes_written = 0;
		write_succeeded = WriteProcessMemory(proc_handle, dst, bytes, size, &num_bytes_written);

		DWORD ignored_protect = 0;
		const auto restore_succeeded = VirtualProtectEx(proc_handle, dst, size, old_protect, &ignored_protect);
		return write_succeeded && num_bytes_written == size && restore_succeeded;
	}

	const char * get_sniff_type_str_for_type(sniff_type_e type) {
		switch (type) {
		case sniff_type_e::str: return "str";
		case sniff_type_e::i8: return "i8";
		case sniff_type_e::i32: return "i32";
		case sniff_type_e::i64: return "i64";
		case sniff_type_e::u8: return "u8";
		case sniff_type_e::u32: return "u32";
		case sniff_type_e::u64: return "u64";
		case sniff_type_e::f32: return "f32";
		case sniff_type_e::f64: return "f64";
		default:
		case sniff_type_e::unknown: return "unknown";
		}
	}

	std::unordered_map<std::string, uint32_t> get_sniff_type_for_str_memo;
	uint32_t get_sniff_type_for_str(const std::string & type_str) {
		if (get_sniff_type_for_str_memo.count(type_str) == 0) {

			uint32_t result = 0;

			if (type_str.find("str") != std::string::npos) {
				result |= (uint32_t)sniff_type_e::str;
			}

			if (type_str.find("i8") != std::string::npos) {
				result |= (uint32_t)sniff_type_e::i8;
			}

			if (type_str.find("u8") != std::string::npos) {
				result |= (uint32_t)sniff_type_e::u8;
			}

			if (type_str.find("i32") != std::string::npos) {
				result |= (uint32_t)sniff_type_e::i32;
			}

			if (type_str.find("u32") != std::string::npos) {
				result |= (uint32_t)sniff_type_e::u32;
			}

			if (type_str.find("i64") != std::string::npos) {
				result |= (uint32_t)sniff_type_e::i64;
			}

			if (type_str.find("u64") != std::string::npos) {
				result |= (uint32_t)sniff_type_e::u64;
			}

			if (type_str.find("f32") != std::string::npos) {
				result |= (uint32_t)sniff_type_e::f32;
			}

			if (type_str.find("f64") != std::string::npos) {
				result |= (uint32_t)sniff_type_e::f64;
			}

			get_sniff_type_for_str_memo[std::string(type_str)] = result;

		}

		return get_sniff_type_for_str_memo.at(type_str);
	}

	std::string get_num_system_cores() {
		SYSTEM_INFO sysinfo;
		GetSystemInfo(&sysinfo);
		return std::to_string(sysinfo.dwNumberOfProcessors);
	}

	uint64_t get_system_page_size() {
		SYSTEM_INFO sysinfo;
		GetSystemInfo(&sysinfo);
		return static_cast<uint64_t>(sysinfo.dwPageSize);
	}

	uint64_t memory_region_copy_t::accessible_size() const {
		if (!refs_split_record) return region_size;
		if (additional_buffer > (std::numeric_limits<uint64_t>::max)() - region_size) {
			return (std::numeric_limits<uint64_t>::max)();
		}
		return region_size + additional_buffer;
	}

	bool memory_region_copy_t::contains(uint64_t offset, size_t length) const {
		const auto available = accessible_size();
		return offset <= available && static_cast<uint64_t>(length) <= available - offset;
	}

	bool memory_region_copy_t::buffer_if_needed(uint64_t addr_from_base_to_load) {
		if (region_size == 0 || base == 0 || has_failed_load || !contains(addr_from_base_to_load, 1)) return false;
		if (addr_from_base_to_load < max_loaded_mem_location) {
			return max_loaded_mem_location - addr_from_base_to_load <= bytes.size();
		}

		const auto proc_handle = open_process((w32::DWORD)pid);
		if (proc_handle == nullptr) {
			has_failed_load = true;
			return false;
		}

		auto max_chunk_factor = page_size * 64;
		while (addr_from_base_to_load >= max_loaded_mem_location) {
			const auto window_start = max_loaded_mem_location;
			const auto bytes_remaining = accessible_size() - window_start;
			const auto window_size = (std::min<uint64_t>)(bytes.size(), bytes_remaining);
			w32::SIZE_T total_bytes_read = 0;
			auto chunk_factor = max_chunk_factor;

			while (total_bytes_read < window_size) {
				const auto logical_offset = window_start + total_bytes_read;
				const auto translated_index = translate_index(logical_offset);
				const auto bytes_to_window_end = window_size - total_bytes_read;
				const auto bytes_to_buffer_end = bytes.size() - translated_index;
				const auto num_bytes_to_read = (std::min<uint64_t>)(chunk_factor, (std::min<uint64_t>)(bytes_to_window_end, bytes_to_buffer_end));
				w32::SIZE_T num_bytes_read = 0;
				const auto rpm_result = ReadProcessMemory(
					proc_handle,
					(LPVOID)(base + logical_offset),
					&bytes[translated_index],
					num_bytes_to_read,
					&num_bytes_read
				);

				if (rpm_result == 0) {
					if (chunk_factor > 1) {
						chunk_factor = 1;
						continue;
					}
					has_failed_load = true;
					return false;
				}
				if (num_bytes_read == 0) {
					has_failed_load = true;
					return false;
				}

				total_bytes_read += num_bytes_read;
				if (chunk_factor < max_chunk_factor) {
					chunk_factor = min(chunk_factor * 4, max_chunk_factor);
				}
			}

			max_loaded_mem_location += total_bytes_read;
		}
		return true;
	}

	uint64_t memory_region_copy_t::translate_index(uint64_t i) {
		return i % bytes.size();
	}

	bool memory_region_copy_t::read_bytes(uint64_t offset, void * destination, size_t length) {
		if (destination == nullptr || !contains(offset, length) || has_failed_load) return false;
		auto output = static_cast<uint8_t *>(destination);
		for (size_t i = 0; i < length; ++i) {
			const auto current_offset = offset + i;
			if (!buffer_if_needed(current_offset) || current_offset >= max_loaded_mem_location) return false;
			output[i] = bytes[translate_index(current_offset)];
		}
		return true;
	}

	std::mutex sniff_record_set_location_mutex;
	void sniff_record_set_t::set_location(sniff_type_e value_type, size_t pid, uint64_t location) {
		std::lock_guard<std::mutex> lock(sniff_record_set_location_mutex);
		locations[value_type].emplace(value_type, pid, location);
	}

	// Thread unsafe set location
	void sniff_record_set_t::set_location_unsafe(const std::tuple<sniff_type_e, size_t, uint64_t> & tuple) {
		locations[std::get<0>(tuple)].emplace(tuple);
	}

	template <class T>
	bool copy_value_from_bytes(const uint8_t * data, size_t size, T & value) {
		if (data == nullptr || size < sizeof(T)) return false;
		std::memcpy(&value, data, sizeof(value));
		return true;
	}

	std::string data_to_string(sniff_type_e type, const uint8_t * data, size_t size) {
		std::string result;

		switch (type) {
		case sniff_type_e::i8: {
			int8_t value = 0;
			if (copy_value_from_bytes(data, size, value)) result = std::to_string(value);
		}
			break;

		case sniff_type_e::i32: {
			int32_t value = 0;
			if (copy_value_from_bytes(data, size, value)) result = std::to_string(value);
		}
			break;

		case sniff_type_e::i64: {
			int64_t value = 0;
			if (copy_value_from_bytes(data, size, value)) result = std::to_string(value);
		}
			break;

		case sniff_type_e::u8: {
			uint8_t value = 0;
			if (copy_value_from_bytes(data, size, value)) result = std::to_string(value);
		}
			break;

		case sniff_type_e::u32: {
			uint32_t value = 0;
			if (copy_value_from_bytes(data, size, value)) result = std::to_string(value);
		}
			break;

		case sniff_type_e::u64: {
			uint64_t value = 0;
			if (copy_value_from_bytes(data, size, value)) result = std::to_string(value);
		}
			break;

		case sniff_type_e::f32: {
			float_t value = 0;
			if (copy_value_from_bytes(data, size, value)) result = std::to_string(value);
		}
			break;

		case sniff_type_e::f64: {
			double_t value = 0;
			if (copy_value_from_bytes(data, size, value)) result = std::to_string(value);
		}
			break;

		case sniff_type_e::str:
			for (auto i = 0; i < size; ++i) { result.push_back(data[i]); }
			break;

		default:
			// NO OP
			break;
		}

		return result;
	}
}
