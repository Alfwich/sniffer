#include "w32_api.h"

#include <string>
#include <set>
#include <unordered_map>
#include <fstream>
#include <iostream>

#include "processthreadsapi.h"
#include "errhandlingapi.h"
#include "winnt.h"
#include "securitybaseapi.h"
#include <stdint.h>

#include "params.h"

namespace w32 {
	std::unordered_map<DWORD, HANDLE> open_handles;

	HANDLE open_process(DWORD pid) {
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

		Process32First(processesSnapshot, &processInfo);
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

	void set_bytes_at_location_for_pid(uint64_t pid, uint64_t location, uint8_t * bytes, size_t size) {
		if (pid == 0 || location == 0) return;

		const auto proc_handle = open_process((w32::DWORD)pid);

		static DWORD oldprotect;
		LPVOID dst = (LPVOID)((SIZE_T)location);
		VirtualProtectEx(proc_handle, dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
		SIZE_T num_bytes_written = 0;
		auto wpm_result = WriteProcessMemory(
			proc_handle,
			dst,
			(LPVOID)bytes,
			size,
			&num_bytes_written
		);
		VirtualProtectEx(proc_handle, dst, size, oldprotect, &oldprotect);
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

	sniff_type_e get_sniff_type_for_str(const std::string & type_str) {
		if (type_str == "str") {
			return sniff_type_e::str;
		}
		else if (type_str == "i8") {
			return sniff_type_e::i8;
		}
		else if (type_str == "i32") {
			return sniff_type_e::i32;
		}
		else if (type_str == "i64") {
			return sniff_type_e::i64;
		}
		else if (type_str == "u8") {
			return sniff_type_e::u8;
		}
		else if (type_str == "u32") {
			return sniff_type_e::u32;
		}
		else if (type_str == "u64") {
			return sniff_type_e::u64;
		}
		else if (type_str == "f32") {
			return sniff_type_e::f32;
		}
		else if (type_str == "f64") {
			return sniff_type_e::f64;
		}

		return sniff_type_e::unknown;
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

	void memory_region_copy_t::buffer_if_needed(uint64_t addr_from_base_to_load) {
		if (region_size == 0 || base == 0 || addr_from_base_to_load < max_loaded_mem_location) return;

		const auto proc_handle = open_process((w32::DWORD)pid);

		w32::SIZE_T total_bytes_read = 0;
		w32::SIZE_T num_bytes_read = 0;

		auto max_chunk_factor = page_size * 64;
		auto chunk_factor = max_chunk_factor;
		auto start = (SIZE_T)max_loaded_mem_location + base;
		auto end = min(start + (page_size * 1022), (base + region_size + (refs_split_record ? 1024 : 0)));
		auto i = 0;
		while (start < end) {
			auto translated_index = translate_index(addr_from_base_to_load + total_bytes_read);
			auto num_bytes_to_read = min(chunk_factor, min(end - start, bytes.size() - translated_index));
			auto rpm_result = ReadProcessMemory(
				proc_handle,
				(LPVOID)start,
				(LPVOID)&bytes[translated_index],
				num_bytes_to_read,
				&num_bytes_read
			);

			if (rpm_result != 0 && chunk_factor < max_chunk_factor) {
				chunk_factor = min(chunk_factor * 4, max_chunk_factor);
			}

			if (rpm_result == 0 && chunk_factor > 1) {
				chunk_factor = max(chunk_factor / 4, 1);
				continue;
			}
			else if (rpm_result == 0) {
				has_failed_load = true;
				break;
			}

			total_bytes_read += num_bytes_read;
			start += num_bytes_read;
		}

		max_loaded_mem_location += total_bytes_read;
	}

	uint64_t memory_region_copy_t::translate_index(uint64_t i) {
		return i % bytes.size();
	}

	uint8_t & memory_region_copy_t::operator[](uint64_t i) {
		buffer_if_needed(i);
		return bytes[translate_index(i)];
	}

	std::mutex sniff_record_set_location_mutex;
	void sniff_record_set_t::set_location(sniff_type_e value_type, size_t pid, uint64_t location) {
		std::lock_guard<std::mutex> lock(sniff_record_set_location_mutex);
		locations[value_type].insert(std::make_tuple(value_type, pid, location));
	}

	std::string data_to_string(sniff_type_e type, uint8_t * data, size_t size) {
		std::string result;

		switch (type) {
		case sniff_type_e::i8:
			result = std::to_string(*(int8_t *)data);
			break;

		case sniff_type_e::i32:
			result = std::to_string(*(int32_t *)data);
			break;

		case sniff_type_e::i64:
			result = std::to_string(*(int64_t *)data);
			break;

		case sniff_type_e::u8:
			result = std::to_string(*(uint8_t *)data);
			break;

		case sniff_type_e::u32:
			result = std::to_string(*(uint32_t *)data);
			break;

		case sniff_type_e::u64:
			result = std::to_string(*(uint64_t *)data);
			break;

		case sniff_type_e::f32:
			result = std::to_string(*(float_t *)data);
			break;

		case sniff_type_e::f64:
			result = std::to_string(*(double_t *)data);
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
