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

#include "Params.h"

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

	/*
	SniffRecordSet getSniffRecordFromLine(std::string & str) {
		SniffRecordSet result;
		size_t last = 0, next = 0;

		for (auto i = 0; i < 4; ++i) {
			next = str.find(SNIFF_FILE_DELIM, last);
			switch (i) {
			case 0:
				result.pid = std::stoll(str.substr(last, next - last));
				break;
			case 1:
				result.location = std::stoll(str.substr(last, next - last));
				break;
			case 2:
			{
				std::string type_str = str.substr(last, next - last);
				result.type = getSniffTypeForStr(type_str);
				break;
			}
			case 3:
			{
				std::string value_str = str.substr(last, next - last);
				result.value.setValue(value_str);
				break;
			}

			}
			last = next + strlen(SNIFF_FILE_DELIM);
		}

		return result;
	}

	std::unordered_map<std::string, std::vector<SniffRecordSet>> getSniffsForProcess(const std::string & sniff_file_name) {
		std::unordered_map<std::string, std::vector<SniffRecordSet>> result;
		std::string current_context;
		std::ifstream sniff_file(sniff_file_name);
		const auto live_pids = getAllLivePIDs();

		if (sniff_file.is_open()) {
			std::string line;
			while (true) {
				std::getline(sniff_file, line);
				if (line.find("ctx|") == 0) {
					current_context = line.substr(4);
					auto _tmp = result[current_context];
					continue;
				}
				if (line.empty()) break;
				auto sniff = getSniffRecordFromLine(line);
				if (live_pids.count(sniff.pid) > 0) {
					result.at(current_context).push_back(sniff);
				}
			}
		}

		return result;
	}

	void writeSniffsToSniffFile(const std::string & sniff_file_name, std::vector<SniffRecordSet> & sniff_records, std::ofstream & sniff_file) {
		if (sniff_file.is_open()) {
			for (auto & record : sniff_records) {
				sniff_file << record.pid << SNIFF_FILE_DELIM << record.location << SNIFF_FILE_DELIM << getSniffTypeStrForType(record.type);
				switch (record.type) {
				case SniffType::i8:
					sniff_file << SNIFF_FILE_DELIM << std::fixed << record.value.asI8() << std::endl;
					break;
				case SniffType::i32:
					sniff_file << SNIFF_FILE_DELIM << std::fixed << record.value.asI32() << std::endl;
					break;
				case SniffType::i64:
					sniff_file << SNIFF_FILE_DELIM << std::fixed << record.value.asI64() << std::endl;
					break;
				case SniffType::u8:
					sniff_file << SNIFF_FILE_DELIM << std::fixed << record.value.asU8() << std::endl;
					break;
				case SniffType::u32:
					sniff_file << SNIFF_FILE_DELIM << std::fixed << record.value.asU32() << std::endl;
					break;
				case SniffType::u64:
					sniff_file << SNIFF_FILE_DELIM << std::fixed << record.value.asU64() << std::endl;
					break;
				case SniffType::f32:
					sniff_file << SNIFF_FILE_DELIM << std::fixed << record.value.asF32() << std::endl;
					break;
				case SniffType::f64:
					sniff_file << SNIFF_FILE_DELIM << std::fixed << record.value.asF64() << std::endl;
					break;
				case SniffType::str:
					sniff_file << SNIFF_FILE_DELIM << std::fixed << record.value.asString() << std::endl;
					break;
				default:
					sniff_file << SNIFF_FILE_DELIM << std::endl;
				}
			}
		}
	}
	*/

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
	void sniff_record_set_t::setLocation(sniff_type_e value_type, size_t pid, uint64_t location) {
		std::lock_guard<std::mutex> lock(sniff_record_set_location_mutex);
		locations[value_type].insert(std::make_tuple(value_type, pid, location));
	}

}
