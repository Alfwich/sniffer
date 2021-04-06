#include <iostream>
#include <assert.h>

#include "libsniffer/sniffer.h"

struct test_heap {
	uint8_t header[4096];
	uint8_t body[4096 * 128];
	uint8_t footer[4096];
};

static test_heap heap = { 0 };

int main(int argc, char * argv[]) {
	auto exec_name_wstring = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes("tests.exe");
	auto pids = w32::get_all_pids_for_process_name(exec_name_wstring);
	auto region_info = w32::MEMORY_BASIC_INFORMATION();
	w32::memory_region_record_t test_mem_record(pids.front(), region_info);
	test_mem_record.BaseAddress = &heap;
	test_mem_record.RegionSize = 4096 * 130;
	sniffer::sniffer_context_t test;
	sniffer::init(argc, argv, test);
	sniffer::setup_sniffer_state(test);

	uint64_t * uint_ptr = (uint64_t *)&heap.body[1024];
	*uint_ptr = 13371337;

	sniffer::update_interactive_args_with_input(test, "find 13371337");
	sniffer::do_pre_workload(test);
	test.state.memory_records.clear();
	test.state.memory_records.push_back(test_mem_record);
	sniffer::do_workload(test);
	sniffer::do_post_workload(test);

	for (const auto & type_to_mem_locations : test.state.sniffs->get_locations()) {
		for (const auto & mem_location : type_to_mem_locations.second) {
			const auto location = (uint64_t *)std::get<2>(mem_location);
			const auto value = *location;
			assert(location == uint_ptr && value == *uint_ptr);
		}
	}

	sniffer::report_operation_side_effects(test);
	sniffer::cleanup_sniffer_state(test);

	std::cout << "All tests pass" << std::endl;

	return 0;
}
