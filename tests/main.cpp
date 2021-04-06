#include <ostream>
#include <iostream>
#include <assert.h>

#include "libsniffer/sniffer.h"

class test_reporter_t {
	std::string test;
public:
	test_reporter_t(const char * test) : test(test) {
		std::cout << "\tExecuting test " << test << "...";
	}
	~test_reporter_t() {
		std::cout << "passed" << std::endl;
	}
};

struct test_heap {
	uint8_t header[4096];
	uint8_t body[4096 * 128];
	uint8_t footer[4096];
};

static test_heap heap = { 0 };

void clear_heap() {
	ZeroMemory(heap.header, 4096);
	ZeroMemory(heap.body, 4096 * 128);
	ZeroMemory(heap.footer, 4096);
}

w32::memory_region_record_t get_test_heap_memory_region() {
	auto exec_name_wstring = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes("tests.exe");
	auto pids = w32::get_all_pids_for_process_name(exec_name_wstring);
	auto region_info = w32::MEMORY_BASIC_INFORMATION();
	w32::memory_region_record_t test_mem_record(pids.front(), region_info);
	test_mem_record.BaseAddress = &heap;
	test_mem_record.RegionSize = 4096 * 130;

	return test_mem_record;
}

void execute_test_command(sniffer::sniffer_context_t & ctx, std::string cmd) {
	sniffer::update_interactive_args_with_input(ctx, cmd);
	sniffer::do_pre_workload(ctx);
	ctx.state.memory_records.clear();
	ctx.state.memory_records.push_back(get_test_heap_memory_region());
	sniffer::do_workload(ctx);
	sniffer::do_post_workload(ctx);
}

std::vector<std::tuple<w32::sniff_type_e, size_t, uint64_t>> get_sniffs(sniffer::sniffer_context_t & ctx) {
	std::vector<std::tuple<w32::sniff_type_e, size_t, uint64_t>> result;

	for (const auto & type_to_mem_locations : ctx.state.sniffs->get_locations()) {
		for (const auto & mem_location : type_to_mem_locations.second) {
			result.push_back(mem_location);
		}
	}

	return std::move(result);
}

namespace tests {
	void do_simple_tests(sniffer::sniffer_context_t & ctx) {
		clear_heap();

		uint64_t * uint_ptr = (uint64_t *)&heap.body[1024];
		*uint_ptr = 13371337;

		{
			test_reporter_t reporter("find 13371337 in heap with one u64 value should return results to the memory location");
			execute_test_command(ctx, "find 13371337");
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto location = (uint64_t *)std::get<2>(mem_location);
				const auto value = *location;
				assert(location == uint_ptr && value == *uint_ptr);
			}
		}

		{
			test_reporter_t reporter("find 13371337 type u64 in heap with one u64 value should only find one u64 record");
			execute_test_command(ctx, "find 13371337 type u64");
			assert(get_sniffs(ctx).size() == 1);
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto location = (uint64_t *)std::get<2>(mem_location);
				const auto value = *location;
				const auto type = std::get<0>(mem_location);
				assert(type == w32::sniff_type_e::u64 && location == uint_ptr && value == *uint_ptr);
			}
		}

		{
			test_reporter_t reporter("find 13371337 type f32 in heap with one u64 value should report no finds");
			execute_test_command(ctx, "find 13371337 type f32");
			assert(get_sniffs(ctx).size() == 0);
		}

		{
			test_reporter_t reporter("set 12341234 in heap with one u64 value should replace value to 12341234");
			execute_test_command(ctx, "find 13371337 type u64");
			execute_test_command(ctx, "set 12341234");
			assert(*uint_ptr == 12341234);
		}
	}

	void do_multi_tests(sniffer::sniffer_context_t & ctx) {
		clear_heap();

		uint64_t * uint_ptr = (uint64_t *)&heap.body[1024];
		*uint_ptr = 13371337;

		uint64_t * uint_ptr2 = (uint64_t *)&heap.body[4155];
		*uint_ptr2 = 21212121;

		double_t * dbl_ptr = (double_t *)&heap.body[6541];
		*dbl_ptr = 1337.1337;

		{
			test_reporter_t reporter("find 13371337 in heap with 3 values (2xu64, 1xf64) finds correct u64");
			execute_test_command(ctx, "find 13371337");
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto location = (uint64_t *)std::get<2>(mem_location);
				const auto value = *location;
				assert(location == uint_ptr && value == *uint_ptr);
			}
		}

		{
			test_reporter_t reporter("find 21212121 in heap with 3 values (2xu64, 1xf64) finds correct u64");
			execute_test_command(ctx, "find 21212121");
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto location = (uint64_t *)std::get<2>(mem_location);
				const auto value = *location;
				assert(location == uint_ptr2 && value == *uint_ptr2);
			}
		}

		{
			test_reporter_t reporter("find 1337.1337 in heap with 3 values (2xu64, 1xf64) only finds single f64");
			execute_test_command(ctx, "find 1337.1337");
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto location = (double_t *)std::get<2>(mem_location);
				const auto value = *location;
				assert(location == dbl_ptr && value == *dbl_ptr);
			}
		}
	}
}

int main(int argc, char * argv[]) {

	std::ostream null_out(0);
	null_out.setstate(std::ios_base::badbit);

	// Null stdout for test sniffer context
	sniffer::sniffer_context_t test(null_out);

	sniffer::init(argc, argv, test);
	sniffer::setup_sniffer_state(test);

	test.state.profile = false;

	std::cout << "Running Sniffer Tests..." << std::endl;

	tests::do_simple_tests(test);
	tests::do_multi_tests(test);

	std::cout << "All tests pass" << std::endl;

	sniffer::cleanup_sniffer_state(test);

	return 0;
}
