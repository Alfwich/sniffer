#include <ostream>
#include <iostream>
#include <sstream>
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

#define TEST_HEAP_SIZE 1024 * 1024 * 4
struct test_heap {
	uint8_t ptr[TEST_HEAP_SIZE] = { 0 };
	uint64_t size = TEST_HEAP_SIZE;
};

static test_heap heap;

void clear_heap() {
	ZeroMemory(heap.ptr, heap.size);
}

w32::memory_region_record_t get_test_heap_memory_region() {
	auto exec_name_wstring = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes("tests.exe");
	auto pids = w32::get_all_pids_for_process_name(exec_name_wstring);
	auto region_info = w32::MEMORY_BASIC_INFORMATION();
	w32::memory_region_record_t test_mem_record(pids.front(), region_info);
	test_mem_record.BaseAddress = &heap;
	test_mem_record.RegionSize = heap.size;

	return test_mem_record;
}

void execute_test_command(sniffer::sniffer_context_t & ctx, std::string cmd) {
	sniffer::update_interactive_args_with_input(ctx, cmd);
	sniffer::do_pre_workload(ctx);
	ctx.state.memory_records.clear();
	ctx.state.memory_records.push_back(get_test_heap_memory_region());
	sniffer::split_large_records(ctx.state.memory_records, 1024 * 4); // Aggressive chunking of records for testing
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

		uint64_t * uint_ptr = (uint64_t *)&heap.ptr[1024];
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

		uint64_t * uint_ptr = (uint64_t *)&heap.ptr[1024];
		*uint_ptr = 13371337;

		uint64_t * uint_ptr2 = (uint64_t *)&heap.ptr[4155];
		*uint_ptr2 = 21212121;

		double_t * dbl_ptr = (double_t *)&heap.ptr[6541];
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

	void do_boundary_tests(sniffer::sniffer_context_t & ctx) {
		clear_heap();

		const auto first_mem_record = ctx.state.memory_records.front();

		// Position this uint64 directly on the boundary between the first and second record where
		// the first byte of the uint64 will lie on the first memory record: [1|2345678].
		// The searching logic needs to pull in the extra 7 bytes for split records to correctly resolve the sniff.
		uint64_t * uint_ptr = (uint64_t *)&heap.ptr[first_mem_record.RegionSize - 1];
		*uint_ptr = ((uint64_t)0) - 1;

		{
			test_reporter_t reporter("find (UINT64_T_MAX) on boundary should find result");
			std::stringstream cmd;
			cmd << "find " << *uint_ptr;
			execute_test_command(ctx, cmd.str());
			assert(!ctx.state.sniffs->empty());
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto location = (uint64_t *)std::get<2>(mem_location);
				const auto value = *location;
				assert(location == uint_ptr && value == *uint_ptr);
			}
		}

		const auto test_string = std::string("Hello World My DUDE!");
		uint8_t * char_ptr = &heap.ptr[first_mem_record.RegionSize - 3];
		for (auto i = 0; i < test_string.size(); ++i) {
			char_ptr[i] = test_string[i];
		}

		{
			test_reporter_t reporter("find \"Hello World My DUDE!\" type str on boundary should find result");
			execute_test_command(ctx, "find \"Hello World My DUDE!\" type str");
			assert(!ctx.state.sniffs->empty());
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto location = (uint8_t *)std::get<2>(mem_location);
				const auto value = std::string((const char *)location);
				assert(location == char_ptr && value == test_string);
			}
		}
	}
}

int main(int argc, char * argv[]) {

	std::ostream null_out(0);
	null_out.setstate(std::ios_base::badbit);

	// Null stdout for test sniffer context
	sniffer::sniffer_context_t test_ctx(null_out);

	sniffer::init(argc, argv, test_ctx);
	sniffer::setup_sniffer_state(test_ctx);

	test_ctx.state.profile = false;

	std::cout << "Running Sniffer Tests..." << std::endl;

	for (auto i = 0; i < 2; ++i) {
		tests::do_simple_tests(test_ctx);
		tests::do_multi_tests(test_ctx);
		tests::do_boundary_tests(test_ctx);
	}

	std::cout << "All tests pass" << std::endl;

	sniffer::cleanup_sniffer_state(test_ctx);

	return 0;
}
