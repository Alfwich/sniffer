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

		*uint_ptr = 13371337;
		{
			test_reporter_t reporter("clear should remove all sniff records");
			execute_test_command(ctx, "find 13371337 type u64");
			assert(!ctx.state.sniffs->empty());
			execute_test_command(ctx, "clear");
			assert(ctx.state.sniffs->empty());
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
			test_reporter_t reporter("find 13371337 in heap with 3 values (2 u64, 1 f64) finds correct u64");
			execute_test_command(ctx, "find 13371337");
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto location = (uint64_t *)std::get<2>(mem_location);
				const auto value = *location;
				assert(location == uint_ptr && value == *uint_ptr);
			}
		}

		{
			test_reporter_t reporter("find 21212121 in heap with 3 values (2 u64, 1 f64) finds correct u64");
			execute_test_command(ctx, "find 21212121");
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto location = (uint64_t *)std::get<2>(mem_location);
				const auto value = *location;
				assert(location == uint_ptr2 && value == *uint_ptr2);
			}
		}

		{
			test_reporter_t reporter("find 1337.1337 in heap with 3 values (2 u64, 1 f64) only finds single f64");
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
			test_reporter_t reporter("find (UINT64_MAX) on boundary should find result");
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

	void do_string_tests(sniffer::sniffer_context_t & ctx) {
		clear_heap();

		const auto test_string = std::string("Hello World My DUDE!");
		uint8_t * char_ptr = &heap.ptr[2033];
		for (auto i = 0; i < test_string.size(); ++i) {
			char_ptr[i] = test_string[i];
		}

		{
			test_reporter_t reporter("find \"Hello World My DUDE!\" type str should find string");
			execute_test_command(ctx, "find \"Hello World My DUDE!\" type str");
			assert(!ctx.state.sniffs->empty());
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto location = (uint8_t *)std::get<2>(mem_location);
				const auto value = std::string((const char *)location);
				assert(location == char_ptr && value == test_string);
			}
		}

		{
			const auto test_str_replace = std::string("Jello World My DUDE!");
			test_reporter_t reporter("set \"Jello World My DUDE!\" set string should update value in heap");
			execute_test_command(ctx, "set \"Jello World My DUDE!\"");
			assert(!ctx.state.sniffs->empty());
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto location = (uint8_t *)std::get<2>(mem_location);
				const auto value = std::string((const char *)location);
				assert(location == char_ptr && value == test_str_replace);
			}
		}
	}

	void do_arg_parsing_tests(sniffer::sniffer_context_t & ctx) {
		clear_heap();

		uint64_t * uint_ptr = (uint64_t *)&heap.ptr[1024];
		*uint_ptr = 1;

		uint64_t * uint_ptr2 = (uint64_t *)&heap.ptr[4155];
		*uint_ptr2 = (uint64_t)0 - 1;

		std::string test_string = "Hello World 1";
		uint8_t * char_ptr = (uint8_t *)&heap.ptr[300 * 1024];
		for (auto i = 0; i < test_string.size(); ++i) {
			char_ptr[i] = test_string[i];
		}

		{
			test_reporter_t reporter("find 1 should return no i8/u8/str results");
			execute_test_command(ctx, "find 1");
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto type = std::get<0>(mem_location);
				assert(type != w32::sniff_type_e::i8 && type != w32::sniff_type_e::u8 && type != w32::sniff_type_e::str);
			}
		}

		{
			test_reporter_t reporter("find 1 type i8 should return i8 results");
			execute_test_command(ctx, "find 1 type i8");
			bool has_seen_i8_type = false;
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto type = std::get<0>(mem_location);
				has_seen_i8_type = has_seen_i8_type || type == w32::sniff_type_e::i8;
			}
			assert(has_seen_i8_type);
		}

		{
			test_reporter_t reporter("find 1 type u8 should return u8 results");
			execute_test_command(ctx, "find 1 type u8");
			bool has_seen_u8_type = false;
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto type = std::get<0>(mem_location);
				has_seen_u8_type = has_seen_u8_type || type == w32::sniff_type_e::u8;
			}
			assert(has_seen_u8_type);
		}
		{
			test_reporter_t reporter("find 1 type str should return str results");
			execute_test_command(ctx, "find 1 type str");
			bool has_seen_str_type = false;
			for (const auto & mem_location : get_sniffs(ctx)) {
				const auto type = std::get<0>(mem_location);
				has_seen_str_type = has_seen_str_type || type == w32::sniff_type_e::str;
			}
			assert(has_seen_str_type);
		}
	}

	void do_context_tests(sniffer::sniffer_context_t & ctx) {
		clear_heap();

		uint64_t * uint_ptr = (uint64_t *)&heap.ptr[1024];
		*uint_ptr = 13371337;

		double_t * dbl_ptr = (double_t *)&heap.ptr[6541];
		*dbl_ptr = 1337.1337;

		{
			test_reporter_t reporter("context tmp should switch to new empty context");
			execute_test_command(ctx, "find 13371337");
			execute_test_command(ctx, "context tmp");
			assert(ctx.state.sniffs->empty());
		}

		{
			test_reporter_t reporter("context global should switch back to the old global context");
			execute_test_command(ctx, "context global");
			assert(!ctx.state.sniffs->empty());
		}

		uint64_t * uint_ptr2 = (uint64_t *)&heap.ptr[32054];
		*uint_ptr2 = 13371337;

		{
			test_reporter_t reporter("set should only impact the records on the current context");
			execute_test_command(ctx, "context global");
			execute_test_command(ctx, "set 12341234");

			assert(*uint_ptr == 12341234);
			assert(*uint_ptr2 == 13371337);
			assert(*dbl_ptr == 1337.1337);

			execute_test_command(ctx, "context tmp2");
			execute_test_command(ctx, "find 13371337");
			execute_test_command(ctx, "set 56785678");

			assert(*uint_ptr == 12341234);
			assert(*uint_ptr2 == 56785678);
			assert(*dbl_ptr == 1337.1337);

			execute_test_command(ctx, "context global");
			execute_test_command(ctx, "set 13371337");

			assert(*uint_ptr == 13371337);
			assert(*uint_ptr2 == 56785678);
			assert(*dbl_ptr == 1337.1337);
		}

		{
			test_reporter_t reporter("deleting the current context should select the global context");
			execute_test_command(ctx, "context tmp3");
			assert(ctx.state.sniffs->empty());
			execute_test_command(ctx, "context rm tmp3");
			assert(!ctx.state.sniffs->empty());
		}

		{
			test_reporter_t reporter("the global context should never be able to deleted");
			execute_test_command(ctx, "context global");
			assert(!ctx.state.sniffs->empty());
			execute_test_command(ctx, "context rm global");
			assert(!ctx.state.sniffs->empty());
		}
	}

	void do_pick_remove_undo_tests(sniffer::sniffer_context_t & ctx) {
		clear_heap();

		for (auto i = 0; i < 1024; ++i) {
			uint64_t * uint_ptr = (uint64_t *)&heap.ptr[1024 + 512 * i];
			*uint_ptr = 1;
		}

		{
			test_reporter_t reporter("pick 0 should reduce the sniff results to the first record");
			execute_test_command(ctx, "find 1 type u8");
			assert(!ctx.state.sniffs->empty());
			const auto old_first_sniff = *ctx.state.sniffs->get_locations().begin()->second.begin();
			execute_test_command(ctx, "pick 0");
			assert(ctx.state.sniffs->size() == 1);
			const auto new_first_sniff = *ctx.state.sniffs->get_locations().begin()->second.begin();
			assert(new_first_sniff == old_first_sniff);
		}

		{
			test_reporter_t reporter("pick 0:4 should reduce the sniff results to the first five records");
			execute_test_command(ctx, "find 1 type u8");
			assert(!ctx.state.sniffs->empty());
			auto test_cache = std::vector<std::tuple<w32::sniff_type_e, size_t, uint64_t>>();
			for (const auto sniff : ctx.state.sniffs->get_locations().begin()->second) {
				test_cache.push_back(sniff);
				if (test_cache.size() == 5) {
					break;
				}
			}
			execute_test_command(ctx, "pick 0:4");
			assert(ctx.state.sniffs->size() == 5);
			size_t i = 0;
			for (const auto sniff : ctx.state.sniffs->get_locations().begin()->second) {
				assert(sniff == test_cache[i++]);
				if (i == 5) break;
			}
		}

		{
			test_reporter_t reporter("undo should undo the previous pick command");
			execute_test_command(ctx, "find 1 type u8");
			assert(!ctx.state.sniffs->empty());
			auto old_sniffs_size = ctx.state.sniffs->size();
			execute_test_command(ctx, "pick 0");
			assert(ctx.state.sniffs->size() == 1);
			execute_test_command(ctx, "undo");
			assert(ctx.state.sniffs->size() == old_sniffs_size);
		}

		{
			test_reporter_t reporter("remove 0 should remove the first sniff record");
			execute_test_command(ctx, "find 1 type u8");
			assert(!ctx.state.sniffs->empty());
			auto old_sniffs_size = ctx.state.sniffs->size();
			auto test_cache = std::vector<std::tuple<w32::sniff_type_e, size_t, uint64_t>>();
			for (const auto sniff : ctx.state.sniffs->get_locations().begin()->second) {
				test_cache.push_back(sniff);
				if (test_cache.size() == 1) {
					break;
				}
			}
			execute_test_command(ctx, "remove 0");
			assert(ctx.state.sniffs->size() == old_sniffs_size - 1);
			size_t i = 0;
			for (const auto sniff : ctx.state.sniffs->get_locations().begin()->second) {
				assert(sniff != test_cache[i++]);
				if (i == 1) break;
			}
		}

		{
			test_reporter_t reporter("undo should undo the previous remove command");
			execute_test_command(ctx, "find 1 type u8");
			assert(!ctx.state.sniffs->empty());
			auto old_sniffs_size = ctx.state.sniffs->size();
			execute_test_command(ctx, "remove 0:19");
			assert(ctx.state.sniffs->size() == old_sniffs_size - 20);
			execute_test_command(ctx, "undo");
			assert(ctx.state.sniffs->size() == old_sniffs_size);
		}

		{
			test_reporter_t reporter("remove 0:4 should remove the first five sniff record");
			execute_test_command(ctx, "find 1 type u8");
			assert(!ctx.state.sniffs->empty());
			auto old_sniffs_size = ctx.state.sniffs->size();
			auto test_cache = std::vector<std::tuple<w32::sniff_type_e, size_t, uint64_t>>();
			for (const auto sniff : ctx.state.sniffs->get_locations().begin()->second) {
				test_cache.push_back(sniff);
				if (test_cache.size() == 5) {
					break;
				}
			}
			execute_test_command(ctx, "remove 0:4");
			assert(ctx.state.sniffs->size() == old_sniffs_size - 5);
			size_t i = 0;
			for (const auto sniff : ctx.state.sniffs->get_locations().begin()->second) {
				assert(sniff != test_cache[i++]);
				if (i == 5) break;
			}
		}
	}

	void do_repeat_replace_tests(sniffer::sniffer_context_t & ctx) {
		clear_heap();

		for (auto i = 0; i < 4; ++i) {
			uint64_t * uint_ptr = (uint64_t *)&heap.ptr[1024 + 512 * i];
			*uint_ptr = 1;
		}

		{
			test_reporter_t reporter("repeat 12341234 should set all sniff records on the background thread");
			execute_test_command(ctx, "find 1 type u64");
			assert(!ctx.state.sniffs->empty());
			execute_test_command(ctx, "repeat 12341234");
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			for (auto i = 0; i < 4; ++i) {
				uint64_t * uint_ptr = (uint64_t *)&heap.ptr[1024 + 512 * i];
				assert(*uint_ptr == 12341234);
			}
		}
		{
			test_reporter_t reporter("repeat should keep updating after being changed");
			execute_test_command(ctx, "set 111111111111111111");
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			for (auto i = 0; i < 4; ++i) {
				uint64_t * uint_ptr = (uint64_t *)&heap.ptr[1024 + 512 * i];
				assert(*uint_ptr == 12341234);
			}
		}
		{
			test_reporter_t reporter("repeat clear should stop setting repeat values");
			execute_test_command(ctx, "repeat clear");
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			execute_test_command(ctx, "set 13371337");
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			for (auto i = 0; i < 4; ++i) {
				uint64_t * uint_ptr = (uint64_t *)&heap.ptr[1024 + 512 * i];
				assert(*uint_ptr == 13371337);
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
		tests::do_string_tests(test_ctx);
		tests::do_arg_parsing_tests(test_ctx);
		tests::do_context_tests(test_ctx);
		tests::do_pick_remove_undo_tests(test_ctx);
		tests::do_repeat_replace_tests(test_ctx);
	}

	std::cout << "All tests pass" << std::endl;

	sniffer::cleanup_sniffer_state(test_ctx);

	return 0;
}
