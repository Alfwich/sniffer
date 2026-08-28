#ifdef NDEBUG
#undef NDEBUG
#endif

#include <ostream>
#include <iostream>
#include <sstream>
#include <assert.h>
#include <atomic>
#include <cstring>

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
static uint64_t chunk_size = 0;

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

void execute_test_command_with_records(
	sniffer::sniffer_context_t & ctx,
	std::string cmd,
	const std::vector<w32::memory_region_record_t> & records,
	bool split_records = false) {
	sniffer::update_interactive_args_with_input(ctx, cmd);
	sniffer::do_pre_workload(ctx);
	ctx.state.memory_records = records;
	if (split_records) {
		if (chunk_size > 0) {
			sniffer::split_large_records(ctx.state.memory_records, chunk_size);
		}
		else {
			sniffer::split_large_records(ctx.state.memory_records, 1024 * 1024);
		}
	}
	sniffer::do_workload(ctx);
	sniffer::do_post_workload(ctx);
}

void execute_test_command(sniffer::sniffer_context_t & ctx, std::string cmd) {
	execute_test_command_with_records(ctx, cmd, { get_test_heap_memory_region() }, true);
}

w32::memory_region_record_t make_memory_region_record(void * base, size_t size) {
	auto info = w32::MEMORY_BASIC_INFORMATION();
	w32::VirtualQuery(base, &info, sizeof(info));
	auto record = w32::memory_region_record_t(w32::GetCurrentProcessId(), info);
	record.BaseAddress = base;
	record.RegionSize = size;
	record.is_split_record = false;
	record.is_end_record = true;
	return record;
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

bool has_sniff_at(sniffer::sniffer_context_t & ctx, w32::sniff_type_e type, const void * address) {
	for (const auto & sniff : get_sniffs(ctx)) {
		if (std::get<0>(sniff) == type && std::get<2>(sniff) == reinterpret_cast<uint64_t>(address)) return true;
	}
	return false;
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

	void do_memory_safety_regression_tests(sniffer::sniffer_context_t & ctx) {
		execute_test_command(ctx, "context global");

		{
			clear_heap();
			auto target = &heap.ptr[4096];
			target[-1] = 0xa5;
			target[0] = 212;
			for (size_t i = 1; i <= 8; ++i) target[i] = static_cast<uint8_t>(0xb0 + i);

			test_reporter_t reporter("u8 replacement should not overwrite adjacent target bytes");
			execute_test_command(ctx, "find 212 type u8");
			assert(has_sniff_at(ctx, w32::sniff_type_e::u8, target));
			execute_test_command(ctx, "set 7");
			assert(target[-1] == 0xa5);
			assert(target[0] == 7);
			for (size_t i = 1; i <= 8; ++i) assert(target[i] == static_cast<uint8_t>(0xb0 + i));
		}

		{
			clear_heap();
			auto target = reinterpret_cast<char *>(&heap.ptr[8192]);
			const char original[] = "catGUARD";
			std::memcpy(target, original, sizeof(original));

			test_reporter_t reporter("string replacement longer than the match should be rejected without overwriting its guard");
			execute_test_command(ctx, "find cat type str");
			assert(has_sniff_at(ctx, w32::sniff_type_e::str, target));
			execute_test_command(ctx, "set elephant");
			assert(std::memcmp(target, original, sizeof(original)) == 0);
		}

		w32::SYSTEM_INFO system_info = {};
		w32::GetSystemInfo(&system_info);
		const auto page_size = static_cast<size_t>(system_info.dwPageSize);
		auto guarded_pages = static_cast<uint8_t *>(w32::VirtualAlloc(
			nullptr,
			page_size * 2,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE));
		assert(guarded_pages != nullptr);
		std::memset(guarded_pages, 0, page_size * 2);
		w32::DWORD old_protect = 0;
		assert(w32::VirtualProtect(guarded_pages + page_size, page_size, PAGE_NOACCESS, &old_protect));
		const auto first_page_record = make_memory_region_record(guarded_pages, page_size);

		{
			guarded_pages[page_size - 1] = 127;
			test_reporter_t reporter("u64 search should reject a truncated value at the end of a readable region");
			execute_test_command_with_records(ctx, "find 127 type u64", { first_page_record });
			assert(!has_sniff_at(ctx, w32::sniff_type_e::u64, guarded_pages + page_size - 1));
		}

		{
			std::memset(guarded_pages, 0, page_size);
			const std::string exact_end = "END!";
			auto target = guarded_pages + page_size - exact_end.size();
			std::memcpy(target, exact_end.data(), exact_end.size());
			test_reporter_t reporter("string search should include a match ending exactly at the readable-region boundary");
			execute_test_command_with_records(ctx, "find END! type str", { first_page_record });
			assert(has_sniff_at(ctx, w32::sniff_type_e::str, target));
		}

		{
			guarded_pages[0] = 42;
			ctx.state.sniffs->clear();
			ctx.state.sniffs->value.set_value("42");
			ctx.state.sniffs->set_location(w32::sniff_type_e::u8, w32::GetCurrentProcessId(), reinterpret_cast<uint64_t>(guarded_pages));
			ctx.state.sniffs->set_location(w32::sniff_type_e::u8, w32::GetCurrentProcessId(), reinterpret_cast<uint64_t>(guarded_pages + page_size));

			test_reporter_t reporter("filter should discard an unreadable result instead of reusing bytes from the prior result");
			const auto saved_thread_count = ctx.state.num_threads;
			ctx.state.num_threads = 1;
			execute_test_command_with_records(ctx, "filter 42 type u8 pred eq", {});
			ctx.state.num_threads = saved_thread_count;
			assert(ctx.state.sniffs->size() == 1);
			assert(has_sniff_at(ctx, w32::sniff_type_e::u8, guarded_pages));
		}

		assert(w32::VirtualFree(guarded_pages, 0, MEM_RELEASE));

		{
			clear_heap();
			auto low = reinterpret_cast<uint32_t *>(&heap.ptr[12288]);
			auto high = reinterpret_cast<uint32_t *>(&heap.ptr[12320]);
			*low = 5;
			*high = 10;
			ctx.state.sniffs->clear();
			ctx.state.sniffs->value.set_value("0");
			ctx.state.sniffs->set_location(w32::sniff_type_e::u32, w32::GetCurrentProcessId(), reinterpret_cast<uint64_t>(low));
			ctx.state.sniffs->set_location(w32::sniff_type_e::u32, w32::GetCurrentProcessId(), reinterpret_cast<uint64_t>(high));

			test_reporter_t reporter("filter lt should compare memory on the left side of the predicate");
			execute_test_command_with_records(ctx, "filter 10 type u32 pred lt", {});
			assert(ctx.state.sniffs->size() == 1);
			assert(has_sniff_at(ctx, w32::sniff_type_e::u32, low));
		}

		{
			clear_heap();
			auto target = reinterpret_cast<int32_t *>(&heap.ptr[16384]);
			*target = -5;

			test_reporter_t reporter("signed find predicates should preserve negative ordering");
			execute_test_command(ctx, "find 0 type i32 pred lt");
			assert(has_sniff_at(ctx, w32::sniff_type_e::i32, target));
			execute_test_command(ctx, "find -5 type i32 pred eq");
			assert(has_sniff_at(ctx, w32::sniff_type_e::i32, target));
		}

		{
			clear_heap();
			auto different = reinterpret_cast<char *>(&heap.ptr[20480]);
			auto equal = reinterpret_cast<char *>(&heap.ptr[20512]);
			std::memcpy(different, "cat", 3);
			std::memcpy(equal, "car", 3);
			ctx.state.sniffs->clear();
			ctx.state.sniffs->value.set_value("cat");
			ctx.state.sniffs->set_location(w32::sniff_type_e::str, w32::GetCurrentProcessId(), reinterpret_cast<uint64_t>(different));
			ctx.state.sniffs->set_location(w32::sniff_type_e::str, w32::GetCurrentProcessId(), reinterpret_cast<uint64_t>(equal));

			test_reporter_t reporter("string ne filtering should compare the whole string rather than require every byte to differ");
			execute_test_command_with_records(ctx, "filter car type str pred ne", {});
			assert(ctx.state.sniffs->size() == 1);
			assert(has_sniff_at(ctx, w32::sniff_type_e::str, different));
		}

		{
			auto protected_page = static_cast<uint8_t *>(w32::VirtualAlloc(
				nullptr,
				page_size,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_READWRITE));
			assert(protected_page != nullptr);
			std::memset(protected_page, 0, page_size);
			w32::DWORD previous_protect = 0;
			assert(w32::VirtualProtect(protected_page, page_size, PAGE_READONLY, &previous_protect));

			test_reporter_t reporter("concurrent writes should restore the original target-page protection");
			std::atomic<bool> writes_succeeded(true);
			std::vector<std::thread> writers;
			for (size_t i = 0; i < 8; ++i) {
				writers.emplace_back([protected_page, i, &writes_succeeded]() {
					const uint8_t value = static_cast<uint8_t>(i + 1);
					for (size_t attempt = 0; attempt < 32; ++attempt) {
						if (!w32::set_bytes_at_location_for_pid(
							w32::GetCurrentProcessId(),
							reinterpret_cast<uint64_t>(protected_page + i),
							&value,
							sizeof(value))) {
							writes_succeeded = false;
						}
					}
				});
			}
			for (auto & writer : writers) writer.join();
			assert(writes_succeeded);

			auto page_info = w32::MEMORY_BASIC_INFORMATION();
			assert(w32::VirtualQuery(protected_page, &page_info, sizeof(page_info)) == sizeof(page_info));
			assert((page_info.Protect & 0xff) == PAGE_READONLY);
			for (size_t i = 0; i < 8; ++i) assert(protected_page[i] == static_cast<uint8_t>(i + 1));
			assert(w32::VirtualFree(protected_page, 0, MEM_RELEASE));
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

	for (size_t i = 0; i < 2; ++i) {
		chunk_size = i * 4096;
		tests::do_simple_tests(test_ctx);
		tests::do_multi_tests(test_ctx);
		tests::do_boundary_tests(test_ctx);
		tests::do_string_tests(test_ctx);
		tests::do_arg_parsing_tests(test_ctx);
		tests::do_context_tests(test_ctx);
		tests::do_pick_remove_undo_tests(test_ctx);
		tests::do_repeat_replace_tests(test_ctx);
		tests::do_memory_safety_regression_tests(test_ctx);
	}

	std::cout << "All tests pass" << std::endl;

	sniffer::cleanup_sniffer_state(test_ctx);

	return 0;
}
