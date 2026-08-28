#pragma once

constexpr auto SNIFF_FILE_DELIM = "|";
constexpr auto SNIFF_GLOBAL_CONTEXT = "global";
constexpr auto HELP_TEXT = "[find|filter|replace|interactive] -pname \"process_name\" -spred [gt|lt|eq|ne] -stype [i8|i32|i64|u8|u32|u64|f32|f64|str] -find \"value_to_sniff_or_resniff_on\" -set \"value_to_set\" -j [num threads to use] -sf \"out_file_name\"";
constexpr auto WIN_MEM_FREE = 0x10000;
constexpr auto NUM_PAGES_TO_BUFFER = 1024;
