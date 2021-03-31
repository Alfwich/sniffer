#pragma once

constexpr auto SNIFF_FILE_DELIM = "|";
constexpr auto SNIFF_GLOBAL_CONTEXT = "global";
constexpr auto HELP_TEXT = "[sniff|resniff|replace|update|interactive] -pname \"process_name\" -spred [gt|lt|eq|ne] -stype [i8|i32|i64|u8|u32|u64|f32|f64|str] -find \"value_to_sniff_or_resniff_on\" -set \"value_to_set\" -j [num threads to use] -sf \"out_file_name\"";
constexpr auto INTERACTIVE_HELP_TEXT = "[list|undo|clear|context]";
constexpr auto RPM_CHUNK_READ_SIZE = 4096;
constexpr auto MEM_REGION_NUM_PAGES = 3;
constexpr auto DEFAULT_THREADS = "12";
