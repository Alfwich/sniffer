#pragma once

#include <string>
#include <unordered_map>

// Sniffer command literals
enum class sniffer_cmd_e {
	quit,
	undo,
	list,
	find,
	filter,
	remove,
	set,
	pick,
	repeat,
	profile,
	info,
	repeat_remove,
	repeat_list,
	repeat_clear,
	clear,
	context,
	context_list,
	context_remove,
	context_clone,
	set_num_threads,
	set_active_process
};

static const std::unordered_map<sniffer_cmd_e, std::vector<std::string> > sniffer_cmd_to_str{
	{ sniffer_cmd_e::quit, { "quit", "q", "exit" } },
	{ sniffer_cmd_e::undo, { "undo" } },
	{ sniffer_cmd_e::list, { "list", "ls", "l" } },
	{ sniffer_cmd_e::find, { "find", "f" } },
	{ sniffer_cmd_e::filter, { "filter" } },
	{ sniffer_cmd_e::remove, { "remove", "rm" } },
	{ sniffer_cmd_e::set, { "set" } },
	{ sniffer_cmd_e::pick, { "pick" } },
	{ sniffer_cmd_e::profile, { "profile" } },
	{ sniffer_cmd_e::repeat, { "repeat" } },
	{ sniffer_cmd_e::repeat_remove, { "remove", "rm" } },
	{ sniffer_cmd_e::repeat_list, { "list", "ls" } },
	{ sniffer_cmd_e::repeat_clear, { "clear", "cls" } },
	{ sniffer_cmd_e::clear, { "clear", "cls" } },
	{ sniffer_cmd_e::context, { "context", "ctx" } },
	{ sniffer_cmd_e::context_list, { "list", "ls" } },
	{ sniffer_cmd_e::context_remove, { "remove", "rm" } },
	{ sniffer_cmd_e::context_clone, { "clone" } },
	{ sniffer_cmd_e::set_num_threads, { "threads", "j" } },
	{ sniffer_cmd_e::set_active_process, { "load" } },
	{ sniffer_cmd_e::info, { "info" } },
};


