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
	take,
	repeat,
	repeat_remove,
	repeat_list,
	repeat_clear,
	clear,
	context,
	context_list,
	context_remove,
	context_clone,
};

static const std::unordered_map<sniffer_cmd_e, std::vector<std::string> > sniffer_cmd_to_str{
	{ sniffer_cmd_e::quit, { "quit", "q", "exit" } },
	{ sniffer_cmd_e::undo, { "undo" } },
	{ sniffer_cmd_e::list, { "list", "ls", "l" } },
	{ sniffer_cmd_e::find, { "find", "f" } },
	{ sniffer_cmd_e::filter, { "filter" } },
	{ sniffer_cmd_e::remove, { "remove", "rm" } },
	{ sniffer_cmd_e::set, { "set" } },
	{ sniffer_cmd_e::take, { "take" } },
	{ sniffer_cmd_e::repeat, { "repeat" } },
	{ sniffer_cmd_e::repeat_remove, { "remove", "rm" } },
	{ sniffer_cmd_e::repeat_list, { "list", "ls" } },
	{ sniffer_cmd_e::repeat_clear, { "clear", "cls" } },
	{ sniffer_cmd_e::clear, { "clear", "cls" } },
	{ sniffer_cmd_e::context, { "context", "ctx" } },
	{ sniffer_cmd_e::context_list, { "list", "ls" } },
	{ sniffer_cmd_e::context_remove, { "remove", "rm" } },
	{ sniffer_cmd_e::context_clone, { "clone" } },
};


