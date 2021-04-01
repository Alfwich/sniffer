#pragma once

#include <unordered_map>
#include <string>

namespace {
	static const std::string default_str = "";
}

class SnifferArgs {
	std::unordered_map<std::string, std::string> arg_map;
	std::vector<std::string> arg_words;
public:
	SnifferArgs() {}
	SnifferArgs(const std::unordered_map<std::string, std::string> & in_args) : arg_map(in_args) {}
	SnifferArgs(const std::unordered_map<std::string, std::string> & in_args, const std::vector<std::string> & in_words) : arg_map(in_args), arg_words(in_words) {}
	bool checkArgs() {
		static std::unordered_map <std::string, std::vector<std::string> > required = {
			{ "action", { "sniff", "replace", "resniff", "update", "interactive", "list" } },
			{ "pname", { "*" } },
		};

		for (const auto & required_pair : required) {
			const auto & key = required_pair.first;
			const auto & value_array = required_pair.second;

			bool has_match = false;
			for (const auto & test_value : value_array) {
				has_match = test_value == "*" || has_match || (arg_map.count(key) > 0 && arg_map.at(key) == test_value);
			}

			if (!has_match) {
				return false;
			}
		}

		return true;
	}

	void updateArgMapAndArgWords(std::unordered_map<std::string, std::string> & new_arg_map, std::vector<std::string> & new_arg_words) {
		arg_map = new_arg_map;
		arg_words = new_arg_words;
	}

	std::string getArg(const char * key, const std::string & def = default_str) const {
		if (arg_map.count(key) > 0) {
			return arg_map.at(key);
		}

		return default_str;
	}

	std::string at(std::vector<std::string> args) const {
		return getFirstArg(args);
	}

	std::string at(const char * key) const {
		return getArg(key);
	}

	std::string at(const char * key, const char * def) const {
		return count(key) > 0
			? at(key)
			: def;
	}

	std::string at(const char * key, std::string def) const {
		return at(key, def.c_str());
	}

	size_t size() const {
		return arg_map.size();
	}

	size_t count(const char * key) const {
		return at(key).size() > 0;
	}

	size_t count(std::vector<std::string> args) const {
		return getFirstArg(args).size() > 0;
	}

	bool empty() {
		return size() == 0;
	}

	std::string getFirstArg(std::vector<std::string> strs, const std::string & def = default_str) const {
		for (const auto key : strs) {
			if (arg_map.count(key) > 0) {
				return arg_map.at(key);
			}
		}

		return default_str;
	}

	std::string getArgAtIndex(uint32_t index) const {
		if (index < arg_words.size()) {
			return arg_words.at(index);
		}

		return default_str;
	}

	bool actionIs(std::string action) const {
		return actionIsOneOf({ action });
	}

	bool actionIsOneOf(std::vector<std::string> actions) const {
		bool result = false;
		const auto action_string = getAction();

		for (const auto & action : actions) {
			result = result || action == action_string;
		}

		return result;
	}

	bool contextIs(std::string context) const {
		return contextIsOneOf({ context });
	}

	bool contextIsOneOf(std::vector<std::string> contexts) const {
		bool result = false;
		const auto context_string = getContext();

		for (const auto & context : contexts) {
			result = result || context == context_string;
		}

		return result;
	}

	std::string getAction() const {
		return at("action");
	}

	std::string getContext(std::string def = "") const {
		const auto result = at("ctx_param", getArgAtIndex(1));
		return result.empty() ? def : result;
	}
};
