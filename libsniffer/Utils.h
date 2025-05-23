#pragma once


class indicies_t {
public:
	uint64_t start_index = 0;
	uint64_t end_index = 0;
};


static inline void left_trim(std::string & s) {
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
		return !std::isspace(ch);
	}));
}

static inline void right_trim(std::string & s) {
	s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
		return !std::isspace(ch);
	}).base(), s.end());
}

static inline void trim(std::string & s) {
	left_trim(s);
	right_trim(s);
}
