#pragma once

#include <iostream>
#include <chrono>
#include <map>
#include <mutex>
#include <thread>

class TimerContext {
public:
	uint64_t time = 0;
	std::mutex timer_mutex;

	void addTime(uint64_t time) {
		std::lock_guard<std::mutex> stack_lock(timer_mutex);
		this->time += time;
	}
};

static std::map<uint8_t, TimerContext> contexts;

class ProfileTimer {
	uint8_t context = 0;
	long long start, end;
	bool started = true;
	const char * label;

	long long getCurrentMicroseconds() {
		auto now = std::chrono::system_clock::now();
		auto time = now.time_since_epoch().count();
		return std::chrono::microseconds(time).count();
	}

	void report() {
		if (context > 0) {
			contexts[context].addTime(end - start);
		}
		else {
			std::cout << label << " took " << (end - start) / 10000.0 << "(ms)" << std::endl;
		}
	}

public:
	ProfileTimer() : label(""), context(0), start(getCurrentMicroseconds()) {}
	ProfileTimer(uint8_t context) : label(""), context(context), start(getCurrentMicroseconds()) {}
	ProfileTimer(const char * label) : label(label), context(0), start(getCurrentMicroseconds()) {}
	~ProfileTimer() { stop(); }

	static void ReportAllContexts() {
		for (const auto & context_to_time : contexts) {
			std::cout << " context " << (int32_t)context_to_time.first << " took " << (context_to_time.second.time / 10000.0) << "(ms)" << std::endl;
		}
		contexts.clear();
	}

	void stop() {
		if (started) {
			end = getCurrentMicroseconds();
			started = false;

			report();
		}
	}
};
