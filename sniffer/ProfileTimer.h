#pragma once

#include <iostream>
#include <chrono>

class ProfileTimer {
    const char * label;
    long long start, end;
    bool started = true;

    long long getCurrentMicroseconds() {
        auto now = std::chrono::system_clock::now();
        auto time = now.time_since_epoch().count();
        return std::chrono::microseconds(time).count();
    }

    void report() {
        std::cout << label << " took " << (end - start) / 10000.0 << "(ms)" << std::endl;
    }

public:
    ProfileTimer() : label(0), start(getCurrentMicroseconds()) {}
    ProfileTimer(const char * label) : label(label), start(getCurrentMicroseconds()) {}
    ~ProfileTimer() { stop(); }

    void stop() {
        if (started) {
            end = getCurrentMicroseconds();
            started = false;

            report();
        }
    }
};

