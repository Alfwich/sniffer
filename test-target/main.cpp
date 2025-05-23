#include <iostream>

#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <vector>
#include <Windows.h>

class test_mem_t {
public:
    int8_t static_int8 = 127;
    int32_t static_int32 = 13371337;
    int64_t static_int64 = 1337133713371337;
    uint8_t static_uint8 = 212;
    uint32_t static_uint32 = 23371337;
    uint64_t static_uint64 = 2337133713371337;
    float_t static_float = 1337.1337f;
    double_t static_double = 13371337.1337;
    std::string static_str = "Hello World!";
};

int main(int argc, char * argv[]) {
    std::vector<test_mem_t> mem;
    mem.resize(5000);

    while (true) {
        const test_mem_t & first = mem.front();
        system("cls");
        std::cout
            << "Static values" << std::setprecision(16)
            << "\n\tstatic_int8 = " << (int32_t)first.static_int8
            << "\n\tstatic_int32 = " << first.static_int32
            << "\n\tstatic_int64 = " << first.static_int64
            << "\n\tstatic_uint8 = " << (int32_t)first.static_uint8
            << "\n\tstatic_uint32 = " << first.static_uint32
            << "\n\tstatic_uint64 = " << first.static_uint64
            << "\n\tstatic_float = " << first.static_float
            << "\n\tstatic_double = " << first.static_double
            << "\n\tstatic_str = " << first.static_str
            << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
