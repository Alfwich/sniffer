#include <iostream>

#include "libsniffer/sniffer.h"

int main(int argc, char * argv[]) {
	sniffer::sniffer_context_t main;
	if (!sniffer::init(argc, argv, main)) {
		std::cout << "Expected usage ./sniffer.exe " << HELP_TEXT << std::endl;
		return -1;
	}

	if (!setup_sniffer_state(main)) {
		std::cout << "Failed to setup global state" << std::endl;
		return -1;
	}

	do {
		if (main.state.is_interactive) {
			if (!sniffer::update_interactive_args(main)) {
				break;
			}
		}
		sniffer::do_pre_workload(main);
		sniffer::do_workload(main);
		sniffer::do_post_workload(main);
		sniffer::report_operation_side_effects(main);
	} while (main.state.is_interactive);

	sniffer::cleanup_sniffer_state(main);

	return 0;
}
