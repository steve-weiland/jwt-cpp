#include "jwt/jwt.hpp"
#include "cmd_args.hpp"
#include <iostream>
#include <fstream>

void printUsage() {
    std::cerr << R"(Usage: jwt++ [options]

Options:
    --version, -v         Show version
    --help, -h            Show this help

Commands (TODO):
    --encode <claims>     Encode claims to JWT
    --decode <jwt>        Decode and display JWT
    --verify <jwt>        Verify JWT signature

Example:
    jwt++ --version

This is a minimal stub. Full functionality will be implemented.
)";
}

int main(int argc, char* argv[]) {
    try {
        auto args = cmd_args::parse(argc, argv);

        if (args.get("version") || args.get("v")) {
            std::cout << "jwt++ version 0.1.0 (bootstrap)\n";
            return 0;
        }

        if (args.get("help") || args.get("h") || argc == 1) {
            printUsage();
            return 0;
        }

        std::cerr << "jwt++ is in bootstrap mode. Full functionality not yet implemented.\n";
        return 1;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
