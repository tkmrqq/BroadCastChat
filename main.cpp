#include "cpp/core/p2p_chat.h"
#include <iostream>

int main() {
    try {
        P2PChat chat;
        chat.run();
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}