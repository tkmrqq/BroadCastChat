#include "p2p_chat.h"
#include <iostream>
#include <cstring>
#include <algorithm>
//#include <sys/select.h>

const int P2PChat::BROADCAST_PORT = 37020;
const int P2PChat::MULTICAST_PORT = 37021;
const char* P2PChat::MULTICAST_GROUP = "239.255.255.250";
const int P2PChat::BROADCAST_INTERVAL = 5;
const int P2PChat::PARTICIPANT_TIMEOUT = 15;

P2PChat::P2PChat() :
                     broadcast_sock(SocketUtils::INVALID_SOCKET_HANDLE),
                     multicast_sock(SocketUtils::INVALID_SOCKET_HANDLE),
                     running(true),
                     in_multicast_group(true) {

    SocketUtils::init();
    NetworkInfo net_info = SocketUtils::get_network_info();
    local_ip = net_info.local_ip;
    broadcast_ip = net_info.broadcast_ip;
    username = generate_username();

    create_broadcast_socket();
    create_multicast_socket();
}

P2PChat::~P2PChat() {
    running = false;

    if (receiver_thread_obj.joinable()) receiver_thread_obj.join();
    if (heartbeat_thread_obj.joinable()) heartbeat_thread_obj.join();

    SocketUtils::close_socket(broadcast_sock);
    SocketUtils::close_socket(multicast_sock);
    SocketUtils::cleanup();
}

std::string P2PChat::generate_username() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    return "User-" + std::to_string(dis(gen));
}

void P2PChat::create_broadcast_socket() {
    broadcast_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (broadcast_sock == SocketUtils::INVALID_SOCKET_HANDLE) {
        throw std::runtime_error("Failed to create broadcast socket");
    }

    int broadcast_enable = 1;
    if (!SocketUtils::set_socket_option(
                broadcast_sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable))) {
        throw std::runtime_error("Failed to set SO_BROADCAST");
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(BROADCAST_PORT);

    if (bind(broadcast_sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        throw std::runtime_error("Failed to bind broadcast socket");
    }
}

void P2PChat::create_multicast_socket() {
    multicast_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (multicast_sock == SocketUtils::INVALID_SOCKET_HANDLE) {
        throw std::runtime_error("Failed to create multicast socket");
    }

    int reuse = 1;
    if (!SocketUtils::set_socket_option(
                multicast_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        throw std::runtime_error("Failed to set SO_REUSEADDR");
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(MULTICAST_PORT);

    if (bind(multicast_sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        throw std::runtime_error("Failed to bind multicast socket");
    }

    join_multicast_group();
}

void P2PChat::join_multicast_group() {
    if (in_multicast_group) return;

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
    mreq.imr_interface.s_addr = inet_addr(local_ip.c_str());

    if (!SocketUtils::set_socket_option(
                multicast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
        throw std::runtime_error("Failed to join multicast group");
    }

    in_multicast_group = true;
}

void P2PChat::leave_multicast_group() {
    if (!in_multicast_group) return;

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
    mreq.imr_interface.s_addr = inet_addr(local_ip.c_str());

    if (!SocketUtils::set_socket_option(
                multicast_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq))) {
        throw std::runtime_error("Failed to leave multicast group");
    }

    in_multicast_group = false;
}

void P2PChat::send_broadcast(const std::string& message) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BROADCAST_PORT);
    addr.sin_addr.s_addr = inet_addr(broadcast_ip.c_str());

#ifdef _WIN32
    sendto(broadcast_sock, message.c_str(), static_cast<int>(message.size()), 0,
           reinterpret_cast<SOCKADDR*>(&addr), sizeof(addr));
#else
    sendto(broadcast_sock, message.c_str(), message.size(), 0,
           reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
#endif
}

void P2PChat::send_multicast(const std::string& message) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MULTICAST_PORT);
    addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);

#ifdef _WIN32
    sendto(multicast_sock, message.c_str(), static_cast<int>(message.size()), 0,
           reinterpret_cast<SOCKADDR*>(&addr), sizeof(addr));
#else
    sendto(multicast_sock, message.c_str(), message.size(), 0,
           reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
#endif
}

void P2PChat::receiver_thread() {
    while (running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(broadcast_sock, &read_fds);
        FD_SET(multicast_sock, &read_fds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int max_fd = std::max(broadcast_sock, multicast_sock);
        int ret = select(max_fd + 1, &read_fds, nullptr, nullptr, &tv);

        if (ret < 0) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        if (FD_ISSET(broadcast_sock, &read_fds)) {
            handle_receive(broadcast_sock);
        }

        if (FD_ISSET(multicast_sock, &read_fds)) {
            handle_receive(multicast_sock);
        }
    }
}

void P2PChat::handle_receive(SocketUtils::SocketHandle sock) {
    char buffer[1024];
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    ssize_t len = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                           reinterpret_cast<struct sockaddr*>(&sender_addr), &addr_len);
    if (len <= 0) return;

    buffer[len] = '\0';
    std::string ip = inet_ntoa(sender_addr.sin_addr);
    std::string message(buffer, len);

    // Check ignore list
    {
        std::lock_guard<std::mutex> lock(ignore_mutex);
        if (ignore_list.find(ip) != ignore_list.end() || ip == local_ip) {
            return;
        }
    }

    // Handle HELLO messages
    if (message.substr(0, 5) == "HELLO") {
        std::lock_guard<std::mutex> lock(participants_mutex);
        participants[ip] = time(nullptr);
    }
    // Handle regular messages
    else if (message.substr(0, 3) == "MSG") {
        std::lock_guard<std::mutex> lock(participants_mutex);
        participants[ip] = time(nullptr);

        std::cout << "\n[" << ip << "]: " << message.substr(4) << std::endl;
        std::cout << "> " << std::flush;
    }
}

void P2PChat::heartbeat_thread() {
    while (running) {
        // Send HELLO message
        std::string hello_msg = "HELLO " + username;
        send_broadcast(hello_msg);

        // Cleanup inactive participants
        {
            std::lock_guard<std::mutex> lock(participants_mutex);
            time_t now = time(nullptr);
            for (auto it = participants.begin(); it != participants.end(); ) {
                if (now - it->second > PARTICIPANT_TIMEOUT) {
                    it = participants.erase(it);
                } else {
                    ++it;
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(BROADCAST_INTERVAL));
    }
}

void P2PChat::run() {
    std::cout << "=== Cross-platform P2P Chat ===" << std::endl;
    std::cout << "Local IP: " << local_ip << std::endl;
    std::cout << "Broadcast IP: " << broadcast_ip << std::endl;
    std::cout << "Username: " << username << std::endl;
    std::cout << "Commands: /join, /leave, /ignore [IP], /list, /exit" << std::endl;
    std::cout << "=================================" << std::endl;

    // Start threads
    receiver_thread_obj = std::thread(&P2PChat::receiver_thread, this);
    heartbeat_thread_obj = std::thread(&P2PChat::heartbeat_thread, this);

    // Main command loop
    while (running) {
        std::cout << "> " << std::flush;
        std::string input;
        std::getline(std::cin, input);

        if (input.empty()) continue;

        // Command processing
        if (input == "/join") {
            join_multicast_group();
            std::cout << "Joined multicast group" << std::endl;
        }
        else if (input == "/leave") {
            leave_multicast_group();
            std::cout << "Left multicast group" << std::endl;
        }
        else if (input.find("/ignore ") == 0) {
            std::string ip = input.substr(8);
            std::lock_guard<std::mutex> lock(ignore_mutex);
            ignore_list.insert(ip);
            std::cout << "Ignoring host: " << ip << std::endl;
        }
        else if (input == "/list") {
            std::lock_guard<std::mutex> lock(participants_mutex);
            std::cout << "\nActive participants (" << participants.size() << "):" << std::endl;
            for (const auto& p : participants) {
                time_t last_active = time(nullptr) - p.second;
                std::cout << " - " << p.first << " (active " << last_active << "s ago)" << std::endl;
            }
            std::cout << std::endl;
        }
        else if (input == "/exit") {
            running = false;
        }
        else {
            // Send regular message
            std::string msg = "MSG " + input;

            if (in_multicast_group) {
                send_multicast(msg);
            }
            send_broadcast(msg);
        }
    }

    // Stop threads
    if (receiver_thread_obj.joinable()) receiver_thread_obj.join();
    if (heartbeat_thread_obj.joinable()) heartbeat_thread_obj.join();
}