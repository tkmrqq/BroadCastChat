#pragma once

#include "network_utils.h"
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <ctime>
#include <chrono>
#include <random>

class P2PChat {
public:
    static const int BROADCAST_PORT;
    static const int MULTICAST_PORT;
    static const char* MULTICAST_GROUP;
    static const int BROADCAST_INTERVAL;
    static const int PARTICIPANT_TIMEOUT;

    P2PChat();
    ~P2PChat();

    void run();

private:
    void create_broadcast_socket();
    void create_multicast_socket();
    void join_multicast_group();
    void leave_multicast_group();
    void send_broadcast(const std::string& message);
    void send_multicast(const std::string& message);
    void receiver_thread();
    void handle_receive(SocketUtils::SocketHandle sock);
    void heartbeat_thread();
    std::string generate_username();

    SocketUtils::SocketHandle broadcast_sock;
    SocketUtils::SocketHandle multicast_sock;
    std::string local_ip;
    std::string broadcast_ip;
    std::string username;

    std::unordered_set<std::string> ignore_list;
    std::unordered_map<std::string, time_t> participants;
    std::mutex participants_mutex;
    std::mutex ignore_mutex;

    std::atomic<bool> running;
    std::atomic<bool> in_multicast_group;

    std::thread receiver_thread_obj;
    std::thread heartbeat_thread_obj;
};