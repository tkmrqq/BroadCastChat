#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <random>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <netdb.h>
#endif

// Конфигурация программы
const int BROADCAST_PORT = 37020;
const int MULTICAST_PORT = 37021;
const char* MULTICAST_GROUP = "239.255.255.250";
const int BROADCAST_INTERVAL = 5;
const int PARTICIPANT_TIMEOUT = 15;

class P2PChat {
private:
#ifdef _WIN32
    SOCKET broadcast_sock;
    SOCKET multicast_sock;
    WSADATA wsaData;
#else
    int broadcast_sock;
    int multicast_sock;
#endif
    std::string local_ip;
    std::string broadcast_ip;
    std::string username;

    std::unordered_set<std::string> ignore_list;
    std::unordered_map<std::string, time_t> participants;
    std::mutex participants_mutex;
    std::mutex ignore_mutex;

    std::atomic<bool> running;
    std::atomic<bool> in_multicast_group;

    // Генерация случайного имени пользователя
    std::string generate_username() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000, 9999);
        return "User-" + std::to_string(dis(gen));
    }

public:
    P2PChat() : running(true), in_multicast_group(true) {
#ifdef _WIN32
        // Инициализация Winsock
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
            exit(EXIT_FAILURE);
        }
#endif

        // Определение сетевых параметров
        get_network_info();
        username = generate_username();

        // Создание сокетов
        create_broadcast_socket();
        create_multicast_socket();
    }

    ~P2PChat() {
        running = false;

        // Закрытие сокетов
#ifdef _WIN32
        closesocket(broadcast_sock);
        closesocket(multicast_sock);
        WSACleanup();
#else
        close(broadcast_sock);
        close(multicast_sock);
#endif
    }

    void get_network_info() {
        local_ip = "127.0.0.1";
        broadcast_ip = "255.255.255.255";

#ifdef _WIN32
        PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
        ULONG outBufLen = 0;
        DWORD dwRetVal = 0;

        // Получаем размер буфера
        GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (!pAddresses) {
            std::cerr << "Memory allocation failed for IP_ADAPTER_ADDRESSES struct" << std::endl;
            return;
        }

        dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
        if (dwRetVal != ERROR_SUCCESS) {
            std::cerr << "GetAdaptersAddresses failed with error: " << dwRetVal << std::endl;
            free(pAddresses);
            return;
        }

        // Итерируем по сетевым адаптерам
        for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; pCurrAddresses; pCurrAddresses = pCurrAddresses->Next) {
            // Пропускаем loopback и неактивные адаптеры
            if (pCurrAddresses->OperStatus != IfOperStatusUp ||
                pCurrAddresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
                continue;
            }

            // Итерируем по IP-адресам адаптера
            for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);

                    // Предпочитаем нелокальные адреса
                    if (strcmp(ip_str, "127.0.0.1") != 0) {
                        local_ip = ip_str;

                        // Рассчитываем broadcast адрес
                        IP_ADAPTER_INFO adapterInfo;
                        ULONG adapterInfoSize = sizeof(adapterInfo);
                        if (GetAdaptersInfo(&adapterInfo, &adapterInfoSize) == ERROR_SUCCESS) {
                            for (PIP_ADAPTER_INFO pAdapter = &adapterInfo; pAdapter; pAdapter = pAdapter->Next) {
                                if (strcmp(pAdapter->IpAddressList.IpAddress.String, local_ip.c_str()) == 0) {
                                    broadcast_ip = pAdapter->IpAddressList.IpMask.String;

                                    // Рассчет broadcast адреса
                                    in_addr local, mask, broadcast;
                                    inet_pton(AF_INET, local_ip.c_str(), &local);
                                    inet_pton(AF_INET, broadcast_ip.c_str(), &mask);
                                    broadcast.s_addr = local.s_addr | ~mask.s_addr;

                                    char broadcast_str[INET_ADDRSTRLEN];
                                    inet_ntop(AF_INET, &broadcast, broadcast_str, INET_ADDRSTRLEN);
                                    broadcast_ip = broadcast_str;
                                    break;
                                }
                            }
                        }
                        free(pAddresses);
                        return;
                    }
                }
            }
        }
        free(pAddresses);
#else
        struct ifaddrs* ifaddr;
        if (getifaddrs(&ifaddr) {
            perror("getifaddrs");
            return;
        }

        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
                continue;

            // Пропускаем loopback интерфейс
            std::string ifname(ifa->ifa_name);
            if (ifname == "lo")
                continue;

            struct sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
            local_ip = inet_ntoa(addr->sin_addr);

            struct sockaddr_in* mask = reinterpret_cast<sockaddr_in*>(ifa->ifa_netmask);
            struct sockaddr_in* bcast = reinterpret_cast<sockaddr_in*>(ifa->ifa_broadaddr);

            // Вычисление broadcast адреса
            if (bcast) {
                broadcast_ip = inet_ntoa(bcast->sin_addr);
            } else if (mask) {
                uint32_t ip = ntohl(addr->sin_addr.s_addr);
                uint32_t netmask = ntohl(mask->sin_addr.s_addr);
                uint32_t broadcast = ip | ~netmask;
                struct in_addr baddr;
                baddr.s_addr = htonl(broadcast);
                broadcast_ip = inet_ntoa(baddr);
            }
            break;
        }
        freeifaddrs(ifaddr);
#endif
    }

    void create_broadcast_socket() {
#ifdef _WIN32
        broadcast_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (broadcast_sock == INVALID_SOCKET) {
            std::cerr << "socket failed: " << WSAGetLastError() << std::endl;
            exit(EXIT_FAILURE);
        }

        // Настройка опции широковещания
        BOOL broadcast_enable = TRUE;
        if (setsockopt(broadcast_sock, SOL_SOCKET, SO_BROADCAST,
                       (char*)&broadcast_enable, sizeof(broadcast_enable)) == SOCKET_ERROR) {
            std::cerr << "setsockopt SO_BROADCAST failed: " << WSAGetLastError() << std::endl;
            exit(EXIT_FAILURE);
        }
#else
        broadcast_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (broadcast_sock < 0) {
            perror("socket");
            exit(EXIT_FAILURE);
        }

        int broadcast_enable = 1;
        if (setsockopt(broadcast_sock, SOL_SOCKET, SO_BROADCAST,
                       &broadcast_enable, sizeof(broadcast_enable))) {
            perror("setsockopt SO_BROADCAST");
            exit(EXIT_FAILURE);
        }
#endif

        // Привязка сокета
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(BROADCAST_PORT);

#ifdef _WIN32
        if (bind(broadcast_sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            std::cerr << "bind broadcast failed: " << WSAGetLastError() << std::endl;
            exit(EXIT_FAILURE);
        }
#else
        if (bind(broadcast_sock, (struct sockaddr*)&addr, sizeof(addr))) {
            perror("bind broadcast");
            exit(EXIT_FAILURE);
        }
#endif
    }

    void create_multicast_socket() {
#ifdef _WIN32
        multicast_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (multicast_sock == INVALID_SOCKET) {
            std::cerr << "socket multicast failed: " << WSAGetLastError() << std::endl;
            exit(EXIT_FAILURE);
        }

        // Настройка повторного использования адреса
        BOOL reuse = TRUE;
        if (setsockopt(multicast_sock, SOL_SOCKET, SO_REUSEADDR,
                       (char*)&reuse, sizeof(reuse)) == SOCKET_ERROR) {
            std::cerr << "setsockopt SO_REUSEADDR failed: " << WSAGetLastError() << std::endl;
        }
#else
        multicast_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (multicast_sock < 0) {
            perror("socket multicast");
            exit(EXIT_FAILURE);
        }

        int reuse = 1;
        if (setsockopt(multicast_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
            perror("setsockopt SO_REUSEADDR");
            exit(EXIT_FAILURE);
        }
#endif

        // Привязка сокета
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(MULTICAST_PORT);

#ifdef _WIN32
        if (bind(multicast_sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            std::cerr << "bind multicast failed: " << WSAGetLastError() << std::endl;
            exit(EXIT_FAILURE);
        }
#else
        if (bind(multicast_sock, (struct sockaddr*)&addr, sizeof(addr))) {
            perror("bind multicast");
            exit(EXIT_FAILURE);
        }
#endif

        // Присоединение к multicast группе
        join_multicast_group();
    }

    void join_multicast_group() {
        if (in_multicast_group) return;

        struct ip_mreq mreq;
        mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
        mreq.imr_interface.s_addr = inet_addr(local_ip.c_str());

#ifdef _WIN32
        if (setsockopt(multicast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       (char*)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
            std::cerr << "setsockopt IP_ADD_MEMBERSHIP failed: " << WSAGetLastError() << std::endl;
            return;
        }
#else
        if (setsockopt(multicast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       &mreq, sizeof(mreq))) {
            perror("setsockopt IP_ADD_MEMBERSHIP");
            return;
        }
#endif

        in_multicast_group = true;
    }

    void leave_multicast_group() {
        if (!in_multicast_group) return;

        struct ip_mreq mreq;
        mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
        mreq.imr_interface.s_addr = inet_addr(local_ip.c_str());

#ifdef _WIN32
        if (setsockopt(multicast_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                       (char*)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
            std::cerr << "setsockopt IP_DROP_MEMBERSHIP failed: " << WSAGetLastError() << std::endl;
            return;
        }
#else
        if (setsockopt(multicast_sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                       &mreq, sizeof(mreq))) {
            perror("setsockopt IP_DROP_MEMBERSHIP");
            return;
        }
#endif

        in_multicast_group = false;
    }

    void send_broadcast(const std::string& message) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(BROADCAST_PORT);
        addr.sin_addr.s_addr = inet_addr(broadcast_ip.c_str());

#ifdef _WIN32
        sendto(broadcast_sock, message.c_str(), static_cast<int>(message.size()), 0,
               (SOCKADDR*)&addr, sizeof(addr));
#else
        sendto(broadcast_sock, message.c_str(), message.size(), 0,
               (struct sockaddr*)&addr, sizeof(addr));
#endif
    }

    void send_multicast(const std::string& message) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(MULTICAST_PORT);
        addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);

#ifdef _WIN32
        sendto(multicast_sock, message.c_str(), static_cast<int>(message.size()), 0,
               (SOCKADDR*)&addr, sizeof(addr));
#else
        sendto(multicast_sock, message.c_str(), message.size(), 0,
               (struct sockaddr*)&addr, sizeof(addr));
#endif
    }

    void receiver_thread() {
        while (running) {
            fd_set read_fds;
            FD_ZERO(&read_fds);

#ifdef _WIN32
            FD_SET(broadcast_sock, &read_fds);
            FD_SET(multicast_sock, &read_fds);

            timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int ret = select(0, &read_fds, nullptr, nullptr, &tv);
            if (ret == SOCKET_ERROR) {
                std::cerr << "select failed: " << WSAGetLastError() << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
#else
            FD_SET(broadcast_sock, &read_fds);
            FD_SET(multicast_sock, &read_fds);

            int max_fd = std::max(broadcast_sock, multicast_sock);
            timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int ret = select(max_fd + 1, &read_fds, nullptr, nullptr, &tv);
            if (ret < 0) {
                perror("select");
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
#endif

            if (FD_ISSET(broadcast_sock, &read_fds)) {
                handle_receive(broadcast_sock);
            }

            if (FD_ISSET(multicast_sock, &read_fds)) {
                handle_receive(multicast_sock);
            }
        }
    }

    void handle_receive(int sock) {
        char buffer[1024];
        struct sockaddr_in sender_addr;
        socklen_t addr_len = sizeof(sender_addr);

#ifdef _WIN32
        int len = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                           (SOCKADDR*)&sender_addr, &addr_len);
        if (len == SOCKET_ERROR) {
            std::cerr << "recvfrom failed: " << WSAGetLastError() << std::endl;
            return;
        }
#else
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                               (struct sockaddr*)&sender_addr, &addr_len);
        if (len <= 0) return;
#endif

        buffer[len] = '\0';
        std::string ip = inet_ntoa(sender_addr.sin_addr);
        std::string message(buffer, len);

        // Проверка игнорируемых IP
        {
            std::lock_guard<std::mutex> lock(ignore_mutex);
            if (ignore_list.find(ip) != ignore_list.end() || ip == local_ip) {
                return;
            }
        }

        // Обработка HELLO-сообщений
        if (message.substr(0, 5) == "HELLO") {
            std::lock_guard<std::mutex> lock(participants_mutex);
            participants[ip] = time(nullptr);
        }
        // Обработка обычных сообщений
        else if (message.substr(0, 3) == "MSG") {
            std::lock_guard<std::mutex> lock(participants_mutex);
            participants[ip] = time(nullptr);

            std::cout << "\n[" << ip << "]: " << message.substr(4) << std::endl;
            std::cout << "> " << std::flush;
        }
    }

    void heartbeat_thread() {
        while (running) {
            // Отправка HELLO-сообщения
            std::string hello_msg = "HELLO " + username;
            send_broadcast(hello_msg);

            // Очистка неактивных участников
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

    void run() {
        std::cout << "=== Cross-platform P2P Chat ===" << std::endl;
        std::cout << "Local IP: " << local_ip << std::endl;
        std::cout << "Broadcast IP: " << broadcast_ip << std::endl;
        std::cout << "Username: " << username << std::endl;
        std::cout << "Commands: /join, /leave, /ignore [IP], /list, /exit" << std::endl;
        std::cout << "=================================" << std::endl;

        // Запуск потоков
        std::thread receiver(&P2PChat::receiver_thread, this);
        std::thread heartbeat(&P2PChat::heartbeat_thread, this);

        // Основной цикл обработки команд
        while (running) {
            std::cout << "> " << std::flush;
            std::string input;
            std::getline(std::cin, input);

            if (input.empty()) continue;

            // Обработка команд
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
                // Отправка обычного сообщения
                std::string msg = "MSG " + input;

                if (in_multicast_group) {
                    send_multicast(msg);
                }
                send_broadcast(msg);
            }
        }

        // Остановка потоков
        if (receiver.joinable()) receiver.join();
        if (heartbeat.joinable()) heartbeat.join();
    }
};

int main() {
    P2PChat chat;
    chat.run();
    return 0;
}