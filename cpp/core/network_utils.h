#pragma once

#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
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

struct NetworkInfo {
    std::string local_ip;
    std::string broadcast_ip;
};

class SocketUtils {
public:
#ifdef _WIN32
    using SocketHandle = SOCKET;
    static const SocketHandle INVALID_SOCKET_HANDLE = INVALID_SOCKET;
#else
    using SocketHandle = int;
    static const SocketHandle INVALID_SOCKET_HANDLE = -1;
#endif

    static bool init();
    static void cleanup();
    static NetworkInfo get_network_info();
    static void close_socket(SocketHandle sock);
    static bool set_socket_option(SocketHandle sock, int level, int optname, const void* optval, socklen_t optlen);
};