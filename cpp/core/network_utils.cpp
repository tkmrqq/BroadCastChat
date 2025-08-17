#include "network_utils.h"
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

bool SocketUtils::init() {
#ifdef _WIN32
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
#else
    return true;
#endif
}

void SocketUtils::cleanup() {
#ifdef _WIN32
    WSACleanup();
#endif
}

NetworkInfo SocketUtils::get_network_info() {
    NetworkInfo info;
    info.local_ip = "127.0.0.1";
    info.broadcast_ip = "255.255.255.255";

#ifdef _WIN32
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    ULONG outBufLen = 0;
    DWORD dwRetVal = 0;

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen) != ERROR_BUFFER_OVERFLOW) {
        return info;
    }

    pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    if (!pAddresses) return info;

    dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
    if (dwRetVal != ERROR_SUCCESS) {
        free(pAddresses);
        return info;
    }

    for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr; pCurr = pCurr->Next) {
        if (pCurr->OperStatus != 1 || pCurr->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurr->FirstUnicastAddress; pUnicast; pUnicast = pUnicast->Next) {
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);

                if (strcmp(ip_str, "127.0.0.1") != 0) {
                    info.local_ip = ip_str;

                    IP_ADAPTER_INFO adapterInfo;
                    ULONG adapterInfoSize = sizeof(adapterInfo);
                    if (GetAdaptersInfo(&adapterInfo, &adapterInfoSize) == ERROR_SUCCESS) {
                        for (PIP_ADAPTER_INFO pAdapter = &adapterInfo; pAdapter; pAdapter = pAdapter->Next) {
                            if (strcmp(pAdapter->IpAddressList.IpAddress.String, info.local_ip.c_str()) == 0) {
                                std::string mask_str = pAdapter->IpAddressList.IpMask.String;

                                in_addr local, mask, broadcast;
                                inet_pton(AF_INET, info.local_ip.c_str(), &local);
                                inet_pton(AF_INET, mask_str.c_str(), &mask);
                                broadcast.s_addr = local.s_addr | ~mask.s_addr;

                                char broadcast_str[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &broadcast, broadcast_str, INET_ADDRSTRLEN);
                                info.broadcast_ip = broadcast_str;
                                break;
                            }
                        }
                    }
                    free(pAddresses);
                    return info;
                }
            }
        }
    }
    free(pAddresses);
#else
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr)) {
        return info;
    }

    for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET ||
            std::string(ifa->ifa_name) == "lo") continue;

        struct sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
        info.local_ip = inet_ntoa(addr->sin_addr);

        struct sockaddr_in* mask = reinterpret_cast<sockaddr_in*>(ifa->ifa_netmask);
        struct sockaddr_in* bcast = reinterpret_cast<sockaddr_in*>(ifa->ifa_broadaddr);

        if (bcast) {
            info.broadcast_ip = inet_ntoa(bcast->sin_addr);
        } else if (mask) {
            uint32_t ip = ntohl(addr->sin_addr.s_addr);
            uint32_t netmask = ntohl(mask->sin_addr.s_addr);
            uint32_t broadcast = ip | ~netmask;
            struct in_addr baddr;
            baddr.s_addr = htonl(broadcast);
            info.broadcast_ip = inet_ntoa(baddr);
        }
        break;
    }
    freeifaddrs(ifaddr);
#endif
    return info;
}

void SocketUtils::close_socket(SocketHandle sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

bool SocketUtils::set_socket_option(SocketHandle sock, int level, int optname, const void* optval, socklen_t optlen) {
#ifdef _WIN32
    return setsockopt(sock, level, optname, reinterpret_cast<const char*>(optval), optlen) == 0;
#else
    return setsockopt(sock, level, optname, optval, optlen) == 0;
#endif
}