#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <string>
#include <iostream>
namespace py = pybind11;
using py::list;
struct Device {
    std::string ip;
    std::string mac;
};

py::list arp_scan(const std::string& iface) {
    py::list result;

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) return result;

    struct ifreq ifr{};
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    ioctl(sock, SIOCGIFINDEX, &ifr);
    int ifindex = ifr.ifr_ifindex;

    ioctl(sock, SIOCGIFHWADDR, &ifr);
    unsigned char src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    ioctl(sock, SIOCGIFADDR, &ifr);
    uint32_t src_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

    sockaddr_ll addr{};
    addr.sll_ifindex = ifindex;
    addr.sll_family = AF_PACKET;
    addr.sll_halen = ETH_ALEN;
    memset(addr.sll_addr, 0xff, 6);

    unsigned char buffer[42]{};
    auto* eth = (ether_header*)buffer;
    auto* arp = (ether_arp*)(buffer + 14);

    memset(eth->ether_dhost, 0xff, 6);
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETH_P_ARP);

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);

    memcpy(arp->arp_sha, src_mac, 6);
    memcpy(arp->arp_spa, &src_ip, 4);
    memset(arp->arp_tha, 0x00, 6);

    for (int i = 1; i < 255; i++) {
        uint32_t target_ip = (src_ip & htonl(0xFFFFFF00)) | htonl(i);
        memcpy(arp->arp_tpa, &target_ip, 4);
        sendto(sock, buffer, sizeof(buffer), 0,
               (sockaddr*)&addr, sizeof(addr));
    }

    struct timeval tv{1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (true) {
        unsigned char recvbuf[65536];
        ssize_t len = recv(sock, recvbuf, sizeof(recvbuf), 0);
        if (len <= 0) break;

        auto* rarp = (ether_arp*)(recvbuf + 14);
        if (ntohs(rarp->ea_hdr.ar_op) == ARPOP_REPLY) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, rarp->arp_spa, ip, sizeof(ip));

            char mac[18];
            snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     rarp->arp_sha[0], rarp->arp_sha[1], rarp->arp_sha[2],
                     rarp->arp_sha[3], rarp->arp_sha[4], rarp->arp_sha[5]);

            py::dict dev;
            dev["ip"] = ip;
            dev["mac"] = mac;

            result.append(dev);
        }
    }

    close(sock);
    return result;
}

list myfunction(std::string name){
    std::cout<<name;
    list x;
    x.append(name);
    return x;
}
PYBIND11_MODULE(scan, m) {
    m.def("name",&myfunction,"list name",py::arg("interface"));
    m.def("arp_scan", &arp_scan, "Fast ARP scan", py::arg("interface"));
}
