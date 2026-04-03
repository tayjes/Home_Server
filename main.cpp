//include header
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>       //for iphdr struct to read TTL from ping reply
#include <netinet/ip_icmp.h>  //for icmphdr struct to build ping packet
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <string>
#include <iostream>
#include <cctype>
#include <algorithm>
#include <unordered_map>
#include <fstream>
#include <unordered_set>
#include <mutex>
//EO header

static std::once_flag init_flag; //to check that init() runs only once

//for testing here in main.cpp add this!
//#include <pybind11/embed.h>

namespace py = pybind11;

//Hashmap for Storing
std::unordered_map<std::string, std::string> oui_map;

//ICMP checksum calculator — every ICMP packet needs a valid checksum
//or the kernel silently drops it. Standard 16-bit one's complement sum.
uint16_t checksum(void* data, int len) {
    uint16_t* buf = (uint16_t*)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len) sum += *(uint8_t*)buf;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

//Send a ping to target_ip and return the TTL value from the IP header reply
//TTL fingerprinting: different OS use different default TTL values
//Windows=128, Linux/macOS/Android=64, Cisco/Router=255
int get_ttl(const std::string& target_ip) {
    //Raw ICMP socket — same NET_RAW capability as the ARP socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return -1;

    //1 second timeout so we don't hang on unresponsive hosts
    struct timeval tv{1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    //Build the ICMP echo request (ping) packet
    //type=8 means ping request, code=0, id=our PID to match replies
    struct icmphdr icmp{};
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = getpid();
    icmp.un.echo.sequence = 1;
    icmp.checksum = checksum(&icmp, sizeof(icmp));

    //Set destination address
    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip.c_str(), &dest.sin_addr);

    //Send the ping
    sendto(sock, &icmp, sizeof(icmp), 0, (sockaddr*)&dest, sizeof(dest));

    //Receive reply — comes back as a full IP packet (IP header + ICMP)
    unsigned char buf[1024];
    ssize_t len = recv(sock, buf, sizeof(buf), 0);
    close(sock);

    if (len <= 0) return -1;

    //TTL is at byte offset 8 inside the IP header
    struct iphdr* ip = (struct iphdr*)buf;
    return ip->ttl;
}

//Guess OS from TTL value
//We use ranges (+/- tolerance) because TTL drops by 1 per router hop
//e.g. Windows machine 2 hops away shows TTL 126 not 128
std::string ttl_to_os(int ttl) {
    if (ttl <= 0)   return "Unknown";
    if (ttl >= 250) return "Network Device (Cisco/Router)";
    if (ttl >= 120) return "Windows";
    if (ttl >= 59)  return "Linux / macOS / Android";
    return "Unknown";
}

//loading the key-value from MAC.txt into oui_map function need to run only once
void init() {
    std::call_once(init_flag, []() {
        const char* env_path = getenv("MAC_DB_PATH");
        std::string path = env_path ? env_path : "helper/MAC.txt";
        std::ifstream file(path);

        if (!file.is_open()) {
            throw std::runtime_error("Cannot open MAC database at: " + path);
        }
        std::string line;

        while (std::getline(file, line)) {
            if (line.find("(hex)") != std::string::npos) {
                std::string key = line.substr(0, 8);
                size_t pos = line.find("(hex)");
                std::string value = line.substr(pos + 6);
                value.erase(0, value.find_first_not_of(" \t"));
                oui_map[key] = value;
            }
        }
    });
}

//search in the Hashmap only use it after running init() function
std::string search(std::string key) {
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::toupper(c); });
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return (c == ':') ? '-' : c; });
    auto it = oui_map.find(key);
    if (it != oui_map.end()) return it->second;
    return "NOT FOUND";
}

//scan the network iface is the interface of the network connected to
py::list arp_scan(const std::string& iface) {
    py::list result;
    std::unordered_set<std::string> seen;

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) return result;

    struct ifreq ifr{};
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        close(sock);
        throw std::runtime_error("Failed to get interface index for: " + iface);
    }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        throw std::runtime_error("Failed to get MAC address for: " + iface);
    }
    unsigned char src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        throw std::runtime_error("Failed to get IP address for: " + iface);
    }
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

            std::string mac_str = mac;
            if (seen.count(mac_str)) continue; //skip duplicate
            seen.insert(mac_str);

            //ping the device and read TTL to guess OS
            int ttl = get_ttl(ip);

            py::dict dev;
            dev["ip"] = ip;
            dev["mac"] = mac;
            dev["company"] = search(std::string(mac).substr(0, 8));
            dev["ttl"] = ttl;        //raw TTL value
            dev["os"] = ttl_to_os(ttl); //guessed OS string
            result.append(dev);
        }
    }

    close(sock);
    return result;
}

//add main only for Testing
/*int main() {
    py::scoped_interpreter guard{};  //To Start Python interpreter

    init();

    py::list tmp = arp_scan("wlp2s0");

    for (auto it : tmp) {
        std::cout << py::str(it).cast<std::string>() << "\n";
    }

    return 0;
}*/

//Uncomment when running cmake
PYBIND11_MODULE(scan, m) {
    m.def("arp_scan", &arp_scan, "Fast ARP scan", py::arg("interface"));
    m.def("init", &init, "Load Mac address");
}