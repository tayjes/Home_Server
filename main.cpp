//include header
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
#include <cctype>
#include <algorithm>
#include <unordered_map>
#include <fstream>
//EO header

//for testing here in main.cpp add this!
//#include <pybind11/embed.h>


namespace py = pybind11;

//Hashmap for Storing
std::unordered_map<std::string, std::string> oui_map;

//loading the key-value from MAC.txt into oui_map function need to run only once
void init(){
    std::ifstream file("helper/MAC.txt");
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
}

//search in the Hashmap only use it after running init() fucntion
std::string search(std::string key){
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::toupper(c); });
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {return (c == ':') ? '-' : c;});
    
    auto it = oui_map.find(key);
    if (it != oui_map.end()) return it->second;
    return "NOT FOUND";
}

//scan the network iface is the interface of the network connected to
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
            std::string key=mac;
            dev["company"]=search(key.substr(0,8));
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
