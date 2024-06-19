#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string>
#include <fstream>
#include "ethhdr.h"
#include "tcphdr.h"
#include "iphdr.h"

Mac my_mac;

typedef struct _pesudoHeader {
    uint32_t srcAddr;
    uint32_t dstAdrr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcpLen;
} pesudoHeader;

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

void get_my_mac(const std::string& dev, Mac* mac) {
    std::ifstream mac_file("/sys/class/net/" + dev + "/address");
    std::string str((std::istreambuf_iterator<char>(mac_file)), std::istreambuf_iterator<char>());
    if (!str.empty()) {
        *mac = Mac(str.c_str());
    }
}

uint16_t Checksum(uint16_t* ptr, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t*)ptr;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

void send_packet(pcap_t* handle, const char* packet, int len) {
    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), len)) {
        fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return 0;
    }

    std::string dev(argv[1]);
    std::string pattern(argv[2]);

    get_my_mac(dev, &my_mac);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev.c_str(), errbuf);
        return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    while (true) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        PEthHdr ethernet_hdr = (PEthHdr)packet;
        if (ethernet_hdr->type() != EthHdr::Ip4) continue;

        PIpHdr ip_hdr = (PIpHdr)(packet + sizeof(EthHdr));
        uint32_t iphdr_len = ip_hdr->ip_len * 4;
        uint32_t ippkt_len = ntohs(ip_hdr->total_len);
        if (ip_hdr->proto != 6) continue;

        PTcpHdr tcp_hdr = (PTcpHdr)((uint8_t*)ip_hdr + iphdr_len);
        uint32_t tcphdr_len = tcp_hdr->th_off * 4;
        uint32_t tcpdata_len = ippkt_len - iphdr_len - tcphdr_len;
        if (tcpdata_len == 0) continue;

        std::string tcp_data((char*)((uint8_t*)tcp_hdr + tcphdr_len), tcpdata_len);
        if (tcp_data.find(pattern) != std::string::npos && tcp_data.compare(0, 3, "GET") == 0) {
            // backward packet (FIN) -> client
            int rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            int value = 1;
            setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value));

            struct sockaddr_in rawaddr;
            rawaddr.sin_family = AF_INET;
            rawaddr.sin_port = tcp_hdr->sport;
            rawaddr.sin_addr.s_addr = ip_hdr->sip_;

            const char* tcpdata_my = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
            uint16_t iphdr_my_len = sizeof(IpHdr), tcphdr_my_len = sizeof(TcpHdr), tcpdata_my_len = strlen(tcpdata_my);
            uint16_t my_total_len = iphdr_my_len + tcphdr_my_len + tcpdata_my_len;

            char* my_packet = (char*)malloc(my_total_len);
            memset(my_packet, 0, my_total_len);

            PIpHdr iphdr_my = (PIpHdr)my_packet;
            PTcpHdr tcphdr_my = (PTcpHdr)(my_packet + iphdr_my_len);
            memcpy(my_packet + iphdr_my_len + tcphdr_my_len, tcpdata_my, tcpdata_my_len);

            tcphdr_my->sport = tcp_hdr->dport;
            tcphdr_my->dport = tcp_hdr->sport;
            tcphdr_my->seqnum = tcp_hdr->acknum;
            tcphdr_my->acknum = htonl(ntohl(tcp_hdr->seqnum) + tcpdata_len);
            tcphdr_my->th_off = tcphdr_my_len / 4;
            tcphdr_my->flags = 0b00010001;
            tcphdr_my->win = htons(60000);

            iphdr_my->ip_len = iphdr_my_len / 4;
            iphdr_my->ip_v = 4;
            iphdr_my->total_len = htons(my_total_len);
            iphdr_my->ttl = 128;
            iphdr_my->proto = 6;
            iphdr_my->sip_ = ip_hdr->dip_;
            iphdr_my->dip_ = ip_hdr->sip_;

            pesudoHeader psdheader;
            memset(&psdheader, 0, sizeof(pesudoHeader));
            psdheader.srcAddr = ip_hdr->dip_;
            psdheader.dstAdrr = ip_hdr->sip_;
            psdheader.protocol = IPPROTO_TCP;
            psdheader.tcpLen = htons(tcphdr_my_len + tcpdata_my_len);

            uint32_t tcp_checksum = Checksum((uint16_t*)tcphdr_my, tcphdr_my_len + tcpdata_my_len) + Checksum((uint16_t*)&psdheader, sizeof(pesudoHeader));
            tcphdr_my->check = (tcp_checksum & 0xffff) + (tcp_checksum >> 16);
            iphdr_my->check = Checksum((uint16_t*)iphdr_my, iphdr_my_len);

            if (sendto(rawsock, my_packet, my_total_len, 0, (struct sockaddr*)&rawaddr, sizeof(rawaddr)) < 0) {
                perror("Failed!\n");
                return -1;
            }
            else printf("Blocked!\n");
            free(my_packet);
            close(rawsock);

            // forward packet (RST) -> server
            uint32_t newpkt_len = sizeof(EthHdr) + iphdr_len + sizeof(TcpHdr);
            char* newpkt = (char*)malloc(newpkt_len);
            memset(newpkt, 0, newpkt_len);
            memcpy(newpkt, packet, newpkt_len);

            ethernet_hdr = (PEthHdr)newpkt;
            ip_hdr = (PIpHdr)(newpkt + sizeof(EthHdr));
            tcp_hdr = (PTcpHdr)((char*)ip_hdr + iphdr_len);

            ethernet_hdr->smac_ = my_mac;
            ip_hdr->total_len = htons(iphdr_len + sizeof(TcpHdr));
            ip_hdr->check = 0;
            tcp_hdr->th_off = sizeof(TcpHdr) / 4;
            tcp_hdr->seqnum = htonl(ntohl(tcp_hdr->seqnum) + tcpdata_len);
            tcp_hdr->flags = 0b00010100;
            tcp_hdr->check = 0;

            memset(&psdheader, 0, sizeof(pesudoHeader));
            psdheader.srcAddr = ip_hdr->sip_;
            psdheader.dstAdrr = ip_hdr->dip_;
            psdheader.protocol = IPPROTO_TCP;
            psdheader.tcpLen = htons(sizeof(TcpHdr));

            tcp_checksum = Checksum((uint16_t*)tcp_hdr, sizeof(TcpHdr)) + Checksum((uint16_t*)&psdheader, sizeof(pesudoHeader));
            tcp_hdr->check = (tcp_checksum & 0xffff) + (tcp_checksum >> 16);
            ip_hdr->check = Checksum((uint16_t*)ip_hdr, iphdr_len);

            send_packet(handle, newpkt, newpkt_len);
            free(newpkt);
        }
    }

    pcap_close(handle);
    return 0;
}

