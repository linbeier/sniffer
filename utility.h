#ifndef UTILITY_H
#define UTILITY_H
#include <pcap.h>
#include <remote-ext.h>
#include <winsock.h>
#include <packet_format.h>
#include <winsock2.h>


class utility
{
public:
    utility();
    int analyze_frame(const u_char *pkt, datapkt *data, pktCount *npacket);
    int analyze_arp(const u_char *pkt, datapkt *data, pktCount *npacket);
    int analyze_ip(const u_char *pkt, datapkt *data, pktCount *npacket);
    int analyze_icmp(const u_char *pkt, datapkt *data, pktCount *npacket);
    int analyze_tcp(const u_char *pkt, datapkt *data, pktCount *npacket);
    int analyze_udp(const u_char *pkt, datapkt *data, pktCount *npacket);
private:
    const u_char *pktInitialAddress;  //捕获的数据包的起始地址
};

#endif // UTILITY_H
