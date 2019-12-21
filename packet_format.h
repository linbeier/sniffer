#ifndef PACKET_FORMAT_H
#define PACKET_FORMAT_H
#include <vector>
#include <iostream>
#include <pcap.h>
extern int netDeviceNum;

//MAC帧头
typedef struct _ethhdr
{
    u_char dest[6];     //6个字节，目标MAC地址
    u_char src[6];      //6个字节，源MAC地址
    u_short type;   //2个字节 类型
}ethhdr;

#define PROTO_IP 0x0800
#define PROTO_ARP 0X0806

//链路层帧的首部长度为14字节
#define ETHERNET_SIZE 14

//ARP头
typedef struct _arphdr
{
    u_short htype;   //2个字节，硬件类型，以太网是0x0001
    u_short prtype;     //2个字节，协议类型，0x0800表示使用ARP的协议类型为IPV4
    u_char hsize;   //硬件地址长度，ARP为6
    u_char prsize;   //协议地址长度，ARP为4
    u_short opcode;     //操作码，1为ARP请求报文，2为ARP回复报文
    u_char senderMac[6];    //发送方MAC地址
    u_char senderIp[4];     //发送方IP地址
    u_char destMac[6];      //接收方MAC地址
    u_char destIp[4];       //接收方IP地址
}arphdr;

//IP包头
typedef struct _iphdr
{
    u_char ip_vhl;      //版本以及报头长度
    u_char tos;         //TOS服务类型
    u_short ip_len;    //IP数据包长度,2个字节
    u_short identification;     //标识
    u_short flags_fo;           //标志位（FLAGS）（3 bits） + 段偏移量（Fragment offset)(13 bits)

#define IP_RF 0x8000        //reservedfragment flag
#define IP_DF 0x4000        //don't fragment flag
#define IP_MF 0x2000        //more fragment flag
#define IP_OFFMASK 0x1fff   //mask for fragment offset bits

    u_char ttl;                 //存活时间(time to live)
    u_char proto;               //协议（protocol)
    u_short hchecksum;          //首部校验和
    u_char saddr[4];            //源地址
    u_char daddr[4];            //目的地址
}iphdr;

#define IP_HL(ip)       ((ip)->ip_vhl & 0x0f)   //得到后4位，即报文的首部长度
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

typedef struct _tcphdr
{
    u_short srcPort;
    u_short destPort;
    u_int seq;
    u_int ack_sql;
    u_char th_offx2;    //data offset, rsvd

#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)   //得到前4位，即包首部长度
    u_char th_flags;

#define TH_FIN 0X01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0X80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

    u_short wnd_size;     //窗口大小，16位
    u_short checksum;   //校验和,16位
    u_short urg_ptr;    //紧急指针
}tcphdr;

//UDP header
typedef struct _udphdr
{
    u_short sport;  //源端口
    u_short dport;  //目的端口
    u_short len;    //UDP数据包长度
    u_short crc;    //校验和
}udphdr;

//icmp header
typedef struct _icmphdr
{
    u_char type;        //类型字段，占8位
    u_char code;        //代码字段，占8位
    u_short chk_sum;    //校验和字段，占16位
    u_short identification; //标识符字段，占16位
    u_short seq;    //序列号字段，占16位
}icmphdr;

//对各种包进行计数
typedef struct _pktCount
{
    int n_ip;
    int n_arp;
    int n_tcp;
    int n_udp;
    int n_icmp;
    int n_http;
    int n_other;
    int n_sum;
}pktCount;

//要保存的数据结构
typedef struct _datapkt
{
    char pktType[8];        //包类型
    int time[6];            //时间戳
    int len;                //长度

    struct _ethhdr *ethh;    //链路层包头
    struct _arphdr *arph;    //arp包头
    struct _iphdr *iph;      //ip包头
    struct _icmphdr *icmph;  //icmp包头
    struct _udphdr *udph;    //udp包头
    struct _tcphdr *tcph;    //tcp包头
    u_char* apph;     //应用层包头
    bool isHttp = false;
    int httpsize;
}datapkt;

//该容器用于存储数据包分析之后得到的结构体
typedef std::vector<datapkt *> datapktVec;
//该容器用于存储捕获的单个数据包所构成的字符串，以便在全部打印出来
typedef std::vector<u_char *> dataVec;

//以太网首部结构
struct ethernet_head
{
    unsigned char dest_mac[6];	//以太网目的地址
    unsigned char src_mac[6];	//以太网源地址
    unsigned short eh_type;		//以太网帧类型
};

struct arp_head
{
    unsigned short hardware_type;	//硬件类型：以太网接口类型为1
    unsigned short protocol_type;	//协议类型：IP协议类型为0x0800
    unsigned char add_len;			//硬件地址长度
    unsigned char pro_len;			//协议地址长度
    unsigned short option;			//操作
    unsigned char sour_addr[6];		//源MAC地址：发送方的MAC地址
    unsigned long sour_ip;			//源IP地址：发送方的IP地址
    unsigned char dest_addr[6];		//目的Mac地址
    unsigned long dest_ip;			//目的IP地址
};

//最终arp包结构
struct arp_packet
{
//    ethernet_head eth;	//以太网头部
//    arp_head arp;		//arp数据包头部
    unsigned char dest_mac[6];	//以太网目的地址
    unsigned char src_mac[6];	//以太网源地址
    unsigned short eh_type;		//以太网帧类型
    unsigned short hardware_type;	//硬件类型：以太网接口类型为1
    unsigned short protocol_type;	//协议类型：IP协议类型为0x0800
    unsigned char add_len;			//硬件地址长度
    unsigned char pro_len;			//协议地址长度
    unsigned short option;			//操作
    unsigned char sour_addr[6];		//源MAC地址：发送方的MAC地址
    unsigned long sour_ip;			//源IP地址：发送方的IP地址
    unsigned char dest_addr[6];		//目的Mac地址
    unsigned long dest_ip;			//目的IP地址
    unsigned char padding[18];
};

#endif // PACKET_FORMAT_H
