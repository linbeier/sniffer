#ifndef ARPTHREAD_H
#define ARPTHREAD_H
#include <QThread>
#include <QMutex>
#include <pcap.h>
#include <packet_format.h>
#include "winsock2.h"
#include "QTimer"
#include "QTime"
#include "QCoreApplication"
class arpthread: public QThread
{
    Q_OBJECT
public:
    arpthread();
    ~arpthread();
    void stop();
    QTime t;
    void run();
private:
    QMutex m_lock;
    volatile bool stopped;
    u_char *fakeTargetArpPkt;       //发送给目标主机的伪造arp数据包
    u_char *fakeGateArpPkt;         //发送给网关的伪造ARP数据包
    pcap_t *adhandle;
    u_char *currentMac;
    u_long targetIp;
    u_char *targetMac;
    u_long gateIp;
    u_char *gateMac;

    u_char *BuildArpPacket(u_char *srcMac, u_long srcIP, u_char *destMac, u_long destIP);
private slots:
    void getCheatInfo(pcap_t *adhandle, u_char *selfmac, u_long destip, u_char *destmac, u_long gateip, u_char *gatemac);
public slots:
    void send();

};

#endif // ARPTHREAD_H
