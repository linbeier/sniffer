#ifndef CAPTHREAD_H
#define CAPTHREAD_H

#include <QObject>
#include <QThread>
#include <QMutex>
#include <pcap.h>
#include <remote-ext.h>
#include <winsock.h>
#include <packet_format.h>
#include <cstdio>

class capthread: public QThread
{
    Q_OBJECT
public:
    capthread(pcap_t *adhandle, pktCount *npacket, datapktVec &datapktLLink, dataVec &dataCharLLink, pcap_dumper_t *dumpfile);
    void stop();
protected:
    void run();
private:
    QMutex m_lock;
    volatile bool stopped;
    pcap_t *adhandle;
    pktCount *npacket;
    datapktVec &datapktLink;
    dataVec &dataCharLink;
    pcap_dumper_t *dumpfile;

signals:
    void addOneCaptureLine(QString timestr, QString srcMac, QString destMac, QString len, QString protoType, QString srcIP, QString dstIP);
    void updatePktCount();
};

#endif // CAPTHREAD_H
