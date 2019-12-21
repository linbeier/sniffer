#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1   //ARP请求
#define ARP_RESPONSE       2      //ARP应答

#include <QMainWindow>
#include <QDebug>
#include <iostream>
#include <cstdio>
#include <conio.h>
#include <pcap.h>
#include <packet32.h>
#include <WinSock2.h>
#include <ntddndis.h>
#include "packet_format.h"
#include <capthread.h>
#include <QMessageBox>
#include <arpthread.h>

using namespace std;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    //fuctions
    int sniff_initCap();       //初始化
    int sniff_startCap();      //开始捕获数据
    void showHexData(u_char*, int len);     //显示数据包中的十六进制内容
    int initDev(int interface_index);      //打开指定的设备
    u_char* GetSelfMac(char *pDevName);        //获得本机网卡的MAC地址
    void transMac(const char source[], u_char *dest);
    //data
    int devCount;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filepath[512];     //临时数据包保存路径
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    pcap_t *adhandle;
    pcap_dumper_t *dumpfile;
    u_char *selfmac;
    QString destip;           //被欺骗主机IP地址
    QString destmac;          //被欺骗主机Mac地址
    QString gateip;
    QString gatemac;
    //作为信号传递的欺骗信息
    u_long deli_destip;
    u_char *deli_destmac;
    u_long deli_gateip;
    u_char *deli_gatemac;

    u_long netmask;
    char filters[50] = "not arp";
    struct bpf_program fcode;

    arpthread *arpthread0;

    pktCount *npacket;
    capthread *capthread0;

    datapktVec datapktLink;
    dataVec dataCharLink;
    int RowCount;
    bool isFileSaved;

private slots:

    void updateTableWidget(QString timestr, QString srcMac, QString destMac, QString len, QString protoType, QString srcIP, QString dstIP);
    void updateCapCalculate();
    void showTree(int row, int column);


    void on_start_Button_clicked();

    void on_stop_Button_clicked();


    void on_cheat_clicked();
    void on_pushButton_clicked();

signals:
     void setCheatInfo(pcap_t *adhandle, u_char *selfmac, u_long deli_destip, u_char *deli_destmac, u_long deli_gateip, u_char *deli_gatemac);

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
