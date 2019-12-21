#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pcap.h"

int netDeviceNum = 0;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("sniffer");
    isFileSaved = false;
    RowCount =0;

    ui->packetWidget->setColumnCount(8);
    ui->packetWidget->setHorizontalHeaderLabels(QStringList() << tr("序号") << tr("时间")
                                                << tr("源MAC地址") << tr("目的MAC地址")
                                                << tr("长度") << tr("协议类型")
                                                << tr("源IP地址") << tr("目的IP地址"));
    //设置为单行选中
    ui->packetWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    //禁止修改内容
    ui->packetWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);

    ui->packetWidget->setColumnWidth(0, 60);
    ui->packetWidget->setColumnWidth(1, 180);
    ui->packetWidget->setColumnWidth(2, 210);
    ui->packetWidget->setColumnWidth(3, 210);
    ui->packetWidget->setColumnWidth(4, 60);
    ui->packetWidget->setColumnWidth(5, 85);
    ui->packetWidget->setColumnWidth(6, 145);
    ui->packetWidget->setColumnWidth(7, 145);
    connect(ui->packetWidget, SIGNAL(cellClicked(int,int)), this, SLOT(showTree(int,int)));

    ui->packetWidget->verticalHeader()->setVisible(false);

    //书状信息初始化
    ui->tree_view->setColumnCount(1);
    ui->tree_view->setHeaderLabel(QString("协议分析结果"));
    ui->tree_view->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->tree_view->setColumnWidth(0,300);
    //combo box初始化
    ui->comboBox_eth->addItem(tr("请选择一个网卡"));

    //初始化，获取网卡列表
    if(sniff_initCap()<0)
    {
        QMessageBox::warning(this,tr("net_device warning"),tr("无法找到网络适配器"),QMessageBox::Ok);
    }

    //将接口列表初始化
    for(dev=alldevs;dev;dev=dev->next)
    {
        if(dev->description)
            ui->comboBox_eth->addItem(QString("%1").arg(dev->description));
    }

    npacket = (pktCount *)malloc(sizeof(pktCount));
    capthread0=NULL;

}

MainWindow::~MainWindow()
{
    delete ui;
}

//初始化winpcap
int MainWindow::sniff_initCap()
{
    devCount = 0;
    if(pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
        return -1;
    for(dev = alldevs; dev; dev = dev->next)
        devCount++;
    return 0;

}

int MainWindow::sniff_startCap()
{
    int interface_index = 0,count;
    u_int netmask;
    struct bpf_program fcode;   //bpf_program结构体在编译BPF过滤规则函数执行成功后将会被填充

    //获得过滤器中写入的内容
    interface_index = ui->comboBox_eth->currentIndex();
    if(interface_index == 0)
    {
        QMessageBox::warning(this,"",tr("请必须选择一个网卡"),QMessageBox::Ok);
        return -1;
    }
    QString filtercontent = ui->filter_Edit->text();

    //获取选中的网卡
    netDeviceNum = interface_index;
    dev=alldevs;
    for(count = 0; count < interface_index - 1; count++){
        dev = dev->next;
        qDebug() << "debug information: " << dev->name << endl;
    }

    if((adhandle = pcap_open_live(dev->name,    //设备名
                                  65536,    //捕获数据包长度
                                  1,    //设置成混杂模式
                                  1000,    //读超时设置
                                  errbuf  //错误信息缓冲
                                  )) == NULL)
    {
        QMessageBox::warning(this, "open error", tr("网卡接口打开失败"), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    }
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        QMessageBox::warning(this, "Sniffer", tr("只支持以太网环境"), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    }
    //获取子网掩码
    if(dev->addresses != NULL)
    {
        netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else
        netmask = 0xffffff;
    //获取过滤规则，若过滤规则为空，则使用默认设置
    if(filtercontent == NULL)
    {
        char filter[] = "";
        if(pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
        {
            QMessageBox::warning(this, "Sniff", tr("无法编译包过滤器，请检查语法"), QMessageBox::Ok);
            pcap_freealldevs(alldevs);
            alldevs = NULL;
            return -1;
        }
    }
    else{
        QByteArray ba = filtercontent.toLatin1();
        char *filter = NULL;
        filter = ba.data();     //上述转换中要求QString中不含有中文，否则会出现乱码
        if(pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
        {
            QMessageBox::warning(this, "Sniff", tr("无法编译包过滤器，请检查语法"), QMessageBox::Ok);
            pcap_freealldevs(alldevs);
            alldevs = NULL;
            return -1;
        }
    }

    //设置过滤器
    if(pcap_setfilter(adhandle, &fcode) < 0)
    {
        QMessageBox::warning(this, "Sniff", tr("设置过滤器发生错误"), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    }

    //释放设备信息
    pcap_freealldevs(alldevs);
    alldevs = NULL;
    //开启线程捕获
    capthread0 = new capthread(adhandle, npacket, datapktLink, dataCharLink, dumpfile);
    connect(capthread0, SIGNAL(addOneCaptureLine(QString,QString,QString,QString,QString,QString,QString)), this, SLOT(updateTableWidget(QString,QString,QString,QString,QString,QString,QString)));
    connect(capthread0, SIGNAL(updatePktCount()), SLOT(updateCapCalculate()));
    capthread0->start();
    return 1;
}


void MainWindow::on_start_Button_clicked()
{
    //每次重新开始进行数据包捕获（包括读取本地数据包的时候）的时候要将对应容器中的结构体释放掉，否则会造成内存泄漏
    std::vector<datapkt *>::iterator it;
    for(it = datapktLink.begin(); it != datapktLink.end(); it++){
        free((*it)->ethh);
        free((*it)->arph);
        free((*it)->iph);
        free((*it)->icmph);
        free((*it)->udph);
        free((*it)->tcph);
        free((*it)->apph);
        free(*it);
    }
    std::vector<u_char *>::iterator kt;
    for(kt = dataCharLink.begin(); kt != dataCharLink.end(); kt++){
        free(*kt);
    }
    datapktVec().swap(datapktLink);
    dataVec().swap(dataCharLink);

    ui->tree_view->clear();
    ui->detail_text->clear();

    //需要重新获取网络接口信息，这里有bug,因为在上一步的释放操作中并没有将指针值重新设置为0，因此会导致程序崩溃
    if(alldevs == NULL){
        if(sniff_initCap() < 0){
            QMessageBox::warning(this, tr("Sniffer"), tr("无法在您的机器上获取网络适配器接口"), QMessageBox::Ok);
            return;
        }
    }
    //这里出现段错误也是因为没有将capthread赋为null导致其变成野指针
    if(capthread0 != NULL){
        delete capthread0;
        capthread0 = NULL;
    }
    memset(npacket, 0, sizeof(struct _pktCount));

    if(sniff_startCap() < 0)
        return;

    //清空QTableWidget控件中的内容
    ui->packetWidget->clearContents();
    ui->packetWidget->setRowCount(0);
//    ui->stop_Button->setEnabled(true);
//    ui->start_Button->setEnabled(false);

}

void MainWindow::on_stop_Button_clicked()
{
    qDebug() << datapktLink.size() << endl;
    qDebug() << dataCharLink.size() << endl;

    //停止线程
    capthread0->stop();
    //关闭winpcap会话句柄，并释放其资源
    pcap_close(adhandle);
}

void MainWindow::updateTableWidget(QString timestr, QString srcMac, QString destMac, QString len, QString protoType, QString srcIP, QString dstIP)
{
    RowCount = ui->packetWidget->rowCount();
    ui->packetWidget->insertRow(RowCount);
    QString orderNumber = QString::number(RowCount, 10);
    ui->packetWidget->setItem(RowCount, 0, new QTableWidgetItem(orderNumber));
    ui->packetWidget->setItem(RowCount, 1, new QTableWidgetItem(timestr));
    ui->packetWidget->setItem(RowCount, 2, new QTableWidgetItem(srcMac));
    ui->packetWidget->setItem(RowCount, 3, new QTableWidgetItem(destMac));
    ui->packetWidget->setItem(RowCount, 4, new QTableWidgetItem(len));
    ui->packetWidget->setItem(RowCount, 5, new QTableWidgetItem(protoType));
    ui->packetWidget->setItem(RowCount, 6, new QTableWidgetItem(srcIP));
    ui->packetWidget->setItem(RowCount, 7, new QTableWidgetItem(dstIP));

    if(RowCount > 1)
    {
        ui->packetWidget->scrollToItem(ui->packetWidget->item(RowCount, 0), QAbstractItemView::PositionAtBottom);
    }

//    QColor color;
//    if(protoType == "TCP" || protoType == "HTTP"){
//        color = QColor(228,255,199);
//    }
//    else if(protoType == "UDP"){
//        color = QColor(218,238,255);
//    }
//    else if(protoType == "ARP"){
//        color = QColor(250,240,215);
//    }
//    else if(protoType == "ICMP"){
//        color = QColor(252,224,255);
//    }
//    for(int i = 0; i < 8 ; i ++){
//        ui->packetWidget->item(RowCount,i)->setBackgroundColor(color);
//    }
}

void MainWindow::updateCapCalculate()
{
    ui->tcpedit->setText(QString::number(npacket->n_tcp));
    ui->udpedit->setText(QString::number(npacket->n_udp));
    ui->icmpedit->setText(QString::number(npacket->n_icmp));
    ui->httpedit->setText(QString::number(npacket->n_http));
    ui->arpedit->setText(QString::number(npacket->n_arp));
    ui->ipv4edit->setText(QString::number(npacket->n_ip));
    ui->otheredit->setText(QString::number(npacket->n_other));
    ui->totaledit->setText(QString::number(npacket->n_sum));
}

void MainWindow::showTree(int row, int column)
{
    qDebug() << row << column << endl;
    //清空控件中的内容
    ui->tree_view->clear();
    ui->detail_text->clear();

    struct _datapkt *mem_data = (struct _datapkt *)datapktLink[row];
    //在编辑栏中要显示的数据包内容
    u_char *print_data = (u_char *)dataCharLink[row];
    int print_len = mem_data->len;
    showHexData(print_data, print_len);

    QString showStr;
    char buf[100];
    sprintf(buf, "接收到的第%d个数据包", row + 1);
    showStr = QString(buf);

    QTreeWidgetItem *root = new QTreeWidgetItem(ui->tree_view);
    root->setText(0, showStr);

    //处理帧数据
    showStr = QString("链路层数据");
    QTreeWidgetItem *level1 = new QTreeWidgetItem(root);
    level1->setText(0, showStr);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->ethh->src[0], mem_data->ethh->src[1],
            mem_data->ethh->src[2], mem_data->ethh->src[3], mem_data->ethh->src[4], mem_data->ethh->src[5]);
    showStr = "源MAC: " + QString(buf);
    QTreeWidgetItem *srcEtherMac = new QTreeWidgetItem(level1);
    srcEtherMac->setText(0, showStr);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->ethh->dest[0], mem_data->ethh->dest[1],
            mem_data->ethh->dest[2], mem_data->ethh->dest[3], mem_data->ethh->dest[4], mem_data->ethh->dest[5]);
    showStr = "目的MAC: " + QString(buf);
    QTreeWidgetItem *destEtherMac = new QTreeWidgetItem(level1);
    destEtherMac->setText(0, showStr);

    sprintf(buf, "%04x", mem_data->ethh->type);
    showStr = "类型:0x" + QString(buf);
    QTreeWidgetItem *etherType = new QTreeWidgetItem(level1);
    etherType->setText(0, showStr);

    //处理IP,ARP类型的数据包
    if(mem_data->ethh->type == 0x0806)      //ARP
    {
        //添加ARP协议头
        showStr = QString("ARP协议头");
        QTreeWidgetItem *level2 = new QTreeWidgetItem(root);
        level2->setText(0, showStr);

        sprintf(buf, "硬件类型: 0x%04x", mem_data->arph->htype);
        showStr = QString(buf);
        QTreeWidgetItem *arpHtype = new QTreeWidgetItem(level2);
        arpHtype->setText(0, showStr);

        sprintf(buf, "协议类型: 0x%04x", mem_data->arph->prtype);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrtype = new QTreeWidgetItem(level2);
        arpPrtype->setText(0, showStr);

        sprintf(buf, "硬件地址长度: %d", mem_data->arph->hsize);
        showStr = QString(buf);
        QTreeWidgetItem *arpHsize = new QTreeWidgetItem(level2);
        arpHsize->setText(0, showStr);

        sprintf(buf, "协议地址长度: %d", mem_data->arph->prsize);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrsize = new QTreeWidgetItem(level2);
        arpPrsize->setText(0, showStr);

        sprintf(buf, "操作码: %d", mem_data->arph->opcode);
        showStr = QString(buf);
        QTreeWidgetItem *arpCode = new QTreeWidgetItem(level2);
        arpCode->setText(0, showStr);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->arph->senderMac[0], mem_data->arph->senderMac[1],
                mem_data->arph->senderMac[2], mem_data->arph->senderMac[3], mem_data->arph->senderMac[4], mem_data->arph->senderMac[5]);
        showStr = "发送方MAC: " + QString(buf);
        QTreeWidgetItem *srcArpMac = new QTreeWidgetItem(level2);
        srcArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->arph->senderIp[0], mem_data->arph->senderIp[1], mem_data->arph->senderIp[2]
                ,mem_data->arph->senderIp[3]);
        showStr = "发送方IP: " + QString(buf);
        QTreeWidgetItem *srcArpIp = new QTreeWidgetItem(level2);
        srcArpIp->setText(0, showStr);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", mem_data->arph->destMac[0], mem_data->arph->destMac[1],
                mem_data->arph->destMac[2], mem_data->arph->destMac[3], mem_data->arph->destMac[4], mem_data->arph->destMac[5]);
        showStr = "接收方MAC: " + QString(buf);
        QTreeWidgetItem *destArpMac = new QTreeWidgetItem(level2);
        destArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->arph->destIp[0], mem_data->arph->destIp[1], mem_data->arph->destIp[2]
                ,mem_data->arph->destIp[3]);
        showStr = "接收方IP: " + QString(buf);
        QTreeWidgetItem *destArpIp = new QTreeWidgetItem(level2);
        destArpIp->setText(0, showStr);
    }
    else if(mem_data->ethh->type == 0x0800)     //IP
    {
        //添加IP协议头
        showStr = QString("IP协议头");
        QTreeWidgetItem *level3 = new QTreeWidgetItem(root);
        level3->setText(0, showStr);

        sprintf(buf, "版本: %d", IP_V(mem_data->iph));
        showStr = QString(buf);
        QTreeWidgetItem *ipVersion = new QTreeWidgetItem(level3);
        ipVersion->setText(0, showStr);

        sprintf(buf, "IP首部长度: %d", IP_HL(mem_data->iph));
        showStr = QString(buf);
        QTreeWidgetItem *ipHeaderLen = new QTreeWidgetItem(level3);
        ipHeaderLen->setText(0, showStr);

        sprintf(buf, "服务类型: %d", mem_data->iph->tos);
        showStr = QString(buf);
        QTreeWidgetItem *ipTos = new QTreeWidgetItem(level3);
        ipTos->setText(0, showStr);

        sprintf(buf, "总长度: %d", mem_data->iph->ip_len);
        showStr = QString(buf);
        QTreeWidgetItem *ipTotalLen = new QTreeWidgetItem(level3);
        ipTotalLen->setText(0, showStr);

        sprintf(buf, "标识: 0x%04x", mem_data->iph->identification);
        showStr = QString(buf);
        QTreeWidgetItem *ipIdentify = new QTreeWidgetItem(level3);
        ipIdentify->setText(0, showStr);

        sprintf(buf, "Reserved Fragment Flag: %d", (mem_data->iph->flags_fo & IP_RF) >> 15);
        showStr = QString(buf);
        QTreeWidgetItem *flag0 = new QTreeWidgetItem(level3);
        flag0->setText(0, showStr);

        sprintf(buf, "Don't fragment Flag: %d", (mem_data->iph->flags_fo & IP_DF) >> 14);
        showStr = QString(buf);
        QTreeWidgetItem *flag1 = new QTreeWidgetItem(level3);
        flag1->setText(0, showStr);

        sprintf(buf, "More Fragment Flag: %d", (mem_data->iph->flags_fo & IP_MF) >> 13);
        showStr = QString(buf);
        QTreeWidgetItem *flag3 = new QTreeWidgetItem(level3);
        flag3->setText(0, showStr);

        sprintf(buf, "段偏移: %d", mem_data->iph->flags_fo & IP_OFFMASK);
        showStr = QString(buf);
        QTreeWidgetItem *ipOffset = new QTreeWidgetItem(level3);
        ipOffset->setText(0, showStr);

        sprintf(buf, "生存期: %d", mem_data->iph->ttl);
        showStr = QString(buf);
        QTreeWidgetItem *ipTTL = new QTreeWidgetItem(level3);
        ipTTL->setText(0, showStr);

        sprintf(buf, "协议: %d", mem_data->iph->proto);
        showStr = QString(buf);
        QTreeWidgetItem *ipProto = new QTreeWidgetItem(level3);
        ipProto->setText(0, showStr);

        sprintf(buf, "首部校验和: 0x%04x", mem_data->iph->hchecksum);
        showStr = QString(buf);
        QTreeWidgetItem *ipHCheckSum = new QTreeWidgetItem(level3);
        ipHCheckSum->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->iph->saddr[0], mem_data->iph->saddr[1], mem_data->iph->saddr[2]
                ,mem_data->iph->saddr[3]);
        showStr = "源IP: " + QString(buf);
        QTreeWidgetItem *ipSrcIp = new QTreeWidgetItem(level3);
        ipSrcIp->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", mem_data->iph->daddr[0], mem_data->iph->daddr[1], mem_data->iph->daddr[2]
                ,mem_data->iph->daddr[3]);
        showStr = "目的IP: " + QString(buf);
        QTreeWidgetItem *ipDestIp = new QTreeWidgetItem(level3);
        ipDestIp->setText(0, showStr);

        //处理传输层udp, icmp, tcp
        if(mem_data->iph->proto == PROTO_ICMP)  //ICMP协议
        {
            //添加ICMP协议头
            showStr = QString("ICMP协议头");
            QTreeWidgetItem *level4 = new QTreeWidgetItem(root);
            level4->setText(0, showStr);

            sprintf(buf, "类型: %d", mem_data->icmph->type);
            sprintf(buf, "类型: 应答");
            showStr = QString(buf);
            QTreeWidgetItem *icmpType = new QTreeWidgetItem(level4);
            icmpType->setText(0, showStr);

            sprintf(buf, "代码: %d", mem_data->icmph->code);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCode = new QTreeWidgetItem(level4);
            icmpCode->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->icmph->chk_sum);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCheck = new QTreeWidgetItem(level4);
            icmpCheck->setText(0, showStr);

            sprintf(buf, "标识: 0x%04x", mem_data->icmph->identification);
            showStr = QString(buf);
            QTreeWidgetItem *icmpIdentify = new QTreeWidgetItem(level4);
            icmpIdentify->setText(0, showStr);

            sprintf(buf, "序列号: 0x%04x", mem_data->icmph->seq);
            showStr = QString(buf);
            QTreeWidgetItem *icmpSeq = new QTreeWidgetItem(level4);
            icmpSeq->setText(0, showStr);
        }
        else if(mem_data->iph->proto == PROTO_TCP)  //TCP协议
        {
            showStr = QString("TCP协议头");
            QTreeWidgetItem *level5 = new QTreeWidgetItem(root);
            level5->setText(0, showStr);

            sprintf(buf, "源端口: %d", mem_data->tcph->srcPort);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSrcPort = new QTreeWidgetItem(level5);
            tcpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", mem_data->tcph->destPort);
            showStr = QString(buf);
            QTreeWidgetItem *tcpDestPort = new QTreeWidgetItem(level5);
            tcpDestPort->setText(0, showStr);

            sprintf(buf, "序列号: 0x%08x", mem_data->tcph->seq);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSeq = new QTreeWidgetItem(level5);
            tcpSeq->setText(0, showStr);

            sprintf(buf, "确认号: 0x%08x", mem_data->tcph->ack_sql);
            showStr = QString(buf);
            QTreeWidgetItem *tcpAck = new QTreeWidgetItem(level5);
            tcpAck->setText(0, showStr);

            sprintf(buf, "首部长度: %d bytes (%d)", TH_OFF(mem_data->tcph) * 4, TH_OFF(mem_data->tcph));
            showStr = QString(buf);
            QTreeWidgetItem *tcpOFF = new QTreeWidgetItem(level5);
            tcpOFF->setText(0, showStr);

            sprintf(buf, "FLAG: 0x%02x", mem_data->tcph->th_flags);
            showStr = QString(buf);
            QTreeWidgetItem *tcpFlag = new QTreeWidgetItem(level5);
            tcpFlag->setText(0, showStr);

            sprintf(buf, "CWR: %d", (mem_data->tcph->th_flags & TH_CWR) >> 7);
            showStr = QString(buf);
            QTreeWidgetItem *cwrflag = new QTreeWidgetItem(tcpFlag);
            cwrflag->setText(0, showStr);

            sprintf(buf, "ECE: %d", (mem_data->tcph->th_flags & TH_ECE) >> 6);
            showStr = QString(buf);
            QTreeWidgetItem *eceflag = new QTreeWidgetItem(tcpFlag);
            eceflag->setText(0, showStr);

            sprintf(buf, "URG: %d", (mem_data->tcph->th_flags & TH_URG) >> 5);
            showStr = QString(buf);
            QTreeWidgetItem *urgflag = new QTreeWidgetItem(tcpFlag);
            urgflag->setText(0, showStr);

            sprintf(buf, "ACK: %d", (mem_data->tcph->th_flags & TH_ACK) >> 4);
            showStr = QString(buf);
            QTreeWidgetItem *ackflag = new QTreeWidgetItem(tcpFlag);
            ackflag->setText(0, showStr);

            sprintf(buf, "PUSH: %d", (mem_data->tcph->th_flags & TH_PUSH) >> 3);
            showStr = QString(buf);
            QTreeWidgetItem *pushflag = new QTreeWidgetItem(tcpFlag);
            pushflag->setText(0, showStr);

            sprintf(buf, "RST: %d", (mem_data->tcph->th_flags & TH_RST) >> 2);
            showStr = QString(buf);
            QTreeWidgetItem *rstflag = new QTreeWidgetItem(tcpFlag);
            rstflag->setText(0, showStr);

            sprintf(buf, "SYN: %d", (mem_data->tcph->th_flags & TH_SYN) >> 1);
            showStr = QString(buf);
            QTreeWidgetItem *synflag = new QTreeWidgetItem(tcpFlag);
            synflag->setText(0, showStr);

            sprintf(buf, "FIN: %d", (mem_data->tcph->th_flags & TH_FIN));
            showStr = QString(buf);
            QTreeWidgetItem *finflag = new QTreeWidgetItem(tcpFlag);
            finflag->setText(0, showStr);

            sprintf(buf, "窗口大小: %d", mem_data->tcph->wnd_size);
            showStr = QString(buf);
            QTreeWidgetItem *tcpWndSize = new QTreeWidgetItem(level5);
            tcpWndSize->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->tcph->checksum);
            showStr = QString(buf);
            QTreeWidgetItem *tcpCheck = new QTreeWidgetItem(level5);
            tcpCheck->setText(0, showStr);

            sprintf(buf, "紧急指针: %d", mem_data->tcph->urg_ptr);
            showStr = QString(buf);
            QTreeWidgetItem *tcpUrgPtr = new QTreeWidgetItem(level5);
            tcpUrgPtr->setText(0, showStr);

            if(mem_data->isHttp == true)
            {
                showStr = QString("HTTP协议头");
                QTreeWidgetItem *level8 = new QTreeWidgetItem(root);
                level8->setText(0, showStr);

                QString content = "";
                u_char *httpps = mem_data->apph;

                qDebug() << QString(*httpps) << QString(*(httpps + 1)) << QString(*(httpps + 2)) << endl;

                u_char *httpps2 = NULL;

                const char *token[] = {"GET","POST","HTTP/1.1","HTTP/1.0"};
                for(int i = 0 ; i < 4 ; i ++){
                    httpps2 = (u_char *)strstr((char *)httpps,token[i]);
                    if(httpps2){
                        break;
                    }
                }
                int size = mem_data->httpsize - (httpps2 - httpps);

                for(int i = 0 ; i < size; i++){
                    if(httpps2[i] == 0x0d){
                        //如果到达http正文结尾
                        if(httpps2[i+1] == 0x0a && httpps2[i+2] == 0x0d && httpps2[i+3] == 0x0a){
                            content += "\\r\\n";
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content)));
                            level8->addChild(new QTreeWidgetItem(level8,QStringList("\\r\\n")));
                            break;
                        }
                        else if(httpps2[i+1] == 0x0a){
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content + "\\r\\n")));
                            content = "";
                            i ++;
                            continue;
                        }
                    }
                    content += httpps2[i];
                }
                level8->addChild(new QTreeWidgetItem(level8,QStringList("(Data)(Data)")));
            }
        }
        else if(mem_data->iph->proto == PROTO_UDP)  //UDP协议
        {
            //添加UDP协议头
            showStr = QString("UDP协议头");
            QTreeWidgetItem *level6 = new QTreeWidgetItem(root);
            level6->setText(0, showStr);

            sprintf(buf, "源端口: %d", mem_data->udph->sport);
            showStr = QString(buf);
            QTreeWidgetItem *udpSrcPort = new QTreeWidgetItem(level6);
            udpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", mem_data->udph->dport);
            showStr = QString(buf);
            QTreeWidgetItem *udpDestPort = new QTreeWidgetItem(level6);
            udpDestPort->setText(0, showStr);

            sprintf(buf, "总长度: %d", mem_data->udph->len);
            showStr = QString(buf);
            QTreeWidgetItem *udpLen = new QTreeWidgetItem(level6);
            udpLen->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", mem_data->udph->crc);
            showStr = QString(buf);
            QTreeWidgetItem *udpCrc = new QTreeWidgetItem(level6);
            udpCrc->setText(0, showStr);
        }
    }
}

void MainWindow::showHexData(u_char *print_data, int print_len)
{
    QString tempnum,tempchar;
    QString oneline;
    int i;
    tempchar = "  ";
    oneline = "";
    for(i = 0 ; i < print_len ; i ++){
        if(i % 16 == 0){
            //输出行号
            oneline += tempnum.sprintf("%04x  ",i);
        }
        oneline += tempnum.sprintf("%02x ",print_data[i]);
        if(isprint(print_data[i])){     //判断是否为可打印字符
            tempchar += print_data[i];
        }
        else{
            tempchar += ".";
        }
        if((i+1)%16 == 0){
            ui->detail_text->append(oneline + tempchar);
            tempchar = "\n";
            oneline = "";
        }
    }
    i %= 16;
    for(; i < 16 ; i ++){
        oneline += "  ";
    }
    ui->detail_text->append(oneline + tempchar);
}


//arp欺骗
void MainWindow::on_cheat_clicked()
{
    //initDev(netDeviceNum);
    qDebug()<<"netdevicenum"<<netDeviceNum;
    initDev(0);
    //获取当前网卡mac地址
    selfmac = GetSelfMac(dev->name
                         + 8);//去除“rpcap://”
    destip = ui->target_ip->text();
    destmac = ui->target_mac->text();
    gateip = ui->gate_ip->text();
    gatemac = ui->gate_mac->text();

    if(!(destip != NULL && destmac != NULL && gateip != NULL && gatemac != NULL)){
        QMessageBox::warning(this, "Cheating Error", tr("请输入完整信息，MAC地址可以通过arp缓存表获得"), QMessageBox::Ok);
        return;
    }

//    if(arpthread0 != NULL){
//        delete arpthread0;
//        arpthread0 = NULL;
//    }
     arpthread0= new arpthread();
     connect(this, SIGNAL(setCheatInfo(pcap_t*, u_char*,u_long,u_char*,u_long,u_char*)), arpthread0, SLOT(getCheatInfo(pcap_t*, u_char*,u_long,u_char*,u_long,u_char*)));
    //todo
    const char *destipStr;
    QByteArray ba = destip.toLatin1();
    destipStr = ba.data();
    deli_destip = inet_addr(destipStr);
    if(deli_destip == INADDR_NONE){
        QMessageBox::warning(this, "Cheat Error", tr("目标IP为无效输入!"), QMessageBox::Ok);
        return;
    }
    const char *gateipStr;
    ba = gateip.toLatin1();
    gateipStr = ba.data();
    deli_gateip = inet_addr(gateipStr);
    if(deli_gateip == INADDR_NONE){
        QMessageBox::warning(this, "Cheat Error", tr("网关IP为无效输入!"), QMessageBox::Ok);
        return;
    }
    const char *destMacStr;
    ba = destmac.toLatin1();
    destMacStr = ba.data();
    deli_destmac = (u_char *)malloc(6 * sizeof(u_char));        //注意释放malloc内存
    transMac(destMacStr, deli_destmac);
    const char *gateMacStr;
    ba = gatemac.toLatin1();
    gateMacStr = ba.data();
    deli_gatemac = (u_char *)malloc(6 * sizeof(u_char));        //注意释放malloc内存
    transMac(gateMacStr, deli_gatemac);
    emit setCheatInfo(adhandle, selfmac, deli_destip, deli_destmac, deli_gateip, deli_gatemac);

    arpthread0->start();
//    //重新开一个线程用于转发数据包
//    if (dev->addresses != NULL)
//        /* 获取接口第一个地址的掩码 */
//        netmask=((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
//    else
//        netmask=0xffffff;
//    //设置过滤规则，只捕获arp数据包
//    if (pcap_compile(adhandle, &fcode, filters, 1, netmask) < 0)
//    {
//        QMessageBox::warning(this, "Cheat Error!", tr("过滤规则编译失败"), QMessageBox::Ok);
//        pcap_freealldevs(alldevs);
//        return;
//    }
//    // set the filter
//    if (pcap_setfilter(adhandle, &fcode) < 0)
//    {
//        QMessageBox::warning(this, "Cheat Error!", tr("过滤规则编译失败"), QMessageBox::Ok);
//        pcap_freealldevs(alldevs);
//        return;
//    }

    //pcap_freealldevs(alldevs);

}

int MainWindow::initDev(int interface_index)
{
    //获取本机网卡列表
    if(pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
        QMessageBox::warning(this, "Cheating Error", tr("获取本机网卡列表失败"), QMessageBox::Ok);
        return -1;
    }
    //移动指针到用户选择的网卡
    int i;
    for(dev = alldevs, i = 0; i < interface_index - 1; dev = dev->next, i++);
    //打开网卡
    if((adhandle = pcap_open_live(dev->name,    //设备名
                                  65536,    //捕获数据包长度
                                  1,    //设置成混杂模式
                                  1000,    //读超时设置
                                  errbuf  //错误信息缓冲
                                  )) == NULL)
    {
        QMessageBox::warning(this, "cheating error", tr("网卡接口打开失败"), QMessageBox::Ok);
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return -1;
    }

    //pcap_freealldevs(alldevs);
    return 0;
}

//将mac字符串转换成6位MAC地址
void MainWindow::transMac(const char source[], u_char *dest)
{
    short i;
    int sourceLen = strlen(source);
    unsigned char highByte, lowByte;
    for (i = 0; i < sourceLen; i += 3)
    {
        highByte = toupper(source[i]);
        lowByte  = toupper(source[i + 1]);
        if(highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;
        if(lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;
        dest[i/3] = (highByte << 4) | lowByte;
    }
}

u_char* MainWindow::GetSelfMac(char *pDevName)
{
    static u_char mac[6];

    memset(mac, 0, sizeof(mac));

    LPADAPTER lpAdapter = PacketOpenAdapter(pDevName);

    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
    {
        return NULL;
    }
    //allocate a buffer to get the MAC address
    PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
    if (OidData == NULL)
    {
        printf("error allocating memory!\n");
        PacketCloseAdapter(lpAdapter);
        return NULL;
    }

    //retrive the adapter MAC querying the NIC driver
    OidData->Oid = OID_802_3_CURRENT_ADDRESS;

    OidData->Length = 6;
    memset(OidData->Data, 0, 6);
    BOOLEAN Status = PacketRequest(lpAdapter, false, OidData);
    if (Status)
    {
        memcpy(mac, (u_char *)(OidData->Data), 6);
    }
    free(OidData);
    PacketCloseAdapter(lpAdapter);
    return mac;
}

void MainWindow::on_pushButton_clicked()
{

    arpthread0->stop();
}
