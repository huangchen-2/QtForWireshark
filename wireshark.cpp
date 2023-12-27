#include "wireshark.h"
#include "ui_wireshark.h"

#pragma comment(lib, "Ws2_32.lib")


#define SET_BOOL_VALUE(value) \
do { \
        if (value) { \
            bool_value = true; \
    } else { \
            bool_value = false; \
    } \
} while (0)



bool isWebSocketPacket(const u_char* pkt_data, int ip_len);



    Wireshark::Wireshark(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Wireshark)
{
    ui->setupUi(this);
    //  qRegisterMetaType<tcpInfo>("tcpInfo");
    select = new WireSharkSelectUi();
    select->show();
    connect(this,&Wireshark::SendProto,select,&WireSharkSelectUi::getProto);
    this->setStyleSheet("QToolTip{border:1px solid rgb(118, 118, 118);white-space: nowrap;");
    deviceTranslationTable["WAN Miniport (Network Monitor)"] = "本地连接（网络监控）";
    deviceTranslationTable["WAN Miniport (IPv6)"] = "本地连接（IPv6）";
    deviceTranslationTable["WAN Miniport (IP)"] = "本地连接（IP）";
    deviceTranslationTable["Bluetooth Device (Personal Area Network)"] = "蓝牙网络连接";
    deviceTranslationTable["VMware Virtual Ethernet Adapter for VMnet8"] = "VMware虚拟以太网适配器（VMnet8）";
    deviceTranslationTable["VMware Virtual Ethernet Adapter for VMnet1"] = "VMware虚拟以太网适配器（VMnet1）";
    deviceTranslationTable["RZ616 Wi-Fi 6E 160MHz"] = "WLAN";
    deviceTranslationTable["Microsoft Wi-Fi Direct Virtual Adapter #2"] = "本地连接(虚拟网卡) #2";
    deviceTranslationTable["Microsoft Wi-Fi Direct Virtual Adapter"] = "本地连接(虚拟网卡)";
    deviceTranslationTable["Adapter for loopback traffic capture"] = "Adapter for loopback traffic capture";
    deviceTranslationTable["Realtek PCIe GbE Family Controller"] = "硬件设备";


    future =   QtConcurrent::run(this,&Wireshark::initDevice);
    QFutureWatcher<void>* theWatcher = new QFutureWatcher<void>;
    connect(theWatcher,&QFutureWatcher<void>::finished,this,[this]{labelSetToolTip();});
    theWatcher->setFuture(future);




}

Wireshark::~Wireshark()
{
    qDebug()<<"子界面析构";
    delete ui;
}


void Wireshark::ifprint(pcap_if_t *d)
{
    pcap_addr_t *a;
    char ip6str[128];
    DeviceInfo deviceinfo;

    /* 设备名(Name) */
    printf("%s\n",d->name);

    /* 设备描述(Description) */
    if (d->description)
        printf("\tDescription: %s\n",d->description);
    QString input = d->description;
    if(!list.contains(input))
    {
        list.append(input);
    }
    int startIndex = input.indexOf('\'');
    int endIndex = input.indexOf('\'', startIndex + 1);
    if (startIndex != -1 && endIndex != -1) {
        QString output = input.mid(startIndex + 1, endIndex - startIndex - 1);
        deviceinfo.Description = output;
    }

    /* 回环地址*/
    printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

    /* IP 地址 */
    for(a=d->addresses;a;a=a->next) {
        switch(a->addr->sa_family)
        {
        case AF_INET:
            if (a->addr)
                deviceinfo.IPv4Address = iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
            if (a->netmask)
                deviceinfo.NetMask = iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
            if (a->broadaddr)
                deviceinfo.Broadcast = iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr);
            if (a->dstaddr)
                break;

        case AF_INET6:
            if (a->addr)
                deviceinfo.IPv6Address = ip6tos(a->addr, ip6str, sizeof(ip6str));
            break;

        default:
            break;
        }
    }
    if(!deviceMap.contains(deviceinfo.Description))
    {
        deviceMap.insert(deviceinfo.Description,deviceinfo);
    }
}


/* 将数字类型的IP地址转换成字符串类型的 */

char * Wireshark::iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* Wireshark::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif


    if(getnameinfo(sockaddr,sockaddrlen,address,addrlen,NULL,0,NI_NUMERICHOST) != 0)
        address = NULL;

    return address;
}

void Wireshark::closeEvent(QCloseEvent *event)
{
    //    qDebug()<<"关闭事件";
    SET_BOOL_VALUE(1);
}

void Wireshark::labelSetToolTip()
{
    for(auto i : deviceMap)
    {
        int index = 0 ;
        QListWidgetItem * item = new QListWidgetItem();
        ui->listWidget->addItem(item);
        item->setText(deviceTranslationTable[i.Description]);
        if(i.IPv4Address == "")
            i.IPv4Address = "无";
        if(i.NetMask == "")
            i.NetMask = "无";
        if(i.IPv6Address == "")
            i.IPv6Address = "无";
        if(i.Broadcast == "")
            i.Broadcast = "无";
        item->setToolTip(QString("<html><b>IPv4地址:</b> %1<br><b>子网掩码:</b> %2<br><b>IPv6地址:</b> %3<br><b>广播地址:</b> %4</html>")
                             .arg((i.IPv4Address))
                             .arg((i.NetMask))
                             .arg((i.IPv6Address))
                             .arg((i.Broadcast)));

        index++;

    }
}

void packet_handler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data)
{

    if(((Wireshark*)param)->bool_value)
    {
        pcap_breakloop(((Wireshark*)param)->adhandle);
        return ;
    }
    ProtoInfo info ;
    ip_header* ih;
    udp_header* uh;
    tcp_header* th;
    QVariant var;
    struct tm ltime;
    char timestr[16];
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;


    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

    info.time = timestr;

    /* 打印数据包的时间戳和长度 */

    /* 获得IP数据包头部的位置 */
    ih = (ip_header*)(pkt_data + 14); //以太网头部长度  14字节为mac头长度

    info.src = QString("%1.%2.%3.%4").arg(ih->saddr.byte1) \
                   .arg(ih->saddr.byte2)\
                   .arg(ih->saddr.byte3)\
                   .arg(ih->saddr.byte4);
    info.dst = QString("%1.%2.%3.%4").arg(ih->daddr.byte1) \
                   .arg(ih->daddr.byte2)\
                   .arg(ih->daddr.byte3)\
                   .arg(ih->daddr.byte4);

    /* 获取MAC地址 */
    struct ether_header *eth = (struct ether_header *)(pkt_data);
    char mac_str[20];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
             eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    info.src_mac = mac_str;
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
             eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    info.dst_mac = mac_str;

    info.dscp = ih->tos & 0x3F;
    info.ecn = ih->tos & 0xC0;
    if (IPPROTO_TCP == ih->proto)
    {
        ip_len = (ih->ver_ihl & 0xf) * 4;

        u_short tlen = ntohs(ih->tlen);

        th = (tcp_header*)((u_char*)ih + ip_len);

        sport = ntohs(th->src_port);
        dport = ntohs(th->dst_port);
        info.len = header->len;

        info.src_port = sport;
        info.dst_port = dport;
        info.ack = th->ack_no;
        info.seq = th->seq_no;

        int thl = th->thl * 4; // Calculate the TCP header length in bytes
        u_char* payload = (u_char*)th + thl; // Calculate the start of the TCP payload
        int payload_len = tlen - ip_len - thl; // Calculate the length of the TCP payload

        if (payload_len > 0 && payload[0] == 'U' && payload[1] == 'p' && payload[2] == 'g' && payload[3] == 'r' && payload[4] == 'a' && payload[5] == 'd' && payload[6] == 'e')
        {
            // This is a WebSocket connection
            info.proto = "WebSocket";
        }
        else
        {
            // This is a regular TCP connection
            info.proto = "TCP";
        }

        for (int i = 0; i < header->len; i++)
        {
            info.array.append(pkt_data[i]);
        }
        var.setValue(info);
        ((Wireshark*)param)->SendProto(var);
    }



    if (IPPROTO_UDP == ih->proto)
    {
        ip_len = (ih->ver_ihl & 0xf) * 4;
        uh = (udp_header*)((u_char*)ih + ip_len);

        sport = ntohs(uh->sport);
        dport = ntohs(uh->dport);
        info.len = header->len;
        info.src_port = sport;
        info.dst_port = dport;
        info.proto = "Udp";
        isWebSocketPacket(pkt_data,ip_len);
        for (int i = 0; i < header->len; i++) {
            info.array.append(pkt_data[i]);
        }
        var.setValue(info);
        ((Wireshark*)param)->SendProto(var);

    }

}

bool isWebSocketPacket(const u_char* pkt_data, int ip_len) {
    // WebSocket协议的数据包以0x81或0x82开头，可以根据这个特征来判断
    if ((pkt_data[ip_len] & 0x0F) != 0) {
        return true;
    }
    return false;
}

/**
 * @brief Wireshark::initDevice
 * 初始化设备
 */
void Wireshark::initDevice()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    char source[PCAP_ERRBUF_SIZE+1];

    fgets(source, PCAP_ERRBUF_SIZE, stdin);
    source[PCAP_ERRBUF_SIZE] = '\0';

    /* 获得接口列表 */
    if (pcap_findalldevs_ex(source, NULL, &alldevs, errbuf) == -1)
    {
        exit(1);
    }

    /* 扫描列表并打印每一项 */
    for(d=alldevs;d;d=d->next)
    {
        deviceList.append(d);
        ifprint(d);
    }
    emit SendInitOk();
    // pcap_freealldevs(alldevs);

}

void Wireshark::OpenSelectDevice(pcap_if_t * d)
{

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    struct pcap_pkthdr *header;    //接收到的数据包的头部
    const u_char *pkt_data;			  //接收到的数据包的内容
    int res;

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        exit(1);
    }

    /* 打开设备 */
    if ( (adhandle= pcap_open(d->name,          // 设备名
                              65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容

                              PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                              1000,             // 读取超时时间
                              NULL,             // 远程机器验证
                              errbuf            // 错误缓冲池
                              ) ) == NULL)
    {
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
    }

    pcap_loop(adhandle, 0, packet_handler, (u_char*)this);




}


void Wireshark::on_listWidget_itemDoubleClicked(QListWidgetItem *item)
{
    QString str = item->text();
    try
    {
        for(int i=0;i<deviceList.size();i++)
        {
            if(list.at(i).contains(deviceTranslationTable.key(str)))
            {
                future = QtConcurrent::run(this,&Wireshark::OpenSelectDevice,deviceList[i]);
                select->current_name  = str ;
            }
        }
    }
    catch(...)
    {
        QMessageBox::information(this,"error","open error");
    }


}

