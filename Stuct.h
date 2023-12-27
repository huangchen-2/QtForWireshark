#ifndef STUCT_H
#define STUCT_H
#include "pcap.h"
#include <QMetaType>
#include <time.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock.h>
#endif

#define IPTOSBUFFERS    12
#define ETH_ALEN 6
#include <QObject>
struct DeviceInfo
{
    QString Description ;//名称
    QString IPv4Address = "无";//地址
    QString NetMask = "无" ;//子网掩码
    QString IPv6Address = "无" ;//地址
    QString Broadcast = "无";//广播地址

};

struct ether_header {
    uint8_t  ether_dhost[ETH_ALEN];   /* 目的MAC地址 */
    uint8_t  ether_shost[ETH_ALEN];   /* 源MAC地址 */
    uint16_t ether_type;              /* 以太网类型字段 */
};



/* 4字节的IP地址 */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header {
    u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  tos;            // 服务类型(Type of service)
    u_short tlen;           // 总长(Total length)
    u_short identification; // 标识(Identification)
    u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    u_char  ttl;            // 存活时间(Time to live)
    u_char  proto;          // 协议(Protocol)
    u_short crc;            // 首部校验和(Header checksum)
    ip_address  saddr;      // 源地址(Source address)
    ip_address  daddr;      // 目的地址(Destination address)
    u_int   op_pad;         // 选项与填充(Option + Padding)

}ip_header;

// UDP 首部
typedef struct udp_header
{
    u_short sport;          // 源端口(Source port)
    u_short dport;          // 目的端口(Destination port)
    u_short len;            // UDP数据包长度(Datagram length)
    u_short crc;            // 校验和(Checksum)
}udp_header;

//TCP首部
typedef struct tcp_header
{
    unsigned short src_port;    //源端口号
    unsigned short dst_port;    //目的端口号
    unsigned int seq_no;        //序列号
    unsigned int ack_no;        //确认号
#if LITTLE_ENDIAN
    unsigned char reserved_1 : 4; //保留6位中的4位首部长度
    unsigned char thl : 4;        //tcp头部长度
    unsigned char flag : 6;       //6位标志
    unsigned char reseverd_2 : 2; //保留6位中的2位
#else
    unsigned char thl : 4;        //tcp头部长度
    unsigned char reserved_1 : 4; //保留6位中的4位首部长度
    unsigned char reseverd_2 : 2; //保留6位中的2位
    unsigned char flag : 6;       //6位标志
#endif
    unsigned short wnd_size;    //16位窗口大小
    unsigned short chk_sum;     //16位TCP检验和
    unsigned short urgt_p;      //16为紧急指针
    unsigned char syn = 0;           //同步序列编号
}tcp_hdr;

struct ProtoInfo
{
    int index = 0 ;
    QString time = "";
    int len = 0 ;
    QString src = "";
    QString dst = "";
    ushort src_port = 0 ;
    ushort dst_port = 0 ;
    uint seq = 0 ;
    uint ack = 0 ;
    QByteArray array = "";
    QString proto = "";
    QString src_mac;
    QString dst_mac;
    uchar dscp;
    uchar ecn;
};

Q_DECLARE_METATYPE(ProtoInfo);



#endif // STUCT_H
