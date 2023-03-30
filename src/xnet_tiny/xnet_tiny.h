#ifndef XNET_TINY_H
#define XNET_TINY_H

#include<stdint.h>

#define XNET_CFG_NETIF_IP {192, 168, 159, 100} //虚拟IP地址

#define XNET_MAC_ADDR_SIZE 6//MAC地址长度
#define XNET_IPV4_ADDR_SIZE 4//IP地址长度

#pragma pack(1)
//协议类型
typedef enum _xnet_protocol_t {
    XNET_PROTOCOL_ARP = 0x0806,
    XNET_PROTOCOL_IPV4 = 0x0800,
    XNET_PROTOCOL_ICMP = 1,
    XNET_PROTOCOL_UDP = 17,
    XNET_PROTOCOL_TCP = 6,
} xnet_protocol_t;

//ether以太网报头
typedef struct _xether_hdr_t {
    uint8_t dest[XNET_MAC_ADDR_SIZE];
    uint8_t src[XNET_MAC_ADDR_SIZE];
    uint16_t protocol;
} xether_hdr_t;

//硬件地址类型
#define XARP_HW_ETHER 0x1
//ARP协议报头 操作码
#define XARP_REQUEST 0X1
#define XARP_REPLY 0x2

//ARP协议报头
typedef struct _xarp_packet_t {
    uint16_t hw_type, pro_type;
    uint8_t hw_len, pro_len;
    uint16_t opcode;
    uint8_t sender_mac[XNET_MAC_ADDR_SIZE];
    uint8_t sender_ip[XNET_IPV4_ADDR_SIZE];
    uint8_t target_mac[XNET_MAC_ADDR_SIZE];
    uint8_t target_ip[XNET_IPV4_ADDR_SIZE];
} xarp_packet_t;


#define XNET_VERSION_IPV4 0x4 // IP 版本号
#define XNET_IP_DEFAULT_TTL 64;//IP报文默认ttl

//IP协议报头
typedef struct _xip_hdr_t {
    uint8_t hdr_len : 4;//报头长度
    uint8_t version : 4;
    uint8_t tos;//服务类型
    uint16_t total_len;//总长度
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_checksum;
    uint8_t src_ip[XNET_IPV4_ADDR_SIZE];
    uint8_t dest_ip[XNET_IPV4_ADDR_SIZE];
} xip_hdr_t;

#define XICMP_TYPE_ECHO_REQUEST 8
#define XICMP_TYPE_ECHO_REPLY 0
#define XICMP_TYPE_UNREACH 3


#define XICMP_CODE_PROTOCOL_UNREACH 3
#define XICMP_CODE_PORT_UNREACH 4

//ICMP协议报头
typedef struct _xicmp_hdr_t {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
}xicmp_hdr_t;

//UDP协议报头
typedef struct _xudp_hdr_t {
    uint16_t src_port, dest_port;
    uint16_t total_len;
    uint16_t checksum;
} xudp_hdr_t;

//TCP协议报头
typedef struct _xtcp_hdr_t {
    uint16_t src_port, dest_port;
    uint32_t seq, ack;//序列号，响应号
    
#define XTCP_FLAG_FIN   (1 << 0) 
#define XTCP_FLAG_SYN   (1 << 1)
#define XTCP_FLAG_RST   (1 << 2)
#define XTCP_FLAG_ACK   (1 << 4)
    union {
        struct {
            uint16_t flags : 6;
            uint16_t reverseved : 6;
            uint16_t hdr_len : 4;
        };
        uint16_t all;
    }hdr_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} xtcp_hdr_t;
#pragma pack()


//ip地址 数据类型
typedef union _xipaddr_t {
    uint8_t array[XNET_IPV4_ADDR_SIZE];
    uint32_t addr;
} xipaddr_t;

//IP-ARP映射表状态
#define XARP_ENTRY_FREE 0
#define XARP_ENTRY_OK 1
#define XARP_ENTRY_PENDING 2
//tmo retry_cnt取值
#define XARP_CFG_ENTRY_PENDING_TMO (1)
#define XARP_CFG_ENTRY_OK_TMO (5)
#define XARP_CFG_MAX_RETRIES (4)
//检查ARP表的间隔时间
#define XARP_TIMER_PERIOD 1
//IP-ARP映射表项
typedef struct _xarp_entry_t {
    xipaddr_t ipaddr;
    uint8_t macaddr[XNET_MAC_ADDR_SIZE];
    uint8_t state;
    uint16_t tmo;
    uint8_t retry_cnt;
} xarp_entry_t;

typedef uint32_t xnet_time_t;

const xnet_time_t xsys_get_time();//获取程序运行时间

////////////////////////////////////////////////////////////////////////

typedef enum _xnet_err_t {
    XNET_ERR_OK = 0,
    XNET_ERR_IO = -1,
    XNET_ERR_NONE = -2,
    XNET_ERR_BINDED = -3,
} xnet_err_t;

#define XNET_CFG_PACKET_MAX_SIZE 1516 //包括2个字节的crc
typedef struct _xnet_packet_t {
    uint16_t size;
    uint8_t *data;
    uint8_t payload[XNET_CFG_PACKET_MAX_SIZE];
} xnet_packet_t;
//////  UDP socket控制块
#define XUDP_CFG_MAX_UDP 10

typedef struct _xudp_t xudp_t;

typedef xnet_err_t (*xudp_handler_t)(xudp_t *udp, xipaddr_t *src_ip, uint16_t src_port);

typedef struct _xudp_t {
    enum {
        XUDP_STATE_FREE,
        XUDP_STATE_USED,
    } state;
    uint16_t local_port;
    xudp_handler_t handler;
} xudp_t;

xudp_t* xudp_open(xudp_handler_t handler);
void xudp_close(xudp_t *udp);
xudp_t* xudp_find(uint16_t port);
xnet_err_t xudp_bind(xudp_t* udp, uint16_t local_port);

////////  TCP socket 控制块
#define XTCP_CFG_MAX_TCP 40

typedef enum _xtcp_conn_state_t {
    XTCP_CONN_CONNECTED,
    XTCP_CONN_DATA_RECV,
    XTCP_CONN_CLOSED,
}xtcp_conn_state_t;

#define XTCP_KIND_END   0
#define XTCP_KIND_MSS   2
#define XTCP_MSS_DEFAULT    1460

typedef struct _xtcp_t xtcp_t;
typedef xnet_err_t (*xtcp_handler_t)(xtcp_t *tcp, xtcp_conn_state_t event);

typedef struct _xtcp_t {
    enum {
        XTCP_STATE_FREE,
        XTCP_STATE_CLOSED,
        XTCP_STATE_LISTEN,
        XTCP_STATE_SYN_RECVD,
        XTCP_STATE_ESTABLISHED,
        XTCP_STATE_FIN_WAIT1,
        XTCP_STATE_FIN_WAIT2,
        XTCP_SATTE_CLOSING,
        XTCP_STATE_TIMED_WAIT,
        XTCP_STATE_CLOSE_WAIT,
        XTCP_STATE_LAST_ACK,
    } state;
    uint16_t local_port, remote_port;
    xipaddr_t remote_ip;

    uint32_t next_seq;
    uint32_t ack;

    uint16_t remote_mss;
    uint16_t remote_win;
    xtcp_handler_t handler;
} xtcp_t;

xtcp_t *xtcp_open(xtcp_handler_t handler);
xnet_err_t xtcp_bind(xtcp_t *tcp, uint16_t local_port);
xnet_err_t xtcp_listen(xtcp_t *tcp);
xnet_err_t xtcp_close(xtcp_t *tcp);


xnet_err_t xnet_driver_open(uint8_t* mac_addr);
xnet_err_t xnet_driver_send(xnet_packet_t* packet);
xnet_err_t xnet_driver_read(xnet_packet_t** packet);

xnet_packet_t* xnet_alloc_for_send(uint16_t data_size);
xnet_packet_t* xnet_alloc_for_read(uint16_t data_size);

void add_header(xnet_packet_t *packet, uint16_t header_size);
void remove_header(xnet_packet_t *packet, uint16_t header_size);
void truncate_packet(xnet_packet_t *packet, uint16_t size);

void xnet_init();
void xnet_poll();

xnet_err_t xudp_out(xudp_t *udp, xipaddr_t *dest_ip, uint16_t dest_port, xnet_packet_t *packet);
#endif