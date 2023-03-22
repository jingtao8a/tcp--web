#ifndef XNET_TINY_H
#define XNET_TINY_H

#include<stdint.h>

#define XNET_CFG_NETIF_IP {192, 168, 159, 100} //虚拟IP地址
#define XNET_CFG_PACKET_MAX_SIZE 1516 //包括2个字节的crc
#define XNET_MAC_ADDR_SIZE 6//MAC地址长度
#define XNET_IPV4_ADDR_SIZE 4//IP地址长度

#pragma pack(1)
//ether以太网报头 协议类型
typedef enum _xnet_protocol_t {
    XNET_PROTOCOL_ARP = 0x0806,
    XNET_PROTOCOL_IPV4 = 0x0800,
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

const xnet_time_t xsys_get_time();

////////////////////////////////////////////////////////////////////////

typedef enum _xnet_err_t {
    XNET_ERR_OK = 0,
    XNET_ERR_IO = -1,
} xnet_err_t;

typedef struct _xnet_packet_t {
    uint16_t size;
    uint8_t *data;
    uint8_t payload[XNET_CFG_PACKET_MAX_SIZE];
} xnet_packet_t;

xnet_err_t xnet_driver_open(uint8_t* mac_addr);
xnet_err_t xnet_driver_send(xnet_packet_t* packet);
xnet_err_t xnet_driver_read(xnet_packet_t** packet);

xnet_packet_t* xnet_alloc_for_send(uint16_t data_size);
xnet_packet_t* xnet_alloc_for_read(uint16_t data_size);

void xnet_init();
void xnet_poll();

#endif