#include "xnet_tiny.h"
#include <string.h>
#define min(a, b) ((a) < (b) ? (a) : (b))
static const xipaddr_t netif_ipaddr = XNET_CFG_NETIF_IP;//虚拟IP地址
static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];//虚拟MAC地址
static const uint8_t ether_broadcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};//广播MAC地址

static xnet_packet_t tx_packet, rx_packet;//xnet的读写缓冲区
static xarp_entry_t arp_entry;//IP-ARP映射表
static xnet_time_t arp_timer;

static int xnet_check_tmo(xnet_time_t *time, uint32_t sec) {
    xnet_time_t curr = xsys_get_time();
    if (sec == 0) {
        *time = curr;
    } else if (curr - *time > sec) {
        *time = curr;
        return 1;
    }
    return 0;
}

static void update_arp_entry(uint8_t* src_ip, uint8_t *mac_addr) {
    memcpy(arp_entry.ipaddr.array, src_ip, XNET_IPV4_ADDR_SIZE);
    memcpy(arp_entry.macaddr, mac_addr, XNET_MAC_ADDR_SIZE);
    arp_entry.state = XARP_ENTRY_OK;
    arp_entry.tmo = XARP_CFG_ENTRY_OK_TMO;
    arp_entry.retry_cnt = XARP_CFG_MAX_RETRIES;
}

static uint16_t swap_order16(uint16_t x) {
    x = ((x & 0xff00) >> 8) | ((x & 0xff) << 8);
    return x;
}

static uint8_t xipaddr_is_equal_buf(xipaddr_t *ip, uint8_t *buf) {
    if (memcmp(ip->array, buf, XNET_IPV4_ADDR_SIZE) == 0) {
        return 1;
    }
    return 0;
}

xnet_packet_t* xnet_alloc_for_send(uint16_t data_size) {
    tx_packet.data = tx_packet.payload + XNET_CFG_PACKET_MAX_SIZE - data_size;
    tx_packet.size = data_size;
    return &tx_packet;
}

xnet_packet_t* xnet_alloc_for_read(uint16_t data_size) {
    rx_packet.data = rx_packet.payload;
    rx_packet.size = data_size;
    return &rx_packet;
}


static void add_header(xnet_packet_t *packet, uint16_t header_size) {
    packet->data -= header_size;
    packet->size += header_size;
}

static void remove_header(xnet_packet_t *packet, uint16_t header_size) {
    packet->data += header_size;
    packet->size -= header_size;
}

static void truncate_packet(xnet_packet_t *packet, uint16_t size) {
    packet->size = min(packet->size, size);
}

static xnet_err_t ethernet_out_to(xnet_protocol_t protocol, const uint8_t *mac_addr, xnet_packet_t *packet) {
    xether_hdr_t *ether_hdr;

    add_header(packet, sizeof(xether_hdr_t));
    ether_hdr = (xether_hdr_t *)packet->data;
    memcpy(ether_hdr->dest, mac_addr, XNET_MAC_ADDR_SIZE);
    memcpy(ether_hdr->src, netif_mac, XNET_MAC_ADDR_SIZE);
    ether_hdr->protocol = swap_order16(protocol);
    
    return xnet_driver_send(packet);
}

xnet_err_t xarp_make_request(const xipaddr_t *ipaddr) {
    xnet_packet_t* packet = xnet_alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t* arp_packet = (xarp_packet_t *)packet->data;

    arp_packet->hw_type = swap_order16(XARP_HW_ETHER);
    arp_packet->pro_type = swap_order16(XNET_PROTOCOL_IPV4);
    arp_packet->hw_len = XNET_MAC_ADDR_SIZE;
    arp_packet->pro_len = XNET_IPV4_ADDR_SIZE;
    arp_packet->opcode = swap_order16(XARP_REQUEST);
    memcpy(arp_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memset(arp_packet->target_mac, 0, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->target_ip, ipaddr->array, XNET_IPV4_ADDR_SIZE);
    return ethernet_out_to(XNET_PROTOCOL_ARP, ether_broadcast, packet);
}

static void xarp_init() {
    arp_entry.state = XARP_ENTRY_FREE;
    xnet_check_tmo(&arp_timer, 0);
}

static xnet_err_t ethernet_init() {
    xnet_driver_open(netif_mac);
    return xarp_make_request(&netif_ipaddr);
}

void xnet_init() {
    ethernet_init();
    xarp_init();
}

/////////////////////////////////////////////////////////

static xnet_err_t xarp_make_response(xarp_packet_t *arp_packet) {
    xnet_packet_t* packet = xnet_alloc_for_send(sizeof(xarp_packet_t));
    xarp_packet_t* response_packet = (xarp_packet_t *)packet->data;

    response_packet->hw_type = swap_order16(XARP_HW_ETHER);
    response_packet->pro_type = swap_order16(XNET_PROTOCOL_IPV4);
    response_packet->hw_len = XNET_MAC_ADDR_SIZE;
    response_packet->pro_len = XNET_IPV4_ADDR_SIZE;
    response_packet->opcode = swap_order16(XARP_REPLY);
    memcpy(response_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memcpy(response_packet->target_mac, arp_packet->sender_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->target_ip, arp_packet->sender_ip, XNET_IPV4_ADDR_SIZE);
    return ethernet_out_to(XNET_PROTOCOL_ARP, arp_packet->sender_mac, packet);
}


static void xarp_in(xnet_packet_t *packet) {
    if (packet->size < sizeof(xarp_packet_t)) {
        return;
    }
    xarp_packet_t *arp_packet = (xarp_packet_t *)packet->data;
    uint16_t opcode = swap_order16(arp_packet->opcode);
    if ((swap_order16(arp_packet->hw_type) != XARP_HW_ETHER) || 
        (arp_packet->hw_len != XNET_MAC_ADDR_SIZE) ||
        (swap_order16(arp_packet->pro_type) != XNET_PROTOCOL_IPV4) || 
        (arp_packet->pro_len != XNET_IPV4_ADDR_SIZE) ||
        (opcode != XARP_REPLY && opcode != XARP_REQUEST)) {
        return;
    }

    if (!xipaddr_is_equal_buf(&netif_ipaddr, arp_packet->target_ip)) {
        return;
    }

    switch (opcode) {
        case XARP_REQUEST:
            xarp_make_response(arp_packet);
            update_arp_entry(arp_packet->sender_ip, arp_packet->sender_mac);
            break;
        case XARP_REPLY:
            update_arp_entry(arp_packet->sender_ip, arp_packet->sender_mac);
            break;
    }
}

static void ethernet_in(xnet_packet_t *packet) {
    xether_hdr_t *ether_hdr;
    uint16_t protocol;
    if (packet->size <= sizeof(xether_hdr_t)) {
        return;
    }
    ether_hdr = (xether_hdr_t *)packet->data;
    protocol = swap_order16(ether_hdr->protocol);
    switch (protocol) {
        case XNET_PROTOCOL_ARP:
            remove_header(packet, sizeof(xether_hdr_t));
            xarp_in(packet);
            break;
        case XNET_PROTOCOL_IPV4:
            break;
    }
}

static void xarp_poll() {
    if (xnet_check_tmo(&arp_timer,  XARP_TIMER_PERIOD)) {
        switch (arp_entry.state) {
            case XARP_ENTRY_OK:
                if (--arp_entry.tmo == 0) {
                    xarp_make_request(&arp_entry.ipaddr);
                    arp_entry.state = XARP_ENTRY_PENDING;
                    arp_entry.tmo = XARP_CFG_ENTRY_PENDING_TMO;
                }
                break;
            case XARP_ENTRY_PENDING:
                if (--arp_entry.tmo == 0) {
                    if (arp_entry.retry_cnt-- == 0) {
                        arp_entry.state  = XARP_ENTRY_FREE;
                    } else {
                        xarp_make_request(&arp_entry.ipaddr);
                        arp_entry.state = XARP_ENTRY_PENDING;
                        arp_entry.tmo = XARP_CFG_ENTRY_PENDING_TMO;
                    }
                }
                break;
        }
    }
}

static void ethernet_poll() {
    xnet_packet_t *packet;
    if (xnet_driver_read(&packet) == XNET_ERR_OK) {
        ethernet_in(packet);
    }
}

void xnet_poll() {
    ethernet_poll();
    xarp_poll();
}