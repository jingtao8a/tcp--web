#include "xnet_tiny.h"
#include <string.h>
#define min(a, b) ((a) < (b) ? (a) : (b))
#define swap_order16(x) (((x) & 0xff00) >> 8) | (((x) & 0xff) << 8)

static xnet_packet_t tx_packet, rx_packet;
static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];//源mac地址

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
    ether_hdr->protocol = protocol;
    
    return xnet_driver_send(packet);
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
            break;
        case XNET_PROTOCOL_IP:
            break;
    }
}

static void ethernet_poll() {
    xnet_packet_t *packet;
    if (xnet_driver_read(&packet) == XNET_ERR_OK) {
        ethernet_in(packet);
    }
}

static xnet_err_t ethernet_init() {
    return xnet_driver_open(netif_mac);
}

void xnet_init() {
    ethernet_init();
}

void xnet_poll() {
    ethernet_poll();
}