#include "xnet_tiny.h"
#include <string.h>
#include <stdlib.h>

#define tcp_get_init_seq()      ((rand() << 16)  + rand())
#define XTCP_DATA_MAX_SIZE  (XNET_CFG_PACKET_MAX_SIZE - sizeof(xether_hdr_t) - sizeof(xip_hdr_t) - sizeof(xtcp_hdr_t))


static xipaddr_t netif_ipaddr = XNET_CFG_NETIF_IP;//虚拟IP地址
static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];//虚拟MAC地址
static uint8_t ether_broadcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};//广播MAC地址

static xnet_packet_t tx_packet, rx_packet;//xnet的读写缓冲区
static xarp_entry_t arp_entry;//IP-ARP映射表
static xnet_time_t arp_timer; //ARP 扫描定时
static xudp_t udp_socket[XUDP_CFG_MAX_UDP];
static xtcp_t tcp_socket[XTCP_CFG_MAX_TCP];

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

static uint16_t checksum16 (uint16_t *buf, uint16_t len, uint16_t pre_sum, int complement) {
    uint32_t checksum = pre_sum;//pre_sum
    uint16_t high;
    while (len > 1) {
        checksum += *buf;
        buf++;
        len -= 2;
    }

    if (len > 0) {
        checksum += *(uint8_t *)buf;
    }

    while ((high = checksum >> 16) != 0) {
        checksum = high + (checksum & 0xffff);
    }
    if (complement) {
        return (uint16_t)~checksum;    
    } else {
        return (uint16_t)checksum;
    }
}

static uint16_t swap_order16(uint16_t x) {
    x = ((x & 0xff00) >> 8) | ((x & 0xff) << 8);
    return x;
}

static uint32_t swap_order32(uint32_t x) {
    // x = (((x >> 0) & 0xFF) << 24) | (((x  >> 8) & 0xFF) << 16) | (((x >> 16) & 0xFF) << 8) | (((x >> 24) & 0xFF) << 0);
    uint8_t *v_array = (uint8_t *)&x;
    uint8_t temp;
    temp = v_array[0];
    v_array[0] = v_array[3];
    v_array[3] = temp;

    temp = v_array[1];
    v_array[1] = v_array[2];
    v_array[2] = temp;

    return x;
}

static void xipaddr_from_buf(xipaddr_t *ip, uint8_t *buf) {
    ip->addr = *(uint32_t *)buf;
}
static uint8_t xipaddr_is_equal_buf(xipaddr_t *ip, uint8_t *buf) {
    return (uint8_t)(memcmp(ip->array, buf, XNET_IPV4_ADDR_SIZE) == 0);
}

static uint8_t xipaddr_is_equal(xipaddr_t *ip_1, xipaddr_t *ip_2) {
    return (uint8_t)(ip_1->addr == ip_2->addr);
}



/////// 全局缓存 及其接口函数 start
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


void add_header(xnet_packet_t *packet, uint16_t header_size) {
    packet->data -= header_size;
    packet->size += header_size;
}

void remove_header(xnet_packet_t *packet, uint16_t header_size) {
    packet->data += header_size;
    packet->size -= header_size;
}

void truncate_packet(xnet_packet_t *packet, uint16_t size) {
    packet->size = min(packet->size, size);
}
/////// 全局缓存 及其接口函数 end


static xnet_err_t ethernet_out_to(xnet_protocol_t protocol, const uint8_t *mac_addr, xnet_packet_t *packet) {
    xether_hdr_t *ether_hdr;

    add_header(packet, sizeof(xether_hdr_t));
    ether_hdr = (xether_hdr_t *)packet->data;
    memcpy(ether_hdr->dest, mac_addr, XNET_MAC_ADDR_SIZE);
    memcpy(ether_hdr->src, netif_mac, XNET_MAC_ADDR_SIZE);
    ether_hdr->protocol = swap_order16(protocol);
    
    return xnet_driver_send(packet);
}

static xnet_err_t xarp_make_request(const xipaddr_t *ipaddr) {
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




////////  TCP socket 控制块 及 接口函数 start
static xtcp_t *tcp_alloc() {
    xtcp_t* tcp, *end;

    for (tcp = tcp_socket, end = tcp_socket + XTCP_CFG_MAX_TCP; tcp < end; ++tcp) {
        if (tcp->state == XTCP_STATE_FREE) {
            tcp->local_port = tcp->remote_port = 0;
            tcp->remote_ip.addr = 0;
            tcp->next_seq = tcp->unacked_seq = tcp_get_init_seq();//随机序列号
            tcp->ack = 0;
            tcp->remote_mss = XTCP_MSS_DEFAULT;
            tcp->remote_win = XTCP_MSS_DEFAULT;
            tcp->handler = (xtcp_handler_t)0;
            extern void tcp_buf_init(xtcp_buf_t *tcp_buf); 
            tcp_buf_init(&tcp->tx_buf);
            tcp_buf_init(&tcp->rx_buf);
            return tcp;
        }
    }
    return (xtcp_t *)0;
}

static void tcp_free(xtcp_t *tcp) {
    tcp->state = XTCP_STATE_FREE;
}

static xtcp_t *tcp_find(xipaddr_t* remote_ip, uint16_t remote_port, uint16_t local_port) {
    xtcp_t *tcp, *end;
    xtcp_t *founded_tcp = (xtcp_t *)0;
    for (tcp = tcp_socket, end = &tcp_socket[XTCP_CFG_MAX_TCP]; tcp < end; ++tcp) {
        if (tcp->state == XTCP_STATE_FREE) {
            continue;
        }

        if (tcp->local_port != local_port) {
            continue;
        }

        if (xipaddr_is_equal(remote_ip, &tcp->remote_ip) && (remote_port == tcp->remote_port)) {
            return tcp;
        }
        if (tcp->state == XTCP_STATE_LISTEN) {
            founded_tcp = tcp;
        }
    }
    return founded_tcp;
}

xtcp_t *xtcp_open(xtcp_handler_t handler) {
    xtcp_t *tcp = tcp_alloc();
    if (!tcp) return (xtcp_t *)0;

    tcp->state = XTCP_STATE_CLOSED;
    tcp->handler = handler;
    return tcp;
}

xnet_err_t xtcp_bind(xtcp_t *tcp, uint16_t local_port) {
    xtcp_t *curr, *end;
    for (curr = tcp_socket, end = &tcp_socket[XTCP_CFG_MAX_TCP]; curr < end; curr++) {
        if (curr != tcp && curr->state != XTCP_STATE_FREE && curr->local_port == local_port) {
            return XNET_ERR_BINDED;
        }
    }

    tcp->local_port = local_port;
    return XNET_ERR_OK;
}

xnet_err_t xtcp_listen(xtcp_t *tcp) {
    tcp->state = XTCP_STATE_LISTEN;
    return XNET_ERR_OK;
}

xnet_err_t xtcp_close(xtcp_t *tcp) {
    xnet_err_t err;
    extern xnet_err_t tcp_send(xtcp_t *tcp, uint8_t flags);
    if (tcp->state == XTCP_STATE_ESTABLISHED) {
        err = tcp_send(tcp, XTCP_FLAG_FIN | XTCP_FLAG_ACK);
        tcp->state = XTCP_STATE_FIN_WAIT1;
    } else {
        tcp_free(tcp);
    }
    return XNET_ERR_OK;
}
////////  TCP socket 控制块 及 接口函数 start



/////////   TCP 控制块的缓存结构及接口函数 start
static void tcp_buf_init(xtcp_buf_t *tcp_buf) {
    tcp_buf->front = tcp_buf->tail = tcp_buf->next = 0;
    tcp_buf->data_count = tcp_buf->unacked_count = 0;
}

static uint16_t tcp_buf_free_count(xtcp_buf_t *tcp_buf) {
    return XTCP_CFG_RTX_BUF_SIZE - tcp_buf->data_count;
}

static uint16_t tcp_buf_wait_send_count(xtcp_buf_t *tcp_buf) {
    return tcp_buf->data_count - tcp_buf->unacked_count;
}

static uint16_t tcp_buf_write(xtcp_buf_t *tcp_buf, uint8_t *from, uint16_t size) {
    uint16_t buf_free_count = tcp_buf_free_count(tcp_buf);
    size = min(size, buf_free_count);
    for (int i = 0; i < size; ++i) {
        tcp_buf->data[tcp_buf->front++] = *from++;
        if (tcp_buf->front >= XTCP_CFG_RTX_BUF_SIZE) {
            tcp_buf->front = 0;
        }
    }
    tcp_buf->data_count += size;
    return size;
}

static uint16_t tcp_buf_read_for_send(xtcp_buf_t *tcp_buf, uint8_t *to, uint16_t size) {
    uint16_t wait_send_count = tcp_buf_wait_send_count(tcp_buf);
    size = min(size, wait_send_count);
    for (int i = 0; i < size; ++i) {
        *to++ = tcp_buf->data[tcp_buf->next++];
        if (tcp_buf->next >= XTCP_CFG_RTX_BUF_SIZE) {
            tcp_buf->next = 0;
        }
    }
    return size;
}

static void tcp_buf_add_acked_count(xtcp_buf_t* tcp_buf, uint16_t size) {
    for (int i = 0; i < size; ++i) {
        tcp_buf->tail ++;
        if (tcp_buf->tail >= XTCP_CFG_RTX_BUF_SIZE) {
            tcp_buf->tail = 0;
        }
    }
    tcp_buf->data_count -= size;
    tcp_buf->unacked_count -= size;
}

static void tcp_buf_add_unacked_count(xtcp_buf_t* tcp_buf, uint16_t size) {
    tcp_buf->unacked_count += size;
}

static uint16_t tcp_buf_read(xtcp_buf_t *tcp_buf, uint8_t *data, uint16_t size) {
    size = min(size, tcp_buf->data_count);
    for (int i = 0; i < size; ++i) {
        *data++ = tcp_buf->data[tcp_buf->tail++];
        if (tcp_buf->tail >= XTCP_CFG_RTX_BUF_SIZE) {
            tcp_buf->tail = 0;
        }
    }
    tcp_buf->data_count -= size;
    return size;
}

/////////   TCP 控制块的缓存结构及接口函数 end



/////////   UDP控制块 接口函数 start
xudp_t* xudp_open(xudp_handler_t handler) {
    xudp_t *udp, *end;
    for (udp = udp_socket, end = &udp_socket[XUDP_CFG_MAX_UDP]; udp < end; udp++) {
        if (udp->state == XUDP_STATE_FREE) {
            udp->handler = handler;
            udp->local_port = 0;
            udp->state = XUDP_STATE_USED;
            return udp;
        }
    }
    return (xudp_t *)0;
}

void xudp_close(xudp_t *udp) {
    udp->state = XUDP_STATE_FREE;
}

xudp_t* xudp_find(uint16_t port) {
    xudp_t *curr, *end;
    for (curr = udp_socket, end = &udp_socket[XUDP_CFG_MAX_UDP]; curr < end; curr++) {
        if (curr->state == XUDP_STATE_USED && curr->local_port == port) {
            return curr;
        }
    }
    return (xudp_t *)0;
}

xnet_err_t xudp_bind(xudp_t* udp, uint16_t local_port) {
    xudp_t *curr, *end;
    for (curr = udp_socket, end = &udp_socket[XUDP_CFG_MAX_UDP]; curr < end; curr++) {
        if (curr != udp && curr->state == XUDP_STATE_USED && curr->local_port == local_port) {
            return XNET_ERR_BINDED;
        }
    }

    udp->local_port = local_port;
    return XNET_ERR_OK;
}
////////////    UDP 控制块 接口函数 end

static void xtcp_init() {
    memset(tcp_socket, 0, sizeof(tcp_socket));
}

static void xudp_init() {
    memset(udp_socket, 0, sizeof(udp_socket));
}

static void xicmp_init() {

}

static void xip_init() {

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
    xip_init();
    xicmp_init();
    xudp_init();
    xtcp_init();
    srand(xsys_get_time());
}

/////////////////////////////////////////////////////////

static uint16_t checksum_peso(xipaddr_t *src_ip, xipaddr_t *dest_ip, uint8_t protocol, uint16_t *buf, uint16_t len) {
    uint8_t zero_protocol[] = {0, protocol};
    uint16_t c_len = swap_order16(len);

    uint32_t sum = checksum16((uint16_t *)src_ip->array, XNET_IPV4_ADDR_SIZE, 0, 0);
    sum = checksum16((uint16_t *)dest_ip->array, XNET_IPV4_ADDR_SIZE, sum, 0);
    sum = checksum16((uint16_t *)zero_protocol, 2, sum, 0);
    sum = checksum16((uint16_t *)&c_len, 2, sum, 0);

    return checksum16(buf, len, sum, 1);
}

int xtcp_write(xtcp_t *tcp, uint8_t *data, uint16_t size) {
    int sended_count;
    if ((tcp->state != XTCP_STATE_ESTABLISHED)) {
        return -1;
    }

    sended_count = tcp_buf_write(&tcp->tx_buf, data, size);
    if (sended_count) {
        extern xnet_err_t tcp_send(xtcp_t *tcp, uint8_t flags);
        tcp_send(tcp, XTCP_FLAG_ACK);
    }
    return sended_count;
}

int xtcp_read(xtcp_t *tcp, uint8_t *data, uint16_t size) {
    return tcp_buf_read(&tcp->rx_buf, data, size);
}

static uint16_t tcp_recv(xtcp_t *tcp, uint16_t flags, uint8_t *data, uint16_t size) {
    uint16_t read_size = tcp_buf_write(&tcp->rx_buf, data, size);
    tcp->ack += read_size;
    if (flags & (XTCP_FLAG_SYN | XTCP_FLAG_FIN)) {
        tcp->ack++;
    }
    return read_size;
}

static xnet_err_t tcp_send(xtcp_t *tcp, uint8_t flags) {
    xnet_packet_t *packet;
    xtcp_hdr_t *tcp_hdr;
    xnet_err_t err;
    uint16_t data_size = tcp_buf_wait_send_count(&tcp->tx_buf);
    uint16_t opt_size = (flags & XTCP_FLAG_SYN) ? 4 : 0;//如果是SYN报文，TCP头部需要带上可选字段opt（只在三次握手时需要）

    if (tcp->remote_win) {//流量控制
        data_size = min(tcp->remote_win, data_size);
        data_size = min(data_size, tcp->remote_mss);
        if (data_size + opt_size > XTCP_DATA_MAX_SIZE) {
            data_size = XTCP_DATA_MAX_SIZE - opt_size;
        }
    } else {
        data_size = 0;
    }
    packet = xnet_alloc_for_send(sizeof(xtcp_hdr_t) + opt_size + data_size);
    tcp_hdr = (xtcp_hdr_t *)packet->data;
    tcp_hdr->src_port = swap_order16(tcp->local_port);
    tcp_hdr->dest_port = swap_order16(tcp->remote_port);
    tcp_hdr->seq = swap_order32(tcp->next_seq);
    tcp_hdr->ack = swap_order32(tcp->ack);
    tcp_hdr->hdr_flags.all = 0;
    tcp_hdr->hdr_flags.hdr_len = (opt_size + sizeof(xtcp_hdr_t)) / 4;
    tcp_hdr->hdr_flags.flags = flags;
    tcp_hdr->hdr_flags.all = swap_order16(tcp_hdr->hdr_flags.all);
    tcp_hdr->window = swap_order16(tcp_buf_free_count(&tcp->rx_buf));
    tcp_hdr->checksum = 0;
    tcp_hdr->urgent_ptr = 0;
    if (flags & XTCP_FLAG_SYN) {//装入选项字段MSS 最大TCP报文长度,只在SYN报文中
        uint8_t *opt_data = packet->data + sizeof(xtcp_hdr_t);
        opt_data[0] = XTCP_KIND_MSS;
        opt_data[1] = 4;
        *(uint16_t *)(opt_data + 2) = swap_order16(XTCP_MSS_DEFAULT);
    }

    tcp_buf_read_for_send(&tcp->tx_buf, packet->data + opt_size + sizeof(xtcp_hdr_t), data_size);

    tcp_hdr->checksum = checksum_peso(&netif_ipaddr, &tcp->remote_ip, XNET_PROTOCOL_TCP, (uint16_t *)packet->data, packet->size);
    tcp_hdr->checksum = tcp_hdr->checksum ? tcp_hdr->checksum : 0xFFFF;
    extern xnet_err_t xip_out(xnet_protocol_t protocol, xipaddr_t *dest_ip, xnet_packet_t* packet);
    err = xip_out(XNET_PROTOCOL_TCP, &tcp->remote_ip, packet);
    if (err != XNET_ERR_OK) {
        return err;
    }

    tcp->remote_win -= data_size;
    tcp->next_seq += data_size;
    tcp_buf_add_unacked_count(&tcp->tx_buf, data_size);
    
    if (flags & (XTCP_FLAG_SYN | XTCP_FLAG_FIN)) {
        tcp->next_seq++; 
    }

    return XNET_ERR_OK;
}

static xnet_err_t tcp_send_reset(uint32_t remote_ack, uint16_t local_port, xipaddr_t *remote_ip, uint16_t remote_port) {
    xnet_packet_t *packet = xnet_alloc_for_send(sizeof(xtcp_hdr_t));
    xtcp_hdr_t *tcp_hdr = (xtcp_hdr_t *)packet->data;
    tcp_hdr->src_port = swap_order16(local_port);
    tcp_hdr->dest_port = swap_order16(remote_port);
    tcp_hdr->seq = 0;
    tcp_hdr->ack = swap_order32(remote_ack);
    tcp_hdr->hdr_flags.all = 0;
    tcp_hdr->hdr_flags.hdr_len = sizeof(xtcp_hdr_t) / 4;
    tcp_hdr->hdr_flags.flags = XTCP_FLAG_RST | XTCP_FLAG_ACK;
    tcp_hdr->hdr_flags.all = swap_order16(tcp_hdr->hdr_flags.all);
    tcp_hdr->window = 0;
    tcp_hdr->checksum = 0;
    tcp_hdr->urgent_ptr = 0;
    tcp_hdr->checksum = checksum_peso(&netif_ipaddr, remote_ip, XNET_PROTOCOL_TCP, (uint16_t *)packet->data, packet->size);
    tcp_hdr->checksum = tcp_hdr->checksum ? tcp_hdr->checksum : 0xFFFF;
    extern xnet_err_t xip_out(xnet_protocol_t protocol, xipaddr_t *dest_ip, xnet_packet_t* packet);
    return xip_out(XNET_PROTOCOL_TCP, remote_ip, packet);
}

static void tcp_read_mss(xtcp_t *tcp, xtcp_hdr_t *tcp_hdr) {
    uint16_t opt_len = tcp_hdr->hdr_flags.hdr_len * 4 - sizeof(xtcp_hdr_t);
    if (opt_len == 0) {
        tcp->remote_mss = XTCP_MSS_DEFAULT;
    } else {
        uint8_t *opt_data = (uint8_t *)tcp_hdr + sizeof(xtcp_hdr_t);
        uint8_t *opt_end = opt_data + opt_len;
        while ((*opt_data != XTCP_KIND_END) && (opt_data < opt_end)) {
            if ((*opt_data++ == XTCP_KIND_MSS) && (*opt_data++ == 4)) {
                tcp->remote_mss = swap_order16(*(uint16_t *)opt_data);
                return;
            }
        }
    }
}

static void tcp_process_accept(xtcp_t *listen_tcp, xipaddr_t *remote_ip, xtcp_hdr_t *tcp_hdr) {
    uint16_t hdr_flags = tcp_hdr->hdr_flags.all;
    if (hdr_flags & XTCP_FLAG_SYN) {
        //创建一个新的控制块，并将其初始化
        xtcp_t *new_tcp = tcp_alloc();
        if (!new_tcp) {
            return;
        }
        new_tcp->state = XTCP_STATE_SYN_RECVD;
        new_tcp->local_port = listen_tcp->local_port;
        new_tcp->handler = listen_tcp->handler;
        new_tcp->remote_port = tcp_hdr->src_port;
        new_tcp->remote_ip.addr = remote_ip->addr;
        new_tcp->ack = tcp_hdr->seq + 1;
        new_tcp->remote_win = tcp_hdr->window;
        tcp_read_mss(new_tcp, tcp_hdr);//mss为TCP协议双方定义的一个选项，表示TCP最大报文段长度(不包含头部)

        xnet_err_t err = tcp_send(new_tcp, XTCP_FLAG_SYN | XTCP_FLAG_ACK);
        if (err != XNET_ERR_OK) {
            tcp_free(new_tcp);
            return;
        }
    } else {
        tcp_send_reset(tcp_hdr->seq + 1, listen_tcp->local_port, remote_ip, tcp_hdr->src_port);
    }
}

static void xtcp_in(xipaddr_t* remote_ip, xnet_packet_t* packet) {
    xtcp_hdr_t* tcp_hdr = (xtcp_hdr_t *)packet->data;
    uint16_t pre_checksum;
    xtcp_t *tcp;
    uint16_t read_size;

    if (packet->size < sizeof(xtcp_hdr_t)) {
        return;
    }

    pre_checksum = tcp_hdr->checksum;
    tcp_hdr->checksum = 0;
    if (pre_checksum != 0) {
        uint16_t checksum = checksum_peso(remote_ip, &netif_ipaddr, XNET_PROTOCOL_TCP, (uint16_t *)tcp_hdr, packet->size);
        checksum = (checksum == 0) ? 0xFFFF : checksum;
        if (checksum != pre_checksum) {
            return;
        }
    }
    tcp_hdr->src_port = swap_order16(tcp_hdr->src_port);
    tcp_hdr->dest_port = swap_order16(tcp_hdr->dest_port);
    tcp_hdr->hdr_flags.all = swap_order16(tcp_hdr->hdr_flags.all);
    tcp_hdr->seq = swap_order32(tcp_hdr->seq);
    tcp_hdr->ack = swap_order32(tcp_hdr->ack);
    tcp_hdr->window = swap_order16(tcp_hdr->window);

    tcp = tcp_find(remote_ip, tcp_hdr->src_port, tcp_hdr->dest_port);
    if (tcp == (xtcp_t *)0) {//TCP端口不可达，未开启该端口
        tcp_send_reset(tcp_hdr->seq + 1, tcp_hdr->dest_port, remote_ip, tcp_hdr->src_port);
    }
    tcp->remote_win = tcp_hdr->window;//流量控制，修改tcp控制块中remote_win大小

    if (tcp->state == XTCP_STATE_LISTEN) {
        tcp_process_accept(tcp, remote_ip, tcp_hdr);
        return;
    }

    if (tcp_hdr->seq != tcp->ack) {
        tcp_send_reset(tcp_hdr->seq + 1, tcp_hdr->dest_port, remote_ip, tcp_hdr->src_port);
        return;
    }

    remove_header(packet, tcp_hdr->hdr_flags.hdr_len * 4);
    switch (tcp->state) {
        case XTCP_STATE_SYN_RECVD:
            if (tcp_hdr->hdr_flags.flags & XTCP_FLAG_ACK) {//第三次握手 ACK报文
                tcp->unacked_seq++;
                tcp->state = XTCP_STATE_ESTABLISHED;
                tcp->handler(tcp, XTCP_CONN_CONNECTED);
            }
            break;
        case XTCP_STATE_ESTABLISHED:
            if (tcp_hdr->hdr_flags.flags & (XTCP_FLAG_ACK | XTCP_FLAG_FIN)) {
                if (tcp_hdr->hdr_flags.flags & (XTCP_FLAG_ACK)) {//ESTABLISHED 对方发送了ACK报文
                    if ((tcp->unacked_seq < tcp_hdr->ack) && (tcp_hdr->ack <= tcp->next_seq)) {
                        uint16_t curr_ack_size = tcp_hdr->ack - tcp->unacked_seq;
                        tcp_buf_add_acked_count(&tcp->tx_buf, curr_ack_size);
                        tcp->unacked_seq += curr_ack_size;
                    }
                }
                
                //包中有可能存在数据，即使是FIN包也可能存在数据
                read_size = tcp_recv(tcp, tcp_hdr->hdr_flags.flags, packet->data, packet->size);

                if (tcp_hdr->hdr_flags.flags & (XTCP_FLAG_FIN)) {//对方发送了FIN报文
                    //收到FIN，发送ACK和FIN报文，进入LAST_ACK状态，等待最后的ACK
                    tcp->state = XTCP_STATE_LAST_ACK;
                    tcp_send(tcp, XTCP_FLAG_FIN | XTCP_FLAG_ACK);
                } else if (read_size) {//对方不是FIN报文，携带数据
                    tcp_send(tcp, XTCP_FLAG_ACK);
                    // tcp->handler(tcp, XTCP_CONN_DATA_RECV);//触发回调函数，读取 TCP读缓存
                } else if (tcp_buf_wait_send_count(&tcp->tx_buf)) {//对方不是FIN报文，但不携带数据
                    tcp_send(tcp, XTCP_FLAG_ACK);
                }
            }
            break;
        case XTCP_STATE_FIN_WAIT1:
            if ((tcp_hdr->hdr_flags.flags & (XTCP_FLAG_FIN | XTCP_FLAG_ACK)) == (XTCP_FLAG_FIN | XTCP_FLAG_ACK)) {
                // tcp->state = XTCP_STATE_TIMED_WAIT;
                tcp_free(tcp);
            } else if (tcp_hdr->hdr_flags.flags & XTCP_FLAG_ACK) {
                tcp->state = XTCP_STATE_FIN_WAIT2;
            }
            break;
        case XTCP_STATE_FIN_WAIT2:
            if (tcp_hdr->hdr_flags.flags & XTCP_FLAG_FIN) {
                tcp->ack++;
                tcp_send(tcp, XTCP_FLAG_ACK);
                tcp_free(tcp);
            }
            break;
        case XTCP_STATE_LAST_ACK:
            if (tcp_hdr->hdr_flags.flags & XTCP_FLAG_ACK) {
                tcp->handler(tcp, XTCP_CONN_CLOSED);
                tcp_free(tcp);
            }
            break;
    }
}

xnet_err_t xudp_out(xudp_t *udp, xipaddr_t *dest_ip, uint16_t dest_port, xnet_packet_t *packet) {
    xudp_hdr_t *udp_hdr;
    uint16_t checksum;

    add_header(packet, sizeof(xudp_hdr_t));
    udp_hdr = (xudp_hdr_t *)packet->data;
    udp_hdr->src_port = swap_order16(udp->local_port);
    udp_hdr->dest_port = swap_order16(dest_port);
    udp_hdr->total_len = swap_order16(packet->size);
    udp_hdr->checksum = 0;
    checksum = checksum_peso(&netif_ipaddr, dest_ip, XNET_PROTOCOL_UDP, (uint16_t *)packet->data, packet->size);
    udp_hdr->checksum = checksum;
    extern xnet_err_t xip_out(xnet_protocol_t protocol, xipaddr_t *dest_ip, xnet_packet_t* packet);
    return xip_out(XNET_PROTOCOL_UDP, dest_ip, packet);
}

static void xudp_in(xudp_t *udp, xipaddr_t *src_ip, xnet_packet_t *packet) {
    xudp_hdr_t *udp_hdr = (xudp_hdr_t *)packet->data;
    if ((packet->size < sizeof(xudp_hdr_t)) || (packet->size < swap_order16(udp_hdr->total_len))) {
        return;
    }

    uint16_t pre_checksum = udp_hdr->checksum;
    udp_hdr->checksum = 0;
    if (pre_checksum != 0) {
        uint16_t checksum = checksum_peso(src_ip, &netif_ipaddr, XNET_PROTOCOL_UDP, (uint16_t *)udp_hdr, swap_order16(udp_hdr->total_len));
        checksum = (checksum == 0) ? 0xFFFF : checksum;
        if (checksum != pre_checksum) {
            return;
        }
    }
    uint16_t src_port = swap_order16(udp_hdr->src_port);
    remove_header(packet, sizeof(xudp_hdr_t));
    if (udp->handler) {
        udp->handler(udp, src_ip, src_port);
    }
}

static xnet_err_t xarp_resolve(xipaddr_t *ipaddr, uint8_t** mac_addr) {
    if (arp_entry.state == XARP_ENTRY_OK && xipaddr_is_equal(ipaddr, &arp_entry.ipaddr)) {
        *mac_addr = arp_entry.macaddr;
        return XNET_ERR_OK;
    }

    xarp_make_request(ipaddr);
    return XNET_ERR_NONE;
}

static xnet_err_t ethernet_out(xipaddr_t *dest_ip, xnet_packet_t *packet) {
    xnet_err_t err;
    uint8_t *mac_addr;
    if ((err = xarp_resolve(dest_ip, &mac_addr)) == XNET_ERR_OK) {
        return ethernet_out_to(XNET_PROTOCOL_IPV4, mac_addr, packet);
    }
    return err;
}

static xnet_err_t xip_out(xnet_protocol_t protocol, xipaddr_t *dest_ip, xnet_packet_t* packet) {
    static uint32_t ip_packet_id = 0;
    xip_hdr_t *iphdr;

    add_header(packet, sizeof(xip_hdr_t));
    iphdr = (xip_hdr_t *)packet->data;
    iphdr->version = XNET_VERSION_IPV4;
    iphdr->hdr_len = sizeof(xip_hdr_t) / 4;
    iphdr->tos = 0;
    iphdr->protocol = protocol;
    iphdr->total_len = swap_order16(packet->size);
    iphdr->id = swap_order16(ip_packet_id);
    iphdr->flags_fragment = 0;
    iphdr->ttl = XNET_IP_DEFAULT_TTL;
    memcpy(iphdr->src_ip, &netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memcpy(iphdr->dest_ip, dest_ip->array, XNET_IPV4_ADDR_SIZE);
    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = checksum16((uint16_t *)iphdr, sizeof(xip_hdr_t), 0, 1);
    
    ip_packet_id++;
    return ethernet_out(dest_ip, packet);
}

static xnet_err_t xicmp_dest_unreach(uint8_t code, xip_hdr_t *ip_hdr) {
    xicmp_hdr_t *icmp_hdr;
    xnet_packet_t *packet;
    xipaddr_t dest_ip;

    uint16_t ip_hdr_size = ip_hdr->hdr_len * 4;
    uint16_t ip_data_size = swap_order16(ip_hdr->total_len) - ip_hdr_size;
    ip_data_size = ip_hdr_size + min(ip_data_size, 8);
    packet = xnet_alloc_for_send(sizeof(xicmp_hdr_t) + ip_data_size);

    icmp_hdr = (xicmp_hdr_t *)packet->data;
    icmp_hdr->type = (XICMP_TYPE_UNREACH);
    icmp_hdr->code = code;
    icmp_hdr->id = icmp_hdr->seq = 0;
    memcpy((uint8_t *)icmp_hdr + sizeof(xicmp_hdr_t), ip_hdr, ip_data_size);
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = checksum16((uint16_t *)icmp_hdr, packet->size, 0, 1);
    xipaddr_from_buf(&dest_ip, ip_hdr->src_ip);
    return xip_out(XNET_PROTOCOL_ICMP, &dest_ip, packet);
}

static xnet_err_t reply_icmp_request(xicmp_hdr_t *icmp_hdr, xipaddr_t *src_ip, xnet_packet_t *packet) {
    xnet_packet_t *tx = xnet_alloc_for_send(packet->size);
    memcpy(tx->data, packet->data, packet->size);
    xicmp_hdr_t *reply_hdr = (xicmp_hdr_t *)tx->data;
    reply_hdr->type = XICMP_TYPE_ECHO_REPLY;
    reply_hdr->code = 0;
    reply_hdr->id = icmp_hdr->id;
    reply_hdr->seq = icmp_hdr->seq;
    reply_hdr->checksum = 0;
    reply_hdr->checksum = checksum16((uint16_t *)reply_hdr, tx->size, 0, 1);
    return xip_out(XNET_PROTOCOL_ICMP, src_ip, tx);
}

static void xicmp_in(xipaddr_t *src_ip, xnet_packet_t *packet) {
    xicmp_hdr_t *icmphdr = (xicmp_hdr_t *)packet->data;
    if ((packet->size >= sizeof(xicmp_hdr_t)) && (icmphdr->type == XICMP_TYPE_ECHO_REQUEST)) {
        reply_icmp_request(icmphdr, src_ip, packet);
    }
}

static void xip_in(xnet_packet_t *packet) {
    xip_hdr_t *iphdr = (xip_hdr_t *)packet->data;
    uint32_t header_size, total_size;
    uint16_t pre_checksum;
    xipaddr_t src_ip;
    if (iphdr->version != XNET_VERSION_IPV4) {
        return;
    }

    header_size = iphdr->hdr_len * 4;
    total_size = swap_order16(iphdr->total_len);
    if ((header_size < sizeof(xip_hdr_t)) || (total_size < header_size)) {
        return;
    }
    pre_checksum = iphdr->hdr_checksum;
    iphdr->hdr_checksum = 0;
    if (pre_checksum != checksum16((uint16_t *)iphdr, header_size, 0, 1)) {
        return;
    }

    if (!xipaddr_is_equal_buf(&netif_ipaddr, iphdr->dest_ip)) {
        return;
    }
    xipaddr_from_buf(&src_ip, iphdr->src_ip);
    switch (iphdr->protocol) {
        case XNET_PROTOCOL_UDP:
            if (packet->size >= sizeof(xudp_hdr_t)) {
                xudp_hdr_t *udp_hdr = (xudp_hdr_t *)(packet->data + header_size);
                xudp_t * udp = xudp_find(swap_order16(udp_hdr->dest_port));
                if (udp) {
                    remove_header(packet, header_size);
                    xudp_in(udp, &src_ip, packet);
                } else {
                    xicmp_dest_unreach(XICMP_CODE_PORT_UNREACH, iphdr);//UDP端口不可达
                }
            }
            break;
        case XNET_PROTOCOL_TCP:
            truncate_packet(packet, total_size);//截断FCS等填充数据
            remove_header(packet, header_size);
            xtcp_in(&src_ip, packet);
            break;
        case XNET_PROTOCOL_ICMP:
            remove_header(packet, header_size);
            xicmp_in(&src_ip, packet);
            break;
        default:
            xicmp_dest_unreach(XICMP_CODE_PROTOCOL_UNREACH, iphdr);//协议不可达
            break;
    }
}
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
            xip_hdr_t *iphdr = (xip_hdr_t *)(packet->data + sizeof(xether_hdr_t));
            update_arp_entry(iphdr->src_ip, ether_hdr->src);
            remove_header(packet, sizeof(xether_hdr_t));
            xip_in(packet);
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