#include "xserver_datetime.h"
#include <time.h>
#include <string.h>

#define TIME_SIR_SIZE 128
static xnet_err_t datetime_handler(xudp_t *udp, xipaddr_t *src_ip, uint16_t src_port) {
    time_t rawtime;
    struct tm* timeinfo;
    uint16_t str_size;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    
    xnet_packet_t *tx_packet = xnet_alloc_for_send(TIME_SIR_SIZE);
    str_size = strftime((char *)tx_packet->data, TIME_SIR_SIZE, "%A, %B, %d, %Y %T-%z", timeinfo);
    truncate_packet(tx_packet, str_size);
    //发送
    return xudp_out(udp, src_ip, src_port, tx_packet);
}

xnet_err_t xserver_datetime_create(uint16_t port) {
    xudp_t *udp = xudp_open(datetime_handler);
    if (udp == NULL) {
        return XNET_ERR_NONE;
    }
    xnet_err_t err = xudp_bind(udp, port);
    if (err != XNET_ERR_OK) {
        return err;
    }
    return XNET_ERR_OK;
}