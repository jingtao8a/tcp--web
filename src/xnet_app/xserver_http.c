#include "xserver_http.h"
#include <stdio.h>

static uint8_t tx_buffer[1024];


static xnet_err_t http_handler(xtcp_t *tcp, xtcp_conn_state_t event) {
    static char *num = "0123456789ABCDEF";
    if (event == XTCP_CONN_CONNECTED) {
        printf("http connected\n");
    } else if (event == XTCP_CONN_DATA_RECV) {
        uint16_t read_size = xtcp_read(tcp, tx_buffer, sizeof(tx_buffer));//读取接收缓存
        uint8_t *data = tx_buffer;
        while (read_size) {
            uint16_t size = xtcp_write(tcp, data, read_size);//发送接收缓存
            read_size -= size;
            data += size;
        }
    } 
    else if (event == XTCP_CONN_CLOSED) {
        printf("http closed\n");
    }
    return XNET_ERR_OK;
}

xnet_err_t xserver_http_create(uint16_t port) {
    xtcp_t *tcp = xtcp_open(http_handler);
    xnet_err_t err;
    err = xtcp_bind(tcp, port);
    if (err != XNET_ERR_OK) {
        return err;
    }
    xtcp_listen(tcp);
    return XNET_ERR_OK;
}