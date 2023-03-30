#include "xserver_http.h"
#include <stdio.h>
static xnet_err_t http_handler(xtcp_t *tcp, xtcp_conn_state_t event) {
    if (event == XTCP_CONN_CONNECTED) {
        printf("http connected\n");
    } else if (event == XTCP_CONN_CLOSED) {
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