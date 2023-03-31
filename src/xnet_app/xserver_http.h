#ifndef XSERVER_HTTP_H
#define SXERVER_HTTP_H

#include "xnet_tiny.h"

#define XHTTP_DOC_PATH "D:/tcp--web/htdocs"

xnet_err_t xserver_http_create(uint16_t port);
void xserver_http_run();

#endif