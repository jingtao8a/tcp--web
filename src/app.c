#include "xnet_tiny.h"
#include "xserver_datetime.h"
#include <stdio.h>
#include "xserver_http.h"

int main (void) {
    xnet_init();
    printf("xnet running\n");
    xserver_datetime_create(13);
    xserver_http_create(80);
    while (1) {
        xnet_poll();
    }

    return 0;
}
