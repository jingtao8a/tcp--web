#include "xnet_tiny.h"
#include "xserver_datetime.h"
#include <stdio.h>

int main (void) {
    xnet_init();
    printf("xnet running\n");
    xserver_datetime_create(13);
    while (1) {
        xnet_poll();
    }

    return 0;
}
