#include "xserver_http.h"
#include <stdio.h>
#include <string.h>

#define XTCP_FIFO_SIZE 40


static char rx_buffer[1024], tx_buffer[1024];
static char url_path[255], file_path[255];

typedef struct _xhttp_fifo_t {
    xtcp_t *buffer[XTCP_FIFO_SIZE];
    uint8_t front, tail, count;
} xhttp_fifo_t;

static xhttp_fifo_t http_fifo;

static void xhttp_fifo_init(xhttp_fifo_t* fifo) {
    fifo->count = fifo->front = fifo->tail = 0;
}

static xnet_err_t xhttp_fifo_in(xhttp_fifo_t* fifo, xtcp_t* tcp) {
    if (fifo->count >= XTCP_FIFO_SIZE) {
        return XNET_ERR_MEM;
    }
    fifo->buffer[fifo->front++] = tcp;
    if (fifo->front >= XTCP_FIFO_SIZE) {
        fifo->front = 0;
    }

    fifo->count++;
    return XNET_ERR_OK;
}

static xtcp_t *http_fifo_out(xhttp_fifo_t *fifo) {
    xtcp_t* tcp;
    if (fifo->count == 0) {
        return (xtcp_t *)0;
    }

    tcp = fifo->buffer[fifo->tail++];
    if (fifo->tail >= XTCP_FIFO_SIZE) {
        fifo->tail = 0;
    }
    return tcp;
}

static xnet_err_t http_handler(xtcp_t *tcp, xtcp_conn_state_t event) {
    if (event == XTCP_CONN_CONNECTED) {
        xhttp_fifo_in(&http_fifo, tcp);
        printf("http connected\n");
    } else if (event == XTCP_CONN_CLOSED) {
        printf("http closed\n");
    }
    return XNET_ERR_OK;
}

static int get_line(xtcp_t* tcp, char* buf, int size) {
    int i = 0;
    while (i < size) {
        char c;
        if (xtcp_read(tcp, (uint8_t *)&c, 1) > 0) {
            if ((c != '\r') && (c != '\n')) {
                buf[i++] = c;
            } else if (c == '\n') {
                break;//读完一行后跳出循环
            }
        }
        xnet_poll();//协议栈得保持运行
    }
    buf[i] = '\0';
    return i;
}

static int http_send(xtcp_t* tcp, char* buf, int size) {
    int sended_size = 0;

    while (size > 0) {
        int curr_size = xtcp_write(tcp, (uint8_t *)buf, (uint16_t)size);
        if (curr_size < 0) {//连接已经关闭
            break;
        }
        size -= curr_size;
        buf += curr_size;
        sended_size += curr_size;

        xnet_poll();
    }

    return sended_size;
}

static void close_http(xtcp_t *tcp) {//服务器主动关闭TCP连接
    xtcp_close(tcp);
    printf("http closed\n");
}

static void send_404_not_found(xtcp_t *tcp) {
    sprintf(tx_buffer, 
            "HTTP/1.0 404 NOT FOUND\r\n"
            "\r\n");
    http_send(tcp, tx_buffer, (int)strlen(tx_buffer));
}

static void send_file(xtcp_t* tcp, char *url) {
    FILE* file;
    uint32_t size;
    while (*url == '/') {//去掉url的‘/’
        url++;
    }
    sprintf(file_path, "%s/%s", XHTTP_DOC_PATH, url);
    file = fopen(file_path, "rb");//打开文件描述符
    if (file == NULL) {
        send_404_not_found(tcp);
        return;
    }

    //获取文件大小
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fseek(file, 0, SEEK_SET);

    sprintf(tx_buffer, 
        "HTTP/1.0 200 OK\r\n"
        "Content-Length:%d\r\n"
        "\r\n",
        (int)size
    );
    http_send(tcp, tx_buffer, (int)strlen(tx_buffer));//发送状态码和响应头

    while (!feof(file)) {//发送响应体
        size = (uint32_t)fread(tx_buffer, 1, sizeof(tx_buffer), file);
        if (http_send(tcp, tx_buffer, size) <= 0) {
            fclose(file);//关闭文件描述符
            return;
        }
    }

    fclose(file);//关闭文件描述符
}

xnet_err_t xserver_http_create(uint16_t port) {
    xtcp_t *tcp = xtcp_open(http_handler);
    xnet_err_t err;
    err = xtcp_bind(tcp, port);
    if (err != XNET_ERR_OK) {
        return err;
    }
    xtcp_listen(tcp);
    xhttp_fifo_init(&http_fifo);
    return XNET_ERR_OK;
}


void xserver_http_run() {
    xtcp_t* tcp;
    while ((tcp = http_fifo_out(&http_fifo)) != (xtcp_t *)0) {
        int i;
        char *c = rx_buffer;
        if (get_line(tcp, rx_buffer, sizeof(rx_buffer)) <= 0) {//出错,
            close_http(tcp);
            continue;
        }

        if (strncmp(rx_buffer, "GET", 3) != 0) {
            close_http(tcp);
            continue;
        }

        while (*c != ' ') {
            c++;
        }
        while (*c == ' ') {
            c++;
        }

        for (i = 0; i < sizeof(url_path); ++i) {
            if (*c == ' ') {//读完了url地址
                break;
            }
            url_path[i] = *c++;
        }
        url_path[i] = '\0';

        if (url_path[strlen(url_path) - 1] == '/') {//如果url为'/'
            strcat(url_path, "index.html");
        }

        send_file(tcp, url_path);

        close_http(tcp);//http短连接，直接关闭
    }
}