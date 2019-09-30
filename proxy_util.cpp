#include "proxy_util.h"

void showLog(const char *msg)
{
    printf("%s\n", msg);
}

void deleteUri(__u8 *buf, __s32 *len)
{

    if (*len > 10 &&
        buf[0] != 'G' &&
        buf[1] != 'E' &&
        buf[2] != 'T' &&
        buf[4] != 'h' &&
        buf[5] != 't' &&
        buf[6] != 't' &&
        buf[7] != 'p') {
        return;        
    }

    __s32 i, cnt = 0;

    for (i = 4; i < *len; i++) {
        if (buf[i] == '/') {
            cnt++;
        }
        if (buf[i] == ' ') {
            return;
        }
        if (cnt == 3) {
            break;
        }
    }

    __s32 domain_len = i - 4;

    __s32 j = domain_len + 4;
    while (buf[j]) {
        buf[j - domain_len] = buf[j];
        j++;
    }
    buf[j - domain_len] = 0;

    *len = *len - domain_len;
}

__s32 expandBuffer(__u8 **buf, __s32 *len)
{
    *len += BUF_SIZE;

    if ((*buf = (__u8*)realloc(*buf, sizeof(__u8) * (*len))) == NULL) {
        showLog("Error: expandBuffer -> realloc");
        return -1;
    }
    return 0;
}


/* Be careful 'target' NULL access */
__s32 getHttpField(const __u8 *name, const __u8 *target, __u8 *buf)
{
    __s32 len;
    for (len = 0; name[len]; len++);

    __s32 i = 0;
    while (target[i + len - 1]) {
        __s32 j, check = 1;
        for (j = 0; j < len; j++) {
            if (target[i + j] != name[j]) {
                check = 0;
                break;
            }
        }

        if (check == 1) {
            j = i + len + 2;

            __s32 buf_index = 0;

            while (target[j] != 0x0d) {
                buf[buf_index] = target[j];
                buf_index++;
                j++;
            }
            buf[buf_index] = 0;
            return 0;
        }

        i++;
    }

    return -1;
}

void addHttpHeader(const __u8 *src, __u8 *dst, __s32 *dst_len)
{
    __s32 i = 0;
    *dst_len = *dst_len - 2;

    while (src[i]) {
        dst[*dst_len + i] = src[i];
        i++;
    }

    dst[*dst_len + i++] = 0x0d;
    dst[*dst_len + i++] = 0x0a;
    dst[*dst_len + i++] = 0x0d;
    dst[*dst_len + i++] = 0x0a;
    dst[*dst_len + i] = 0x00;
    
    *dst_len = *dst_len + i;
}

void appendPacket(const __u8 *src, __s32 src_size, __u8 *dst, __s32 dst_index)
{
    __s32 i;
    for (i = 0; i < src_size; i++) {
        dst[dst_index] = src[i];
        dst_index++;
    }

    dst[dst_index] = 0;
}

__s32 find(const __u8 *symbol, __s32 symbol_len, const __u8 *data, __s32 data_len)
{
    __s32 i = 0;
    while (1) {
        if (i + symbol_len > data_len) {
            return -1;
        }

        __s32 j, check = 1;
        for (j = 0; j < symbol_len; j++) {
            if (symbol[j] != data[i + j]) {
                check = 0;
                break;
            }
        }

        if (check == 1) {
            return i;
        }
        i++;       
    }
    return -1;
}

struct sockaddr_in createAddress(in_port_t n_port)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = n_port;
    addr.sin_addr.s_addr = INADDR_ANY;

    return addr;
}

__s32 createSocket()
{
    __s32 sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        showLog("Error: createSocket -> socket");
        return 0;
    }

    __s32 *opt = (__s32*)malloc(sizeof(__s32));
    *opt = 1;

    /*
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (__s8*)opt, sizeof(__s32)) == -1 ||
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (__s8*)opt, sizeof(__s32)) == -1) {
        showLog("Error: createAcceptSocket -> setsockopt");
        free(opt);
        return 0;
    }*/

    free(opt);

    return sock;
}

__u32 getIpFromDomain(__u8 *domain)
{
    /* Bug with addrinfo in vscode
    struct addrinfo hints;
    struct addrinfo *info;
    memset(&hints, 0x00, sizeof(struct addrinfo));*/

    struct hostent *host_entry = gethostbyname((char*)domain);
    if (!host_entry) {
        showLog("Error: getIpFromDomain");
        return 0;
    }

    return inet_addr(inet_ntoa(*(struct in_addr*)host_entry->h_addr_list[0]));    
}

