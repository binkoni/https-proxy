#pragma once
#include <pthread.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "proxy_util.h"
#include "clienthello_cb.h"

#define TYPE_CLIENT 0x01
#define TYPE_SERVER 0x02

void proxyStart(char *port_str);
void *proxyHandler(void *arg);
__s32 receiveHttps(SSL *ssl, __u8 **buf, __s32 *buf_len, __s32 type);
__s32 sendHttps(SSL *ssl, const __u8 *buf, __s32 buf_len);
__s32 relayWithHttpsServer(__u8 *recv_buf, __s32 *recv_len, __u8 **relay_buf, __s32 *relay_size);

/*
__s32 receiveHttp(__s32 sock, __u8 **buf, __s32 *buf_len, __s32 type);
__s32 sendHttp(__s32 sock, const __u8 *buf, __s32 buf_len);
__s32 relayWithServer(__u8 *recv_buf, __s32 *recv_len, __u8 **relay_buf, __s32 *relay_size);
*/