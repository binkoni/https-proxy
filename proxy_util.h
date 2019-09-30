#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 4096
#define END_SYMBOL_LEN 4

void showLog(const char *msg);
void deleteUri(__u8 *buf, __s32 *len);
__s32 expandBuffer(__u8 **buf, __s32 *len);
__s32 getHttpField(const __u8 *name, const __u8 *target, __u8 *buf);
void addHttpHeader(const __u8 *src, __u8 *dst, __s32 *dst_len);
void appendPacket(const __u8 *src, __s32 src_size, __u8 *dst, __s32 dst_index);
__s32 find(const __u8 *symbol, __s32 symbol_len, const __u8 *data, __s32 data_len);
struct sockaddr_in createAddress(in_port_t n_port);
__s32 createSocket();
__u32 getIpFromDomain(__u8 *domain);

