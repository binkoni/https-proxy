#pragma once

#include <openssl/ssl.h>

int LoadCertificate(SSL *s, int *al, void *arg);
