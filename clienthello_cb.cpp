#include "clienthello_cb.h"
#include "str_cert.h"

#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define X509_NAME_add(x509_name, field, bytes) \
    X509_NAME_add_entry_by_txt(x509_name, field, MBSTRING_ASC, reinterpret_cast<const unsigned char *>(bytes), -1, -1, 0)

void SetCertificate(SSL *s, const char *commonName);
int add_extension(X509 *issuer, X509 *subject, int nid, const char *value);

int LoadCertificate(SSL *s, int * /*al*/, void * /*arg*/)
{
    int type = SSL_get_servername_type(s);
    if (type < 0) {
        std::cerr << "Server Name Error\n";
        return SSL_TLSEXT_ERR_NOACK;
    }

    const char *host = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    std::cout << "Server Name: " << host << '\n';

    SetCertificate(s, host);

    return SSL_CLIENT_HELLO_SUCCESS;
}

void SetCertificate(SSL *s, const char *commonName)
{
    int nVersion = 1;
    static int serialNum = 0;

    // Load host key
    EVP_PKEY *hostKey = nullptr;

    BIO *bo = BIO_new(BIO_s_mem());
    BIO_write(bo, s_hostKey.c_str(), static_cast<int>(s_hostKey.length()));
    PEM_read_bio_PrivateKey(bo, &hostKey, nullptr, nullptr);
    BIO_free(bo);

    // set version of x509 req
    X509_REQ *x509_req = X509_REQ_new();
    X509_REQ_set_version(x509_req, nVersion);

    // set subject of x509 req
    X509_NAME *x509_name = X509_REQ_get_subject_name(x509_req);

    X509_NAME_add(x509_name, "C", "KR");
    X509_NAME_add(x509_name, "ST", "Seoul");
    X509_NAME_add(x509_name, "L", "Geumcheon-gu");
    X509_NAME_add(x509_name, "O", "Kitri BoB");
    X509_NAME_add(x509_name, "OU", "DMG");
    X509_NAME_add(x509_name, "CN", commonName);

    // set public key of x509 req
    X509_REQ_set_pubkey(x509_req, hostKey);

    // set sign key of x509 req
    X509_REQ_sign(x509_req, hostKey, EVP_sha512());

    // Load CA key
    EVP_PKEY *caKey = nullptr;

    bo = BIO_new(BIO_s_mem());
    BIO_write(bo, s_caKey.c_str(), static_cast<int>(s_caKey.length()));
    PEM_read_bio_PrivateKey(bo, &caKey, nullptr, nullptr);
    BIO_free(bo);

    // Load CA Certificate
    X509 *caCert = nullptr;

    bo = BIO_new(BIO_s_mem());
    BIO_write(bo, s_caCert.c_str(), static_cast<int>(s_caCert.length()));
    PEM_read_bio_X509(bo, &caCert, nullptr, nullptr);
    BIO_free(bo);

    // Convert X509_REQ to X509
    X509 *hostCert = X509_REQ_to_X509(x509_req, 365, caKey);

    // Add extensions
    add_extension(caCert, hostCert, NID_basic_constraints, "CA:FALSE");
    add_extension(caCert, hostCert, NID_authority_key_identifier, "keyid");
    add_extension(caCert, hostCert, NID_subject_key_identifier, "hash");
    add_extension(caCert, hostCert, NID_key_usage, "Digital Signature, Non Repudiation, Key Encipherment");
    add_extension(caCert, hostCert, NID_ext_key_usage, "TLS Web Server Authentication, TLS Web Client Authentication");
    std::string altName = "DNS:";
    altName += commonName;
    add_extension(caCert, hostCert, NID_subject_alt_name, altName.c_str());

    // Set Issure Name
    X509_set_issuer_name(hostCert, X509_get_issuer_name(caCert));

    // Set Version
    X509_set_version(hostCert, nVersion);

    // Set Serial Number
    ASN1_INTEGER_set(X509_get_serialNumber(hostCert), serialNum++);

    // Set Expiration
    X509_gmtime_adj(X509_get_notBefore(hostCert), 0);
    X509_gmtime_adj(X509_get_notAfter(hostCert), 60 * 60 * 24 * 365);

    // Sign
    X509_sign(hostCert, caKey, EVP_sha512());

    // Set Certificate
    if (SSL_use_certificate(s, hostCert) != 1) {
        ERR_print_errors_fp(stderr);
        std::cerr << "SSL_CTX_use_certificate\n";
    }

    // Set Private Key
    if (SSL_use_PrivateKey(s, hostKey) != 1) {
        ERR_print_errors_fp(stderr);
        std::cerr << "SSL_CTX_use_PrivateKey\n";
    }

    // Check
    if (SSL_check_private_key(s) != 1) {
        ERR_print_errors_fp(stderr);
        std::cerr << "Private key does not match the public certificate\n";
    }

    // Free
    X509_free(caCert);
    EVP_PKEY_free(caKey);
    X509_REQ_free(x509_req);

    X509_free(hostCert);
    EVP_PKEY_free(hostKey);
}

int add_extension(X509 *issuer, X509 *subject, int nid, const char *value)
{
    X509V3_CTX ctx;
    ctx.db = nullptr;

    X509V3_set_ctx(&ctx, issuer, subject, nullptr, nullptr, 0);
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(subject, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}
