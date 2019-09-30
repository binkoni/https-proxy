#include "proxy.h"
#include "proxy_util.h"

int main(int argc, char *argv[])
{
    if (argc != 2) {
        showLog("Usage: ./proxy <port_number>");
        return 1;
    }

    proxyStart(argv[1]);
    return 0;
}