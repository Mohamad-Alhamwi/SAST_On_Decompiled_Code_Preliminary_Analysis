#include <stddef.h>
#include <sys/types.h>
#include "src/main.h"

int main()
{
    Slirp *slirp = 0;
    struct mbuf *m = 0;
    struct socket *so = 0;
    char buf[128] = {0};

    if_encap(slirp, m);
    slirp_send(so, buf, sizeof(buf), 0);

    return 0;
}