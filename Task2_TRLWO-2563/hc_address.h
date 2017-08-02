#ifndef __HC_ADDRESS_H__
#define __HC_ADDRESS_H__

#include <stdio.h>
#include <errno.h>

#include <arpa/inet.h>

static inline int hc_format_address_inet(const char *in_addr, char *out_addr)
{
    unsigned char decimals[4];
    int res = sscanf(in_addr, "%hhu.%hhu.%hhu.%hhu",
	&decimals[0], &decimals[1], &decimals[2], &decimals[3]);

    if (res < 4)
        return -1;

    sprintf(out_addr, "%hhu.%hhu.%hhu.%hhu",
	decimals[0], decimals[1], decimals[2], decimals[3]);

    return 0;
}

static inline int hc_get_address_inet(const struct sockaddr *addr,
    char *str_dst, unsigned short *port_dst)
{
    const struct sockaddr_in *ipaddr = (const struct sockaddr_in *)addr;

    if (inet_ntop(AF_INET, &ipaddr->sin_addr, str_dst, INET_ADDRSTRLEN) == NULL)
        return -1;

    *port_dst = ntohs(ipaddr->sin_port);

    return 0;
}

static inline int hc_set_address_inet(const char *addr_str, unsigned short port,
    struct sockaddr *addr)
{
    struct sockaddr_in *ipaddr = (struct sockaddr_in *)addr;
    int res = inet_pton(AF_INET, addr_str, &ipaddr->sin_addr);

    if(res != 1)
    {
        if (res == 0)
            errno = EINVAL;
        return -1;
    }

    ipaddr->sin_family = AF_INET;
    ipaddr->sin_port  = htons(port);

    return 0;
}

static inline int hc_get_address_inet6(const struct sockaddr *addr,
    char *str_dst, unsigned short *port_dst)
{
    const struct sockaddr_in6 *ip6addr = (const struct sockaddr_in6 *)addr;

    if (inet_ntop(AF_INET6, &ip6addr->sin6_addr,
        str_dst, INET6_ADDRSTRLEN) == NULL)
    {
        return -1;
    }

    *port_dst = ntohs(ip6addr->sin6_port);

    return 0;
}

static inline int hc_set_address_inet6(const char *addr_str,
    unsigned short port, struct sockaddr *addr)
{
    struct sockaddr_in6 *ip6addr = (struct sockaddr_in6 *)addr;
    int res = inet_pton(AF_INET6, addr_str, &ip6addr->sin6_addr);

    if(res != 1)
    {
        if (res == 0)
            errno = EINVAL;
        return -1;
    }

    ip6addr->sin6_family = AF_INET6;
    ip6addr->sin6_port = htons(port);

    return 0;
}

#endif
