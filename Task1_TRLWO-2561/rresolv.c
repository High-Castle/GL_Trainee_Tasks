#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAX_HOST_STRLEN 1025

/* Inet_pton is not required to handle leading zeros in ipv4 addresses
 * ( .01. != .1. ); such behaviour is not expected of utilities
 * (ping, host, etc.).
 */
static int format_address_inet(const char *in_addr, char *out_addr)
{
    unsigned char decimals[4];
    int res = sscanf(in_addr, "%hhu.%hhu.%hhu.%hhu",
	&decimals[0], &decimals[1], &decimals[2], &decimals[3]);

    if (res < sizeof(decimals))
        return -1;

    sprintf(out_addr, "%hhu.%hhu.%hhu.%hhu",
	decimals[0], decimals[1], decimals[2], decimals[3]);

    return 0;
}

static void errlog_inet_pton(int err_res)
{
    if (err_res == -1)
    {
        fprintf(stderr, "\nexception : %s\n", strerror(errno));
        return ;
    }
    fprintf(stderr, "\nexception : Invalid address\n");
}


static void errlog_getnameinfo(int err_res)
{
    if (err_res == EAI_SYSTEM)
    {
        fprintf(stderr, "\nexception: %s\n", strerror(errno));
        return ;
    }
    fprintf(stderr, "\nexception : %s\n", gai_strerror(errno));
}


int main(int args_n, char **args)
{
    int res;
    char *const arg_addr_str = args[1];
    char inet4_addr_str[INET6_ADDRSTRLEN], domain_str[MAX_HOST_STRLEN];

    if (args_n != 2)
    {
        fprintf(stderr, "\nusage : rresolv <IPv4|IPv6 address>\n");
        return -1;
    }

    if (!format_address_inet(arg_addr_str, inet4_addr_str))
    {
        struct sockaddr_in addr = { .sin_family = AF_INET };

        res = inet_pton(AF_INET, inet4_addr_str, &addr.sin_addr);

        if (res != 1)
	{
            errlog_inet_pton(res);
	    return -1;
        }

        res = getnameinfo((struct sockaddr *)&addr, sizeof(struct sockaddr_in),
	    domain_str, sizeof(domain_str), NULL, 0, NI_NAMEREQD);

	if (res)
	{
	    errlog_getnameinfo(res);
            return -1;
        }
    }
    else
    {
        struct sockaddr_in6 addr = { .sin6_family = AF_INET6 };

	res = inet_pton(AF_INET6, arg_addr_str, &addr.sin6_addr);

        if (res != 1)
	{
            errlog_inet_pton(res);
            return -1;
        }

        res = getnameinfo((struct sockaddr *)&addr, sizeof(struct sockaddr_in6),
	    domain_str, sizeof(domain_str), NULL, 0, NI_NAMEREQD);

        if (res)
	{
            errlog_getnameinfo( res ) ;
            return -1;
        }
    }

    printf("%s\n", domain_str);

    return 0;
}
