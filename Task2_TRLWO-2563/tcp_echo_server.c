#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>

#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "hc_address.h"
#include "hc_list.h"
#include "hc_event_handler.h"

#define LISTEN_QUEUE_LENGTH 10
#define SERVER_MAX_EPOLL_EVENT_N 20

typedef struct tcp_server_t {
    hc_event_handler_t handler_base;
    hc_list_t clients;
    int epoll_fd;
    int fd;
} tcp_server_t;

typedef struct tcp_client_t {
    hc_event_handler_t handler_base;
    hc_list_node node;
    int fd;
} tcp_client_t;

static volatile int int_sig_occured;

static int tcp_server_listener_handler(hc_event_handler_t *obj, void *arg);
static int tcp_server_client_handler(hc_event_handler_t *obj, void *arg);
static int tcp_client_mfree(void *obj);

static hc_event_handler_call_table serv_ctable = {
    NULL,
    tcp_server_listener_handler
};

static hc_event_handler_call_table client_ctable = {
    tcp_client_mfree,
    tcp_server_client_handler
};

static void handle_server_intsig(int sig)
{
    int_sig_occured = 1;
}

static int set_address(const char *addr_str, unsigned short port,
    struct sockaddr *addr)
{
    char addr_fmt_str[INET6_ADDRSTRLEN];

    if (!hc_format_address_inet(addr_str, addr_fmt_str))
        return hc_set_address_inet(addr_fmt_str, port, addr);

    return hc_set_address_inet6(addr_str, port, addr);
}

static int get_address(const struct sockaddr *addr, char *addr_dst_str,
    unsigned short *dst_port)
{
    if (addr->sa_family == AF_INET)
        return hc_get_address_inet(addr, addr_dst_str, dst_port);

    return hc_get_address_inet6(addr, addr_dst_str, dst_port);
}

static int set_non_blocking (int fd)
{
    int flags = fcntl(fd, F_GETFL);

    if (flags < 0)
        return -1;

    if(fcntl(fd, F_SETFL, flags|O_NONBLOCK) == -1)
        return -1;

    return 0;
}

static int sendall(int sock, const unsigned char *src,
    size_t const buff_size, size_t *written)
{
    *written = 0;

    do
    {
        ssize_t written_by_call = send(sock, src + *written,
	    buff_size - *written, MSG_NOSIGNAL);

        if (written_by_call == -1)
            return -1;

        *written += written_by_call;
    }
    while (*written < buff_size);

    return 0;
}

static int tcp_client_init(tcp_client_t *obj, int fd, tcp_server_t *serv_sock,
    hc_event_handler_t handler_base)
{
    obj->handler_base = handler_base;
    obj->fd = fd;
    hc_list_node_insert_before(hc_list_end(&serv_sock->clients), &obj->node);
    return 0;
}

static int tcp_server_init(tcp_server_t *obj, int fd, int associated_epoll_fd,
    hc_event_handler_t handler_base)
{
    obj->handler_base = handler_base;
    obj->fd = fd;
    obj->epoll_fd = associated_epoll_fd;
    hc_list_init(&obj->clients);
    return 0;
}

static int tcp_client_free(void *ptr)
{
    tcp_client_t *obj = (tcp_client_t *) ptr;
    close(obj->fd);
    hc_list_node_purge(&obj->node);
    return 0 ;
}

static int tcp_client_mfree(void *ptr)
{
    tcp_client_free(ptr);
    free(ptr);
    return 0;
}

static void thunk_list_node_to_tcp_client_mfree(hc_list_node *ptr)
{
    tcp_client_mfree((char *)ptr - offsetof(tcp_client_t, node));
}

static int tcp_server_free(void * ptr)
{
    tcp_server_t *obj = (tcp_server_t *)ptr;

    hc_list_for_each_node(hc_list_begin(&obj->clients),
            hc_list_end(&obj->clients),
            thunk_list_node_to_tcp_client_mfree);

    hc_list_destroy(&obj->clients);
    close(obj->epoll_fd);
    close(obj->fd);
    return 0;
}

static int tcp_server_listener_handler(hc_event_handler_t *obj, void *arg_ev)
{
    int accepted_fd, local_errno;
    struct epoll_event event_buff;
    tcp_client_t *client_buff;
    tcp_server_t *serv = (tcp_server_t *)obj;
    uint32_t ev = *(uint32_t *)arg_ev;

    if (!(ev & EPOLLIN))
        return 0;

    client_buff = (tcp_client_t *)malloc(sizeof(tcp_client_t));

    if (!client_buff)
        return -1;

    accepted_fd = accept(serv->fd, NULL, NULL);

    if (accepted_fd == -1 || set_non_blocking(accepted_fd))
    {
        free(client_buff);
        return -1;
    }

    if (tcp_client_init((tcp_client_t *)client_buff, accepted_fd, serv,
	(hc_event_handler_t){ &client_ctable }))
    {
        local_errno = errno;
        free(client_buff);
        goto ERR_EXIT_ACCEPTED_FD;
    }

    accepted_fd = -1;

    event_buff.events = EPOLLIN | EPOLLRDHUP;
    event_buff.data.ptr = client_buff;

    if (epoll_ctl(serv->epoll_fd, EPOLL_CTL_ADD, client_buff->fd, &event_buff))
    {
	local_errno = errno;
        goto ERR_EXIT_CLIENT;
    }

    fprintf(stderr, "\nClient connected.") ;

    return 0;

ERR_EXIT_CLIENT:
    tcp_client_mfree(client_buff);
ERR_EXIT_ACCEPTED_FD:
    close(accepted_fd);
    errno = local_errno ;
    return -1;
}

static int tcp_server_client_handler(hc_event_handler_t *obj, void *arg)
{
    unsigned char buff[256];
    size_t bytes_sent;
    ssize_t bytes_read;
    tcp_client_t *sock = (tcp_client_t *)obj;
    uint32_t ev = *(uint32_t *)arg;

    if (ev & EPOLLRDHUP)
    {
        fprintf(stderr, "\nClient disconnected.");
        tcp_client_mfree(sock);
        return 0;
    }

    bytes_read = recv(sock->fd, buff, sizeof(buff), 0);

    if (bytes_read == -1)
        return - 1;

    buff[sizeof(buff) - 1] = '\0';

    fprintf(stderr ,"\nMessage : %s", buff);

    if (sendall(sock->fd, buff, bytes_read, &bytes_sent))
        return -1;

    fprintf(stderr, "\n%s", buff);

    return 0;
}

static int create_listening_socket(char const *addr_str, unsigned short port)
{
    int fd, local_errno;
    struct sockaddr_storage addr_buff;

    if(set_address(addr_str, port, (struct sockaddr *)&addr_buff))
    {
        local_errno = errno;
        goto ERR_EXIT;
    }

    if ((fd = socket(addr_buff.ss_family, SOCK_STREAM, 0)) == -1)
    {
        local_errno = errno;
        goto ERR_EXIT;
    }

    if (bind(fd, (struct sockaddr *)&addr_buff,
	sizeof(struct sockaddr_storage)))
    {
        local_errno = errno;
        goto ERR_EXIT_FD;
    }

    if (listen(fd, LISTEN_QUEUE_LENGTH))
    {
        local_errno = errno;
        goto ERR_EXIT_FD;
    }

    return fd;

ERR_EXIT_FD:
    close(fd);
ERR_EXIT:
    errno = local_errno;
    return -1;
}

int main(int arg_n, char **args)
{
    tcp_server_t server;
    int epoll_instance_fd, server_socket_fd, local_errno;
    struct epoll_event event_buff;
    struct epoll_event * triggered_events_buff;
    const char *addr_str;
    int port;

    //TODO: will be removed after config implementation
    if (arg_n != 3)
        return -1;

    addr_str = args[1];
    port = atoi(args[2]);

    if (port > USHRT_MAX)
        return -1;

    if (signal(SIGINT, handle_server_intsig) == SIG_ERR)
    {
        fprintf(stderr, "\nError while setting signal handler");
        local_errno = EINVAL;
        goto ERR_EXIT;
    }

    triggered_events_buff = (struct epoll_event *)
        malloc(SERVER_MAX_EPOLL_EVENT_N * sizeof(struct epoll_event));

    if (!triggered_events_buff)
    {
        local_errno = errno;
        goto ERR_EXIT;
    }

    if ((epoll_instance_fd = epoll_create1(0)) == -1)
    {
        local_errno = errno;
        goto ERR_EXIT_EPOLL_BUFF;
    }

    if ((server_socket_fd = create_listening_socket(addr_str, port)) == -1)
    {
        local_errno = errno;
        goto ERR_EXIT_EPOLL_CREATED;
    }

    if (set_non_blocking(server_socket_fd))
    {
        local_errno = errno;
        goto ERR_EXIT_SERV_SOCK_FD;
    }

    if (tcp_server_init(&server, server_socket_fd,
        epoll_instance_fd, (hc_event_handler_t){ &serv_ctable }))
    {
        local_errno = errno;
        goto ERR_EXIT_SERV_SOCK_FD;
    }

    server_socket_fd = -1;
    epoll_instance_fd = -1;

    event_buff.events = EPOLLIN;
    event_buff.data.ptr = &server;

    if (epoll_ctl(server.epoll_fd, EPOLL_CTL_ADD, server.fd, &event_buff))
    {
         local_errno = errno;
         goto ERR_EXIT_SERV_SOCK;
    }

    while(1)
    {
        ssize_t triggered_num;

        if (int_sig_occured)
            break;

        triggered_num = epoll_wait(server.epoll_fd, triggered_events_buff,
            SERVER_MAX_EPOLL_EVENT_N, -1);

        if (triggered_num == -1)
        {
            if (errno == EINTR)
		break;
            local_errno = errno;
            goto ERR_EXIT_SERV_SOCK;
        }

        for (int idx = 0; idx < triggered_num; ++idx)
        {
            if (hc_event_handler_handle_event(
		triggered_events_buff[idx].data.ptr,
		&triggered_events_buff[idx].events))
            {
                perror("Exception");
            }
        }
    }

    fprintf(stderr , "\nserver was interrupted;");
    fprintf(stderr , "\nfreeing...");

    if (tcp_server_free(&server))
        perror("Cleaning : ");

    fprintf(stderr, "\n\t...done");

    return 0;

ERR_EXIT_SERV_SOCK:
    tcp_server_free(&server);
ERR_EXIT_SERV_SOCK_FD:
    close(server_socket_fd);
ERR_EXIT_EPOLL_CREATED:
    close(epoll_instance_fd);
ERR_EXIT_EPOLL_BUFF:
    free(triggered_events_buff);
ERR_EXIT:
    fprintf(stderr, "Exception : %s", strerror(local_errno));
    return -1;
}
