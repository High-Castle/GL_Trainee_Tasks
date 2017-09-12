#include "http_subserver.h" // requires

#define LISTEN_QUEUE_LENGTH 100

typedef struct http_tcp_subserver_t {
    http_subserver_t subserver_base;
    int fd;
} http_tcp_subserver_t;

typedef struct http_tcp_subserver_ctable_t {
    http_subserver_ctable_t http_subserver_ctable;
} http_tcp_subserver_ctable_t;

typedef struct http_tcp_client_t {
    http_client_t client_base;
    int fd;
} http_tcp_client_t;

typedef struct http_tcp_client_ctable_t {
    http_client_ctable_t http_client_ctable;
} http_tcp_client_ctable_t;


ssize_t http_client_TU_static_symbolic_parameter_recv(
    http_client_t *obj, void *buff, size_t sz);
int http_client_TU_static_symbolic_parameter_routine_sendall(
    http_client_t *obj, size_t quant);

static http_tcp_client_t *http_tcp_client_from_http_client_static_cast();
static int http_tcp_client_init(http_tcp_client_t *, http_subserver_t *,
    const char *, unsigned short, hc_clock_t, size_t, int);
static int http_tcp_client_free(http_tcp_client_t *);
static int http_tcp_client_mfree(http_tcp_client_t *);
static int http_tcp_client_disconnect(http_tcp_client_t *);
static ssize_t http_tcp_client_recv(http_tcp_client_t *, void *, size_t);
static int http_tcp_client_execute_task(http_tcp_client_t *);
static int http_tcp_client_routine_sendall(http_tcp_client_t *, size_t);
static int http_tcp_client_from_http_client_from_hc_client_disconnect(hc_client_t *obj);
static int http_tcp_client_from_http_client_from_hc_client_execute_task(hc_client_t *obj);
static int http_tcp_client_from_http_client_from_hc_client_from_hc_event_handler_mfree
	(hc_event_handler_iface *obj);


static http_tcp_subserver_t
  *http_tcp_subserver_from_http_subserver_static_cast(http_subserver_t *obj);
static int http_tcp_subserver_init (http_tcp_subserver_t *obj, hc_server_t *serv,
  server_config_t *conf, int fd);
static int http_tcp_subserver_free (http_tcp_subserver_t *obj);
static int http_tcp_subserver_mfree (http_tcp_subserver_t *obj);
static int http_tcp_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_mfree(
    hc_event_handler_iface *obj);
static int http_tcp_subserver_handle_event(http_tcp_subserver_t *serv, void *arg_ev);
static int http_tcp_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_handle_event(
    hc_event_handler_iface *obj, void *arg);


static int set_non_blocking (int fd);

static int create_listening_socket(const struct sockaddr *addr,
    size_t addr_sz);

static void *hc_server_module_add_instance_to(hc_server_t *serv);

hc_server_module_t hc_server_module_instance = {
    hc_server_module_add_instance_to
};


static http_tcp_client_ctable_t http_tcp_client_ctable = {
  {
     {
        .hc_event_handler_ctable = {
	    http_tcp_client_from_http_client_from_hc_client_from_hc_event_handler_mfree,
	    http_client_from_hc_client_from_hc_event_handler_handle_event
	 },
         http_tcp_client_from_http_client_from_hc_client_disconnect,
         http_tcp_client_from_http_client_from_hc_client_execute_task,
     }
  }
};


static http_tcp_subserver_ctable_t http_tcp_subserver_ctable = {
  {
    {
      {
	  http_tcp_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_mfree,
	  http_tcp_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_handle_event,
      }
    }
  }
};


static ssize_t http_tcp_client_recv(http_tcp_client_t *obj, void *buff,
    size_t sz)
{
	ssize_t ret;

	http_client_debug_log(&obj->client_base, SERVER_LOG_TRACE,
		"received from %d", obj->fd);

	if ((ret = recv(obj->fd, buff, sz, 0)) == -1)
	{
            if (errno == EAGAIN || errno == EWOULDBLOCK)
		{
			errno = HTTP_CLIENT_ERRNO_EAGAIN_READ;
			return -1;
		}
		errno = HTTP_CLIENT_ERRNO_ERROR;
		return -1;
        }

    return ret;
}


static int http_tcp_client_execute_task(http_tcp_client_t *obj)
{
    int res;

    http_client_debug_log(&obj->client_base, SERVER_LOG_TRACE,
        "calling \"http_tcp_client_execute_task\"");

    switch ((*obj).client_base.current_task)
    {
        case HTTP_CLIENT_TASK_PARSE_REQUEST:
            res = http_client_task_parse_request(&obj->client_base);
            break;
        case HTTP_CLIENT_TASK_RESPONSE_GET:
            res = http_client_task_response_get(&obj->client_base);
            break;
        case HTTP_CLIENT_TASK_SENDFILE:
            res = http_client_task_sendfile(&obj->client_base);
            break;
        case HTTP_CLIENT_TASK_SEND_CTE:
            res = http_client_task_send_cte(&obj->client_base);
            break;
        case HTTP_CLIENT_TASK_RESPONSE_ERROR:
            res = http_client_task_response_error(&obj->client_base);
            break;
        default:
            http_client_debug_log(&obj->client_base,
                SERVER_LOG_FATAL, "bad task");
            return HC_CLIENT_TASK_CODE_ERROR_FATAL;
    }
    return res;
}

static inline int http_tcp_client_routine_sendall(http_tcp_client_t *obj,
    size_t quant)
{
    size_t to_send;
    ssize_t sz;

    http_client_debug_log(&(*obj).client_base, SERVER_LOG_TRACE,
         "calling \"http_client_routine_sendall\"");

    to_send = (*obj).client_base.task_data.sendall.remaining_sz < quant ?
        (*obj).client_base.task_data.sendall.remaining_sz : quant;

    sz = send(obj->fd, (*obj).client_base.task_data.sendall.data_ref,
        to_send, 0);

    if (sz == -1)
    {
	errno = (errno == EWOULDBLOCK || errno == EAGAIN ?
	  HTTP_CLIENT_ERRNO_EAGAIN_WRITE : HTTP_CLIENT_ERRNO_ERROR);

        return HTTP_CLIENT_ROUTINE_ERROR;
    }

    (*obj).client_base.task_data.sendall.remaining_sz -= sz;
    (*obj).client_base.task_data.sendall.data_ref += sz;

    if ((*obj).client_base.task_data.sendall.remaining_sz == 0)
        return HTTP_CLIENT_ROUTINE_DONE;

    return HTTP_CLIENT_ROUTINE_IN_PROGRESS;
}


static http_tcp_client_t *http_tcp_client_from_http_client_static_cast(
    http_client_t *obj)
{
    return (http_tcp_client_t *)((char *)obj
        - offsetof(http_tcp_client_t, client_base));
}



ssize_t http_client_TU_static_symbolic_parameter_recv(
    http_client_t *obj, void *buff, size_t sz)
{
    return http_tcp_client_recv(
        http_tcp_client_from_http_client_static_cast(obj), buff, sz);
}

int http_client_TU_static_symbolic_parameter_routine_sendall(
    http_client_t *obj, size_t quant)
{
	return http_tcp_client_routine_sendall(
		http_tcp_client_from_http_client_static_cast(obj), quant);
}



static int http_tcp_client_init(http_tcp_client_t *obj, http_subserver_t *serv,
    const char *addr_ip_str, unsigned short addr_port,
    hc_clock_t tm_default_inactive_out, size_t buff_sz, int fd)
{
	if (http_client_init(&obj->client_base, serv, addr_ip_str, addr_port,
		tm_default_inactive_out, buff_sz))
	{
		return -1;
	}

	(*obj).client_base.client_base.handler_base.ctable =
		&http_tcp_client_ctable.http_client_ctable
		  .hc_client_ctable.hc_event_handler_ctable;

	obj->fd = fd;
	return 0;
}

static int http_tcp_client_free(http_tcp_client_t *obj)
{
    close(obj->fd);
    (*obj).client_base.client_base.handler_base.ctable
        = &http_client_ctable.hc_client_ctable.hc_event_handler_ctable;

    return http_client_free(&obj->client_base);
}

static int http_tcp_client_mfree(http_tcp_client_t *ptr)
{
    int res = http_tcp_client_free(ptr);
    int local_errno = errno;
    free(ptr);
    errno = local_errno;
    return res;
}

static int http_tcp_client_disconnect(http_tcp_client_t *obj)
{
    http_client_disconnect(&obj->client_base);

    http_tcp_client_mfree(obj);

    return 0;
}

static
int http_tcp_client_from_http_client_from_hc_client_disconnect(hc_client_t *obj)
{
     return http_tcp_client_disconnect(
	http_tcp_client_from_http_client_static_cast(
	http_client_from_hc_client_static_cast(obj)));
}

static int http_tcp_client_from_http_client_from_hc_client_execute_task(hc_client_t *obj)
{
    return http_tcp_client_execute_task(
	http_tcp_client_from_http_client_static_cast(
        http_client_from_hc_client_static_cast(obj)));
}

static int http_tcp_client_from_http_client_from_hc_client_from_hc_event_handler_mfree
	(hc_event_handler_iface *obj)
{
    return http_tcp_client_mfree(http_tcp_client_from_http_client_static_cast(
        http_client_from_hc_client_static_cast(
        hc_client_from_hc_event_handler_static_cast(obj))));
}


static inline
http_tcp_subserver_t
  *http_tcp_subserver_from_http_subserver_static_cast(http_subserver_t *obj)
{
    return (http_tcp_subserver_t *)((char *)obj
        - offsetof(http_tcp_subserver_t, subserver_base));
}


static
int http_tcp_subserver_init (http_tcp_subserver_t *obj, hc_server_t *serv,
  server_config_t *conf, int fd)
{
    if (http_subserver_init(&obj->subserver_base, serv, conf))
	return -1;

    (*obj).subserver_base.subserver_base.handler_base.ctable =
	&http_tcp_subserver_ctable.http_subserver_ctable
	    .hc_subserver_ctable.hc_event_handler_ctable;

    obj->fd = fd;
    return 0;
}

static
int http_tcp_subserver_free (http_tcp_subserver_t *obj)
{
    close(obj->fd);

    obj->subserver_base.subserver_base.handler_base.ctable =
	&http_subserver_ctable.hc_subserver_ctable
	  .hc_event_handler_ctable;

    return http_subserver_free(&obj->subserver_base);
}

static
int http_tcp_subserver_mfree (http_tcp_subserver_t *obj)
{
    int res = http_tcp_subserver_free(obj);
    free(obj);
    return res;
}

static
int http_tcp_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_mfree(
    hc_event_handler_iface *obj)
{
    return http_tcp_subserver_mfree(
	http_tcp_subserver_from_http_subserver_static_cast(
	  http_subserver_from_hc_event_handler_static_cast(obj)));
}

static
int http_tcp_subserver_handle_event(http_tcp_subserver_t *serv, void *arg_ev)
{
    int accepted_fd, local_errno;
    struct sockaddr_in6 client_address;
    char client_addr_ip_str[INET6_ADDRSTRLEN];
    unsigned short client_addr_port;
    struct epoll_event event_buff;
    http_tcp_client_t *client_buff;
    uint32_t ev = *(uint32_t *)arg_ev;

    http_subserver_debug_log(&serv->subserver_base, SERVER_LOG_TRACE,
        "calling \"http_subserver_handle_event\"");

    if (!(ev & EPOLLIN))
    {
        http_subserver_debug_log(&serv->subserver_base, SERVER_LOG_FATAL,
            "\nAcceptor Error.");
        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_FATAL_ERROR;
    }

    if (!(client_buff = (http_tcp_client_t *)malloc(sizeof(http_tcp_client_t))))
        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;

    accepted_fd = accept(serv->fd, (struct sockaddr *)&client_address,
        &(socklen_t){sizeof(client_address)});

    if (accepted_fd == -1 || set_non_blocking(accepted_fd))
    {
        free(client_buff);
        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
    }

    if ((((struct sockaddr *)&client_address)->sa_family == AF_INET ?
      hc_get_address_inet : hc_get_address_inet6)
	((struct sockaddr *)&client_address, client_addr_ip_str,
	 &client_addr_port))
    {
        local_errno = errno;
        free(client_buff);
        goto ERR_EXIT_ACCEPTED_FD;
    }

    if (http_tcp_client_init(client_buff, &serv->subserver_base,
	client_addr_ip_str, client_addr_port,
	SERVER_DEFAULT_KA_TIMEOUT_MSEC, REQUEST_BUFF_SZ,
        accepted_fd))
    {
        local_errno = errno;
        free(client_buff);
        goto ERR_EXIT_ACCEPTED_FD;
    }

    accepted_fd = -1;

    event_buff.events = EPOLLIN | EPOLLRDHUP | EPOLLET; // TODO: | EPOLLOUT;
    event_buff.data.ptr = &(*client_buff).client_base.client_base.handler_base;

    if (epoll_ctl(serv->subserver_base.subserver_base.server_ref->epoll_fd,
        EPOLL_CTL_ADD, client_buff->fd, &event_buff))
    {
        local_errno = errno;
        goto ERR_EXIT_CLIENT;
    }

    http_client_state_inited_to_inactive_change(&client_buff->client_base);

    http_subserver_debug_log(&serv->subserver_base, SERVER_LOG_INFO,
        "\nClient %s:%hu connected (descriptor %d).",
        (*client_buff).client_base.remote_address.ip_str,
        (*client_buff).client_base.remote_address.port, client_buff->fd);

    return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;

ERR_EXIT_CLIENT:
    http_tcp_client_mfree(client_buff);
ERR_EXIT_ACCEPTED_FD:
    close(accepted_fd);
    errno = local_errno;
    return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
}

static
int http_tcp_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_handle_event(
    hc_event_handler_iface *obj, void *arg)
{
    return http_tcp_subserver_handle_event(
        http_tcp_subserver_from_http_subserver_static_cast(
	  http_subserver_from_hc_event_handler_static_cast(obj)),arg);
}


static inline int set_non_blocking (int fd)
{
    int flags = fcntl(fd, F_GETFL);

    if (flags < 0)
        return -1;

    if (fcntl(fd, F_SETFL, flags|O_NONBLOCK) == -1)
        return -1;

    return 0;
}


static inline int create_listening_socket(const struct sockaddr *addr, size_t addr_sz)
{
    int fd, local_errno;

    if ((fd = socket(addr->sa_family, SOCK_STREAM, 0)) == -1)
    {
        local_errno = errno;
        goto ERR_EXIT;
    }

    if (bind(fd, addr, addr_sz))
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


void *hc_server_module_add_instance_to(hc_server_t *server)
{
    http_tcp_subserver_t *subserver;
    server_config_t config;
    int server_socket_fd;
    struct epoll_event event_buff;

    if (!(subserver = (http_tcp_subserver_t *)malloc(sizeof(http_tcp_subserver_t))))
    {
	return NULL;
    }

    if (server_config_json_init(&config, "config.json", "defaults_config.json",
        255, 255))
    {
	free(subserver);
        return NULL;
    }

    if ((server_socket_fd = create_listening_socket(
        (struct sockaddr *)&config.address, sizeof(config.address))) == -1)
    {
        server_config_free(&config);
	free(subserver);
        return NULL;
    }

    if (set_non_blocking(server_socket_fd))
    {
	close(server_socket_fd);
        server_config_free(&config);
	free(subserver);
        return NULL;
    }

    if (http_tcp_subserver_init(subserver, server, &config, server_socket_fd))
    {
	close(server_socket_fd);
	server_config_free(&config);
	free(subserver);
        return NULL;
    }

    server_config_free(&config);
    server_socket_fd = -1;

    event_buff.events = EPOLLIN;
    event_buff.data.ptr = subserver;

    if (epoll_ctl(subserver->subserver_base.subserver_base.server_ref->epoll_fd,
        EPOLL_CTL_ADD, subserver->fd, &event_buff))
    {
	 http_tcp_subserver_mfree(subserver);
         return NULL;
    }

    hc_server_add_subserver(server, &subserver->subserver_base.subserver_base);

    return &(*subserver).subserver_base.subserver_base;
}
