#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "http_subserver.h"
#include "server_tls_config.h"
// requires
#define LISTEN_QUEUE_LENGTH 100

enum
{
    HTTP_TLS_CLIENT_TASK_TLS_HANDSHAKE = HTTP_CLIENT_TASK_ENUM_END,
    HTTP_TLS_CLIENT_TASK_TLS_CLOSE_NOTIFY
};

//TODO: handle resume

static void *hc_server_module_add_instance_to(hc_server_t *);

typedef struct http_tls_subserver_t {
    http_subserver_t subserver_base;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;

    struct {
	mbedtls_ssl_config ssl_config;
    } shared;

    mbedtls_net_context net_ctx;
} http_tls_subserver_t;

typedef struct http_tls_subserver_ctable_t {
    http_subserver_ctable_t http_subserver_ctable;
} http_tls_subserver_ctable_t;

typedef struct http_tls_client_t {
    http_client_t client_base;
    mbedtls_net_context net_ctx;
    mbedtls_ssl_context ssl_ctx;
} http_tls_client_t;

typedef struct http_tls_client_ctable_t {
    http_client_ctable_t http_client_ctable;
} http_tls_client_ctable_t;


ssize_t http_client_TU_static_symbolic_parameter_recv(
    http_client_t *obj, void *buff, size_t sz);
int http_client_TU_static_symbolic_parameter_routine_sendall(
    http_client_t *obj, size_t quant);

static http_tls_client_t *http_tls_client_from_http_client_static_cast();
static int http_tls_client_init(http_tls_client_t *, http_subserver_t *,
    const char *, unsigned short, hc_clock_t, size_t, mbedtls_net_context *);

static int http_tls_client_free(http_tls_client_t *);
static int http_tls_client_mfree(http_tls_client_t *);
static int http_tls_client_disconnect(http_tls_client_t *);
static ssize_t http_tls_client_recv(http_tls_client_t *, void *, size_t);
static int http_tls_client_execute_task(http_tls_client_t *);
static int http_tls_client_routine_sendall(http_tls_client_t *, size_t);
static int http_tls_client_from_http_client_from_hc_client_disconnect(hc_client_t *obj);
static int http_tls_client_from_http_client_from_hc_client_execute_task(hc_client_t *obj);
static int http_tls_client_from_http_client_from_hc_client_from_hc_event_handler_mfree
	(hc_event_handler_iface *obj);
int http_tls_client_disconnect_unconditional(http_tls_client_t *obj);

static http_tls_subserver_t
  *http_tls_subserver_from_http_subserver_static_cast(http_subserver_t *obj);

  static int http_tls_subserver_init (http_tls_subserver_t *, hc_server_t *,
    server_config_t *, server_tls_config_t *);

static int http_tls_subserver_free (http_tls_subserver_t *obj);
static int http_tls_subserver_mfree (http_tls_subserver_t *obj);
static int http_tls_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_mfree(
    hc_event_handler_iface *obj);
static int http_tls_subserver_handle_event(http_tls_subserver_t *serv, void *arg_ev);
static int http_tls_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_handle_event(
    hc_event_handler_iface *obj, void *arg);
static int http_tls_client_task_tls_close_notify (http_tls_client_t *);
static int http_tls_client_task_tls_handshake (http_tls_client_t *);
static int set_non_blocking (int fd);


hc_server_module_t hc_server_module_instance = {
    hc_server_module_add_instance_to
};

static http_tls_client_ctable_t http_tls_client_ctable = {
  {
     {
        .hc_event_handler_ctable = {
	    http_tls_client_from_http_client_from_hc_client_from_hc_event_handler_mfree,
	    http_client_from_hc_client_from_hc_event_handler_handle_event
	 },
         http_tls_client_from_http_client_from_hc_client_disconnect,
         http_tls_client_from_http_client_from_hc_client_execute_task,
     }
  }
};


static http_tls_subserver_ctable_t http_tls_subserver_ctable = {
  {
    {
      {
	  http_tls_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_mfree,
	  http_tls_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_handle_event,
      }
    }
  }
};


static ssize_t http_tls_client_recv(http_tls_client_t *obj, void *buff,
    size_t sz)
{
       int ret;

       http_client_debug_log(&obj->client_base, SERVER_LOG_TRACE,
               "tls received from %d", obj->net_ctx.fd);

       ret = mbedtls_ssl_read(&obj->ssl_ctx, buff, sz);

       if (ret < 0)
       {
               if (ret == MBEDTLS_ERR_SSL_WANT_READ)
               {
                   errno = HTTP_CLIENT_ERRNO_EAGAIN_READ;
                   return -1;
               }

               if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
               {
                   errno = HTTP_CLIENT_ERRNO_EAGAIN_WRITE;
                   return -1;
               }

               errno = HTTP_CLIENT_ERRNO_ERROR;
               return -1;
       }

       return ret;
}

static inline int http_tls_client_routine_sendall(http_tls_client_t *obj,
    size_t quant)
{
    size_t to_send;
    int sz;

    http_client_debug_log(&(*obj).client_base, SERVER_LOG_TRACE,
         "calling \"http_client_routine_sendall\"");

    to_send = (*obj).client_base.task_data.sendall.remaining_sz < quant ?
        (*obj).client_base.task_data.sendall.remaining_sz : quant;

    sz = mbedtls_ssl_write(&(*obj).ssl_ctx, (*obj).client_base.task_data.sendall.data_ref,
        to_send);

    if (sz < 0)
    {
	switch (sz)
	{
	  case MBEDTLS_ERR_SSL_WANT_READ:
	  case MBEDTLS_ERR_SSL_WANT_WRITE:
	     return HTTP_CLIENT_ROUTINE_IN_PROGRESS;
	}

	return HTTP_CLIENT_ROUTINE_ERROR;
    }

    (*obj).client_base.task_data.sendall.remaining_sz -= sz;
    (*obj).client_base.task_data.sendall.data_ref += sz;

    if ((*obj).client_base.task_data.sendall.remaining_sz == 0)
        return HTTP_CLIENT_ROUTINE_DONE;

    return HTTP_CLIENT_ROUTINE_IN_PROGRESS;
}

static int http_tls_client_execute_task(http_tls_client_t *obj)
{
    int res;

    http_client_debug_log(&obj->client_base, SERVER_LOG_TRACE,
        "calling \"http_tls_client_execute_task\"");

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
	case HTTP_TLS_CLIENT_TASK_TLS_CLOSE_NOTIFY:
	    res = http_tls_client_task_tls_close_notify(obj);
	    break;
	case HTTP_TLS_CLIENT_TASK_TLS_HANDSHAKE:
	    res = http_tls_client_task_tls_handshake(obj);
	    break;
        default:
            http_client_debug_log(&obj->client_base,
                SERVER_LOG_FATAL, "bad task");
            return HC_CLIENT_TASK_CODE_ERROR_FATAL;
    }
    return res;
}

static http_tls_client_t *http_tls_client_from_http_client_static_cast(
    http_client_t *obj)
{
    return (http_tls_client_t *)((char *)obj
        - offsetof(http_tls_client_t, client_base));
}



ssize_t http_client_TU_static_symbolic_parameter_recv(
    http_client_t *obj, void *buff, size_t sz)
{
    return http_tls_client_recv(
        http_tls_client_from_http_client_static_cast(obj), buff, sz);
}

int http_client_TU_static_symbolic_parameter_routine_sendall(
    http_client_t *obj, size_t quant)
{
    return http_tls_client_routine_sendall(
	http_tls_client_from_http_client_static_cast(obj), quant);
}

static int http_tls_client_init(http_tls_client_t *obj, http_subserver_t *serv,
    const char *addr_ip_str, unsigned short addr_port,
    hc_clock_t tm_default_inactive_out, size_t buff_sz,
    mbedtls_net_context *net_ctx)
{
	if (http_client_init(&obj->client_base, serv, addr_ip_str, addr_port,
		tm_default_inactive_out, buff_sz))
	{
		return -1;
	}

	(*obj).client_base.client_base.handler_base.ctable =
		&http_tls_client_ctable.http_client_ctable
		  .hc_client_ctable.hc_event_handler_ctable;

	obj->net_ctx = *net_ctx;

	mbedtls_ssl_init(&obj->ssl_ctx);

	if (mbedtls_ssl_setup(&obj->ssl_ctx,
	    &http_tls_subserver_from_http_subserver_static_cast(
	      serv)->shared.ssl_config))
	{
	      mbedtls_ssl_free(&obj->ssl_ctx);
	      (*obj).client_base.client_base.handler_base.ctable =
		  &http_client_ctable.hc_client_ctable.hc_event_handler_ctable;
	      http_client_free(&obj->client_base);
	      return -1;
	}

	mbedtls_ssl_set_bio(&obj->ssl_ctx, &obj->net_ctx,
		mbedtls_net_send, mbedtls_net_recv, NULL);

	(*obj).client_base.current_task
            = HTTP_TLS_CLIENT_TASK_TLS_HANDSHAKE;

	return 0;
}

static int http_tls_client_free(http_tls_client_t *obj)
{
    mbedtls_ssl_free(&obj->ssl_ctx);
    mbedtls_net_free(&obj->net_ctx);
    (*obj).client_base.client_base.handler_base.ctable =
	&http_client_ctable.hc_client_ctable.hc_event_handler_ctable;
    return http_client_free(&obj->client_base);
}

static int http_tls_client_mfree(http_tls_client_t *ptr)
{
    int res = http_tls_client_free(ptr);
    int local_errno = errno;
    free(ptr);
    errno = local_errno;
    return res;
}

int http_tls_client_task_tls_handshake (http_tls_client_t *obj)
{
       switch ((*obj).client_base.task_data.state)
       {
       case HTTP_CLIENT_TASK_STATE_INITIAL:
               switch (mbedtls_ssl_handshake(&obj->ssl_ctx))
               {
               case 0:
                       http_client_switch_to(&obj->client_base,
                               HTTP_CLIENT_TASK_PARSE_REQUEST);
                       return HC_CLIENT_TASK_CODE_SUCCESS;

               case MBEDTLS_ERR_SSL_WANT_READ:
                       http_client_state_active_to_inactive_change(&obj->client_base);
                       return HC_CLIENT_TASK_CODE_SUCCESS;

               case MBEDTLS_ERR_SSL_WANT_WRITE:
                       // TODO : EPOLLOUT
                       return HC_CLIENT_TASK_CODE_SUCCESS;

               default :
                       http_tls_client_disconnect(obj);
                       return HC_CLIENT_TASK_CODE_SUCCESS;
               }

       default:
               fprintf(stderr, "bad state");
               abort();
       }
       return HC_CLIENT_TASK_CODE_SUCCESS;
}

int http_tls_client_task_tls_close_notify(http_tls_client_t *obj)
{
       switch ((*obj).client_base.task_data.state)
       {
       case HTTP_CLIENT_TASK_STATE_INITIAL:
               switch (mbedtls_ssl_close_notify(&obj->ssl_ctx))
               {
               case MBEDTLS_ERR_SSL_WANT_READ:
                    http_client_state_active_to_inactive_change(&obj->client_base);
                    return HC_CLIENT_TASK_CODE_SUCCESS;

               case MBEDTLS_ERR_SSL_WANT_WRITE:
                    return HC_CLIENT_TASK_CODE_SUCCESS;

               case 0:
               default:
		    http_tls_client_disconnect_unconditional(obj);
                    return HC_CLIENT_TASK_CODE_SUCCESS;
               }
       }
       return HC_CLIENT_TASK_CODE_SUCCESS;
}

int http_tls_client_disconnect_unconditional(http_tls_client_t *obj)
{
    http_client_disconnect(&obj->client_base);
    http_tls_client_mfree(obj);
    return 0;
}

int http_tls_client_disconnect(http_tls_client_t *obj)
{
    if ((*obj).ssl_ctx.state == MBEDTLS_SSL_SERVER_HELLO_DONE)
    {
	http_client_switch_to(&obj->client_base,
	  HTTP_TLS_CLIENT_TASK_TLS_CLOSE_NOTIFY);
        return 0;
    }

    return http_tls_client_disconnect_unconditional(obj);
}

int http_tls_client_from_http_client_from_hc_client_disconnect(hc_client_t *obj)
{
    return http_tls_client_disconnect(
	http_tls_client_from_http_client_static_cast(
	http_client_from_hc_client_static_cast(obj)));
}

static int http_tls_client_from_http_client_from_hc_client_execute_task(hc_client_t *obj)
{
    return http_tls_client_execute_task(
	http_tls_client_from_http_client_static_cast(
        http_client_from_hc_client_static_cast(obj)));
}

static int http_tls_client_from_http_client_from_hc_client_from_hc_event_handler_mfree
	(hc_event_handler_iface *obj)
{
    return http_tls_client_mfree(http_tls_client_from_http_client_static_cast(
        http_client_from_hc_client_static_cast(
        hc_client_from_hc_event_handler_static_cast(obj))));
}

static inline
http_tls_subserver_t
  *http_tls_subserver_from_http_subserver_static_cast(http_subserver_t *obj)
{
    return (http_tls_subserver_t *)((char *)obj
        - offsetof(http_tls_subserver_t, subserver_base));
}

static
int http_tls_subserver_init (http_tls_subserver_t *obj, hc_server_t *serv,
  server_config_t *conf, server_tls_config_t *conf_tls)
{
    char ip_str [INET6_ADDRSTRLEN], port_str[6];
    unsigned short port;

    if ((((struct sockaddr *)&conf->address)->sa_family == AF_INET ?
      hc_get_address_inet : hc_get_address_inet6)((struct sockaddr *)&conf->address, ip_str, &port))
    {
	return -1;
    }

    snprintf(port_str, sizeof(port_str), "%hu", port); // TODO: bound checking

    if (http_subserver_init(&obj->subserver_base, serv, conf))
	return -1;

    (*obj).subserver_base.subserver_base.handler_base.ctable =
	&http_tls_subserver_ctable.http_subserver_ctable
	    .hc_subserver_ctable.hc_event_handler_ctable;

    mbedtls_entropy_init(&obj->entropy);
    mbedtls_ctr_drbg_init(&obj->ctr_drbg);
    mbedtls_x509_crt_init(&obj->srvcert);
    mbedtls_pk_init(&obj->pkey);
    mbedtls_ssl_config_init(&obj->shared.ssl_config);
    mbedtls_net_init(&obj->net_ctx);

    if (mbedtls_ctr_drbg_seed(&obj->ctr_drbg, mbedtls_entropy_func,
        &obj->entropy, NULL, 0))
    {
	goto ERR_EXIT_ALL_MBEDTLS_INIT;
    }

    if (mbedtls_ssl_config_defaults(&obj->shared.ssl_config,
        MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT))
    {
	goto ERR_EXIT_ALL_MBEDTLS_INIT;
    }

    if (mbedtls_x509_crt_parse_file(&obj->srvcert, conf_tls->crt_path))
    {
	goto ERR_EXIT_ALL_MBEDTLS_INIT;
    }

    if (mbedtls_pk_parse_keyfile(&obj->pkey, conf_tls->pk_path, NULL))
    {
	goto ERR_EXIT_ALL_MBEDTLS_INIT;
    }

    mbedtls_ssl_conf_rng(&obj->shared.ssl_config, mbedtls_ctr_drbg_random,
	&obj->ctr_drbg);

    if (mbedtls_ssl_conf_own_cert(&obj->shared.ssl_config, &obj->srvcert,
        &obj->pkey))
    {
	goto ERR_EXIT_ALL_MBEDTLS_INIT;
    }

    if (mbedtls_net_bind(&obj->net_ctx, ip_str, port_str,
	MBEDTLS_NET_PROTO_TCP))
    {
	goto ERR_EXIT_ALL_MBEDTLS_INIT;
    }

    return 0;

ERR_EXIT_ALL_MBEDTLS_INIT:
    mbedtls_net_free(&obj->net_ctx);
    mbedtls_ssl_config_free(&obj->shared.ssl_config);
    mbedtls_pk_free(&obj->pkey);
    mbedtls_x509_crt_free(&obj->srvcert);
    mbedtls_ctr_drbg_free(&obj->ctr_drbg);
    mbedtls_entropy_free(&obj->entropy);

    (*obj).subserver_base.subserver_base.handler_base.ctable
	= &http_subserver_ctable.hc_subserver_ctable.hc_event_handler_ctable;
    http_subserver_free(&obj->subserver_base);

    return -1;
}

static
int http_tls_subserver_free (http_tls_subserver_t *obj)
{
    mbedtls_net_free(&obj->net_ctx);
    mbedtls_ssl_config_free(&obj->shared.ssl_config);
    mbedtls_pk_free(&obj->pkey);
    mbedtls_x509_crt_free(&obj->srvcert);
    mbedtls_ctr_drbg_free(&obj->ctr_drbg);
    mbedtls_entropy_free(&obj->entropy);

    obj->subserver_base.subserver_base.handler_base.ctable =
	&http_subserver_ctable.hc_subserver_ctable
	  .hc_event_handler_ctable;
    return http_subserver_free(&obj->subserver_base);
}

static
int http_tls_subserver_mfree (http_tls_subserver_t *obj)
{
    int res = http_tls_subserver_free(obj);
    free(obj);
    return res;
}

static
int http_tls_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_mfree(
    hc_event_handler_iface *obj)
{
    return http_tls_subserver_mfree(
	http_tls_subserver_from_http_subserver_static_cast(
	  http_subserver_from_hc_event_handler_static_cast(obj)));
}

int http_tls_subserver_handle_event(http_tls_subserver_t *serv, void *arg_ev)
{
    mbedtls_net_context accepted_net_ctx;
    struct sockaddr_in6 client_address;
    char client_addr_ip_str[INET6_ADDRSTRLEN];
    unsigned short client_addr_port;
    struct epoll_event event_buff;
    http_tls_client_t *client_buff;

    uint32_t ev = *(uint32_t *)arg_ev;

    http_subserver_debug_log(&serv->subserver_base, SERVER_LOG_TRACE,
        "calling \"http_server_handle_event\"");

    if (!(ev & EPOLLIN))
    {
        http_subserver_debug_log(&serv->subserver_base,
            SERVER_LOG_FATAL, "\nAcceptor Error.");
        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_FATAL_ERROR;
    }

    if (!(client_buff = (http_tls_client_t *)malloc(sizeof(http_tls_client_t))))
        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;

    mbedtls_net_init(&accepted_net_ctx);

    switch(mbedtls_net_accept(&serv->net_ctx, &accepted_net_ctx,
      NULL, 0, NULL))
    {
    case 0:
        break;
    case MBEDTLS_ERR_NET_BUFFER_TOO_SMALL:
    case MBEDTLS_ERR_NET_ACCEPT_FAILED:
    case MBEDTLS_ERR_SSL_WANT_READ:
        free(client_buff);
        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
    }

    if (mbedtls_net_set_nonblock(&accepted_net_ctx))
    {
        mbedtls_net_free(&accepted_net_ctx);
        free(client_buff);
        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
    }

    if (getpeername(accepted_net_ctx.fd, (struct sockaddr *)&client_address,
	&(socklen_t){sizeof(struct sockaddr_in6)}))
    {
	mbedtls_net_free(&accepted_net_ctx);
        free(client_buff);
	return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
    }

    if ((((struct sockaddr *)&client_address)->sa_family == AF_INET ?
      hc_get_address_inet : hc_get_address_inet6)
      ((struct sockaddr *)&client_address, client_addr_ip_str,
       &client_addr_port))
    {
        mbedtls_net_free(&accepted_net_ctx),
        free(client_buff);
        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
    }
    // TODO :  &serv->subserver_base
    if (http_tls_client_init(client_buff, &serv->subserver_base, client_addr_ip_str,
        client_addr_port, SERVER_DEFAULT_KA_TIMEOUT_MSEC, REQUEST_BUFF_SZ,
        &accepted_net_ctx))
    {
        mbedtls_net_free(&accepted_net_ctx);
	free(client_buff);
        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
    }

    event_buff.events = EPOLLIN | EPOLLRDHUP | EPOLLET; // TODO: | EPOLLOUT;
    event_buff.data.ptr = &client_buff->client_base.client_base.handler_base;

    if (epoll_ctl((*serv).subserver_base.subserver_base.server_ref->epoll_fd,
        EPOLL_CTL_ADD, client_buff->net_ctx.fd,
        &event_buff))
    {
        http_tls_client_mfree(client_buff);
	return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
    }

    http_client_state_inited_to_inactive_change(&client_buff->client_base);

    http_subserver_debug_log(&serv->subserver_base, SERVER_LOG_INFO, "\nClient %s:%hu connected"
        " (descriptor %d).",
        (*client_buff).client_base.remote_address.ip_str,
        (*client_buff).client_base.remote_address.port, client_buff->net_ctx.fd);

    return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
}


static
int http_tls_subserver_from_http_subserver_from_hc_subserver_from_hc_event_handler_handle_event(
    hc_event_handler_iface *obj, void *arg)
{
    return http_tls_subserver_handle_event(
        http_tls_subserver_from_http_subserver_static_cast(
	  http_subserver_from_hc_event_handler_static_cast(obj)),arg);
}


void *hc_server_module_add_instance_to(hc_server_t *server)
{
    fprintf(stderr, "HI.!");
    http_tls_subserver_t *subserver;
    server_config_t config;
    server_tls_config_t config_tls;
    struct epoll_event event_buff;

    if (!(subserver = (http_tls_subserver_t *)malloc(sizeof(http_tls_subserver_t))))
    {
	return NULL;
    }

    if (server_config_json_init(&config, "config_tls.json", "defaults_config_tls.json",
        255, 255))
    {
	free(subserver);
        return NULL;
    }

    if (server_tls_config_json_init(&config_tls, "config_tls.json", "defaults_config_tls.json",
        255, 255))
    {
	server_config_free(&config);
	free(subserver);
	return NULL;
    }

    if (http_tls_subserver_init(subserver, server, &config, &config_tls))
    {
        server_tls_config_free(&config_tls);
	server_config_free(&config);
	free(subserver);
        return NULL;
    }
//
    server_tls_config_free(&config_tls);
    server_config_free(&config);

    event_buff.events = EPOLLIN;
    event_buff.data.ptr = &(*subserver).subserver_base.subserver_base.handler_base;

    if (epoll_ctl(subserver->subserver_base.subserver_base.server_ref->epoll_fd,
        EPOLL_CTL_ADD, subserver->net_ctx.fd, &event_buff))
    {
	 http_tls_subserver_mfree(subserver);
         return NULL;
    }

    hc_server_add_subserver(server, &subserver->subserver_base.subserver_base);

    return &(*subserver).subserver_base.subserver_base;
}
