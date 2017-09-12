#ifndef __HC_HTTP_SUBSERVER_H__
#define __HC_HTTP_SUBSERVER_H__

// TODO: correct dependencies

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>

#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "hc_address.h"
#include "hc_server.h"
#include "hc_list.h"
#include "hc_string.h"
#include "hc_event_handler.h"
#include "hc_http_parser.h"
#include "hc_clock.h"

#include "server_config.h"

// TODO: to config 
#define SERVER_DEFAULT_KA_TIMEOUT_MSEC 10 * 1000
#define CTE_BUFF_SZ 1024
#define REQUEST_BUFF_SZ  256
#define SEND_FILE_BUFF_SZ 1024

enum
{
    HTTP_ERROR_400_BAD_REQUEST,
    HTTP_ERROR_404_NOT_FOUND,
    HTTP_ERROR_501_NOT_IMPLEMENTED,

    HTTP_CLIENT_TASK_DATA_NIL,
    HTTP_CLIENT_TASK_DATA_TASK_SENDFILE,
    HTTP_CLIENT_TASK_DATA_TASK_SEND_CTE,

    HTTP_CLIENT_ROUTINE_DONE,
    HTTP_CLIENT_ROUTINE_IN_PROGRESS,
    HTTP_CLIENT_ROUTINE_ERROR,
    
    HTTP_CLIENT_TASK_STATE_INITIAL,
    HTTP_CLIENT_TASK_STATE_SENDALL,
    HTTP_CLIENT_TASK_STATE_FINAL_ACTION,
    
    HTTP_URI_RECOGNIZE_SINGLE_SLASH,
    HTTP_URI_RECOGNIZE_FILE,
    HTTP_URI_RECOGNIZE_DIRECTORY,
    HTTP_URI_RECOGNIZE_ASTERIX,
    HTTP_URI_RECOGNIZE_ERROR,
};


enum
{
    HTTP_CLIENT_TASK_PARSE_REQUEST,
    HTTP_CLIENT_TASK_RESPONSE_GET,
    HTTP_CLIENT_TASK_SENDFILE,
    HTTP_CLIENT_TASK_SEND_CTE,
    HTTP_CLIENT_TASK_RESPONSE_ERROR,
    HTTP_CLIENT_TASK_ENUM_END
};

enum
{
    HTTP_URI_RECOGNIZE_FLAGS_NONE = 0,
    HTTP_URI_RECOGNIZE_FLAGS_DOUBLE_DOT_INSIDE = 1,
};

enum
{
    HTTP_CLIENT_ERRNO_EAGAIN_READ,
    HTTP_CLIENT_ERRNO_EAGAIN_WRITE,
    HTTP_CLIENT_ERRNO_ERROR
};

enum
{
    HTTP_CLIENT_QUANT_C = 1000000,
    HTTP_CLIENT_QUANT_B = 1000000,
    HTTP_CLIENT_QUANT_A = 1000000,
};

typedef struct http_subserver_t {
    hc_subserver_t subserver_base;
    struct {
        char *uri_path_client_buff;
        char *client_writes_uri_here;
        size_t uri_client_buff_sz;
        server_config_t config;
    } shared;    
} http_subserver_t;

typedef struct http_subserver_ctable_t {
    hc_subserver_ctable_t hc_subserver_ctable;
} http_subserver_ctable_t;

typedef struct stream_buff_t {
    unsigned char *buff;
    size_t sz;
    unsigned char const *read_curr_ptr;
    unsigned char *write_curr_ptr;
} stream_buff_t;

typedef struct http_client_task_data_t
{
    struct {
        char *uri_str;
        const char *method_str_ref;
        const char *partial_ptr;
        int last_parsed;
        int ka_flag;
    } parsing;

    struct {
        const unsigned char *data_ref;
        size_t remaining_sz;
    } sendall;

    union {
        struct {
            unsigned char *buff;
            size_t buff_sz;
            size_t to_read_sz;
            int fd;
        } send_file;

        struct {
            unsigned char *buff;
            unsigned char *write_data_ptr;
            size_t buff_sz;
            size_t head_buff_sz;
            int fd;
        } send_cte;
    } task;

    void *data_ptr;
    int active_data;
    int state;

} http_client_task_data_t;

typedef struct http_client_t {
    hc_client_t client_base;
    stream_buff_t in_stream;
    http_client_task_data_t task_data;
    struct {
        time_t last_request_processing_start_tm;
        hc_clock_t last_request_processing_start_timestamp;
    } logging;
    struct {
        const char *ip_str;
        unsigned short port;
    } remote_address;
    int current_task;
} http_client_t;

typedef struct http_client_ctable_t {
    hc_client_ctable_t hc_client_ctable;
} http_client_ctable_t;



static inline int stream_buff_init(stream_buff_t *, size_t sz);
static inline int stream_buff_free(stream_buff_t *);
static inline size_t stream_buff_bytes_to_write(stream_buff_t *);
static inline size_t stream_buff_bytes_to_read(stream_buff_t *);
static inline int stream_buff_shift_left(stream_buff_t *);
static inline int stream_buff_rewind(stream_buff_t *);
static inline http_client_t *http_client_from_hc_client_from_hc_event_handler_static_cast(
    hc_event_handler_iface *);
static inline int http_client_init(http_client_t *, http_subserver_t *,
    const char *addr_ip_str, unsigned short addr_port,
    hc_clock_t tm_default_inactive_out, size_t buff_sz);
static inline int http_client_free(http_client_t *);
static inline int http_client_log_start_processing_time_update(http_client_t *);
static inline int http_client_debug_log(http_client_t *, int level,
    const char *fmt, ...);
static inline int http_client_disconnect(http_client_t *);
static inline int http_client_state_inited_to_inactive_change(http_client_t *);
static inline int http_client_state_inactive_to_active_change(http_client_t *);
static inline int http_client_state_active_to_inactive_change(http_client_t *);
static inline int set_non_blocking (int);
static inline int http_subserver_request_log_print_start (http_subserver_t *);
static inline int http_client_request_log (http_client_t *, int response_code);
static inline int http_subserver_debug_log(http_subserver_t *, int level, const char *fmt,
    ...);
static inline int http_uri_recognize(const char *str, int *flags);
static inline const char *http_uri_extension(const char *str);
static inline int http_client_routine_sendall_set(http_client_t *,
    unsigned char const *data, size_t sz);
static inline int http_client_task_data_init(http_client_task_data_t *, size_t uri_sz);
static inline int http_client_task_data_task_send_file_init(http_client_task_data_t *,
    size_t buff_sz, int fd, size_t fsize);
static inline int http_client_task_data_task_send_cte_init(http_client_task_data_t *,
    int fd, size_t buff_sz);
static inline int http_client_task_data_task_rewind(http_client_task_data_t *);
static inline int http_client_task_data_rewind(http_client_task_data_t *);
static inline int http_client_task_data_free(http_client_task_data_t *);
static inline int http_client_switch_to(http_client_t *, int task);
static inline size_t http_client_compute_quant(http_client_t *);
static inline int http_client_switch_to_final (http_client_t *);
static inline const char *http_ext_to_mime(const char *ext);
static inline int http_client_task_response_get (http_client_t *);
static inline int http_client_task_sendfile (http_client_t *);
static inline int http_client_task_send_cte (http_client_t *);
static inline int http_client_switch_to_response_error(http_client_t *, int err);
static inline int http_client_task_response_error(http_client_t *);
static inline int http_client_task_parse_request(http_client_t *);
static inline int http_client_handle_event(http_client_t *, void *arg);
static inline int http_client_from_hc_client_from_hc_event_handler_handle_event(
    hc_event_handler_iface *, void *arg);
static inline int http_client_last_active_timestamp_update(http_client_t *);
static inline int http_subserver_init(http_subserver_t *, hc_server_t *obj, 
    server_config_t *conf);
static inline int http_subserver_free(http_subserver_t *);
static inline int http_client_from_hc_client_from_hc_event_handler_handle_event(
    hc_event_handler_iface *obj, void *arg);
static inline http_subserver_t *http_subserver_from_hc_subserver_static_cast(
    hc_subserver_t *obj);       
static inline http_subserver_t *http_subserver_from_hc_event_handler_static_cast(
    hc_event_handler_iface *obj);
static inline ssize_t http_client_TU_static_symbolic_parameter_recv(
    http_client_t *, void *, size_t);
static inline int http_client_TU_static_symbolic_parameter_routine_sendall(
    http_client_t *, size_t);
static inline http_subserver_t *http_client_subserver_ref(http_client_t *obj);

static http_subserver_ctable_t http_subserver_ctable = {
  {
    {
        NULL,
        NULL
    }
  }
};

static http_client_ctable_t http_client_ctable = {
  {
    {
	NULL,
	http_client_from_hc_client_from_hc_event_handler_handle_event
    },
    NULL,
    NULL
  }
};


static inline 
int http_client_last_active_timestamp_update(http_client_t *obj)
{
    return hc_client_last_active_timestamp_update(&obj->client_base);
}
    
static inline
int stream_buff_init(stream_buff_t *obj, size_t sz)
{
    if (!(obj->buff = (unsigned char *)malloc(sz)))
        return -1;

    obj->read_curr_ptr = obj->buff;
    obj->write_curr_ptr = obj->buff;
    obj->sz = sz;

    return 0;
}

static inline
int stream_buff_free(stream_buff_t *obj)
{
    free((*obj).buff);
    return 0;
}

static inline
size_t stream_buff_bytes_to_write(stream_buff_t *obj)
{
    return obj->buff + obj->sz - obj->write_curr_ptr;
}

static inline
size_t stream_buff_bytes_to_read(stream_buff_t *obj)
{
    return obj->write_curr_ptr - obj->read_curr_ptr;
}

static inline
int stream_buff_shift_left(stream_buff_t *obj)
{
    assert(obj->write_curr_ptr >= obj->read_curr_ptr);

    size_t read_sz = stream_buff_bytes_to_read(obj);

    memmove(obj->buff, obj->read_curr_ptr, read_sz);

    obj->read_curr_ptr = obj->buff;
    obj->write_curr_ptr = obj->buff + read_sz;
    return 0;
}

static inline
int stream_buff_rewind(stream_buff_t *obj)
{
    obj->read_curr_ptr = obj->buff;
    obj->write_curr_ptr = obj->buff;
    return 0;
}


int http_client_debug_log(http_client_t *obj, int level,
    const char *fmt, ...)
{
    assert(level < SERVER_LOG_ENUM_END);

    if (http_client_subserver_ref(obj)->shared.config.logging_mask[level])
    {
        va_list arg_l;
        va_start(arg_l, fmt);
        fprintf(stderr, "\nClient %s:%hu : ", (*obj).remote_address.ip_str,
            (*obj).remote_address.port);

        int res = vfprintf(stderr, fmt, arg_l);
        va_end(arg_l);
        return res;
    }

    return 0;
}


static inline ssize_t http_client_recv (http_client_t *obj,
    void *buff, size_t sz)
{
    return http_client_TU_static_symbolic_parameter_recv(obj, buff, sz);
}

static inline int http_client_routine_sendall (http_client_t *obj, size_t quant)
{
    return http_client_TU_static_symbolic_parameter_routine_sendall(obj, quant);
}

static inline http_subserver_t *http_subserver_from_hc_event_handler_static_cast(
    hc_event_handler_iface *obj)
{
    return http_subserver_from_hc_subserver_static_cast(
        hc_subserver_from_hc_event_handler_static_cast(obj));
}

static inline int http_subserver_request_log_print_start (http_subserver_t *obj)
{
    int printed;
    time_t curr_time;
    struct tm *curr_time_info;

    if (!(*obj).shared.config.logging_mask[SERVER_LOG_ACCESS])
        return 0;

    if (time(&curr_time) == -1)
        return -1;

    curr_time_info = localtime(&curr_time);

    printed = fprintf(obj->shared.config.logging_out, "#Version: 1.0"
        "\r\n#Fields: date time time-taken c-ip cs-method cs-uri sc-status"
        "\r\n#Start-Date: %.2u-%.2u-%.2u %.2u:%.2u:%.2u",
        curr_time_info->tm_year + 1900,
        curr_time_info->tm_mon,
        curr_time_info->tm_mday,
        curr_time_info->tm_hour,
        curr_time_info->tm_min,
        curr_time_info->tm_sec);

    fflush(obj->shared.config.logging_out);

    return printed;
}

static inline int http_subserver_debug_log(http_subserver_t *obj, int level,
    const char *fmt, ...)
{
    assert(level < SERVER_LOG_ENUM_END);

    if ((*obj).shared.config.logging_mask[level])
    {
        va_list arg_l;
        va_start(arg_l, fmt);
        int res = vfprintf(stderr, fmt, arg_l);
        va_end(arg_l);
        return res;
    }

    return 0;
}


static inline void free_and_null(void **ptr)
{
    free(*ptr);
    *ptr = NULL;
}

static inline int http_uri_recognize(const char *str,
     int *flags)
{
    const char *last_elem_ptr;
    size_t str_strlen = strlen(str);

    *flags = HTTP_URI_RECOGNIZE_FLAGS_NONE;

    if (!str_strlen)
        return HTTP_URI_RECOGNIZE_ERROR;

    last_elem_ptr = str + str_strlen - 1;

    if (!strcmp(str, "/"))
        return HTTP_URI_RECOGNIZE_SINGLE_SLASH;

    if (!strcmp(str, "*"))
        return HTTP_URI_RECOGNIZE_ASTERIX;

    if (strstr(str, "../"))
        *flags |= HTTP_URI_RECOGNIZE_FLAGS_DOUBLE_DOT_INSIDE;

    if (*last_elem_ptr == '/')
        return HTTP_URI_RECOGNIZE_DIRECTORY;


    return HTTP_URI_RECOGNIZE_FILE;
}


static inline const char *http_uri_extension(const char *str)
{
    const char *extension;

    size_t str_strlen = strlen(str);
    const char *last_elem_ptr = str + str_strlen - 1;

    extension = hc_rstrtok(last_elem_ptr, str_strlen, "./", 2,
        hc_find_char);

    if (extension)
    {
        if (*extension == '/'
            || extension == last_elem_ptr
            || extension == str
            || *(extension - 1) == '/')
        {
            return NULL;
        }
    }

    return extension;
}


static inline int http_client_log_start_processing_time_update(http_client_t *obj)
{
    if (time(&(*obj).logging.last_request_processing_start_tm) == -1)
    {
        fprintf(stderr, "Error while updating the time (line %d)", __LINE__);
        abort();
    }

    (*obj).logging.last_request_processing_start_timestamp = hc_clock_ms();
    return 0;
}


static inline int http_client_disconnect_vcall(http_client_t *obj)
{
    http_client_debug_log(obj, SERVER_LOG_TRACE,
        "calling \"http_client_disconnect_vcall\"");
    
    return hc_client_disconnect_vcall(&obj->client_base);
}

static inline int http_client_disconnect(http_client_t *obj)
{
    http_client_debug_log(obj, SERVER_LOG_TRACE,
        "calling \"http_client_disconnect\"");

    return hc_client_disconnect(&obj->client_base);
}

http_subserver_t *http_client_subserver_ref(http_client_t *obj)
{
    return http_subserver_from_hc_subserver_static_cast(
        obj->client_base.subserver_ref);
}

int http_client_request_log (http_client_t *obj, int response_code)
{
    struct tm *curr_time_info;
    long long processing_time_delta_ms;
    int printed;

    if (!http_client_subserver_ref(obj)->shared.config.logging_mask[SERVER_LOG_ACCESS])
        return 0;

    processing_time_delta_ms = (long long)(hc_clock_ms()
        - (*obj).logging.last_request_processing_start_timestamp);

    curr_time_info = localtime(
        &(*obj).logging.last_request_processing_start_tm);

    printed = fprintf(http_client_subserver_ref(obj)->shared.config.logging_out,
		"\r\n%.2u-%.2u-%.2u %.2u:%.2u:%.2u %lld.%lld %s:%hu %s %s %d",
        (curr_time_info->tm_year + 1900),
        curr_time_info->tm_mon,
        curr_time_info->tm_mday,
        curr_time_info->tm_hour,
        curr_time_info->tm_min,
        curr_time_info->tm_sec,
        processing_time_delta_ms / 1000, processing_time_delta_ms % 1000,
        (*obj).remote_address.ip_str,
        (*obj).remote_address.port,
        (*obj).task_data.parsing.method_str_ref,
        (*obj).task_data.parsing.uri_str, response_code);

    fflush(http_client_subserver_ref(obj)->shared.config.logging_out);

    return printed;
}


static inline int http_subserver_init(http_subserver_t *obj,
    hc_server_t *serv, server_config_t *conf)
{
    size_t root_strlen;
    
    if (hc_subserver_init(&obj->subserver_base, serv))
        return -1;
    
    (*obj).subserver_base.handler_base.ctable = &http_subserver_ctable
	  .hc_subserver_ctable.hc_event_handler_ctable;

    root_strlen = strlen(conf->root_path);
    obj->shared.uri_client_buff_sz = FILENAME_MAX;

    if (!(obj->shared.uri_path_client_buff = malloc(root_strlen
        + obj->shared.uri_client_buff_sz)))
    {
        (*obj).subserver_base.handler_base.ctable 
            = &hc_subserver_ctable.hc_event_handler_ctable;
        hc_subserver_free(&obj->subserver_base);
        return -1;
    }

    (*obj).shared.client_writes_uri_here
        = obj->shared.uri_path_client_buff + root_strlen;

    memcpy(obj->shared.uri_path_client_buff, conf->root_path, root_strlen);

    server_config_move_init(&obj->shared.config, conf);
    
    return 0;
}

static inline int http_subserver_free(http_subserver_t *obj)
{
    server_config_free(&obj->shared.config);
    free((*obj).shared.uri_path_client_buff);
    
    (*obj).subserver_base.handler_base.ctable = 
        &hc_subserver_ctable.hc_event_handler_ctable;
    
    hc_subserver_free(&(*obj).subserver_base);
    return 0;
}

http_subserver_t *http_subserver_from_hc_subserver_static_cast(
  hc_subserver_t *obj)
{
    return (http_subserver_t *)((char *)obj
        - offsetof(http_subserver_t, subserver_base));
}

static inline http_subserver_t *
  http_subserver_from_hc_subserver_from_hc_event_handler_static_cast(
    hc_event_handler_iface *obj)
{
    return http_subserver_from_hc_subserver_static_cast(
	hc_subserver_from_hc_event_handler_static_cast(obj));
}

static inline http_client_t *http_client_from_hc_client_static_cast(hc_client_t *obj)
{
    return (http_client_t *)((char *)obj
        - offsetof(http_client_t, client_base));
}

static inline http_client_t *http_client_from_hc_client_from_hc_event_handler_static_cast(
    hc_event_handler_iface *obj)
{
    return http_client_from_hc_client_static_cast(
	hc_client_from_hc_event_handler_static_cast(obj));
}

int http_client_init(http_client_t *obj, http_subserver_t *serv,
    const char *addr_ip_str, unsigned short addr_port,
    hc_clock_t tm_default_inactive_out, size_t buff_sz)
{
    int local_errno;
    size_t addr_strlen;
    char *ip_str;

    http_subserver_debug_log(serv, SERVER_LOG_TRACE,
         "\ncalling \"http_client_init\"");
    
    if (hc_client_init(&obj->client_base, &serv->subserver_base, 
        tm_default_inactive_out, HC_CLIENT_STATE_INITED))
    {
	return -1;
    }
	 
    (*obj).client_base.handler_base.ctable 
        = &http_client_ctable.hc_client_ctable.hc_event_handler_ctable;

    addr_strlen = strlen(addr_ip_str);

    if (!(ip_str = (char *)malloc(addr_strlen + 1))) 
    {
        local_errno = errno;
	goto ERR_EXIT_HC_CLIENT;
    }
    
    if (stream_buff_init(&obj->in_stream, buff_sz))
    {
        local_errno = errno;
        goto ERR_EXIT_MALLOC_ADDRESS_IP_STR;
    }

    if (http_client_task_data_init(&obj->task_data,
        serv->shared.uri_client_buff_sz))
    {
        local_errno = errno;
        goto ERR_EXIT_IN_STREAM;
    }

    memcpy(ip_str, addr_ip_str, addr_strlen + 1);
    obj->remote_address.ip_str = ip_str;
    obj->remote_address.port = addr_port;
    (*obj).current_task = HTTP_CLIENT_TASK_PARSE_REQUEST;
    return 0;

ERR_EXIT_IN_STREAM:
    stream_buff_free(&obj->in_stream);
ERR_EXIT_MALLOC_ADDRESS_IP_STR:
    free(ip_str);
ERR_EXIT_HC_CLIENT:
    hc_client_free(&obj->client_base);
    errno = local_errno;
    return -1;
}

int http_client_free(http_client_t *obj)
{
    http_client_task_data_free(&obj->task_data);
    stream_buff_free(&obj->in_stream);
    free((void *)obj->remote_address.ip_str);
    return 0;
}

int http_client_state_inited_to_inactive_change(http_client_t *obj)
{
    http_client_debug_log(obj, SERVER_LOG_TRACE,
        "calling \"http_client_state_inited_to_inactive_change\"");
    return hc_client_state_inited_to_inactive_change(&obj->client_base);
}

int http_client_state_inactive_to_active_change(http_client_t *obj)
{
    http_client_debug_log(obj, SERVER_LOG_TRACE,
        "calling \"http_client_state_inactive_to_active_change\"");
    return hc_client_state_inactive_to_active_change(&obj->client_base);
}

int http_client_state_active_to_inactive_change(http_client_t *obj)
{
    http_client_debug_log(obj, SERVER_LOG_TRACE,
         "calling \"http_client_state_active_to_inactive_change\"");
    
    assert((*obj).client_base.state != HC_CLIENT_STATE_INITED);
    assert((*obj).client_base.state != HC_CLIENT_STATE_INACTIVE);
    assert((*obj).client_base.state == HC_CLIENT_STATE_ACTIVE);
    
    return hc_client_state_active_to_inactive_change(&obj->client_base);
}

static inline
int http_client_task_data_init(http_client_task_data_t *obj,
    size_t uri_sz)
{
    if (uri_sz < 2)
        return -1;

    if (!((*obj).parsing.uri_str = (char *)malloc(uri_sz)))
        return -1;

    sprintf((*obj).parsing.uri_str, "-");

    (*obj).parsing.method_str_ref = "-";

    (*obj).data_ptr = NULL;

    (*obj).parsing.partial_ptr = NULL;

    (*obj).parsing.last_parsed = HC_HTTP_PARSER_REQUEST_LINE_NOTHING;

    (*obj).state = HTTP_CLIENT_TASK_STATE_INITIAL;

    (*obj).parsing.ka_flag = 0;

    obj->active_data = HTTP_CLIENT_TASK_DATA_NIL;

    return 0;
}

static inline
int http_client_task_data_task_send_file_init(
    http_client_task_data_t *obj, size_t buff_sz, int fd, size_t fsize)
{
    assert(obj->active_data == HTTP_CLIENT_TASK_DATA_NIL);

    if (!(obj->task.send_file.buff = malloc(buff_sz)))
        return -1;

    obj->task.send_file.buff_sz = buff_sz;
    obj->task.send_file.fd = fd;
    obj->task.send_file.to_read_sz = fsize;

    obj->active_data = HTTP_CLIENT_TASK_DATA_TASK_SENDFILE;
    return 0;
}

static inline
int http_client_task_data_task_send_cte_init( http_client_task_data_t *obj, 
    int fd, size_t buff_sz)
{
    assert(obj->active_data == HTTP_CLIENT_TASK_DATA_NIL);

    assert(buff_sz);
    assert(!(fd < 0));

    const char *const max_additional_symbols = "\r\n"/*num*/"\r\n\r\n";

    size_t head_sz = hc_digit_count(buff_sz, 16)
        + strlen(max_additional_symbols) + 1;

    if (!(obj->task.send_cte.buff = malloc(buff_sz + head_sz)))
        return -1;

    obj->task.send_cte.write_data_ptr = obj->task.send_cte.buff + head_sz;

    obj->task.send_cte.buff_sz = buff_sz;
    obj->task.send_cte.head_buff_sz = head_sz;
    obj->task.send_cte.fd = fd;

    obj->active_data = HTTP_CLIENT_TASK_DATA_TASK_SEND_CTE;

    return 0;
}

static inline int http_client_task_data_task_rewind(
    http_client_task_data_t *obj)
{
    switch(obj->active_data)
    {
        case HTTP_CLIENT_TASK_DATA_NIL:
            return 0;
        case HTTP_CLIENT_TASK_DATA_TASK_SENDFILE:
            close(obj->task.send_file.fd);
            free(obj->task.send_file.buff);
            break;
        case HTTP_CLIENT_TASK_DATA_TASK_SEND_CTE:
            close(obj->task.send_cte.fd);
            free(obj->task.send_cte.buff);
            break;
        default:
            assert(!"bad task data state");
    }

    obj->active_data = HTTP_CLIENT_TASK_DATA_NIL;
    return 0;
}

static inline
int http_client_task_data_rewind(http_client_task_data_t *obj)
{
    http_client_task_data_task_rewind(obj);
    (*obj).parsing.ka_flag = 0;
    (*obj).parsing.last_parsed = HC_HTTP_PARSER_REQUEST_LINE_NOTHING;
    (*obj).parsing.partial_ptr = NULL;
    sprintf((*obj).parsing.uri_str, "-");
    (*obj).parsing.method_str_ref = "-";
    (*obj).state = HTTP_CLIENT_TASK_STATE_INITIAL;
    return 0;
}

static inline
int http_client_task_data_free(http_client_task_data_t *obj)
{
    http_client_task_data_task_rewind(obj);
    free_and_null(&obj->data_ptr);
    free((*obj).parsing.uri_str);
    return 0;
}

int http_client_switch_to(http_client_t *obj, int task)
{
    http_client_debug_log(obj, SERVER_LOG_TRACE,
         "calling \"http_client_switch_to\" task enum: %d", task);
    
    (*obj).current_task = task;
    (*obj).task_data.state = HTTP_CLIENT_TASK_STATE_INITIAL;
    return 0;
}

size_t http_client_compute_quant(http_client_t *obj)
{
    if (obj->client_base.subserver_ref->server_ref
        ->active_clients_count < 9)
    {
        return (size_t)HTTP_CLIENT_QUANT_A;
    }
    
    if (obj->client_base.subserver_ref->server_ref
        ->active_clients_count < 99)
    {
        return (size_t)HTTP_CLIENT_QUANT_B;
    }
    
    return (size_t)HTTP_CLIENT_QUANT_C;
}

int http_client_switch_to_final (http_client_t *obj)
{
    http_client_debug_log(obj, SERVER_LOG_TRACE,
         "calling \"http_client_switch_to_final\"");

    http_client_request_log(obj, 200);

    if ((*obj).task_data.parsing.ka_flag)
    {
        http_client_task_data_rewind(&obj->task_data);
        stream_buff_shift_left(&obj->in_stream);
        (*obj).client_base.timeout_ms = SERVER_DEFAULT_KA_TIMEOUT_MSEC;
        (*obj).current_task = HTTP_CLIENT_TASK_PARSE_REQUEST;
        http_client_last_active_timestamp_update(obj);
        return 0;
    }

    http_client_disconnect_vcall(obj);
    return 0;
}

const char *http_ext_to_mime(const char *ext)
{
    static const char *pair[][2] = {
        { ".html" , "text/html" } ,
        { ".pdf" , "application/pdf" } ,
        { ".txt" , "text/plain" },
        { ".jpg" , "image/jpeg" } } ;

    if (ext)
    {
        for (size_t idx = 0; idx != sizeof(pair)/sizeof(*pair); ++idx)
            if (!strcmp(ext, pair[idx][0]))
                return pair[idx][1];
    }

    return "application/octet-stream";
}

static inline int http_client_routine_sendall_set(http_client_t *obj,
    unsigned char const *data, size_t sz)
{
    (*obj).task_data.sendall.data_ref = data;
    (*obj).task_data.sendall.remaining_sz = sz;
    return 0;
}

int http_client_task_response_get (http_client_t *obj)
{
    http_client_debug_log(obj, SERVER_LOG_TRACE,
        "calling \"http_client_task_response_get\"");
    const size_t send_file_buff_sz = 1024; 
    switch ((*obj).task_data.state)
    {

    case HTTP_CLIENT_TASK_STATE_INITIAL:
    {
        int fd, rec_flags, file_error;
        const char *mime_str;
        struct stat stat;
        int recognized = http_uri_recognize((*obj).task_data.parsing.uri_str,
            &rec_flags);

        if (rec_flags & HTTP_URI_RECOGNIZE_FLAGS_DOUBLE_DOT_INSIDE)
        {
            http_client_switch_to_response_error(obj,
                HTTP_ERROR_400_BAD_REQUEST);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        switch (hc_http_uri_decode(
            http_client_subserver_ref(obj)->shared.client_writes_uri_here,
            recognized != HTTP_URI_RECOGNIZE_SINGLE_SLASH ?
            (*obj).task_data.parsing.uri_str
            : http_client_subserver_ref(obj)->shared.config.file_name,
            http_client_subserver_ref(obj)->shared.uri_client_buff_sz))
        {
            case HC_HTTP_URI_DECODE_TO_SZ_ERROR_SUCCESS:
                break;
            case HC_HTTP_URI_DECODE_TO_SZ_ERROR_BAD_SRC_STR:
            case HC_HTTP_URI_DECODE_TO_SZ_ERROR_NULL_NOT_FOUND:
                http_client_switch_to_response_error(obj,
                    HTTP_ERROR_400_BAD_REQUEST);
                return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        mime_str = http_ext_to_mime(http_uri_extension(
            http_client_subserver_ref(obj)->shared.client_writes_uri_here));

        if ((fd = open( http_client_subserver_ref(obj)
                ->shared.uri_path_client_buff, O_RDONLY | O_NONBLOCK)) == -1)
        {
            switch (errno)
            {
                case EISDIR:
                    file_error = HTTP_ERROR_400_BAD_REQUEST;
                    break;
                default:
                    file_error = HTTP_ERROR_404_NOT_FOUND;
            }

            http_client_switch_to_response_error(obj, file_error);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        if (fstat(fd, &stat))
        {
            http_client_switch_to_response_error(obj,
                HTTP_ERROR_404_NOT_FOUND);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        if (S_ISREG(stat.st_mode))
        {
            ssize_t written;
            const char *fmt = "HTTP/1.1 200 OK\r\nContent-Type: %s;"
                "\r\nContent-Length: %zd""\r\n\r\n";
            size_t header_buff_sz = strlen(fmt) - strlen("%s%zd")
                + strlen(mime_str) + hc_digit_count(stat.st_size, 10) + 1;

            if (!(obj->task_data.data_ptr = malloc(header_buff_sz)))
            {
                close(fd);
                http_client_disconnect_vcall(obj);
                return HC_CLIENT_TASK_CODE_ERROR;
            }

            written = snprintf(obj->task_data.data_ptr, header_buff_sz,
                fmt, mime_str, stat.st_size);

            if (written < 0)
            {
                close(fd);
                http_client_disconnect_vcall(obj);
                return HC_CLIENT_TASK_CODE_ERROR;
            }

            if (http_client_task_data_task_send_file_init(&obj->task_data,
                send_file_buff_sz, fd, stat.st_size))
            {
                close(fd);
                http_client_disconnect_vcall(obj);
                return HC_CLIENT_TASK_CODE_ERROR;
            }

            http_client_routine_sendall_set(obj, obj->task_data.data_ptr,
                (size_t)written);
        }
        else if (S_ISFIFO(stat.st_mode))
        {
            ssize_t written;
            const char *fmt = "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n"
                              "Transfer-Encoding: chunked\r\n";
            size_t header_buff_sz = strlen(fmt) - strlen("%s")
                + strlen(mime_str) + 1;

            if (!(obj->task_data.data_ptr = malloc(header_buff_sz)))
            {
                close(fd);
                http_client_disconnect_vcall(obj);
                return HC_CLIENT_TASK_CODE_ERROR;
            }

            written = snprintf(obj->task_data.data_ptr, header_buff_sz,
                fmt, mime_str);

            if (written < 0)
            {
                close(fd);
                http_client_disconnect_vcall(obj);
                return HC_CLIENT_TASK_CODE_ERROR;
            }

            if (http_client_task_data_task_send_cte_init(&obj->task_data, fd,
                CTE_BUFF_SZ))
            {
                close(fd);
                http_client_disconnect_vcall(obj);
                return HC_CLIENT_TASK_CODE_ERROR;
            }

            http_client_routine_sendall_set(obj, obj->task_data.data_ptr,
                (size_t)written);
        }
        else
        {
            http_client_switch_to_response_error(obj,
                HTTP_ERROR_404_NOT_FOUND);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        (*obj).task_data.state = HTTP_CLIENT_TASK_STATE_SENDALL;
    }

    case HTTP_CLIENT_TASK_STATE_SENDALL:

        switch (http_client_routine_sendall(obj,
            http_client_compute_quant(obj)))
        {
            case HTTP_CLIENT_ROUTINE_DONE:
                http_client_last_active_timestamp_update(obj);
                break;

            case HTTP_CLIENT_ROUTINE_IN_PROGRESS:
                http_client_last_active_timestamp_update(obj);
                return HC_CLIENT_TASK_CODE_SUCCESS;

            case HTTP_CLIENT_ROUTINE_ERROR:
                
		if (errno == HTTP_CLIENT_ERRNO_EAGAIN_WRITE)
		{
		    // TODO: to inactive change
		    return HC_CLIENT_TASK_CODE_SUCCESS;
		}
	      
		if (errno == HTTP_CLIENT_ERRNO_EAGAIN_READ)
		{
		    http_client_state_active_to_inactive_change(obj);
		    return HC_CLIENT_TASK_CODE_SUCCESS;
		}
		
                http_client_disconnect_vcall(obj);

                return HC_CLIENT_TASK_CODE_SUCCESS;

            default :
                assert(!"bad return value");
        }

        free_and_null(&(*obj).task_data.data_ptr);

        switch ((*obj).task_data.active_data)
        {
            case HTTP_CLIENT_TASK_DATA_TASK_SENDFILE:
                http_client_switch_to(obj, HTTP_CLIENT_TASK_SENDFILE);
                break;

            case HTTP_CLIENT_TASK_DATA_TASK_SEND_CTE:
                http_client_switch_to(obj, HTTP_CLIENT_TASK_SEND_CTE);
                break;

            default:
                assert(!"bad active_data value");
                http_client_debug_log(obj, SERVER_LOG_FATAL,
                    "bad active_data value");
                return HC_CLIENT_TASK_CODE_ERROR_FATAL;
        }
    }

    return HC_CLIENT_TASK_CODE_SUCCESS;
}



int http_client_task_sendfile (http_client_t *obj)
{
    http_client_debug_log(obj, SERVER_LOG_TRACE,
            "calling \"http_client_task_sendfile\"");

    assert((*obj).task_data.active_data == HTTP_CLIENT_TASK_DATA_TASK_SENDFILE);

    switch ((*obj).task_data.state)
    {
    case HTTP_CLIENT_TASK_STATE_INITIAL:
    {
        ssize_t read_bytes;
/*
        http_client_debug_log(obj, SERVER_LOG_TRACE, "transfering %d --> %d",
                    (*obj).task_data.task.send_file.fd, (*obj).fd);
*/
        read_bytes = read((*obj).task_data.task.send_file.fd,
            (*obj).task_data.task.send_file.buff,
            (*obj).task_data.task.send_file.buff_sz);

        if (read_bytes == -1)
        {
            assert((*obj).task_data.task.send_file.to_read_sz);

            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // TODO: to inactive change
                return HC_CLIENT_TASK_CODE_SUCCESS;
            }

            http_client_debug_log(obj, SERVER_LOG_INFO, "%d: %s",
                __LINE__, strerror(errno));
            http_client_disconnect_vcall(obj);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        if (read_bytes == 0)
        {
            http_client_switch_to_final(obj);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        (*obj).task_data.task.send_file.to_read_sz -= read_bytes;

        http_client_routine_sendall_set(obj, obj->task_data.task.send_file.buff,
            read_bytes);

        (*obj).task_data.state = HTTP_CLIENT_TASK_STATE_SENDALL;
    }
    case HTTP_CLIENT_TASK_STATE_SENDALL:

        switch (http_client_routine_sendall(obj,
                http_client_compute_quant(obj)))
        {
            case HTTP_CLIENT_ROUTINE_DONE:
                http_client_last_active_timestamp_update(obj);
                break;

            case HTTP_CLIENT_ROUTINE_IN_PROGRESS:
                http_client_last_active_timestamp_update(obj);
                return HC_CLIENT_TASK_CODE_SUCCESS;

            case HTTP_CLIENT_ROUTINE_ERROR:
	      
		if (errno == HTTP_CLIENT_ERRNO_EAGAIN_WRITE)
		{
		    return HC_CLIENT_TASK_CODE_SUCCESS;
		}
                
                if (errno == HTTP_CLIENT_ERRNO_EAGAIN_READ)
		{
		    http_client_state_active_to_inactive_change(obj);
		    return HC_CLIENT_TASK_CODE_SUCCESS;
		}
		
                http_client_disconnect_vcall(obj);

                return HC_CLIENT_TASK_CODE_SUCCESS;

            default :
                assert(!"bad return value");
                return HC_CLIENT_TASK_CODE_ERROR_FATAL;
        }

        if ((*obj).task_data.task.send_file.to_read_sz == 0)
        {
            http_client_switch_to_final(obj);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        (*obj).task_data.state = HTTP_CLIENT_TASK_STATE_INITIAL;
    }
    return HC_CLIENT_TASK_CODE_SUCCESS;
}

int http_client_task_send_cte (http_client_t *obj)
{
    assert((*obj).task_data.active_data
        == HTTP_CLIENT_TASK_DATA_TASK_SEND_CTE);

    http_client_debug_log(obj, SERVER_LOG_TRACE,
         "calling \"http_client_task_send_cte\"");

    switch ((*obj).task_data.state)
    {
        case HTTP_CLIENT_TASK_STATE_INITIAL:
        {
            unsigned char *send_begin;
            ssize_t written;
            ssize_t read_bytes = read((*obj).task_data.task.send_cte.fd,
                (*obj).task_data.task.send_cte.write_data_ptr,
                (*obj).task_data.task.send_cte.buff_sz);

            if (read_bytes == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN)
                    return HC_CLIENT_TASK_CODE_SUCCESS;

                http_client_disconnect_vcall(obj);
                return HC_CLIENT_TASK_CODE_SUCCESS;
            }

            written = snprintf((char *)(*obj).task_data.task.send_cte.buff,
                (*obj).task_data.task.send_cte.head_buff_sz,
                (read_bytes ? "\r\n%zx\r\n" : "\r\n0\r\n\r\n"), read_bytes);

            http_client_debug_log(obj, SERVER_LOG_TRACE,
                "\nsend_cte: pack head : %s",
                (char *)(*obj).task_data.task.send_cte.buff);

            if (written < 0)
            {
                http_client_debug_log(obj, SERVER_LOG_INFO,
                    "\nError while \"snprintf\" into the buffer: "
                    "%ld bytes are written into the buffer of size %zd",
                    written, (*obj).task_data.task.send_cte.head_buff_sz);

                http_client_disconnect_vcall(obj);
                return HC_CLIENT_TASK_CODE_SUCCESS;
            }

            send_begin = (*obj).task_data.task.send_cte.buff
                + ((*obj).task_data.task.send_cte.head_buff_sz - written);

            assert(send_begin + written
                == (*obj).task_data.task.send_cte.write_data_ptr);

            memmove(send_begin, (*obj).task_data.task.send_cte.buff, written);

            http_client_routine_sendall_set(obj, send_begin,
                (size_t)(written + read_bytes));

            (*obj).task_data.state = (read_bytes ? HTTP_CLIENT_TASK_STATE_SENDALL
                : HTTP_CLIENT_TASK_STATE_FINAL_ACTION);
        }

        case HTTP_CLIENT_TASK_STATE_SENDALL:
        case HTTP_CLIENT_TASK_STATE_FINAL_ACTION:

            switch (http_client_routine_sendall(obj,
                    http_client_compute_quant(obj)))
            {
                case HTTP_CLIENT_ROUTINE_DONE:
                    http_client_last_active_timestamp_update(obj);
                    break;

                case HTTP_CLIENT_ROUTINE_IN_PROGRESS:
                    http_client_last_active_timestamp_update(obj);
                    return HC_CLIENT_TASK_CODE_SUCCESS;

                case HTTP_CLIENT_ROUTINE_ERROR:
		    
		    if (errno == HTTP_CLIENT_ERRNO_EAGAIN_WRITE)
		    {
			return HC_CLIENT_TASK_CODE_SUCCESS;
		    }
		  
		    if (errno == HTTP_CLIENT_ERRNO_EAGAIN_READ)
		    {
			http_client_state_active_to_inactive_change(obj);
			return HC_CLIENT_TASK_CODE_SUCCESS;
		    }
		    
		    http_client_disconnect_vcall(obj);

		    return HC_CLIENT_TASK_CODE_SUCCESS;

                default :
                    assert(!"bad return value");
                    return HC_CLIENT_TASK_CODE_ERROR_FATAL;
            }

            if ((*obj).task_data.state == HTTP_CLIENT_TASK_STATE_SENDALL)
            {
                (*obj).task_data.state = HTTP_CLIENT_TASK_STATE_INITIAL;
            }
            else
            {
                assert((*obj).task_data.state
                    == HTTP_CLIENT_TASK_STATE_FINAL_ACTION);
                http_client_switch_to_final(obj);
            }

            return HC_CLIENT_TASK_CODE_SUCCESS;

        default :
            http_client_debug_log(obj, SERVER_LOG_FATAL,
                "%d: invalid task state", __LINE__);
            return HC_CLIENT_TASK_CODE_ERROR_FATAL;
    }
    return HC_CLIENT_TASK_CODE_SUCCESS;
}

int http_client_switch_to_response_error(http_client_t *obj, int err)
{
    const char *str;
    int error_code;

    switch (err)
    {
        case HTTP_ERROR_400_BAD_REQUEST:
            str = "HTTP/1.1 400 Bad Request\r\n\r\n";
            error_code = 400;
            break;
        case HTTP_ERROR_404_NOT_FOUND:
            str = "HTTP/1.1 404 Not Found\r\n\r\n";
            error_code = 404;
            break;
        case HTTP_ERROR_501_NOT_IMPLEMENTED:
            str = "HTTP/1.1 501 Not Implemented\r\n\r\n";
            error_code = 501;
            break;
        default:
            http_client_debug_log(obj, SERVER_LOG_FATAL,
                "%d: Unrecognized err value: %d", __LINE__, err);
            str = "HTTP/1.1 500 Internal Error";
            error_code = 500;
    }

    http_client_request_log(obj, error_code);

    http_client_routine_sendall_set(obj, (unsigned char const *)str,
        strlen(str));

    http_client_switch_to(obj, HTTP_CLIENT_TASK_RESPONSE_ERROR);
    return 0;
}

int http_client_task_response_error(http_client_t *obj)
{
    http_client_debug_log(obj, SERVER_LOG_TRACE,
         "calling \"http_client_task_response_error\"");

    switch (http_client_routine_sendall(obj,
        http_client_compute_quant(obj)))
    {
        case HTTP_CLIENT_ROUTINE_DONE:
            http_client_last_active_timestamp_update(obj);
            break;

        case HTTP_CLIENT_ROUTINE_IN_PROGRESS:
            http_client_last_active_timestamp_update(obj);
            return HC_CLIENT_TASK_CODE_SUCCESS;

        case HTTP_CLIENT_ROUTINE_ERROR:

	    if (errno == HTTP_CLIENT_ERRNO_EAGAIN_WRITE)
	    {
		return HC_CLIENT_TASK_CODE_SUCCESS;
	    }

	    if (errno == HTTP_CLIENT_ERRNO_EAGAIN_READ)
	    {
		http_client_state_active_to_inactive_change(obj);
		return HC_CLIENT_TASK_CODE_SUCCESS;
	    }
	    

	    http_client_disconnect_vcall(obj);

	    return HC_CLIENT_TASK_CODE_SUCCESS;
        default :
            assert(!"bad return value");
    }

    http_client_disconnect_vcall(obj);
    return HC_CLIENT_TASK_CODE_SUCCESS;
}

static inline int http_client_task_parse_request(http_client_t *obj)
{
    assert((*obj).client_base.state == HC_CLIENT_STATE_ACTIVE);

    const char *token_begin, *token_end;

    static const char * const not_supported_methods[] = {
	"POST",
	"PUT",
	"OPTIONS",
	"HEAD",
	"DELETE",
	"CONNECT"
    };

    http_client_debug_log(obj, SERVER_LOG_TRACE,
        "calling \"http_client_task_parse_request\"");

    if ((*obj).task_data.state == HTTP_CLIENT_TASK_STATE_INITIAL)
    {
        http_client_debug_log(obj, SERVER_LOG_TRACE,
            ".task_data.state == INITIAL");
        http_client_log_start_processing_time_update(obj);
        (*obj).task_data.state = HTTP_CLIENT_TASK_STATE_FINAL_ACTION;
        assert(obj->in_stream.write_curr_ptr == obj->in_stream.read_curr_ptr);
        assert(obj->in_stream.buff == obj->in_stream.read_curr_ptr);
    }

    http_client_debug_log(obj, SERVER_LOG_TRACE,
        ".task_data.state == FINAL_ACTION");

    assert((*obj).task_data.state == HTTP_CLIENT_TASK_STATE_FINAL_ACTION);

    if (!stream_buff_bytes_to_read(&obj->in_stream))
    {
        ssize_t received_sz;

        assert(stream_buff_bytes_to_write(&obj->in_stream)
            <= obj->in_stream.sz);

        assert(stream_buff_bytes_to_read(&obj->in_stream) <= obj->in_stream.sz);

        received_sz = http_client_recv(obj, (*obj).in_stream.write_curr_ptr,
            stream_buff_bytes_to_write(&(*obj).in_stream));

        if (received_sz == -1)
        {
            http_client_debug_log(obj, SERVER_LOG_TRACE, "recv: ERROR");

            switch (errno)
            {
	      case HTTP_CLIENT_ERRNO_EAGAIN_READ:
                http_client_debug_log(obj, SERVER_LOG_TRACE,
                    "recv: EWOULDBLOCK");

                http_client_state_active_to_inactive_change(obj);
		return HC_CLIENT_TASK_CODE_SUCCESS;
		
	      case HTTP_CLIENT_ERRNO_EAGAIN_WRITE:
                return HC_CLIENT_TASK_CODE_SUCCESS;
            }
            http_client_disconnect_vcall(obj);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        if (received_sz == 0)
        {
            http_client_disconnect_vcall(obj);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        (*obj).in_stream.write_curr_ptr += received_sz;

        http_client_debug_log(obj, SERVER_LOG_TRACE, "\nReceived ||%.*s||",
            (int)stream_buff_bytes_to_read(&obj->in_stream),
            (*obj).in_stream.read_curr_ptr);
/* 
        http_client_debug_log(obj, SERVER_LOG_TRACE, "\nBuffer %zd ||%.*s||",
           obj->in_stream.sz, (int)obj->in_stream.sz, (*obj).in_stream.buff);
  
        */
    }

    http_client_last_active_timestamp_update(obj);

    for (; ;)
    {
        if ((*obj).task_data.parsing.last_parsed
                == HC_HTTP_PARSER_REQUEST_PARSE_ERROR)
        {
            http_client_debug_log(obj, SERVER_LOG_INFO,
                "last_parsed == PARSE_ERROR");
            http_client_switch_to_response_error(obj,
                HTTP_ERROR_400_BAD_REQUEST);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        if ((*obj).task_data.parsing.last_parsed
            == HC_HTTP_PARSER_REQUEST_EMPTY_LINE)
        {
            http_client_switch_to(obj, HTTP_CLIENT_TASK_RESPONSE_GET);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        token_begin = (*obj).task_data.parsing.partial_ptr;
        token_end = NULL;

        (*obj).in_stream.read_curr_ptr = (const unsigned char *)
            hc_http_parse_request((char *)(*obj).in_stream.read_curr_ptr,
                (char *)(*obj).in_stream.write_curr_ptr,
                &token_begin, &token_end,
                &(*obj).task_data.parsing.last_parsed);


        if (!token_begin) // no token found
        {
            assert(!(*obj).task_data.parsing.partial_ptr);
            http_client_debug_log(obj, SERVER_LOG_TRACE,
                "REWINDING");
            stream_buff_rewind(&obj->in_stream);
            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        if (!token_end) // is partial
        {
            size_t data_sz = (const char *)obj->in_stream.write_curr_ptr
                - token_begin;
            size_t begin_offset = token_begin
                - (const char *)obj->in_stream.buff;

            http_client_debug_log(obj, SERVER_LOG_TRACE,
                "\nbefore shifting : %zd ||%.*s|| ||%.*s||" ,
                begin_offset, (int)data_sz, token_begin,
                (int)(obj->in_stream.write_curr_ptr - obj->in_stream.buff),
                (char *)obj->in_stream.buff);

            memmove(obj->in_stream.buff, token_begin, data_sz);

            token_begin = (char *)obj->in_stream.buff;

            obj->in_stream.write_curr_ptr -= begin_offset;
            obj->in_stream.read_curr_ptr -= begin_offset;

            (*obj).task_data.parsing.partial_ptr = token_begin;

            if (!stream_buff_bytes_to_write(&obj->in_stream))
            {
                assert(!begin_offset);
                http_client_switch_to_response_error(obj,
                    HTTP_ERROR_400_BAD_REQUEST);
                return HC_CLIENT_TASK_CODE_SUCCESS;
            }

            return HC_CLIENT_TASK_CODE_SUCCESS;
        }

        (*obj).task_data.parsing.partial_ptr = NULL;

        switch ((*obj).task_data.parsing.last_parsed)
        {

        case HC_HTTP_PARSER_REQUEST_LINE_METHOD:

            http_client_debug_log(obj, SERVER_LOG_TRACE,
		"mehtod current token %.*s", (int)(token_end - token_begin),
		token_begin);

            if (!hc_streq(token_begin, token_end - token_begin, "GET",
                strlen("GET")))
            {
                for (size_t idx = 0; idx != sizeof(not_supported_methods)
                    /sizeof(void*); ++idx)
                {
                    if (hc_streq(token_begin, token_end - token_begin,
                        not_supported_methods[idx],
                        strlen(not_supported_methods[idx])))
                    {
                        (*obj).task_data.parsing.method_str_ref
                            = not_supported_methods[idx];

                        http_client_switch_to_response_error(obj,
                            HTTP_ERROR_501_NOT_IMPLEMENTED);

                        return HC_CLIENT_TASK_CODE_SUCCESS;
                    }
                }

                (*obj).task_data.parsing.method_str_ref = "-";

                http_client_debug_log(obj, SERVER_LOG_TRACE,
					"\n\nBAD METHOD\n\n");

                http_client_switch_to_response_error(obj,
                    HTTP_ERROR_400_BAD_REQUEST);

                return HC_CLIENT_TASK_CODE_SUCCESS;
            }

            (*obj).task_data.parsing.method_str_ref = "GET";

            break;

        case HC_HTTP_PARSER_REQUEST_LINE_URI:

            assert(token_end >= token_begin);

            if ((size_t)(token_end - token_begin) + 1 >
                http_client_subserver_ref(obj)->shared.uri_client_buff_sz)
            {
                return http_client_switch_to_response_error(obj,
                    HTTP_ERROR_400_BAD_REQUEST);
            }

            memcpy((*obj).task_data.parsing.uri_str, token_begin,
                token_end - token_begin);

            (*obj).task_data.parsing.uri_str[token_end - token_begin] = '\0';
            break;

        case HC_HTTP_PARSER_REQUEST_HEADER_VALUE:

            if (!(*obj).task_data.parsing.ka_flag)
            {
                if (!(token_end - token_begin))
                    break;

                const char *trimmed_end = hc_rfind_not_char(' ', token_end - 1,
                    token_end - token_begin);

                if (hc_streq_ic(token_begin, trimmed_end + 1 - token_begin,
                    "keep-alive", strlen("keep-alive")))
                {
                    http_client_debug_log(obj, SERVER_LOG_INFO, "KEEP-ALIVE");
                    (*obj).task_data.parsing.ka_flag = 1;
                    break;
                }
            }

        default:
           http_client_debug_log(obj, SERVER_LOG_INFO,
                "\nskipping %s: %.*s" ,
                hc_http_parser_request_enum_to_str(
                    (*obj).task_data.parsing.last_parsed),
                    (int)(token_end - token_begin), token_begin);
            break;
        }
    }
    return HC_CLIENT_TASK_CODE_SUCCESS;
}


int http_client_handle_event(http_client_t *obj, void *arg)
{
    uint32_t ev = *(uint32_t *)arg;

    http_client_debug_log(obj, SERVER_LOG_TRACE,
        "calling \"http_client_handle_event\"; event mask %u", ev);

    if (ev & EPOLLERR)
    {
        http_client_debug_log(obj, SERVER_LOG_INFO,
            "\ndisconnected unexpectedly (%s).", ev & EPOLLHUP
                ? "RST" : "Internal Error");

        http_client_disconnect_vcall(obj);
        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
    }

    if (ev & EPOLLRDHUP)
    {
        http_client_debug_log(obj, SERVER_LOG_INFO,
            "disconnected (EPOLLRDHUP)");

        http_client_disconnect_vcall(obj);

        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
    }

    if (ev & EPOLLIN)
    {
        http_client_debug_log(obj, SERVER_LOG_INFO, "EPOLLIN.");

        if ((*obj).client_base.state == HC_CLIENT_STATE_INACTIVE)
            http_client_state_inactive_to_active_change(obj);

        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
    }

    return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
}

int http_client_from_hc_client_from_hc_event_handler_handle_event(
    hc_event_handler_iface *obj, void *arg)
{
    return http_client_handle_event(
        http_client_from_hc_client_from_hc_event_handler_static_cast(obj), arg);
}

#endif