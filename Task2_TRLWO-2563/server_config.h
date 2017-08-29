#ifndef __SERVER_CONFIG_H__
#define __SERVER_CONFIG_H__

#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>

enum
{
    SERVER_LOG_ACCESS,
    SERVER_LOG_TRACE,
    SERVER_LOG_INFO,
    SERVER_LOG_FATAL,
    SERVER_LOG_ENUM_END
};

typedef struct server_config_t {
    unsigned char *logging_mask;
    const char *root_path;
    const char *file_name;
    FILE *logging_out;
    struct sockaddr_in6 address;
    char use_ssl;
} server_config_t;

int server_config_json_init(server_config_t *, const char *, const char*,
    size_t, size_t);

int server_config_move_init (server_config_t *, server_config_t*);

int server_config_free (server_config_t *);


#endif
