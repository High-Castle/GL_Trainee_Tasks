#ifndef __SERVER_CONFIG_H__
#define __SERVER_CONFIG_H__

#include <sys/socket.h>
#include <netinet/in.h>

typedef enum logging_level_t
{
    HC_LOGGING_DEBUG,
    HC_LOGGING_RELEASE,
    HC_LOGGING_SERVER,

    HC_LOGGING_ENUM_END,
} logging_level_t;

typedef struct server_config_t {
    const char *root_path;
    const char *file_name;
    struct sockaddr_in6 address;
    logging_level_t logging_lev;
    char use_ssl;
} server_config_t;

int server_config_json_init(server_config_t *, const char *, const char*,
    size_t, size_t);

int server_config_free (server_config_t *);

#endif
