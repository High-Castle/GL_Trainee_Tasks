#ifndef __SERVER_TLS_CONFIG_H__
#define __SERVER_TLS_CONFIG_H__

#include <stddef.h>

typedef struct server_tls_config_t {
    const char *crt_path;
    const char *pk_path;
} server_tls_config_t;

int server_tls_config_move_init (server_tls_config_t *to, 
  server_tls_config_t* from);

int server_tls_config_json_init(server_tls_config_t *, const char *,
  const char *, size_t, size_t);

int server_tls_config_free (server_tls_config_t *ctx);

#endif

