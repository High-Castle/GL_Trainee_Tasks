#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>

#include "utilities/parson/parson.h"

#include "server_tls_config.h"

int server_tls_config_move_init (server_tls_config_t *to, server_tls_config_t* from)
{
    *to = *from;
    from->crt_path = NULL;
    from->pk_path = NULL;
    return 0;
}

int server_tls_config_json_init(server_tls_config_t *conf, const char *fname,
    const char* defaults_fname, size_t max_path_strlen, size_t max_fname_strlen)
{
    int local_errno = 0;
    char const *crt_path_str, *pk_path_str;
    char *crt_path_buff, *pk_path_buff;
    size_t crt_path_sz, pk_path_sz;
    JSON_Object *root_object, *defaults_root_object;
    JSON_Value *root_value, *defaults_root_value;
	
    if (!(defaults_root_value = json_parse_file_with_comments(defaults_fname)))
    {
        local_errno = EINVAL;
        fprintf(stderr, "\nError: no valid defaults config file");
        goto ERR_EXIT;
    }

    if (!(defaults_root_object = json_object(defaults_root_value)))
    {
        local_errno = EINVAL;
        fprintf(stderr, "\nError: invalid json in config file");
        goto ERR_EXIT_DEFAULTS_JSON_VALUE;
    }

    if (!(root_value = json_parse_file_with_comments(fname)))
    {
        local_errno = EINVAL;
        fprintf(stderr, "\nError: no valid config file");
        goto ERR_EXIT_DEFAULTS_JSON_VALUE;
    }

    if ((root_object = json_object(root_value)) == NULL)
    {
        local_errno = EINVAL;
        fprintf(stderr, "\nError: invalid json in config file");
        goto ERR_EXIT_JSON_VALUE;
    }

    if ((crt_path_str = json_object_get_string(root_object,
        "crt_path")) == NULL)
    {
        if ((crt_path_str = json_object_get_string(defaults_root_object,
            "crt_path")) == NULL)
        {
            local_errno = EINVAL;
            fprintf(stderr, "\nError: no crt_path specified"
                " in config file");
            goto ERR_EXIT_JSON_VALUE;
        }
    }

    if ((pk_path_str = json_object_get_string(root_object,
        "pk_path")) == NULL)
    {
        if ((pk_path_str = json_object_get_string(defaults_root_object,
            "pk_path")) == NULL)
        {
            local_errno = EINVAL;
            fprintf(stderr, "\nError: no pk_path specified"
                " in config file");
            goto ERR_EXIT_JSON_VALUE;
        }
    }

    crt_path_sz = strlen(crt_path_str);
    pk_path_sz = strlen(pk_path_str);

    if (crt_path_sz == max_path_strlen || pk_path_sz == max_fname_strlen)
    {
        local_errno = EINVAL;
        fprintf(stderr, "Error: %s path is too long",
            crt_path_sz == max_path_strlen ? "root" : "file");
        goto ERR_EXIT_JSON_VALUE;
    }

    if ((crt_path_buff = (char *)malloc(crt_path_sz + 1)) == NULL)
    {
        local_errno = errno;
        goto ERR_EXIT_JSON_VALUE;
    }

    if ((pk_path_buff = (char *)malloc(pk_path_sz + 1)) == NULL)
    {
        local_errno = errno;
        goto ERR_EXIT_MALLOC_CRT;
    }

    memcpy(crt_path_buff, crt_path_str, crt_path_sz + 1);
    memcpy(pk_path_buff, pk_path_str, pk_path_sz + 1);

    conf->crt_path = crt_path_buff;
    conf->pk_path = pk_path_buff;

    json_value_free(defaults_root_value);
    json_value_free(root_value);

    return 0;
    
ERR_EXIT_MALLOC_CRT:
    free(crt_path_buff);
ERR_EXIT_JSON_VALUE:
    json_value_free(root_value);
ERR_EXIT_DEFAULTS_JSON_VALUE:
    json_value_free(defaults_root_value);
ERR_EXIT:
    errno = local_errno;
    return -1;
}

int server_tls_config_free (server_tls_config_t *ctx)
{
    free((void *)ctx->pk_path);
    free((void *)ctx->crt_path);
    return 0;
}