#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "utilities/parson/parson.h"

#include "hc_address.h"
#include "server_config.h"

int server_config_json_init(server_config_t *conf, const char *fname,
    const char* defaults_fname, size_t max_path_strlen, size_t max_fname_strlen)
{
    int local_errno;
    char const *root_path_str, *file_path_str, *address_str, *port_str,
        *logging_lev_str;
    char *root_path_buff;
    char *file_name_buff;
    uintmax_t port_no, logging_lev_no;
    size_t root_path_sz, file_path_sz;
    char *end_of_str;
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

    if ((conf->use_ssl = json_object_get_boolean(root_object,
        "use_ssl")) == -1)
    {
        if ((conf->use_ssl = json_object_get_boolean(defaults_root_object,
            "use_ssl")) == -1)
        {
            local_errno = EINVAL;
            fprintf(stderr, "\nError: no ssl usage specified");
            goto ERR_EXIT_JSON_VALUE;
        }
    }

    if ((logging_lev_str = json_object_get_string(root_object,
        "logging")) == NULL)
    {
        if ((logging_lev_str = json_object_get_string(defaults_root_object,
            "logging")) == NULL)
        {
            local_errno = EINVAL;
            fprintf(stderr, "\nError: no logging level specified");
            goto ERR_EXIT_JSON_VALUE;
        }
    }

    if ((address_str = json_object_get_string(root_object, "address")) == NULL)
        if ((address_str = json_object_get_string(defaults_root_object,
            "address")) == NULL)
        {
            local_errno = EINVAL;
            fprintf(stderr, "\nError: no interface address to bind specified");
            goto ERR_EXIT_JSON_VALUE;
        }

    if ((port_str = json_object_get_string(root_object, "port")) == NULL)
        if ((port_str = json_object_get_string(defaults_root_object,
            "port")) == NULL)
        {
            local_errno = EINVAL;
            fprintf(stderr, "\nError: no root directory"
                " specified in config file");
            goto ERR_EXIT_JSON_VALUE;
        }

    if ((root_path_str = json_object_get_string(root_object,
        "root_path")) == NULL)
    {
        if ((root_path_str = json_object_get_string(defaults_root_object,
            "root_path")) == NULL)
        {
            local_errno = EINVAL;
            fprintf(stderr, "\nError: no root directory specified"
                " in config file");
            goto ERR_EXIT_JSON_VALUE;
        }
    }

    if ((file_path_str = json_object_get_string(root_object,
        "file_name")) == NULL)
    {
        if ((file_path_str = json_object_get_string(defaults_root_object,
            "file_name")) == NULL)
        {
            local_errno = EINVAL;
            fprintf(stderr, "\nError: no root directory specified"
                " in config file");
            goto ERR_EXIT_JSON_VALUE;
        }
    }

    //TODO: replace strtoumax (it does parse 123tred as 123)
    logging_lev_no = strtoumax(logging_lev_str, &end_of_str, 10);

    if (logging_lev_no == 0 && end_of_str == logging_lev_str)
    {
        local_errno = errno;
        fprintf(stderr, "\nError: bad logging level specified "
            "inside config file");
        goto ERR_EXIT_JSON_VALUE;
    }

    if (!isdigit(*logging_lev_str) || end_of_str
        - logging_lev_str != (ptrdiff_t)strlen(logging_lev_str))
    {
        local_errno = EINVAL;
        fprintf(stderr, "\nError: bad logging level specified inside config "
            "file, invalid number");
        goto ERR_EXIT_JSON_VALUE;
    }

    if (logging_lev_no >= HC_LOGGING_ENUM_END)
    {
        local_errno = EINVAL;
        fprintf(stderr, "\nError: bad logging level specified inside config "
            "file, too large number");
        goto ERR_EXIT_JSON_VALUE;
    }

    conf->logging_lev = (logging_level_t)logging_lev_no;

    port_no = strtoumax(port_str, &end_of_str, 10);

    if (port_no == 0 && end_of_str == port_str)
    {
        local_errno = errno;
        fprintf(stderr, "\nError: bad port specified inside config file");
        goto ERR_EXIT_JSON_VALUE;
    }

    if (!isdigit(*port_str) || end_of_str
        - port_str != (ptrdiff_t)strlen(port_str))
    {
        local_errno = EINVAL;
        fprintf(stderr, "\nError: bad port specified inside config "
            "file, invalid number");
        goto ERR_EXIT_JSON_VALUE;
    }

    if (port_no > USHRT_MAX)
    {
        local_errno = EINVAL;
        fprintf(stderr, "\nError: bad port specified inside config file,"
            " too large number");
        goto ERR_EXIT_JSON_VALUE;
    }

    if (hc_set_address(address_str, (unsigned short)port_no,
        (struct sockaddr *)&conf->address))
    {
        local_errno = errno;
        fprintf(stderr, "\nError: invalid address specified");
        goto ERR_EXIT_JSON_VALUE;
    }

    root_path_sz = strlen(root_path_str);
    file_path_sz = strlen(file_path_str);

    if (root_path_sz == max_path_strlen || file_path_sz == max_fname_strlen)
    {
        local_errno = EINVAL;
        fprintf(stderr, "Error: %s path is too long",
            root_path_sz == max_path_strlen ? "root" : "file");
        goto ERR_EXIT_JSON_VALUE;
    }

    if ((root_path_buff = (char *)malloc(root_path_sz + 1)) == NULL)
    {
        local_errno = errno;
        goto ERR_EXIT_JSON_VALUE;
    }

    if ((file_name_buff = (char *)malloc(file_path_sz + 1)) == NULL)
    {
        local_errno = errno;
        goto ERR_EXIT_MALLOC_ROOT;
    }

    memcpy(root_path_buff, root_path_str, root_path_sz + 1);
    memcpy(file_name_buff, file_path_str, file_path_sz + 1);

    conf->root_path = root_path_buff;
    conf->file_name = file_name_buff;

    json_value_free(defaults_root_value);
    json_value_free(root_value);

    return 0;

ERR_EXIT_MALLOC_ROOT:
    free(root_path_buff);
ERR_EXIT_JSON_VALUE:
    json_value_free(root_value);
ERR_EXIT_DEFAULTS_JSON_VALUE:
    json_value_free(defaults_root_value);
ERR_EXIT:
    errno = local_errno;
    return -1;
}

int server_config_free (server_config_t *ctx)
{
    free((void *)ctx->file_name);
    free((void *)ctx->root_path);
    return 0;
}
