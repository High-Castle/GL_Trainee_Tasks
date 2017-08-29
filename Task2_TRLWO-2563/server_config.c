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
#include "hc_string.h"
#include "server_config.h"

static int server_log_str_to_enum(const char *log_str)
{
    static struct {
        const char *str;
        int enum_val;
    } log_str_to_enum [] = {
            {"INFO", SERVER_LOG_INFO},
            {"TRACE", SERVER_LOG_TRACE},
            {"FATAL", SERVER_LOG_FATAL},
            {"ACCESS", SERVER_LOG_ACCESS}
        };

    for (size_t idx = 0; idx != sizeof(log_str_to_enum)
        /sizeof(*log_str_to_enum); ++idx)
    {
        if (hc_streq_ic(log_str, strlen(log_str),
            log_str_to_enum[idx].str, strlen(log_str_to_enum[idx].str)))
        {
            return log_str_to_enum[idx].enum_val;
        }
    }

    return SERVER_LOG_ENUM_END;
}

int server_config_move_init (server_config_t *to, server_config_t* from)
{
    *to = *from;
    from->logging_out = NULL;
    from->logging_mask = NULL;
    from->root_path = NULL;
    from->file_name = NULL;
    return 0;
}

int server_config_json_init(server_config_t *conf, const char *fname,
    const char* defaults_fname, size_t max_path_strlen, size_t max_fname_strlen)
{
    int local_errno = 0;
    char const *root_path_str, *file_path_str, *address_str, *port_str;
    char *root_path_buff;
    char *file_name_buff;
    const char *access_out_filename;
    uintmax_t port_no;
    size_t root_path_sz, file_path_sz;
    char *end_of_str;
    JSON_Object *root_object, *defaults_root_object;
    JSON_Value *root_value, *defaults_root_value;
    JSON_Array *logging_arr;
	
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

    if ((logging_arr = json_object_get_array(root_object,
        "logging")) == NULL)
    {
        if ((logging_arr = json_object_get_array(defaults_root_object,
            "logging")) == NULL)
        {
            local_errno = EINVAL;
            fprintf(stderr, "\nError: no logging level specified");
            goto ERR_EXIT_JSON_VALUE;
        }
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

    if (!(conf->logging_mask = (unsigned char *)calloc(SERVER_LOG_ENUM_END,
        sizeof(*conf->logging_mask))))
    {
        local_errno = errno;
        goto ERR_EXIT_JSON_VALUE;
    }

    for (size_t idx = 0; idx != json_array_get_count(logging_arr); ++idx)
    {
        const char *logging_str_ref;
        int logging_enum;

        if (!(logging_str_ref = json_array_get_string(logging_arr, idx)))
        {
            fprintf(stderr, "\nError: something gone wrong while getting string"
                            " from logging array");
            goto ERR_EXIT_CALLOC_LOGGING_MASK;
        }

        logging_enum = server_log_str_to_enum(logging_str_ref);

        if (logging_enum == SERVER_LOG_ENUM_END)
        {
            fprintf(stderr, "\nError: bad logging specified");
            goto ERR_EXIT_CALLOC_LOGGING_MASK;
        }

        conf->logging_mask[logging_enum] = 1;
    }
    
	conf->logging_out = stdout; 
	
	if ((access_out_filename = json_object_get_string(root_object, 
		"logging_out")))
	{
		if (!(conf->logging_out = fopen(access_out_filename, "wb")))
		{
			local_errno = errno;
			fprintf(stderr, "\nError: no interface address to bind specified");
			goto ERR_EXIT_CALLOC_LOGGING_MASK;
		}
	}

    root_path_sz = strlen(root_path_str);
    file_path_sz = strlen(file_path_str);

    if (root_path_sz == max_path_strlen || file_path_sz == max_fname_strlen)
    {
        local_errno = EINVAL;
        fprintf(stderr, "Error: %s path is too long",
            root_path_sz == max_path_strlen ? "root" : "file");
        goto ERR_EXIT_LOG_FILE;
    }

    if ((root_path_buff = (char *)malloc(root_path_sz + 1)) == NULL)
    {
        local_errno = errno;
        goto ERR_EXIT_LOG_FILE;
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
ERR_EXIT_LOG_FILE:
	fclose(conf->logging_out);
ERR_EXIT_CALLOC_LOGGING_MASK:
    free(conf->logging_mask);
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
	if (ctx->logging_out && ctx->logging_out != stdout)
		fclose(ctx->logging_out);
	
	free((void *)ctx->file_name);
    free((void *)ctx->root_path);
    free(ctx->logging_mask);
    return 0;
}
