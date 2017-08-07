#include <stdio.h>

#include "server_config.h"

int main (void)
{
    server_config_t serv_conf;
    
    if (server_config_json_init(&serv_conf, "test_config.json", 
        "defaults_config.json", FILENAME_MAX, FILENAME_MAX))
    {
        perror("\nError");
        return -1;
    }
    
    printf("root: %s\nfile: %s\nuse ssl: %s\n", serv_conf.root_path, 
           serv_conf.file_name, (serv_conf.use_ssl ? "true" : "false"));
    
    server_config_free(&serv_conf);
    return 0;
}