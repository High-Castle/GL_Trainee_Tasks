// 18:29
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

#include <dlfcn.h>
#include <fcntl.h>

#include "hc_list.h"
#include "hc_event_handler.h"
#include "hc_server.h"

#define SERVER_MAX_EPOLL_EVENT_N 1

// TODO: add support for multiple pipe readers
// TODO: to inactive change on write EWOULDBLOCK (and wait for EPOLLOUT)

static volatile int int_sig_occured;

void handle_server_intsig (int sig)
{
    fprintf(stderr, "\nserver was interrupted with signal %d;", sig);
    int_sig_occured = 1;
}

typedef struct so_node
{
    hc_list_node node;
    void *handle;
} so_node;

static
void so_node_mfree(hc_list_node *obj)
{
    so_node *lib_handle_node = (so_node *)((char *)obj
        - offsetof(so_node, node));

    hc_list_node_purge(obj);

    dlclose(lib_handle_node->handle);

    free(lib_handle_node);
}


static ssize_t
handle_events(hc_server_t *server, struct epoll_event *triggered_events_buff,
    size_t ev_numm, int timeout)
{
    ssize_t triggered_num;

    triggered_num = epoll_wait(server->epoll_fd, triggered_events_buff,
        ev_numm, timeout);

    if (triggered_num == -1)
        return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_EPOLL_ERROR;

    for (int idx = 0; idx < triggered_num; ++idx)
    {
        int err = hc_event_handler_handle_event(
            triggered_events_buff[idx].data.ptr,
            &triggered_events_buff[idx].events);

        if (err != HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS)
            return err;
    }

    return HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS;
}


int main(int arg_n, char *args[])
{
    struct epoll_event *triggered_events_buff;
    hc_server_t server;
    hc_list_t loaded_so_list;
    int timeout_head_exp;
    int epoll_instance_fd, handle_events_error;

    int local_errno = 0;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR
        || signal(SIGINT, handle_server_intsig) == SIG_ERR)
    {
        fprintf(stderr, "\nError while setting signal handler");
        local_errno = EINVAL;
        goto ERR_EXIT;
    }

    triggered_events_buff = (struct epoll_event *)
        malloc(SERVER_MAX_EPOLL_EVENT_N * sizeof(struct epoll_event));

    if (!triggered_events_buff)
    {
        local_errno = errno;
        goto ERR_EXIT;
    }

    if ((epoll_instance_fd = epoll_create1(0)) == -1)
    {
        local_errno = errno;
        goto ERR_EXIT_EPOLL_BUFF;
    }

    hc_list_init(&loaded_so_list);

    if (hc_server_init(&server, epoll_instance_fd))
    {
        local_errno = errno;
        goto ERR_EXIT_LOADED_SO_LIST;
    }

    epoll_instance_fd = -1;

    for (size_t idx = 1; idx != (unsigned int)arg_n; ++idx)
    {
        so_node *node;
        hc_server_module_t *instance;

        if (!(node = (so_node *)malloc(sizeof(so_node))))
             goto ERR_EXIT_SERVER;

        if (!(node->handle = dlopen(args[idx], RTLD_NOW)))
        {
            fprintf(stderr, "\n\n%s\n\n", dlerror());
            free(node);
            goto ERR_EXIT_SERVER;
        }

        hc_list_node_insert_before(hc_list_node_next(
            hc_list_begin(&loaded_so_list)),
            &node->node);

        if (!(instance = (hc_server_module_t *) dlsym(node->handle,
	    "hc_server_module_instance")))
        {
            goto ERR_EXIT_SERVER;
        }

        if (!instance->add_to(&server))
            goto ERR_EXIT_SERVER;
    }

    while (!int_sig_occured)
    {
        timeout_head_exp
            = hc_server_get_last_inactive_client_ka_time_remaining_ms(&server);

        handle_events_error = handle_events(&server,
            triggered_events_buff, SERVER_MAX_EPOLL_EVENT_N, timeout_head_exp);

        if (handle_events_error != HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS)
        {
            if (handle_events_error
                    == HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_EPOLL_ERROR
                && errno == EINTR)
            {
                goto EXIT_REGULAR;
            }

            local_errno = errno;
            goto ERR_EXIT_SERVER;
        }

        hc_server_kick_experied_ka_clients(&server);

        while (!hc_list_empty(&server.active_clients))
        {
	    server.next_active_client_node =
		hc_list_begin(&server.active_clients);

            for (; server.next_active_client_node
		  != hc_list_end(&server.active_clients) ;)
            {
                hc_list_node *curr = server.next_active_client_node;

                server.next_active_client_node = hc_list_node_next(curr);

                if (int_sig_occured)
		    goto EXIT_REGULAR;

                switch (hc_client_execute_task_vcall(
                    hc_client_from_hc_list_node_shift(curr)))
                {
		    case HC_CLIENT_TASK_CODE_SUCCESS:
		    case HC_CLIENT_TASK_CODE_ERROR:
			break;
		    case HC_CLIENT_TASK_CODE_ERROR_FATAL:
			local_errno = errno;
			goto ERR_EXIT_SERVER;
		    default:
			assert(!"Bad return code from client task");
		}

                handle_events_error = handle_events(&server,
                    triggered_events_buff, SERVER_MAX_EPOLL_EVENT_N, 0);

                if (handle_events_error
                    != HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS)
                {
                    if (handle_events_error
                        == HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_EPOLL_ERROR
                        && errno == EINTR)
                    {
                        goto EXIT_REGULAR;
                    }

                    local_errno = errno;
                    goto ERR_EXIT_SERVER;
                }

                hc_server_kick_experied_ka_clients(&server);
            }
        }
    }

EXIT_REGULAR:

    fprintf(stderr, "\nfreeing...");

    hc_server_free(&server);

    hc_list_for_each_node(hc_list_begin(&loaded_so_list),
        hc_list_end(&loaded_so_list),
        so_node_mfree);

    hc_list_destroy(&loaded_so_list);

    free(triggered_events_buff);

    fprintf(stderr, "\n\t...done");

    return 0;

ERR_EXIT_SERVER:
    hc_server_free(&server);

ERR_EXIT_LOADED_SO_LIST:
    hc_list_for_each_node(hc_list_begin(&loaded_so_list),
        hc_list_end(&loaded_so_list),
        so_node_mfree);

    hc_list_destroy(&loaded_so_list);
    close(epoll_instance_fd);

ERR_EXIT_EPOLL_BUFF:
    free(triggered_events_buff);

ERR_EXIT:
    fprintf(stderr, "\nException : %s", strerror(local_errno));
    return -1;
}
