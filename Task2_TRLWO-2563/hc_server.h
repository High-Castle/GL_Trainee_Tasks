#ifndef __HC_SERVER_H__
#define __HC_SERVER_H__

#include <unistd.h>

#include "hc_list.h"
#include "hc_event_handler.h"
#include "hc_clock.h"

enum
{
    HC_CLIENT_STATE_INITED,
    HC_CLIENT_STATE_INACTIVE,
    HC_CLIENT_STATE_ACTIVE,

    HC_CLIENT_TASK_CODE_SUCCESS,
    HC_CLIENT_TASK_CODE_ERROR,
    HC_CLIENT_TASK_CODE_ERROR_FATAL,

    HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_SUCCESS,
    HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_EPOLL_ERROR,
    HC_SUBSERVER_EVENT_HANDLER_EXIT_CODE_FATAL_ERROR,
};

typedef struct hc_server_t {
    hc_list_t subserver_list;
    hc_list_t inactive_clients;
    hc_list_t active_clients;
    size_t active_clients_count;
    hc_list_node *next_active_client_node; // end
    int epoll_fd;
} hc_server_t;
// create_subserver_* + hc_server_add_subserver etc

typedef struct hc_subserver_t {
    hc_event_handler_iface handler_base;
    hc_list_node node;
    hc_server_t *server_ref;
} hc_subserver_t;

typedef struct hc_subserver_ctable_t {
    hc_event_handler_ctable_t hc_event_handler_ctable;
} hc_subserver_ctable_t;

typedef struct hc_client_t {
    hc_event_handler_iface handler_base;
    hc_list_node node;
    hc_subserver_t *subserver_ref;
    hc_clock_t last_active_timestamp;
    hc_clock_t timeout_ms;
    int state;
} hc_client_t;

typedef struct hc_client_ctable_t {
    hc_event_handler_ctable_t hc_event_handler_ctable;
    int (*disconnect) (hc_client_t *);
    int (*execute_task) (hc_client_t *);
} hc_client_ctable_t;

typedef struct hc_server_module_t
{
    void *(*add_to)(hc_server_t *);
} hc_server_module_t;



static inline hc_subserver_t *hc_subserver_from_hc_event_handler_static_cast(
    hc_event_handler_iface *obj);
static inline hc_client_t *hc_client_from_hc_event_handler_static_cast(
    hc_event_handler_iface *obj);
static inline hc_client_t *hc_client_from_hc_list_node_shift(hc_list_node *obj);
static inline void hc_client_from_hc_list_node_mfree_thunk(hc_list_node *obj);
static inline hc_subserver_t *hc_subserver_from_hc_list_node_shift(hc_list_node *obj);
static inline void hc_subserver_from_hc_list_node_mfree_thunk(
    hc_list_node *obj);
static inline int hc_server_init(hc_server_t *obj, int epoll_fd);
static inline int hc_server_free(hc_server_t *obj);
static inline int hc_server_add_subserver(hc_server_t *obj,
    hc_subserver_t *subserv);
static inline int hc_subserver_init(hc_subserver_t *obj, hc_server_t *server);
static inline int hc_subserver_free(hc_subserver_t *obj);
static inline int hc_subserver_mfree_vcall (hc_subserver_t *obj);
static inline int hc_client_init (hc_client_t *obj, hc_subserver_t *subserv,
    hc_clock_t tm_default_inactive_out, int state);
static inline int hc_client_free (hc_client_t *obj);
static inline int hc_server_get_last_inactive_client_ka_time_remaining_ms(
    hc_server_t *obj);
static inline int hc_server_kick_experied_ka_clients(hc_server_t *obj);
static inline int hc_client_mfree_vcall(hc_client_t *obj);
static inline int hc_client_disconnect_vcall(hc_client_t *obj);
static inline int hc_client_execute_task_vcall(hc_client_t *obj);
static inline int hc_client_handle_event_vcall(hc_client_t *obj, void *arg);
static inline int hc_client_disconnect(hc_client_t *obj);
static inline int hc_client_state_inited_to_inactive_change(hc_client_t *obj);
static inline int hc_client_state_inactive_to_active_change(hc_client_t *obj);
static inline int hc_client_state_active_to_inactive_change(hc_client_t *obj);
static inline int hc_client_last_active_timestamp_update(hc_client_t *obj);





static hc_subserver_ctable_t hc_subserver_ctable = {
    {
        NULL,
        NULL
    }
};

static hc_client_ctable_t hc_client_ctable = {
    {
	NULL,
	NULL,
    },
    NULL,
    NULL
};


hc_subserver_t *hc_subserver_from_hc_event_handler_static_cast(
    hc_event_handler_iface *obj)
{
    return (hc_subserver_t *)((char *)obj
        - offsetof(hc_subserver_t, handler_base));
}

hc_client_t *hc_client_from_hc_event_handler_static_cast(
    hc_event_handler_iface *obj)
{
    return (hc_client_t *)((char *)obj
        - offsetof(hc_client_t, handler_base));
}

hc_client_t *hc_client_from_hc_list_node_shift(hc_list_node *obj)
{
    return (hc_client_t *)((char *)obj - offsetof(hc_client_t, node));
}

void hc_client_from_hc_list_node_mfree_thunk(hc_list_node *obj)
{
    hc_client_mfree_vcall(hc_client_from_hc_list_node_shift(obj));
}

hc_subserver_t *hc_subserver_from_hc_list_node_shift(hc_list_node *obj)
{
    return (hc_subserver_t *)((char *)obj
        - offsetof(hc_subserver_t, node));
}

void hc_subserver_from_hc_list_node_mfree_thunk(
    hc_list_node *obj)
{
    hc_subserver_mfree_vcall(hc_subserver_from_hc_list_node_shift(obj));
}

int hc_server_init(hc_server_t *obj, int epoll_fd)
{
    hc_list_init(&obj->subserver_list);
    hc_list_init(&obj->inactive_clients);
    hc_list_init(&obj->active_clients);
    obj->active_clients_count = 0;
    obj->epoll_fd = epoll_fd;
    return 0;
}

int hc_server_free(hc_server_t *obj)
{
    close(obj->epoll_fd);

    hc_list_for_each_node(hc_list_begin(&obj->inactive_clients),
        hc_list_end(&obj->inactive_clients),
        hc_client_from_hc_list_node_mfree_thunk);

    hc_list_for_each_node(hc_list_begin(&obj->active_clients),
        hc_list_end(&obj->active_clients),
        hc_client_from_hc_list_node_mfree_thunk);

    hc_list_for_each_node(hc_list_begin(&obj->subserver_list),
        hc_list_end(&obj->subserver_list),
        hc_subserver_from_hc_list_node_mfree_thunk);

    hc_list_init(&obj->active_clients);
    hc_list_init(&obj->inactive_clients);
    hc_list_init(&obj->subserver_list);
    return 0;
}

int hc_server_add_subserver(hc_server_t *obj,
    hc_subserver_t *subserv)
{
    hc_list_node_insert_before(hc_list_end(&obj->subserver_list),
	&subserv->node);
    return 0;
}

int hc_subserver_init(hc_subserver_t *obj, hc_server_t *server)
{
    obj->handler_base.ctable = &hc_subserver_ctable.hc_event_handler_ctable;
    obj->server_ref = server;
    return 0;
}

int hc_subserver_free (hc_subserver_t *obj)
{
    (void)(obj);
    return 0;
}

int hc_subserver_mfree_vcall (hc_subserver_t *obj)
{
    return hc_event_handler_mfree(&obj->handler_base);
}

int hc_client_init (hc_client_t *obj, hc_subserver_t *subserv,
    hc_clock_t tm_default_inactive_out, int state)
{
    obj->handler_base.ctable
        = &hc_client_ctable.hc_event_handler_ctable;

    obj->subserver_ref = subserv;
    obj->last_active_timestamp = hc_clock_ms();
    obj->timeout_ms = tm_default_inactive_out;
    obj->state = state;

    return 0;
}

int hc_client_free (hc_client_t *obj)
{
    (void)(obj);
    return 0;
}

int hc_server_get_last_inactive_client_ka_time_remaining_ms(
    hc_server_t *obj)
{
    hc_clock_t diff;
    hc_client_t *head;

    if (hc_list_empty(&obj->inactive_clients))
        return -1;

    head = hc_client_from_hc_list_node_shift(
        hc_list_begin(&obj->inactive_clients));

    diff = hc_clock_ms() - head->last_active_timestamp;

    if (diff > (unsigned int)head->timeout_ms)
        return 0;

    return head->timeout_ms - diff;
}

int hc_server_kick_experied_ka_clients(hc_server_t *obj)
{
    hc_clock_t now = hc_clock_ms();

    for (hc_list_node *it = hc_list_begin(&obj->inactive_clients),
        *to = hc_list_end(&obj->inactive_clients); it != to ;)
    {
        hc_list_node *curr = it;
        hc_client_t *client = hc_client_from_hc_list_node_shift(curr);

        it = hc_list_node_next(it);

        if (now - client->last_active_timestamp < client->timeout_ms)
            return 0;

        hc_client_disconnect_vcall(client);
    }
    return 0;
}

int hc_client_mfree_vcall(hc_client_t *obj)
{
    return hc_event_handler_mfree(&obj->handler_base);
}

int hc_client_disconnect_vcall(hc_client_t *obj)
{
    return ((hc_client_ctable_t*)obj->handler_base.ctable)
        ->disconnect(obj);
}

int hc_client_execute_task_vcall(hc_client_t *obj)
{
    return ((hc_client_ctable_t*)obj->handler_base.ctable)
	->execute_task(obj);
}

int hc_client_handle_event_vcall(hc_client_t *obj, void *arg)
{
   return obj->handler_base.ctable->handle_event(
      &obj->handler_base, arg);
}

int hc_client_disconnect(hc_client_t *obj)
{
    if (obj->subserver_ref->server_ref->next_active_client_node == &obj->node)
    {
        obj->subserver_ref->server_ref->next_active_client_node =
            hc_list_node_next(&obj->node);
    }

    hc_list_node_purge(&obj->node);
    return 0;
}


int hc_client_state_inited_to_inactive_change(hc_client_t *obj)
{
    assert(obj->state == HC_CLIENT_STATE_INITED);

    hc_list_node_insert_before(
        hc_list_end(&obj->subserver_ref->server_ref->inactive_clients), &obj->node);

    assert(!hc_list_empty(&obj->subserver_ref->server_ref->inactive_clients));

    obj->state = HC_CLIENT_STATE_INACTIVE;
    return 0;
}

int hc_client_state_inactive_to_active_change(hc_client_t *obj)
{
    hc_list_node_purge(&obj->node);

    hc_list_node_insert_before(
        hc_list_end(&obj->subserver_ref->server_ref->active_clients), &obj->node);

    ++ obj->subserver_ref->server_ref->active_clients_count;

    obj->state = HC_CLIENT_STATE_ACTIVE;
    return 0;
}

int hc_client_state_active_to_inactive_change(hc_client_t *obj)
{
    assert(obj->state == HC_CLIENT_STATE_ACTIVE);

    if (obj->subserver_ref->server_ref
        ->next_active_client_node == &obj->node)
    {
        obj->subserver_ref->server_ref->next_active_client_node
            = hc_list_node_next(&obj->node);
    }

    hc_list_node_purge(&obj->node);

    assert(obj->subserver_ref->server_ref->active_clients_count);

    -- obj->subserver_ref->server_ref->active_clients_count;

    hc_list_node_insert_before(
        hc_list_end(&obj->subserver_ref
	  ->server_ref->inactive_clients), &obj->node);

    obj->state = HC_CLIENT_STATE_INACTIVE;
    return 0;
}

int hc_client_last_active_timestamp_update(hc_client_t *obj)
{
    obj->last_active_timestamp = hc_clock_ms();
    return 0;
}

#endif
