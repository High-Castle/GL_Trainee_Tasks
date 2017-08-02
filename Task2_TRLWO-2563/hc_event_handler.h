#ifndef __HC_EVENT_HANDLER_H__
#define __HC_EVENT_HANDLER_H__

typedef struct hc_event_handler_t {
    struct hc_event_handler_call_table const *table_;
} hc_event_handler_t;

typedef struct hc_event_handler_call_table {
    int(* handle_mfree)(void *);
    int(* handle_event)(hc_event_handler_t *, void *);
} hc_event_handler_call_table;

static inline int hc_event_handler_mfree(hc_event_handler_t *arg)
{
    return arg->table_->handle_mfree(arg);
}

static inline int hc_event_handler_handle_event(hc_event_handler_t *arg,
    void *arg_ev)
{
    return arg->table_->handle_event(arg, arg_ev);
}

#endif
