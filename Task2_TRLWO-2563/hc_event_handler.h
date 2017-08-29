#ifndef __HC_EVENT_HANDLER_H__
#define __HC_EVENT_HANDLER_H__

typedef struct hc_event_handler_iface {
    struct hc_event_handler_ctable_t const *ctable;
} hc_event_handler_iface;

typedef struct hc_event_handler_ctable_t {
    int(* handle_mfree)(hc_event_handler_iface *);
    int(* handle_event)(hc_event_handler_iface *, void *);
} hc_event_handler_ctable_t;

inline static int hc_event_handler_mfree(hc_event_handler_iface *obj)
{
    return obj->ctable->handle_mfree(obj);
}

inline static int hc_event_handler_handle_event(hc_event_handler_iface *obj,
    void *arg_ev)
{
    return obj->ctable->handle_event(obj, arg_ev);
}

#endif
