#ifndef __HC_LIST_H__
#define __HC_LIST_H__

#include <stddef.h>
#include <assert.h>

typedef struct hc_list_node {
    struct hc_list_node *next;
    struct hc_list_node *prev;
} hc_list_node;

typedef struct hc_list_t {
    hc_list_node sentinel;
} hc_list_t ;

static inline void hc_list_init(hc_list_t *list);
static inline void hc_list_for_each_node(hc_list_node *from, hc_list_node *to,
    void(*func)(hc_list_node*));

static inline hc_list_node *hc_list_node_next(hc_list_node *n);
static inline hc_list_node *hc_list_node_prev(hc_list_node *n);
static inline hc_list_node *hc_list_begin(hc_list_t *l);
static inline hc_list_node *hc_list_end(hc_list_t *l);

static inline void hc_list_init(hc_list_t *list)
{
    list->sentinel.next = &list->sentinel;
    list->sentinel.prev = &list->sentinel;
}

static inline int hc_list_empty(hc_list_t *l)
{
    if ((void *)l == (void *)(l->sentinel.next))
    {
        assert((void *)l == (void *)(l->sentinel.prev));
        return 1;
    }
    assert((void *)l != (void *)(l->sentinel.prev));
    return 0;
}

static inline void hc_list_destroy(hc_list_t *list)
{
    (void)(list);
}


static inline void hc_list_move_init(hc_list_t *list, hc_list_t *from)
{
    assert(hc_list_empty(list));

    if (hc_list_empty(from))
    {
        hc_list_init(list);
        return ;
    }

    list->sentinel.next = from->sentinel.next;
    list->sentinel.next->prev = &list->sentinel;

    list->sentinel.prev = from->sentinel.prev;
    list->sentinel.prev->next = &list->sentinel;

    from->sentinel.next = &from->sentinel;
    from->sentinel.prev = &from->sentinel;
}


static inline void hc_list_for_each_node (hc_list_node *from, hc_list_node *to,
    void(*func)(hc_list_node*))
{
    while (from != to)
    {
        hc_list_node *current = from;
        from = hc_list_node_next(current);
        func(current);
    }
}

static inline void hc_list_for_each_immutable_node (hc_list_node *from,
    hc_list_node *to, void (*func)(hc_list_node*))
{
    for (; from != to; from = hc_list_node_next(from))
        func(from);
}

static inline hc_list_node *hc_list_node_next (hc_list_node *n)
{
    return n->next;
}

static inline hc_list_node *hc_list_node_prev (hc_list_node *n)
{
    return n->prev;
}

static inline hc_list_node * hc_list_node_next_at (hc_list_node *n, size_t idx)
{
    for (; idx; --idx)
        n = hc_list_node_next(n);

    return n;
}

static inline hc_list_node * hc_list_node_prev_at (hc_list_node *n,
    size_t idx)
{
    for (; idx; --idx)
        n = hc_list_node_prev(n);

    return n;
}

static inline void hc_list_node_insert_before (hc_list_node *pos,
    hc_list_node *node)
{
    pos->prev->next = node;
    node->prev = pos->prev;
    pos->prev = node;
    node->next = pos;
}

static inline void hc_list_node_purge (hc_list_node *it)
{
    hc_list_node *next_node = hc_list_node_next(it);
    next_node->prev = it->prev;
    it->prev->next = next_node;
}

static inline hc_list_node * hc_list_begin (hc_list_t *l)
{
    return l->sentinel.next;
}

static inline hc_list_node * hc_list_end (hc_list_t *l)
{
    return &l->sentinel;
}

#endif