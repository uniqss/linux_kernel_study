/* SPDX-License-Identifier: GPL-2.0 */

#include <stdbool.h>

// printf
#include <stdio.h>

// offsetof/NULL
#include <stddef.h>

// static_assert
#include <assert.h>

// free
#include <stdlib.h>



#define __scalar_type_to_expr_cases(type) unsigned type : (unsigned type)0, signed type : (signed type)0

#define __unqual_scalar_typeof(x)                                                                                                           \
    __typeof__(_Generic((x), char                                                                                                           \
                        : (char)0, __scalar_type_to_expr_cases(char), __scalar_type_to_expr_cases(short), __scalar_type_to_expr_cases(int), \
                          __scalar_type_to_expr_cases(long), __scalar_type_to_expr_cases(long long), default                                \
                        : (x)))

#define POISON_POINTER_DELTA 0
#define LIST_POISON1 ((void *)0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2 ((void *)0x122 + POISON_POINTER_DELTA)

#define __WRITE_ONCE(x, val)                     \
    do {                                         \
        *(volatile __typeof__(x) *)&(x) = (val); \
    } while (0)
#define WRITE_ONCE(x, val)    \
    do {                      \
        __WRITE_ONCE(x, val); \
    } while (0)

#define __native_word(t) (sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))

#ifdef __OPTIMIZE__
#define __compiletime_assert(condition, msg, prefix, suffix)                  \
    do {                                                                      \
        /*                                                                    \
         * __noreturn is needed to give the compiler enough                   \
         * information to avoid certain possibly-uninitialized                \
         * warnings (regardless of the build failing).                        \
         */                                                                   \
        __noreturn extern void prefix##suffix(void) __compiletime_error(msg); \
        if (!(condition)) prefix##suffix();                                   \
    } while (0)
#else
#define __compiletime_assert(condition, msg, prefix, suffix) \
    do {                                                     \
    } while (0)
#endif

#define _compiletime_assert(condition, msg, prefix, suffix) __compiletime_assert(condition, msg, prefix, suffix)

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#define compiletime_assert(condition, msg) _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
#define compiletime_assert_rwonce_type(t) compiletime_assert(__native_word(t) || sizeof(t) == sizeof(long long), "Unsupported access size for {READ,WRITE}_ONCE().")

#ifndef __READ_ONCE
#define __READ_ONCE(x) (*(const volatile __unqual_scalar_typeof(x) *)&(x))
#endif

#define READ_ONCE(x)                       \
    ({                                     \
        compiletime_assert_rwonce_type(x); \
        __READ_ONCE(x);                    \
    })

#define __same_type(a, b) __builtin_types_compatible_p(__typeof__(a), __typeof__(b))

#define container_of(ptr, type, member)                                                                                                  \
    ({                                                                                                                                   \
        void *__mptr = (void *)(ptr);                                                                                                    \
        static_assert(__same_type(*(ptr), ((type *)0)->member) || __same_type(*(ptr), void), "pointer type mismatch in container_of()"); \
        ((type *)(__mptr - offsetof(type, member)));                                                                                     \
    })



struct hlist_head {
    struct hlist_node *first;
};

struct hlist_node {
    struct hlist_node *next, **pprev;
};

#define HLIST_HEAD_INIT \
    { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {.first = NULL}
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void INIT_HLIST_NODE(struct hlist_node *h) {
    h->next = NULL;
    h->pprev = NULL;
}
static inline int hlist_unhashed(const struct hlist_node *h) {
    return !h->pprev;
}

static inline int hlist_unhashed_lockless(const struct hlist_node *h) {
    return !READ_ONCE(h->pprev);
}

static inline int hlist_empty(const struct hlist_head *h) {
    return !READ_ONCE(h->first);
}

static inline void __hlist_del(struct hlist_node *n) {
    struct hlist_node *next = n->next;
    struct hlist_node **pprev = n->pprev;

    WRITE_ONCE(*pprev, next);
    if (next) WRITE_ONCE(next->pprev, pprev);
}

static inline void hlist_del(struct hlist_node *n) {
    __hlist_del(n);
    n->next = LIST_POISON1;
    n->pprev = LIST_POISON2;
}

static inline void hlist_del_init(struct hlist_node *n) {
    if (!hlist_unhashed(n)) {
        __hlist_del(n);
        INIT_HLIST_NODE(n);
    }
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h) {
    struct hlist_node *first = h->first;
    WRITE_ONCE(n->next, first);
    if (first) WRITE_ONCE(first->pprev, &n->next);
    WRITE_ONCE(h->first, n);
    WRITE_ONCE(n->pprev, &h->first);
}
static inline void hlist_add_before(struct hlist_node *n, struct hlist_node *next) {
    WRITE_ONCE(n->pprev, next->pprev);
    WRITE_ONCE(n->next, next);
    WRITE_ONCE(next->pprev, &n->next);
    WRITE_ONCE(*(n->pprev), n);
}
static inline void hlist_add_behind(struct hlist_node *n, struct hlist_node *prev) {
    WRITE_ONCE(n->next, prev->next);
    WRITE_ONCE(prev->next, n);
    WRITE_ONCE(n->pprev, &prev->next);

    if (n->next) WRITE_ONCE(n->next->pprev, &n->next);
}
static inline void hlist_add_fake(struct hlist_node *n) {
    n->pprev = &n->next;
}
static inline bool hlist_fake(struct hlist_node *h) {
    return h->pprev == &h->next;
}
static inline bool hlist_is_singular_node(struct hlist_node *n, struct hlist_head *h) {
    return !n->next && n->pprev == &h->first;
}
static inline void hlist_move_list(struct hlist_head *old, struct hlist_head *new) {
    new->first = old->first;
    if (new->first) new->first->pprev = &new->first;
    old->first = NULL;
}

#define hlist_entry(ptr, type, member) container_of(ptr, type, member)

#define hlist_for_each(pos, head) for (pos = (head)->first; pos; pos = pos->next)

#define hlist_for_each_safe(pos, n, head)        \
    for (pos = (head)->first; pos && ({          \
                                  n = pos->next; \
                                  1;             \
                              });                \
         pos = n)

#define hlist_entry_safe(ptr, type, member)                  \
    ({                                                       \
        __typeof__(ptr) ____ptr = (ptr);                     \
        ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
    })

#define hlist_for_each_entry_safe(pos, n, head, member)                                             \
    for (pos = hlist_entry_safe((head)->first, __typeof__(*pos), member); pos && ({                 \
                                                                              n = pos->member.next; \
                                                                              1;                    \
                                                                          });                       \
         pos = hlist_entry_safe(n, __typeof__(*pos), member))

static inline void hash_del(struct hlist_node *node) {
    hlist_del_init(node);
}



struct i40e_cloud_filter {
    struct hlist_node cloud_node;
    unsigned long cookie;
};

/* struct that defines the Ethernet device */
struct i40e_pf {
    struct pci_dev *pdev;
    struct msix_entry *msix_entries;
    int iwarp_base_vector;
    int queues_left; /* queues left unclaimed */

    struct hlist_head fdir_filter_list;
    unsigned long fd_flush_timestamp;

    struct hlist_head cloud_filter_list;
};

int main() {
    struct i40e_pf opf1;
    struct i40e_pf *pf = &opf1;

    INIT_HLIST_HEAD(&pf->cloud_filter_list);

    for (int i = 1; i < 5; ++i) {
        struct i40e_cloud_filter *filter = malloc(sizeof(struct i40e_cloud_filter));
        INIT_HLIST_NODE(&filter->cloud_node);
        filter->cookie = i;
        hlist_add_head(&filter->cloud_node, &pf->cloud_filter_list);
    }


    struct i40e_cloud_filter *cfilter;
    struct hlist_node *node;

    hlist_for_each_entry_safe(cfilter, node, &pf->cloud_filter_list, cloud_node) { printf("%lu\n", cfilter->cookie); }

    hlist_for_each_entry_safe(cfilter, node, &pf->cloud_filter_list, cloud_node) {
        if (cfilter->cookie < 2 || cfilter->cookie > 5) continue;

        hash_del(&cfilter->cloud_node);
        free(cfilter);
    }

    hlist_for_each_entry_safe(cfilter, node, &pf->cloud_filter_list, cloud_node) { printf("%lu\n", cfilter->cookie); }

    hlist_for_each_entry_safe(cfilter, node, &pf->cloud_filter_list, cloud_node) {
        hash_del(&cfilter->cloud_node);
        free(cfilter);
    }

    hlist_for_each_entry_safe(cfilter, node, &pf->cloud_filter_list, cloud_node) { printf("%lu\n", cfilter->cookie); }

    return 0;
}

/*
gcc -g -Wall -std=c11 hashtable_test_simplelist.c
*/

/*
只是一个比单链表优化一点能在任何节点直接访问头指针的封装
*/
