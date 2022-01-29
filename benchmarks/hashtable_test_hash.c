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

#ifndef typeof
#define typeof __typeof__
#endif



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

#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

#define __hash_32 __hash_32_generic
static inline unsigned __hash_32_generic(unsigned val) {
    return val * GOLDEN_RATIO_32;
}
static inline unsigned hash_32(unsigned val, unsigned int bits) {
    /* High bits are more random, so use them. */
    return __hash_32(val) >> (32 - bits);
}
#define hash_64 hash_64_generic

static __always_inline unsigned hash_64_generic(unsigned long long val, unsigned int bits) {
    /* 64x64-bit multiply is efficient on all 64-bit processors */
    return val * GOLDEN_RATIO_64 >> (64 - bits);
}

#define hash_long(val, bits) hash_64(val, bits)



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

#define DEFINE_HASHTABLE(name, bits) struct hlist_head name[1 << (bits)] = {[0 ...((1 << (bits)) - 1)] = HLIST_HEAD_INIT}

#define DEFINE_READ_MOSTLY_HASHTABLE(name, bits) struct hlist_head name[1 << (bits)] __read_mostly = {[0 ...((1 << (bits)) - 1)] = HLIST_HEAD_INIT}

#define DECLARE_HASHTABLE(name, bits) struct hlist_head name[1 << (bits)]

#define HASH_SIZE(name) (ARRAY_SIZE(name))
#define HASH_BITS(name) ilog2(HASH_SIZE(name))

#define hash_min(val, bits) (sizeof(val) <= 4 ? hash_32(val, bits) : hash_long(val, bits))



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
        typeof(ptr) ____ptr = (ptr);                         \
        ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
    })

#define hlist_for_each_entry(pos, head, member) \
    for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member); pos; pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

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



#define hash_for_each(name, bkt, obj, member) \
    for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name); (bkt)++) hlist_for_each_entry(obj, &name[bkt], member)

#define hash_for_each_rcu(name, bkt, obj, member) \
    for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name); (bkt)++) hlist_for_each_entry_rcu(obj, &name[bkt], member)

#define hash_for_each_safe(name, bkt, tmp, obj, member) \
    for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name); (bkt)++) hlist_for_each_entry_safe(obj, tmp, &name[bkt], member)

#define hash_for_each_possible(name, obj, member, key) hlist_for_each_entry(obj, &name[hash_min(key, HASH_BITS(name))], member)

#define hash_add(hashtable, node, key) hlist_add_head(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])


struct kvm_svm {
    unsigned avic_vm_id;

    /* Struct members for AVIC */
    struct page *avic_logical_id_table_page;
    struct page *avic_physical_id_table_page;
    struct hlist_node hnode;
};

#define AVIC_VCPU_ID_BITS 8
#define AVIC_VCPU_ID_MASK ((1 << AVIC_VCPU_ID_BITS) - 1)

#define AVIC_VM_ID_BITS 24
#define AVIC_VM_ID_NR (1 << AVIC_VM_ID_BITS)
#define AVIC_VM_ID_MASK ((1 << AVIC_VM_ID_BITS) - 1)

#define AVIC_GATAG(x, y) (((x & AVIC_VM_ID_MASK) << AVIC_VCPU_ID_BITS) | (y & AVIC_VCPU_ID_MASK))
#define AVIC_GATAG_TO_VMID(x) ((x >> AVIC_VCPU_ID_BITS) & AVIC_VM_ID_MASK)
#define AVIC_GATAG_TO_VCPUID(x) (x & AVIC_VCPU_ID_MASK)

#define SVM_VM_DATA_HASH_BITS 8
static DEFINE_HASHTABLE(svm_vm_data_hash, SVM_VM_DATA_HASH_BITS);

int main() {
    struct kvm_svm *kvm_svm;
    unsigned ga_tag = 1234;
    unsigned vm_id = AVIC_GATAG_TO_VMID(ga_tag);
    bool empty = false;

    for (int i = 0; i < 5; ++i) {
        struct kvm_svm *newnode = malloc(sizeof(struct kvm_svm));
        newnode->avic_vm_id = AVIC_GATAG_TO_VMID(i);
        hash_add(svm_vm_data_hash, &newnode->hnode, kvm_svm->avic_vm_id);
    }

    vm_id = AVIC_GATAG_TO_VMID(1);

    int bkt = 0;
    hash_for_each(svm_vm_data_hash, bkt, kvm_svm, hnode) { printf("bkt:%d, avic_vm_id:%d\n", bkt, kvm_svm->avic_vm_id); }

    // hash_for_each_possible(svm_vm_data_hash, kvm_svm, hnode, vm_id) {
    //     printf("%d\n", kvm_svm->avic_vm_id);
    // }

    vm_id = AVIC_GATAG_TO_VMID(1);
    hash_for_each_possible(svm_vm_data_hash, kvm_svm, hnode, vm_id) {
        if (kvm_svm->avic_vm_id != vm_id) continue;
        break;
    }
    printf("avic_vm_id:%d\n", kvm_svm->avic_vm_id);

    hash_del(&kvm_svm->hnode);

    empty = hash_empty(svm_vm_data_hash);
    printf("empty:%d\n", empty ? 1 : 0);

    hash_for_each(svm_vm_data_hash, bkt, kvm_svm, hnode) { printf("bkt:%d, avic_vm_id:%d\n", bkt, kvm_svm->avic_vm_id); }

    empty = hash_empty(svm_vm_data_hash);
    printf("empty:%d\n", empty ? 1 : 0);

    hash_for_each(svm_vm_data_hash, bkt, kvm_svm, hnode) { hash_del(&kvm_svm->hnode); }

    empty = hash_empty(svm_vm_data_hash);
    printf("empty:%d\n", empty ? 1 : 0);

    return 0;
}

/*
gcc -g -Wall -std=c11 hashtable_test_hash.c
*/

/*
*/
