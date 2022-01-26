/* SPDX-License-Identifier: GPL-2.0 */

// printf
#include <stdio.h>

// offsetof
#include <stddef.h>

struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) \
    { &(name), &(name) }

#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

#define __WRITE_ONCE(x, val)                 \
    do {                                     \
        *(volatile __typeof__(x) *)&(x) = (val); \
    } while (0)

#define WRITE_ONCE(x, val)    \
    do {                      \
        __WRITE_ONCE(x, val); \
    } while (0)

static inline void INIT_LIST_HEAD(struct list_head *list) {
    WRITE_ONCE(list->next, list);
    list->prev = list;
}

static inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next) {
    next->prev = new;
    new->next = next;
    new->prev = prev;
    WRITE_ONCE(prev->next, new);
}

#define __same_type(a, b) __builtin_types_compatible_p(__typeof__(a), __typeof__(b))

#define container_of(ptr, type, member)                                                                                                  \
    ({                                                                                                                                   \
        void *__mptr = (void *)(ptr);                                                                                                    \
        static_assert(__same_type(*(ptr), ((type *)0)->member) || __same_type(*(ptr), void), "pointer type mismatch in container_of()"); \
        ((type *)(__mptr - offsetof(type, member)));                                                                                     \
    })

static inline void list_add(struct list_head *new, struct list_head *head) {
    __list_add(new, head, head->next);
}

#define list_entry(ptr, type, member) container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) list_entry((ptr)->next, type, member)

#define list_entry_is_head(pos, head, member) (&pos->member == (head))

#define list_next_entry(pos, member) list_entry((pos)->member.next, __typeof__(*(pos)), member)

#define list_for_each_entry(pos, head, member) \
    for (pos = list_first_entry(head, __typeof__(*pos), member); !list_entry_is_head(pos, head, member); pos = list_next_entry(pos, member))

#define POISON_POINTER_DELTA 0
#define LIST_POISON1 ((void *)0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2 ((void *)0x122 + POISON_POINTER_DELTA)

static inline void __list_del(struct list_head *prev, struct list_head *next) {
    next->prev = prev;
    WRITE_ONCE(prev->next, next);
}
static inline void __list_del_entry(struct list_head *entry) {
    __list_del(entry->prev, entry->next);
}
// 删
static inline void list_del(struct list_head *entry) {
    __list_del_entry(entry);
    entry->next = LIST_POISON1;
    entry->prev = LIST_POISON2;
}

struct miscdevice {
    int minor;
    struct list_head list;
    unsigned short mode;
};

static LIST_HEAD(misc_list);

int main() {
    struct miscdevice misc_obj1;
    misc_obj1.minor = 111;
    // 初始化
    INIT_LIST_HEAD(&misc_obj1.list);

    // 增
    list_add(&misc_obj1.list, &misc_list);

    struct miscdevice misc_obj2;
    misc_obj2.minor = 222;
    INIT_LIST_HEAD(&misc_obj2.list);
    list_add(&misc_obj2.list, &misc_list);

    struct miscdevice misc_obj3;
    misc_obj3.minor = 333;
    INIT_LIST_HEAD(&misc_obj3.list);
    list_add(&misc_obj3.list, &misc_list);

    struct miscdevice misc_obj4;
    misc_obj4.minor = 444;
    INIT_LIST_HEAD(&misc_obj4.list);
    list_add(&misc_obj4.list, &misc_list);

    // 打印
    {
        struct miscdevice *c;
        list_for_each_entry(c, &misc_list, list) { printf("%d\n", c->minor); }
    }

    // 查
    struct miscdevice *c;
    list_for_each_entry(c, &misc_list, list) {
        if (c->minor == 222) {
            break;
        }
    }

    // 删
    list_del(&c->list);

    // 打印
    {
        struct miscdevice *c;
        list_for_each_entry(c, &misc_list, list) { printf("%d\n", c->minor); }
    }

    // 改
    {
        struct miscdevice *c;
        list_for_each_entry(c, &misc_list, list) {
            if (c->minor == 333) {
                break;
            }
        }
        c->minor = 33333;
    }

    // 打印
    {
        struct miscdevice *c;
        list_for_each_entry(c, &misc_list, list) { printf("%d\n", c->minor); }
    }


    return 0;
}
