
// printf
#include <stdio.h>

// offsetof
#include <stddef.h>

// static_assert
#include <assert.h>


#define dmb(option) __asm__ __volatile__("dmb " #option : : : "memory")

#define aarch32_smp_mb() dmb(ish)
#define aarch32_smp_rmb() dmb(ishld)
#define aarch32_smp_wmb() dmb(ishst)

#undef smp_mb
#undef smp_rmb
#undef smp_wmb

#define smp_mb() aarch32_smp_mb()
#define smp_rmb() aarch32_smp_rmb()
#define smp_wmb() aarch32_smp_wmb()



#define __same_type(a, b) __builtin_types_compatible_p(__typeof__(a), __typeof__(b))

#define BUILD_BUG_ON_ZERO(e) ((int)(sizeof(struct { int : (-!!(e)); })))

#define __must_be_array(a) BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))



struct __kfifo {
    unsigned int in;
    unsigned int out;
    unsigned int mask;
    unsigned int esize;
    void *data;
};

#define __STRUCT_KFIFO_COMMON(datatype, recsize, ptrtype) \
    union {                                               \
        struct __kfifo kfifo;                             \
        datatype *type;                                   \
        const datatype *const_type;                       \
        char (*rectype)[recsize];                         \
        ptrtype *ptr;                                     \
        ptrtype const *ptr_const;                         \
    }

#define __STRUCT_KFIFO(type, size, recsize, ptrtype)               \
    {                                                              \
        __STRUCT_KFIFO_COMMON(type, recsize, ptrtype);             \
        type buf[((size < 2) || (size & (size - 1))) ? -1 : size]; \
    }

#define STRUCT_KFIFO(type, size) struct __STRUCT_KFIFO(type, size, 0, type)

#define DECLARE_KFIFO(fifo, type, size) STRUCT_KFIFO(type, size) fifo

#define __STRUCT_KFIFO_PTR(type, recsize, ptrtype)     \
    {                                                  \
        __STRUCT_KFIFO_COMMON(type, recsize, ptrtype); \
        type buf[0];                                   \
    }

#define STRUCT_KFIFO_PTR(type) struct __STRUCT_KFIFO_PTR(type, 0, type)

#define __is_kfifo_ptr(fifo) (sizeof(*fifo) == sizeof(STRUCT_KFIFO_PTR(__typeof__(*(fifo)->type))))

#define INIT_KFIFO(fifo)                                                        \
    (void)({                                                                    \
        __typeof__(&(fifo)) __tmp = &(fifo);                                    \
        struct __kfifo *__kfifo = &__tmp->kfifo;                                \
        __kfifo->in = 0;                                                        \
        __kfifo->out = 0;                                                       \
        __kfifo->mask = __is_kfifo_ptr(__tmp) ? 0 : ARRAY_SIZE(__tmp->buf) - 1; \
        __kfifo->esize = sizeof(*__tmp->buf);                                   \
        __kfifo->data = __is_kfifo_ptr(__tmp) ? NULL : __tmp->buf;              \
    })

static inline unsigned int kfifo_unused(struct __kfifo *fifo) {
    return (fifo->mask + 1) - (fifo->in - fifo->out);
}

#define __KFIFO_POKE(data, in, mask, val) ((data)[(in) & (mask)] = (unsigned char)(val))

static void __kfifo_poke_n(struct __kfifo *fifo, unsigned int n, size_t recsize) {
    unsigned int mask = fifo->mask;
    unsigned char *data = fifo->data;

    __KFIFO_POKE(data, fifo->in, mask, n);

    if (recsize > 1) __KFIFO_POKE(data, fifo->in + 1, mask, n >> 8);
}

static void kfifo_copy_in(struct __kfifo *fifo, const void *src, unsigned int len, unsigned int off) {
    unsigned int size = fifo->mask + 1;
    unsigned int esize = fifo->esize;
    unsigned int l;

    off &= fifo->mask;
    if (esize != 1) {
        off *= esize;
        size *= esize;
        len *= esize;
    }
    l = min(len, size - off);

    memcpy(fifo->data + off, src, l);
    memcpy(fifo->data, src + l, len - l);
    /*
     * make sure that the data in the fifo is up to date before
     * incrementing the fifo->in index counter
     */
    smp_wmb();
}

unsigned int __kfifo_in_r(struct __kfifo *fifo, const void *buf, unsigned int len, size_t recsize) {
    if (len + recsize > kfifo_unused(fifo)) return 0;

    __kfifo_poke_n(fifo, len, recsize);

    kfifo_copy_in(fifo, buf, len, fifo->in + recsize);
    fifo->in += len + recsize;
    return len;
}

#define kfifo_put(fifo, val)                                                                                                                                           \
    ({                                                                                                                                                                 \
        __typeof__((fifo) + 1) __tmp = (fifo);                                                                                                                         \
        __typeof__(*__tmp->const_type) __val = (val);                                                                                                                  \
        unsigned int __ret;                                                                                                                                            \
        size_t __recsize = sizeof(*__tmp->rectype);                                                                                                                    \
        struct __kfifo *__kfifo = &__tmp->kfifo;                                                                                                                       \
        if (__recsize)                                                                                                                                                 \
            __ret = __kfifo_in_r(__kfifo, &__val, sizeof(__val), __recsize);                                                                                           \
        else {                                                                                                                                                         \
            __ret = !kfifo_is_full(__tmp);                                                                                                                             \
            if (__ret) {                                                                                                                                               \
                (__is_kfifo_ptr(__tmp) ? ((__typeof__(__tmp->type))__kfifo->data) : (__tmp->buf))[__kfifo->in & __tmp->kfifo.mask] = *(__typeof__(__tmp->type))&__val; \
                smp_wmb();                                                                                                                                             \
                __kfifo->in++;                                                                                                                                         \
            }                                                                                                                                                          \
        }                                                                                                                                                              \
        __ret;                                                                                                                                                         \
    })


struct ad7124_channel_config {
    unsigned int cfg_slot;
    unsigned int filter_type;
};

#define AD7124_MAX_CONFIGS 8

struct ad7124_state {
    unsigned int adc_control;
    unsigned int num_channels;
    DECLARE_KFIFO(live_cfgs_fifo, struct ad7124_channel_config *, AD7124_MAX_CONFIGS);
};


int main() {
    struct ad7124_state st_instance;
    struct ad7124_state *st = &st_instance;
    INIT_KFIFO(st->live_cfgs_fifo);

    struct ad7124_channel_config cfg_arr[10];
    for (int i = 0; i < 10; ++i) {
        struct ad7124_channel_config *cfg = &cfg_arr[i];
        kfifo_put(&st->live_cfgs_fifo, cfg);
    }

    return 0;
}

/*
gcc -g -Wall -std=c11 kfifo_test.c
*/

/*
kfifo简单总结：
    ps:ARRAY_SIZE里面在编译阶段判定一下类型的做法，非常赞
*/
