#ifndef XDROP_KERN_DEF_H
#define XDROP_KERN_DEF_H

#ifndef XDROP_KERNDEF_VERSION 
#define XDROP_KERNDEF_VERSION "1.0.0"
#endif

#define XDROP_FILTER_API \
    static __always_inline

#define XDROP_FILTER_DEFINE(_type) \
XDROP_FILTER_API int filter_##_type(struct hdr_cursor *cur, void *data_end)

#define XDROP_FILTER_CALL(_type, ...) \
    filter_##_type(__VA_ARGS__)

#define MAP_DEFINE(_type) \
struct bpf_map_def SEC("maps") MAP_NAME(_type)

#define XDROP_STATIS(_s)      \
do {                          \
    (_s)->byte += cur->size;  \
    (_s)->count++;            \
}while(0)

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void) __sync_fetch_and_add(ptr, val))
#endif

#define XDROP_STATIS_SAFE(_s)               \
do {                                        \
    lock_xadd(&(_s)->byte, cur->size);      \
    lock_xadd(&(_s)->count, 1);             \
}while(0)

#define MAP_INIT(_t, _ks, _vs, _me)   \
{                                     \
    .type = (_t),                     \
    .key_size = (_ks),                \
    .value_size = (_vs),              \
    .max_entries = (_me),             \
}

#define MAP_INIT_NO_PREALLOC(_t, _ks, _vs, _me) \
{                                     \
    .type = (_t),                     \
    .key_size = (_ks),                \
    .value_size = (_vs),              \
    .max_entries = (_me),             \
    .map_flags = BPF_F_NO_PREALLOC    \
}

#define CALL_FILTER(_type) XDROP_FILTER_CALL(_type, cur, data_end)
#endif
