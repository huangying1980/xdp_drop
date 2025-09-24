#ifndef XDROP_UTIL_H
#define XDROP_UTIL_H

#define FOR_EACH_MAP_KEY(_err, _map_fd, _map_key, _prev_key)           \
    for (_err = bpf_map_get_next_key(_map_fd, NULL, &_map_key);        \
        !_err;                                                         \
        _prev_key = _map_key,                                          \
        _err = bpf_map_get_next_key(_map_fd, &_prev_key, &_map_key))

#define FOR_EACH_MAP_PKEY(_err, _map_fd, _map_pkey, _prev_pkey)        \
    for (_err = bpf_map_get_next_key(_map_fd, NULL, _map_pkey);        \
        !_err;                                                         \
        _prev_pkey = _map_pkey,                                        \
        _err = bpf_map_get_next_key(_map_fd, _prev_pkey, _map_pkey))

#define min(x, y) ((x) < (y) ? x : y)
#define max(x, y) ((x) > (y) ? x : y)

#define XDP_UNKNOWN XDP_REDIRECT + 1
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_UNKNOWN + 1)
#endif

int get_pinned_object_fd(const char *path, void *info, __u32 *info_len);
int get_pinned_map_fd(const char *bpf_root, const char *map_name,
    struct bpf_map_info *info);

int double_rlimit(void);
int check_bpf_env(void);

int is_mount(void);
int do_mount(void);

const char *action2str(__u32 action);

int clear_map(const char *path);

char *get_prog_path(const char *proc_name, const char *prog_name);
#endif
