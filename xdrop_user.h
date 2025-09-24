#ifndef XDROP_USER_H
#define XDROP_USER_H

extern int verbose;

#ifndef PATH_MAX
#define PATH_MAX    4096
#endif

#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

#include "xdrop_util.h"
#include "xdrop_config.h"
int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd);
int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id);

struct bpf_object *load_bpf_object_file(const char *filename, int ifindex);
struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg);
int pin_maps(struct bpf_object *obj, const char* pin_dir);

#endif
