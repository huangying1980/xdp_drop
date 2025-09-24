#ifndef XDROP_CONFIG_H
#define XDROP_CONFIG_H
#include <stdbool.h>
#include <linux/types.h>
#include <linux/limits.h>

#define PROG_NAME "xdrop"
#define PROG_KERN "xdrop_kern.obj"

#ifndef HOME_PATH
#define HOME_PATH "/usr/local/xdp_drop"
#endif

struct config {
    __u32 xdp_flags;
    bool do_load;
    bool do_unload;
	int ifindex;
	char *ifname;
	char filename[PATH_MAX];
    char progsec[32];
    bool reuse_maps;
    char pin_dir[512];
};

#endif
