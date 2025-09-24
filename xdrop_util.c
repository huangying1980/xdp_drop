#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/limits.h>
#include <linux/if_link.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <libgen.h>

#include "libbpf.h"
#include "bpf.h"

#include "xdrop_util.h"
#include "xdrop_log.h"

#define MOUNTS_FILE "/proc/mounts"
#define MAX_BUF 1024
#define BPF_PATH "/sys/fs/bpf"


static const char *xdp_action_names[XDP_ACTION_MAX] = {
    [XDP_ABORTED]   = "ABORTED",
    [XDP_DROP]      = "DROP",
    [XDP_PASS]      = "PASS",
    [XDP_TX]        = "TX",
    [XDP_REDIRECT]  = "REDIRECT",
    [XDP_UNKNOWN]   = "UNKNOWN",
};


int get_pinned_object_fd(const char *path, void *info, __u32 *info_len)
{
    int pin_fd = -1;

    pin_fd = bpf_obj_get(path);
    if (pin_fd < 0) {
        DEBUG_OUT("Couldn't retrieve pinned object '%s', err %d, %s\n",
            path, errno, strerror(errno));
        return -1;
    }

    if (info && bpf_obj_get_info_by_fd(pin_fd, info, info_len)) {
        DEBUG_OUT("Couldn't retrieve object info, err %d, %s\n",
            errno, strerror(errno));
        return -1;
    }

    return pin_fd;
}

int get_pinned_map_fd(const char *bpf_root, const char *map_name,
    struct bpf_map_info *info)
{
    __u32 info_len = sizeof(*info);
    char buf[PATH_MAX];

    snprintf(buf, sizeof(buf), "%s/%s", bpf_root, map_name);
    if (access(buf, F_OK)) {
        ERR_OUT("map file %s not existed\n", buf);
        return -1;
    }
    DEBUG_OUT("Getting pinned object from %s\n", buf);
    return get_pinned_object_fd(buf, info, &info_len);
}


static int set_rlimit(unsigned int min_limit)
{
    struct rlimit limit;
    int err = 0;
    
    err = getrlimit(RLIMIT_MEMLOCK, &limit);
    if (err){
        err = -errno;
        ERR_OUT("Couldn't get current rlimit\n");       
        return err;
    }

    if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur == 0){
        DEBUG_OUT("Current rlimit is infinity or 0. Not raising\n");
        return -ENOMEM;
    }
    
    if (min_limit){
        if (limit.rlim_cur >= min_limit){
            return 0;
        }
        
        limit.rlim_cur = min_limit;
    }else{
       limit.rlim_cur <<= 1; 
    }

    limit.rlim_max = max(limit.rlim_cur, limit.rlim_max);
    err = setrlimit(RLIMIT_MEMLOCK, &limit);
    if (err){
        err = -errno;
        ERR_OUT("Couldn't raise rlimit: %s\n", strerror(-err));
        return err;
    }
    return 0;
}

int double_rlimit(void){

    return set_rlimit(0);
}

int check_bpf_env(void)
{   
    int err;

    if (geteuid() != 0){ 
        DEBUG_OUT("geteuid err");
        return 1;
    }   
            
//    set_rlimit(1024 * 1024);
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;

    err = setrlimit(RLIMIT_MEMLOCK, &limit);
    if (err){

        ERR_OUT("Couldn't raise rlimit. \n");
        return 1;
    }
    return 0;
}

int is_mount(void)
{
    FILE* fp;
    char buf[MAX_BUF];
    char* ptr;

    fp = fopen(MOUNTS_FILE, "r");
    if(!fp){
        ERR_OUT("open %s file faile!", MOUNTS_FILE);
        return 1;
    }

    while(fgets(buf, sizeof(buf), fp) != 0){
        ptr = strstr(buf, BPF_PATH);
        if(ptr != NULL)
            return 0;
    }

    return 1;
}

int do_mount(void)
{
    int err;
    err = mount("bpf", BPF_PATH, "bpf", 0, NULL);
    if(err){
        ERR_OUT("mount error (%d): %s\n",
             err, strerror(-err));
        return 1;
    }

    return 0;
}

int clear_map(const char *path)
{
    char path_name[PATH_MAX];
    DIR *dir;
    struct dirent *dp;
    dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "open dir %s failed, err %d, %s\n",
            path, errno, strerror(errno));
        return -1;
    }
    while ((dp = readdir(dir))) {
        if (!strcmp(dp->d_name, ".")) {
            continue; 
        }
        if (!strcmp(dp->d_name, "..")) {
            continue; 
        }
        snprintf(path_name, PATH_MAX, "%s/%s", path, dp->d_name);
        remove(path_name);
    }
    closedir(dir);
    rmdir(path);
    return 0;
}

const char *action2str(__u32 action)
{
        if (action < XDP_ACTION_MAX)
                return xdp_action_names[action];
        return NULL;
}

