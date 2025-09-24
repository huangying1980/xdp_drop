#ifndef XDROP_COMMON_KERN_USER_H
#define XDROP_COMMON_KERN_USER_H

#define FEAT_TCP	(1<<0)
#define FEAT_UDP	(1<<1)
#define FEAT_IPV6	(1<<2)
#define FEAT_IPV4	(1<<3)
#define FEAT_ETHERNET	(1<<4)
#define FEAT_ALL	(FEAT_TCP|FEAT_UDP|FEAT_IPV6|FEAT_IPV4|FEAT_ETHERNET)
#define FEAT_ALLOW	(1<<5)
#define FEAT_DENY	(1<<6)

#define MAP_FLAG_SRC (1<<0)
#define MAP_FLAG_DST (1<<1)
#define MAP_FLAG_TCP (1<<2)
#define MAP_FLAG_UDP (1<<3)
#define MAP_FLAGS (MAP_FLAG_SRC|MAP_FLAG_DST|MAP_FLAG_TCP|MAP_FLAG_UDP)

#define MAP_FLAG_IPV4 (1<<0)
#define MAP_FLAG_IPV6 (1<<1)
#define MAP_FLAG_IP (MAP_FLAG_IPV4|MAP_FLAG_IPV6)

#define COUNTER_SHIFT 6

#define MAP_NAME(_type) map_filter_##_type
#define MAP_REF(_type) &MAP_NAME(_type)

#ifndef MAX_STATIS_NUM
#define MAX_STATIS_NUM (XDP_REDIRECT + 1)
#endif


#ifndef MAX_PORT_NUM
#define MAX_PORT_NUM (1024)
#endif

#ifndef MAX_LAYER3_NUM
#define MAX_LAYER3_NUM (16)
#endif

#ifndef MAX_LAYER4_NUM
#define MAX_LAYER4_NUM (8)
#endif

#ifndef MAX_LPM_IPV4_NUM
#define MAX_LPM_IPV4_NUM (1024)
#endif

#ifndef MAX_LPM_IPV6_NUM
#define MAX_LPM_IPV6_NUM (1024)
#endif

#define MAP_FLAG_LAYER3 (1<<0)
#define MAP_FLAG_LAYER4 (1<<1)


enum xdp_attach_mode {
    XDP_MODE_UNSPEC = 0,
    XDP_MODE_NATIVE,
    XDP_MODE_SKB,
    XDP_MODE_HW
};
struct drop_statis {
    __u64    byte;
    __u64    count;
};

#endif
