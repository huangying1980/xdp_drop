#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_link.h>
#include <bpf_util.h>
#include <arpa/inet.h>

#include "linux/bpf.h"
#include "bpf.h"
#include "bpf_endian.h"

#include "xdrop_cmdline.h"
#include "xdrop_log.h"
#include "xdrop_util.h"
#include "xdrop_user.h"
#include "xdrop_common_kern_user.h"

const char *load_file_name = "xdrop_kern.obj";

int print_subnet(int map_fd, unsigned int flag);

struct flag_val map_flags_ip[] = {
    {"ipv4", MAP_FLAG_IPV4},
    {"ipv6", MAP_FLAG_IPV6},
    {}
};

struct flag_val map_flags_all[] = {
    {"src", MAP_FLAG_SRC},
    {"dst", MAP_FLAG_DST},
    {"tcp", MAP_FLAG_TCP},
    {"udp", MAP_FLAG_UDP},
    {}
};

struct flag_val map_flags_srcdst[] = {
    {"src", MAP_FLAG_SRC},
    {"dst", MAP_FLAG_DST},
    {}
};

struct flag_val map_flags_tcpudp[] = {
    {"tcp", MAP_FLAG_TCP},
    {"udp", MAP_FLAG_UDP},
    {}
};

struct flag_val map_flags_layer[] = {
    {"network",   MAP_FLAG_LAYER3},
    {"transport", MAP_FLAG_LAYER4},
    {}
};

struct flag_val load_features[] = {
	{"tcp", FEAT_TCP},
	{"udp", FEAT_UDP},
	{"ipv6", FEAT_IPV6},
	{"ipv4", FEAT_IPV4},
	{"ethernet", FEAT_ETHERNET},
	{"all", FEAT_ALL},
	{}
};

struct flag_val print_features[] = {
	{"tcp", FEAT_TCP},
	{"udp", FEAT_UDP},
	{"ipv6", FEAT_IPV6},
	{"ipv4", FEAT_IPV4},
	{"ethernet", FEAT_ETHERNET},
	{"allow", FEAT_ALLOW},
	{"deny", FEAT_DENY},
	{}
};

struct enum_val xdp_modes[] = {
       {"native", XDP_MODE_NATIVE},
       {"skb", XDP_MODE_SKB},
       {"hw", XDP_MODE_HW},
       {NULL, 0}
};

struct enum_val policy_modes[] = {
       {"allow", FEAT_ALLOW},
       {"deny", FEAT_DENY},
       {NULL, 0}
};

//for load
static const struct loadopt {
    bool                    help;
    bool                    reuse_map;
    unsigned int            features;
    unsigned int            policy_mode;
    struct iface            iface;
    enum xdp_attach_mode    mode;
} defaults_load = {
    .features = FEAT_ALL,
    .mode = XDP_MODE_NATIVE,
    .policy_mode = FEAT_ALLOW,
    .reuse_map = false,
};

static struct prog_option load_options[] = {
	DEFINE_OPTION("mode", OPT_ENUM, struct loadopt, mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<mode>",
		      .help = "Load XDP program in <mode>; default native"),
	DEFINE_OPTION("dev", OPT_IFNAME, struct loadopt, iface,
		      .positional = true,
		      .metavar = "<ifname>",
		      .required = true,
		      .help = "Load on device <ifname>"),
    DEFINE_OPTION("reuse_map", OPT_BOOL, struct loadopt, reuse_map, 
        .short_opt = 'M',
        .help = "reuse has added rulses map."),
	END_OPTIONS
};

int do_load(const void *cfg, const char *pin_root_path)
{
    const struct loadopt *opt = cfg;
    
    struct config cfg_t = {
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
    };
    struct bpf_object *bpf_obj;
    int err;
#ifdef XDROP_DEBUG
    DEBUG_OUT("ifindex %d, ifname %s\n", opt->iface.ifindex, opt->iface.ifname);
    DEBUG_OUT("pin root path %s\n", pin_root_path);
#endif

    // nead mount -t bpf bpf /sys/fs/bpf
    if(is_mount() != 0){
        do_mount();
    }
    
    switch (opt->mode){
        case XDP_MODE_NATIVE:
            cfg_t.xdp_flags &= ~XDP_FLAGS_MODES;
            cfg_t.xdp_flags |= XDP_FLAGS_DRV_MODE;
            break;
        case XDP_MODE_SKB:
            cfg_t.xdp_flags &= ~XDP_FLAGS_MODES;
            cfg_t.xdp_flags |= XDP_FLAGS_SKB_MODE;
            break;
        case XDP_MODE_HW:
            cfg_t.xdp_flags &= ~XDP_FLAGS_MODES;
            cfg_t.xdp_flags |= XDP_FLAGS_HW_MODE;
            break;
        default:
            break;
    }

    // force load    
    //cfg_t.xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;

    snprintf(cfg_t.filename, PATH_MAX - 1, "%s/%s", HOME_PATH, load_file_name);
    strncpy(cfg_t.pin_dir, pin_root_path, sizeof(cfg_t.pin_dir));
    cfg_t.ifname = opt->iface.ifname;
    cfg_t.ifindex = opt->iface.ifindex;
    cfg_t.reuse_maps = opt->reuse_map;

    bpf_obj = load_bpf_and_xdp_attach(&cfg_t);
    if(!bpf_obj){
        ERR_OUT("load_bpf_and_xdp_attach error\n");
        return EXIT_FAILURE;
    }

    if (!cfg_t.reuse_maps)
    {
        err = pin_maps(bpf_obj, pin_root_path);
        if(err){
            ERR_OUT("pin maps error.\n");
            return EXIT_FAILURE;
        }
    }
    
    return EXIT_SUCCESS; 
}

//for unload
static struct unloadopt {
    bool            all;
    bool            keep;
    struct iface    iface;
    enum xdp_attach_mode    mode;
} defaults_unload = {
    .keep = false,
    .mode = XDP_MODE_NATIVE,
};

static struct prog_option unload_options[] = {
    DEFINE_OPTION("dev", OPT_IFNAME, struct unloadopt, iface,
        .positional = true,
        .metavar = "<ifname>",
        .help = "Unload from device <ifname>"),
    DEFINE_OPTION("all", OPT_BOOL, struct unloadopt, all,
        .short_opt = 'a',
        .help = "Unload from all interfaces"),
    DEFINE_OPTION("keep-maps", OPT_BOOL, struct unloadopt, keep,
        .short_opt = 'k',
        .help = "Don't destroy unused maps after unloading"),
	DEFINE_OPTION("mode", OPT_ENUM, struct unloadopt, mode,
		.short_opt = 'm',
		.typearg = xdp_modes,
		.metavar = "<mode>",
		.help = "Unload XDP program in <mode>; default native"),
    END_OPTIONS
};

int do_unload(const void *cfg, const char *pin_root_path)
{
    const struct unloadopt *opt = cfg;
    int err;

#ifdef XDROP_DEBUG
    DEBUG_OUT("ifindex %d, ifname %s\n", opt->iface.ifindex, opt->iface.ifname);
    DEBUG_OUT("pin root path %s\n", pin_root_path);
#endif
    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
    
    switch (opt->mode){
        case XDP_MODE_NATIVE:
            xdp_flags &= ~XDP_FLAGS_MODES;
            xdp_flags |= XDP_FLAGS_DRV_MODE;
            break;
        case XDP_MODE_SKB:
            xdp_flags &= ~XDP_FLAGS_MODES;
            xdp_flags |= XDP_FLAGS_SKB_MODE;
            break;
        case XDP_MODE_HW:
            xdp_flags &= ~XDP_FLAGS_MODES;
            xdp_flags |= XDP_FLAGS_HW_MODE;
            break;
        default:
            break;
    }

    // force unload    
    //xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
    if (!opt->keep){
        clear_map(pin_root_path);
    }

    err = xdp_link_detach(opt->iface.ifindex, xdp_flags, 0);
    if(err){
        ERR_OUT("xdp_link detach error!\n");
        return EXIT_FAILURE;
    }

    // fix unload bug, when load -m native, unload -m skb.
    // juge once again
    __u32 curr_prog_id = 0;
    err = bpf_get_link_xdp_id(opt->iface.ifindex, &curr_prog_id, xdp_flags);
    if (curr_prog_id != 0) {
        ERR_OUT("ERR: xdp_link detach error,maybe unload mode is not match!\n" );
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

//for ip
static const struct ipopt {
    unsigned int    mode;
    struct ip_addr  addr;
    bool            print_status;
    bool            remove;
} defaults_ip = {
    .mode = MAP_FLAG_SRC,
};

static struct prog_option ip_options[] = {
    DEFINE_OPTION("addr", OPT_IPADDR, struct ipopt, addr,
        .positional = true,
        .metavar = "<addr>",
        .required = true,
        .help = "Address to add or remove"),
    DEFINE_OPTION("remove", OPT_BOOL, struct ipopt, remove,
        .short_opt = 'r',
        .help = "Remove address instead of adding"),
/*
    DEFINE_OPTION("mode", OPT_FLAGS, struct ipopt, mode,
        .short_opt = 'm',
        .metavar = "<mode>",
        .typearg = map_flags_srcdst,
        .help = "Filter mode; default src"),
*/
    DEFINE_OPTION("status", OPT_BOOL, struct ipopt, print_status,
        .short_opt = 's',
        .help = "Print status of filtered addresses after changing"),
    END_OPTIONS
};
int print_ip(int map_fd, unsigned flag)
{
    return print_subnet(map_fd, flag);
}
int do_ip(const void *cfg, const char *pin_root_dir)
{
    int      map_fd = -1;
    int      ret = EXIT_FAILURE;
    char    *map_name = NULL;
    __u32    size;
    __u32    prefix;
    unsigned int flag;

    struct bpf_lpm_trie_key *key;
    struct drop_statis   value = {0, 0};
    struct bpf_map_info  info = {};
    struct ipopt *opt = (struct ipopt *)cfg;
    
    switch (opt->addr.af) {
        case AF_INET:
            map_name = textify(MAP_NAME(ipv4));
            flag = MAP_FLAG_IPV4;
            size = sizeof(struct in_addr);
            prefix = 32;
            break;
        case AF_INET6:
            flag = MAP_FLAG_IPV6;
            map_name = textify(MAP_NAME(ipv6));
            size = sizeof(struct in6_addr);
            prefix = 128;
            break;
        default:
            ERR_OUT("address family error: %d\n", opt->addr.af);
            goto err;
    }
    map_fd = get_pinned_map_fd(pin_root_dir, map_name, &info);
    if (map_fd < 0) {
        goto err;
    }

    key = alloca(sizeof(struct bpf_lpm_trie_key) + size);
    if (!key) {
        ERR_OUT("alloca for key failed\n");
        goto err;
    }
    key->prefixlen = prefix;
    memcpy(key->data, &opt->addr.addr, size);

    if (opt->remove) {
        if (!bpf_map_delete_elem(map_fd, key)) {
            DEBUG_OUT("remove from map '%s' succeed\n", map_name);
            goto out;
        }
        ERR_OUT("remove from map '%s' failed, err %d, %s\n",
            map_name, errno, strerror(errno));
        goto err;
    }
    if (bpf_map_update_elem(map_fd, key, &value, BPF_NOEXIST)) {
        ERR_OUT("add to map '%s' failed, err %d, %s\n",
            map_name, errno, strerror(errno));
        goto err;
    }

    if (opt->print_status) {
        print_ip(map_fd, flag);
    }

out:
    ret = EXIT_SUCCESS;
err:
    return ret;
}

//for subnet
static const struct subnetopt {
    unsigned int        mode;
    struct subnet_addr  subnet;
    bool                print_status;
    bool                remove;
} defaults_subnet = {
    .mode = MAP_FLAG_SRC,
};

static struct prog_option subnet_options[] = {
    DEFINE_OPTION("subnet", OPT_SUBNET, struct subnetopt, subnet,
        .positional = true,
        .metavar = "<subnet>",
        .required = true,
        .help = "Subnet to add or remove"),
    DEFINE_OPTION("remove", OPT_BOOL, struct subnetopt, remove,
        .short_opt = 'r',
        .help = "Remove subnet instead of adding"),
    DEFINE_OPTION("status", OPT_BOOL, struct subnetopt, print_status,
        .short_opt = 's',
        .help = "Print status of filtered subnet after changing"),
    END_OPTIONS
};

int print_subnet(int map_fd, unsigned int flag)
{
    char     buf[32];
    int      err; 

    struct bpf_lpm_trie_key *map_key;
    struct bpf_lpm_trie_key *prev_key;
    char addr[INET6_ADDRSTRLEN];

    if (flag & MAP_FLAG_IPV4) {
        map_key = alloca(sizeof(struct bpf_lpm_trie_key)
            + sizeof(struct in_addr));
        print_flags(buf, sizeof(buf), map_flags_ip, flag);
        fprintf(stderr, "enabled subnet for %s:\n", buf);
        FOR_EACH_MAP_PKEY (err, map_fd, map_key, prev_key) {
            printf("%d.%d.%d.%d/%u\n",
                map_key->data[0], map_key->data[1],
                map_key->data[2], map_key->data[3],
                map_key->prefixlen);
        }
    }
    if (flag & MAP_FLAG_IPV6) {
        map_key = alloca(sizeof(struct bpf_lpm_trie_key)
            + sizeof(struct in6_addr));
        print_flags(buf, sizeof(buf), map_flags_ip, flag);
        fprintf(stderr, "enabled subnet for %s:\n", buf);
        FOR_EACH_MAP_PKEY (err, map_fd, map_key, prev_key) {
            inet_ntop(AF_INET6, (struct in6_addr*)map_key->data, addr, INET6_ADDRSTRLEN);
            printf("%s/%u\n", addr, map_key->prefixlen);
        }
    }

    return 0;
}

int do_subnet(const void *cfg, const char *pin_root_dir)
{
    int      map_fd = -1;
    int      ret = EXIT_FAILURE;
    char    *map_name = NULL;
    __u32    size;
    unsigned int flag;

    struct bpf_lpm_trie_key *key;
    struct drop_statis   value = {0, 0};
    struct bpf_map_info  info = {};
    struct subnetopt *opt = (struct subnetopt *)cfg;
    
    switch (opt->subnet.af) {
        case AF_INET:
            map_name = textify(MAP_NAME(ipv4));
            flag = MAP_FLAG_IPV4;
            size = sizeof(struct in_addr);
            break;
        case AF_INET6:
            flag = MAP_FLAG_IPV6;
            map_name = textify(MAP_NAME(ipv6));
            size = sizeof(struct in6_addr);
            break;
        default:
            ERR_OUT("address family error: %d\n", opt->subnet.af);
            goto err;
    }
    map_fd = get_pinned_map_fd(pin_root_dir, map_name, &info);
    if (map_fd < 0) {
        goto err;
    }

    key = alloca(sizeof(struct bpf_lpm_trie_key) + size);
    if (!key) {
        ERR_OUT("alloca for key failed\n");
        goto err;
    }
    key->prefixlen = opt->subnet.prefix;
    memcpy(key->data, &opt->subnet.addr, size);

    if (opt->remove) {
        if (!bpf_map_delete_elem(map_fd, key)) {
            DEBUG_OUT("remove from map '%s' succeed\n", map_name);
            goto out;
        }
        ERR_OUT("remove from map '%s' failed, err %d, %s\n",
            map_name, errno, strerror(errno));
        goto err;
    }
    if (bpf_map_update_elem(map_fd, key, &value, BPF_NOEXIST)) {
        ERR_OUT("add to map '%s' failed, err %d, %s\n",
            map_name, errno, strerror(errno));
        goto err;
    }

    if (opt->print_status) {
        print_subnet(map_fd, flag);
    }

out:
    ret = EXIT_SUCCESS;
err:
    return ret;
}

//for port
static const struct portopt {
    unsigned int mode;
    unsigned int proto;
    __u16        port;
    bool         print_status;
    bool         remove;
} defaults_port = {
    .proto = MAP_FLAG_TCP,
};

static struct prog_option port_options[] = {
    DEFINE_OPTION("port", OPT_U16, struct portopt, port,
            .positional = true,
            .metavar = "<port>",
            .required = true,
            .help = "Port to add or remove"),
    DEFINE_OPTION("remove", OPT_BOOL, struct portopt, remove,
            .short_opt = 'r',
            .help = "Remove port instead of adding"),
    DEFINE_OPTION("proto", OPT_FLAGS, struct portopt, proto,
            .short_opt = 'p',
            .metavar = "<proto>",
            .typearg = map_flags_tcpudp,
            .help = "Protocol to filter; default tcp"),
    DEFINE_OPTION("status", OPT_BOOL, struct portopt, print_status,
            .short_opt = 's',
            .help = "Print status of filtered ports after changing"),
#if 0
    // only support destination port
    DEFINE_OPTION("mode", OPT_FLAGS, struct portopt, mode,
            .short_opt = 'm',
            .metavar = "<mode>",
            .typearg = map_flags_srcdst,
            .help = "Filter mode; default dst"),
#endif
    END_OPTIONS
};

int print_port(int map_fd, unsigned int proto)
{
    __u32 map_key = -1;
    __u32 prev_key = 0;
    char  buf[32];
    int   err;
    print_flags(buf, sizeof(buf), map_flags_tcpudp, proto);
    fprintf(stderr, "enabled port for %s:\n", buf);
    FOR_EACH_MAP_KEY (err, map_fd, map_key, prev_key) {
        printf("%d\n", bpf_ntohs(map_key));
    }
    return 0;
}

int do_port(const void *cfg, const char *pin_root_dir)
{
    int     map_fd = -1;
    int     ret = EXIT_FAILURE;
    char   *map_name = NULL;
    __u32   key;
    unsigned int nr_cpus = bpf_num_possible_cpus();

    struct portopt       *opt = (struct portopt *)cfg;
    struct drop_statis    value[nr_cpus];
    struct bpf_map_info   info = {};

    if (opt->proto & MAP_FLAG_TCP) {
        map_name = textify(MAP_NAME(tcp_port));
    }
    if (opt->proto & MAP_FLAG_UDP) {
        map_name = textify(MAP_NAME(udp_port));
    }
    DEBUG_OUT("map name %s\n", map_name);
    map_fd = get_pinned_map_fd(pin_root_dir, map_name, &info);
    if (map_fd < 0) {
        goto err;
    }
    key = bpf_htons(opt->port);
    if (opt->remove) {
        if (!bpf_map_delete_elem(map_fd, &key)) {
            DEBUG_OUT("remove from map '%s' succeed\n", map_name);
            goto out;
        }
        ERR_OUT("remove from map '%s' failed, err %d, %s\n",
            map_name, errno, strerror(errno));
        goto err;
    }

    memset(value, 0, sizeof(value));
    if (bpf_map_update_elem(map_fd, &key, value, BPF_NOEXIST)) {
        ERR_OUT("add to map '%s' failed, err %d, %s\n",
            map_name, errno, strerror(errno));
        goto err;
    }

    if (opt->print_status) {
        print_port(map_fd, opt->proto);
    }

out:
    ret = EXIT_SUCCESS;
err:
    return ret;
}

//for protocal
static const struct protoopt {
    unsigned int proto;
    unsigned int layer;
    bool         print_status;
    bool         remove;
} defaults_proto = {};

static struct prog_option proto_options[] = {
    DEFINE_OPTION("proto", OPT_U32, struct protoopt, proto,
            .positional = true,
            .metavar = "<proto>",
            .required = true,
            .help = "protocal to add or remove"),
    DEFINE_OPTION("remove", OPT_BOOL, struct protoopt, remove,
            .short_opt = 'r',
            .help = "Remove port instead of adding"),
    DEFINE_OPTION("layer", OPT_FLAGS, struct protoopt, layer,
            .short_opt = 'l',
            .metavar = "<layer>",
            .typearg = map_flags_layer,
            .help = "layer to filter"),
    DEFINE_OPTION("status", OPT_BOOL, struct protoopt, print_status,
            .short_opt = 's',
            .help = "Print status of filtered ports after changing"),
    END_OPTIONS
};

int print_proto(int map_fd, unsigned int layer)
{
    __u32 map_key = -1;
    __u32 prev_key = 0;
    char  buf[32];
    int   err;
    print_flags(buf, sizeof(buf), map_flags_layer, layer);
    fprintf(stderr, "enabled protocol in layer %s:\n", buf);
    FOR_EACH_MAP_KEY (err, map_fd, map_key, prev_key) {
        //printf("%02X\n", map_key);
        printf("%u\n", map_key);
    }
    return 0;
}

int drop_statis_print(int map_fd, void *keyp, enum rule_type rt)
{
    unsigned int nr_cpus = bpf_num_possible_cpus();
    struct drop_statis values[nr_cpus];
    void *prev_keyp = NULL;
    int err;
    struct bpf_lpm_trie_key *map_key;
    bool print_header_flag = true;
    char addr6 [INET6_ADDRSTRLEN];    

    FOR_EACH_MAP_PKEY(err, map_fd, keyp, prev_keyp){
        __u64 total_byte = 0;
        __u64 total_count = 0;
        int i = 0;

        if ((bpf_map_lookup_elem(map_fd, keyp, values)) != 0) {
           ERR_OUT("bpf_map_lookup_elem failed key"); 
           continue;
        }
        //sum
        if (rt == IPV4_RULE || rt == IPV6_RULE){
            total_byte = values[0].byte;
            total_count = values[0].count;
        }else{
            for(i = 0; i < nr_cpus; i++){
                total_byte += values[i].byte;
                total_count += values[i].count;
            }
        }
        
        switch (rt){
            case TCP_PORT_RULE:
                if (print_header_flag) printf("=tcp port drop statis=:\n"); 
                printf("tcpport-rule:%-12u, drop_byte:%15llu, drop_count:%15llu\n", bpf_ntohs(*(__u32*)keyp), 
                    total_byte, total_count);
                break;
            case UDP_PORT_RULE:
                if (print_header_flag) printf("=udp port drop statis=:\n"); 
                printf("udpport-rule:%-12u, drop_byte:%15llu, drop_count:%15llu\n", bpf_ntohs(*(__u32*)keyp), 
                    total_byte, total_count);
                break;
            case LAYER3_RULE:
                if (print_header_flag) printf("=layer3 drop statis=:\n"); 
                printf("layer3-rule:%-12u, drop_byte:%15llu, drop_count:%15llu\n", *(__u32*)keyp,
                    total_byte, total_count);
                break;
            case LAYER4_RULE:
                if (print_header_flag) printf("=layer4 drop statis=:\n"); 
                printf("layer4-rule:%-12u, drop_byte:%15llu, drop_count:%15llu\n", *(__u32*)keyp,
                    total_byte, total_count);
                break;
            case IPV4_RULE:
                if (print_header_flag) printf("=ipv4 drop statis=:\n"); 
                map_key = (struct bpf_lpm_trie_key *) keyp;
                printf("ipv4-rule:%d.%d.%d.%d/%u, drop_byte:%15llu, drop_count:%15llu\n", 
                    map_key->data[0], map_key->data[1],
                    map_key->data[2], map_key->data[3], 
                    map_key->prefixlen, total_byte, total_count);
                break;
            case IPV6_RULE:
                if (print_header_flag) printf("=ipv6 drop statis=:\n"); 
                map_key = (struct bpf_lpm_trie_key *) keyp; 
                inet_ntop(AF_INET6, (struct in6_addr*)map_key->data, addr6, INET6_ADDRSTRLEN);
                printf("ipv6-rule:%-12s/%u, drop_byte:%15llu, drop_count:%15llu\n", 
                    addr6, map_key->prefixlen, total_byte, total_count);
                break;
            case TOTAL_STATIS:
                if (print_header_flag) printf("=total drop statis=:\n"); 
                printf("action-statis:%-12s, byte:%15llu, count:%15llu\n", action2str(*(__u32*)keyp),
                    total_byte, total_count);
                break;
        }
        print_header_flag = false;
    }

    if(!print_header_flag) printf("\n");
    return 0;   
}

int print_layer3_drop_statis(int map_fd)
{
   __u32 keyp;
    drop_statis_print(map_fd, &keyp, LAYER3_RULE);
    
    return 0;   
}

int print_layer4_drop_statis(int map_fd)
{
   __u32 keyp; 
    drop_statis_print(map_fd, &keyp, LAYER4_RULE);
    
    return 0;   
}


int print_port_drop_statis(int map_fd, enum rule_type rt)
{
    __u32 keyp;
    drop_statis_print(map_fd, &keyp, rt);
    
    return 0;
}


int print_ipv4_drop_statis(int map_fd)
{
    struct bpf_lpm_trie_key *keyp;
     keyp = alloca(sizeof(struct bpf_lpm_trie_key)
            + sizeof(struct in_addr));
    drop_statis_print(map_fd, keyp, IPV4_RULE);  
    
    return 0;
}

int print_ipv6_drop_statis(int map_fd)
{
    struct bpf_lpm_trie_key *keyp;
     keyp = alloca(sizeof(struct bpf_lpm_trie_key)
            + sizeof(struct in6_addr));
    drop_statis_print(map_fd, keyp, IPV6_RULE);  
    
    return 0;
}
int print_total_statis(int map_fd)
{
   __u32 keyp;
     
    drop_statis_print(map_fd, &keyp, TOTAL_STATIS);  
    return 0;
}

int do_proto(const void *cfg, const char *pin_root_dir)
{
    int     map_fd = -1;
    int     ret = EXIT_FAILURE;
    char   *map_name = NULL;
    __u32   key;
    unsigned int nr_cpus = bpf_num_possible_cpus();

    struct protoopt     *opt = (struct protoopt *)cfg;
    struct drop_statis   value[nr_cpus];
    struct bpf_map_info  info = {};
    
    switch (opt->layer) {
        case MAP_FLAG_LAYER3:
            map_name = textify(MAP_NAME(layer3));
            DEBUG_OUT("get fd layer3 map %s/%s\n", pin_root_dir, map_name);
            if (opt->proto >= 1 << 16) {
                ERR_OUT("proto error!\n");
                goto err;
            }
            key = bpf_htons(opt->proto);
            break;
        case MAP_FLAG_LAYER4:
            map_name = textify(MAP_NAME(layer4));
            DEBUG_OUT("get fd layer4 map %s/%s\n", pin_root_dir, map_name);
            if (opt->proto >= 1 << 8) {
                ERR_OUT("proto error\n");
                goto err;
            }
            key = opt->proto;
            break;
        default:
            ERR_OUT("layer error\n");
            goto err;
    }

    map_fd = get_pinned_map_fd(pin_root_dir, map_name, &info);
    if (map_fd < 0) {
        goto err;
    }
    if (opt->remove) {
        if (!bpf_map_delete_elem(map_fd, &key)) {
           DEBUG_OUT("remove from map '%s' succeed\n", map_name);
            goto out;
        }
        ERR_OUT("remove from map '%s' failed, err %d, %s\n",
            map_name, errno, strerror(errno));
        goto err;
    }
    memset(value, 0, sizeof(value));
    if (bpf_map_update_elem(map_fd, &key, value, BPF_NOEXIST)) {
        ERR_OUT("add to map '%s' failed, err %d, %s\n",
            map_name, errno, strerror(errno));
        goto err;
    }

    if (opt->print_status) {
        print_proto(map_fd, opt->layer);
    }
out:
    ret = EXIT_SUCCESS;
err:
    return ret;
}
//for statistics
static struct prog_option statis_options[] = { END_OPTIONS };

int do_statis(const void *cfg, const char *pin_root_path)
{
    int err = EXIT_SUCCESS, map_fd = -1;
    struct bpf_map_info info = {};
    
    // protoc lay 3
    map_fd = get_pinned_map_fd(pin_root_path, textify(MAP_NAME(layer3)), &info);
    if (map_fd < 0){
        err = map_fd;
        DEBUG_OUT("can't get layer3 map.");
        goto out;
    }
    print_layer3_drop_statis(map_fd);

    //protoc layer4
    map_fd = get_pinned_map_fd(pin_root_path, textify(MAP_NAME(layer4)), &info);
    if (map_fd < 0){
        err = map_fd;
        DEBUG_OUT("can't get layer4 map.");
        goto out;
    }
    print_layer4_drop_statis(map_fd);
    
    // tcp_port
    map_fd = get_pinned_map_fd(pin_root_path, textify(MAP_NAME(tcp_port)), &info); 
    if (map_fd < 0){
        err = map_fd;
        DEBUG_OUT("can't get tcp port map.");
        goto out;
    }
    print_port_drop_statis(map_fd, TCP_PORT_RULE); 
    
    // udp_port
    map_fd = get_pinned_map_fd(pin_root_path, textify(MAP_NAME(udp_port)), &info); 
    if (map_fd < 0){
        err = map_fd;
        DEBUG_OUT("can't get udp port map.");
        goto out;
    }
    print_port_drop_statis(map_fd, UDP_PORT_RULE);
    
    //ipv4
    map_fd = get_pinned_map_fd(pin_root_path, textify(MAP_NAME(ipv4)), &info); 
    if (map_fd < 0){
        err = map_fd;
        DEBUG_OUT("can't get ipv4 map.");
        goto out;
    }
    print_ipv4_drop_statis(map_fd);
    
    // ipv6
    map_fd = get_pinned_map_fd(pin_root_path, textify(MAP_NAME(ipv6)), &info); 
    if (map_fd < 0){
        err = map_fd;
        DEBUG_OUT("can't get ipv6 map.");
        goto out;
    }
    print_ipv6_drop_statis(map_fd);
    
    //total
    map_fd = get_pinned_map_fd(pin_root_path, textify(MAP_NAME(statis)), &info);
    if (map_fd < 0){
        err = map_fd;
        DEBUG_OUT("can't get total statis map.");
        goto out;
    }
    print_total_statis(map_fd);

out:
    if(map_fd >= 0){
        close(map_fd);
    }   
    
    return err;
}

//for version
//static struct prog_option version_options[] = { END_OPTIONS };

int do_version(const void *cfg, const char *pin_root_dir)
{
    fprintf(stderr, "%s version: %s\n", PROG_NAME, XDROP_VERSION);
    fprintf(stderr, "%s version: %s\n", PROG_KERN, XDROP_KERN_VERSION);
    return 0;
}

union all_opts {
    struct loadopt      load;
    struct unloadopt    unload;
    struct ipopt        ip;
    struct subnetopt    subnet;
    struct portopt      port;
    struct protoopt     proto;     
};

int do_help(const void *cfg, const char *pin_root_path)
{
    fprintf(stderr,
       "Usage: xdrop COMMAND [options]\n"
        "\n"
        "COMMAND can be one of:\n"
        "       load        - load xdrop on an interface\n"
        "       unload      - unload xdrop from an interface\n"
        "       port        - add a port to the black list\n"
        "       ip          - add an IP address to the black list\n"
        "       subnet      - add an subnet to the black list\n"
        "       proto       - add an protocal to the black list\n"
        "       statis      - show current xdrop statistics\n"
        "       help        - show this help message\n"
        "       version     - show version\n"
        "\n"
        "Use 'xdrop COMMAND --help' to see options for each command\n");
    return -1;
}

static const struct prog_command cmds[] = {
    DEFINE_COMMAND(load, "Load xdrop on an interface"),
    DEFINE_COMMAND(unload, "Unload xdrop from an interface"),
    DEFINE_COMMAND(ip, "Add or remove IP addresses from xdrop"),
    DEFINE_COMMAND(subnet, "Add or remove subnet from xdrop"),
    DEFINE_COMMAND(port, "Add or remove destination sports from xdrop"),
    DEFINE_COMMAND(proto, "Add or remove protocal from xdrop"),
    DEFINE_COMMAND_NODEF(statis, "Show xdrop statistics"),
    //DEFINE_COMMAND_NODEF(version, "Show version"),
    { .name = "help", .func = do_help, .no_cfg = true },
    { .name = "version", .func = do_version, .no_cfg = true },
    END_COMMANDS
};

int main(int argc, char* argv[])
{
    if (argc > 1) {
        return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
            sizeof(union all_opts), PROG_NAME);
       
    }

    return do_help(NULL, NULL);
}
