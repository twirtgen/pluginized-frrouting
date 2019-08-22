//
// Created by thomas on 19/08/19.
//


#include "bgp_ubpf_api.h"
#include "ubpf_tools/include/tools_ubpf_api.h"
#include "bgpd/bgp_label.h"

#include <bgpd/bgp_route.h>
#include <bgpd/bgp_attr.h>
#include <bgpd/bgp_community.h>
#include <bgpd/bgp_ecommunity.h>
#include <bgpd/bgp_lcommunity.h>

#include <json-c/json_object.h>


struct bgp_path_info_pair *get_cmp_prefixes(context_t *vm_ctx, bpf_full_args_t *args, int pos_new, int pos_exist) {

    struct bgp_path_info_pair *p;
    struct bgp_path_info *new, *new_p;
    struct bgp_path_info *old, *old_p;

    if (!safe_args(args, pos_new, BPF_ARG_PATH_INFO) || !safe_args(args, pos_exist, BPF_ARG_PATH_INFO))
        return NULL;

    if (vm_ctx->args_type != ARGS_DECISION_STEPS) return NULL;

    new_p = get_arg(args, pos_new, struct bgp_path_info *);
    old_p = get_arg(args, pos_exist, struct bgp_path_info *);

    if (!new_p || !old_p) return NULL;

    p = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct bgp_path_info_pair *));
    if (!p) return NULL;

    new = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct bgp_path_info));
    if (!new) {
        my_free(&vm_ctx->p->heap.mp, p);
        return NULL;
    }
    old = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct bgp_path_info));
    if (!old) {
        my_free(&vm_ctx->p->heap.mp, p);
        my_free(&vm_ctx->p->heap.mp, new);
        return NULL;
    }

    *new = *new_p;
    *old = *old_p;

    p->new = new;
    p->old = old;

    return p;
}

struct attr *get_attr_from_prefix(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {

    struct attr *attr, *plug_attr;

    /* check matching arg */
    if (!safe_args(args, pos_arg, BPF_ARG_PATH_INFO)) return NULL;
    /* is function allowed to call this helper */
    if (vm_ctx->args_type != ARGS_DECISION_STEPS) return NULL;

    /* get the argument */
    attr = get_arg(args, pos_arg, struct bgp_path_info *)->attr; // CHECK THIS

    /* copy data to plugin space */
    plug_attr = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct attr));
    if (!plug_attr) return NULL;
    *plug_attr = *attr;

    return plug_attr;
}


peer_ebpf_t *peer_from_prefix(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {
    struct bgp_path_info *prefix_info;
    struct peer_ebpf *peer;

    if (vm_ctx->args_type != ARGS_DECISION_STEPS) return NULL;

    if (!safe_args(args, pos_arg, BPF_ARG_PATH_INFO)) return NULL;
    prefix_info = get_arg(args, pos_arg, struct bgp_path_info *);

    peer = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct peer_ebpf));
    if (!peer) return NULL;

    copy_peer_ebpf(prefix_info->peer, peer);

    return peer;
}

/* copied from bgpd.c */
static bgp_peer_sort_t ebpf_peer_calc_sort(peer_ebpf_t *peer) {

    struct bgp *bgp;

    bgp = peer->bgp;

    /* Peer-group */
    if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
        if (peer->as_type == AS_INTERNAL)
            return BGP_PEER_IBGP;

        else if (peer->as_type == AS_EXTERNAL)
            return BGP_PEER_EBGP;

        else if (peer->as_type == AS_SPECIFIED && peer->as) {
            assert(bgp);
            return (bgp->as == peer->as ? BGP_PEER_IBGP
                                        : BGP_PEER_EBGP);
        } else {
            struct peer *peer1;

            assert(peer->group);
            peer1 = listnode_head(peer->group->peer);

            if (peer1)
                return peer1->sort;
        }
        return BGP_PEER_INTERNAL;
    }

    /* Normal peer */
    if (bgp && CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
        if (peer->local_as == 0)
            return BGP_PEER_INTERNAL;

        if (peer->local_as == peer->as) {
            if (bgp->as == bgp->confed_id) {
                if (peer->local_as == bgp->as)
                    return BGP_PEER_IBGP;
                else
                    return BGP_PEER_EBGP;
            } else {
                if (peer->local_as == bgp->confed_id)
                    return BGP_PEER_EBGP;
                else
                    return BGP_PEER_IBGP;
            }
        }

        if (bgp_confederation_peers_check(bgp, peer->as))
            return BGP_PEER_CONFED;

        return BGP_PEER_EBGP;
    } else {
        if (peer->as_type == AS_UNSPECIFIED) {
            /* check if in peer-group with AS information */
            if (peer->group
                && (peer->group->conf->as_type != AS_UNSPECIFIED)) {
                if (peer->group->conf->as_type
                    == AS_SPECIFIED) {
                    if (peer->local_as
                        == peer->group->conf->as)
                        return BGP_PEER_IBGP;
                    else
                        return BGP_PEER_EBGP;
                } else if (peer->group->conf->as_type
                           == AS_INTERNAL)
                    return BGP_PEER_IBGP;
                else
                    return BGP_PEER_EBGP;
            }
            /* no AS information anywhere, let caller know */
            return BGP_PEER_UNSPECIFIED;
        } else if (peer->as_type != AS_SPECIFIED)
            return (peer->as_type == AS_INTERNAL ? BGP_PEER_IBGP
                                                 : BGP_PEER_EBGP);

        return (peer->local_as == 0
                ? BGP_PEER_INTERNAL
                : peer->local_as == peer->as ? BGP_PEER_IBGP
                                             : BGP_PEER_EBGP);
    }
}

bgp_peer_sort_t ebpf_peer_sort(context_t *vm_ctx, peer_ebpf_t *peer) {
    UNUSED(vm_ctx);
    peer->sort = ebpf_peer_calc_sort(peer);
    return peer->sort;
}

struct bgp_path_info *get_bgp_path_info_from_args(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {

    struct bgp_path_info *from_args, *to_plugin;


    if (!safe_args(args, pos_arg, BPF_ARG_PATH_INFO)) return NULL;

    switch (vm_ctx->args_type) {
        case ARGS_DECISION_STEPS:
            break;
        default:
            return NULL;
    }

    from_args = get_arg(args, pos_arg, struct bgp_path_info *);
    to_plugin = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct bgp_path_info));
    if (to_plugin == NULL) return NULL;

    *to_plugin = *from_args;
    return to_plugin;
}

struct bgp_path_info_extra *extra_from_prefix(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {

    struct bgp_path_info_extra *extra;
    struct bgp_path_info *path_info;

    if (vm_ctx->args_type != ARGS_DECISION_STEPS) return NULL;
    if (!safe_args(args, pos_arg, BPF_ARG_PATH_INFO)) return NULL;

    path_info = get_arg(args, pos_arg, struct bgp_path_info *);
    if (!path_info->extra) return NULL;

    extra = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct bgp_path_info_extra));
    if (!extra) return NULL;

    *extra = *path_info->extra;
    return extra;


}

struct bgp_maxpaths_cfg *get_maxpath_cfg(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {

    struct bgp_maxpaths_cfg *mp, *mp_plug;

    if (!safe_args(args, pos_arg, BPF_ARG_PATH_INFO)) return NULL;
    mp = get_arg(args, pos_arg, struct bgp_maxpaths_cfg *);

    if (!mp) return NULL;

    switch (vm_ctx->args_type) {
        case ARGS_DECISION_STEPS:
            break;
        default:
            return NULL;
    }

    mp_plug = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct bgp_maxpaths_cfg));
    if (mp_plug == NULL) return NULL;

    *mp_plug = *mp;
    return mp_plug;
}

void free_aspath_plugin(memory_pool_t *heap, struct aspath *plugin_aspath) {

    struct assegment *seg, *p_seg;

    seg = plugin_aspath->segments;

    while(seg) {
        p_seg = seg;
        if(seg->as) my_free(heap, seg->as);
        seg = seg->next;
        my_free(heap, p_seg);
    }

    my_free(heap, plugin_aspath);
}


static struct aspath *alloc_aspath(memory_pool_t *heap, struct aspath *host_path) {

    struct aspath *plug_aspath;
    struct assegment *seg, *curr_seg_plugin, *curr_seg_plugin_previous;
    int i;

    if ((host_path == NULL) || (host_path->segments == NULL)) {
        fprintf(stderr, "NULL\n");
        return 0;
    }

    curr_seg_plugin = NULL;

    plug_aspath = my_malloc(heap, sizeof(struct aspath));
    if (!plug_aspath) return NULL;


    plug_aspath = my_malloc(heap, sizeof(struct aspath));
    if(!plug_aspath) return NULL;

    seg = host_path->segments;
    while (seg) {
        curr_seg_plugin_previous = curr_seg_plugin;
        curr_seg_plugin = my_malloc(heap, sizeof(struct assegment));
        if(!curr_seg_plugin) {
            free_aspath_plugin(heap, plug_aspath);
            return NULL;
        }
        if(curr_seg_plugin_previous) curr_seg_plugin_previous->next = curr_seg_plugin;
        *curr_seg_plugin = *seg;
        curr_seg_plugin->as = NULL;
        curr_seg_plugin->next = NULL;
        curr_seg_plugin->as = my_malloc(heap, sizeof(as_t) * seg->length);
        if(!curr_seg_plugin->as) {
            free_aspath_plugin(heap, plug_aspath);
        }

        for (i = 0; i < seg->length; i++) {
            curr_seg_plugin->as[i] = seg->as[i];
        }
        seg = seg->next;
    }

    return plug_aspath;
}

struct aspath *as_path_from_prefix(context_t *vm_ctx, bpf_full_args_t *args, int pos_args) {

    struct bgp_path_info *pinfo;

    if (!safe_args(args, pos_args, BPF_ARG_PREFIX)) return NULL;
    pinfo = get_arg(args, pos_args, struct bgp_path_info *);

    if (vm_ctx->args_type != ARGS_DECISION_STEPS) return NULL;

    return alloc_aspath(&vm_ctx->p->heap.mp, pinfo->attr->aspath);

}


struct aspath *get_aspath_from_attr_args(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {

    struct aspath *aspath;

    if (!safe_args(args, pos_arg, BPF_ARG_ATTR)) return NULL;
    aspath = get_arg(args, pos_arg, struct aspath *);

    switch (vm_ctx->args_type) {
        case ARGS_BGP_PROC_OUTPUT_FILTER:
        case ARGS_BGP_PROC_INPUT_FILTER:
            break;
        default:
            return NULL;
    }

    return alloc_aspath(&vm_ctx->p->heap.mp, aspath);
}

/**
 * Get the AS number from which the path has been advertised
 */
as_t get_as_from_attr(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {

    struct attr *attr;
    struct aspath *aspath;
    int i;
    struct assegment *seg;

    if (!safe_args(args, pos_arg, BPF_ARG_ATTR)) return 0;

    attr = get_arg(args, pos_arg, struct attr *);
    aspath = attr->aspath;

    switch (vm_ctx->args_type) {
        case ARGS_BGP_PROC_OUTPUT_FILTER:
        case ARGS_BGP_PROC_INPUT_FILTER:
            break;
        default:
            return 0;
    }

    if ((aspath == NULL) || (aspath->segments == NULL)) {
        fprintf(stderr, "NULL\n");
        return 0;
    }

    seg = aspath->segments;
    while (seg) {
        for (i = 0; i < seg->length; i++) {
            return seg->as[i];
        }
        seg = seg->next;
    }
    return 0;
}


struct attr *get_attr_from_path_info(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {

    if (!safe_args(args, pos_arg, BPF_ARG_PATH_INFO)) return NULL;

    struct bgp_path_info *pinfo;
    struct attr *attr;

    pinfo = get_arg(args, pos_arg, struct bgp_path_info *);

    attr = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct attr));
    if (!attr) return NULL;

    *attr = *pinfo->attr;

    return attr;
}

struct attr *get_attr_from_args(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {
    struct attr *attr, *a;

    if (!safe_args(args, pos_arg, BPF_ARG_ATTR)) return NULL;
    attr = get_arg(args, pos_arg, struct attr *);

    a = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct attr));
    if (!a) return NULL;

    switch (vm_ctx->args_type) {
        case ARGS_BGP_PROC_INPUT_FILTER:
        case ARGS_BGP_PROC_OUTPUT_FILTER:
        case ARGS_ZEBRA_ANNOUNCE_PREFIX:
        case ARGS_ZEBRA_RM_PREFIX:
            break;
        default:
            fprintf(stderr, "DEFAULT NULL; (ATTR ARGS %d)\n", vm_ctx->args_type);
            return NULL;
    }

    *a = *attr;
    return a;
}

struct cluster_list *get_cluster_from_attr_path_info(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {

    struct bgp_path_info *pinfo;
    struct cluster_list *clust;

    if (!safe_args(args, pos_arg, BPF_ARG_PATH_INFO)) return NULL;
    pinfo = get_arg(args, pos_arg, struct bgp_path_info *);

    if (!pinfo->attr->cluster) return NULL;

    switch (vm_ctx->args_type) {
        case ARGS_DECISION_STEPS:
            break;
        default:
            return NULL;
    }

    clust = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct cluster_list));
    if (!clust) return NULL;

    *clust = *pinfo->attr->cluster;

    return clust;

}

int set_med_attr(context_t *vm_ctx, bpf_full_args_t *args, int pos_args, uint32_t med) {
    struct attr *a;

    if(!safe_args(args, pos_args, BPF_ARG_ATTR)) return -1;
    a = get_arg(args, pos_args, struct attr *);

    switch (vm_ctx->args_type) {
        case ARGS_BGP_PROC_INPUT_FILTER:
        case ARGS_BGP_PROC_OUTPUT_FILTER:
            break;
        default:
            return -1;
    }


    a->med = med;
    return 0;
}

int set_local_pref_attr(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg, uint32_t local_pref) {
    struct attr *a;

    if (!safe_args(args, pos_arg, BPF_ARG_ATTR)) return -1;
    a = get_arg(args, pos_arg, struct attr *);

    switch (vm_ctx->args_type) {
        case ARGS_BGP_PROC_INPUT_FILTER:
        case ARGS_BGP_PROC_OUTPUT_FILTER:
            break;
        default:
            return -1;
    }
    a->local_pref = local_pref;

    return 0;
}

#define community_fun(community_type, fun_name) \
struct community_type *fun_name(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {\
    struct bgp_path_info *selected;\
    struct community_type *cm;\
\
    switch(vm_ctx->args_type) {\
        case ARGS_DECISION_STEPS:\
        case ARGS_BGP_PROC_INPUT_FILTER:\
        case ARGS_BGP_PROC_OUTPUT_FILTER:\
            break;\
        default:\
            return NULL;\
    }\
    if(!safe_args(args, pos_arg, BPF_ARG_PATH_INFO)) return NULL;\
    selected = get_arg(args, pos_arg, struct bgp_path_info *);\
\
    if (!selected->attr->community_type) return NULL;\
\
    cm = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct community_type));\
    if (!cm) return NULL;\
\
    *cm = *selected->attr->community_type;\
    return cm;\
}

community_fun(community, get_community_from_path_info)

community_fun(ecommunity, get_ecommunity_from_path_info)

community_fun(lcommunity, get_lcommunity_from_path_info)

#define val_community_fun(val_type, fun_name, community_type)\
val_type *fun_name(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {\
    val_type *cm;\
    struct bgp_path_info *pinfo;\
    size_t tot_len;\
\
    if (vm_ctx->args_type != ARGS_DECISION_STEPS) return NULL;\
    if (!safe_args(args, pos_arg, BPF_ARG_PATH_INFO)) return NULL;\
\
    pinfo = get_arg(args, pos_arg, struct bgp_path_info *);\
    tot_len = pinfo->attr->community_type->size * sizeof(val_type);\
    if (!pinfo->attr->community_type) return NULL;\
    cm = my_malloc(&vm_ctx->p->heap.mp, sizeof(val_type) * pinfo->attr->community_type->size);\
    if(!cm) return NULL;\
\
    memcpy(cm, pinfo->attr->community_type->val, tot_len);\
\
    return cm;\
}


val_community_fun(uint32_t, get_community_values_from_path_info, community)

val_community_fun(uint8_t, get_ecommunity_values_from_path_info, ecommunity)

val_community_fun(uint8_t, get_lcommunity_values_from_path_info, lcommunity)


#define defun_community_args(type_community, fun_name, type, len)\
struct type_community *fun_name(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {\
    struct type_community *c;\
    struct attr *attr;\
    size_t tot_len;\
    type *com_val;\
    if (!safe_args(args, pos_arg, BPF_ARG_ATTR)) return NULL;\
    attr = get_arg(args, pos_arg, struct attr *);\
    \
    if(!attr->type_community) return NULL;\
    c = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct type_community));\
    if(!c) return NULL;\
    *c = *attr->type_community;\
    \
    switch (vm_ctx->args_type) {\
        case ARGS_BGP_PROC_INPUT_FILTER:\
        case ARGS_BGP_PROC_OUTPUT_FILTER: {\
            break;\
        }\
        default:\
            return NULL;\
    }\
    tot_len = len * attr->type_community->size;\
    if (tot_len != 0) {\
        com_val = my_malloc(&vm_ctx->p->heap.mp, tot_len);\
        if (!com_val) {\
            my_free(&vm_ctx->p->heap.mp, c);\
            return NULL;\
        }\
        memcpy(com_val, attr->type_community->val, tot_len);\
        c->val = com_val;\
    } else {\
        c->val = NULL;\
    }\
    return c;\
}

defun_community_args(community, get_community_from_args, uint32_t, sizeof(uint32_t))

defun_community_args(ecommunity, get_ecommunity_from_args, uint8_t, ECOMMUNITY_SIZE)

defun_community_args(lcommunity, get_lcommunity_from_args, uint8_t, LCOMMUNITY_SIZE)


bgp_ebpf_t *get_bgp_instance(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {

    bgp_ebpf_t *from_cpy, *plug_bgp;

    if (!safe_args(args, pos_arg, BPF_ARG_BGP)) {
        return NULL;
    }

    /* todo better handle authorizations */
    switch (vm_ctx->args_type) {
        case ARGS_DECISION_STEPS:
        case ARGS_RCV_UPDATE_PROCEDURE:
        case ARGS_BGP_DECISION_PROCESS:
        case ARGS_ZEBRA_ANNOUNCE_PREFIX:
        case ARGS_ZEBRA_RM_PREFIX:
            break;
        default:
            return NULL;
    }

    from_cpy = get_arg(args, pos_arg, bgp_ebpf_t *);
    plug_bgp = my_malloc(&vm_ctx->p->heap.mp, sizeof(bgp_ebpf_t));
    if (!plug_bgp) return NULL;

    *plug_bgp = *from_cpy;

    return plug_bgp;

}

int set_path_eq(context_t *vm_ctx, bpf_full_args_t *args, int pos_args, int val) {

    int *paths_eq;
    if(!safe_args(args, pos_args, BPF_ARG_INT_MOD)) return -1;

    paths_eq = get_arg(args, pos_args, int *);

    if (vm_ctx->args_type != ARGS_DECISION_STEPS) return -1;
    if (val != 0 && val != 1) return -1;

    *paths_eq = val;

    return 0;

}

int del_community_val_form_args_attr(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg, uint32_t val) {

    struct community *c;
    uint32_t hton_val;

    if (!safe_args(args, pos_arg, BPF_ARG_ATTR)) return -1;
    c = get_arg(args, pos_arg, struct attr *)->community;

    hton_val = htonl(val);

    switch (vm_ctx->args_type) {
        case ARGS_BGP_PROC_INPUT_FILTER:
        case ARGS_BGP_PROC_OUTPUT_FILTER:
            break;
        default:
            return -1;
    }

    if (community_include(c, val)) {
        community_del_val(c, &hton_val);
        return 0;
    } else {
        return -1;
    }


}

static int community_compare(const void *a1, const void *a2) {
    uint32_t v1;
    uint32_t v2;

    memcpy(&v1, a1, sizeof(uint32_t));
    memcpy(&v2, a2, sizeof(uint32_t));
    v1 = ntohl(v1);
    v2 = ntohl(v2);

    if (v1 < v2)
        return -1;
    if (v1 > v2)
        return 1;
    return 0;
}

int add_community_val_to_attr(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg, uint32_t val) {

    struct community *com;
    struct attr *attr;

    if (!safe_args(args, pos_arg, BPF_ARG_ATTR)) return -1;

    attr = get_arg(args, pos_arg, struct attr *);

    switch (vm_ctx->args_type) {
        case ARGS_BGP_PROC_INPUT_FILTER:
        case ARGS_BGP_PROC_OUTPUT_FILTER:
            break;
        default:
            return -1;
    }

    if (!attr->community) {
        com = XCALLOC(MTYPE_COMMUNITY, sizeof(struct community));
        com->json = NULL;
        community_add_val(com, val);
        community_intern(com);
        attr->community = com;
    } else {
        com = attr->community;
        if (!community_include(com, val))
            community_add_val(com, val);
    }

    qsort(com->val, com->size, sizeof(uint32_t), community_compare);

    return 0;


}

char *as_path_store_from_attr(context_t *vm_ctx, bpf_full_args_t *args, int nb_arg, size_t *total_len) {

    struct aspath *aspath;
    char *buf;

    if (!safe_args(args, nb_arg, BPF_ARG_ATTR)) return NULL;
    aspath = get_arg(args, nb_arg, struct attr *)->aspath;
    aspath_str_update(aspath, 0);

    buf = my_malloc(&vm_ctx->p->heap.mp, (aspath->str_len + 1) * sizeof(char));
    if (!buf) return NULL;

    strncpy(buf, aspath->str, aspath->str_len);
    buf[aspath->str_len] = 0;
    if (total_len) *total_len = aspath->str_len;

    return buf;
}



int count_adj_rib_in_peer(context_t *vm_ctx, unsigned long (*pcount)[AFI_MAX][SAFI_MAX], uint64_t *t_count) {

    UNUSED(vm_ctx);

    uint64_t count = 0;
    int i, j;

    for (i = AFI_IP; i < AFI_MAX; i++) {
        for (j = SAFI_UNICAST; j < SAFI_MAX; j++) {
            if ((*pcount)[i][j]) {
                count += (*pcount)[i][j];
            }
        }
    }
    *t_count = count;
    return 1;
}

int count_adj_rib_out_peer(context_t *vm_ctx, unsigned long (*scount)[AFI_MAX][SAFI_MAX], uint64_t *t_count) {
    return count_adj_rib_in_peer(vm_ctx, scount, t_count);
}

uint64_t count_loc_rib_from_peer_args(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg) {

    UNUSED(vm_ctx);

    struct bgp *bgp;
    uint64_t count = 0;

    if(!safe_args(args, pos_arg, BPF_ARG_PEER)) return 0;
    bgp = get_arg(args, pos_arg, peer_ebpf_t *)->bgp;

    int i, j;

    for (i = AFI_IP; i < AFI_MAX; i++) {
        for (j = SAFI_UNICAST; j < SAFI_MAX; j++) {
            count += bgp->rib[i][j]->route_table->count;
        }
    }

    return count;
}


/* nb route to reach p */
int nb_matched_routes(context_t *vm_ctx, const struct route_table *table, struct prefix p) {
    UNUSED(vm_ctx);
    struct route_node *node;
    int count = 0;

    node = table->top;

    /* Walk down tree */
    while (node && node->p.prefixlen <= p.prefixlen
           && prefix_match(&node->p, &p)) {
        if (node->info) {
            count++;
        }

        if (node->p.prefixlen == p.prefixlen)
            break;

        node = node->link[prefix_bit(&p.u.prefix, node->p.prefixlen)];
    }

    return count;
}

/* should ideally be done in eBPF but induces huge memory latency overhead */
static struct route_node *route_node_match_lowest(context_t *vm_ctx, const struct route_table *table,
                                                  union prefixconstptr pu) {
    UNUSED(vm_ctx);
    const struct prefix *p = pu.p;
    struct route_node *node;

    node = table->top;

    /* Walk down tree.  If there is matched route then store it to
       matched. */
    while (node && node->p.prefixlen <= p->prefixlen
           && prefix_match(&node->p, p)) {
        if (node->info) {
            return node;
        }

        node = node->link[prefix_bit(&p->u.prefix, node->p.prefixlen)];
    }

    return NULL;
}


/* lowest prefix to reach p */
int rib_lookup(context_t *vm_ctx, afi_t afi, safi_t safi, struct prefix *p, struct prefix *store) {

    // assert(0 && "To be refactored");

    struct route_node *retrieved;
    struct bgp *bgp;
    struct listnode *node, *nnode;

    if (afi <= 0 || safi <= 0 || afi >= AFI_MAX || safi >= SAFI_MAX) return -1;


    for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
        if (bgp) {
            retrieved = route_node_match_lowest(vm_ctx, bgp->rib[afi][safi]->route_table, p);
            if (retrieved) {
                if (store) *store = retrieved->p;
                return 0;
            }
        }
    }

    return -1;
}

/* how much specific prefix has p  */
int bgp_table_range_nb_ebpf(context_t *vm_ctx, afi_t afi, safi_t safi, struct prefix *p, uint8_t maxlen, uint8_t max_count) {

    UNUSED(vm_ctx);
    struct bgp *bgp;
    struct listnode *node, *nnode;
    int rt;

    assert(family2afi(p->family) == afi);

    for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
        if (bgp) {
            rt = bgp_table_range_nb(bgp->rib[afi][safi], p, maxlen, max_count);
            if (rt > 0) return rt;
        }
    }

    return 0;
}

unsigned int bpf_aspath_count_hops(context_t *ctx, const struct aspath *as) {
    UNUSED(ctx);
    return aspath_count_hops(as);
}

int bpf_aspath_cmp_left(context_t *ctx, const struct aspath *as1, const struct aspath *as2) {
    UNUSED(ctx);
    return aspath_cmp_left(as1, as2);
}

bool bpf_aspath_cmp_left_confed(context_t *ctx, const struct aspath *as1, const struct aspath *as2) {
    UNUSED(ctx);
    return aspath_cmp_left_confed(as1, as2);
}

unsigned int bpf_aspath_count_confeds(context_t *ctx, struct aspath *as) {
    UNUSED(ctx);
    return aspath_count_confeds(as);
}

int bpf_bgp_is_valid_label(context_t *ctx, mpls_label_t *label) {
    UNUSED(ctx);
    return bgp_is_valid_label(label);
}

bool bpf_aspath_cmp(context_t *ctx, const void *as1, const void *as2){
    UNUSED(ctx);
    return aspath_cmp(as1, as2);
}

int bpf_bgp_flag_check(context_t *vm_ctx, bgp_ebpf_t *bgp, uint32_t flag) {
    UNUSED(vm_ctx);
    return CHECK_FLAG(bgp->flags, flag);
}
