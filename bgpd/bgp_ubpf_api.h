//
// Created by thomas on 19/08/19.
//

#ifndef FRR_UBPF_BGP_UBPF_API_H
#define FRR_UBPF_BGP_UBPF_API_H

#include "defaults.h"
#include "bgp_ubpf_light_struct.h"
#include <bgpd/bgpd.h>
#include <bgpd/bgp_aspath.h>
#include <ubpf_tools/include/ebpf_mod_struct.h>
#include <ubpf_tools/ubpf_context.h>

#include <lib/table.h>




static inline void copy_peer_ebpf(struct peer *peer, peer_ebpf_t *to) {

    to->bgp = peer->bgp;
    to->group = peer->group;
    to->as_type = peer->as_type;
    to->as = peer->as;
    to->local_as = peer->local_as;
    to->sort = peer->sort;
    to->change_local_as = peer->change_local_as;
    to->remote_id = peer->remote_id;
    to->local_id = peer->local_id;
    to->su_local = peer->su_local;
    to->su_remote = peer->su_remote;
    to->flags = peer->flags;
    to->sflags = peer->sflags;

    memcpy(to->scount, peer->scount, sizeof(peer->scount));
    memcpy(to->pcount, peer->pcount, sizeof(peer->pcount));


}

static inline void copy_bgp_to_ebpf(struct bgp *bgp, bgp_ebpf_t *to) {

    to->as = bgp->as;
    to->inst_type = bgp->inst_type;
    to->vrf_id = bgp->vrf_id;
    to->config = bgp->config;
    to->router_id = bgp->router_id;
    to->cluster_id = bgp->cluster_id;
    to->confed_id = bgp->confed_id;
    to->flags = bgp->flags;
    to->default_local_pref = bgp->default_local_pref;

}


struct bgp_path_info_pair *get_cmp_prefixes(context_t *vm_ctx, bpf_full_args_t *args, int pos_new, int pos_exist);

struct attr *get_attr_from_prefix(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

peer_ebpf_t *peer_from_prefix(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

bgp_peer_sort_t ebpf_peer_sort(context_t *vm_ctx, peer_ebpf_t *peer);

struct bgp_path_info *get_bgp_path_info_from_args(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

struct bgp_path_info_extra *extra_from_prefix(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

struct bgp_maxpaths_cfg *get_maxpath_cfg(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

void free_aspath_plugin(memory_pool_t *heap, struct aspath *plugin_aspath);

struct aspath *as_path_from_prefix(context_t *vm_ctx, bpf_full_args_t *args, int pos_args);

struct aspath *get_aspath_from_attr_args(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

as_t get_as_from_attr(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

struct attr *get_attr_from_path_info(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

struct attr *get_attr_from_args(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

struct cluster_list *get_cluster_from_attr_path_info(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

int set_med_attr(context_t *vm_ctx, bpf_full_args_t *args, int pos_args, uint32_t med);

int set_local_pref_attr(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg, uint32_t local_pref);

struct community *get_community_from_path_info(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

struct ecommunity *get_ecommunity_from_path_info(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

struct lcommunity *get_lcommunity_from_path_info(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

uint32_t *get_community_values_from_path_info(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

uint8_t *get_ecommunity_values_from_path_info(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

uint8_t *get_lcommunity_values_from_path_info(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

struct community *get_community_from_args(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

struct ecommunity *get_ecommunity_from_args(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

struct lcommunity *get_lcommunity_from_args(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

bgp_ebpf_t *get_bgp_instance(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

int set_path_eq(context_t *vm_ctx, bpf_full_args_t *args, int pos_args, int val);

int del_community_val_form_args_attr(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg, uint32_t val);

int add_community_val_to_attr(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg, uint32_t val);

char *as_path_store_from_attr(context_t *vm_ctx, bpf_full_args_t *args, int nb_arg, size_t *total_len);

int count_adj_rib_in_peer(context_t *vm_ctx, unsigned long (*pcount)[AFI_MAX][SAFI_MAX], uint64_t *t_count);

int count_adj_rib_out_peer(context_t *vm_ctx, unsigned long (*scount)[AFI_MAX][SAFI_MAX], uint64_t *t_count);

uint64_t count_loc_rib_from_peer_args(context_t *vm_ctx, bpf_full_args_t *args, int pos_arg);

int nb_matched_routes(context_t *vm_ctx, const struct route_table *table, struct prefix p);

int rib_lookup(context_t *vm_ctx, afi_t afi, safi_t safi, struct prefix *p, struct prefix *store);

int bgp_table_range_nb_ebpf(context_t *vm_ctx, afi_t afi, safi_t safi, struct prefix *p, uint8_t maxlen, uint8_t max_count) ;

unsigned int bpf_aspath_count_hops(context_t *ctx, const struct aspath *as);

int bpf_aspath_cmp_left(context_t *ctx, const struct aspath *as1, const struct aspath *as2);

bool bpf_aspath_cmp_left_confed(context_t *ctx, const struct aspath *as1, const struct aspath *as2);

unsigned int bpf_aspath_count_confeds(context_t *ctx, struct aspath *as);

int bpf_bgp_is_valid_label(context_t *ctx, mpls_label_t *label);

bool bpf_aspath_cmp(context_t *ctx, const void *as1, const void *as2);

int bpf_bgp_flag_check(context_t *vm_ctx, bgp_ebpf_t *bgp, uint32_t flag);

#endif //FRR_UBPF_BGP_UBPF_API_H