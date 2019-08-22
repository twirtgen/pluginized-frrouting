//
// Created by thomas on 20/08/19.
//

#ifndef FRR_UBPF_BGP_UBPF_API_PLUGINS_H
#define FRR_UBPF_BGP_UBPF_API_PLUGINS_H


#include <ubpf_tools/include/tools_ubpf_api.h>
#include <ubpf_tools/include/ebpf_mod_struct.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgp_ubpf_light_struct.h"

#include <bgpd/bgp_aspath.h>
#include <lib/table.h>


extern struct bgp_path_info_pair *get_cmp_prefixes(bpf_full_args_t *args, int pos_new, int pos_exist);

extern struct attr *get_attr_from_prefix(bpf_full_args_t *args, int pos_arg);

extern peer_ebpf_t *peer_from_prefix(bpf_full_args_t *args, int pos_arg);

extern peer_ebpf_t *peer_from_args(peer_ebpf_t *p) ;

extern struct prefix *get_raw_prefix_from_args(struct prefix *prefix);

extern bgp_peer_sort_t ebpf_peer_sort(peer_ebpf_t *peer);

extern struct bgp_path_info *get_bgp_path_info_from_args(bpf_full_args_t *args, int pos_arg);

extern struct bgp_path_info_extra *extra_from_prefix(bpf_full_args_t *args, int pos_arg);

extern struct bgp_maxpaths_cfg *get_maxpath_cfg(bpf_full_args_t *args, int pos_arg);

// void free_aspath_plugin(memory_pool_t *heap, struct aspath *plugin_aspath);

extern struct aspath *as_path_from_prefix(bpf_full_args_t *args, int pos_args);

extern struct aspath *get_aspath_from_attr_args(bpf_full_args_t *args, int pos_arg);

extern as_t get_as_from_attr(bpf_full_args_t *args, int pos_arg);

extern struct attr *get_attr_from_path_info(bpf_full_args_t *args, int pos_arg);

extern struct attr *get_attr_from_args(bpf_full_args_t *args, int pos_arg);

extern struct cluster_list *get_cluster_from_attr_path_info(bpf_full_args_t *args, int pos_arg);

extern int set_med_attr(bpf_full_args_t *args, int pos_args, uint32_t med);

extern int set_local_pref_attr(bpf_full_args_t *args, int pos_arg, uint32_t local_pref);

extern struct community *get_community_from_path_info(bpf_full_args_t *args, int pos_arg);

extern struct ecommunity *get_ecommunity_from_path_info(bpf_full_args_t *args, int pos_arg);

extern struct lcommunity *get_lcommunity_from_path_info(bpf_full_args_t *args, int pos_arg);

extern uint32_t *get_community_values_from_path_info(bpf_full_args_t *args, int pos_arg);

extern uint8_t *get_ecommunity_values_from_path_info(bpf_full_args_t *args, int pos_arg);

extern uint8_t *get_lcommunity_values_from_path_info(bpf_full_args_t *args, int pos_arg);

extern struct community *get_community_from_args(bpf_full_args_t *args, int pos_arg);

extern struct ecommunity *get_ecommunity_from_args(bpf_full_args_t *args, int pos_arg);

extern struct lcommunity *get_lcommunity_from_args(bpf_full_args_t *args, int pos_arg);

extern bgp_ebpf_t *get_bgp_instance(bpf_full_args_t *args, int pos_arg);

extern int set_path_eq(bpf_full_args_t *args, int pos_args, int val);

extern int del_community_val_form_args_attr(bpf_full_args_t *args, int pos_arg, uint32_t val);

extern int add_community_val_to_attr(bpf_full_args_t *args, int pos_arg, uint32_t val);

extern char *as_path_store_from_attr(bpf_full_args_t *args, int nb_arg, size_t *total_len);

extern int count_adj_rib_in_peer(unsigned long (*pcount)[AFI_MAX][SAFI_MAX], uint64_t *t_count);

extern int count_adj_rib_out_peer(unsigned long (*scount)[AFI_MAX][SAFI_MAX], uint64_t *t_count);

extern uint64_t count_loc_rib_from_peer_args(bpf_full_args_t *args, int pos_arg);

extern int nb_matched_routes(const struct route_table *table, struct prefix p);

extern int rib_lookup(afi_t afi, safi_t safi, struct prefix *p, struct prefix *store);

extern int bgp_table_range_nb_ebpf(afi_t afi, safi_t safi, struct prefix *p, uint8_t maxlen, uint8_t max_count) ;

extern unsigned int bpf_aspath_count_hops(const struct aspath *as);

extern int bpf_aspath_cmp_left(const struct aspath *as1, const struct aspath *as2);

extern bool bpf_aspath_cmp_left_confed(const struct aspath *as1, const struct aspath *as2);

extern unsigned int bpf_aspath_count_confeds(struct aspath *as);

extern int bpf_bgp_is_valid_label(mpls_label_t *label);

extern bool bpf_aspath_cmp(const void *as1, const void *as2);

extern int bpf_bgp_flag_check(bgp_ebpf_t *bgp, uint32_t flag);

#endif //FRR_UBPF_BGP_UBPF_API_PLUGINS_H
