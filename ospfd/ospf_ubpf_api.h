//
// Created by thomas on 19/08/19.
//

#ifndef FRR_UBPF_OSPF_UBPF_API_H
#define FRR_UBPF_OSPF_UBPF_API_H

#include "ubpf_tools/include/tools_ubpf_api.h"
#include "ospf_lsa.h"
#include "ospf_lsdb.h"
#include "ospf_interface.h"
#include "ospf_neighbor.h"

struct ospf_interface *get_ospf_interface_list_from_area(api_args, int *nb);

struct interface *get_interface_from_ospf_interface(api_args);

struct ospf_lsa *get_ospf_lsa(api_args);

struct lsa_header *get_lsa_header_from_lsa(api_args, int force_length);

struct lsa_header *get_lsa_header_from_vertex(api_args, int force_length);

struct ospf_area *get_ospf_area(api_args);

struct ospf *get_ospf(api_args);

struct vertex *get_candidate_vertex_from_pqueue(api_args, int stat);

int set_ospf_area(api_args, struct ospf_area *area_copy);

int set_ospf_interface(api_args, struct ospf_interface *oi_copy);

int set_ospf_interface_area(api_args, struct ospf_interface *oi_copy, int index);

struct vertex *plugin_ospf_vertex_new(context_t *ctx, struct ospf_lsa *lsa, struct vertex **copy_v);

int plugin_ospf_lsa_has_link(context_t *ctx, struct lsa_header *w, struct lsa_header *v);

void plugin_trickle_up(api_args, int index);

struct ospf_lsa *plugin_ospf_lsa_lookup(context_t *vm_ctx, void **args);

void plugin_pqueue_enqueue(api_args, void *data);

struct ospf_lsa *plugin_ospf_lsa_lookup_by_id(context_t *vm_ctx, bpf_full_args_t *args,
                                              int pos_area, uint32_t type,
                                              struct in_addr id);

struct ospf_lsa *
plugin_ospf_lsa_install(context_t *ctx, struct ospf *ospf, struct ospf_interface *oi, struct ospf_lsa *lsa);

int plugin_ospf_flood_through_area(api_args, struct ospf_neighbor *inbr, struct ospf_lsa *lsa);

unsigned int plugin_ospf_nexthop_calculation(context_t *vm_ctx, void **tab_args);

static char my_link_info_set(struct stream **s, struct in_addr id,
                             struct in_addr data, uint8_t type, uint8_t tos,
                             uint16_t cost, uint32_t metric);

static uint16_t my_ospf_link_cost(struct ospf_interface *oi);

int plugin_lsa_link_broadcast_set(context_t *ctx, struct stream **s, struct ospf_interface *oi, uint32_t metric);

struct ospf_lsa *plugin_ospf_lsa_new_and_data(api_args, struct stream *s);

int my_get_lsah(context_t *ctx, struct ospf_lsa *lsa, struct lsa_header *lsah);

#endif //FRR_UBPF_OSPF_UBPF_API_H
