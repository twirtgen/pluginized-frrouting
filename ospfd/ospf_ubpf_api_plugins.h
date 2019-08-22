//
// Created by thomas on 20/08/19.
//

#ifndef FRR_UBPF_OSPF_UBPF_API_PLUGINS_H
#define FRR_UBPF_OSPF_UBPF_API_PLUGINS_H

#include "ubpf_tools/include/tools_ubpf_api.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_flood.h"

#undef  api_args
#define api_args bpf_full_args_t *args, int pos_arg

extern struct ospf_interface *get_ospf_interface_list_from_area(api_args, int *nb);

extern struct interface *get_interface_from_ospf_interface(api_args);

extern struct ospf_lsa *get_ospf_lsa(api_args);

extern struct lsa_header *get_lsa_header_from_lsa(api_args, int force_length);

extern struct lsa_header *get_lsa_header_from_vertex(api_args, int force_length);

extern struct ospf_area *get_ospf_area(api_args);

extern struct ospf *get_ospf(api_args);

extern struct vertex *get_candidate_vertex_from_pqueue(api_args, int stat);

extern int set_ospf_area(api_args, struct ospf_area *area_copy);

extern int set_ospf_interface(api_args, struct ospf_interface *oi_copy);

extern int set_ospf_interface_area(api_args, struct ospf_interface *oi_copy, int index);

extern struct vertex *plugin_ospf_vertex_new(struct ospf_lsa *lsa, struct vertex **copy_v);

extern int plugin_ospf_lsa_has_link(struct lsa_header *w, struct lsa_header *v);

extern void plugin_trickle_up(api_args, int index);

extern struct ospf_lsa *plugin_ospf_lsa_lookup(void **args);

extern void plugin_pqueue_enqueue(api_args, void *data);

extern struct ospf_lsa *plugin_ospf_lsa_lookup_by_id(bpf_full_args_t *args,
                                              int pos_area, uint32_t type,
                                              struct in_addr id);

extern struct ospf_lsa *plugin_ospf_lsa_install(struct ospf *ospf, struct ospf_interface *oi, struct ospf_lsa *lsa);

extern int plugin_ospf_flood_through_area(api_args, struct ospf_neighbor *inbr, struct ospf_lsa *lsa);

extern unsigned int plugin_ospf_nexthop_calculation(void **tab_args);

extern int plugin_lsa_link_broadcast_set(struct stream **s, struct ospf_interface *oi, uint32_t metric);

extern struct ospf_lsa *plugin_ospf_lsa_new_and_data(api_args, struct stream *s);

extern int my_get_lsah(struct ospf_lsa *lsa, struct lsa_header *lsah);

#endif //FRR_UBPF_OSPF_UBPF_API_PLUGINS_H
