//
// Created by thomas on 21/02/19.
//

#ifndef FRR_UBPF_BGP_DECISION_STEPS_H
#define FRR_UBPF_BGP_DECISION_STEPS_H

#include <ubpf_tools/include/decision_process_manager.h>
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd.h"
#include "bgp_label.h"

extern uint64_t bgp_weight_check(bpf_full_args_t *args);

extern uint64_t bgp_local_pref(bpf_full_args_t *args);

extern uint64_t bgp_local_route(bpf_full_args_t *args);

extern uint64_t bgp_as_path_length(bpf_full_args_t *args);

extern uint64_t origin_check(bpf_full_args_t *args);

extern uint64_t med_check(bpf_full_args_t *args);

extern uint64_t bgp_peer_type(bpf_full_args_t *args);

extern uint64_t confed_check(bpf_full_args_t *args);

extern uint64_t bgp_igp_m(bpf_full_args_t *args);

extern uint64_t bgp_prefer_first_path(bpf_full_args_t *args);

extern uint64_t router_id_cmp(bpf_full_args_t *args);

extern uint64_t cluster_id_cmp(bpf_full_args_t *args);

extern uint64_t neighbor_addr_cmp(bpf_full_args_t *args);

#endif //FRR_UBPF_BGP_DECISION_STEPS_H
