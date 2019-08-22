//
// Created by thomas on 20/08/19.
//

#ifndef FRR_UBPF_BGP_UBPF_LIGHT_STRUCT_H
#define FRR_UBPF_BGP_UBPF_LIGHT_STRUCT_H

#include "bgpd.h"

typedef struct peer_ebpf {

    struct bgp *bgp;
    struct peer_group *group;

    int as_type;
    as_t as;
    as_t local_as;
    bgp_peer_sort_t sort;
    as_t change_local_as;

    /* Remote router ID. */
    struct in_addr remote_id;

    /* Local router ID. */
    struct in_addr local_id;
    union sockunion *su_local;  /* Sockunion of local address.  */
    union sockunion *su_remote; /* Sockunion of remote address.  */
    uint32_t flags;
    uint16_t sflags;

    // maybe induce overhead
    unsigned long scount[AFI_MAX][SAFI_MAX];
    unsigned long pcount[AFI_MAX][SAFI_MAX];


} peer_ebpf_t;

typedef struct bgp_ebpf {

    as_t as;
    enum bgp_instance_type inst_type;
    vrf_id_t vrf_id;
    uint16_t config;
    struct in_addr router_id;
    struct in_addr cluster_id;
    as_t confed_id;
    uint32_t flags;
    uint32_t default_local_pref;


} bgp_ebpf_t;


#endif //FRR_UBPF_BGP_UBPF_LIGHT_STRUCT_H
