//
// Created by thomas on 21/02/19.
//

#include <stdint.h>

#include "lib/if.h"
#include "lib/prefix.h"
#include "lib/zebra.h"
#include "bgpd.h"
#include "bgp_attr.h"
#include "bgp_route.h"
#include "bgp_aspath.h"
#include "bgp_label.h"
#include "mpls.h"
#include "bgp_attr_evpn.h"

#include "ubpf_tools/include/public.h"
#include "ubpf_tools/include/ebpf_mod_struct.h"
#include "bgp_decision_steps.h"
#include "bgp_ubpf_api.h"

static inline uint32_t bgp_med_value(struct attr *attr, bgp_ebpf_t *bgp) { // TODO CHECK HERE ATTR
    if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
        return attr->med;
    else {
        if (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST))
            return BGP_MED_MAX;
        else
            return 0;
    }
}

DEFFUN_VM(bgp_weight_check, uint64_t, (bpf_full_args_t * args), BGP_DECISION_WEIGHT, args, sizeof(bpf_full_args_t *), {

    /* 1. Weight Check. */

    uint32_t new_weight;
    uint32_t exist_weight;

    new_weight = ((struct bgp_path_info *) (args)->args[2].arg)->attr->weight ;
    exist_weight = ((struct bgp_path_info *) (args)->args[1].arg)->attr->weight ;

    if (new_weight > exist_weight) {
        RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
    }

    if (new_weight < exist_weight) {
        RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
    }

    RETVAL_VM(BGP_DECISION_LOCAL_PREF, 0, args, sizeof(bpf_full_args_t *)); // MOVE TO THE NEXT STEP
})

DEFFUN_VM(bgp_local_pref, uint64_t, (bpf_full_args_t *args), BGP_DECISION_LOCAL_PREF, args, sizeof(bpf_full_args_t *), {

    uint32_t new_pref, exist_pref;
    struct attr *attr_new, *attr_exist;

    new_pref = exist_pref = ((bgp_ebpf_t *) (args)->args[3].arg)->default_local_pref; //->bgp->default_local_pref;
    attr_exist = ((struct bgp_path_info *) (args)->args[1].arg)->attr;
    attr_new = ((struct bgp_path_info *) (args)->args[2].arg)->attr;

    if (attr_new->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
        new_pref = attr_new->local_pref;
    if (attr_exist->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
        exist_pref = attr_exist->local_pref;

    if (new_pref > exist_pref) {
        RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
    }

    if (new_pref < exist_pref) {
        RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
    }

    RETVAL_VM(BGP_DECISION_LOCAL_ROUTE, 0, args, sizeof(bpf_full_args_t *));
})

DEFFUN_VM(bgp_local_route, uint64_t, (bpf_full_args_t *args), BGP_DECISION_LOCAL_ROUTE, args, sizeof(bpf_full_args_t *), {

    struct bgp_path_info *new, *exist;

    exist = (args)->args[1].arg;
    new = (args)->args[2].arg;

    if (!(new->sub_type == BGP_ROUTE_NORMAL ||
          new->sub_type == BGP_ROUTE_IMPORTED)) {
        RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
    }

    if (!(exist->sub_type == BGP_ROUTE_NORMAL ||
          exist->sub_type == BGP_ROUTE_IMPORTED)) {
        RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
    }

    RETVAL_VM(BGP_DECISION_ASPATH, 0, args, sizeof(bpf_full_args_t *));
})

DEFFUN_VM(bgp_as_path_length, uint64_t, (bpf_full_args_t * args), BGP_DECISION_ASPATH, args, sizeof(bpf_full_args_t *), {

    bgp_ebpf_t *bgp;
    struct bgp_path_info *new, *exist;

    exist = (args)->args[1].arg;
    new = (args)->args[2].arg;
    bgp = (args)->args[3].arg;

    if (!CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE)) {
        int exist_hops = aspath_count_hops(exist->attr->aspath);
        int exist_confeds = aspath_count_confeds(exist->attr->aspath);

        if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED)) {
            int aspath_hops;

            aspath_hops = aspath_count_hops(new->attr->aspath);
            aspath_hops += aspath_count_confeds(new->attr->aspath);

            if (aspath_hops < (exist_hops + exist_confeds)) {
                RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
            }

            if (aspath_hops > (exist_hops + exist_confeds)) {
                RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
            }
        } else {
            int newhops = aspath_count_hops(new->attr->aspath);

            if (newhops < exist_hops) {
                RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
            }

            if (newhops > exist_hops) {
                RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
            }
        }
    }
    RETVAL_VM(BGP_DECISION_ORIGIN_CHECK, 0, args, sizeof(bpf_full_args_t *));
})

DEFFUN_VM(origin_check, uint64_t, (bpf_full_args_t *args), BGP_DECISION_ORIGIN_CHECK, args, sizeof(bpf_full_args_t), {

    struct bgp_path_info *new, *exist;

    exist = (args)->args[1].arg;
    new = (args)->args[2].arg;

    if (new->attr->origin < exist->attr->origin) {
        RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t));
    }

    if (new->attr->origin > exist->attr->origin) {
        RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t));
    }
    RETVAL_VM(BGP_DECISION_MED_CHECK, 0, args, sizeof(bpf_full_args_t));
})

DEFFUN_VM(med_check, uint64_t, (bpf_full_args_t *args), BGP_DECISION_MED_CHECK, args, sizeof(bpf_full_args_t), {

    bgp_ebpf_t *bgp;
    struct bgp_path_info *new, *exist;

    exist = (args)->args[1].arg;
    new = (args)->args[2].arg;
    bgp = (args)->args[3].arg;

    int internal_as_route, confed_as_route;
    struct attr *newattr, *existattr;
    uint32_t new_med, exist_med;

    newattr = new->attr;
    existattr = exist->attr;

    internal_as_route = (aspath_count_hops(newattr->aspath) == 0
                         && aspath_count_hops(existattr->aspath) == 0);
    confed_as_route = (aspath_count_confeds(newattr->aspath) > 0
                       && aspath_count_confeds(existattr->aspath) > 0
                       && aspath_count_hops(newattr->aspath) == 0
                       && aspath_count_hops(existattr->aspath) == 0);

    if (CHECK_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED)
        || (CHECK_FLAG(bgp->flags, BGP_FLAG_MED_CONFED) && confed_as_route)
        || aspath_cmp_left(newattr->aspath, existattr->aspath)
        || aspath_cmp_left_confed(newattr->aspath, existattr->aspath)
        || internal_as_route) {
        new_med = bgp_med_value(new->attr, bgp);
        exist_med = bgp_med_value(exist->attr, bgp);

        if (new_med < exist_med) {
            RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
        }

        if (new_med > exist_med) {
            RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
        }
    }
    RETVAL_VM(BGP_DECISION_PEER_TYPE, 0, args, sizeof(bpf_full_args_t *));
})

DEFFUN_VM(bgp_peer_type, uint64_t, (bpf_full_args_t *args), BGP_DECISION_PEER_TYPE, args, sizeof(bpf_full_args_t *), {

    struct bgp_path_info *new, *exist;

    exist = (args)->args[1].arg;
    new = (args)->args[2].arg;

    bgp_peer_sort_t new_sort, exist_sort;

    new_sort = new->peer->sort;
    exist_sort = exist->peer->sort;

    if (new_sort == BGP_PEER_EBGP
        && (exist_sort == BGP_PEER_IBGP || exist_sort == BGP_PEER_CONFED)) {
        RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
    }

    if (exist_sort == BGP_PEER_EBGP
        && (new_sort == BGP_PEER_IBGP || new_sort == BGP_PEER_CONFED)) {
        RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
    }
    RETVAL_VM(BGP_DECISION_CONFED_CHECK, 0, args, sizeof(bpf_full_args_t *));
})

DEFFUN_VM(confed_check, uint64_t, (bpf_full_args_t *args), BGP_DECISION_CONFED_CHECK, args, sizeof(bpf_full_args_t *), {

    bgp_ebpf_t *bgp;
    struct bgp_path_info *new, *exist;

    exist = (args)->args[1].arg;
    new = (args)->args[2].arg;
    bgp = (args)->args[3].arg;

    bgp_peer_sort_t new_sort, exist_sort;
    new_sort = new->peer->sort;
    exist_sort = exist->peer->sort;

    if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION)) {
        if (new_sort == BGP_PEER_CONFED
            && exist_sort == BGP_PEER_IBGP) {
            RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
        }

        if (exist_sort == BGP_PEER_CONFED
            && new_sort == BGP_PEER_IBGP) {
            RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
        }
    }

    RETVAL_VM(BGP_DECISION_IGP_ALL, 0, args, sizeof(bpf_full_args_t *));
})

DEFFUN_VM(bgp_igp_m, uint64_t, (bpf_full_args_t *args), BGP_DECISION_IGP_ALL, args, sizeof(bpf_full_args_t *), {

    bgp_ebpf_t *bgp;
    struct bgp_path_info *new, *exist;
    struct bgp_maxpaths_cfg *mpath_cfg;
    int *paths_eq;

    exist = (args)->args[1].arg;
    new = (args)->args[2].arg;
    bgp = (args)->args[3].arg;
    mpath_cfg = (args)->args[4].arg;
    paths_eq = (args)->args[5].arg;

    unsigned int ret = 0;
    uint32_t newm, existm;

    /* 8. IGP metric check. */
    newm = existm = 0;

    if (new->extra)
        newm = new->extra->igpmetric;
    if (exist->extra)
        existm = exist->extra->igpmetric;

    if (newm < existm) {
        ret = 1;
    } else if (newm > existm) {
        ret = 0;
    } else {
        /* 9. Same IGP metric. Compare the cluster list length as
	   representative of IGP hops metric. Rewrite the metric value
	   pair (newm, existm) with the cluster list length. Prefer the
	   path with smaller cluster list length.                       */
        if (peer_sort(new->peer) == BGP_PEER_IBGP
            && peer_sort(exist->peer) == BGP_PEER_IBGP
            && (mpath_cfg == NULL
                || CHECK_FLAG(
                mpath_cfg->ibgp_flags,
                BGP_FLAG_IBGP_MULTIPATH_SAME_CLUSTERLEN))) {
            newm = (uint32_t) BGP_CLUSTER_LIST_LENGTH(new->attr);
            existm = (uint32_t) BGP_CLUSTER_LIST_LENGTH(exist->attr);

            if (newm < existm) {
                ret = 1;
            }

            if (newm > existm) {
                ret = 0;
            }
        }
    }

    /* 11. Maximum path check. */
    if (newm == existm) {
        /* If one path has a label but the other does not, do not treat
        * them as equals for multipath
        */
        if ((new->extra && bgp_is_valid_label(&new->extra->label[0]))
            != (exist->extra
                && bgp_is_valid_label(&exist->extra->label[0]))) {
            // inconsistency
        } else if (CHECK_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX)) {

            /*
            * For the two paths, all comparison steps till IGP
            * metric
            * have succeeded - including AS_PATH hop count. Since
            * 'bgp
            * bestpath as-path multipath-relax' knob is on, we
            * don't need
            * an exact match of AS_PATH. Thus, mark the paths are
            * equal.
            * That will trigger both these paths to get into the
            * multipath
            * array.
            */
            *paths_eq = 1;

        } else if (new->peer->sort == BGP_PEER_IBGP) {
            if (aspath_cmp(new->attr->aspath, exist->attr->aspath)) {
                *paths_eq = 1;

            }
        } else if (new->peer->as == exist->peer->as) {
            *paths_eq = 1;
        }
    } else {
        /*
        * TODO: If unequal cost ibgp multipath is enabled we can
        * mark the paths as equal here instead of returning
        */

        RETVAL_VM(ret == 1 ? BGP_SPEC_COMP_2 : BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *)); /// WHY RETURNING HERE ??
    }
    RETVAL_VM(BGP_DECISION_PREFER_FIRST_PATH, 0, args, sizeof(bpf_full_args_t *));
})

DEFFUN_VM(bgp_prefer_first_path, uint64_t, (bpf_full_args_t *args), BGP_DECISION_PREFER_FIRST_PATH, args,
          sizeof(bpf_full_args_t *), {

              bgp_ebpf_t *bgp;
              struct bgp_path_info *new, *exist;
              exist = (args)->args[1].arg;
              new = (args)->args[2].arg;
              bgp = (args)->args[3].arg;

              bgp_peer_sort_t new_sort;
              bgp_peer_sort_t exist_sort;

              new_sort = new->peer->sort;
              exist_sort = exist->peer->sort;

              if (!CHECK_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID)
                  && new_sort == BGP_PEER_EBGP && exist_sort == BGP_PEER_EBGP) {
                  if (CHECK_FLAG(new->flags, BGP_PATH_SELECTED)) {
                      RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
                  }

                  if (CHECK_FLAG(exist->flags, BGP_PATH_SELECTED)) {
                      RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
                  }
              }
              RETVAL_VM(BGP_DECISION_ROUTE_ID, 0, args, sizeof(bpf_full_args_t *));
          })

DEFFUN_VM(router_id_cmp, uint64_t, (bpf_full_args_t *args), BGP_DECISION_ROUTE_ID, args, sizeof(bpf_full_args_t *), {

    struct bgp_path_info *new, *exist;
    exist = (args)->args[1].arg;
    new = (args)->args[2].arg;


    struct attr *existattr, *newattr;
    struct in_addr new_id, exist_id;

    newattr = new->attr;
    existattr = exist->attr;


    if (newattr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
        new_id.s_addr = newattr->originator_id.s_addr;
    else
        new_id.s_addr = new->peer->remote_id.s_addr;
    if (existattr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
        exist_id.s_addr = existattr->originator_id.s_addr;
    else
        exist_id.s_addr = exist->peer->remote_id.s_addr;

    if (ntohl(new_id.s_addr) < ntohl(exist_id.s_addr)) {
        RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
    }

    if (ntohl(new_id.s_addr) > ntohl(exist_id.s_addr)) {
        RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
    }

    RETVAL_VM(BGP_DECISION_CLUSTER_ID_CMP, 0, args, sizeof(bpf_full_args_t *));
})

DEFFUN_VM(cluster_id_cmp, uint64_t, (bpf_full_args_t *args), BGP_DECISION_CLUSTER_ID_CMP, args, sizeof(bpf_full_args_t *), {

    struct bgp_path_info *new, *exist;


    exist = (args)->args[1].arg;
    new = (args)->args[2].arg;


    int new_cluster;
    int exist_cluster;

    new_cluster = BGP_CLUSTER_LIST_LENGTH(new->attr);
    exist_cluster = BGP_CLUSTER_LIST_LENGTH(exist->attr);

    if (new_cluster < exist_cluster) {
        RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
    }

    if (new_cluster > exist_cluster) {
        RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
    }
    RETVAL_VM(BGP_DECISION_NEIGHBOR_ADDR_CMP, 0, args, sizeof(bpf_full_args_t *));
})

DEFFUN_VM(neighbor_addr_cmp, uint64_t, (bpf_full_args_t *args), BGP_DECISION_NEIGHBOR_ADDR_CMP, args, sizeof(bpf_full_args_t *), {

    struct bgp_path_info *new, *exist;
    exist = (args)->args[1].arg;
    new = (args)->args[2].arg;


    int ret;

    if (CHECK_FLAG(exist->flags, BGP_PATH_STALE)) {
        RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
    }

    if (CHECK_FLAG(new->flags, BGP_PATH_STALE)) {
        RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
    }

    /* locally configured routes to advertise do not have su_remote */
    if (new->peer->su_remote == NULL)
        RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
    if (exist->peer->su_remote == NULL)
        RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));

    ret = sockunion_cmp(new->peer->su_remote, exist->peer->su_remote);

    if (ret == 1) {
        RETVAL_VM(BGP_SPEC_COMP_1, 0, args, sizeof(bpf_full_args_t *));
    }

    if (ret == -1) {
        RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *));
    }

    RETVAL_VM(BGP_SPEC_COMP_2, 0, args, sizeof(bpf_full_args_t *)); // end of bgp_decision process
})
// white space