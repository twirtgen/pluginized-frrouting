//
// Created by cyril on 29/04/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <ospfd/ospf_ubpf_api_plugins.h>
#include <ospfd/ospf_spf.h>
#include <ospfd/ospf_lsa.h>
#include <ospfd/ospfd.h>

struct my_link {
    struct in_addr link_id;
    struct in_addr link_data;
    uint8_t type;
    uint8_t tos;
    uint16_t metric;
    uint32_t color;
};

#define RED 1
#define GREEN 2

#define cleanup \
ctx_free(v);\
ctx_free(lsah);\
ctx_free(area);


/* RFC2328 Section 16.1 (2).
 * v is on the SPF tree.  Examine the links in v's LSA.  Update the list
 * of candidates with any vertices not already on the list.  If a lower-cost
 * path is found to a vertex already on the candidate list, store the new cost.
 * The plugin does something more. For each router-LSA, it checks if there is a corresponding type 13 LSA. If yes, we check if the link is green or red.
 * If the link is red, we ignore it and thus "prune" the tree after it.
 */
uint64_t ospf_spf_next(bpf_full_args_t *data) {

    int vertex_args = 0;
    int ospf_args = 1;
    int area_args = 2;
    struct vertex *v;
    struct lsa_header *lsah;
    struct ospf_area *area;

    struct ospf_lsa *w_lsa = NULL;
    uint8_t *p;
    uint8_t *lim;
    struct router_lsa_link *l = NULL;
    struct in_addr *r;
    int type = 0, lsa_pos = -1, lsa_pos_next = 0;


    v = bpf_get_args(0, data);
    area = bpf_get_args(2, data);
    lsah = get_lsa_header_from_vertex(data, 0, 1); // force length
    lsah = ctx_realloc(lsah, (unsigned int) (((lsah->length & 0x00FFu) << 8u) | ((lsah->length & 0xFF00u) >> 8u)));



    /* If this is a router-LSA, and bit V of the router-LSA (see Section
       A.4.2:RFC2328) is set, set Area A's TransitCapability to TRUE.  */

    if (v->type == OSPF_VERTEX_ROUTER) { // This is a router LSA
        if (IS_ROUTER_LSA_VIRTUAL((struct router_lsa *) lsah)) {
            area->transit = OSPF_TRANSIT_TRUE;
            if (set_ospf_area(data, 2, area) != 1) return 0;
        }
    }

    p = ((uint8_t *) lsah) + OSPF_LSA_HEADER_SIZE + 4;
    lim = ((uint8_t *) lsah) + ((uint8_t) ebpf_ntohs(lsah->length));
    struct ospf_lsa *test_lsa;
    void *lookup_args[] = {data, &ospf_args, &area_args, &v->id, &v->id};
    test_lsa = plugin_ospf_lsa_lookup(lookup_args);
    while (p < lim) {
        struct vertex *w = NULL;
        unsigned int distance;

        /* In case of V is Router-LSA. */
        if (lsah->type == OSPF_ROUTER_LSA) {
            l = (struct router_lsa_link *) p;

            int ignored = 0;
            if (test_lsa != NULL) { // There is a type 13 corresponding LSA

                struct lsa_header *test_lsah = test_lsa->data;
                test_lsah = ctx_realloc(test_lsah, (unsigned int) (((test_lsah->length & 0x00FFu) << 8u) |
                                                                   ((test_lsah->length & 0xFF00u) >> 8u)));
                uint8_t *my_p = ((uint8_t *) test_lsah) + OSPF_LSA_HEADER_SIZE + 4;
                while (my_p < ((uint8_t *) test_lsah) +
                              (((test_lsah->length & 0x00FFu) << 8u) | ((test_lsah->length & 0xFF00u) >> 8u))) {
                    struct my_link *my_link = (struct my_link *) my_p;
                    if (l->link_id.s_addr == my_link->link_id.s_addr) {
                        if (ebpf_ntohl(my_link->color) == RED) { // If the link is red, we ignore it
                            ignored = 1;
                            break;
                        }
                    }
                    my_p += sizeof(struct my_link);
                }
            }

            lsa_pos = lsa_pos_next; /* LSA link position */
            lsa_pos_next++;
            p += (OSPF_ROUTER_LSA_LINK_SIZE + (l->m[0].tos_count * OSPF_ROUTER_LSA_TOS_SIZE));

            if (ignored) { // skip this link, it is the wrong color
                continue;
            }

            /* (a) If this is a link to a stub network, examine the
               next
               link in V's LSA.  Links to stub networks will be
               considered in the second stage of the shortest path
               calculation. */
            if ((type = l->m[0].type) == LSA_LINK_TYPE_STUB)
                continue;

            /* (b) Otherwise, W is a transit vertex (router or
               transit
               network).  Look up the vertex W's LSA (router-LSA or
               network-LSA) in Area A's link state database. */
            switch (type) {
                case LSA_LINK_TYPE_POINTOPOINT:
                case LSA_LINK_TYPE_VIRTUALLINK:{
                    int ospf_router_lsa = OSPF_ROUTER_LSA;
                    void *my_args[] = {data, &ospf_args, &area_args, &ospf_router_lsa, &l->link_id, &l->link_id };
                    w_lsa = plugin_ospf_lsa_lookup(my_args);
                    break;
                }
                case LSA_LINK_TYPE_TRANSIT:
                    w_lsa = plugin_ospf_lsa_lookup_by_id(data, 2, OSPF_NETWORK_LSA, l->link_id);
                    break;
                default:
                    continue;
            }
        } else {
            /* In case of V is Network-LSA. */
            r = (struct in_addr *) p;
            p += sizeof(struct in_addr);

            /* Lookup the vertex W's LSA. */
            w_lsa = plugin_ospf_lsa_lookup_by_id(data, 2, OSPF_ROUTER_LSA, *r);
        }

        /* (b cont.) If the LSA does not exist, or its LS age is equal
           to MaxAge, or it does not have a link back to vertex V,
           examine the next link in V's LSA.[23] */
        if (w_lsa == NULL) {
            continue;
        }


        struct lsa_header *w_lsah = w_lsa->data;
        if (w_lsah->ls_age == OSPF_LSA_MAXAGE) {
            ctx_free(w_lsa->data);
            ctx_free(w_lsa);
            continue;
        }

        if (plugin_ospf_lsa_has_link(w_lsa->data, v->lsa) < 0) {
            ctx_free(w_lsa->data);
            ctx_free(w_lsa);
            continue;
        }

        /* (c) If vertex W is already on the shortest-path tree, examine
           the next link in the LSA. */
        if (w_lsa->stat == LSA_SPF_IN_SPFTREE) {
            ctx_free(w_lsa->data);
            ctx_free(w_lsa);
            continue;
        }

        /* (d) Calculate the link state cost D of the resulting path
           from the root to vertex W.  D is equal to the sum of the link
           state cost of the (already calculated) shortest path to
           vertex V and the advertised cost of the link between vertices
           V and W.  If D is: */

        /* calculate link cost D. */
        if (lsah->type == OSPF_ROUTER_LSA)
            distance = v->distance + (((l->m[0].metric & 0x00FFu) << 8u) | ((l->m[0].metric & 0xFF00u) >> 8u));
        else /* v is not a Router-LSA */
            distance = v->distance;

        void *my_args[] = {data, &area_args, &vertex_args,
                           w, l, &distance, &lsa_pos};

        /* Is there already vertex W in candidate list? */
        if (w_lsa->stat == LSA_SPF_NOT_EXPLORED) {
            /* prepare vertex W. */
            w = plugin_ospf_vertex_new(w_lsa, NULL);

            /* Calculate nexthop to W. */



            if (plugin_ospf_nexthop_calculation(my_args))
                plugin_pqueue_enqueue(data, 3, w);
        } else if (w_lsa->stat >= 0) {
            /* Get the vertex from candidates. */
            if ((w = get_candidate_vertex_from_pqueue(data, 3, w_lsa->stat)) == NULL) return 0;

            /* if D is greater than. */
            if (w->distance < distance) {
                ctx_free(w_lsa->data);
                ctx_free(w_lsa);
                continue;
            } else if (w->distance == distance) { /* equal to. */
                /* Found an equal-cost path to W.
                 * Calculate nexthop of to W from V. */

                plugin_ospf_nexthop_calculation(my_args);
            } else { /* less than. */
                /* Found a lower-cost path to W.
                 * nexthop_calculation is conditional, if it
                 * finds
                 * valid nexthop it will call spf_add_parents,
                 * which
                 * will flush the old parents
                 */
                if (plugin_ospf_nexthop_calculation(my_args))
                    /* Decrease the key of the node in the
                     * heap.
                     * trickle-sort it up towards root, just
                     * in case this
                     * node should now be the new root due
                     * the cost change.
                     * (next pqueue_{de,en}queue will fully
                     * re-heap the queue).
                     */
                    plugin_trickle_up(data, 3, w_lsa->stat);
            }
        } /* end W is already on the candidate list */
        ctx_free(w_lsa->data);
        ctx_free(w_lsa);
    }     /* end loop over the links in V's LSA */


    cleanup
    return 1;
}