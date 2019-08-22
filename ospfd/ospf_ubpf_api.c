//
// Created by thomas on 19/08/19.
//

#include "ospf_ubpf_api.h"
#include "ospfd.h"
#include "ospf_interface.h"
#include "ospf_flood.h"

#include <lib/pqueue.h>

/* definition of static  */
struct vertex *ospf_vertex_new(struct ospf_lsa *lsa);

int ospf_lsa_has_link(struct lsa_header *w, struct lsa_header *v);

/****** Getter functions ******/


struct ospf_interface *get_ospf_interface_from_area(api_args) {
    return NULL;
}


struct ospf_interface *get_ospf_interface_list_from_area(api_args, int *nb) {


    struct ospf_area *area;
    struct list *oilist;
    struct listnode *node;
    struct ospf_interface *lst_oi, *oi;

    struct interface *curr;

    int ifs_nb = 0;
    int i;

    if (nb) *nb = 0;

    area = auto_get(BPF_ARG_OSPF_AREA, struct ospf_area *);
    if (!area) return NULL;

    oilist = area->oiflist;

    for (ALL_LIST_ELEMENTS_RO(oilist, node, oi)) {
        ifs_nb++;
    }

    lst_oi = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct ospf_interface) * ifs_nb);
    if (!lst_oi) return NULL;

    i = 0;
    for (ALL_LIST_ELEMENTS_RO(oilist, node, oi)) {
        if (oi) {
            lst_oi[i] = *oi;

            if (oi->ifp) {
                curr = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct interface));
                if (!curr) return NULL; // TODO free everything
                *curr = *oi->ifp;
                lst_oi[i].ifp = curr;
            } else {
                lst_oi[i].ifp = NULL;
            }
            i++;
        }
    }

    if (nb) *nb = ifs_nb;

    return lst_oi;
}


/*
 * Getter function to get an interface.
 */
struct interface *get_interface_from_ospf_interface(api_args) {
    struct ospf_interface *oi;
    struct interface *ifp, *ifp_plug;

    oi = auto_get(BPF_ARG_INTERFACE, struct ospf_interface *);
    ifp = oi->ifp;
    ifp_plug = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct interface));
    if (!ifp || !ifp_plug) return NULL;

    *ifp_plug = *ifp;
    return ifp_plug;
}

/*
 * Getter function to get an ospf_lsa
 */
struct ospf_lsa *get_ospf_lsa(api_args) {

    struct ospf_lsa *lsa, *plug_lsa;

    lsa = auto_get(BPF_ARG_OSPF_LSA, struct ospf_lsa *);
    if (!lsa) return NULL;
    plug_lsa = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct ospf_lsa));
    if (!plug_lsa) return NULL;

    *plug_lsa = *lsa;
    return plug_lsa;
}


struct lsa_header *get_lsa_header_from_lsa(api_args, int force_length) {

    struct lsa_header *plugin_lsah;
    struct ospf_lsa *lsa;

    lsa = auto_get(BPF_ARG_OSPF_LSA, struct ospf_lsa *);
    if (!lsa) return NULL;

    if (force_length) {
        plugin_lsah = my_malloc(&vm_ctx->p->heap.mp, sizeof(lsa->data->length));
    } else {
        plugin_lsah = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct lsa_header));
    }

    if (!plugin_lsah) return NULL;

    *plugin_lsah = *lsa->data;
    return plugin_lsah;
}

struct lsa_header *get_lsa_header_from_vertex(api_args, int force_length) {
    struct lsa_header *plugin_lsah;
    struct vertex *v;

    v = auto_get(BPF_ARG_VERTEX, struct vertex *);
    if (!v) return NULL;

    if (force_length) {
        plugin_lsah = my_malloc(&vm_ctx->p->heap.mp, sizeof(v->lsa->length));
    } else {
        plugin_lsah = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct lsa_header));
    }

    if (!plugin_lsah) return NULL;

    *plugin_lsah = *v->lsa;
    return plugin_lsah;
}

/*
 * Getter function to get an ospf area
 */
struct ospf_area *get_ospf_area(api_args) {

    struct ospf_area *area, *plug_area;
    area = auto_get(BPF_ARG_OSPF_AREA, struct ospf_area *);
    if (!area) return NULL;
    plug_area = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct ospf_area));
    if (!plug_area) return NULL;

    *plug_area = *area;
    return NULL;
}

/*
 * Getter function to get an ospf structure (bigger than stack --> need to allocate on heap)
 */
struct ospf *get_ospf(api_args) {

    struct ospf *ospf, *plug_ospf;
    ospf = auto_get(BPF_ARG_OSPF, struct ospf *);
    if (!ospf) return NULL;
    plug_ospf = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct ospf));
    if (!plug_ospf) return NULL;

    *plug_ospf = *ospf;
    return plug_ospf;
}

struct vertex *get_candidate_vertex_from_pqueue(api_args, int stat) {

    struct pqueue *candidate;
    struct vertex *vertex, *_v;

    candidate = auto_get(BPF_ARG_PQUEUE, struct pqueue *);
    if (!candidate) return NULL;
    if (candidate->size <= stat) return NULL;
    vertex = my_malloc(&vm_ctx->p->heap.mp, sizeof(struct vertex));
    if (!vertex) return NULL;

    _v = candidate->array[stat];

    *vertex = *_v;
    return vertex;
}


/* Setter functions */

int set_ospf_area(api_args, struct ospf_area *area_copy) {

    struct ospf_area *area;

    if (!area_copy) return -1;

    area = auto_get(BPF_ARG_OSPF_AREA, struct ospf_area *);
    if (!area) return -1;

    /* TODO safe_ptr area_copy */

    memcpy(area, area_copy, sizeof(struct ospf_area));

    return 0;
}


int set_ospf_interface(api_args, struct ospf_interface *oi_copy) {

    struct ospf_interface *oi;
    if (!oi_copy) return -1;
    oi = auto_get(BPF_ARG_OSPF_INTERFACE, struct ospf_interface *);
    if (!oi) return -1;

    memcpy(oi, oi_copy, sizeof(struct ospf_interface));

    return 0;
}

int set_ospf_interface_area(api_args, struct ospf_interface *oi_copy, int index) {

    int i;
    struct ospf_area *area;
    struct list *oilist;
    struct listnode *node;
    struct ospf_interface *oi;

    i = 0;
    area = auto_get(BPF_ARG_OSPF_AREA, struct ospf_area *);
    if (!area) return -1;


    oilist = area->oiflist;

    for (ALL_LIST_ELEMENTS_RO(oilist, node, oi)) {

        if (i == index) {
            memcpy(oi, oi_copy, sizeof(struct ospf_interface));
            return 0;
        }
        i++;
    }

    return -1;
}


/****** OSPF functions *****/

struct vertex *plugin_ospf_vertex_new(context_t *ctx, struct ospf_lsa *lsa, struct vertex **copy_v) {

    struct vertex *v;

    if (lsa == NULL) return NULL;
    v = ospf_vertex_new(lsa);

    if (copy_v) {

        *copy_v = my_malloc(&ctx->p->heap.mp, sizeof(struct vertex));
        if (!*copy_v) return NULL;

        **copy_v = *v;
    }

    return v;
}

int plugin_ospf_lsa_has_link(context_t *ctx, struct lsa_header *w, struct lsa_header *v) {
    if (w == NULL) return 0;
    if (v == NULL) return 0;
    return ospf_lsa_has_link(w, v);
}

void plugin_trickle_up(api_args, int index) {

    struct pqueue *queue;

    queue = auto_get(BPF_ARG_PQUEUE, struct pqueue *);
    if (!queue) return;

    trickle_up(index, queue);
}

static struct ospf_lsa *_plugin_ospf_lsa_lookup(context_t *vm_ctx, bpf_full_args_t *args,
                                                int pos_ospf, int pos_area,
                                                uint32_t type, struct in_addr id,
                                                struct in_addr adv_router) {

    struct ospf *ospf;
    struct ospf_area *area;
    struct ospf_lsa *lsa, *plug_lsa;

    if (!safe_args(args, pos_ospf, BPF_ARG_OSPF)) return NULL;
    if (!safe_args(args, pos_area, BPF_ARG_OSPF_AREA)) return NULL;

    ospf = get_arg(args, pos_ospf, struct ospf *);
    area = get_arg(args, pos_area, struct ospf_area *);

    lsa = ospf_lsa_lookup(ospf, area, type, id, adv_router);

    if (!lsa) return NULL;

    plug_lsa = my_malloc(&vm_ctx->p->heap.mp, sizeof(*lsa));
    if (!plug_lsa) return NULL;

    plug_lsa->data = my_malloc(&vm_ctx->p->heap.mp, sizeof(lsa->data->length));
    if (!plug_lsa->data) {
        my_free(&vm_ctx->p->heap.mp, plug_lsa);
        return NULL;
    }

    *plug_lsa = *lsa;
    *plug_lsa->data = *lsa->data;
    return plug_lsa;
}


struct ospf_lsa *plugin_ospf_lsa_lookup(context_t *vm_ctx, void **args) {

    bpf_full_args_t *fargs = args[0];
    int *pos_ospf = args[1];
    int *pos_area = args[2];
    uint32_t *type = args[3];
    struct in_addr *id = args[4];
    struct in_addr *adv_router = args[5];


    return _plugin_ospf_lsa_lookup(vm_ctx, fargs, *pos_ospf, *pos_area,
                                   *type, *id, *adv_router);
}

void plugin_pqueue_enqueue(api_args, void *data) {

    struct pqueue *queue;
    queue = auto_get(BPF_ARG_PQUEUE, struct pqueue *);
    if (!queue) return;

    if (data == NULL) return;
    return pqueue_enqueue(data, queue);
}

struct ospf_lsa *plugin_ospf_lsa_lookup_by_id(context_t *vm_ctx, bpf_full_args_t *args,
                                              int pos_area, uint32_t type,
                                              struct in_addr id) {
    struct ospf_area *area;
    struct ospf_lsa *lsa, *plug_lsa;

    if (!safe_args(args, pos_area, BPF_ARG_OSPF_AREA)) return NULL;
    area = get_arg(args, pos_area, struct ospf_area *);

    lsa = ospf_lsa_lookup_by_id(area, type, id);
    if (!lsa) return NULL;

    plug_lsa = my_malloc(&vm_ctx->p->heap.mp, sizeof(*lsa));
    if (!plug_lsa) return NULL;
    plug_lsa->data = my_malloc(&vm_ctx->p->heap.mp, sizeof(lsa->data->length));
    if (!plug_lsa->data) {
        my_free(&vm_ctx->p->heap.mp, plug_lsa);
        return NULL;
    }

    *plug_lsa = *lsa;
    *plug_lsa->data = *lsa->data;
    return plug_lsa;
}


struct ospf_lsa *
plugin_ospf_lsa_install(context_t *ctx, struct ospf *ospf, struct ospf_interface *oi, struct ospf_lsa *lsa) {

    ospf_lsa_install(ospf, oi, lsa);
    return lsa;
}

int plugin_ospf_flood_through_area(api_args, struct ospf_neighbor *inbr, struct ospf_lsa *lsa) {

    struct ospf_area *area;

    area = auto_get(BPF_ARG_OSPF_AREA, struct ospf_area *);
    if (!area) return -1;
    if (lsa == NULL) return -1;

    ospf_flood_through_area(area, inbr, lsa);
    return 1;
}

extern unsigned int ospf_nexthop_calculation(struct ospf_area *area,
                                             struct vertex *v, struct vertex *w,
                                             struct router_lsa_link *l,
                                             unsigned int distance, int lsa_pos);

static inline unsigned int _plugin_ospf_nexthop_calculation(context_t *vm_ctx, bpf_full_args_t *args, int area_arg,
                                                            int vertex_args, struct vertex *w,
                                                            struct router_lsa_link *l,
                                                            unsigned int distance, int lsa_pos) {

    UNUSED(vm_ctx);


    if (!safe_args(args, area_arg, BPF_ARG_OSPF_AREA)) return 0;
    if (!safe_args(args, vertex_args, BPF_ARG_VERTEX)) return 0;


    struct ospf_area *area = get_arg(args, BPF_ARG_OSPF_AREA, struct ospf_area *);
    struct vertex *v = get_arg(args, BPF_ARG_VERTEX, struct vertex *);

    if (!area || !v) return 0;

    return ospf_nexthop_calculation(area, v, w, l, distance, lsa_pos);
}


unsigned int plugin_ospf_nexthop_calculation(context_t *vm_ctx, void **tab_args) {

    bpf_full_args_t *args = tab_args[0];
    int *area_args_idx = tab_args[1];
    int *vertex_args = tab_args[2];
    struct vertex *w = tab_args[3];
    struct router_lsa_link *l = tab_args[4];
    unsigned int *distance = tab_args[5];
    int *lsa_pos = tab_args[6];

    return _plugin_ospf_nexthop_calculation(vm_ctx, args, *area_args_idx,
                                            *vertex_args, w, l, *distance, *lsa_pos);
}

/* Set a link information. */
static char my_link_info_set(struct stream **s, struct in_addr id,
                             struct in_addr data, uint8_t type, uint8_t tos,
                             uint16_t cost, uint32_t metric) {

    /* TOS based routing is not supported. */
    stream_put_ipv4(*s, id.s_addr);   /* Link ID. */
    stream_put_ipv4(*s, data.s_addr); /* Link Data. */
    stream_putc(*s, type);          /* Link Type. */
    stream_putc(*s, tos);          /* TOS = 0. */
    stream_putw(*s, cost);          /* Link Cost. */
    stream_putl(*s, metric);          /* Link color */

    return 1;
}

static uint16_t my_ospf_link_cost(struct ospf_interface *oi) {
    /* RFC3137 stub router support */
    if (!CHECK_FLAG(oi->area->stub_router_state, OSPF_AREA_IS_STUB_ROUTED))
        return oi->output_cost;
    else
        return OSPF_OUTPUT_COST_INFINITE;
}

/* Describe Broadcast Link. */
int plugin_lsa_link_broadcast_set(context_t *ctx, struct stream **s, struct ospf_interface *oi, uint32_t metric) {
    struct ospf_neighbor *dr;
    struct in_addr id, mask;
    uint16_t cost = my_ospf_link_cost(oi);

    /* Describe Type 3 Link. */
    if (oi->state == 3) {
        masklen2ip(oi->address->prefixlen, &mask);
        id.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
        return my_link_info_set(s, id, mask, LSA_LINK_TYPE_STUB, 0,
                                oi->output_cost, metric);
    }

    dr = ospf_nbr_lookup_by_addr(oi->nbrs, &DR(oi));
    /* Describe Type 2 link. */
    if (dr && (dr->state == 9
               || IPV4_ADDR_SAME(&oi->address->u.prefix4, &DR(oi)))
        && ospf_nbr_count(oi, 9) > 0) {
        return my_link_info_set(s, DR(oi), oi->address->u.prefix4,
                                LSA_LINK_TYPE_TRANSIT, 0, cost, metric);
    }
        /* Describe type 3 link. */
    else {
        masklen2ip(oi->address->prefixlen, &mask);
        id.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
        return my_link_info_set(s, id, mask, LSA_LINK_TYPE_STUB, 0,
                                oi->output_cost, metric);
    }
}

struct ospf_lsa *plugin_ospf_lsa_new_and_data(api_args, struct stream *s) {

    struct ospf_area *area;
    area = auto_get(BPF_ARG_OSPF_AREA, struct ospf_area *);
    if (!area) return NULL;

    int length = s->endp;
    struct lsa_header *lsah = (struct lsa_header *) s->data;
    lsah->length = htons(length);
    struct ospf_lsa *new = ospf_lsa_new_and_data(length);
    // TODO: This set should probably be done in the plugin
    new->area = area;
    SET_FLAG(new->flags, OSPF_LSA_SELF | OSPF_LSA_SELF_CHECKED);
    new->vrf_id = area->ospf->vrf_id;
    memcpy(new->data, lsah, length);
    return new;
}


int my_get_lsah(context_t *ctx, struct ospf_lsa *lsa, struct lsa_header *lsah) {
    memcpy(lsah, lsa->data, sizeof(struct lsa_header));
    return 1;
}