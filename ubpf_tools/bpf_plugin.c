//
// Created by thomas on 7/02/19.
//

#include "bpf_plugin.h"
#include "ubpf_tools/list.h"
#include "ubpf_tools/map.h"
#include "ubpf_tools/include/plugin_arguments.h"
#include "plugins_manager.h"
#include "ubpf_context.h"

#define STRING_PTR_ARRAY 17

/* comparator for inserting sub plugins */
static const char *plugin_comparator = NULL;

static int comp(void *a) { // multi thread not SAFE !
    if (!plugin_comparator) return 0; // should be placed to the end
    return strncmp((*((vm_container_t **) a))->name, plugin_comparator, 20) == 0;
}


bpf_plugin_type_placeholder_t bpf_type_str_to_enum(const char *str) {

    int i;
    int max = sizeof(conversion_placeholder) / sizeof(conversion_placeholder[0]);

    for (i = 0; i < max; i++) {
        if (!strncmp(str, conversion_placeholder[i].str, strlen(conversion_placeholder[i].str))) {
            return conversion_placeholder[i].val;
        }
    }

    return 0;
}

const char *id_plugin_to_str(unsigned int id) {
    int i, max;

    max = sizeof(conversion_id_plugin) / sizeof(conversion_id_plugin[0]);

    for (i = 0; i < max; i++) {
        if (conversion_id_plugin[i].val == id) return conversion_id_plugin[i].str;
    }
    return "UNK";
}

int ptr_to_string(char *dest, void *ptr, size_t len) {

    if (len < STRING_PTR_ARRAY) return -1;
    if (!ptr) return -1;

    snprintf(dest, STRING_PTR_ARRAY - 1, "%p", ptr);
    dest[STRING_PTR_ARRAY - 1] = 0;

    return 0;
}


plugin_t *init_plugin(size_t heap_size, plugin_type_t plugid) {

    size_t total_allowed_mem;
    uint8_t *heap_block = NULL;
    plugin_t *p;
    argument_type_t args_id;

    p = malloc(sizeof(plugin_t));
    if (!p) return NULL;

    p->is_active_replace = 0;
    p->is_active_pre = 0;
    p->is_active_post = 0;
    p->is_active_pre_append = 0;
    p->is_active_post_append = 0;
    p->heap.has_mp = 0;
    p->heap.block = NULL;

    total_allowed_mem = heap_size + MAX_SIZE_ARGS_PLUGIN;
    p->size_allowed_mem = total_allowed_mem;


    if (heap_size > 0 && heap_size <= MAX_HEAP_PLUGIN) {

        heap_block = malloc(total_allowed_mem);
        if (!heap_block) {
            free(p);
            return NULL;
        }

        if(init_memory_management(&p->heap.mp, heap_block, total_allowed_mem) != 0) {
            free(p);
            return NULL;
        }

        p->heap.has_mp = 1;
        p->heap.block = heap_block;

    } else {
        free(p);
        return NULL; // HEAP MEMORY TOO LARGE
    }

    map_init(&p->pre_functions);
    map_init(&p->post_functions);

    p->pre_append = init_list(sizeof(vm_container_t *));
    p->post_append = init_list(sizeof(vm_container_t *));

    if (!p->pre_append || !p->post_append) {
        if (p->pre_append) destroy_list(p->pre_append);
        if (p->post_append) destroy_list(p->post_append);

        free(heap_block);
        free(p);
        return NULL;
    }

    p->replace_function = NULL;

    if (plugid == 0 || plugid == BGP_NOT_ASSIGNED_TO_ANY_FUNCTION) {
        free(heap_block);
        free(p);
        return NULL;
    }
    p->plugin_id = plugid;

    args_id = get_args_id_by_plug_id(p->plugin_id);

    if (args_id == ARGS_INVALID) {
        free(heap_block);
        free(p);
        return NULL;
    }

    p->argument_type = args_id;
    p->plugin_id = plugid;

    return p;
}

void destroy_plugin(plugin_t *p) {

    vm_container_t *curr, *curr_l;
    const char *key;
    map_vm_t *map_curr;
    int i;

    if (!p) return;
    map_vm_t *iteration[] = {&p->pre_functions, &p->post_functions};
    list_t *it_list[] = {p->pre_append, p->post_append};

    if (p->replace_function) shutdown_vm(p->replace_function);


    for (i = 0; i < 2; i++) {
        map_curr = iteration[i];

        map_iter_t it = map_iter(map_curr);
        while ((key = map_next(map_curr, &it))) {

            curr = *map_get(map_curr, key);
            shutdown_vm(curr);

        }
        map_deinit(map_curr);
    }

    for (i = 0; i < 2; i++) {
        while (pop(it_list[i], &curr_l) == 0) {
            shutdown_vm(curr_l);
        }

        destroy_list(it_list[i]);

    }

    destroy_memory_management(&p->heap.mp);
    free(p->heap.block);
    free(p);
}

static int name_in_use(map_vm_t *map_vm, const char *name) {

    if (!map_vm || !name) return 1; // consider it is inside but NULL references

    return map_get(map_vm, name) ? 1 : 0;

}


static int init_ebpf_code(plugin_t *p, vm_container_t **new_vm, const char *sub_name,
                          const uint8_t *bytecode, size_t len, uint8_t jit) {


    context_t *ctx;

    if(!p) return -1; // plugin must be init before loading eBPF code

    ctx = new_context(p);
    if (!ctx) return -1;

    if (!register_context(ctx)) {
        free(ctx);
        return -1;
    }

    // CHECK
    // ctx->args_type = p->argument_type;
    // ctx->args = p->ptr_args;

    if (!vm_init(new_vm, ctx, p->heap.block, sub_name, strnlen(sub_name, 20),
                 p->size_allowed_mem, jit))
        return -1;

    if (!start_vm(*new_vm)) return -1;
    if (!inject_code_ptr(*new_vm, bytecode, len)) return -1;

    return 0;
}

static int add_append(plugin_t *p, list_t *l_append, const uint8_t *bytecode, size_t len,
                      const char *sub_plugin_name, const char *after, uint8_t jit) {


    list_iterator_t it;

    if (list_iterator(l_append, &it) != 0) return -1;

    vm_container_t **c;
    vm_container_t *new_vm;

    // check if sub_plugin_name already injected
    while ((c = iterator_next(&it)) != NULL) {
        if (strncmp((*c)->name, sub_plugin_name, strnlen(sub_plugin_name, 20)) == 0) {
            fprintf(stderr, "Plugin already inserted\n");
            return -1;
        }
    }

    if (init_ebpf_code(p, &new_vm, sub_plugin_name, bytecode, len, jit) != 0) {
        return -1;
    }

    plugin_comparator = after;
    enqueue_after(l_append, &new_vm, comp);
    plugin_comparator = NULL;

    return 0;
}

static inline int
generic_add_function(plugin_t *p, const uint8_t *bytecode, size_t len, const char *sub_plugin_name,
                     const char *after, int type, uint8_t jit) {

    map_vm_t *l = NULL;
    vm_container_t *new_vm;

    if (!p || !bytecode) return -1;

    switch (type) {
        case BPF_PRE:
            l = &p->pre_functions;
            break;
        case BPF_POST:
            l = &p->post_functions;
            break;
        case BPF_REPLACE:
            if (p->replace_function) return -1; // a function is already injected for this plugin
            break;
        case BPF_PRE_APPEND:
            return add_append(p, p->pre_append, bytecode, len, sub_plugin_name, after, jit);
        case BPF_POST_APPEND:
            return add_append(p, p->post_append, bytecode, len, sub_plugin_name, after, jit);
        default:
            return -1;
    }


    if (init_ebpf_code(p, &new_vm, sub_plugin_name, bytecode, len, jit) != 0) {
        return -1;
    }


    if (type != BPF_REPLACE) {
        if (name_in_use(l, sub_plugin_name)) return -1; // name in use, change the name or replace it
        if (map_set(l, sub_plugin_name, new_vm) != 0) return -1;
    } else {
        p->replace_function = new_vm;
    }

    return 0;
}

int add_pre_function(plugin_t *p, const uint8_t *bytecode, size_t len, const char *sub_plugin_name, uint8_t jit) {
    if (!p) return -1;
    p->is_active_pre = 1;
    return generic_add_function(p, bytecode, len, sub_plugin_name, NULL, BPF_PRE, jit);
}

int add_post_function(plugin_t *p, const uint8_t *bytecode, size_t len, const char *sub_plugin_name, uint8_t jit) {
    if (!p) return -1;
    p->is_active_post = 1;
    return generic_add_function(p, bytecode, len, sub_plugin_name, NULL, BPF_POST, jit);
}

int add_replace_function(plugin_t *p, const uint8_t *bytecode, size_t len, const char *sub_plugin_name, uint8_t jit) {
    if (!p) return -1;
    p->is_active_replace = 1;
    return generic_add_function(p, bytecode, len, sub_plugin_name, NULL, BPF_REPLACE, jit);
}

int add_pre_append_function(plugin_t *p, const uint8_t *bytecode, size_t len, const char *after,
                            const char *sub_plugin_name, uint8_t jit) {
    if (!p) return -1;
    p->is_active_pre_append = 1;
    return generic_add_function(p, bytecode, len, sub_plugin_name, after, BPF_PRE_APPEND, jit);
}

int add_post_append_function(plugin_t *p, const uint8_t *bytecode, size_t len, const char *after,
                             const char *sub_plugin_name, uint8_t jit) {
    if (!p) return -1;
    p->is_active_post_append = 1;
    return generic_add_function(p, bytecode, len, sub_plugin_name, after, BPF_POST_APPEND, jit);
}

static inline int generic_run_function(plugin_t *p, uint8_t *args, size_t args_size, int type, uint64_t *ret) {

    map_iter_t it;
    map_vm_t *vm_map;
    const char *key;
    vm_container_t *vm;
    int exec_ok;
    argument_type_t args_id;

    switch (type) {
        case BPF_PRE:
            vm_map = &p->pre_functions;
            break;
        case BPF_POST:
            vm_map = &p->post_functions;
            break;
        default:
            return -1;
    }

    it = map_iter(vm_map);

    while ((key = map_next(vm_map, &it))) {
        vm = *map_get(vm_map, key);

        args_id = p->argument_type;
        exec_ok = run_injected_code(vm, args, args_size, args_id, ret);
        if (exec_ok != 0) {
            // fprintf(stderr, "bytecode execution encountered an error\n");
        }
    }

    return 0;
}

int run_pre_functions(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret) {
    if (!p) return -1;
    if (!p->is_active_pre) return -1;
    return generic_run_function(p, args, args_size, BPF_PRE, ret);
}

int run_post_functions(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret) {
    if (!p) return -1;
    if (!p->is_active_post) return -1;
    return generic_run_function(p, args, args_size, BPF_POST, ret);
}

int run_replace_function(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret_val) {

    int exec_ok;
    argument_type_t args_id;
    uint64_t return_value;

    if (!p) return -1;
    if (!p->is_active_replace) return -1;
    if (!p->replace_function) return -1; // double check

    args_id = p->argument_type;

    exec_ok = run_injected_code(p->replace_function, args, args_size, args_id, &return_value);

    if (ret_val) *ret_val = return_value;

    return exec_ok;
}


int run_append_function(plugin_t *p, uint8_t *args, size_t args_size, uint64_t *ret_val, int type) {

    list_t *l;
    list_iterator_t it;
    vm_container_t **c;
    int exec_ok;
    uint64_t return_value = UINT64_MAX;

    if (!p) return -1;

    switch (type) {
        case BPF_PRE_APPEND:
            if (!p->is_active_pre_append) return -1;
            l = p->pre_append;
            break;
        case BPF_POST_APPEND:
            if (!p->is_active_post_append) return -1;
            l = p->post_append;
            break;
        default:
            return -1;
    }

    if (list_iterator(l, &it) != 0) return -1;

    while ((c = iterator_next(&it)) != NULL) {
        exec_ok = run_injected_code(*c, args, args_size, p->argument_type, &return_value);
        if (exec_ok != 0) return -1;
        if (return_value != BGP_CONTINUE) {
            if (ret_val) *ret_val = return_value;
            return -1;
        }

    }

    if (ret_val) *ret_val = return_value;
    return 0;

}