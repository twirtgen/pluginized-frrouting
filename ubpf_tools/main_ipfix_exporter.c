//
// Created by thomas on 8/01/19.
//

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "ubpf_tools/monitoring_server.h"

//////// LINKER FIX //////// SHOULDN'T DO THAT BUT THESE FUNCTIONS ARE DEFINED IN BGP_MAIN
struct zebra_privs_t bgpd_privs;

#include "privs.h" // fix linker

void *rfp_start(struct thread_master *master, struct rfapi_rfp_cfg **cfgp,
                struct rfapi_rfp_cb_methods **cbmp){
    fprintf(stderr, "%s must not be used... DIE\n", __func__);
    exit(EXIT_FAILURE);
}

void rfp_stop(void *rfp_start_val){
    fprintf(stderr, "%s must not be used... DIE\n", __func__);
    exit(EXIT_FAILURE);
}

void rfp_clear_vnc_nve_all(void){
    fprintf(stderr, "%s must not be used... DIE\n", __func__);
    exit(EXIT_FAILURE);
}
//////// LINKER FIX ////////

static inline int usage(char *prog_name) {

    if (!prog_name) {
        fprintf(stderr, "Internal Error\n");
        return EXIT_FAILURE;
    }

    fprintf(
            stderr,
            "%s: An IPFIX flow exporter. Listen from local eBPF plugins through a UNIX socket\n"
            "Usage : ./%s [-p ipfix_collector_port] [-c ipfix_collector_addr]\n"
            "\t-p ipfix_collector_port : port from which the exporter must contact the collector (default 4739)\n"
            "\t-c ipfix_collector addr :  address or hostname of the IPFIX collector /!\\ IPv4 only (default localhost)\n",
            prog_name,
            prog_name
    );

    return EXIT_FAILURE;
}

int main(int argc, char *argv[]) {

    int opt;

    char ipfix_coll_addr[16];
    char port[6];

    memset(ipfix_coll_addr, 0, sizeof(ipfix_coll_addr));
    memset(port, 0, sizeof(port));

    strncpy(ipfix_coll_addr, "localhost", strlen("localhost") + 1);
    strncpy(port, "4739", strlen("4739") + 1);

    while ((opt = getopt(argc, argv, "p:c:")) != -1) {



        switch (opt) {
            case 'p':
                strncpy(ipfix_coll_addr, optarg, sizeof(char) * 15);
                break;
            case 'c':
                strncpy(port, optarg, sizeof(char) * 5);
                break;
            default:
                return usage(argv[0]);
        }
    }

    main_monitor(ipfix_coll_addr, port);


    return EXIT_SUCCESS;
}