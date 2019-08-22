/*
 * OSPFd main routine.
 *   Copyright (C) 1998, 99 Kunihiro Ishiguro, Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include <lib/version.h>
#include <ubpf_tools/include/public.h>
#include <ubpf_tools/ubpf_api.h>
#include "getopt.h"
#include "thread.h"
#include "prefix.h"
#include "linklist.h"
#include "if.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "log.h"
#include "memory.h"
#include "memory_vty.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "vrf.h"
#include "libfrr.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_bfd.h"
#include "ospfd/ospf_errors.h"
#include "ospf_ubpf_api.h"

/* ospfd privileges */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_NET_ADMIN,
				  ZCAP_SYS_ADMIN};

struct zebra_privs_t ospfd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0};

/* OSPFd options. */
struct option longopts[] = {{"instance", required_argument, NULL, 'n'},
			    {"apiserver", no_argument, NULL, 'a'},
			    {0}};

/* OSPFd program name */

/* Master of threads. */
struct thread_master *master;

#ifdef SUPPORT_OSPF_API
extern int ospf_apiserver_enable;
#endif /* SUPPORT_OSPF_API */


static proto_ext_fun_t api[] = {
        {.fn = get_ospf_interface_list_from_area, .name = "get_ospf_interface_list_from_area"},
        {.fn = get_interface_from_ospf_interface, .name = "get_interface_from_ospf_interface"},
        {.fn = get_ospf_lsa, .name = "get_ospf_lsa"},
        {.fn = get_lsa_header_from_lsa, .name = "get_lsa_header_from_lsa"},
        {.fn = get_lsa_header_from_vertex, .name = "get_lsa_header_from_vertex"},
        {.fn = get_ospf_area, .name = "get_ospf_area"},
        {.fn = get_ospf, .name = "get_ospf"},
        {.fn = get_candidate_vertex_from_pqueue, .name = "get_candidate_vertex_from_pqueue"},
        {.fn = set_ospf_area, .name = "set_ospf_area"},
        {.fn = set_ospf_interface, .name = "set_ospf_interface"},
        {.fn = plugin_ospf_vertex_new, .name = "plugin_ospf_vertex_new"},
        {.fn = plugin_ospf_lsa_has_link, .name = "plugin_ospf_lsa_has_link"},
        {.fn = plugin_trickle_up, .name = "plugin_trickle_up"},
        {.fn = plugin_ospf_lsa_lookup, .name = "plugin_ospf_lsa_lookup"},
        {.fn = plugin_pqueue_enqueue, .name = "plugin_pqueue_enqueue"},
        {.fn = plugin_ospf_lsa_lookup_by_id, .name = "plugin_ospf_lsa_lookup_by_id"},
        {.fn = plugin_ospf_lsa_install, .name = "plugin_ospf_lsa_install"},
        {.fn = plugin_ospf_flood_through_area, .name = "plugin_ospf_flood_through_area"},
        {.fn = plugin_ospf_nexthop_calculation, .name = "plugin_ospf_nexthop_calculation"},
        {.fn = plugin_lsa_link_broadcast_set, .name = "plugin_lsa_link_broadcast_set"},
        {.fn = plugin_ospf_lsa_new_and_data, .name = "plugin_ospf_lsa_new_and_data"},
        {.fn = set_ospf_interface_area, .name = "set_ospf_interface_area"},
        {.fn = my_get_lsah, .name = "my_get_lsah"},
        NULL
};

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");
}

/* SIGINT / SIGTERM handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");
	ospf_terminate();
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct quagga_signal_t ospf_signals[] = {
	{
		.signal = SIGHUP,
		.handler = &sighup,
	},
	{
		.signal = SIGUSR1,
		.handler = &sigusr1,
	},
	{
		.signal = SIGINT,
		.handler = &sigint,
	},
	{
		.signal = SIGTERM,
		.handler = &sigint,
	},
};

static const struct frr_yang_module_info *ospfd_yang_modules[] = {
	&frr_interface_info,
};

FRR_DAEMON_INFO(ospfd, OSPF, .vty_port = OSPF_VTY_PORT,

		.proghelp = "Implementation of the OSPFv2 routing protocol.",

		.signals = ospf_signals, .n_signals = array_size(ospf_signals),

		.privs = &ospfd_privs, .yang_modules = ospfd_yang_modules,
		.n_yang_modules = array_size(ospfd_yang_modules), )

/* OSPFd main routine. */
int main(int argc, char **argv)
{
	unsigned short instance = 0;
	int p[2];
	if(pipe(p) < 0) {
	    perror("Pipe failure");
	    exit(EXIT_FAILURE);
	}

    char json_plugins[512];
    memset(json_plugins, 0, 512 * sizeof(char));

#ifdef SUPPORT_OSPF_API
	/* OSPF apiserver is disabled by default. */
	ospf_apiserver_enable = 0;
#endif /* SUPPORT_OSPF_API */

	frr_preinit(&ospfd_di, argc, argv);
	frr_opt_add("n:a", longopts,
		    "  -n, --instance     Set the instance id\n"
		    "  -a, --apiserver    Enable OSPF apiserver\n");

	while (1) {
		int opt;

		opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case 'n':
			ospfd_di.instance = instance = atoi(optarg);
			if (instance < 1)
				exit(0);
			break;
		case 0:
			break;
#ifdef SUPPORT_OSPF_API
		case 'a':
			ospf_apiserver_enable = 1;
			break;
#endif /* SUPPORT_OSPF_API */
		default:
			frr_help_exit(1);
			break;
		}
	}

	/* Invoked by a priviledged user? -- endo. */
	if (geteuid() != 0) {
		errno = EPERM;
		perror(ospfd_di.progname);
		exit(1);
	}

    snprintf(json_plugins, 511, "%s/list_plugins.json", frr_sysconfdir);
    switch (fork()) {

        // error
        case -1:
            perror("Fork error");
            exit(3);

            // 0 for child process
        case 0:
            // we are in the child
            close(p[1]);
            char addr[64];
            char port[10];

            load_monit_info(json_plugins, addr, 64, port, 10);
            main_monitor2(addr, port, p[0]);

            fprintf(stderr, "Should not happen\n");
            return EXIT_FAILURE;

        default:
            close(p[0]);
            set_write_fd(p[1]);
    }


    /* OSPF master init. */
	ospf_master_init(frr_init());

	/* Initializations. */
	master = om->master;

	/* Library inits. */
	ospf_debug_init();
	ospf_vrf_init();

	access_list_init();
	prefix_list_init();

	/* OSPFd inits. */
	ospf_if_init();
	ospf_zebra_init(master, instance);

	/* OSPF vty inits. */
	ospf_vty_init();
	ospf_vty_show_init();
	ospf_vty_clear_init();

	/* OSPF BFD init */
	ospf_bfd_init();

	ospf_route_map_init();
	ospf_opaque_init();

	/* OSPF errors init */
	ospf_error_init();

	/* Need to initialize the default ospf structure, so the interface mode
	   commands can be duly processed if they are received before 'router
	   ospf',
	   when quagga(ospfd) is restarted */
	if (!ospf_get_instance(instance)) {
		flog_err(EC_OSPF_INIT_FAIL, "OSPF instance init failed: %s",
			 strerror(errno));
		exit(1);
	}

	frr_config_fork();

	/* uBPF start  */
	if(!init_plugin_manager(api)) {
	    fprintf(stderr, "uBPF plugin manager start failed\n");
	    return EXIT_FAILURE;
	}
	init_queue_ext_send();
	start_ubpf_plugin_listener(api);

    // plugin started in boot time will be read from a json file.
    if (load_from_json(json_plugins) > 0) {
        fprintf(stderr, "[WARNING] Some plugins couldn't be loaded\n");
    } else {
        fprintf(stderr, "Plugins successfully loaded\n");
    }
    /* uBPF start complete */



	frr_run(master);

	/* Not reached. */
	return (0);
}
