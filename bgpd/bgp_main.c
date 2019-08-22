/* Main routine of bgpd.
 * Copyright (C) 1996, 97, 98, 1999 Kunihiro Ishiguro
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

#include <pthread.h>
#include "vector.h"
#include "command.h"
#include "getopt.h"
#include "thread.h"
#include <lib/version.h>
#include "memory.h"
#include "memory_vty.h"
#include "prefix.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "routemap.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "queue.h"
#include "vrf.h"
#include "bfd.h"
#include "libfrr.h"
#include "ns.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_keepalives.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_errors.h"

#include "ubpf_tools/include/public.h"

extern int init_queue_ext_send(void);

#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#include "bgp_ubpf_api.h"

#endif

/* bgpd options, we use GNU getopt library. */
static const struct option longopts[] = {
	{"bgp_port", required_argument, NULL, 'p'},
	{"listenon", required_argument, NULL, 'l'},
    {"plugins", required_argument, NULL, 'b'},
#if CONFDATE > 20190521
	CPP_NOTICE("-r / --retain has reached deprecation EOL, remove")
#endif
	{"retain", no_argument, NULL, 'r'},
	{"no_kernel", no_argument, NULL, 'n'},
	{"skip_runas", no_argument, NULL, 'S'},
	{"ecmp", required_argument, NULL, 'e'},
	{"int_num", required_argument, NULL, 'I'},
	{0}};

/* signal definitions */
void sighup(void);
void sigint(void);
void sigusr1(void);

static void bgp_exit(int);
static void bgp_vrf_terminate(void);

static proto_ext_fun_t api[46] = {
        {.fn = get_cmp_prefixes, .name = "get_cmp_prefixes"},
        {.fn = get_attr_from_prefix, .name = "get_attr_from_prefix"},
        {.fn = peer_from_prefix, .name = "peer_from_prefix"},
        {.fn = ebpf_peer_sort, .name = "ebpf_peer_sort"},
        {.fn = get_bgp_path_info_from_args, .name = "get_bgp_path_info_from_args"},
        {.fn = extra_from_prefix, .name = "extra_from_prefix"},
        {.fn = get_maxpath_cfg, .name = "get_maxpath_cfg"},
        {.fn = free_aspath_plugin, .name = "free_aspath_plugin"},
        {.fn = as_path_from_prefix, .name = "as_path_from_prefix"},
        {.fn = get_aspath_from_attr_args, .name = "get_aspath_from_attr_args"},
        {.fn = get_as_from_attr, .name = "get_as_from_attr"},
        {.fn = get_attr_from_path_info, .name = "get_attr_from_path_info"},
        {.fn = get_attr_from_args, .name = "get_attr_from_args"},
        {.fn = get_cluster_from_attr_path_info, .name = "get_cluster_from_attr_path_info"},
        {.fn = set_med_attr, .name = "set_med_attr"},
        {.fn = set_local_pref_attr, .name = "set_local_pref_attr"},
        {.fn = get_community_from_path_info, .name = "get_community_from_path_info"},
        {.fn = get_ecommunity_from_path_info, .name = "get_ecommunity_from_path_info"},
        {.fn = get_lcommunity_from_path_info, .name = "get_lcommunity_from_path_info"},
        {.fn = get_community_values_from_path_info, .name = "get_community_values_from_path_info"},
        {.fn = get_ecommunity_values_from_path_info, .name = "get_ecommunity_values_from_path_info"},
        {.fn = get_lcommunity_values_from_path_info, .name = "get_lcommunity_values_from_path_info"},
        {.fn = get_community_from_args, .name = "get_community_from_args"},
        {.fn = get_ecommunity_from_args, .name = "get_ecommunity_from_args"},
        {.fn = get_lcommunity_from_args, .name = "get_lcommunity_from_args"},
        {.fn = get_bgp_instance, .name = "get_bgp_instance"},
        {.fn = set_path_eq, .name = "set_path_eq"},
        {.fn = del_community_val_form_args_attr, .name = "del_community_val_form_args_attr"},
        {.fn = add_community_val_to_attr, .name = "add_community_val_to_attr"},
        {.fn = as_path_store_from_attr, .name = "as_path_store_from_attr"},
        {.fn = count_adj_rib_in_peer, .name = "count_adj_rib_in_peer"},
        {.fn = count_adj_rib_out_peer, .name = "count_adj_rib_out_peer"},
        {.fn = count_loc_rib_from_peer_args, .name = "count_loc_rib_from_peer_args"},
        {.fn = nb_matched_routes, .name = "nb_matched_routes"},
        {.fn = rib_lookup, .name = "rib_lookup"},
        {.fn = bgp_table_range_nb_ebpf, .name = "bgp_table_range_nb_ebpf"},
        {.fn = bpf_aspath_count_hops, .name = "bpf_aspath_count_hops"},
        {.fn = bpf_aspath_cmp_left, .name = "bpf_aspath_cmp_left"},
        {.fn = bpf_aspath_cmp_left_confed, .name = "bpf_aspath_cmp_left_confed"},
        {.fn = bpf_aspath_count_confeds, .name = "bpf_aspath_count_confeds"},
        {.fn = bpf_bgp_is_valid_label, .name = "bpf_bgp_is_valid_label"},
        {.fn = bpf_aspath_cmp, .name = "bpf_aspath_cmp"},
        {.fn = bpf_bgp_flag_check, .name = "bpf_bgp_flag_check"},
        {NULL},
};


static struct quagga_signal_t bgp_signals[] = {
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

/* privileges */
static zebra_capabilities_t _caps_p[] = {ZCAP_BIND, ZCAP_NET_RAW,
					 ZCAP_NET_ADMIN, ZCAP_SYS_ADMIN};

struct zebra_privs_t bgpd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0,
};

static struct frr_daemon_info bgpd_di;

/* SIGHUP handler. */
void sighup(void)
{
	zlog_info("SIGHUP received");

	/* Terminate all thread. */
	bgp_terminate();
	bgp_reset();
	zlog_info("bgpd restarting!");

	/* Reload config file. */
	vty_read_config(NULL, bgpd_di.config_file, config_default);

	/* Try to return to normal operation. */
}

/* SIGINT handler. */
__attribute__((__noreturn__)) void sigint(void)
{
	zlog_notice("Terminating on signal");
	assert(bm->terminating == false);
	bm->terminating = true;	/* global flag that shutting down */

	bgp_terminate();

	bgp_exit(0);

	exit(0);
}

/* SIGUSR1 handler. */
void sigusr1(void)
{
	zlog_rotate();
}

/*
  Try to free up allocations we know about so that diagnostic tools such as
  valgrind are able to better illuminate leaks.

  Zebra route removal and protocol teardown are not meant to be done here.
  For example, "retain_mode" may be set.
*/
static __attribute__((__noreturn__)) void bgp_exit(int status)
{
	struct bgp *bgp, *bgp_default;
	struct listnode *node, *nnode;

	/* it only makes sense for this to be called on a clean exit */
	assert(status == 0);

	frr_early_fini();

	bfd_gbl_exit();

	bgp_close();

	bgp_default = bgp_get_default();

	/* reverse bgp_master_init */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (bgp_default == bgp)
			continue;
		bgp_delete(bgp);
	}
	if (bgp_default)
		bgp_delete(bgp_default);

	/* reverse bgp_dump_init */
	bgp_dump_finish();

	/* reverse bgp_route_init */
	bgp_route_finish();

	/* cleanup route maps */
	bgp_route_map_terminate();

	/* reverse bgp_attr_init */
	bgp_attr_finish();

	/* stop pthreads */
	bgp_pthreads_finish();

	/* reverse access_list_init */
	access_list_add_hook(NULL);
	access_list_delete_hook(NULL);
	access_list_reset();

	/* reverse bgp_filter_init */
	as_list_add_hook(NULL);
	as_list_delete_hook(NULL);
	bgp_filter_reset();

	/* reverse prefix_list_init */
	prefix_list_add_hook(NULL);
	prefix_list_delete_hook(NULL);
	prefix_list_reset();

	/* reverse community_list_init */
	community_list_terminate(bgp_clist);

	bgp_vrf_terminate();
#if ENABLE_BGP_VNC
	vnc_zebra_destroy();
#endif
	bgp_zebra_destroy();

	bf_free(bm->rd_idspace);
	list_delete(&bm->bgp);

	bgp_lp_finish();

	memset(bm, 0, sizeof(*bm));

	remove_xsi(); // remove any queue and shared memory

	frr_fini();
	exit(status);
}

static int bgp_vrf_new(struct vrf *vrf)
{
	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF Created: %s(%u)", vrf->name, vrf->vrf_id);

	return 0;
}

static int bgp_vrf_delete(struct vrf *vrf)
{
	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF Deletion: %s(%u)", vrf->name, vrf->vrf_id);

	return 0;
}

static int bgp_vrf_enable(struct vrf *vrf)
{
	struct bgp *bgp;
	vrf_id_t old_vrf_id;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF enable add %s id %u", vrf->name, vrf->vrf_id);

	bgp = bgp_lookup_by_name(vrf->name);
	if (bgp) {
		if (bgp->name && strmatch(vrf->name, VRF_DEFAULT_NAME)) {
			XFREE(MTYPE_BGP, bgp->name);
			bgp->name = NULL;
			XFREE(MTYPE_BGP, bgp->name_pretty);
			bgp->name_pretty = XSTRDUP(MTYPE_BGP, "VRF default");
		}
		old_vrf_id = bgp->vrf_id;
		/* We have instance configured, link to VRF and make it "up". */
		bgp_vrf_link(bgp, vrf);

		bgp_handle_socket(bgp, vrf, old_vrf_id, true);
		/* Update any redistribute vrf bitmaps if the vrf_id changed */
		if (old_vrf_id != bgp->vrf_id)
			bgp_update_redist_vrf_bitmaps(bgp, old_vrf_id);
		bgp_instance_up(bgp);
		vpn_leak_zebra_vrf_label_update(bgp, AFI_IP);
		vpn_leak_zebra_vrf_label_update(bgp, AFI_IP6);
		vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP,
				    bgp_get_default(), bgp);
		vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP,
				    bgp_get_default(), bgp);
		vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6,
				    bgp_get_default(), bgp);
		vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP6,
				    bgp_get_default(), bgp);
	}

	return 0;
}

static int bgp_vrf_disable(struct vrf *vrf)
{
	struct bgp *bgp;
	vrf_id_t old_vrf_id;

	if (vrf->vrf_id == VRF_DEFAULT)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF disable %s id %d", vrf->name, vrf->vrf_id);

	bgp = bgp_lookup_by_name(vrf->name);
	if (bgp) {

		vpn_leak_zebra_vrf_label_withdraw(bgp, AFI_IP);
		vpn_leak_zebra_vrf_label_withdraw(bgp, AFI_IP6);
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP,
				   bgp_get_default(), bgp);
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP,
				   bgp_get_default(), bgp);
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6,
				   bgp_get_default(), bgp);
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP6,
				   bgp_get_default(), bgp);

		old_vrf_id = bgp->vrf_id;
		bgp_handle_socket(bgp, vrf, VRF_UNKNOWN, false);
		/* We have instance configured, unlink from VRF and make it
		 * "down". */
		bgp_vrf_unlink(bgp, vrf);
		/* Update any redistribute vrf bitmaps if the vrf_id changed */
		if (old_vrf_id != bgp->vrf_id)
			bgp_update_redist_vrf_bitmaps(bgp, old_vrf_id);
		bgp_instance_down(bgp);
	}

	/* Note: This is a callback, the VRF will be deleted by the caller. */
	return 0;
}

static void bgp_vrf_init(void)
{
	vrf_init(bgp_vrf_new, bgp_vrf_enable, bgp_vrf_disable,
		 bgp_vrf_delete, NULL);
}

static void bgp_vrf_terminate(void)
{
	vrf_terminate();
}

static const struct frr_yang_module_info *bgpd_yang_modules[] = {
};

FRR_DAEMON_INFO(bgpd, BGP, .vty_port = BGP_VTY_PORT,

		.proghelp = "Implementation of the BGP routing protocol.",

		.signals = bgp_signals, .n_signals = array_size(bgp_signals),

		.privs = &bgpd_privs, .yang_modules = bgpd_yang_modules,
		.n_yang_modules = array_size(bgpd_yang_modules), )

#if CONFDATE > 20190521
CPP_NOTICE("-r / --retain has reached deprecation EOL, remove")
#endif
#define DEPRECATED_OPTIONS "r"

/* Main routine of bgpd. Treatment of argument and start bgp finite
   state machine is handled at here. */
int main(int argc, char **argv)
{


    int p[2];
    if(pipe(p) < 0) {
        perror("Pipe");
        exit(EXIT_FAILURE);
    }


	int opt;
	int tmp_port;

	int bgp_port = BGP_PORT_DEFAULT;
	char *bgp_address = NULL;
	int no_fib_flag = 0;
	int no_zebra_flag = 0;
	int skip_runas = 0;
	int instance = 0;
	int plugins_flags = 0;

    char json_plugins[512];
    memset(json_plugins, 0, 512 * sizeof(char));
    int rval;

	frr_preinit(&bgpd_di, argc, argv);
	frr_opt_add(
		"p:l:Sne:I:b:" DEPRECATED_OPTIONS, longopts,
		"  -p, --bgp_port     Set BGP listen port number (0 means do not listen).\n"
		"  -l, --listenon     Listen on specified address (implies -n)\n"
		"  -n, --no_kernel    Do not install route to kernel.\n"
		"  -Z, --no_zebra     Do not communicate with Zebra.\n"
		"  -S, --skip_runas   Skip capabilities checks, and changing user and group IDs.\n"
		"  -e, --ecmp         Specify ECMP to use.\n"
		"  -I, --int_num      Set instance number (label-manager)\n"
        "  -b  --plugins      Path to the json formatted file, listing every plugins to load at startup\n");

	/* Command line argument treatment. */
	while (1) {
		opt = frr_getopt(argc, argv, 0);

		if (opt && opt < 128 && strchr(DEPRECATED_OPTIONS, opt)) {
			fprintf(stderr,
				"The -%c option no longer exists.\nPlease refer to the manual.\n",
				opt);
			continue;
		}

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'p':
			tmp_port = atoi(optarg);
			if (tmp_port < 0 || tmp_port > 0xffff)
				bgp_port = BGP_PORT_DEFAULT;
			else
				bgp_port = tmp_port;
			break;
		case 'e':
			multipath_num = atoi(optarg);
			if (multipath_num > MULTIPATH_NUM
			    || multipath_num <= 0) {
				flog_err(
					EC_BGP_MULTIPATH,
					"Multipath Number specified must be less than %d and greater than 0",
					MULTIPATH_NUM);
				return 1;
			}
			break;
		case 'l':
			bgp_address = optarg;
		/* listenon implies -n */
		/* fallthru */
		case 'n':
			no_fib_flag = 1;
			break;
		case 'Z':
			no_zebra_flag = 1;
			break;
		case 'S':
			skip_runas = 1;
			break;
		case 'I':
			instance = atoi(optarg);
			if (instance > (unsigned short)-1)
				zlog_err("Instance %i out of range (0..%u)",
					 instance, (unsigned short)-1);
			break;
		case 'b':
		    plugins_flags = 1;
		    snprintf(json_plugins, 511, "%s", optarg);

            rval = access(json_plugins, F_OK);
            if(rval != 0) {
                fprintf(stderr, "%s do not exist\n", json_plugins);
                exit(EXIT_FAILURE);
            }

            rval = access (json_plugins, R_OK);
		    if(rval != 0) {
		        fprintf(stderr, "%s is not readable\n", json_plugins);
		        exit(EXIT_FAILURE);
		    }
		    break;
		default:
			frr_help_exit(1);
			break;
		}
	}

    if(!plugins_flags) snprintf(json_plugins, 511, "%s/list_plugins.json", frr_sysconfdir);


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

    if (skip_runas)
		memset(&bgpd_privs, 0, sizeof(bgpd_privs));

	/* BGP master init. */
	bgp_master_init(frr_init());
	bm->port = bgp_port;
	if (bgp_port == 0)
		bgp_option_set(BGP_OPT_NO_LISTEN);
	bm->address = bgp_address;
	if (no_fib_flag || no_zebra_flag)
		bgp_option_set(BGP_OPT_NO_FIB);
	if (no_zebra_flag)
		bgp_option_set(BGP_OPT_NO_ZEBRA);
	bgp_error_init();
	/* Initializations. */
	bgp_vrf_init();

	/* BGP related initialization.  */
	bgp_init((unsigned short)instance);

	snprintf(bgpd_di.startinfo, sizeof(bgpd_di.startinfo), ", bgp@%s:%d",
		 (bm->address ? bm->address : "<all>"), bm->port);

	frr_config_fork();

	/// uBPF START ! (after an optionally daemonization otherwise created threads will be lost)


	if(!init_plugin_manager(api)){ // this function starts the monitoring server needed for some plugins
		fprintf(stderr, "Unable to start the plugin manager\n");
		return EXIT_FAILURE;
	}
    init_queue_ext_send();


    start_ubpf_plugin_listener(api); // listen for incoming new plugins


    // plugin started in boot time will be read from a json file.
    if (load_from_json(json_plugins) > 0) {
        fprintf(stderr, "[WARNING] Some plugins couldn't be loaded\n");
    } else {
    	fprintf(stderr, "Plugins successfuly loaded\n");
    }


	/// redirect stderr to temp
	/*int fd;
	fd = open("/tmp/uBPF_BGP_DEBUG.log", O_CREAT|O_RDWR, 0744);

	if(fd == -1){
	    fprintf(stderr, "Unable to open a fucking file\n");
	    return EXIT_FAILURE;
	}

	if(dup2(fd, fileno(stderr)) == -1){
	    fprintf(stderr, "Can't duplicate stderr\n");
	    return EXIT_FAILURE;
	}

	fprintf(stderr, "TESTTESTTEST\n");*/

	//// uBPF start end

	/* must be called after fork() */
	bgp_pthreads_run();
	frr_run(bm->master);

	/* Not reached. */
	return (0);
}
