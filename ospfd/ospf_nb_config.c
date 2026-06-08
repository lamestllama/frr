// SPDX-License-Identifier: GPL-2.0-or-later

#include <zebra.h>

#include "if.h"
#include "hash.h"
#include "log.h"
#include "northbound.h"
#include "plist.h"
#include "table.h"
#include "vty.h"
#include "yang.h"
#include "yang_wrappers.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_bfd.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_ldp_sync.h"
#include "ospfd/ospf_nb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_sr.h"
#include "ospfd/ospf_ri.h"
#include "ospfd/ospf_te.h"
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_zebra.h"

static struct ospf *routing_ospf_get(const struct lyd_node *dnode)
{
	return nb_running_get_entry(dnode, NULL, true);
}

static struct ospf *routing_ospf_lookup(const struct lyd_node *dnode)
{
	return nb_running_get_entry(dnode, NULL, false);
}

static struct ospf *routing_ospf_parent_entry(const void *parent_list_entry)
{
	if (parent_list_entry)
		return (struct ospf *)parent_list_entry;

	return ospf_lookup_instance(ospf_instance);
}

static bool routing_ospf_control_plane_protocol_is_ospf(
	const struct lyd_node *dnode)
{
	const char *type;

	type = yang_dnode_get_string(dnode, "type");
	return type && (!strcmp(type, "frr-ospfd:ospf") ||
			!strcmp(type, "ospf"));
}

static unsigned short
routing_ospf_control_plane_protocol_instance(const struct lyd_node *dnode)
{
	if (yang_dnode_exists(dnode, "frr-ospfd:ospf/instance"))
		return yang_dnode_get_uint16(dnode, "frr-ospfd:ospf/instance");

	return yang_get_default_uint16(FRR_OSPFD_OSPF_XPATH "/instance");
}

static const struct lyd_node *
routing_ospf_control_plane_protocol_dnode(const struct lyd_node *dnode)
{
	return yang_dnode_get_parent(dnode, "control-plane-protocol");
}

static int routing_ospf_validate_default_vrf(const struct lyd_node *dnode,
					     char *errmsg,
					     size_t errmsg_len)
{
	const struct lyd_node *cpp;
	const char *vrf_name;

	cpp = routing_ospf_control_plane_protocol_dnode(dnode);
	vrf_name = yang_dnode_get_string(cpp, "vrf");
	if (strmatch(vrf_name, VRF_DEFAULT_NAME))
		return NB_OK;

	snprintf(errmsg, errmsg_len, "This command only runs on DEFAULT VRF");
	return NB_ERR_VALIDATION;
}

int routing_control_plane_protocols_ospfd_validate(
	struct nb_cb_create_args *args)
{
	unsigned short instance;

	if (!routing_ospf_control_plane_protocol_is_ospf(args->dnode))
		return NB_OK;

	instance = routing_ospf_control_plane_protocol_instance(args->dnode);
	if (instance != ospf_instance) {
		snprintf(args->errmsg, args->errmsg_len,
			 "OSPF instance %u does not match this ospfd process",
			 instance);
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

int routing_control_plane_protocols_ospfd_create(struct nb_cb_create_args *args)
{
	const char *vrf_name;
	struct ospf *ospf;
	bool created;

	if (!routing_ospf_control_plane_protocol_is_ospf(args->dnode))
		return NB_OK;

	vrf_name = yang_dnode_get_string(args->dnode, "vrf");
	ospf = ospf_get(routing_ospf_control_plane_protocol_instance(args->dnode),
			vrf_name, &created);
	(void)created;

	nb_running_set_entry(args->dnode, ospf);

	return NB_OK;
}

int routing_control_plane_protocols_ospfd_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	if (!routing_ospf_control_plane_protocol_is_ospf(args->dnode))
		return NB_OK;

	ospf = nb_running_unset_entry(args->dnode);
	if (!ospf)
		return NB_OK;

	if (ospf->gr_info.restart_support)
		ospf_gr_nvm_delete(ospf);
	ospf_finish(ospf);

	return NB_OK;
}

static struct interface *lib_interface_ospf_get_ifp(const struct lyd_node *dnode)
{
	return nb_running_get_entry(dnode, NULL, true);
}

static bool lib_interface_ospf_ensure_if_info(struct interface *ifp)
{
	if (!ifp)
		return false;

	if (!IF_OSPF_IF_INFO(ifp) && ospf_if_new_hook(ifp) != 0)
		return false;

	return IF_OSPF_IF_INFO(ifp) && IF_DEF_PARAMS(ifp);
}

static struct ospf_if_params *
lib_interface_ospf_get_params(const struct lyd_node *dnode)
{
	struct interface *ifp;

	ifp = lib_interface_ospf_get_ifp(dnode);
	if (!lib_interface_ospf_ensure_if_info(ifp))
		return NULL;

	return IF_DEF_PARAMS(ifp);
}

static const struct lyd_node *
lib_interface_ospf_address_dnode(const struct lyd_node *dnode)
{
	return yang_dnode_get_parent(dnode, "interface-address");
}

static bool lib_interface_ospf_address(const struct lyd_node *dnode,
				       struct in_addr *addr)
{
	const struct lyd_node *addr_dnode;

	addr_dnode = lib_interface_ospf_address_dnode(dnode);
	if (!addr_dnode)
		return false;

	yang_dnode_get_ipv4(addr, addr_dnode, "address");
	return true;
}

static struct ospf_if_params *
lib_interface_ospf_get_address_params(const struct lyd_node *dnode, bool create,
				      struct interface **ifp_out,
				      struct in_addr *addr_out)
{
	struct ospf_if_params *params;
	struct interface *ifp;
	struct in_addr addr;

	ifp = lib_interface_ospf_get_ifp(dnode);
	if (!lib_interface_ospf_ensure_if_info(ifp))
		return NULL;
	if (!lib_interface_ospf_address(dnode, &addr))
		return NULL;

	params = create ? ospf_get_if_params(ifp, addr)
			: ospf_lookup_if_params(ifp, addr);
	if (create && params)
		ospf_if_update_params(ifp, addr);
	if (ifp_out)
		*ifp_out = ifp;
	if (addr_out)
		*addr_out = addr;

	return params;
}

static void lib_interface_ospf_free_address_params(struct interface *ifp,
						   struct in_addr addr)
{
	ospf_free_if_params(ifp, addr);
	ospf_if_update_params(ifp, addr);
}

static void
lib_interface_ospf_clear_address_params(struct ospf_if_params *params)
{
	struct listnode *node;
	struct listnode *nnode;
	struct crypt_key *ck;

	UNSET_IF_PARAM(params, output_cost_cmd);
	UNSET_IF_PARAM(params, transmit_delay);
	UNSET_IF_PARAM(params, retransmit_interval);
	UNSET_IF_PARAM(params, retransmit_window);
	UNSET_IF_PARAM(params, passive_interface);
	UNSET_IF_PARAM(params, v_hello);
	UNSET_IF_PARAM(params, fast_hello);
	UNSET_IF_PARAM(params, v_gr_hello_delay);
	UNSET_IF_PARAM(params, v_wait);
	UNSET_IF_PARAM(params, priority);
	UNSET_IF_PARAM(params, auth_simple);
	UNSET_IF_PARAM(params, auth_type);
	UNSET_IF_PARAM(params, if_area);
	UNSET_IF_PARAM(params, opaque_capable);
	UNSET_IF_PARAM(params, prefix_suppression);
	UNSET_IF_PARAM(params, keychain_name);
	UNSET_IF_PARAM(params, nbr_filter_name);
	UNSET_IF_PARAM(params, mtu_ignore);

	memset(params->auth_simple, 0, sizeof(params->auth_simple));
	params->auth_type = OSPF_AUTH_NOTSET;
	XFREE(MTYPE_OSPF_IF_PARAMS, params->keychain_name);
	XFREE(MTYPE_OSPF_IF_PARAMS, params->nbr_filter_name);

	for (ALL_LIST_ELEMENTS(params->auth_crypt, node, nnode, ck)) {
		listnode_delete(params->auth_crypt, ck);
		XFREE(MTYPE_OSPF_CRYPT_KEY, ck);
	}
}

static bool lib_interface_ospf_oi_matches_addr(struct ospf_interface *oi,
					       struct in_addr addr)
{
	return oi && oi->address &&
	       IPV4_ADDR_SAME(&oi->address->u.prefix4, &addr);
}

static void lib_interface_ospf_nbr_timer_update_addr(struct interface *ifp,
						     struct in_addr addr)
{
	struct route_node *rn;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (lib_interface_ospf_oi_matches_addr(oi, addr))
			ospf_nbr_timer_update(oi);
	}
}

static void lib_interface_ospf_flap_addr(struct interface *ifp,
					 struct in_addr addr)
{
	struct route_node *rn;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (lib_interface_ospf_oi_matches_addr(oi, addr) &&
		    oi->state > ISM_Down) {
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
		}
	}
}

static void lib_interface_ospf_multicast_update(struct interface *ifp)
{
	struct route_node *rn;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (oi)
			ospf_if_set_multicast(oi);
	}
}

static void
lib_interface_ospf_prefix_suppression_lsa_update_addr(struct interface *ifp,
						      struct in_addr addr)
{
	struct route_node *rn;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (lib_interface_ospf_oi_matches_addr(oi, addr) &&
		    oi->state > ISM_Down) {
			(void)ospf_router_lsa_update_area(oi->area);
			if (oi->state == ISM_DR)
				ospf_network_lsa_update(oi);
		}
	}
}

static void lib_interface_ospf_neighbor_filter_update_addr(struct interface *ifp,
							   struct in_addr addr)
{
	struct prefix_list *nbr_filter;
	struct route_node *rn;
	const char *name;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!lib_interface_ospf_oi_matches_addr(oi, addr))
			continue;

		name = OSPF_IF_PARAM(oi, nbr_filter_name);
		nbr_filter = name ? prefix_list_lookup(AFI_IP, name) : NULL;
		if (oi->nbr_filter == nbr_filter)
			continue;

		oi->nbr_filter = nbr_filter;
		if (oi->nbr_filter)
			ospf_intf_neighbor_filter_apply(oi);
	}
}

static void
lib_interface_ospf_gr_hello_delay_reset_addr(struct interface *ifp,
					     struct in_addr addr)
{
	struct route_node *rn;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!lib_interface_ospf_oi_matches_addr(oi, addr))
			continue;

		oi->gr.hello_delay.elapsed_seconds = 0;
		event_cancel(&oi->gr.hello_delay.t_grace_send);
	}
}

static void lib_interface_ospf_gr_hello_delay_reset(struct interface *ifp)
{
	struct route_node *rn;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;

		oi->gr.hello_delay.elapsed_seconds = 0;
		event_cancel(&oi->gr.hello_delay.t_grace_send);
	}
}

static int lib_interface_ospf_attachment_instance(const struct lyd_node *dnode)
{
	const struct lyd_node *attachment;

	attachment = yang_dnode_get_parent(dnode, "attachment");
	if (!attachment)
		return -1;

	return yang_dnode_get_uint16(attachment, "instance");
}

static struct ospf *
lib_interface_ospf_attachment_get_ospf(const struct lyd_node *dnode)
{
	int instance;

	instance = lib_interface_ospf_attachment_instance(dnode);
	if (instance < 0)
		return NULL;

	return ospf_lookup_instance(instance);
}

static int
lib_interface_ospf_attachment_area_id(const struct lyd_node *dnode,
				      struct in_addr *area_id)
{
	const struct lyd_node *attachment;
	const char *area_id_str;
	int format;

	attachment = yang_dnode_get_parent(dnode, "attachment");
	if (!attachment)
		return -1;

	area_id_str = yang_dnode_get_string(attachment, "area-id");
	return str2area_id(area_id_str, area_id, &format);
}

static bool routing_ospf_has_networks(struct ospf *ospf)
{
	struct route_node *rn;

	if (!ospf || !ospf->networks)
		return false;

	for (rn = route_top(ospf->networks); rn; rn = route_next(rn))
		if (rn->info)
			return true;

	return false;
}

static uint16_t routing_ospf_instance(const struct lyd_node *dnode)
{
	const struct lyd_node *ospf_dnode;

	ospf_dnode = yang_dnode_get_parent(dnode, "ospf");
	if (!ospf_dnode || !yang_dnode_exists(ospf_dnode, "instance"))
		return 0;

	return yang_dnode_get_uint16(ospf_dnode, "instance");
}

static const struct lyd_node *
routing_ospf_area_dnode(const struct lyd_node *dnode)
{
	return yang_dnode_get_parent(dnode, "area");
}

static int routing_ospf_area_id(const struct lyd_node *dnode,
				struct in_addr *area_id)
{
	const struct lyd_node *area_dnode;
	const char *area_id_str;
	int format;

	area_dnode = routing_ospf_area_dnode(dnode);
	if (!area_dnode)
		return -1;

	area_id_str = yang_dnode_get_string(area_dnode, "area-id");
	return str2area_id(area_id_str, area_id, &format);
}

static struct ospf_area *
routing_ospf_area_get(const struct lyd_node *dnode, bool create)
{
	struct ospf *ospf;
	struct ospf_area *area;
	struct in_addr area_id;

	ospf = routing_ospf_get(dnode);
	if (routing_ospf_area_id(dnode, &area_id) < 0)
		return NULL;

	area = create ? ospf_area_get(ospf, area_id)
		      : ospf_area_lookup_by_area_id(ospf, area_id);
	return area;
}

static struct ospf_area *
routing_ospf_area_lookup(const struct lyd_node *dnode)
{
	struct ospf *ospf;
	struct in_addr area_id;

	ospf = routing_ospf_lookup(dnode);
	if (!ospf || routing_ospf_area_id(dnode, &area_id) < 0)
		return NULL;

	return ospf_area_lookup_by_area_id(ospf, area_id);
}

static void routing_ospf_area_announce_default(struct ospf_area *area)
{
	struct prefix_ipv4 p = {};

	p.family = AF_INET;
	p.prefix.s_addr = OSPF_DEFAULT_DESTINATION;
	p.prefixlen = 0;
	ospf_abr_announce_network_to_area(&p, area->default_cost, area);
}

static void routing_ospf_area_filter_set(struct ospf *ospf,
					 struct ospf_area *area, bool in,
					 const char *name)
{
	struct prefix_list *plist;
	char **namep;
	struct prefix_list **listp;

	plist = prefix_list_lookup(AFI_IP, name);
	listp = in ? &PREFIX_LIST_IN(area) : &PREFIX_LIST_OUT(area);
	namep = in ? &PREFIX_NAME_IN(area) : &PREFIX_NAME_OUT(area);

	*listp = plist;
	free(*namep);
	*namep = strdup(name);
	ospf_schedule_abr_task(ospf);
}

static void routing_ospf_area_filter_unset(struct ospf *ospf,
					   struct ospf_area *area, bool in)
{
	char **namep;
	struct prefix_list **listp;

	listp = in ? &PREFIX_LIST_IN(area) : &PREFIX_LIST_OUT(area);
	namep = in ? &PREFIX_NAME_IN(area) : &PREFIX_NAME_OUT(area);

	*listp = NULL;
	free(*namep);
	*namep = NULL;
	ospf_schedule_abr_task(ospf);
	ospf_area_check_free(ospf, area->area_id);
}

static void routing_ospf_area_flood_reduction_set(struct ospf *ospf,
						  struct ospf_area *area,
						  bool enabled)
{
	if (area->fr_info.configured == enabled)
		return;

	area->fr_info.configured = enabled;
	ospf_area_update_fr_state(area);
	ospf_refresh_area_self_lsas(area);
	if (!enabled)
		ospf_area_check_free(ospf, area->area_id);
}

static void routing_ospf_flood_reduction_set(struct ospf *ospf, bool enabled)
{
	struct ospf_area *area;
	struct listnode *node;

	if (ospf->fr_configured == enabled)
		return;

	ospf->fr_configured = enabled;
	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (!area)
			continue;

		ospf_area_update_fr_state(area);
		ospf_refresh_area_self_lsas(area);
	}
}

static void routing_ospf_passive_interface_default_set(struct ospf *ospf,
						       bool passive)
{
	struct ospf_interface *oi;
	struct listnode *node;

	ospf->passive_interface_default = passive ? OSPF_IF_PASSIVE
						  : OSPF_IF_ACTIVE;

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi))
		ospf_if_set_multicast(oi);
}

static int routing_ospf_metric_type_from_yang(int value)
{
	switch (value) {
	case 1:
		return EXTERNAL_METRIC_TYPE_1;
	case 2:
		return EXTERNAL_METRIC_TYPE_2;
	}

	return DEFAULT_METRIC_TYPE;
}

static int routing_ospf_area_nssa_metric(const struct lyd_node *dnode)
{
	const struct lyd_node *dio;

	dio = yang_dnode_get_parent(dnode, "default-information-originate");
	if (dio && yang_dnode_exists(dio, "metric"))
		return yang_dnode_get_uint32(dio, "metric");

	return -1;
}

static int routing_ospf_area_nssa_metric_type(const struct lyd_node *dnode)
{
	const struct lyd_node *dio;

	dio = yang_dnode_get_parent(dnode, "default-information-originate");
	if (dio && yang_dnode_exists(dio, "metric-type"))
		return routing_ospf_metric_type_from_yang(
			yang_dnode_get_enum(dio, "metric-type"));

	return DEFAULT_METRIC_TYPE;
}

static const struct lyd_node *
routing_ospf_area_range_dnode(const struct lyd_node *dnode)
{
	return yang_dnode_get_parent(dnode, "range");
}

static bool routing_ospf_area_range_prefix(const struct lyd_node *dnode,
					   struct prefix_ipv4 *p)
{
	const struct lyd_node *range_dnode;

	range_dnode = routing_ospf_area_range_dnode(dnode);
	if (!range_dnode)
		return false;

	yang_dnode_get_ipv4p(p, range_dnode, "prefix");
	return true;
}

static int routing_ospf_area_range_apply(const struct lyd_node *dnode,
					 bool nssa)
{
	const struct lyd_node *range_dnode;
	struct route_table *ranges;
	struct ospf_area *area;
	struct prefix_ipv4 p;
	struct prefix_ipv4 s;
	bool advertise;

	area = routing_ospf_area_get(dnode, true);
	if (!area || !routing_ospf_area_range_prefix(dnode, &p))
		return NB_ERR_INCONSISTENCY;

	range_dnode = routing_ospf_area_range_dnode(dnode);
	ranges = nssa ? area->nssa_ranges : area->ranges;
	if (nssa)
		advertise = !yang_dnode_get_bool(range_dnode, "not-advertise");
	else
		advertise = yang_dnode_get_bool(range_dnode, "advertise");

	ospf_area_range_set(area->ospf, area, ranges, &p,
			    advertise ? OSPF_AREA_RANGE_ADVERTISE : 0, nssa);

	if (yang_dnode_exists(range_dnode, "cost"))
		ospf_area_range_cost_set(area->ospf, area, ranges, &p,
					 yang_dnode_get_uint32(range_dnode,
							       "cost"));

	if (!nssa) {
		if (advertise && yang_dnode_exists(range_dnode, "substitute")) {
			yang_dnode_get_ipv4p(&s, range_dnode, "substitute");
			ospf_area_range_substitute_set(area->ospf, area, &p,
						       &s);
		} else if (!advertise) {
			ospf_area_range_substitute_unset(area->ospf, area, &p);
		}
	}

	return NB_OK;
}

static int routing_ospf_area_range_delete(const struct lyd_node *dnode,
					  bool nssa)
{
	struct route_table *ranges;
	struct ospf_area *area;
	struct prefix_ipv4 p;

	area = routing_ospf_area_get(dnode, false);
	if (!area)
		return NB_OK;
	if (!routing_ospf_area_range_prefix(dnode, &p))
		return NB_ERR_INCONSISTENCY;

	ranges = nssa ? area->nssa_ranges : area->ranges;
	ospf_area_range_unset(area->ospf, area, ranges, &p);
	ospf_area_check_free(area->ospf, area->area_id);
	return NB_OK;
}

static int routing_ospf_area_range_cost_delete(const struct lyd_node *dnode,
					       bool nssa)
{
	struct ospf_area_range *range;
	struct route_table *ranges;
	struct ospf_area *area;
	struct prefix_ipv4 p;

	area = routing_ospf_area_get(dnode, false);
	if (!area)
		return NB_OK;
	if (!routing_ospf_area_range_prefix(dnode, &p))
		return NB_ERR_INCONSISTENCY;

	ranges = nssa ? area->nssa_ranges : area->ranges;
	range = ospf_area_range_lookup(area, ranges, &p);
	if (!range)
		return NB_OK;

	if (range->cost_config != OSPF_AREA_RANGE_COST_UNSPEC) {
		range->cost_config = OSPF_AREA_RANGE_COST_UNSPEC;
		if (ospf_area_range_active(range))
			ospf_schedule_abr_task(area->ospf);
	}

	return NB_OK;
}

static int routing_ospf_area_range_option_modify(struct nb_cb_modify_args *args,
						 bool nssa)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_area_range_apply(args->dnode, nssa);
	}

	return NB_OK;
}

static int
routing_ospf_area_range_cost_destroy(struct nb_cb_destroy_args *args, bool nssa)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_area_range_cost_delete(args->dnode, nssa);
	}

	return NB_OK;
}

static int lib_interface_ospf_md5_key_set(struct ospf_if_params *params,
					  uint8_t key_id, const char *key);
static int lib_interface_ospf_md5_key_delete(struct ospf_if_params *params,
					     uint8_t key_id);

static const struct lyd_node *
routing_ospf_area_virtual_link_dnode(const struct lyd_node *dnode)
{
	return yang_dnode_get_parent(dnode, "virtual-link");
}

static bool routing_ospf_area_virtual_link_peer(const struct lyd_node *dnode,
						struct in_addr *peer)
{
	const struct lyd_node *vlink_dnode;

	vlink_dnode = routing_ospf_area_virtual_link_dnode(dnode);
	if (!vlink_dnode)
		return false;

	yang_dnode_get_ipv4(peer, vlink_dnode, "neighbor");
	return true;
}

static int routing_ospf_area_virtual_link_validate(const struct lyd_node *dnode,
						   char *errmsg,
						   size_t errmsg_len)
{
	struct ospf_area *area;
	struct in_addr area_id;
	struct ospf *ospf;

	if (routing_ospf_area_id(dnode, &area_id) < 0)
		return NB_ERR_INCONSISTENCY;

	if (area_id.s_addr == OSPF_AREA_BACKBONE) {
		snprintf(errmsg, errmsg_len,
			 "Configuring VLs over the backbone is not allowed");
		return NB_ERR_VALIDATION;
	}

	ospf = routing_ospf_lookup(dnode);
	if (!ospf)
		return NB_OK;

	if (!CHECK_FLAG(ospf->flags, OSPF_FLAG_ABR)) {
		snprintf(errmsg, errmsg_len,
			 "Configuring VLs on non-ABRs is not allowed");
		return NB_ERR_VALIDATION;
	}

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area && area->external_routing != OSPF_AREA_DEFAULT) {
		snprintf(errmsg, errmsg_len,
			 "Virtual links require a normal transit area");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static struct ospf_vl_data *
routing_ospf_area_virtual_link_get(const struct lyd_node *dnode, bool create,
				   char *errmsg, size_t errmsg_len)
{
	struct ospf_vl_data *vl_data;
	struct ospf_area *area;
	struct in_addr area_id;
	struct in_addr peer;
	struct ospf *ospf;

	ospf = routing_ospf_get(dnode);
	if (routing_ospf_area_id(dnode, &area_id) < 0 ||
	    !routing_ospf_area_virtual_link_peer(dnode, &peer))
		return NULL;

	if (area_id.s_addr == OSPF_AREA_BACKBONE) {
		snprintf(errmsg, errmsg_len,
			 "Configuring VLs over the backbone is not allowed");
		return NULL;
	}

	if (!CHECK_FLAG(ospf->flags, OSPF_FLAG_ABR)) {
		snprintf(errmsg, errmsg_len,
			 "Configuring VLs on non-ABRs is not allowed");
		return NULL;
	}

	area = create ? ospf_area_get(ospf, area_id)
		      : ospf_area_lookup_by_area_id(ospf, area_id);
	if (!area)
		return NULL;

	if (area->external_routing != OSPF_AREA_DEFAULT) {
		snprintf(errmsg, errmsg_len,
			 "Virtual links require a normal transit area");
		return NULL;
	}

	vl_data = ospf_vl_lookup(ospf, area, peer);
	if (vl_data || !create)
		return vl_data;

	vl_data = ospf_vl_data_new(area, peer);
	if (!vl_data)
		return NULL;

	vl_data->vl_oi = ospf_vl_new(ospf, vl_data);
	if (!vl_data->vl_oi) {
		ospf_vl_data_free(vl_data);
		return NULL;
	}

	ospf_vl_add(ospf, vl_data);
	ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);
	return vl_data;
}

static struct ospf_if_params *
routing_ospf_area_virtual_link_params(const struct lyd_node *dnode,
				      char *errmsg, size_t errmsg_len)
{
	struct ospf_vl_data *vl_data;
	struct interface *ifp;

	vl_data = routing_ospf_area_virtual_link_get(dnode, true, errmsg,
						     errmsg_len);
	if (!vl_data || !vl_data->vl_oi || !vl_data->vl_oi->ifp)
		return NULL;

	ifp = vl_data->vl_oi->ifp;
	if (!lib_interface_ospf_ensure_if_info(ifp))
		return NULL;

	return IF_DEF_PARAMS(ifp);
}

static struct interface *
routing_ospf_area_virtual_link_ifp(const struct lyd_node *dnode, char *errmsg,
				   size_t errmsg_len)
{
	struct ospf_vl_data *vl_data;

	vl_data = routing_ospf_area_virtual_link_get(dnode, true, errmsg,
						     errmsg_len);
	if (!vl_data || !vl_data->vl_oi || !vl_data->vl_oi->ifp)
		return NULL;

	return vl_data->vl_oi->ifp;
}

static int lib_interface_ospf_auth_mode_from_dnode(const struct lyd_node *dnode)
{
	switch (yang_dnode_get_enum(dnode, NULL)) {
	case 0:
		return OSPF_AUTH_NULL;
	case 1:
		return OSPF_AUTH_SIMPLE;
	case 2:
	case 3:
		return OSPF_AUTH_CRYPTOGRAPHIC;
	}

	return OSPF_AUTH_NOTSET;
}

static uint8_t
routing_ospf_area_virtual_link_md5_key_id(const struct lyd_node *dnode)
{
	const struct lyd_node *key_dnode;

	key_dnode = yang_dnode_get_parent(dnode, "message-digest-key");
	if (!key_dnode)
		return 0;

	return yang_dnode_get_uint8(key_dnode, "key-id");
}

static int routing_ospf_area_virtual_link_md5_key_set(const struct lyd_node *dnode,
						      char *errmsg,
						      size_t errmsg_len)
{
	const struct lyd_node *key_dnode;
	struct ospf_if_params *params;
	uint8_t key_id;

	key_dnode = yang_dnode_get_parent(dnode, "message-digest-key");
	if (!key_dnode || !yang_dnode_exists(key_dnode, "md5-key"))
		return NB_OK;

	params = routing_ospf_area_virtual_link_params(key_dnode, errmsg,
						       errmsg_len);
	if (!params)
		return NB_ERR_INCONSISTENCY;

	key_id = routing_ospf_area_virtual_link_md5_key_id(key_dnode);
	return lib_interface_ospf_md5_key_set(
		params, key_id, yang_dnode_get_string(key_dnode, "md5-key"));
}

static int
routing_ospf_area_virtual_link_md5_key_delete(const struct lyd_node *dnode,
					      char *errmsg, size_t errmsg_len)
{
	const struct lyd_node *key_dnode;
	struct ospf_if_params *params;
	uint8_t key_id;

	key_dnode = yang_dnode_get_parent(dnode, "message-digest-key");
	if (!key_dnode)
		return NB_OK;

	params = routing_ospf_area_virtual_link_params(key_dnode, errmsg,
						       errmsg_len);
	if (!params)
		return NB_OK;

	key_id = routing_ospf_area_virtual_link_md5_key_id(key_dnode);
	return lib_interface_ospf_md5_key_delete(params, key_id);
}

static void lib_interface_ospf_nbr_timer_update(struct interface *ifp)
{
	struct route_node *rn;
	struct ospf_interface *oi;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		oi = rn->info;
		if (oi)
			ospf_nbr_timer_update(oi);
	}
}

static void lib_interface_ospf_auth_mode_set(struct ospf_if_params *params,
					     int mode)
{
	SET_IF_PARAM(params, auth_type);
	params->auth_type = mode;
}

static void lib_interface_ospf_auth_mode_unset(struct ospf_if_params *params)
{
	UNSET_IF_PARAM(params, auth_type);
	params->auth_type = OSPF_AUTH_NOTSET;
}

static void lib_interface_ospf_auth_simple_set(struct ospf_if_params *params,
					       const char *key)
{
	memset(params->auth_simple, 0, OSPF_AUTH_SIMPLE_SIZE + 1);
	strlcpy((char *)params->auth_simple, key, sizeof(params->auth_simple));
	SET_IF_PARAM(params, auth_simple);
}

static void lib_interface_ospf_auth_simple_unset(struct ospf_if_params *params)
{
	memset(params->auth_simple, 0, OSPF_AUTH_SIMPLE_SIZE + 1);
	UNSET_IF_PARAM(params, auth_simple);
}

static void lib_interface_ospf_key_chain_set(struct ospf_if_params *params,
					     const char *name)
{
	lib_interface_ospf_auth_mode_set(params, OSPF_AUTH_CRYPTOGRAPHIC);
	SET_IF_PARAM(params, keychain_name);
	XFREE(MTYPE_OSPF_IF_PARAMS, params->keychain_name);
	params->keychain_name = XSTRDUP(MTYPE_OSPF_IF_PARAMS, name);
	UNSET_IF_PARAM(params, auth_crypt);
}

static void lib_interface_ospf_key_chain_unset(struct ospf_if_params *params)
{
	UNSET_IF_PARAM(params, keychain_name);
	XFREE(MTYPE_OSPF_IF_PARAMS, params->keychain_name);
}

static int lib_interface_ospf_md5_key_set(struct ospf_if_params *params,
					  uint8_t key_id, const char *key)
{
	struct crypt_key *ck;

	if (!key_id)
		return NB_ERR_INCONSISTENCY;

	ospf_crypt_key_delete(params->auth_crypt, key_id);

	ck = ospf_crypt_key_new();
	ck->key_id = key_id;
	memset(ck->auth_key, 0, OSPF_AUTH_MD5_SIZE + 1);
	strlcpy((char *)ck->auth_key, key, sizeof(ck->auth_key));
	ospf_crypt_key_add(params->auth_crypt, ck);
	SET_IF_PARAM(params, auth_crypt);
	return NB_OK;
}

static int lib_interface_ospf_md5_key_delete(struct ospf_if_params *params,
					     uint8_t key_id)
{
	if (!key_id)
		return NB_ERR_INCONSISTENCY;

	ospf_crypt_key_delete(params->auth_crypt, key_id);
	if (list_isempty(params->auth_crypt))
		UNSET_IF_PARAM(params, auth_crypt);
	return NB_OK;
}

static void lib_interface_ospf_set_hello_interval(struct ospf_if_params *params,
						  uint32_t seconds,
						  bool configured)
{
	if (configured)
		SET_IF_PARAM(params, v_hello);
	else
		UNSET_IF_PARAM(params, v_hello);

	params->v_hello = seconds;
}

static void lib_interface_ospf_set_dead_interval(struct ospf_if_params *params,
						 uint32_t seconds,
						 bool configured)
{
	if (configured)
		SET_IF_PARAM(params, v_wait);
	else
		UNSET_IF_PARAM(params, v_wait);

	params->v_wait = seconds;
	params->is_v_wait_set = configured;
}

static void
lib_interface_ospf_set_retransmit_interval(struct ospf_if_params *params,
					   uint32_t seconds,
					   bool configured)
{
	if (configured)
		SET_IF_PARAM(params, retransmit_interval);
	else
		UNSET_IF_PARAM(params, retransmit_interval);

	params->retransmit_interval = seconds;
}

static void
lib_interface_ospf_set_retransmit_window(struct ospf_if_params *params,
					 uint32_t milliseconds, bool configured)
{
	if (configured)
		SET_IF_PARAM(params, retransmit_window);
	else
		UNSET_IF_PARAM(params, retransmit_window);

	params->retransmit_window = milliseconds;
}

static void lib_interface_ospf_set_transmit_delay(struct ospf_if_params *params,
						  uint32_t seconds,
						  bool configured)
{
	if (configured)
		SET_IF_PARAM(params, transmit_delay);
	else
		UNSET_IF_PARAM(params, transmit_delay);

	params->transmit_delay = seconds;
}

static void lib_interface_ospf_priority_update(struct interface *ifp)
{
	struct route_node *rn;
	struct ospf_interface *oi;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		oi = rn->info;
		if (!oi)
			continue;

		if (PRIORITY(oi) == OSPF_IF_PARAM(oi, priority))
			continue;

		PRIORITY(oi) = OSPF_IF_PARAM(oi, priority);
			OSPF_ISM_EVENT_SCHEDULE(oi, ISM_NeighborChange);
	}
}

static int lib_interface_ospf_iftype_from_yang(const char *val)
{
	if (!strcmp(val, "broadcast"))
		return OSPF_IFTYPE_BROADCAST;
	if (!strcmp(val, "non-broadcast"))
		return OSPF_IFTYPE_NBMA;
	if (!strcmp(val, "point-to-multipoint"))
		return OSPF_IFTYPE_POINTOMULTIPOINT;
	if (!strcmp(val, "point-to-point"))
		return OSPF_IFTYPE_POINTOPOINT;

	return -1;
}

static void lib_interface_ospf_flap_oifs(struct interface *ifp)
{
	struct route_node *rn;

	if (!IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (oi && oi->state > ISM_Down) {
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
		}
	}
}

static void lib_interface_ospf_apply_interface_type(struct interface *ifp,
						    int new_type)
{
	struct ospf_if_params *params;
	struct route_node *rn;
	int old_type;
	uint8_t old_ptp_dmvpn;
	uint8_t old_p2mp_delay_reflood;
	uint8_t old_p2mp_non_broadcast;

	if (!lib_interface_ospf_ensure_if_info(ifp))
		return;

	params = IF_DEF_PARAMS(ifp);
	old_type = params->type;
	old_ptp_dmvpn = params->ptp_dmvpn;
	old_p2mp_delay_reflood = params->p2mp_delay_reflood;
	old_p2mp_non_broadcast = params->p2mp_non_broadcast;

	params->ptp_dmvpn = 0;
	params->p2mp_delay_reflood = OSPF_P2MP_DELAY_REFLOOD_DEFAULT;
	params->p2mp_non_broadcast = OSPF_P2MP_NON_BROADCAST_DEFAULT;
	params->type = new_type;
	params->type_cfg = true;
	SET_IF_PARAM(params, type);

	if (params->type == old_type && params->ptp_dmvpn == old_ptp_dmvpn &&
	    params->p2mp_delay_reflood == old_p2mp_delay_reflood &&
	    params->p2mp_non_broadcast == old_p2mp_non_broadcast)
		return;

	if (!IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;

		oi->type = params->type;
		oi->ptp_dmvpn = params->ptp_dmvpn;
		oi->p2mp_delay_reflood = params->p2mp_delay_reflood;
		oi->p2mp_non_broadcast = params->p2mp_non_broadcast;

		if (oi->type != old_type || oi->ptp_dmvpn != old_ptp_dmvpn ||
		    oi->p2mp_non_broadcast != old_p2mp_non_broadcast) {
			if (oi->state > ISM_Down) {
				OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
				OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
			}
		}
	}
}

enum lib_interface_ospf_network_option {
	LIB_INTERFACE_OSPF_PTP_DMVPN,
	LIB_INTERFACE_OSPF_P2MP_DELAY_REFLOOD,
	LIB_INTERFACE_OSPF_P2MP_NON_BROADCAST,
};

static void lib_interface_ospf_apply_network_option(
	struct interface *ifp, enum lib_interface_ospf_network_option option,
	bool enabled)
{
	struct ospf_if_params *params;
	struct route_node *rn;
	bool old_value = false;
	bool flap = false;

	if (!lib_interface_ospf_ensure_if_info(ifp))
		return;

	params = IF_DEF_PARAMS(ifp);
	switch (option) {
	case LIB_INTERFACE_OSPF_PTP_DMVPN:
		old_value = params->ptp_dmvpn;
		params->ptp_dmvpn = enabled ? 1 : 0;
		flap = old_value != params->ptp_dmvpn;
		break;
	case LIB_INTERFACE_OSPF_P2MP_DELAY_REFLOOD:
		old_value = params->p2mp_delay_reflood;
		params->p2mp_delay_reflood = enabled;
		flap = false;
		break;
	case LIB_INTERFACE_OSPF_P2MP_NON_BROADCAST:
		old_value = params->p2mp_non_broadcast;
		params->p2mp_non_broadcast = enabled;
		flap = old_value != params->p2mp_non_broadcast;
		break;
	}

	if (!IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;

		oi->ptp_dmvpn = params->ptp_dmvpn;
		oi->p2mp_delay_reflood = params->p2mp_delay_reflood;
		oi->p2mp_non_broadcast = params->p2mp_non_broadcast;

		if (flap && oi->state > ISM_Down) {
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
		}
	}
}

static void lib_interface_ospf_prefix_suppression_lsa_update(struct interface *ifp)
{
	struct route_node *rn;

	if (!IF_OSPF_IF_INFO(ifp) || !IF_OIFS(ifp))
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (oi && oi->state > ISM_Down) {
			(void)ospf_router_lsa_update_area(oi->area);
			if (oi->state == ISM_DR)
				ospf_network_lsa_update(oi);
		}
	}
}

static int lib_interface_ospf_validate_ldp_sync(struct interface *ifp,
						char *errmsg,
						size_t errmsg_len)
{
	if (if_is_loopback(ifp)) {
		snprintf(errmsg, errmsg_len,
			 "ldp-sync does not run on loopback interface");
		return NB_ERR_VALIDATION;
	}

	if (ifp->vrf->vrf_id != VRF_DEFAULT) {
		snprintf(errmsg, errmsg_len,
			 "ldp-sync only runs on DEFAULT VRF");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static struct ldp_sync_info *
lib_interface_ospf_ldp_sync_info_get(struct ospf_if_params *params)
{
	if (!params->ldp_sync_info)
		params->ldp_sync_info = ldp_sync_info_create();

	return params->ldp_sync_info;
}

static uint8_t lib_interface_ospf_bfd_default_multiplier(void)
{
	return yang_get_default_uint8(FRR_OSPFD_IFACE_XPATH
				      "/bfd/detection-multiplier");
}

static uint32_t lib_interface_ospf_bfd_default_min_rx(void)
{
	return yang_get_default_uint32(FRR_OSPFD_IFACE_XPATH
				       "/bfd/required-min-rx-interval");
}

static uint32_t lib_interface_ospf_bfd_default_min_tx(void)
{
	return yang_get_default_uint32(FRR_OSPFD_IFACE_XPATH
				       "/bfd/desired-min-tx-interval");
}

static bool lib_interface_ospf_bfd_default_quick(void)
{
	return yang_get_default_bool(FRR_OSPFD_IFACE_XPATH "/bfd/quick");
}

static void lib_interface_ospf_bfd_sync_config_from_dnode(struct interface *ifp,
							  const struct lyd_node *dnode)
{
	struct bfd_configuration *config;

	config = ospf_interface_bfd_config_get(ifp);
	config->detection_multiplier =
		yang_dnode_exists(dnode, "detection-multiplier")
			? yang_dnode_get_uint8(dnode, "detection-multiplier")
			: lib_interface_ospf_bfd_default_multiplier();
	config->min_rx = yang_dnode_exists(dnode, "required-min-rx-interval")
				 ? yang_dnode_get_uint32(
					   dnode, "required-min-rx-interval")
				 : lib_interface_ospf_bfd_default_min_rx();
	config->min_tx = yang_dnode_exists(dnode, "desired-min-tx-interval")
				 ? yang_dnode_get_uint32(
					   dnode, "desired-min-tx-interval")
				 : lib_interface_ospf_bfd_default_min_tx();
	config->quick = yang_dnode_exists(dnode, "quick")
				? yang_dnode_get_bool(dnode, "quick")
				: lib_interface_ospf_bfd_default_quick();

	if (yang_dnode_exists(dnode, "profile"))
		strlcpy(config->profile, yang_dnode_get_string(dnode, "profile"),
			sizeof(config->profile));
	else
		config->profile[0] = '\0';
}

static void routing_ospf_auto_cost_update(struct ospf *ospf, uint32_t refbw)
{
	struct vrf *vrf;
	struct interface *ifp;

	if (ospf->ref_bandwidth == refbw)
		return;

	ospf->ref_bandwidth = refbw;
	vrf = vrf_lookup_by_id(ospf->vrf_id);
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_if_recalculate_output_cost(ifp);
}

static void routing_ospf_stub_router_admin_set(struct ospf *ospf, bool enable)
{
	struct listnode *ln;
	struct ospf_area *area;

	if (enable) {
		for (ALL_LIST_ELEMENTS_RO(ospf->areas, ln, area)) {
			SET_FLAG(area->stub_router_state,
				 OSPF_AREA_ADMIN_STUB_ROUTED);
			if (!CHECK_FLAG(area->stub_router_state,
					OSPF_AREA_IS_STUB_ROUTED))
				ospf_router_lsa_update_area(area);
		}
		ospf->stub_router_admin_set = OSPF_STUB_ROUTER_ADMINISTRATIVE_SET;
		return;
	}

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, ln, area)) {
		UNSET_FLAG(area->stub_router_state, OSPF_AREA_ADMIN_STUB_ROUTED);
		if (CHECK_FLAG(area->stub_router_state,
			       OSPF_AREA_IS_STUB_ROUTED)
		    && !area->t_stub_router) {
			UNSET_FLAG(area->stub_router_state,
				   OSPF_AREA_IS_STUB_ROUTED);
			ospf_router_lsa_update_area(area);
		}
	}
	ospf->stub_router_admin_set = OSPF_STUB_ROUTER_ADMINISTRATIVE_UNSET;
}

static void routing_ospf_stub_router_startup_set(struct ospf *ospf,
						 uint32_t seconds)
{
	ospf->stub_router_startup_time = seconds;
}

static void routing_ospf_stub_router_startup_unset(struct ospf *ospf)
{
	struct listnode *ln;
	struct ospf_area *area;

	ospf->stub_router_startup_time = OSPF_STUB_ROUTER_UNCONFIGURED;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, ln, area)) {
		SET_FLAG(area->stub_router_state,
			 OSPF_AREA_WAS_START_STUB_ROUTED);
		event_cancel(&area->t_stub_router);

		if (!CHECK_FLAG(area->stub_router_state,
				OSPF_AREA_ADMIN_STUB_ROUTED)) {
			UNSET_FLAG(area->stub_router_state,
				   OSPF_AREA_IS_STUB_ROUTED);
			ospf_router_lsa_update_area(area);
		}
	}
}

static void routing_ospf_stub_router_shutdown_set(struct ospf *ospf,
						  uint32_t seconds)
{
	ospf->stub_router_shutdown_time = seconds;
}

static void routing_ospf_stub_router_shutdown_unset(struct ospf *ospf)
{
	ospf->stub_router_shutdown_time = OSPF_STUB_ROUTER_UNCONFIGURED;
}

static void routing_ospf_ldp_sync_enabled_set(struct ospf *ospf, bool enable)
{
	struct interface *ifp;
	struct vrf *vrf;

	if (enable) {
		zclient_register_opaque(ospf_zclient,
					LDP_IGP_SYNC_IF_STATE_UPDATE);
		zclient_register_opaque(ospf_zclient,
					LDP_IGP_SYNC_ANNOUNCE_UPDATE);

		if (CHECK_FLAG(ospf->ldp_sync_cmd.flags,
			       LDP_SYNC_FLAG_ENABLE))
			return;

		SET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE);
		vrf = vrf_lookup_by_id(ospf->vrf_id);
		FOR_ALL_INTERFACES (vrf, ifp)
			ospf_if_set_ldp_sync_enable(ospf, ifp);
		return;
	}

	if (!CHECK_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE))
		return;

	zclient_unregister_opaque(ospf_zclient, LDP_IGP_SYNC_IF_STATE_UPDATE);
	zclient_unregister_opaque(ospf_zclient, LDP_IGP_SYNC_ANNOUNCE_UPDATE);
	UNSET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_ENABLE);

	vrf = vrf_lookup_by_id(ospf->vrf_id);
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_ldp_sync_if_remove(ifp, false);
}

static void routing_ospf_ldp_sync_holddown_set(struct ospf *ospf,
					       uint16_t holddown,
					       bool configured)
{
	struct interface *ifp;
	struct vrf *vrf;

	if (configured) {
		SET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);
		ospf->ldp_sync_cmd.holddown = holddown;
	} else {
		UNSET_FLAG(ospf->ldp_sync_cmd.flags, LDP_SYNC_FLAG_HOLDDOWN);
		ospf->ldp_sync_cmd.holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
	}

	vrf = vrf_lookup_by_id(ospf->vrf_id);
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_if_set_ldp_sync_holddown(ospf, ifp);
}

static void routing_ospf_ti_lfa_set(struct ospf *ospf, bool enable,
				    bool node_protection)
{
	enum protection_type protection_type;

	if (enable)
		protection_type = node_protection ? OSPF_TI_LFA_NODE_PROTECTION
						  : OSPF_TI_LFA_LINK_PROTECTION;
	else
		protection_type = OSPF_TI_LFA_UNDEFINED_PROTECTION;

	if (ospf->ti_lfa_enabled == enable &&
	    ospf->ti_lfa_protection_type == protection_type)
		return;

	ospf->ti_lfa_enabled = enable;
	ospf->ti_lfa_protection_type = protection_type;
	ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);
}

static void routing_ospf_distance_update(struct ospf *ospf, uint8_t *field,
					 uint8_t distance)
{
	if (*field == distance)
		return;

	*field = distance;
	ospf_restart_spf(ospf);
}

static uint8_t *routing_ospf_distance_field(struct ospf *ospf, size_t offset)
{
	return (uint8_t *)((char *)ospf + offset);
}

static int routing_ospf_distance_modify(struct nb_cb_modify_args *args,
					size_t offset)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_distance_update(
			ospf, routing_ospf_distance_field(ospf, offset),
			yang_dnode_get_uint8(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

static int routing_ospf_distance_destroy(struct nb_cb_destroy_args *args,
					 size_t offset, uint8_t distance)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_distance_update(
			ospf, routing_ospf_distance_field(ospf, offset),
			distance);
		break;
	}

	return NB_OK;
}

static void routing_ospf_timers_spf_update(struct ospf *ospf,
					   unsigned int delay,
					   unsigned int hold,
					   unsigned int max)
{
	if (ospf->spf_delay != delay || ospf->spf_holdtime != hold ||
	    ospf->spf_max_holdtime != max)
		ospf->spf_hold_multiplier = 1;

	ospf->spf_delay = delay;
	ospf->spf_holdtime = hold;
	ospf->spf_max_holdtime = max;
}

static void routing_ospf_maxage_delay_update(struct ospf *ospf,
					     unsigned int delay)
{
	ospf->maxage_delay = delay;
	event_cancel(&ospf->t_maxage);
	OSPF_TIMER_ON(ospf->t_maxage, ospf_maxage_lsa_remover,
		      ospf->maxage_delay);
}

static void routing_ospf_abr_type_update(struct ospf *ospf, uint8_t abr_type)
{
	if (ospf->abr_type == abr_type)
		return;

	ospf->abr_type = abr_type;
	ospf_schedule_abr_task(ospf);
	ospf_spf_calculate_schedule(ospf, SPF_FLAG_ABR_STATUS_CHANGE);
}

static void routing_ospf_flag_update(struct ospf *ospf, uint8_t flag,
				     bool enable)
{
	if (enable && !CHECK_FLAG(ospf->config, flag))
		SET_FLAG(ospf->config, flag);
	else if (!enable && CHECK_FLAG(ospf->config, flag))
		UNSET_FLAG(ospf->config, flag);
}

static void routing_ospf_rfc1583_update(struct ospf *ospf, bool enable)
{
	bool current = CHECK_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE);

	if (current == enable)
		return;

	routing_ospf_flag_update(ospf, OSPF_RFC1583_COMPATIBLE, enable);
	ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);
}

static void routing_ospf_opaque_capability_update(struct ospf *ospf,
						  bool enable)
{
	bool current = CHECK_FLAG(ospf->config, OSPF_OPAQUE_CAPABLE);

	if (current == enable)
		return;

	routing_ospf_flag_update(ospf, OSPF_OPAQUE_CAPABLE, enable);
	ospf_renegotiate_optional_capabilities(ospf);
}

static void routing_ospf_reinstall_table(struct ospf *ospf,
					 struct route_table *rt)
{
	struct route_node *rn;

	if (!rt)
		return;

	for (rn = route_top(rt); rn; rn = route_next(rn)) {
		struct ospf_route *or = rn->info;

		if (!or)
			continue;

		if (or->type == OSPF_DESTINATION_NETWORK)
			ospf_zebra_add(ospf, (struct prefix_ipv4 *)&rn->p, or);
		else if (or->type == OSPF_DESTINATION_DISCARD)
			ospf_zebra_add_discard(ospf,
					       (struct prefix_ipv4 *)&rn->p);
	}
}

static void routing_ospf_send_extra_data_update(struct ospf *ospf,
						bool enable)
{
	bool current = CHECK_FLAG(ospf->config, OSPF_SEND_EXTRA_DATA_TO_ZEBRA);

	if (current == enable)
		return;

	routing_ospf_flag_update(ospf, OSPF_SEND_EXTRA_DATA_TO_ZEBRA, enable);
	routing_ospf_reinstall_table(ospf, ospf->new_table);
	routing_ospf_reinstall_table(ospf, ospf->new_external_route);
}

static void routing_ospf_per_interface_socket_update(struct ospf *ospf,
						     bool enable)
{
	struct listnode *node;
	struct ospf_interface *oi;

	if (ospf->intf_socket_enabled == enable)
		return;

	ospf->intf_socket_enabled = enable;

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		if (enable)
			ospf_ifp_sock_init(oi->ifp);
		else
			ospf_ifp_sock_close(oi->ifp);
	}
}

static int routing_ospf_modify_apply_finish(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

static int routing_ospf_create_apply_finish(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

static int routing_ospf_destroy_apply_finish(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

static uint32_t routing_ospf_get_uint32_default(const struct lyd_node *dnode,
						const char *path,
						const char *default_path)
{
	if (yang_dnode_exists(dnode, path))
		return yang_dnode_get_uint32(dnode, "%s", path);

	return yang_get_default_uint32("%s", default_path);
}

static uint16_t routing_ospf_get_uint16_default(const struct lyd_node *dnode,
						const char *path,
						const char *default_path)
{
	if (yang_dnode_exists(dnode, path))
		return yang_dnode_get_uint16(dnode, "%s", path);

	return yang_get_default_uint16("%s", default_path);
}

static uint8_t routing_ospf_get_uint8_default(const struct lyd_node *dnode,
					      const char *path,
					      const char *default_path)
{
	if (yang_dnode_exists(dnode, path))
		return yang_dnode_get_uint8(dnode, "%s", path);

	return yang_get_default_uint8("%s", default_path);
}

static bool routing_ospf_get_bool_default(const struct lyd_node *dnode,
					  const char *path,
					  const char *default_path)
{
	if (yang_dnode_exists(dnode, path))
		return yang_dnode_get_bool(dnode, "%s", path);

	return yang_get_default_bool("%s", default_path);
}

static int routing_ospf_gr_validate_not_preparing(struct ospf *ospf,
						  char *errmsg,
						  size_t errmsg_len)
{
	if (!ospf->gr_info.prepare_in_progress)
		return NB_OK;

	snprintf(errmsg, errmsg_len,
		 "graceful restart preparation is in progress");
	return NB_ERR_VALIDATION;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/dscp/all
 */
static int lib_interface_ospf_dscp_all_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		if (lyd_is_default(args->dnode))
			UNSET_IF_PARAM(params, dscp_ospf_all);
		else
			SET_IF_PARAM(params, dscp_ospf_all);
		params->dscp_ospf_all = yang_dnode_get_uint8(args->dnode, NULL);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_dscp_all_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		UNSET_IF_PARAM(params, dscp_ospf_all);
		params->dscp_ospf_all = yang_get_default_uint8(
			FRR_OSPFD_IFACE_XPATH "/dscp/all");
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/dscp/low-control
 */
static int lib_interface_ospf_dscp_low_control_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		SET_IF_PARAM(params, dscp_low_control);
		params->dscp_low_control =
			yang_dnode_get_uint8(args->dnode, NULL);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_dscp_low_control_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		UNSET_IF_PARAM(params, dscp_low_control);
		params->dscp_low_control = IPTOS_PREC_INTERNETCONTROL >> 2;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/dead-timer-reset-any-control
 */
static int lib_interface_ospf_dead_timer_reset_any_control_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;
	bool reset_any;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		reset_any = yang_dnode_get_bool(args->dnode, NULL);
		if (reset_any)
			SET_IF_PARAM(params, dead_timer_any);
		else
			UNSET_IF_PARAM(params, dead_timer_any);
		params->dead_timer_any = reset_any;
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_dead_timer_reset_any_control_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		UNSET_IF_PARAM(params, dead_timer_any);
		params->dead_timer_any = yang_get_default_bool(
			FRR_OSPFD_IFACE_XPATH
			"/dead-timer-reset-any-control");
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/bfd
 */
static int lib_interface_ospf_bfd_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		if (!lib_interface_ospf_ensure_if_info(ifp))
			return NB_OK;

		ospf_interface_bfd_config_get(ifp);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_bfd_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		if (!lib_interface_ospf_ensure_if_info(ifp))
			return NB_OK;

		params = IF_DEF_PARAMS(ifp);
		ospf_interface_disable_bfd(ifp, params);
		break;
	}

	return NB_OK;
}

static void lib_interface_ospf_bfd_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct interface *ifp;

	ifp = lib_interface_ospf_get_ifp(args->dnode);
	if (!lib_interface_ospf_ensure_if_info(ifp))
		return;

	lib_interface_ospf_bfd_sync_config_from_dnode(ifp, args->dnode);
	ospf_interface_enable_bfd(ifp, yang_dnode_get_bool(args->dnode, "quick"));
	ospf_interface_bfd_apply(ifp);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/bfd/profile
 */
static int lib_interface_ospf_bfd_profile_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* APPLY is intentionally a no-op; the parent /bfd applies. */
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_bfd_profile_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* Deletion restores the default; the parent /bfd applies. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/bfd/detection-multiplier
 */
static int lib_interface_ospf_bfd_detection_multiplier_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* APPLY is intentionally a no-op; the parent /bfd applies. */
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/bfd/required-min-rx-interval
 */
static int lib_interface_ospf_bfd_required_min_rx_interval_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* APPLY is intentionally a no-op; the parent /bfd applies. */
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/bfd/desired-min-tx-interval
 */
static int lib_interface_ospf_bfd_desired_min_tx_interval_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* APPLY is intentionally a no-op; the parent /bfd applies. */
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/bfd/quick
 */
static int lib_interface_ospf_bfd_quick_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* APPLY is intentionally a no-op; the parent /bfd applies. */
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/ldp-sync/mode
 */
static int lib_interface_ospf_ldp_sync_mode_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;
	int mode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		return lib_interface_ospf_validate_ldp_sync(
			ifp, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		mode = yang_dnode_get_enum(args->dnode, NULL);
		ldp_sync_info = lib_interface_ospf_ldp_sync_info_get(params);
		if (mode == 0) {
			UNSET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG);
			ldp_sync_info->enabled = LDP_IGP_SYNC_DEFAULT;
			ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
			event_cancel(&ldp_sync_info->t_holddown);
			ospf_if_recalculate_output_cost(ifp);
			return NB_OK;
		}

		SET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG);
		ldp_sync_info->enabled = mode == 1 ? LDP_IGP_SYNC_ENABLED
						   : LDP_IGP_SYNC_DEFAULT;
		if (ldp_sync_info->enabled == LDP_IGP_SYNC_ENABLED &&
		    (params->type == OSPF_IFTYPE_POINTOPOINT ||
		     if_is_pointopoint(ifp))) {
			ldp_sync_info->state = LDP_IGP_SYNC_STATE_REQUIRED_NOT_UP;
			ospf_ldp_sync_state_req_msg(ifp);
		} else {
			ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
			event_cancel(&ldp_sync_info->t_holddown);
			ospf_if_recalculate_output_cost(ifp);
		}
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_ldp_sync_mode_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		return lib_interface_ospf_validate_ldp_sync(
			ifp, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params || !params->ldp_sync_info)
			return NB_OK;

		ldp_sync_info = params->ldp_sync_info;
		UNSET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_IF_CONFIG);
		ldp_sync_info->enabled = LDP_IGP_SYNC_DEFAULT;
		ldp_sync_info->state = LDP_IGP_SYNC_STATE_NOT_REQUIRED;
		event_cancel(&ldp_sync_info->t_holddown);
		ospf_if_recalculate_output_cost(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/ldp-sync/holddown
 */
static int lib_interface_ospf_ldp_sync_holddown_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		return lib_interface_ospf_validate_ldp_sync(
			ifp, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		ldp_sync_info = lib_interface_ospf_ldp_sync_info_get(params);
		SET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN);
		ldp_sync_info->holddown =
			yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_ldp_sync_holddown_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct ospf *ospf;
	struct ospf_if_params *params;
	struct ldp_sync_info *ldp_sync_info;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		return lib_interface_ospf_validate_ldp_sync(
			ifp, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params || !params->ldp_sync_info)
			return NB_OK;

		ldp_sync_info = params->ldp_sync_info;
		if (!CHECK_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN))
			return NB_OK;

		UNSET_FLAG(ldp_sync_info->flags, LDP_SYNC_FLAG_HOLDDOWN);
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf && CHECK_FLAG(ospf->ldp_sync_cmd.flags,
				       LDP_SYNC_FLAG_HOLDDOWN))
			ldp_sync_info->holddown = ospf->ldp_sync_cmd.holddown;
		else
			ldp_sync_info->holddown = LDP_IGP_SYNC_HOLDDOWN_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-type
 */
static int lib_interface_ospf_interface_type_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	const char *val;
	int type;

	val = yang_dnode_get_string(args->dnode, NULL);
	type = lib_interface_ospf_iftype_from_yang(val);
	if (type < 0) {
		if (args->event == NB_EV_VALIDATE)
			snprintf(args->errmsg, args->errmsg_len,
				 "unsupported interface-type enum '%s'", val);
		return args->event == NB_EV_VALIDATE ? NB_ERR_VALIDATION
						     : NB_OK;
	}

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		if (if_is_loopback(ifp)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "cannot set interface-type on loopback interface %s",
				 ifp->name);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		lib_interface_ospf_apply_interface_type(ifp, type);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_type_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params || !OSPF_IF_PARAM_CONFIGURED(params, type))
			return NB_OK;

		UNSET_IF_PARAM(params, type);
		params->type_cfg = false;
		lib_interface_ospf_flap_oifs(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/point-to-point-dmvpn
 */
static int lib_interface_ospf_point_to_point_dmvpn_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		lib_interface_ospf_apply_network_option(
			ifp, LIB_INTERFACE_OSPF_PTP_DMVPN,
			yang_dnode_get_bool(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_point_to_point_dmvpn_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		lib_interface_ospf_apply_network_option(
			ifp, LIB_INTERFACE_OSPF_PTP_DMVPN, false);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/point-to-multipoint-delay-reflood
 */
static int lib_interface_ospf_point_to_multipoint_delay_reflood_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		lib_interface_ospf_apply_network_option(
			ifp, LIB_INTERFACE_OSPF_P2MP_DELAY_REFLOOD,
			yang_dnode_get_bool(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_point_to_multipoint_delay_reflood_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		lib_interface_ospf_apply_network_option(
			ifp, LIB_INTERFACE_OSPF_P2MP_DELAY_REFLOOD, false);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/point-to-multipoint-non-broadcast
 */
static int lib_interface_ospf_point_to_multipoint_non_broadcast_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		lib_interface_ospf_apply_network_option(
			ifp, LIB_INTERFACE_OSPF_P2MP_NON_BROADCAST,
			yang_dnode_get_bool(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_point_to_multipoint_non_broadcast_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		lib_interface_ospf_apply_network_option(
			ifp, LIB_INTERFACE_OSPF_P2MP_NON_BROADCAST, false);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/authentication-mode
 */
static int lib_interface_ospf_authentication_mode_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		lib_interface_ospf_auth_mode_set(
			params,
			lib_interface_ospf_auth_mode_from_dnode(args->dnode));
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_authentication_mode_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		lib_interface_ospf_auth_mode_unset(params);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/authentication-key
 */
static int lib_interface_ospf_authentication_key_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		lib_interface_ospf_auth_simple_set(
			params, yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_authentication_key_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		lib_interface_ospf_auth_simple_unset(params);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/message-digest-key
 */
static int lib_interface_ospf_message_digest_key_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* The mandatory md5-key leaf applies the key material. */
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_message_digest_key_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	uint8_t key_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		key_id = yang_dnode_get_uint8(args->dnode, "key-id");
		return lib_interface_ospf_md5_key_delete(params, key_id);
	}

	return NB_OK;
}

static const void *lib_interface_ospf_message_digest_key_get_next(struct nb_cb_get_next_args *args)
{
	const struct interface *ifp = args->parent_list_entry;
	const struct ospf_if_params *params;
	const struct listnode *node = args->list_entry;

	if (!ifp || !IF_OSPF_IF_INFO(ifp))
		return NULL;

	params = IF_DEF_PARAMS(ifp);
	if (!params->auth_crypt)
		return NULL;

	return node ? listnextnode(node) : listhead(params->auth_crypt);
}

static int lib_interface_ospf_message_digest_key_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct listnode *node = args->list_entry;
	const struct crypt_key *ck = listgetdata(node);

	args->keys->num = 1;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%u",
		 ck->key_id);

	return NB_OK;
}

static const void *lib_interface_ospf_message_digest_key_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const struct interface *ifp = args->parent_list_entry;
	struct ospf_if_params *params;
	struct listnode *node;
	struct crypt_key *ck;
	uint8_t key_id;

	if (!ifp || !IF_OSPF_IF_INFO(ifp))
		return NULL;

	params = IF_DEF_PARAMS(ifp);
	if (!params->auth_crypt)
		return NULL;

	key_id = yang_str2uint8(args->keys->key[0]);
	for (ALL_LIST_ELEMENTS_RO(params->auth_crypt, node, ck))
		if (ck->key_id == key_id)
			return node;

	return NULL;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/message-digest-key/md5-key
 */
static int lib_interface_ospf_message_digest_key_md5_key_modify(struct nb_cb_modify_args *args)
{
	const struct lyd_node *key_dnode;
	struct ospf_if_params *params;
	uint8_t key_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		key_dnode = yang_dnode_get_parent(args->dnode,
						  "message-digest-key");
		if (!key_dnode)
			return NB_ERR_INCONSISTENCY;

		params = lib_interface_ospf_get_params(key_dnode);
		if (!params)
			return NB_OK;

		key_id = yang_dnode_get_uint8(key_dnode, "key-id");
		return lib_interface_ospf_md5_key_set(
			params, key_id, yang_dnode_get_string(args->dnode, NULL));
	}

	return NB_OK;
}


/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/key-chain
 */
static int lib_interface_ospf_key_chain_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		lib_interface_ospf_key_chain_set(
			params, yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_key_chain_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		lib_interface_ospf_key_chain_unset(params);
		lib_interface_ospf_auth_mode_unset(params);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/cost
 */
static int lib_interface_ospf_cost_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		SET_IF_PARAM(params, output_cost_cmd);
		params->output_cost_cmd = yang_dnode_get_uint16(args->dnode,
								NULL);
		ospf_if_recalculate_output_cost(ifp);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_cost_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		if (!OSPF_IF_PARAM_CONFIGURED(params, output_cost_cmd))
			return NB_OK;

		UNSET_IF_PARAM(params, output_cost_cmd);
		ospf_if_recalculate_output_cost(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/dead-interval/interval
 */
static void lib_interface_ospf_uint16_default_read(const struct lyd_node *dnode,
						   const char *path,
						   const char *default_path,
						   uint16_t *value,
						   bool *configured)
{
	struct lyd_node *leaf;

	leaf = yang_dnode_get(dnode, path);
	*configured = leaf && !lyd_is_default(leaf);
	*value = leaf ? yang_dnode_get_uint16(leaf, NULL)
		      : yang_get_default_uint16("%s", default_path);
}

static void lib_interface_ospf_bool_default_read(const struct lyd_node *dnode,
						 const char *path,
						 const char *default_path,
						 bool *value,
						 bool *configured)
{
	struct lyd_node *leaf;

	leaf = yang_dnode_get(dnode, path);
	*configured = leaf && !lyd_is_default(leaf);
	*value = leaf ? yang_dnode_get_bool(leaf, NULL)
		      : yang_get_default_bool("%s", default_path);
}

static void lib_interface_ospf_fast_hello_set(struct ospf_if_params *params,
					      uint8_t multiplier,
					      bool configured)
{
	if (configured)
		SET_IF_PARAM(params, fast_hello);
	else
		UNSET_IF_PARAM(params, fast_hello);

	params->fast_hello = multiplier;
}

static void lib_interface_ospf_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	struct in_addr addr = { .s_addr = 0L };
	const struct lyd_node *minimal;
	uint16_t retransmit_interval;
	uint16_t retransmit_window;
	uint16_t transmit_delay;
	uint16_t hello_interval;
	uint16_t dead_interval;
	bool retransmit_interval_configured;
	bool retransmit_window_configured;
	bool transmit_delay_configured;
	bool hello_configured;
	bool dead_configured;
	bool wait_configured;
	bool fast_configured;
	bool wait_explicit;
	uint8_t fast_hello;
	bool nbr_update;
	bool hello_update;
	bool old_gr_hello_delay_configured;
	bool gr_hello_delay_configured;
	uint16_t gr_hello_delay;
	bool mtu_ignore_configured;
	bool mtu_ignore;

	ifp = lib_interface_ospf_get_ifp(args->dnode);
	params = lib_interface_ospf_get_params(args->dnode);
	if (!params)
		return;

	lib_interface_ospf_uint16_default_read(
		args->dnode, "hello-interval",
		FRR_OSPFD_IFACE_XPATH "/hello-interval", &hello_interval,
		&hello_configured);
	minimal = yang_dnode_get(args->dnode, "dead-interval/minimal");
	if (minimal) {
		fast_configured = true;
		fast_hello = yang_dnode_get_uint8(minimal, "hello-multiplier");
		dead_interval = OSPF_ROUTER_DEAD_INTERVAL_MINIMAL;
		wait_configured = true;
		wait_explicit = true;
	} else {
		lib_interface_ospf_uint16_default_read(
			args->dnode, "dead-interval/interval",
			FRR_OSPFD_IFACE_XPATH "/dead-interval/interval",
			&dead_interval, &dead_configured);
		fast_configured = false;
		fast_hello = OSPF_FAST_HELLO_DEFAULT;
		if (dead_configured) {
			wait_configured = true;
			wait_explicit = true;
		} else if (hello_configured) {
			dead_interval = 4 * hello_interval;
			wait_configured = true;
			wait_explicit = false;
		} else {
			wait_configured = false;
			wait_explicit = false;
		}
	}

	nbr_update =
		OSPF_IF_PARAM_CONFIGURED(params, v_wait) != wait_configured ||
		params->v_wait != dead_interval ||
		params->is_v_wait_set != wait_explicit ||
		OSPF_IF_PARAM_CONFIGURED(params, fast_hello) !=
			fast_configured ||
		params->fast_hello != fast_hello;
	hello_update =
		OSPF_IF_PARAM_CONFIGURED(params, v_hello) != hello_configured ||
		params->v_hello != hello_interval ||
		OSPF_IF_PARAM_CONFIGURED(params, fast_hello) !=
			fast_configured ||
		params->fast_hello != fast_hello;

	lib_interface_ospf_set_hello_interval(params, hello_interval,
					      hello_configured);
	lib_interface_ospf_set_dead_interval(params, dead_interval,
					     wait_configured);
	params->is_v_wait_set = wait_explicit;
	lib_interface_ospf_fast_hello_set(params, fast_hello,
					  fast_configured);

	lib_interface_ospf_uint16_default_read(
		args->dnode, "retransmit-interval",
		FRR_OSPFD_IFACE_XPATH "/retransmit-interval",
		&retransmit_interval, &retransmit_interval_configured);
	lib_interface_ospf_set_retransmit_interval(
		params, retransmit_interval, retransmit_interval_configured);

	lib_interface_ospf_uint16_default_read(
		args->dnode, "retransmit-window",
		FRR_OSPFD_IFACE_XPATH "/retransmit-window",
		&retransmit_window, &retransmit_window_configured);
	lib_interface_ospf_set_retransmit_window(
		params, retransmit_window, retransmit_window_configured);

	lib_interface_ospf_uint16_default_read(
		args->dnode, "transmit-delay",
		FRR_OSPFD_IFACE_XPATH "/transmit-delay", &transmit_delay,
		&transmit_delay_configured);
	lib_interface_ospf_set_transmit_delay(params, transmit_delay,
					      transmit_delay_configured);

	lib_interface_ospf_bool_default_read(
		args->dnode, "mtu-ignore", FRR_OSPFD_IFACE_XPATH "/mtu-ignore",
		&mtu_ignore, &mtu_ignore_configured);
	if (mtu_ignore_configured)
		SET_IF_PARAM(params, mtu_ignore);
	else
		UNSET_IF_PARAM(params, mtu_ignore);
	params->mtu_ignore = mtu_ignore ? 1 : 0;

	old_gr_hello_delay_configured =
		OSPF_IF_PARAM_CONFIGURED(params, v_gr_hello_delay);
	lib_interface_ospf_uint16_default_read(
		args->dnode, "graceful-restart/hello-delay",
		FRR_OSPFD_IFACE_XPATH "/graceful-restart/hello-delay",
		&gr_hello_delay, &gr_hello_delay_configured);
	if (gr_hello_delay_configured)
		SET_IF_PARAM(params, v_gr_hello_delay);
	else
		UNSET_IF_PARAM(params, v_gr_hello_delay);
	params->v_gr_hello_delay = gr_hello_delay;
	if (old_gr_hello_delay_configured && !gr_hello_delay_configured)
		lib_interface_ospf_gr_hello_delay_reset(ifp);

	if (nbr_update)
		lib_interface_ospf_nbr_timer_update(ifp);
	if (hello_update)
		ospf_reset_hello_timer(ifp, addr, false);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/dead-interval/interval
 */
static int lib_interface_ospf_dead_interval_interval_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int lib_interface_ospf_dead_interval_interval_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/dead-interval/minimal
 */
static int lib_interface_ospf_dead_interval_minimal_create(struct nb_cb_create_args *args)
{
	return routing_ospf_create_apply_finish(args);
}

static int lib_interface_ospf_dead_interval_minimal_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/dead-interval/minimal/hello-multiplier
 */
static int lib_interface_ospf_dead_interval_minimal_hello_multiplier_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/hello-interval
 */
static int lib_interface_ospf_hello_interval_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int lib_interface_ospf_hello_interval_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/retransmit-interval
 */
static int lib_interface_ospf_retransmit_interval_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int lib_interface_ospf_retransmit_interval_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/retransmit-window
 */
static int lib_interface_ospf_retransmit_window_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int lib_interface_ospf_retransmit_window_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/transmit-delay
 */
static int lib_interface_ospf_transmit_delay_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int lib_interface_ospf_transmit_delay_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/mtu-ignore
 */
static int lib_interface_ospf_mtu_ignore_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int lib_interface_ospf_mtu_ignore_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/priority
 */
static int lib_interface_ospf_priority_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		if (lyd_is_default(args->dnode))
			UNSET_IF_PARAM(params, priority);
		else
			SET_IF_PARAM(params, priority);

		params->priority = yang_dnode_get_uint8(args->dnode, NULL);
		lib_interface_ospf_priority_update(ifp);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_priority_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		UNSET_IF_PARAM(params, priority);
		params->priority = yang_get_default_uint8(
			FRR_OSPFD_IFACE_XPATH "/priority");
		lib_interface_ospf_priority_update(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/passive
 */
static int lib_interface_ospf_passive_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	struct in_addr addr = { .s_addr = INADDR_ANY };
	uint8_t newval;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		newval = yang_dnode_get_bool(args->dnode, NULL)
				 ? OSPF_IF_PASSIVE
				 : OSPF_IF_ACTIVE;
		ospf_passive_interface_update(ifp, params, addr, newval);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_passive_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	struct in_addr addr = { .s_addr = INADDR_ANY };
	bool passive;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		passive = yang_get_default_bool(FRR_OSPFD_IFACE_XPATH "/passive");
		ospf_passive_interface_update(ifp, params, addr,
					      passive ? OSPF_IF_PASSIVE
						      : OSPF_IF_ACTIVE);
		UNSET_IF_PARAM(params, passive_interface);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/prefix-suppression
 */
static int lib_interface_ospf_prefix_suppression_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	bool old_value;
	bool new_value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		old_value = params->prefix_suppression;
		new_value = yang_dnode_get_bool(args->dnode, NULL);
		if (new_value != OSPF_PREFIX_SUPPRESSION_DEFAULT)
			SET_IF_PARAM(params, prefix_suppression);
		else
			UNSET_IF_PARAM(params, prefix_suppression);

		params->prefix_suppression = new_value;
		if (old_value != new_value)
			lib_interface_ospf_prefix_suppression_lsa_update(ifp);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_prefix_suppression_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	bool old_value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		old_value = params->prefix_suppression;
		UNSET_IF_PARAM(params, prefix_suppression);
		params->prefix_suppression = yang_get_default_bool(
			FRR_OSPFD_IFACE_XPATH "/prefix-suppression");
		if (old_value != params->prefix_suppression)
			lib_interface_ospf_prefix_suppression_lsa_update(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/capability-opaque
 */
static int lib_interface_ospf_capability_opaque_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	bool new_value;
	bool old_value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		old_value = params->opaque_capable;
		new_value = yang_dnode_get_bool(args->dnode, NULL);
		if (new_value != OSPF_OPAQUE_CAPABLE_DEFAULT)
			SET_IF_PARAM(params, opaque_capable);
		else
			UNSET_IF_PARAM(params, opaque_capable);
		params->opaque_capable = new_value;

		if (old_value != new_value)
			lib_interface_ospf_flap_oifs(ifp);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_capability_opaque_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	bool old_value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		old_value = params->opaque_capable;
		UNSET_IF_PARAM(params, opaque_capable);
		params->opaque_capable = yang_get_default_bool(
			FRR_OSPFD_IFACE_XPATH "/capability-opaque");
		if (old_value != params->opaque_capable)
			lib_interface_ospf_flap_oifs(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/neighbor-filter
 */
static int lib_interface_ospf_neighbor_filter_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	struct prefix_list *nbr_filter;
	struct route_node *rn;
	const char *name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		name = yang_dnode_get_string(args->dnode, NULL);
		XFREE(MTYPE_OSPF_IF_PARAMS, params->nbr_filter_name);
		SET_IF_PARAM(params, nbr_filter_name);
		params->nbr_filter_name = XSTRDUP(MTYPE_OSPF_IF_PARAMS, name);
		nbr_filter = prefix_list_lookup(AFI_IP, params->nbr_filter_name);

		if (!IF_OIFS(ifp))
			return NB_OK;

		for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
			struct ospf_interface *oi = rn->info;

			if (oi && oi->nbr_filter != nbr_filter) {
				oi->nbr_filter = nbr_filter;
				if (oi->nbr_filter)
					ospf_intf_neighbor_filter_apply(oi);
			}
		}
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_neighbor_filter_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct ospf_if_params *params;
	struct route_node *rn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params)
			return NB_OK;

		UNSET_IF_PARAM(params, nbr_filter_name);
		XFREE(MTYPE_OSPF_IF_PARAMS, params->nbr_filter_name);

		if (!IF_OIFS(ifp))
			return NB_OK;

		for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
			struct ospf_interface *oi = rn->info;

			if (oi)
				oi->nbr_filter = NULL;
		}
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/graceful-restart/hello-delay
 */
static int lib_interface_ospf_graceful_restart_hello_delay_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int lib_interface_ospf_graceful_restart_hello_delay_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/attachment
 */
static int lib_interface_ospf_attachment_create(struct nb_cb_create_args *args)
{
	struct in_addr area_id;
	struct interface *ifp;
	struct ospf *ospf;
	struct ospf_if_params *params;
	int instance;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		if (memcmp(ifp->name, "VLINK", 5) == 0) {
			snprintf(args->errmsg, args->errmsg_len,
				 "cannot enable OSPF on virtual link interface %s",
				 ifp->name);
			return NB_ERR_VALIDATION;
		}
		ospf = lib_interface_ospf_attachment_get_ospf(args->dnode);
		if (routing_ospf_has_networks(ospf)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "please remove all network commands first");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		if (!lib_interface_ospf_ensure_if_info(ifp))
			return NB_OK;
		instance = lib_interface_ospf_attachment_instance(args->dnode);
		if (instance < 0)
			return NB_ERR;
		if (lib_interface_ospf_attachment_area_id(args->dnode, &area_id) < 0)
			return NB_ERR;

		params = IF_DEF_PARAMS(ifp);
		SET_IF_PARAM(params, if_area);
		params->if_ospf_instance = instance;
		params->if_area = area_id;
		params->if_area_id_fmt = OSPF_AREA_ID_FMT_DOTTEDQUAD;

		ospf = lib_interface_ospf_attachment_get_ospf(args->dnode);
		if (ospf)
			ospf_interface_area_set(ospf, ifp);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_attachment_destroy(struct nb_cb_destroy_args *args)
{
	struct in_addr area_id;
	struct interface *ifp;
	struct ospf *ospf;
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ifp = lib_interface_ospf_get_ifp(args->dnode);
		params = lib_interface_ospf_get_params(args->dnode);
		if (!params || !OSPF_IF_PARAM_CONFIGURED(params, if_area))
			return NB_OK;
		if (lib_interface_ospf_attachment_area_id(args->dnode,
							  &area_id) < 0)
			return NB_ERR;

		UNSET_IF_PARAM(params, if_area);
		params->if_ospf_instance = 0;
		ospf = lib_interface_ospf_attachment_get_ospf(args->dnode);
		if (ospf) {
			ospf_interface_area_unset(ospf, ifp);
			ospf_area_check_free(ospf, area_id);
		}
		break;
	}

	return NB_OK;
}

static const void *lib_interface_ospf_attachment_get_next(struct nb_cb_get_next_args *args)
{
	const struct interface *ifp = args->parent_list_entry;
	const struct ospf_if_params *params;

	if (args->list_entry || !ifp || !IF_OSPF_IF_INFO(ifp))
		return NULL;

	params = IF_DEF_PARAMS(ifp);
	if (!OSPF_IF_PARAM_CONFIGURED(params, if_area))
		return NULL;

	return params;
}

static int lib_interface_ospf_attachment_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct ospf_if_params *params = args->list_entry;

	args->keys->num = 2;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%u",
		 params->if_ospf_instance);
	inet_ntop(AF_INET, &params->if_area, args->keys->key[1],
		  sizeof(args->keys->key[1]));

	return NB_OK;
}

static const void *lib_interface_ospf_attachment_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const struct interface *ifp = args->parent_list_entry;
	const struct ospf_if_params *params;
	struct in_addr area_id;
	uint16_t instance;
	int format;

	if (!ifp || !IF_OSPF_IF_INFO(ifp))
		return NULL;

	params = IF_DEF_PARAMS(ifp);
	if (!OSPF_IF_PARAM_CONFIGURED(params, if_area))
		return NULL;

	instance = yang_str2uint16(args->keys->key[0]);
	if (str2area_id(args->keys->key[1], &area_id, &format) < 0)
		return NULL;
	if (params->if_ospf_instance != instance ||
	    !IPV4_ADDR_SAME(&params->if_area, &area_id))
		return NULL;

	return params;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address
 */
static int lib_interface_ospf_interface_address_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* Child leaves create the sparse address params entry. */
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	bool old_prefix_suppression;
	bool old_opaque_capable;
	struct in_addr area_id;
	struct in_addr addr;
	bool had_area;
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		had_area = OSPF_IF_PARAM_CONFIGURED(params, if_area);
		if (had_area)
			area_id = params->if_area;
		old_prefix_suppression =
			OSPF_IF_PARAM_CONFIGURED(params, prefix_suppression)
				? params->prefix_suppression
				: IF_DEF_PARAMS(ifp)->prefix_suppression;
		old_opaque_capable =
			OSPF_IF_PARAM_CONFIGURED(params, opaque_capable)
				? params->opaque_capable
				: IF_DEF_PARAMS(ifp)->opaque_capable;

		lib_interface_ospf_clear_address_params(params);
		lib_interface_ospf_free_address_params(ifp, addr);

		if (had_area) {
			ospf = ifp->vrf ? ifp->vrf->info : NULL;
			if (ospf) {
				ospf_interface_area_unset(ospf, ifp);
				ospf_area_check_free(ospf, area_id);
			}
		}
		ospf_if_recalculate_output_cost(ifp);
		lib_interface_ospf_nbr_timer_update_addr(ifp, addr);
		ospf_reset_hello_timer(ifp, addr, true);
		lib_interface_ospf_priority_update(ifp);
		lib_interface_ospf_multicast_update(ifp);
		if (old_prefix_suppression != IF_DEF_PARAMS(ifp)->prefix_suppression)
			lib_interface_ospf_prefix_suppression_lsa_update_addr(
				ifp, addr);
		if (old_opaque_capable != IF_DEF_PARAMS(ifp)->opaque_capable)
			lib_interface_ospf_flap_addr(ifp, addr);
		lib_interface_ospf_neighbor_filter_update_addr(ifp, addr);
		lib_interface_ospf_gr_hello_delay_reset_addr(ifp, addr);
		break;
	}

	return NB_OK;
}

static const void *lib_interface_ospf_interface_address_get_next(struct nb_cb_get_next_args *args)
{
	const struct interface *ifp = args->parent_list_entry;
	struct route_node *rn;

	if (!ifp || !IF_OSPF_IF_INFO(ifp))
		return NULL;

	if (!args->list_entry)
		rn = route_top(IF_OIFS_PARAMS(ifp));
	else
		rn = route_next((struct route_node *)args->list_entry);
	while (rn && !rn->info)
		rn = route_next(rn);

	return rn;
}

static int lib_interface_ospf_interface_address_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct route_node *rn = args->list_entry;

	args->keys->num = 1;
	inet_ntop(AF_INET, &rn->p.u.prefix4, args->keys->key[0],
		  sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_interface_ospf_interface_address_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct interface *ifp = (struct interface *)args->parent_list_entry;
	struct prefix_ipv4 p;
	struct in_addr addr;
	struct route_node *rn;

	if (!ifp || !IF_OSPF_IF_INFO(ifp))
		return NULL;
	if (!inet_aton(args->keys->key[0], &addr))
		return NULL;

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.prefix = addr;
	rn = route_node_lookup(IF_OIFS_PARAMS(ifp), (struct prefix *)&p);
	if (!rn)
		return NULL;
	if (!rn->info) {
		route_unlock_node(rn);
		return NULL;
	}

	return rn;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/area
 */
static int lib_interface_ospf_interface_address_area_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr area_id;
	struct in_addr addr;
	struct ospf *ospf;
	const char *area;
	int format;

	switch (args->event) {
	case NB_EV_VALIDATE:
		area = yang_dnode_get_string(args->dnode, NULL);
		if (str2area_id(area, &area_id, &format) < 0) {
			snprintf(args->errmsg, args->errmsg_len,
				 "invalid OSPF area '%s'", area);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		area = yang_dnode_get_string(args->dnode, NULL);
		if (str2area_id(area, &area_id, &format) < 0)
			return NB_ERR_INCONSISTENCY;

		SET_IF_PARAM(params, if_area);
		params->if_area = area_id;
		params->if_area_id_fmt = format;

		ospf = ifp->vrf ? ifp->vrf->info : NULL;
		if (ospf)
			ospf_interface_area_set(ospf, ifp);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_area_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr area_id;
	struct in_addr addr;
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp,
							       &addr);
		if (!params || !OSPF_IF_PARAM_CONFIGURED(params, if_area))
			return NB_OK;

		area_id = params->if_area;
		UNSET_IF_PARAM(params, if_area);
		lib_interface_ospf_free_address_params(ifp, addr);

		ospf = ifp->vrf ? ifp->vrf->info : NULL;
		if (ospf) {
			ospf_interface_area_unset(ospf, ifp);
			ospf_area_check_free(ospf, area_id);
		}
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/authentication-mode
 */
static int lib_interface_ospf_interface_address_authentication_mode_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, NULL, NULL);
		if (!params)
			return NB_OK;

		lib_interface_ospf_auth_mode_set(
			params,
			lib_interface_ospf_auth_mode_from_dnode(args->dnode));
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_authentication_mode_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp, &addr);
		if (!params)
			return NB_OK;

		lib_interface_ospf_auth_mode_unset(params);
		lib_interface_ospf_free_address_params(ifp, addr);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/authentication-key
 */
static int lib_interface_ospf_interface_address_authentication_key_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, NULL, NULL);
		if (!params)
			return NB_OK;

		lib_interface_ospf_auth_simple_set(
			params, yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_authentication_key_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp, &addr);
		if (!params)
			return NB_OK;

		lib_interface_ospf_auth_simple_unset(params);
		lib_interface_ospf_free_address_params(ifp, addr);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/message-digest-key
 */
static int lib_interface_ospf_interface_address_message_digest_key_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/* The mandatory md5-key leaf applies the key material. */
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_message_digest_key_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;
	uint8_t key_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp, &addr);
		if (!params)
			return NB_OK;

		key_id = yang_dnode_get_uint8(args->dnode, "key-id");
		if (lib_interface_ospf_md5_key_delete(params, key_id) != NB_OK)
			return NB_ERR_INCONSISTENCY;
		lib_interface_ospf_free_address_params(ifp, addr);
		break;
	}

	return NB_OK;
}

static const void *lib_interface_ospf_interface_address_message_digest_key_get_next(struct nb_cb_get_next_args *args)
{
	const struct route_node *rn = args->parent_list_entry;
	struct ospf_if_params *params;
	struct listnode *node;

	if (!rn || !rn->info)
		return NULL;

	params = rn->info;
	if (!params->auth_crypt)
		return NULL;

	if (!args->list_entry)
		node = listhead(params->auth_crypt);
	else {
		node = listnode_lookup(params->auth_crypt, args->list_entry);
		node = listnextnode(node);
	}

	return node ? listgetdata(node) : NULL;
}

static int lib_interface_ospf_interface_address_message_digest_key_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct crypt_key *ck = args->list_entry;

	args->keys->num = 1;
	snprintf(args->keys->key[0], sizeof(args->keys->key[0]), "%u",
		 ck->key_id);
	return NB_OK;
}

static const void *lib_interface_ospf_interface_address_message_digest_key_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const struct route_node *rn = args->parent_list_entry;
	struct ospf_if_params *params;
	unsigned long key_id;
	char *endptr = NULL;

	if (!rn || !rn->info)
		return NULL;

	key_id = strtoul(args->keys->key[0], &endptr, 10);
	if (!endptr || *endptr || key_id > UINT8_MAX)
		return NULL;

	params = rn->info;
	return ospf_crypt_key_lookup(params->auth_crypt, key_id);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/message-digest-key/md5-key
 */
static int lib_interface_ospf_interface_address_message_digest_key_md5_key_modify(struct nb_cb_modify_args *args)
{
	const struct lyd_node *key_dnode;
	struct ospf_if_params *params;
	uint8_t key_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		key_dnode = yang_dnode_get_parent(args->dnode,
						  "message-digest-key");
		if (!key_dnode)
			return NB_ERR_INCONSISTENCY;

		params = lib_interface_ospf_get_address_params(key_dnode, true,
							       NULL, NULL);
		if (!params)
			return NB_OK;

		key_id = yang_dnode_get_uint8(key_dnode, "key-id");
		return lib_interface_ospf_md5_key_set(
			params, key_id, yang_dnode_get_string(args->dnode, NULL));
	}

	return NB_OK;
}


/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/key-chain
 */
static int lib_interface_ospf_interface_address_key_chain_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, NULL, NULL);
		if (!params)
			return NB_OK;

		lib_interface_ospf_key_chain_set(
			params, yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_key_chain_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp, &addr);
		if (!params)
			return NB_OK;

		lib_interface_ospf_key_chain_unset(params);
		lib_interface_ospf_auth_mode_unset(params);
		lib_interface_ospf_free_address_params(ifp, addr);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/cost
 */
static int lib_interface_ospf_interface_address_cost_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, &ifp, NULL);
		if (!params)
			return NB_OK;

		SET_IF_PARAM(params, output_cost_cmd);
		params->output_cost_cmd = yang_dnode_get_uint16(args->dnode,
								NULL);
		ospf_if_recalculate_output_cost(ifp);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_cost_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		UNSET_IF_PARAM(params, output_cost_cmd);
		lib_interface_ospf_free_address_params(ifp, addr);
		ospf_if_recalculate_output_cost(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address
 */
static void lib_interface_ospf_address_uint16_read(const struct lyd_node *dnode,
						   const char *path,
						   uint16_t default_value,
						   uint16_t *value,
						   bool *configured)
{
	struct lyd_node *leaf;

	leaf = yang_dnode_get(dnode, path);
	*configured = leaf && !lyd_is_default(leaf);
	*value = leaf ? yang_dnode_get_uint16(leaf, NULL) : default_value;
}

static bool
lib_interface_ospf_address_timer_configured(const struct lyd_node *dnode)
{
	return yang_dnode_get(dnode, "dead-interval/interval") ||
	       yang_dnode_get(dnode, "dead-interval/minimal") ||
	       yang_dnode_get(dnode, "hello-interval") ||
	       yang_dnode_get(dnode, "retransmit-interval") ||
	       yang_dnode_get(dnode, "retransmit-window") ||
	       yang_dnode_get(dnode, "transmit-delay");
}

static void lib_interface_ospf_address_fast_hello_set(struct ospf_if_params *params,
						      uint8_t multiplier,
						      bool configured)
{
	if (configured)
		SET_IF_PARAM(params, fast_hello);
	else
		UNSET_IF_PARAM(params, fast_hello);

	params->fast_hello = multiplier;
}

static void
lib_interface_ospf_address_timers_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;
	const struct lyd_node *minimal;
	uint16_t retransmit_interval;
	uint16_t retransmit_window;
	uint16_t transmit_delay;
	uint16_t hello_interval;
	uint16_t dead_interval;
	bool retransmit_interval_configured;
	bool retransmit_window_configured;
	bool transmit_delay_configured;
	bool hello_configured;
	bool dead_configured;
	bool wait_configured;
	bool fast_configured;
	bool wait_explicit;
	bool has_timers;
	uint8_t fast_hello;
	bool nbr_update;
	bool hello_update;

	has_timers = lib_interface_ospf_address_timer_configured(args->dnode);
	params = lib_interface_ospf_get_address_params(args->dnode, has_timers,
						       &ifp, &addr);
	if (!params)
		return;

	lib_interface_ospf_address_uint16_read(
		args->dnode, "hello-interval", OSPF_HELLO_INTERVAL_DEFAULT,
		&hello_interval, &hello_configured);
	minimal = yang_dnode_get(args->dnode, "dead-interval/minimal");
	if (minimal) {
		fast_configured = true;
		fast_hello = yang_dnode_get_uint8(minimal, "hello-multiplier");
		dead_interval = OSPF_ROUTER_DEAD_INTERVAL_MINIMAL;
		wait_configured = true;
		wait_explicit = true;
	} else {
		lib_interface_ospf_address_uint16_read(
			args->dnode, "dead-interval/interval",
			OSPF_ROUTER_DEAD_INTERVAL_DEFAULT, &dead_interval,
			&dead_configured);
		fast_configured = false;
		fast_hello = OSPF_FAST_HELLO_DEFAULT;
		if (dead_configured) {
			wait_configured = true;
			wait_explicit = true;
		} else if (hello_configured) {
			dead_interval = 4 * hello_interval;
			wait_configured = true;
			wait_explicit = false;
		} else {
			wait_configured = false;
			wait_explicit = false;
		}
	}

	nbr_update =
		OSPF_IF_PARAM_CONFIGURED(params, v_wait) != wait_configured ||
		params->v_wait != dead_interval ||
		params->is_v_wait_set != wait_explicit ||
		OSPF_IF_PARAM_CONFIGURED(params, fast_hello) !=
			fast_configured ||
		params->fast_hello != fast_hello;
	hello_update =
		OSPF_IF_PARAM_CONFIGURED(params, v_hello) != hello_configured ||
		params->v_hello != hello_interval ||
		OSPF_IF_PARAM_CONFIGURED(params, fast_hello) !=
			fast_configured ||
		params->fast_hello != fast_hello;

	lib_interface_ospf_set_hello_interval(params, hello_interval,
					      hello_configured);
	lib_interface_ospf_set_dead_interval(params, dead_interval,
					     wait_configured);
	params->is_v_wait_set = wait_explicit;
	lib_interface_ospf_address_fast_hello_set(params, fast_hello,
						  fast_configured);

	lib_interface_ospf_address_uint16_read(
		args->dnode, "retransmit-interval",
		OSPF_RETRANSMIT_INTERVAL_DEFAULT, &retransmit_interval,
		&retransmit_interval_configured);
	lib_interface_ospf_set_retransmit_interval(
		params, retransmit_interval, retransmit_interval_configured);

	lib_interface_ospf_address_uint16_read(
		args->dnode, "retransmit-window",
		OSPF_RETRANSMIT_WINDOW_DEFAULT, &retransmit_window,
		&retransmit_window_configured);
	lib_interface_ospf_set_retransmit_window(
		params, retransmit_window, retransmit_window_configured);

	lib_interface_ospf_address_uint16_read(
		args->dnode, "transmit-delay", OSPF_TRANSMIT_DELAY_DEFAULT,
		&transmit_delay, &transmit_delay_configured);
	lib_interface_ospf_set_transmit_delay(params, transmit_delay,
					      transmit_delay_configured);

	lib_interface_ospf_free_address_params(ifp, addr);
	if (nbr_update)
		lib_interface_ospf_nbr_timer_update_addr(ifp, addr);
	if (hello_update)
		ospf_reset_hello_timer(ifp, addr, true);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dead-interval/interval
 */
static int lib_interface_ospf_interface_address_dead_interval_interval_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int lib_interface_ospf_interface_address_dead_interval_interval_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dead-interval/minimal
 */
static int lib_interface_ospf_interface_address_dead_interval_minimal_create(struct nb_cb_create_args *args)
{
	return routing_ospf_create_apply_finish(args);
}

static int lib_interface_ospf_interface_address_dead_interval_minimal_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dead-interval/minimal/hello-multiplier
 */
static int lib_interface_ospf_interface_address_dead_interval_minimal_hello_multiplier_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/hello-interval
 */
static int lib_interface_ospf_interface_address_hello_interval_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int lib_interface_ospf_interface_address_hello_interval_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/retransmit-interval
 */
static int lib_interface_ospf_interface_address_retransmit_interval_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int lib_interface_ospf_interface_address_retransmit_interval_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/retransmit-window
 */
static int lib_interface_ospf_interface_address_retransmit_window_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int lib_interface_ospf_interface_address_retransmit_window_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/transmit-delay
 */
static int lib_interface_ospf_interface_address_transmit_delay_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int lib_interface_ospf_interface_address_transmit_delay_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/mtu-ignore
 */
static int lib_interface_ospf_interface_address_mtu_ignore_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, NULL, NULL);
		if (!params)
			return NB_OK;

		SET_IF_PARAM(params, mtu_ignore);
		params->mtu_ignore = yang_dnode_get_bool(args->dnode, NULL)
					     ? 1
					     : 0;
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_mtu_ignore_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		UNSET_IF_PARAM(params, mtu_ignore);
		params->mtu_ignore = OSPF_MTU_IGNORE_DEFAULT;
		lib_interface_ospf_free_address_params(ifp, addr);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/priority
 */
static int lib_interface_ospf_interface_address_priority_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, &ifp, NULL);
		if (!params)
			return NB_OK;

		SET_IF_PARAM(params, priority);
		params->priority = yang_dnode_get_uint8(args->dnode, NULL);
		lib_interface_ospf_priority_update(ifp);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_priority_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		UNSET_IF_PARAM(params, priority);
		params->priority = OSPF_ROUTER_PRIORITY_DEFAULT;
		lib_interface_ospf_free_address_params(ifp, addr);
		lib_interface_ospf_priority_update(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/passive
 */
static int lib_interface_ospf_interface_address_passive_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;
	uint8_t newval;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		newval = yang_dnode_get_bool(args->dnode, NULL)
				 ? OSPF_IF_PASSIVE
				 : OSPF_IF_ACTIVE;
		SET_IF_PARAM(params, passive_interface);
		params->passive_interface = newval;
		lib_interface_ospf_multicast_update(ifp);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_passive_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		UNSET_IF_PARAM(params, passive_interface);
		params->passive_interface = OSPF_IF_ACTIVE;
		lib_interface_ospf_free_address_params(ifp, addr);
		lib_interface_ospf_multicast_update(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/prefix-suppression
 */
static int lib_interface_ospf_interface_address_prefix_suppression_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;
	bool old_value;
	bool new_value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		old_value = OSPF_IF_PARAM_CONFIGURED(params, prefix_suppression)
				    ? params->prefix_suppression
				    : IF_DEF_PARAMS(ifp)->prefix_suppression;
		new_value = yang_dnode_get_bool(args->dnode, NULL);
		SET_IF_PARAM(params, prefix_suppression);
		params->prefix_suppression = new_value;
		if (old_value != new_value)
			lib_interface_ospf_prefix_suppression_lsa_update_addr(
				ifp, addr);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_prefix_suppression_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;
	bool new_value;
	bool old_value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		old_value = OSPF_IF_PARAM_CONFIGURED(params, prefix_suppression)
				    ? params->prefix_suppression
				    : IF_DEF_PARAMS(ifp)->prefix_suppression;
		UNSET_IF_PARAM(params, prefix_suppression);
		params->prefix_suppression = OSPF_PREFIX_SUPPRESSION_DEFAULT;
		lib_interface_ospf_free_address_params(ifp, addr);
		new_value = IF_DEF_PARAMS(ifp)->prefix_suppression;
		if (old_value != new_value)
			lib_interface_ospf_prefix_suppression_lsa_update_addr(
				ifp, addr);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/capability-opaque
 */
static int lib_interface_ospf_interface_address_capability_opaque_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;
	bool old_value;
	bool new_value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		old_value = OSPF_IF_PARAM_CONFIGURED(params, opaque_capable)
				    ? params->opaque_capable
				    : IF_DEF_PARAMS(ifp)->opaque_capable;
		new_value = yang_dnode_get_bool(args->dnode, NULL);
		SET_IF_PARAM(params, opaque_capable);
		params->opaque_capable = new_value;
		if (old_value != new_value)
			lib_interface_ospf_flap_addr(ifp, addr);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_capability_opaque_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;
	bool new_value;
	bool old_value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		old_value = OSPF_IF_PARAM_CONFIGURED(params, opaque_capable)
				    ? params->opaque_capable
				    : IF_DEF_PARAMS(ifp)->opaque_capable;
		UNSET_IF_PARAM(params, opaque_capable);
		params->opaque_capable = OSPF_OPAQUE_CAPABLE_DEFAULT;
		lib_interface_ospf_free_address_params(ifp, addr);
		new_value = IF_DEF_PARAMS(ifp)->opaque_capable;
		if (old_value != new_value)
			lib_interface_ospf_flap_addr(ifp, addr);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/neighbor-filter
 */
static int lib_interface_ospf_interface_address_neighbor_filter_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;
	const char *name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		name = yang_dnode_get_string(args->dnode, NULL);
		XFREE(MTYPE_OSPF_IF_PARAMS, params->nbr_filter_name);
		SET_IF_PARAM(params, nbr_filter_name);
		params->nbr_filter_name = XSTRDUP(MTYPE_OSPF_IF_PARAMS, name);
		lib_interface_ospf_neighbor_filter_update_addr(ifp, addr);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_neighbor_filter_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		UNSET_IF_PARAM(params, nbr_filter_name);
		XFREE(MTYPE_OSPF_IF_PARAMS, params->nbr_filter_name);
		lib_interface_ospf_free_address_params(ifp, addr);
		lib_interface_ospf_neighbor_filter_update_addr(ifp, addr);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd:ospf/interface-address/graceful-restart/hello-delay
 */
static int lib_interface_ospf_interface_address_graceful_restart_hello_delay_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       true, NULL, NULL);
		if (!params)
			return NB_OK;

		SET_IF_PARAM(params, v_gr_hello_delay);
		params->v_gr_hello_delay =
			yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}


static int lib_interface_ospf_interface_address_graceful_restart_hello_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;
	struct interface *ifp = NULL;
	struct in_addr addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = lib_interface_ospf_get_address_params(args->dnode,
							       false, &ifp,
							       &addr);
		if (!params)
			return NB_OK;

		UNSET_IF_PARAM(params, v_gr_hello_delay);
		params->v_gr_hello_delay = OSPF_HELLO_DELAY_DEFAULT;
		lib_interface_ospf_free_address_params(ifp, addr);
		lib_interface_ospf_gr_hello_delay_reset_addr(ifp, addr);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-id
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_router_id_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	struct in_addr router_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		yang_dnode_get_ipv4(&router_id, args->dnode, NULL);
		ospf->router_id_static = router_id;
		ospf_router_id_update(ospf);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf->router_id_static.s_addr = INADDR_ANY;
		ospf_router_id_update(ospf);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/instance
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_instance_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	unsigned short instance;

	switch (args->event) {
	case NB_EV_VALIDATE:
		instance = yang_dnode_get_uint16(args->dnode, NULL);
		if (instance != ospf_instance) {
			snprintf(args->errmsg, args->errmsg_len,
				 "OSPF instance %u does not match this ospfd process",
				 instance);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		/*
		 * The control-plane-protocol create hook creates and anchors the
		 * daemon object using this leaf.  The leaf itself is selector
		 * data, so APPLY only checks that the anchored object matches.
		 */
		ospf = routing_ospf_get(args->dnode);
		instance = yang_dnode_get_uint16(args->dnode, NULL);
		if (ospf->instance != instance)
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_instance_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	unsigned short instance;

	switch (args->event) {
	case NB_EV_VALIDATE:
		instance = yang_get_default_uint16(FRR_OSPFD_OSPF_XPATH
						   "/instance");
		if (instance != ospf_instance) {
			snprintf(args->errmsg, args->errmsg_len,
				 "OSPF instance %u does not match this ospfd process",
				 instance);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		instance = yang_get_default_uint16(FRR_OSPFD_OSPF_XPATH
						   "/instance");
		if (ospf->instance != instance)
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

static void
routing_control_plane_protocols_control_plane_protocol_ospf_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct ospf *ospf;

	ospf = routing_ospf_get(args->dnode);
	ospf->proactive_arp = routing_ospf_get_bool_default(
		args->dnode, "proactive-arp",
		FRR_OSPFD_OSPF_XPATH "/proactive-arp");
	ospf->forwarding_address_self = routing_ospf_get_bool_default(
		args->dnode, "forwarding-address-self",
		FRR_OSPFD_OSPF_XPATH "/forwarding-address-self");
	ospf->write_oi_count = routing_ospf_get_uint8_default(
		args->dnode, "write-multiplier",
		FRR_OSPFD_OSPF_XPATH "/write-multiplier");
	routing_ospf_rfc1583_update(
		ospf, routing_ospf_get_bool_default(
			      args->dnode, "compatible-rfc1583",
			      FRR_OSPFD_OSPF_XPATH "/compatible-rfc1583"));
	routing_ospf_flood_reduction_set(
		ospf, routing_ospf_get_bool_default(
			      args->dnode, "flood-reduction",
			      FRR_OSPFD_OSPF_XPATH "/flood-reduction"));
	routing_ospf_send_extra_data_update(
		ospf, routing_ospf_get_bool_default(
			      args->dnode, "send-extra-data",
			      FRR_OSPFD_OSPF_XPATH "/send-extra-data"));
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/abr-type
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_abr_type_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_abr_type_update(
			ospf, yang_dnode_get_enum(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_abr_type_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_abr_type_update(
			ospf,
			yang_get_default_enum(FRR_OSPFD_OSPF_XPATH
					      "/abr-type"));
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/auto-cost-reference-bandwidth
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_auto_cost_reference_bandwidth_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_auto_cost_update(
			ospf, yang_dnode_get_uint32(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_auto_cost_reference_bandwidth_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_auto_cost_update(
			ospf, yang_get_default_uint32(
				      FRR_OSPFD_OSPF_XPATH
				      "/auto-cost-reference-bandwidth"));
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/proactive-arp
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_proactive_arp_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_proactive_arp_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/opaque-capability
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_opaque_capability_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ospf = routing_ospf_get(args->dnode);
		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable && ospf->vrf_id != VRF_DEFAULT) {
			snprintf(args->errmsg, args->errmsg_len,
				 "OSPF opaque LSA is only supported in default VRF");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_opaque_capability_update(
			ospf, yang_dnode_get_bool(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_opaque_capability_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_opaque_capability_update(
			ospf, yang_get_default_bool(
				      FRR_OSPFD_OSPF_XPATH
				      "/opaque-capability"));
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/shutdown
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	bool shutdown;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ospf = routing_ospf_get(args->dnode);
		shutdown = yang_dnode_get_bool(args->dnode, NULL);
		if (shutdown && ospf->gr_info.restart_support &&
		    !CHECK_FLAG(ospf->config, OSPF_OPAQUE_CAPABLE)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "graceful restart requires opaque capability");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		shutdown = yang_dnode_get_bool(args->dnode, NULL);
		if (shutdown)
			ospf_gr_shutdown_enter(ospf);
		ospf_shutdown(ospf, shutdown);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_shutdown_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf_shutdown(ospf, yang_get_default_bool(
					   FRR_OSPFD_OSPF_XPATH "/shutdown"));
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/forwarding-address-self
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_forwarding_address_self_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_forwarding_address_self_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/compatible-rfc1583
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_compatible_rfc1583_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_compatible_rfc1583_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-metric
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_default_metric_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf->default_metric = yang_dnode_get_uint32(args->dnode, NULL);
		ospf_schedule_asbr_redist_update(ospf);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_default_metric_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf->default_metric = -1;
		ospf_schedule_asbr_redist_update(ospf);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/write-multiplier
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_write_multiplier_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_write_multiplier_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/maximum-paths
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_maximum_paths_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	uint16_t paths;

	switch (args->event) {
	case NB_EV_VALIDATE:
		paths = yang_dnode_get_uint16(args->dnode, NULL);
		if (paths > MULTIPATH_NUM) {
			snprintf(args->errmsg, args->errmsg_len,
				 "maximum-paths exceeds platform max %u",
				 MULTIPATH_NUM);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		paths = yang_dnode_get_uint16(args->dnode, NULL);
		if (ospf->max_multipath == paths)
			return NB_OK;

		ospf->max_multipath = paths;
		ospf_restart_spf(ospf);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_maximum_paths_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		if (ospf->max_multipath == MULTIPATH_NUM)
			return NB_OK;

		ospf->max_multipath = MULTIPATH_NUM;
		ospf_restart_spf(ospf);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/flood-reduction
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_flood_reduction_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_flood_reduction_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/send-extra-data
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_send_extra_data_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_send_extra_data_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/log-adjacency-changes
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_create(struct nb_cb_create_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		SET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES);
		UNSET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		UNSET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL);
		UNSET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/log-adjacency-changes/detail
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_detail_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	bool detail;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		detail = yang_dnode_get_bool(args->dnode, NULL);
		SET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES);
		routing_ospf_flag_update(ospf, OSPF_LOG_ADJACENCY_DETAIL,
					 detail);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_detail_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_flag_update(
			ospf, OSPF_LOG_ADJACENCY_DETAIL,
			yang_get_default_bool(
				FRR_OSPFD_OSPF_XPATH
				"/log-adjacency-changes/detail"));
		break;
	}

	return NB_OK;
}

static void routing_control_plane_protocols_control_plane_protocol_ospf_socket_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct ospf *ospf;
	uint32_t recv;
	uint32_t send;

	ospf = routing_ospf_get(args->dnode);
	recv = routing_ospf_get_uint32_default(
		args->dnode, "receive-buffer",
		FRR_OSPFD_OSPF_XPATH "/socket/receive-buffer");
	send = routing_ospf_get_uint32_default(
		args->dnode, "send-buffer",
		FRR_OSPFD_OSPF_XPATH "/socket/send-buffer");

	ospf_update_bufsize(ospf, recv, send);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/socket/per-interface
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_socket_per_interface_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_per_interface_socket_update(
			ospf, yang_dnode_get_bool(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_socket_per_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_per_interface_socket_update(
			ospf, yang_get_default_bool(
				      FRR_OSPFD_OSPF_XPATH
				      "/socket/per-interface"));
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/scope
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_scope_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	uint8_t scope;
	char errmsg[128];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		scope = yang_dnode_get_enum(args->dnode, NULL) == 0
				? OSPF_OPAQUE_AS_LSA
				: OSPF_OPAQUE_AREA_LSA;
		if (ospf_router_info_set(ospf, scope, errmsg, sizeof(errmsg)) <
		    0) {
			snprintf(args->errmsg, args->errmsg_len, "%s", errmsg);
			return NB_ERR_INCONSISTENCY;
		}
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_scope_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf_router_info_unset();
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/address
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_address_modify(struct nb_cb_modify_args *args)
{
	struct in_addr address;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		yang_dnode_get_ipv4(&address, args->dnode, NULL);
		ospf_pce_address_set(address);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_address_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf_pce_address_unset();
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf_pce_scope_set(yang_dnode_get_uint32(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf_pce_scope_unset();
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/domain-as
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_domain_as_create(struct nb_cb_create_args *args)
{
	struct ri_pce_subtlv_domain *domain;
	uint32_t as;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		as = yang_dnode_get_uint32(args->dnode, "as");
		domain = ospf_pce_domain_as_set(as);
		nb_running_set_entry(args->dnode, domain);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_domain_as_destroy(struct nb_cb_destroy_args *args)
{
	struct ri_pce_subtlv_domain *domain;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		domain = nb_running_unset_entry(args->dnode);
		ospf_pce_domain_as_unset(domain);
		break;
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_domain_as_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_domain_as_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_domain_as_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/neighbor-as
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_neighbor_as_create(struct nb_cb_create_args *args)
{
	struct ri_pce_subtlv_neighbor *neighbor;
	uint32_t as;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		as = yang_dnode_get_uint32(args->dnode, "as");
		neighbor = ospf_pce_neighbor_as_set(as);
		nb_running_set_entry(args->dnode, neighbor);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_neighbor_as_destroy(struct nb_cb_destroy_args *args)
{
	struct ri_pce_subtlv_neighbor *neighbor;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		neighbor = nb_running_unset_entry(args->dnode);
		ospf_pce_neighbor_as_unset(neighbor);
		break;
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_neighbor_as_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_neighbor_as_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_neighbor_as_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/flag
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_flag_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf_pce_flag_set(yang_dnode_get_uint32(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_flag_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf_pce_flag_unset();
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/enabled
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_enabled_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	bool enabled;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ospf = routing_ospf_get(args->dnode);
		enabled = yang_dnode_get_bool(args->dnode, NULL);
		if (!enabled)
			return routing_ospf_gr_validate_not_preparing(
				ospf, args->errmsg, args->errmsg_len);
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		enabled = yang_dnode_get_bool(args->dnode, NULL);
		if (enabled)
			ospf_gr_restart_support_enable(ospf);
		else
			ospf_gr_restart_support_disable(ospf);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ospf = routing_ospf_get(args->dnode);
		return routing_ospf_gr_validate_not_preparing(
			ospf, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf_gr_restart_support_disable(ospf);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/grace-period
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_grace_period_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ospf = routing_ospf_get(args->dnode);
		return routing_ospf_gr_validate_not_preparing(
			ospf, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf_gr_set_grace_period(
			ospf, yang_dnode_get_uint16(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_grace_period_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ospf = routing_ospf_get(args->dnode);
		return routing_ospf_gr_validate_not_preparing(
			ospf, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf_gr_set_grace_period(
			ospf,
			yang_get_default_uint16(
				FRR_OSPFD_OSPF_XPATH
				"/graceful-restart/grace-period"));
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper/enabled-for-router
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enabled_for_router_create(struct nb_cb_create_args *args)
{
	struct in_addr router_id;
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		yang_dnode_get_ipv4(&router_id, args->dnode, "router-id");
		ospf_gr_helper_support_set_per_routerid(ospf, &router_id,
							OSPF_GR_TRUE);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enabled_for_router_destroy(struct nb_cb_destroy_args *args)
{
	struct in_addr router_id;
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		yang_dnode_get_ipv4(&router_id, args->dnode, "router-id");
		ospf_gr_helper_support_set_per_routerid(ospf, &router_id,
							OSPF_GR_FALSE);
		break;
	}

	return NB_OK;
}

static void routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct ospf *ospf;

	ospf = routing_ospf_get(args->dnode);
	ospf_gr_helper_support_set(
		ospf,
		routing_ospf_get_bool_default(
			args->dnode, "enabled",
			FRR_OSPFD_OSPF_XPATH
			"/graceful-restart/helper/enabled"));
	ospf_gr_helper_lsa_check_set(
		ospf,
		routing_ospf_get_bool_default(
			args->dnode, "strict-lsa-checking",
			FRR_OSPFD_OSPF_XPATH
			"/graceful-restart/helper/strict-lsa-checking"));
	ospf_gr_helper_supported_gracetime_set(
		ospf,
		routing_ospf_get_uint16_default(
			args->dnode, "supported-grace-time",
			FRR_OSPFD_OSPF_XPATH
			"/graceful-restart/helper/supported-grace-time"));
	ospf_gr_helper_set_supported_planned_only_restart(
		ospf,
		routing_ospf_get_bool_default(
			args->dnode, "planned-only",
			FRR_OSPFD_OSPF_XPATH
			"/graceful-restart/helper/planned-only"));
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enabled_for_router_get_next(struct nb_cb_get_next_args *args)
{
	const struct advRtr *prev = args->list_entry;
	const struct advRtr *rtr;
	struct ospf *ospf;
	unsigned int i;

	ospf = routing_ospf_parent_entry(args->parent_list_entry);
	if (!ospf || !ospf->enable_rtr_list)
		return NULL;

	for (i = 0; i < ospf->enable_rtr_list->size; i++) {
		struct hash_bucket *bucket;

		for (bucket = ospf->enable_rtr_list->index[i]; bucket;
		     bucket = bucket->next) {
			rtr = bucket->data;
			if (!prev)
				return rtr;
			if (rtr == prev)
				prev = NULL;
		}
	}

	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enabled_for_router_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct advRtr *rtr = args->list_entry;

	args->keys->num = 1;
	inet_ntop(AF_INET, &rtr->advRtrAddr, args->keys->key[0],
		  sizeof(args->keys->key[0]));

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enabled_for_router_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct advRtr lookup;
	struct ospf *ospf;

	ospf = routing_ospf_parent_entry(args->parent_list_entry);
	if (!ospf || !ospf->enable_rtr_list)
		return NULL;

	if (!inet_aton(args->keys->key[0], &lookup.advRtrAddr))
		return NULL;

	return hash_lookup(ospf->enable_rtr_list, &lookup);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/ldp-sync/enabled
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_ldp_sync_enabled_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return routing_ospf_validate_default_vrf(
			args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		if (ospf->vrf_id != VRF_DEFAULT)
			return NB_ERR_INCONSISTENCY;

		routing_ospf_ldp_sync_enabled_set(
			ospf, yang_dnode_get_bool(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_ldp_sync_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return routing_ospf_validate_default_vrf(
			args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		if (ospf->vrf_id != VRF_DEFAULT)
			return NB_ERR_INCONSISTENCY;

		routing_ospf_ldp_sync_enabled_set(
			ospf, yang_get_default_bool(
				      FRR_OSPFD_OSPF_XPATH "/ldp-sync/enabled"));
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/ldp-sync/holddown
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_ldp_sync_holddown_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return routing_ospf_validate_default_vrf(
			args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		if (ospf->vrf_id != VRF_DEFAULT)
			return NB_ERR_INCONSISTENCY;

		routing_ospf_ldp_sync_holddown_set(
			ospf, yang_dnode_get_uint16(args->dnode, NULL), true);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_ldp_sync_holddown_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return routing_ospf_validate_default_vrf(
			args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		if (ospf->vrf_id != VRF_DEFAULT)
			return NB_ERR_INCONSISTENCY;

		routing_ospf_ldp_sync_holddown_set(
			ospf,
			yang_get_default_uint16(
				FRR_OSPFD_OSPF_XPATH "/ldp-sync/holddown"),
			false);
		break;
	}

	return NB_OK;
}

static void routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct ospf *ospf;
	bool enable;
	bool node_protection;

	ospf = routing_ospf_get(args->dnode);
	enable = routing_ospf_get_bool_default(
		args->dnode, "enable",
		FRR_OSPFD_OSPF_XPATH "/fast-reroute/ti-lfa/enable");
	node_protection = routing_ospf_get_bool_default(
		args->dnode, "node-protection",
		FRR_OSPFD_OSPF_XPATH
		"/fast-reroute/ti-lfa/node-protection");

	routing_ospf_ti_lfa_set(ospf, enable, node_protection);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/fast-reroute/ti-lfa/enable
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_enable_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* APPLY is intentionally done by the parent apply_finish. */
		break;
	}

	return NB_OK;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_enable_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* APPLY is intentionally done by the parent apply_finish. */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/fast-reroute/ti-lfa/node-protection
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_node_protection_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* APPLY is intentionally done by the parent apply_finish. */
		break;
	}

	return NB_OK;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_node_protection_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* APPLY is intentionally done by the parent apply_finish. */
		break;
	}

	return NB_OK;
}

static const struct lyd_node *
routing_ospf_policy_parent(const struct lyd_node *dnode, const char *name)
{
	return yang_dnode_get_parent(dnode, name);
}

static int routing_ospf_metric_common_value(const struct lyd_node *dnode)
{
	if (yang_dnode_exists(dnode, "metric"))
		return yang_dnode_get_uint32(dnode, "metric");

	return -1;
}

static int routing_ospf_metric_common_type(const struct lyd_node *dnode)
{
	if (yang_dnode_exists(dnode, "metric-type"))
		return routing_ospf_metric_type_from_yang(
			yang_dnode_get_enum(dnode, "metric-type"));

	return -1;
}

static const char *routing_ospf_metric_common_route_map(
	const struct lyd_node *dnode)
{
	if (yang_dnode_exists(dnode, "route-map"))
		return yang_dnode_get_string(dnode, "route-map");

	return NULL;
}

static int routing_ospf_redist_protocol(const struct lyd_node *dnode)
{
	return proto_redistnum(AFI_IP,
			       yang_dnode_get_string(dnode, "protocol"));
}

static uint16_t routing_ospf_redist_source_id(const struct lyd_node *dnode)
{
	return yang_dnode_get_uint16(dnode, "source-id");
}

static int routing_ospf_redist_validate(const struct lyd_node *dnode,
					char *errmsg, size_t errmsg_len)
{
	int protocol;
	uint16_t instance;
	uint16_t source_id;

	protocol = routing_ospf_redist_protocol(dnode);
	if (protocol == ZEBRA_ROUTE_ERROR) {
		snprintf(errmsg, errmsg_len, "unsupported redistribute protocol");
		return NB_ERR_VALIDATION;
	}

	if (protocol != ZEBRA_ROUTE_OSPF)
		return NB_OK;

	instance = routing_ospf_instance(dnode);
	source_id = routing_ospf_redist_source_id(dnode);
	if (!instance) {
		snprintf(errmsg, errmsg_len,
			 "instance redistribution in non-instanced OSPF is not allowed");
		return NB_ERR_VALIDATION;
	}
	if (instance == source_id) {
		snprintf(errmsg, errmsg_len,
			 "same instance OSPF redistribution is not allowed");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static int routing_ospf_redist_apply(const struct lyd_node *dnode)
{
	struct ospf_redist *red;
	struct ospf *ospf;
	const char *route_map;
	uint16_t source_id;
	int protocol;
	bool update;

	ospf = routing_ospf_get(dnode);
	protocol = routing_ospf_redist_protocol(dnode);
	if (protocol == ZEBRA_ROUTE_ERROR)
		return NB_ERR_INCONSISTENCY;

	source_id = routing_ospf_redist_source_id(dnode);
	red = ospf_redist_lookup(ospf, protocol, source_id);
	update = red != NULL;
	if (!red)
		red = ospf_redist_add(ospf, protocol, source_id);

	route_map = routing_ospf_metric_common_route_map(dnode);
	if (route_map)
		ospf_routemap_set(red, route_map);
	else
		ospf_routemap_unset(red);

	if (update)
		return ospf_redistribute_update(
			ospf, red, protocol, source_id,
			routing_ospf_metric_common_type(dnode),
			routing_ospf_metric_common_value(dnode));

	return ospf_redistribute_set(
		ospf, red, protocol, source_id,
		routing_ospf_metric_common_type(dnode),
		routing_ospf_metric_common_value(dnode));
}

static int routing_ospf_redist_unset(const struct lyd_node *dnode)
{
	struct ospf_redist *red;
	struct ospf *ospf;
	uint16_t source_id;
	int protocol;

	ospf = routing_ospf_get(dnode);
	protocol = routing_ospf_redist_protocol(dnode);
	if (protocol == ZEBRA_ROUTE_ERROR)
		return NB_ERR_INCONSISTENCY;

	source_id = routing_ospf_redist_source_id(dnode);
	red = ospf_redist_lookup(ospf, protocol, source_id);
	if (!red)
		return NB_OK;

	ospf_routemap_unset(red);
	ospf_redist_del(ospf, protocol, source_id);
	return ospf_redistribute_unset(ospf, protocol, source_id);
}

static void
routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	routing_ospf_redist_apply(args->dnode);
}

static int routing_ospf_default_information_apply(const struct lyd_node *dnode)
{
	struct ospf_redist *red;
	struct ospf *ospf;
	const char *route_map;
	int originate;

	ospf = routing_ospf_get(dnode);
	red = ospf_redist_add(ospf, DEFAULT_ROUTE, 0);

	route_map = routing_ospf_metric_common_route_map(dnode);
	if (route_map)
		ospf_routemap_set(red, route_map);
	else
		ospf_routemap_unset(red);

	red->dmetric.type = routing_ospf_metric_common_type(dnode);
	red->dmetric.value = routing_ospf_metric_common_value(dnode);
	originate = routing_ospf_get_bool_default(
			    dnode, "always",
			    FRR_OSPFD_OSPF_XPATH
			    "/default-information-originate/always")
		    ? DEFAULT_ORIGINATE_ALWAYS
		    : DEFAULT_ORIGINATE_ZEBRA;

	return ospf_redistribute_default_set(ospf, originate,
					     red->dmetric.type,
					     red->dmetric.value);
}

static int routing_ospf_default_information_unset(const struct lyd_node *dnode)
{
	struct ospf_redist *red;
	struct ospf *ospf;

	ospf = routing_ospf_get(dnode);
	red = ospf_redist_lookup(ospf, DEFAULT_ROUTE, 0);
	if (red) {
		ospf_routemap_unset(red);
		ospf_redist_del(ospf, DEFAULT_ROUTE, 0);
	}

	return ospf_redistribute_default_set(ospf, DEFAULT_ORIGINATE_NONE, 0,
					     0);
}

static void
routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	routing_ospf_default_information_apply(args->dnode);
}

static bool routing_ospf_summary_prefix(const struct lyd_node *dnode,
					struct prefix_ipv4 *p)
{
	const struct lyd_node *summary_dnode;

	summary_dnode = routing_ospf_policy_parent(dnode, "summary-address");
	if (!summary_dnode)
		return false;

	yang_dnode_get_ipv4p(p, summary_dnode, "prefix");
	apply_mask_ipv4(p);
	return true;
}

static route_tag_t routing_ospf_summary_tag(const struct lyd_node *dnode)
{
	const struct lyd_node *summary_dnode;

	summary_dnode = routing_ospf_policy_parent(dnode, "summary-address");
	if (summary_dnode && yang_dnode_exists(summary_dnode, "tag"))
		return yang_dnode_get_uint32(summary_dnode, "tag");

	return 0;
}

static bool routing_ospf_summary_no_advertise(const struct lyd_node *dnode)
{
	const struct lyd_node *summary_dnode;

	summary_dnode = routing_ospf_policy_parent(dnode, "summary-address");
	return summary_dnode && yang_dnode_exists(summary_dnode, "no-advertise")
		       ? yang_dnode_get_bool(summary_dnode, "no-advertise")
		       : false;
}

static int routing_ospf_summary_validate(const struct lyd_node *dnode,
					 char *errmsg, size_t errmsg_len)
{
	struct prefix_ipv4 p;

	if (!routing_ospf_summary_prefix(dnode, &p)) {
		snprintf(errmsg, errmsg_len, "missing summary-address prefix");
		return NB_ERR_VALIDATION;
	}
	if (is_default_prefix4(&p)) {
		snprintf(errmsg, errmsg_len,
			 "default address cannot be configured as summary address");
		return NB_ERR_VALIDATION;
	}
	if (!is_valid_summary_addr(&p)) {
		snprintf(errmsg, errmsg_len, "not a valid summary address");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static int routing_ospf_summary_apply(const struct lyd_node *dnode)
{
	struct prefix_ipv4 p;
	struct ospf *ospf;
	int ret;

	if (!routing_ospf_summary_prefix(dnode, &p))
		return NB_ERR_INCONSISTENCY;

	ospf = routing_ospf_get(dnode);
	if (routing_ospf_summary_no_advertise(dnode))
		ret = ospf_asbr_external_rt_no_advertise(ospf, &p);
	else
		ret = ospf_asbr_external_aggregator_set(
			ospf, &p, routing_ospf_summary_tag(dnode));

	return ret == OSPF_SUCCESS ? NB_OK : NB_ERR_INCONSISTENCY;
}

static int routing_ospf_summary_unset(const struct lyd_node *dnode)
{
	struct prefix_ipv4 p;
	struct ospf *ospf;
	int ret;

	if (!routing_ospf_summary_prefix(dnode, &p))
		return NB_ERR_INCONSISTENCY;

	ospf = routing_ospf_get(dnode);
	ret = ospf_asbr_external_aggregator_unset(
		ospf, &p, routing_ospf_summary_tag(dnode));
	return ret == OSPF_SUCCESS || ret == OSPF_INVALID
		       ? NB_OK
		       : NB_ERR_INCONSISTENCY;
}

static void
routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	routing_ospf_summary_apply(args->dnode);
}

static int routing_ospf_network_prefix(const struct lyd_node *dnode,
				       struct prefix_ipv4 *p)
{
	const struct lyd_node *network_dnode;

	network_dnode = routing_ospf_policy_parent(dnode, "network");
	if (!network_dnode)
		return -1;

	yang_dnode_get_ipv4p(p, network_dnode, "prefix");
	apply_mask_ipv4(p);
	return 0;
}

static int routing_ospf_network_area_id(const struct lyd_node *dnode,
					struct in_addr *area_id)
{
	const struct lyd_node *network_dnode;
	const char *area_id_str;
	int format;

	network_dnode = routing_ospf_policy_parent(dnode, "network");
	if (!network_dnode || !yang_dnode_exists(network_dnode, "area"))
		return -1;

	area_id_str = yang_dnode_get_string(network_dnode, "area");
	return str2area_id(area_id_str, area_id, &format);
}

static bool routing_ospf_candidate_has_interface_attachments(
	const struct lyd_node *dnode, uint16_t instance)
{
	const struct lyd_node *root = dnode;
	struct ly_set *set = NULL;
	char xpath[XPATH_MAXLEN];
	bool found = false;

	while (lyd_parent(root))
		root = lyd_parent(root);
	root = lyd_first_sibling(root);

	snprintf(xpath, sizeof(xpath),
		 "/frr-interface:lib/interface/frr-ospfd:ospf/"
		 "attachment[instance='%u']",
		 instance);
	if (lyd_find_xpath(root, xpath, &set) == LY_SUCCESS && set)
		found = set->count > 0;
	if (set)
		ly_set_free(set, NULL);

	return found;
}

static int routing_ospf_network_validate(const struct lyd_node *dnode,
					 char *errmsg, size_t errmsg_len)
{
	struct ospf *ospf;
	uint16_t instance;

	instance = routing_ospf_instance(dnode);
	ospf = routing_ospf_lookup(dnode);
	if ((ospf && ospf_count_area_params(ospf) > 0) ||
	    routing_ospf_candidate_has_interface_attachments(dnode, instance)) {
		snprintf(errmsg, errmsg_len,
			 "please remove all ip ospf area commands first");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

static int routing_ospf_network_apply(const struct lyd_node *dnode)
{
	struct ospf_network *network;
	struct prefix_ipv4 p;
	struct in_addr area_id;
	struct route_node *rn;
	struct ospf *ospf;
	int ret;

	if (routing_ospf_network_prefix(dnode, &p) < 0 ||
	    routing_ospf_network_area_id(dnode, &area_id) < 0)
		return NB_ERR_INCONSISTENCY;

	ospf = routing_ospf_get(dnode);
	rn = route_node_lookup(ospf->networks, (struct prefix *)&p);
	if (rn) {
		network = rn->info;
		route_unlock_node(rn);
		if (network && !IPV4_ADDR_SAME(&network->area_id, &area_id))
			ospf_network_unset(ospf, &p, network->area_id);
	}

	ret = ospf_network_set(ospf, &p, area_id, OSPF_AREA_ID_FMT_DOTTEDQUAD);
	return ret ? NB_OK : NB_ERR_INCONSISTENCY;
}

static int routing_ospf_network_unset(const struct lyd_node *dnode)
{
	struct prefix_ipv4 p;
	struct in_addr area_id;
	struct ospf *ospf;

	if (routing_ospf_network_prefix(dnode, &p) < 0 ||
	    routing_ospf_network_area_id(dnode, &area_id) < 0)
		return NB_ERR_INCONSISTENCY;

	ospf = routing_ospf_get(dnode);
	ospf_network_unset(ospf, &p, area_id);
	return NB_OK;
}

static void
routing_control_plane_protocols_control_plane_protocol_ospf_network_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	routing_ospf_network_apply(args->dnode);
}

static int routing_ospf_distribute_list_protocol(const struct lyd_node *dnode)
{
	return proto_redistnum(AFI_IP,
			       yang_dnode_get_string(dnode, "protocol"));
}

static int routing_ospf_distribute_list_apply(const struct lyd_node *dnode,
					      bool enable)
{
	struct ospf *ospf;
	const char *name;
	int protocol;

	ospf = routing_ospf_get(dnode);
	protocol = routing_ospf_distribute_list_protocol(dnode);
	if (protocol == ZEBRA_ROUTE_ERROR)
		return NB_ERR_INCONSISTENCY;

	name = yang_dnode_get_string(dnode, "name");
	if (enable)
		return ospf_distribute_list_out_set(ospf, protocol, name);

	return ospf_distribute_list_out_unset(ospf, protocol, name);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/summary-address
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return routing_ospf_summary_validate(args->dnode, args->errmsg,
						     args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_summary_unset(args->dnode);
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/summary-address/tag
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_tag_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_tag_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/summary-address/no-advertise
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_no_advertise_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/aggregation-timer
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_aggregation_timer_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf_external_aggregator_timer_set(
			ospf, yang_dnode_get_uint16(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_aggregation_timer_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf_external_aggregator_timer_set(
			ospf, yang_get_default_uint16(
				      FRR_OSPFD_OSPF_XPATH
				      "/aggregation-timer"));
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information-originate
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_create(struct nb_cb_create_args *args)
{
	return routing_ospf_create_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_default_information_unset(args->dnode);
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information-originate/always
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_always_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information-originate/metric
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_metric_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_metric_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information-originate/metric-type
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_metric_type_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_metric_type_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information-originate/route-map
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_route_map_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return routing_ospf_redist_validate(args->dnode, args->errmsg,
						    args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_redist_unset(args->dnode);
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/metric
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_metric_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_metric_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/metric-type
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_metric_type_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_metric_type_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/route-map
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_route_map_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_route_map_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distance/admin-value
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_distance_admin_value_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_distance_modify(args,
					    offsetof(struct ospf, distance_all));
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_distance_admin_value_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_distance_destroy(
		args, offsetof(struct ospf, distance_all), 0);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distance/ospf/external
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_external_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_distance_modify(
		args, offsetof(struct ospf, distance_external));
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_external_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_distance_destroy(
		args, offsetof(struct ospf, distance_external),
		yang_get_default_uint8(FRR_OSPFD_OSPF_XPATH
				       "/distance/ospf/external"));
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distance/ospf/inter-area
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_inter_area_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_distance_modify(
		args, offsetof(struct ospf, distance_inter));
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_inter_area_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_distance_destroy(
		args, offsetof(struct ospf, distance_inter),
		yang_get_default_uint8(FRR_OSPFD_OSPF_XPATH
				       "/distance/ospf/inter-area"));
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distance/ospf/intra-area
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_intra_area_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_distance_modify(
		args, offsetof(struct ospf, distance_intra));
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_intra_area_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_distance_destroy(
		args, offsetof(struct ospf, distance_intra),
		yang_get_default_uint8(FRR_OSPFD_OSPF_XPATH
				       "/distance/ospf/intra-area"));
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distribute-list/dlist
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_distribute_list_dlist_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (routing_ospf_distribute_list_protocol(args->dnode) ==
		    ZEBRA_ROUTE_ERROR) {
			snprintf(args->errmsg, args->errmsg_len,
				 "unsupported distribute-list protocol");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_distribute_list_apply(args->dnode, true);
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_distribute_list_dlist_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_distribute_list_apply(args->dnode, false);
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_distribute_list_dlist_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_distribute_list_dlist_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_distribute_list_dlist_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/administrative
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_administrative_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		enable = yang_dnode_get_bool(args->dnode, NULL);
		routing_ospf_stub_router_admin_set(ospf, enable);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_administrative_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		enable = yang_get_default_bool(
			FRR_OSPFD_OSPF_XPATH
			"/max-metric/router-lsa/administrative");
		routing_ospf_stub_router_admin_set(ospf, enable);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/on-shutdown
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_stub_router_shutdown_set(
			ospf, yang_dnode_get_uint32(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_shutdown_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_stub_router_shutdown_unset(ospf);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/on-startup
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_startup_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_stub_router_startup_set(
			ospf, yang_dnode_get_uint32(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_startup_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_stub_router_startup_unset(ospf);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls-te/on
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_on_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	char errmsg[128];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		if (ospf_mpls_te_enabled_set(
			    ospf, yang_dnode_get_bool(args->dnode, NULL),
			    errmsg, sizeof(errmsg)) < 0) {
			snprintf(args->errmsg, args->errmsg_len, "%s", errmsg);
			return NB_ERR_INCONSISTENCY;
		}
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls-te/router-address
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_router_address_modify(struct nb_cb_modify_args *args)
{
	struct in_addr address;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		yang_dnode_get_ipv4(&address, args->dnode, NULL);
		ospf_mpls_te_router_addr_set(address);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_router_address_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf_mpls_te_router_addr_unset();
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls-te/export
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_export_modify(struct nb_cb_modify_args *args)
{
	char errmsg[128];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (ospf_mpls_te_export_set(
			    yang_dnode_get_bool(args->dnode, NULL), errmsg,
			    sizeof(errmsg)) < 0) {
			snprintf(args->errmsg, args->errmsg_len, "%s", errmsg);
			return NB_ERR_INCONSISTENCY;
		}
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls-te/inter-as/as
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_as_create(struct nb_cb_create_args *args)
{
	struct in_addr area_id = {};
	char errmsg[128];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (ospf_mpls_te_inter_as_set(AS, area_id, errmsg,
					      sizeof(errmsg)) < 0) {
			snprintf(args->errmsg, args->errmsg_len, "%s", errmsg);
			return NB_ERR_INCONSISTENCY;
		}
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_as_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf_mpls_te_inter_as_unset();
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls-te/inter-as/area
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_area_modify(struct nb_cb_modify_args *args)
{
	struct in_addr area_id;
	char errmsg[128];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		yang_dnode_get_ipv4(&area_id, args->dnode, NULL);
		if (ospf_mpls_te_inter_as_set(Area, area_id, errmsg,
					      sizeof(errmsg)) < 0) {
			snprintf(args->errmsg, args->errmsg_len, "%s", errmsg);
			return NB_ERR_INCONSISTENCY;
		}
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_area_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf_mpls_te_inter_as_unset();
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/refresh-interval
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_timers_refresh_interval_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	uint16_t interval;

	switch (args->event) {
	case NB_EV_VALIDATE:
		interval = yang_dnode_get_uint16(args->dnode, NULL);
		if (interval % OSPF_LSA_REFRESHER_GRANULARITY) {
			snprintf(args->errmsg, args->errmsg_len,
				 "refresh-interval must be a multiple of %u",
				 OSPF_LSA_REFRESHER_GRANULARITY);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		interval = yang_dnode_get_uint16(args->dnode, NULL);
		ospf_timers_refresh_set(ospf, interval);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_timers_refresh_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf_timers_refresh_set(
			ospf,
			yang_get_default_uint16(
				FRR_OSPFD_OSPF_XPATH
				"/timers/refresh-interval"));
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/lsa-refresh-time
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_refresh_time_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf->lsa_refresh_timer =
			yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_refresh_time_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf->lsa_refresh_timer = yang_get_default_uint16(
			FRR_OSPFD_OSPF_XPATH "/timers/lsa-refresh-time");
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/maxage-delay
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_timers_maxage_delay_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_maxage_delay_update(
			ospf, yang_dnode_get_uint8(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_timers_maxage_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_maxage_delay_update(
			ospf, yang_get_default_uint8(
				      FRR_OSPFD_OSPF_XPATH
				      "/timers/maxage-delay"));
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/lsa-min-arrival
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_min_arrival_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf->min_ls_arrival =
			yang_dnode_get_uint32(args->dnode, NULL);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_min_arrival_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf->min_ls_arrival = yang_get_default_uint32(
			FRR_OSPFD_OSPF_XPATH "/timers/lsa-min-arrival");
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/throttle/lsa-all
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_timers_throttle_lsa_all_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf->min_ls_interval =
			yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_timers_throttle_lsa_all_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		ospf->min_ls_interval = yang_get_default_uint16(
			FRR_OSPFD_OSPF_XPATH "/timers/throttle/lsa-all");
		break;
	}

	return NB_OK;
}

static void routing_control_plane_protocols_control_plane_protocol_ospf_timers_throttle_spf_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct ospf *ospf;

	ospf = routing_ospf_get(args->dnode);
	routing_ospf_timers_spf_update(
		ospf,
		routing_ospf_get_uint32_default(
			args->dnode, "delay",
			FRR_OSPFD_OSPF_XPATH
			"/timers/throttle/spf/delay"),
		routing_ospf_get_uint32_default(
			args->dnode, "initial-holdtime",
			FRR_OSPFD_OSPF_XPATH
			"/timers/throttle/spf/initial-holdtime"),
		routing_ospf_get_uint32_default(
			args->dnode, "max-holdtime",
			FRR_OSPFD_OSPF_XPATH
			"/timers/throttle/spf/max-holdtime"));
}

static void routing_ospf_sr_blocks_get(const struct lyd_node *dnode,
				       uint32_t *gb_lower, uint32_t *gb_upper,
				       uint32_t *lb_lower, uint32_t *lb_upper)
{
	const struct lyd_node *sr_dnode;

	sr_dnode = yang_dnode_get_parent(dnode, "segment-routing");

	*gb_lower = routing_ospf_get_uint32_default(
		sr_dnode, "global-block/lower-bound",
		FRR_OSPFD_OSPF_XPATH "/segment-routing/global-block/lower-bound");
	*gb_upper = routing_ospf_get_uint32_default(
		sr_dnode, "global-block/upper-bound",
		FRR_OSPFD_OSPF_XPATH "/segment-routing/global-block/upper-bound");
	*lb_lower = routing_ospf_get_uint32_default(
		sr_dnode, "srlb/lower-bound",
		FRR_OSPFD_OSPF_XPATH "/segment-routing/srlb/lower-bound");
	*lb_upper = routing_ospf_get_uint32_default(
		sr_dnode, "srlb/upper-bound",
		FRR_OSPFD_OSPF_XPATH "/segment-routing/srlb/upper-bound");
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_pre_validate(struct nb_cb_pre_validate_args *args)
{
	uint32_t gb_lower, gb_upper;
	uint32_t lb_lower, lb_upper;

	routing_ospf_sr_blocks_get(args->dnode, &gb_lower, &gb_upper,
				   &lb_lower, &lb_upper);
	if (ospf_sr_blocks_validate(gb_lower, gb_upper, lb_lower, lb_upper,
				    args->errmsg, args->errmsg_len) < 0)
		return NB_ERR_VALIDATION;

	return NB_OK;
}

static void routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_apply_finish(struct nb_cb_apply_finish_args *args)
{
	uint32_t gb_lower, gb_upper;
	uint32_t lb_lower, lb_upper;
	char errmsg[128];

	routing_ospf_sr_blocks_get(args->dnode, &gb_lower, &gb_upper,
				   &lb_lower, &lb_upper);
	if (ospf_sr_blocks_set(gb_lower, gb_upper, lb_lower, lb_upper,
			       errmsg, sizeof(errmsg)) < 0)
		zlog_warn("%s", errmsg);
}

static int routing_ospf_sr_blocks_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}

static int routing_ospf_sr_blocks_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/global-block/lower-bound
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_global_block_lower_bound_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_sr_blocks_modify(args);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/global-block/upper-bound
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_global_block_upper_bound_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_sr_blocks_modify(args);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/srlb/lower-bound
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_srlb_lower_bound_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_sr_blocks_modify(args);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/srlb/upper-bound
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_srlb_upper_bound_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_sr_blocks_modify(args);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/node-msd
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_node_msd_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf_sr_node_msd_set(yang_dnode_get_uint8(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_node_msd_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf_sr_node_msd_unset();
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/on
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_on_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;
	bool enabled;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ospf = routing_ospf_get(args->dnode);
		enabled = yang_dnode_get_bool(args->dnode, NULL);
		if (enabled && ospf->vrf_id != VRF_DEFAULT) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Segment Routing is only supported in default VRF");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		if (ospf_sr_enabled_set(ospf,
					yang_dnode_get_bool(args->dnode, NULL)) < 0)
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_on_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		if (ospf_sr_enabled_set(
			    ospf, yang_get_default_bool(FRR_OSPFD_OSPF_XPATH
							"/segment-routing/on")) < 0)
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

static const struct lyd_node *
routing_ospf_sr_prefix_sid_dnode(const struct lyd_node *dnode)
{
	return yang_dnode_get_parent(dnode, "prefix-sid");
}

static uint8_t routing_ospf_sr_prefix_sid_flags(const struct lyd_node *dnode)
{
	int value;

	if (yang_dnode_exists(dnode, "last-hop-behavior"))
		value = yang_dnode_get_enum(dnode, "last-hop-behavior");
	else
		value = yang_get_default_enum(
			FRR_OSPFD_OSPF_XPATH
			"/segment-routing/prefix-sid/last-hop-behavior");

	switch (value) {
	case 0:
		return EXT_SUBTLV_PREFIX_SID_NPFLG | EXT_SUBTLV_PREFIX_SID_EFLG;
	case 1:
		return EXT_SUBTLV_PREFIX_SID_NPFLG;
	case 2:
	default:
		return 0;
	}
}

static int routing_ospf_sr_prefix_sid_apply(const struct lyd_node *dnode,
					    struct sr_prefix **srp_out,
					    char *errmsg, size_t errmsg_len)
{
	struct prefix_ipv4 p;
	uint32_t index;
	uint8_t flags;

	yang_dnode_get_ipv4p(&p, dnode, "prefix");
	index = yang_dnode_get_uint16(dnode, "index");
	flags = routing_ospf_sr_prefix_sid_flags(dnode);

	return ospf_sr_prefix_sid_set(&p, index, flags, srp_out, errmsg,
				      errmsg_len);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/prefix-sid
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_create(struct nb_cb_create_args *args)
{
	struct sr_prefix *srp;
	char errmsg[128];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (routing_ospf_sr_prefix_sid_apply(args->dnode, &srp, errmsg,
						     sizeof(errmsg)) < 0) {
			snprintf(args->errmsg, args->errmsg_len, "%s", errmsg);
			return NB_ERR_INCONSISTENCY;
		}
		nb_running_set_entry(args->dnode, srp);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_destroy(struct nb_cb_destroy_args *args)
{
	struct sr_prefix *srp;
	char errmsg[128];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		srp = nb_running_unset_entry(args->dnode);
		if (ospf_sr_prefix_sid_delete(srp, errmsg, sizeof(errmsg)) < 0) {
			snprintf(args->errmsg, args->errmsg_len, "%s", errmsg);
			return NB_ERR_INCONSISTENCY;
		}
		break;
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/prefix-sid/index
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_index_modify(struct nb_cb_modify_args *args)
{
	const struct lyd_node *sid_dnode;
	struct sr_prefix *srp;
	char errmsg[128];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		srp = nb_running_get_entry(args->dnode, NULL, true);
		sid_dnode = routing_ospf_sr_prefix_sid_dnode(args->dnode);
		if (routing_ospf_sr_prefix_sid_apply(sid_dnode, &srp, errmsg,
						     sizeof(errmsg)) < 0) {
			snprintf(args->errmsg, args->errmsg_len, "%s", errmsg);
			return NB_ERR_INCONSISTENCY;
		}
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/prefix-sid/last-hop-behavior
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_last_hop_behavior_modify(struct nb_cb_modify_args *args)
{
	const struct lyd_node *sid_dnode;
	struct sr_prefix *srp;
	char errmsg[128];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		srp = nb_running_get_entry(args->dnode, NULL, true);
		sid_dnode = routing_ospf_sr_prefix_sid_dnode(args->dnode);
		if (routing_ospf_sr_prefix_sid_apply(sid_dnode, &srp, errmsg,
						     sizeof(errmsg)) < 0) {
			snprintf(args->errmsg, args->errmsg_len, "%s", errmsg);
			return NB_ERR_INCONSISTENCY;
		}
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/passive-interface-default
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_passive_interface_default_modify(struct nb_cb_modify_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_passive_interface_default_set(
			ospf, yang_dnode_get_bool(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_passive_interface_default_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_passive_interface_default_set(
			ospf, yang_get_default_bool(FRR_OSPFD_OSPF_XPATH
						    "/passive-interface-default"));
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/neighbor
 */
static const struct lyd_node *
routing_ospf_neighbor_dnode(const struct lyd_node *dnode)
{
	return yang_dnode_get_parent(dnode, "neighbor");
}

static void routing_ospf_neighbor_addr(const struct lyd_node *dnode,
				       struct in_addr *addr)
{
	const struct lyd_node *neighbor_dnode = routing_ospf_neighbor_dnode(dnode);

	yang_dnode_get_ipv4(addr, neighbor_dnode, "ip");
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_create(struct nb_cb_create_args *args)
{
	struct ospf_nbr_nbma *nbr_nbma;
	struct in_addr addr;
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		routing_ospf_neighbor_addr(args->dnode, &addr);
		ospf_nbr_nbma_set(ospf, addr);
		nbr_nbma = ospf_nbr_nbma_lookup(ospf, addr);
		nb_running_set_entry(args->dnode, nbr_nbma);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_nbr_nbma *nbr_nbma;
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		nbr_nbma = nb_running_unset_entry(args->dnode);
		if (nbr_nbma)
			ospf_nbr_nbma_unset(ospf, nbr_nbma->addr);
		break;
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/neighbor/priority
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_priority_modify(struct nb_cb_modify_args *args)
{
	struct ospf_nbr_nbma *nbr_nbma;
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		nbr_nbma = nb_running_get_entry(args->dnode, NULL, true);
		ospf_nbr_nbma_priority_set(
			ospf, nbr_nbma->addr,
			yang_dnode_get_uint8(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/neighbor/poll-interval
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_poll_interval_modify(struct nb_cb_modify_args *args)
{
	struct ospf_nbr_nbma *nbr_nbma;
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		nbr_nbma = nb_running_get_entry(args->dnode, NULL, true);
		ospf_nbr_nbma_poll_interval_set(
			ospf, nbr_nbma->addr,
			yang_dnode_get_uint16(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/network
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_network_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return routing_ospf_network_validate(args->dnode, args->errmsg,
						     args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_network_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_network_unset(args->dnode);
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_network_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_network_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_network_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/network/area
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_network_area_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_create(struct nb_cb_create_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (!area)
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct ospf_area *area;
	struct in_addr area_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		if (routing_ospf_area_id(args->dnode, &area_id) < 0)
			return NB_ERR_INCONSISTENCY;

		area = ospf_area_lookup_by_area_id(ospf, area_id);
		if (area) {
			ospf_area_check_free(ospf, area_id);
			area = ospf_area_lookup_by_area_id(ospf, area_id);
			if (area) {
				snprintf(args->errmsg, args->errmsg_len,
					 "area is still referenced");
				return NB_ERR_INCONSISTENCY;
			}
		}
		break;
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/authentication
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_create(struct nb_cb_create_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (area)
			area->auth_type = OSPF_AUTH_SIMPLE;
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf *ospf;
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		area = routing_ospf_area_get(args->dnode, false);
		if (area) {
			area->auth_type = OSPF_AUTH_NULL;
			ospf_area_check_free(ospf, area->area_id);
		}
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/authentication/message-digest
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_message_digest_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (area)
			area->auth_type = yang_dnode_get_bool(args->dnode, NULL)
						  ? OSPF_AUTH_CRYPTOGRAPHIC
						  : OSPF_AUTH_SIMPLE;
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/default-cost
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_default_cost_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (!area)
			return NB_ERR_INCONSISTENCY;

		area->default_cost = yang_dnode_get_uint32(args->dnode, NULL);
		if (area->external_routing != OSPF_AREA_DEFAULT)
			routing_ospf_area_announce_default(area);
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/export-list
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_export_list_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (area)
			ospf_area_export_list_set(
				area->ospf, area,
				yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_export_list_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, false);
		if (area)
			ospf_area_export_list_unset(area->ospf, area);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/import-list
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_import_list_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (area)
			ospf_area_import_list_set(
				area->ospf, area,
				yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_import_list_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, false);
		if (area)
			ospf_area_import_list_unset(area->ospf, area);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/filter-list/in
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_in_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (area)
			routing_ospf_area_filter_set(
				area->ospf, area, true,
				yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_in_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, false);
		if (area)
			routing_ospf_area_filter_unset(area->ospf, area, true);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/filter-list/out
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_out_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (area)
			routing_ospf_area_filter_set(
				area->ospf, area, false,
				yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_out_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, false);
		if (area)
			routing_ospf_area_filter_unset(area->ospf, area, false);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/flood-reduction
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_flood_reduction_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (area)
			routing_ospf_area_flood_reduction_set(
				area->ospf, area,
				yang_dnode_get_bool(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_create(struct nb_cb_create_args *args)
{
	struct ospf_area *area;
	struct in_addr area_id;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		area = routing_ospf_area_lookup(args->dnode);
		if (area && ospf_vl_count(area->ospf, area)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "area cannot be nssa as it contains a virtual link");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (!area)
			return NB_ERR_INCONSISTENCY;

		if (routing_ospf_area_id(args->dnode, &area_id) < 0)
			return NB_ERR_INCONSISTENCY;

		ret = ospf_area_nssa_set(area->ospf, area_id);
		if (!ret)
			return NB_ERR_INCONSISTENCY;
		ospf_flush_lsa_from_area(area->ospf, area_id,
					 OSPF_AS_EXTERNAL_LSA);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_area *area;
	struct in_addr area_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, false);
		if (!area)
			return NB_OK;
		if (routing_ospf_area_id(args->dnode, &area_id) < 0)
			return NB_ERR_INCONSISTENCY;

		ospf_flush_lsa_from_area(area->ospf, area_id,
					 OSPF_AS_NSSA_LSA);
		ospf_area_no_summary_unset(area->ospf, area_id);
		ospf_area_nssa_default_originate_unset(area->ospf, area_id);
		ospf_area_nssa_suppress_fa_unset(area->ospf, area_id);
		ospf_area_nssa_unset(area->ospf, area_id);
		ospf_schedule_abr_task(area->ospf);
		break;
	}

	return NB_OK;
}

static void routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct ospf_area *area;

	area = routing_ospf_area_get(args->dnode, false);
	if (!area)
		return;

	ospf_schedule_abr_task(area->ospf);
	ospf_schedule_asbr_redist_update(area->ospf);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/no-summary
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_no_summary_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;
	struct in_addr area_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (!area)
			return NB_ERR_INCONSISTENCY;
		if (routing_ospf_area_id(args->dnode, &area_id) < 0)
			return NB_ERR_INCONSISTENCY;

		if (yang_dnode_get_bool(args->dnode, NULL))
			ospf_area_nssa_no_summary_set(area->ospf, area_id);
		else
			ospf_area_no_summary_unset(area->ospf, area_id);
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/translate
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_translate_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;
	struct in_addr area_id;
	int role;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (!area)
			return NB_ERR_INCONSISTENCY;
		if (routing_ospf_area_id(args->dnode, &area_id) < 0)
			return NB_ERR_INCONSISTENCY;

		switch (yang_dnode_get_enum(args->dnode, NULL)) {
		case 1:
			role = OSPF_NSSA_ROLE_ALWAYS;
			break;
		case 2:
			role = OSPF_NSSA_ROLE_NEVER;
			break;
		default:
			role = OSPF_NSSA_ROLE_CANDIDATE;
			break;
		}
		ospf_area_nssa_translator_role_set(area->ospf, area_id, role);
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/suppress-fa
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_suppress_fa_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;
	struct in_addr area_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (!area)
			return NB_ERR_INCONSISTENCY;
		if (routing_ospf_area_id(args->dnode, &area_id) < 0)
			return NB_ERR_INCONSISTENCY;

		if (yang_dnode_get_bool(args->dnode, NULL))
			ospf_area_nssa_suppress_fa_set(area->ospf, area_id);
		else
			ospf_area_nssa_suppress_fa_unset(area->ospf, area_id);
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/default-information-originate
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_create(struct nb_cb_create_args *args)
{
	return routing_ospf_create_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_area *area;
	struct in_addr area_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, false);
		if (!area)
			return NB_OK;
		if (routing_ospf_area_id(args->dnode, &area_id) < 0)
			return NB_ERR_INCONSISTENCY;

		ospf_area_nssa_default_originate_unset(area->ospf, area_id);
		break;
	}

	return NB_OK;
}

static void
routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct ospf_area *area;
	struct in_addr area_id;

	area = routing_ospf_area_get(args->dnode, true);
	if (!area)
		return;
	if (routing_ospf_area_id(args->dnode, &area_id) < 0)
		return;

	ospf_area_nssa_default_originate_set(
		area->ospf, area_id, routing_ospf_area_nssa_metric(args->dnode),
		routing_ospf_area_nssa_metric_type(args->dnode));
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/default-information-originate/metric
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_metric_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_metric_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/default-information-originate/metric-type
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_metric_type_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_modify_apply_finish(args);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_metric_type_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_destroy_apply_finish(args);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/ranges/range
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_area_range_apply(args->dnode, true);
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_area_range_delete(args->dnode, true);
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/ranges/range/not-advertise
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_not_advertise_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_area_range_option_modify(args, true);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/ranges/range/cost
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_cost_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_area_range_option_modify(args, true);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_cost_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_area_range_cost_destroy(args, true);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_area_range_apply(args->dnode, false);
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_area_range_delete(args->dnode, false);
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/advertise
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_advertise_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_area_range_option_modify(args, false);
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/cost
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_cost_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_area_range_option_modify(args, false);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_cost_destroy(struct nb_cb_destroy_args *args)
{
	return routing_ospf_area_range_cost_destroy(args, false);
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/substitute
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_substitute_modify(struct nb_cb_modify_args *args)
{
	return routing_ospf_area_range_option_modify(args, false);
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_substitute_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_area *area;
	struct prefix_ipv4 p;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, false);
		if (!area)
			return NB_OK;
		if (!routing_ospf_area_range_prefix(args->dnode, &p))
			return NB_ERR_INCONSISTENCY;

		ospf_area_range_substitute_unset(area->ospf, area, &p);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/stub
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_stub_create(struct nb_cb_create_args *args)
{
	struct ospf_area *area;
	struct in_addr area_id;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		area = routing_ospf_area_lookup(args->dnode);
		if (area && ospf_vl_count(area->ospf, area)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "area cannot be stub as it contains a virtual link");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (!area)
			return NB_ERR_INCONSISTENCY;
		if (routing_ospf_area_id(args->dnode, &area_id) < 0)
			return NB_ERR_INCONSISTENCY;

		ret = ospf_area_stub_set(area->ospf, area_id);
		if (!ret)
			return NB_ERR_INCONSISTENCY;

		ospf_flush_lsa_from_area(area->ospf, area_id,
					 OSPF_AS_EXTERNAL_LSA);
		ospf_area_no_summary_unset(area->ospf, area_id);
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_stub_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_area *area;
	struct in_addr area_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, false);
		if (!area)
			return NB_OK;
		if (routing_ospf_area_id(args->dnode, &area_id) < 0)
			return NB_ERR_INCONSISTENCY;

		ospf_area_stub_unset(area->ospf, area_id);
		ospf_area_no_summary_unset(area->ospf, area_id);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/stub/no-summary
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_stub_no_summary_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;
	struct in_addr area_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (!area)
			return NB_ERR_INCONSISTENCY;
		if (routing_ospf_area_id(args->dnode, &area_id) < 0)
			return NB_ERR_INCONSISTENCY;

		if (yang_dnode_get_bool(args->dnode, NULL))
			ospf_area_no_summary_set(area->ospf, area_id);
		else
			ospf_area_no_summary_unset(area->ospf, area_id);
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/shortcut/mode
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_shortcut_mode_modify(struct nb_cb_modify_args *args)
{
	struct ospf_area *area;
	int mode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		area = routing_ospf_area_get(args->dnode, true);
		if (!area)
			return NB_ERR_INCONSISTENCY;

		mode = yang_dnode_get_enum(args->dnode, NULL);
		if (mode == OSPF_SHORTCUT_DEFAULT)
			ospf_area_shortcut_unset(area->ospf, area);
		else
			ospf_area_shortcut_set(area->ospf, area, mode);
		break;
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return routing_ospf_area_virtual_link_validate(
			args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (!routing_ospf_area_virtual_link_get(args->dnode, true,
							args->errmsg,
							args->errmsg_len))
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_vl_data *vl_data;
	struct ospf_area *area;
	struct in_addr peer;
	struct ospf *ospf;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ospf = routing_ospf_get(args->dnode);
		area = routing_ospf_area_get(args->dnode, false);
		if (!area)
			return NB_OK;

		if (!routing_ospf_area_virtual_link_peer(args->dnode, &peer))
			return NB_ERR_INCONSISTENCY;

		vl_data = ospf_vl_lookup(ospf, area, peer);
		if (vl_data) {
			ospf_vl_delete(ospf, vl_data);
			ospf_area_check_free(ospf, area->area_id);
		}
		break;
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/authentication-mode
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_authentication_mode_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;
	int mode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = routing_ospf_area_virtual_link_params(
			args->dnode, args->errmsg, args->errmsg_len);
		if (!params)
			return NB_ERR_INCONSISTENCY;

		mode = lib_interface_ospf_auth_mode_from_dnode(args->dnode);
		if (mode == OSPF_AUTH_NOTSET)
			return NB_ERR_INCONSISTENCY;

		lib_interface_ospf_auth_mode_set(params, mode);
		if (yang_dnode_get_enum(args->dnode, NULL) != 3) {
			lib_interface_ospf_key_chain_unset(params);
		}
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_authentication_mode_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = routing_ospf_area_virtual_link_params(
			args->dnode, args->errmsg, args->errmsg_len);
		if (!params)
			return NB_OK;

		lib_interface_ospf_auth_mode_unset(params);
		lib_interface_ospf_key_chain_unset(params);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/authentication-key
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_authentication_key_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = routing_ospf_area_virtual_link_params(
			args->dnode, args->errmsg, args->errmsg_len);
		if (!params)
			return NB_ERR_INCONSISTENCY;

		lib_interface_ospf_auth_simple_set(
			params, yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_authentication_key_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = routing_ospf_area_virtual_link_params(
			args->dnode, args->errmsg, args->errmsg_len);
		if (!params)
			return NB_OK;

		lib_interface_ospf_auth_simple_unset(params);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/message-digest-key
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_area_virtual_link_md5_key_set(
			args->dnode, args->errmsg, args->errmsg_len);
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_area_virtual_link_md5_key_delete(
			args->dnode, args->errmsg, args->errmsg_len);
	}

	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_get_next(struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_get_keys(struct nb_cb_get_keys_args *args)
{
	/* TODO: implement me. */
	return NB_OK;
}

static const void *routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/message-digest-key/md5-key
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_md5_key_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return routing_ospf_area_virtual_link_md5_key_set(
			args->dnode, args->errmsg, args->errmsg_len);
	}

	return NB_OK;
}


/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/key-chain
 */
static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_key_chain_modify(struct nb_cb_modify_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = routing_ospf_area_virtual_link_params(
			args->dnode, args->errmsg, args->errmsg_len);
		if (!params)
			return NB_ERR_INCONSISTENCY;

		lib_interface_ospf_key_chain_set(
			params, yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}


static int routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_key_chain_destroy(struct nb_cb_destroy_args *args)
{
	struct ospf_if_params *params;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		params = routing_ospf_area_virtual_link_params(
			args->dnode, args->errmsg, args->errmsg_len);
		if (!params)
			return NB_OK;

		lib_interface_ospf_key_chain_unset(params);
		if (params->auth_type == OSPF_AUTH_CRYPTOGRAPHIC) {
			lib_interface_ospf_auth_mode_unset(params);
		}
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/timers
 */
static void routing_ospf_vlink_timer_read(const struct lyd_node *dnode,
					  const char *name, uint32_t *value,
					  bool *configured)
{
	struct lyd_node *leaf;

	leaf = yang_dnode_get(dnode, name);
	*configured = leaf && !lyd_is_default(leaf);
	if (leaf)
		*value = yang_dnode_get_uint16(leaf, NULL);
	else
		*value = yang_get_default_uint16(
			FRR_OSPFD_AREA_VLINK_TIMERS_XPATH "/%s", name);
}

#define ROUTING_OSPF_VLINK_PARAM_CHANGED(PARAMS, FIELD, VALUE, CONFIGURED)    \
	(OSPF_IF_PARAM_CONFIGURED((PARAMS), FIELD) != (CONFIGURED) ||         \
	 (PARAMS)->FIELD != (VALUE))

static void
routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_timers_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct ospf_if_params *params;
	struct in_addr addr = { .s_addr = 0L };
	struct interface *ifp;
	char errmsg[256];
	bool configured;
	bool nbr_timer_update = false;
	bool hello_update = false;
	uint32_t value;

	ifp = routing_ospf_area_virtual_link_ifp(args->dnode, errmsg,
						sizeof(errmsg));
	if (!ifp || !lib_interface_ospf_ensure_if_info(ifp))
		return;

	params = IF_DEF_PARAMS(ifp);

	routing_ospf_vlink_timer_read(args->dnode, "dead-interval", &value,
				      &configured);
	if (ROUTING_OSPF_VLINK_PARAM_CHANGED(params, v_wait, value,
					     configured)) {
		lib_interface_ospf_set_dead_interval(params, value,
						     configured);
		nbr_timer_update = true;
	}

	routing_ospf_vlink_timer_read(args->dnode, "hello-interval", &value,
				      &configured);
	if (ROUTING_OSPF_VLINK_PARAM_CHANGED(params, v_hello, value,
					     configured)) {
		lib_interface_ospf_set_hello_interval(params, value,
						      configured);
		hello_update = true;
	}

	routing_ospf_vlink_timer_read(args->dnode, "retransmit-interval",
				      &value, &configured);
	if (ROUTING_OSPF_VLINK_PARAM_CHANGED(params, retransmit_interval,
					     value, configured)) {
		lib_interface_ospf_set_retransmit_interval(params, value,
							   configured);
		nbr_timer_update = true;
	}

	routing_ospf_vlink_timer_read(args->dnode, "retransmit-window",
				      &value, &configured);
	if (ROUTING_OSPF_VLINK_PARAM_CHANGED(params, retransmit_window, value,
					     configured))
		lib_interface_ospf_set_retransmit_window(params, value,
							 configured);

	routing_ospf_vlink_timer_read(args->dnode, "transmit-delay", &value,
				      &configured);
	if (ROUTING_OSPF_VLINK_PARAM_CHANGED(params, transmit_delay, value,
					     configured))
		lib_interface_ospf_set_transmit_delay(params, value,
						      configured);

	if (nbr_timer_update)
		lib_interface_ospf_nbr_timer_update(ifp);
	if (hello_update)
		ospf_reset_hello_timer(ifp, addr, false);
}

#undef ROUTING_OSPF_VLINK_PARAM_CHANGED

/* clang-format off */
const struct frr_yang_module_info frr_ospfd_nb_info = {
	.name = "frr-ospfd",
	.nodes = {
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf",
			.cbs = {
				.apply_finish = lib_interface_ospf_apply_finish,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/dscp/all",
			.cbs = {
				.modify = lib_interface_ospf_dscp_all_modify,
				.destroy = lib_interface_ospf_dscp_all_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/dscp/low-control",
			.cbs = {
				.modify = lib_interface_ospf_dscp_low_control_modify,
				.destroy = lib_interface_ospf_dscp_low_control_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/dead-timer-reset-any-control",
			.cbs = {
				.modify = lib_interface_ospf_dead_timer_reset_any_control_modify,
				.destroy = lib_interface_ospf_dead_timer_reset_any_control_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/bfd",
			.cbs = {
				.create = lib_interface_ospf_bfd_create,
				.destroy = lib_interface_ospf_bfd_destroy,
				.apply_finish = lib_interface_ospf_bfd_apply_finish,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/bfd/profile",
			.cbs = {
				.modify = lib_interface_ospf_bfd_profile_modify,
				.destroy = lib_interface_ospf_bfd_profile_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/bfd/detection-multiplier",
			.cbs = {
				.modify = lib_interface_ospf_bfd_detection_multiplier_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/bfd/required-min-rx-interval",
			.cbs = {
				.modify = lib_interface_ospf_bfd_required_min_rx_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/bfd/desired-min-tx-interval",
			.cbs = {
				.modify = lib_interface_ospf_bfd_desired_min_tx_interval_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/bfd/quick",
			.cbs = {
				.modify = lib_interface_ospf_bfd_quick_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/ldp-sync/mode",
			.cbs = {
				.modify = lib_interface_ospf_ldp_sync_mode_modify,
				.destroy = lib_interface_ospf_ldp_sync_mode_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/ldp-sync/holddown",
			.cbs = {
				.modify = lib_interface_ospf_ldp_sync_holddown_modify,
				.destroy = lib_interface_ospf_ldp_sync_holddown_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-type",
			.cbs = {
				.modify = lib_interface_ospf_interface_type_modify,
				.destroy = lib_interface_ospf_interface_type_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/point-to-point-dmvpn",
			.cbs = {
				.modify = lib_interface_ospf_point_to_point_dmvpn_modify,
				.destroy = lib_interface_ospf_point_to_point_dmvpn_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/point-to-multipoint-delay-reflood",
			.cbs = {
				.modify = lib_interface_ospf_point_to_multipoint_delay_reflood_modify,
				.destroy = lib_interface_ospf_point_to_multipoint_delay_reflood_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/point-to-multipoint-non-broadcast",
			.cbs = {
				.modify = lib_interface_ospf_point_to_multipoint_non_broadcast_modify,
				.destroy = lib_interface_ospf_point_to_multipoint_non_broadcast_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/authentication-mode",
			.cbs = {
				.modify = lib_interface_ospf_authentication_mode_modify,
				.destroy = lib_interface_ospf_authentication_mode_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/authentication-key",
			.cbs = {
				.modify = lib_interface_ospf_authentication_key_modify,
				.destroy = lib_interface_ospf_authentication_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/message-digest-key",
			.cbs = {
				.create = lib_interface_ospf_message_digest_key_create,
				.destroy = lib_interface_ospf_message_digest_key_destroy,
				.get_next = lib_interface_ospf_message_digest_key_get_next,
				.get_keys = lib_interface_ospf_message_digest_key_get_keys,
				.lookup_entry = lib_interface_ospf_message_digest_key_lookup_entry,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/message-digest-key/md5-key",
			.cbs = {
				.modify = lib_interface_ospf_message_digest_key_md5_key_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/key-chain",
			.cbs = {
				.modify = lib_interface_ospf_key_chain_modify,
				.destroy = lib_interface_ospf_key_chain_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/cost",
			.cbs = {
				.modify = lib_interface_ospf_cost_modify,
				.destroy = lib_interface_ospf_cost_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/dead-interval/interval",
			.cbs = {
				.modify = lib_interface_ospf_dead_interval_interval_modify,
				.destroy = lib_interface_ospf_dead_interval_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/dead-interval/minimal",
			.cbs = {
				.create = lib_interface_ospf_dead_interval_minimal_create,
				.destroy = lib_interface_ospf_dead_interval_minimal_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/dead-interval/minimal/hello-multiplier",
			.cbs = {
				.modify = lib_interface_ospf_dead_interval_minimal_hello_multiplier_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/hello-interval",
			.cbs = {
				.modify = lib_interface_ospf_hello_interval_modify,
				.destroy = lib_interface_ospf_hello_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/retransmit-interval",
			.cbs = {
				.modify = lib_interface_ospf_retransmit_interval_modify,
				.destroy = lib_interface_ospf_retransmit_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/retransmit-window",
			.cbs = {
				.modify = lib_interface_ospf_retransmit_window_modify,
				.destroy = lib_interface_ospf_retransmit_window_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/transmit-delay",
			.cbs = {
				.modify = lib_interface_ospf_transmit_delay_modify,
				.destroy = lib_interface_ospf_transmit_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/mtu-ignore",
			.cbs = {
				.modify = lib_interface_ospf_mtu_ignore_modify,
				.destroy = lib_interface_ospf_mtu_ignore_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/priority",
			.cbs = {
				.modify = lib_interface_ospf_priority_modify,
				.destroy = lib_interface_ospf_priority_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/passive",
			.cbs = {
				.modify = lib_interface_ospf_passive_modify,
				.destroy = lib_interface_ospf_passive_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/prefix-suppression",
			.cbs = {
				.modify = lib_interface_ospf_prefix_suppression_modify,
				.destroy = lib_interface_ospf_prefix_suppression_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/capability-opaque",
			.cbs = {
				.modify = lib_interface_ospf_capability_opaque_modify,
				.destroy = lib_interface_ospf_capability_opaque_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/neighbor-filter",
			.cbs = {
				.modify = lib_interface_ospf_neighbor_filter_modify,
				.destroy = lib_interface_ospf_neighbor_filter_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/graceful-restart/hello-delay",
			.cbs = {
				.modify = lib_interface_ospf_graceful_restart_hello_delay_modify,
				.destroy = lib_interface_ospf_graceful_restart_hello_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/attachment",
			.cbs = {
				.create = lib_interface_ospf_attachment_create,
				.destroy = lib_interface_ospf_attachment_destroy,
				.get_next = lib_interface_ospf_attachment_get_next,
				.get_keys = lib_interface_ospf_attachment_get_keys,
				.lookup_entry = lib_interface_ospf_attachment_lookup_entry,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address",
			.cbs = {
				.create = lib_interface_ospf_interface_address_create,
				.destroy = lib_interface_ospf_interface_address_destroy,
				.apply_finish = lib_interface_ospf_address_timers_apply_finish,
				.get_next = lib_interface_ospf_interface_address_get_next,
				.get_keys = lib_interface_ospf_interface_address_get_keys,
				.lookup_entry = lib_interface_ospf_interface_address_lookup_entry,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/area",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_area_modify,
				.destroy = lib_interface_ospf_interface_address_area_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/authentication-mode",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_authentication_mode_modify,
				.destroy = lib_interface_ospf_interface_address_authentication_mode_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/authentication-key",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_authentication_key_modify,
				.destroy = lib_interface_ospf_interface_address_authentication_key_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/message-digest-key",
			.cbs = {
				.create = lib_interface_ospf_interface_address_message_digest_key_create,
				.destroy = lib_interface_ospf_interface_address_message_digest_key_destroy,
				.get_next = lib_interface_ospf_interface_address_message_digest_key_get_next,
				.get_keys = lib_interface_ospf_interface_address_message_digest_key_get_keys,
				.lookup_entry = lib_interface_ospf_interface_address_message_digest_key_lookup_entry,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/message-digest-key/md5-key",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_message_digest_key_md5_key_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/key-chain",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_key_chain_modify,
				.destroy = lib_interface_ospf_interface_address_key_chain_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/cost",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_cost_modify,
				.destroy = lib_interface_ospf_interface_address_cost_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dead-interval/interval",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_dead_interval_interval_modify,
				.destroy = lib_interface_ospf_interface_address_dead_interval_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dead-interval/minimal",
			.cbs = {
				.create = lib_interface_ospf_interface_address_dead_interval_minimal_create,
				.destroy = lib_interface_ospf_interface_address_dead_interval_minimal_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/dead-interval/minimal/hello-multiplier",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_dead_interval_minimal_hello_multiplier_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/hello-interval",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_hello_interval_modify,
				.destroy = lib_interface_ospf_interface_address_hello_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/retransmit-interval",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_retransmit_interval_modify,
				.destroy = lib_interface_ospf_interface_address_retransmit_interval_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/retransmit-window",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_retransmit_window_modify,
				.destroy = lib_interface_ospf_interface_address_retransmit_window_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/transmit-delay",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_transmit_delay_modify,
				.destroy = lib_interface_ospf_interface_address_transmit_delay_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/mtu-ignore",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_mtu_ignore_modify,
				.destroy = lib_interface_ospf_interface_address_mtu_ignore_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/priority",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_priority_modify,
				.destroy = lib_interface_ospf_interface_address_priority_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/passive",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_passive_modify,
				.destroy = lib_interface_ospf_interface_address_passive_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/prefix-suppression",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_prefix_suppression_modify,
				.destroy = lib_interface_ospf_interface_address_prefix_suppression_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/capability-opaque",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_capability_opaque_modify,
				.destroy = lib_interface_ospf_interface_address_capability_opaque_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/neighbor-filter",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_neighbor_filter_modify,
				.destroy = lib_interface_ospf_interface_address_neighbor_filter_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ospfd:ospf/interface-address/graceful-restart/hello-delay",
			.cbs = {
				.modify = lib_interface_ospf_interface_address_graceful_restart_hello_delay_modify,
				.destroy = lib_interface_ospf_interface_address_graceful_restart_hello_delay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-id",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_id_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_id_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/instance",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_instance_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_instance_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/abr-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_abr_type_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_abr_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/auto-cost-reference-bandwidth",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_auto_cost_reference_bandwidth_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_auto_cost_reference_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/proactive-arp",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_proactive_arp_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_proactive_arp_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/opaque-capability",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_opaque_capability_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_opaque_capability_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/shutdown",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_shutdown_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_shutdown_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/forwarding-address-self",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_forwarding_address_self_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_forwarding_address_self_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/compatible-rfc1583",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_compatible_rfc1583_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_compatible_rfc1583_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-metric",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_default_metric_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_default_metric_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/write-multiplier",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_write_multiplier_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_write_multiplier_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/maximum-paths",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_maximum_paths_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_maximum_paths_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/flood-reduction",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_flood_reduction_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_flood_reduction_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/send-extra-data",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_send_extra_data_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_send_extra_data_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/log-adjacency-changes",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/log-adjacency-changes/detail",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_detail_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_log_adjacency_changes_detail_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/socket",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_socket_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/socket/send-buffer",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/socket/receive-buffer",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/socket/per-interface",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_socket_per_interface_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_socket_per_interface_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/scope",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_scope_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_scope_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/address",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_address_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_address_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/scope",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_scope_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/domain-as",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_domain_as_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_domain_as_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_domain_as_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_domain_as_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_domain_as_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/neighbor-as",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_neighbor_as_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_neighbor_as_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_neighbor_as_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_neighbor_as_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_neighbor_as_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/router-info/pce/flag",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_flag_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_router_info_pce_flag_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/enabled",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_enabled_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/grace-period",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_grace_period_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_grace_period_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper/enabled",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper/enabled-for-router",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enabled_for_router_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enabled_for_router_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enabled_for_router_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enabled_for_router_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_graceful_restart_helper_enabled_for_router_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper/strict-lsa-checking",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper/supported-grace-time",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/graceful-restart/helper/planned-only",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/ldp-sync/enabled",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_ldp_sync_enabled_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_ldp_sync_enabled_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/ldp-sync/holddown",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_ldp_sync_holddown_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_ldp_sync_holddown_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/fast-reroute/ti-lfa",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/fast-reroute/ti-lfa/enable",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_enable_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_enable_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/fast-reroute/ti-lfa/node-protection",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_node_protection_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_fast_reroute_ti_lfa_node_protection_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/summary-address",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_apply_finish,
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/summary-address/tag",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_tag_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_tag_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/summary-address/no-advertise",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_summary_address_no_advertise_modify,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/aggregation-timer",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_aggregation_timer_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_aggregation_timer_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information-originate",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_apply_finish,
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information-originate/always",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_always_modify,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information-originate/metric",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_metric_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_metric_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information-originate/metric-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_metric_type_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_metric_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/default-information-originate/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_default_information_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_apply_finish,
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/metric",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_metric_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_metric_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/metric-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_metric_type_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_metric_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/redistribute/route-map",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_route_map_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_redistribute_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distance/admin-value",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_distance_admin_value_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_distance_admin_value_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distance/ospf/external",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_external_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_external_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distance/ospf/inter-area",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_inter_area_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_inter_area_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distance/ospf/intra-area",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_intra_area_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_distance_ospf_intra_area_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/distribute-list/dlist",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_distribute_list_dlist_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_distribute_list_dlist_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_distribute_list_dlist_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_distribute_list_dlist_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_distribute_list_dlist_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/administrative",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_administrative_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_administrative_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/on-shutdown",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_shutdown_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_shutdown_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/max-metric/router-lsa/on-startup",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_startup_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_max_metric_router_lsa_on_startup_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls-te/on",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_on_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls-te/router-address",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_router_address_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_router_address_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls-te/export",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_export_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls-te/inter-as/as",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_as_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_as_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/mpls-te/inter-as/area",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_area_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_mpls_te_inter_as_area_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/refresh-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_timers_refresh_interval_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_timers_refresh_interval_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/lsa-refresh-time",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_refresh_time_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_refresh_time_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/maxage-delay",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_timers_maxage_delay_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_timers_maxage_delay_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/lsa-min-arrival",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_min_arrival_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_timers_lsa_min_arrival_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/throttle/lsa-all",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_timers_throttle_lsa_all_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_timers_throttle_lsa_all_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/throttle/spf",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_timers_throttle_spf_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/throttle/spf/delay",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/throttle/spf/initial-holdtime",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/timers/throttle/spf/max-holdtime",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing",
			.cbs = {
				.pre_validate = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_pre_validate,
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/global-block/lower-bound",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_global_block_lower_bound_modify,
				.destroy = routing_ospf_sr_blocks_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/global-block/upper-bound",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_global_block_upper_bound_modify,
				.destroy = routing_ospf_sr_blocks_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/srlb/lower-bound",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_srlb_lower_bound_modify,
				.destroy = routing_ospf_sr_blocks_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/srlb/upper-bound",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_srlb_upper_bound_modify,
				.destroy = routing_ospf_sr_blocks_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/node-msd",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_node_msd_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_node_msd_destroy,
			}
		},
			{
				.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/on",
				.cbs = {
					.modify = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_on_modify,
					.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_on_destroy,
				}
			},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/prefix-sid",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/prefix-sid/index",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_index_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/segment-routing/prefix-sid/last-hop-behavior",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_segment_routing_prefix_sid_last_hop_behavior_modify,
			}
		},
			{
				.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/passive-interface-default",
				.cbs = {
					.modify = routing_control_plane_protocols_control_plane_protocol_ospf_passive_interface_default_modify,
					.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_passive_interface_default_destroy,
				}
			},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/neighbor",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/neighbor/priority",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_priority_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/neighbor/poll-interval",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_neighbor_poll_interval_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/network",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_network_apply_finish,
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_network_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_network_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_network_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_network_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_network_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/network/area",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_network_area_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/authentication",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/authentication/message-digest",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_authentication_message_digest_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/default-cost",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_default_cost_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/export-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_export_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_export_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/import-list",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_import_list_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_import_list_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/filter-list/in",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_in_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/filter-list/out",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_out_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/flood-reduction",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_flood_reduction_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_destroy,
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/no-summary",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_no_summary_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/translate",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_translate_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/suppress-fa",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_suppress_fa_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/default-information-originate",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_apply_finish,
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/default-information-originate/metric",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_metric_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_metric_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/default-information-originate/metric-type",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_metric_type_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_default_information_originate_metric_type_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/ranges/range",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/ranges/range/not-advertise",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_not_advertise_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/nssa/ranges/range/cost",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_cost_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_nssa_ranges_range_cost_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/advertise",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_advertise_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/cost",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_cost_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_cost_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/ranges/range/substitute",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_substitute_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_ranges_range_substitute_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/stub",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_stub_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_stub_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/stub/no-summary",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_stub_no_summary_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/shortcut/mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_shortcut_mode_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/authentication-mode",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_authentication_mode_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_authentication_mode_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/authentication-key",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_authentication_key_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_authentication_key_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/message-digest-key",
			.cbs = {
				.create = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_create,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_destroy,
				.get_next = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_get_next,
				.get_keys = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_get_keys,
				.lookup_entry = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_lookup_entry,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/message-digest-key/md5-key",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_message_digest_key_md5_key_modify,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/key-chain",
			.cbs = {
				.modify = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_key_chain_modify,
				.destroy = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_key_chain_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/timers",
			.cbs = {
				.apply_finish = routing_control_plane_protocols_control_plane_protocol_ospf_areas_area_virtual_link_timers_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/timers/dead-interval",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/timers/hello-interval",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/timers/retransmit-interval",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/timers/retransmit-window",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-ospfd:ospf/areas/area/virtual-link/timers/transmit-delay",
			.cbs = {
				.modify = routing_ospf_modify_apply_finish,
				.destroy = routing_ospf_destroy_apply_finish,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
