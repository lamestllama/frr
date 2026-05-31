// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv2 northbound notifications (RFC 9129 ietf-ospf).
 * Copyright (C) 2026  Eric Parsonage
 *
 * Wires the existing ospf_nsm_change / ospf_ism_change / GR helper /
 * packet validation hooks to the YANG notification dispatcher so mgmtd
 * (and any frontend subscribed to it) sees an ietf-ospf event each time
 * an OSPFv2 state transitions.
 */

#include <zebra.h>

#include "debug.h"
#include "if.h"
#include "linklist.h"
#include "log.h"
#include "northbound.h"
#include "prefix.h"
#include "table.h"
#include "yang.h"
#include "yang_wrappers.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospf_nb.h"

#define _dbg(fmt, ...) DEBUGD(&nb_dbg_notif, "OSPF-NOTIF: %s: " fmt, __func__, ##__VA_ARGS__)

/*
 * Translate FRR's internal NSM state code into the integer value RFC 9129's
 * `nbr-state-type` enum assigns to the same name.  yang_data_new_enum() takes
 * the YANG-defined numeric value and looks up the corresponding name.
 *
 * FRR reserves 0 / 1 for the DependUpon / Deleted lifecycle codes that have
 * no protocol existence in RFC 2328; both fold into the RFC's `down` state,
 * which the protocol defines as "no recent information received from the
 * neighbor".  Without this fold every adjacency tear-down (KillNbr, dead
 * timer, explicit clear) lands on NSM_Deleted and the hook silently drops
 * the notification, so subscribers never see neighbours go away.
 */
static const int ospfd_ietf_nbr_state_table[OSPF_NSM_STATE_MAX] = {
	[NSM_DependUpon] = 1, /* down */
	[NSM_Deleted] = 1,    /* down */
	[NSM_Down] = 1,       /* down */
	[NSM_Attempt] = 2,    /* attempt */
	[NSM_Init] = 3,       /* init */
	[NSM_TwoWay] = 4,     /* 2-way */
	[NSM_ExStart] = 5,    /* exstart */
	[NSM_Exchange] = 6,   /* exchange */
	[NSM_Loading] = 7,    /* loading */
	[NSM_Full] = 8,       /* full */
};

static int ospfd_ietf_nbr_state_yang(int nsm_state)
{
	int val;

	if (nsm_state < 0 ||
	    (size_t)nsm_state >= array_size(ospfd_ietf_nbr_state_table))
		return -1;

	val = ospfd_ietf_nbr_state_table[nsm_state];
	return val ? val : -1;
}

/*
 * Translate FRR's internal ISM state code into RFC 9129's `if-state-type`
 * enum.  Numeric values agree for Down/Loopback/Waiting/PointToPoint but
 * diverge for the DR-election trio: FRR orders DROther=5, Backup=6, DR=7
 * while the RFC orders dr=5, bdr=6, dr-other=7.
 *
 * FRR reserves 0 for the DependUpon lifecycle code that has no protocol
 * existence; it folds into the RFC's `down` so a tear-down through that
 * state stays observable through if-state-change.
 */
static const int ospfd_ietf_if_state_table[OSPF_ISM_STATE_MAX] = {
	[ISM_DependUpon] = 1,   /* down */
	[ISM_Down] = 1,         /* down */
	[ISM_Loopback] = 2,     /* loopback */
	[ISM_Waiting] = 3,      /* waiting */
	[ISM_PointToPoint] = 4, /* point-to-point */
	[ISM_DR] = 5,           /* dr */
	[ISM_Backup] = 6,       /* bdr */
	[ISM_DROther] = 7,      /* dr-other */
};

static int ospfd_ietf_if_state_yang(int ism_state)
{
	int val;

	if (ism_state < 0 ||
	    (size_t)ism_state >= array_size(ospfd_ietf_if_state_table))
		return -1;

	val = ospfd_ietf_if_state_table[ism_state];
	return val ? val : -1;
}

static void ospfd_ietf_notif_add_instance_hdr(struct list *args, const char *xpath,
					      const struct ospf *ospf)
{
	char xpath_arg[XPATH_MAXLEN];
	char buf[XPATH_MAXLEN];

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/routing-protocol-name", xpath);
	listnode_add(args,
		     yang_data_new_string(xpath_arg,
					  ospfd_ietf_ospf_instance_name(ospf, buf, sizeof(buf))));
}

static void ospfd_ietf_notif_add_interface_hdr(struct list *args, const char *xpath,
					       const struct interface *ifp)
{
	char xpath_arg[XPATH_MAXLEN];

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface/interface", xpath);
	listnode_add(args, yang_data_new_string(xpath_arg, ifp->name));
}

static void ospfd_ietf_notif_add_neighbor_hdr(struct list *args, const char *xpath,
					      const struct ospf_neighbor *nbr)
{
	char xpath_arg[XPATH_MAXLEN];
	char buf[INET_ADDRSTRLEN];

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor-router-id", xpath);
	inet_ntop(AF_INET, &nbr->router_id, buf, sizeof(buf));
	listnode_add(args, yang_data_new_string(xpath_arg, buf));

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/neighbor-ip-addr", xpath);
	inet_ntop(AF_INET, &nbr->src, buf, sizeof(buf));
	listnode_add(args, yang_data_new_string(xpath_arg, buf));
}

/*
 * XPath: /ietf-ospf:nbr-state-change
 *
 * Emitted on every NSM transition.  The OSPF-v2 NSM hook fires after the
 * state has been swapped in, so `nbr->state` is already `next_state` here;
 * the `oldstate` argument is supplied by the hook caller.
 */
static int ospfd_ietf_nbr_state_change(struct ospf_neighbor *nbr, int next_state, int old_state)
{
	const char *xpath = "/ietf-ospf:nbr-state-change";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	int yang_state;

	yang_state = ospfd_ietf_nbr_state_yang(next_state);
	if (yang_state < 0)
		return 0;
	(void)old_state;

	if (!nbr->oi || !nbr->oi->ifp || !nbr->oi->ospf)
		return 0;

	args = yang_data_list_new();
	ospfd_ietf_notif_add_instance_hdr(args, xpath, nbr->oi->ospf);
	ospfd_ietf_notif_add_interface_hdr(args, xpath, nbr->oi->ifp);
	ospfd_ietf_notif_add_neighbor_hdr(args, xpath, nbr);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/state", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, yang_state));

	_dbg("nbr %pI4 on %s -> %s", &nbr->router_id, nbr->oi->ifp->name,
	     lookup_msg(ospf_nsm_state_msg, next_state, NULL));

	nb_notification_send(xpath, args);
	return 0;
}

/*
 * Translate FRR's `ospf_helper_exit_reason` (0..4 enum) into RFC 9129's
 * `restart-exit-reason-type` (1..5 enum).  FRR's enum order differs from
 * the RFC value order: TOPO_CHG=2 maps to topology-changed=5, while
 * COMPLETED=4 maps to completed=3.  A simple offset does not work.
 *
 * The default returns -1 so an unfamiliar reason surfaces as an error the
 * caller can log and suppress.  Folding an unknown reason into `none`
 * would falsely claim "the helper has not exited" when in fact it just
 * exited for a reason this build does not yet know about.
 */
static const int
	ospfd_ietf_helper_exit_reason_table[OSPF_GR_HELPER_COMPLETED + 1] = {
		[OSPF_GR_HELPER_EXIT_NONE] = 1,     /* none */
		[OSPF_GR_HELPER_INPROGRESS] = 2,    /* in-progress */
		[OSPF_GR_HELPER_COMPLETED] = 3,     /* completed */
		[OSPF_GR_HELPER_GRACE_TIMEOUT] = 4, /* timed-out */
		[OSPF_GR_HELPER_TOPO_CHG] = 5,      /* topology-changed */
	};

static int ospfd_ietf_helper_exit_reason_yang(int exit_reason)
{
	int val;

	if (exit_reason < 0 ||
	    (size_t)exit_reason >= array_size(ospfd_ietf_helper_exit_reason_table))
		return -1;

	val = ospfd_ietf_helper_exit_reason_table[exit_reason];
	return val ? val : -1;
}

/*
 * XPath: /ietf-ospf:restart-status-change
 *
 * Emit when the local OSPFv2 instance transitions in or out of graceful-
 * restart mode.  `status` follows RFC 9129's restart-status-type values
 * (1=not-restarting, 2=planned-restart, 3=unplanned-restart).
 * `exit_reason` is in FRR's `enum ospf_helper_exit_reason` space; we
 * translate to the RFC enum.  All FRR-known restart reasons are SW-
 * initiated and map to planned-restart.
 */
void ospfd_ietf_notif_restart_status_change(struct ospf *ospf, int status, int exit_reason)
{
	const char *xpath = "/ietf-ospf:restart-status-change";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	int yang_exit;

	if (!ospf)
		return;

	args = yang_data_list_new();
	ospfd_ietf_notif_add_instance_hdr(args, xpath, ospf);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/status", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, status));

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/restart-interval", xpath);
	listnode_add(args, yang_data_new_uint16(xpath_arg, ospf->gr_info.grace_period));

	yang_exit = ospfd_ietf_helper_exit_reason_yang(exit_reason);
	if (yang_exit < 0) {
		zlog_warn("%s: unrecognised GR exit reason %d, suppressing notification",
			  __func__, exit_reason);
		list_delete(&args);
		return;
	}
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/exit-reason", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, yang_exit));

	_dbg("instance %s gr status %d exit %d", ospf->name ?: VRF_DEFAULT_NAME, status,
	     exit_reason);
	nb_notification_send(xpath, args);
}

/*
 * XPath: /ietf-ospf:nbr-restart-helper-status-change
 *
 * Emit when this router enters or leaves helper mode for a neighbour's
 * graceful restart.  `status` is RFC restart-helper-status-type
 * (1=not-helping, 2=helping).  `age` is the remaining helper time in
 * seconds.  `exit_reason` is FRR's enum ospf_helper_exit_reason.
 */
void ospfd_ietf_notif_nbr_restart_helper_status_change(struct ospf_neighbor *nbr, int status,
						       uint16_t age, int exit_reason)
{
	const char *xpath = "/ietf-ospf:nbr-restart-helper-status-change";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	int yang_exit;

	if (!nbr || !nbr->oi || !nbr->oi->ifp || !nbr->oi->ospf)
		return;

	args = yang_data_list_new();
	ospfd_ietf_notif_add_instance_hdr(args, xpath, nbr->oi->ospf);
	ospfd_ietf_notif_add_interface_hdr(args, xpath, nbr->oi->ifp);
	ospfd_ietf_notif_add_neighbor_hdr(args, xpath, nbr);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/status", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, status));

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/age", xpath);
	listnode_add(args, yang_data_new_uint16(xpath_arg, age));

	yang_exit = ospfd_ietf_helper_exit_reason_yang(exit_reason);
	if (yang_exit < 0) {
		zlog_warn("%s: unrecognised GR helper exit reason %d, suppressing notification",
			  __func__, exit_reason);
		list_delete(&args);
		return;
	}
	snprintf(xpath_arg, sizeof(xpath_arg), "%s/exit-reason", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, yang_exit));

	_dbg("nbr %pI4 helper status %d exit %d", &nbr->router_id, status, exit_reason);
	nb_notification_send(xpath, args);
}

/*
 * XPath: /ietf-ospf:if-state-change
 *
 * Emitted on every ISM transition.  The OSPFv2 ISM hook fires after the
 * state has been swapped in.  The `old_state` argument is not part of the
 * RFC notification so we only consume it to silence the unused-parameter
 * warning -- it is, however, available for future hooks that may want to
 * filter on the transition direction.
 */
static int ospfd_ietf_if_state_change(struct ospf_interface *oi, int state, int old_state)
{
	const char *xpath = "/ietf-ospf:if-state-change";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	int yang_state;

	yang_state = ospfd_ietf_if_state_yang(state);
	if (yang_state < 0)
		return 0;
	(void)old_state;

	if (!oi->ifp || !oi->ospf)
		return 0;

	args = yang_data_list_new();
	ospfd_ietf_notif_add_instance_hdr(args, xpath, oi->ospf);
	ospfd_ietf_notif_add_interface_hdr(args, xpath, oi->ifp);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/state", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, yang_state));

	_dbg("iface %s -> %s", oi->ifp->name, lookup_msg(ospf_ism_state_msg, state, NULL));

	nb_notification_send(xpath, args);
	return 0;
}

/*
 * XPath: /ietf-ospf:if-rx-bad-packet
 *
 * Emit when an OSPFv2 packet cannot be parsed on a given interface.
 * Caller supplies the source address (in network byte order) and the
 * OSPF packet type (1..5 matching the RFC packet-type enum); the type
 * is left as 1 (hello) when the packet didn't parse far enough to
 * extract it.
 */
void ospfd_ietf_notif_if_rx_bad_packet(struct ospf_interface *oi, struct in_addr src,
				       uint8_t packet_type)
{
	const char *xpath = "/ietf-ospf:if-rx-bad-packet";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	char buf[INET_ADDRSTRLEN];

	if (!oi || !oi->ifp || !oi->ospf)
		return;

	args = yang_data_list_new();
	ospfd_ietf_notif_add_instance_hdr(args, xpath, oi->ospf);
	ospfd_ietf_notif_add_interface_hdr(args, xpath, oi->ifp);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/packet-source", xpath);
	inet_ntop(AF_INET, &src, buf, sizeof(buf));
	listnode_add(args, yang_data_new_string(xpath_arg, buf));

	if (packet_type >= 1 && packet_type <= 5) {
		snprintf(xpath_arg, sizeof(xpath_arg), "%s/packet-type", xpath);
		listnode_add(args, yang_data_new_enum(xpath_arg, packet_type));
	}

	_dbg("bad packet on %s from %s type %u", oi->ifp->name, buf, packet_type);
	nb_notification_send(xpath, args);
}

/*
 * XPath: /ietf-ospf:if-config-error
 *
 * Emit when an OSPFv2 packet's contents diverge from the local interface
 * configuration (mismatched hello/dead interval, area mismatch, version,
 * MTU, auth, etc).  `error_name` is the RFC enum identifier string;
 * we pass it as a yang_data_new_string so libyang validates and accepts
 * it without depending on the enum's numeric value (the RFC leaves
 * if-config-error's numeric values implicit).
 */
void ospfd_ietf_notif_if_config_error(struct ospf_interface *oi, struct in_addr src,
				      uint8_t packet_type, const char *error_name)
{
	const char *xpath = "/ietf-ospf:if-config-error";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	char buf[INET_ADDRSTRLEN];

	if (!oi || !oi->ifp || !oi->ospf || !error_name)
		return;

	args = yang_data_list_new();
	ospfd_ietf_notif_add_instance_hdr(args, xpath, oi->ospf);
	ospfd_ietf_notif_add_interface_hdr(args, xpath, oi->ifp);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/packet-source", xpath);
	inet_ntop(AF_INET, &src, buf, sizeof(buf));
	listnode_add(args, yang_data_new_string(xpath_arg, buf));

	if (packet_type >= 1 && packet_type <= 5) {
		snprintf(xpath_arg, sizeof(xpath_arg), "%s/packet-type", xpath);
		listnode_add(args, yang_data_new_enum(xpath_arg, packet_type));
	}

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/error", xpath);
	listnode_add(args, yang_data_new_string(xpath_arg, error_name));

	_dbg("config error on %s from %s type %u: %s", oi->ifp->name, buf, packet_type, error_name);
	nb_notification_send(xpath, args);
}

/*
 * XPath: /ietf-ospf:nssa-translator-status-change
 *
 * Emit when an OSPFv2 area's NSSA translator state transitions.  RFC 9129
 * defines three states (enabled=1, elected=2, disabled=3); FRR only
 * tracks DISABLED (this router isn't translating) and ENABLED (this
 * router is the elected translator), so we map DISABLED -> `disabled`
 * and ENABLED -> `elected`.  OSPFv3 has no NSSA translator surface in
 * FRR, so this notification is OSPFv2-only.
 */
void ospfd_ietf_notif_nssa_translator_state_change(struct ospf *ospf, struct in_addr area_id,
						   int translator_state)
{
	const char *xpath = "/ietf-ospf:nssa-translator-status-change";
	struct list *args;
	char xpath_arg[XPATH_MAXLEN];
	char buf[INET_ADDRSTRLEN];
	int yang_state;

	if (!ospf)
		return;

	yang_state = (translator_state == OSPF_NSSA_TRANSLATE_DISABLED) ? 3 : 2;

	args = yang_data_list_new();
	ospfd_ietf_notif_add_instance_hdr(args, xpath, ospf);

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/area-id", xpath);
	inet_ntop(AF_INET, &area_id, buf, sizeof(buf));
	listnode_add(args, yang_data_new_string(xpath_arg, buf));

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/status", xpath);
	listnode_add(args, yang_data_new_enum(xpath_arg, yang_state));

	_dbg("area %pI4 nssa-translator status %d", &area_id, translator_state);
	nb_notification_send(xpath, args);
}

void ospfd_ietf_notif_init(void)
{
	hook_register(ospf_nsm_change, ospfd_ietf_nbr_state_change);
	hook_register(ospf_ism_change, ospfd_ietf_if_state_change);
}
