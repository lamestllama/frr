// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF northbound definitions.
 */

#ifndef _FRR_OSPF_NB_H_
#define _FRR_OSPF_NB_H_

#include "northbound.h"

#define FRR_OSPFD_IFACE_XPATH "/frr-interface:lib/interface/frr-ospfd:ospf"
#define FRR_OSPFD_OSPF_XPATH                                                   \
	"/frr-routing:routing/control-plane-protocols/control-plane-protocol"   \
	"/frr-ospfd:ospf"
#define FRR_OSPFD_AREA_XPATH FRR_OSPFD_OSPF_XPATH "/areas/area"
#define FRR_OSPFD_AREA_VLINK_XPATH FRR_OSPFD_AREA_XPATH "/virtual-link"
#define FRR_OSPFD_AREA_VLINK_TIMERS_XPATH                                      \
	FRR_OSPFD_AREA_VLINK_XPATH "/timers"

extern const struct frr_yang_module_info frr_ospfd_nb_info;

int routing_control_plane_protocols_ospfd_validate(
	struct nb_cb_create_args *args);
int routing_control_plane_protocols_ospfd_create(struct nb_cb_create_args *args);
int routing_control_plane_protocols_ospfd_destroy(
	struct nb_cb_destroy_args *args);

#endif /* _FRR_OSPF_NB_H_ */
