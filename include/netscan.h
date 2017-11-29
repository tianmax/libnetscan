/*
 * Copyright (C) 2017 Konstantin Vasin
 *
 * Licensed under GPLv2, see file LICENSE for more information.
 */
#ifndef _NETSCAN_H_
#define _NETSCAN_H_

#include <jansson.h>

extern int scan_dhcp(const char *ifname, unsigned int time, json_t *result);
extern int scan_pppoe(const char *ifname, unsigned int time, json_t *result);

/* return only discovery result without additional info */
extern int scan_pppoe_result(const char *ifname, unsigned int time);
extern int scan_dhcp_result(const char *ifname, unsigned int time);

#endif /* _NETSCAN_H_ */
