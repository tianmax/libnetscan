/*
 * Copyright (C) 2017 Konstantin Vasin
 *
 * Licensed under GPLv2, see file LICENSE for more information.
 */
#ifndef _SCAN_COMMON_H
#define _SCAN_COMMON_H

#include <jansson.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if.h>

#define MAX_WAIT_TIME 15
#define MAX_ERROR_LENGTH 1500

extern uint32_t s_random_id(void);
extern int s_get_hw_address(const char *ifname, uint8_t addr[ETH_ALEN]);
extern unsigned int s_get_ifindex(const char *ifname);
extern uint16_t s_inet_cksum(uint16_t *addr, int nleft);
extern int s_set_err(json_t *result, const char *msg, ...);

#endif /* _SCAN_COMMON_H */
