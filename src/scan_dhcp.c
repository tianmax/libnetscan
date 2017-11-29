/*
 * Copyright (C) 2017 Konstantin Vasin
 *
 * Licensed under GPLv2, see file LICENSE for more information.
 */
#include "scan_common.h"

/* DHCP protocol. RFC 2131, RFC 2132 */
#define DHCP_MAGIC 				0x63825363
#define DHCP_FIXED_LEN			240 /* with DHCP magic */
#define DHCP_UDP_OVERHEAD		28 /* IP + UDP headers */
#define DHCP_MTU_MAX			1500
#define DHCP_MTU_MIN			576
#define DHCP_OPTIONS_BUF_MIN	(DHCP_MTU_MIN - DHCP_FIXED_LEN - DHCP_UDP_OVERHEAD)
#define DHCP_OPTIONS_BUF_MAX	(DHCP_MTU_MAX - DHCP_FIXED_LEN - DHCP_UDP_OVERHEAD)

#define BOOTREQUEST				1
#define BOOTREPLY				2

/* DHCP Ports and Addresses */
#define CLIENT_PORT		68
#define SERVER_PORT		67

/* DHCP packet */
struct dhcp_packet {
    uint8_t op;				/* BOOTREQUEST or BOOTREPLY */
    uint8_t htype;			/* hardware address type. 1 = 10Mb ethernet */
    uint8_t hlen;			/* hardware address length */
    uint8_t hops;			/* used by relay agents only */
    uint32_t xid;			/* unuque id */
    uint16_t secs; 			/* seconds since client started looking */
    uint16_t flags;			/* only one flag */
    uint32_t ciaddr;		/* clients IP address (if already in use) */
    uint32_t yiaddr;		/* client IP address */
    uint32_t siaddr_nip;	/* next server used in bootstrap */
    uint32_t gateway_nip;	/* relay agent IP address */
    uint8_t chaddr[16];		/* MAC address of client */
    uint8_t sname[64];		/* server host name (ASCIZ) */
    uint8_t file[128];		/* boot file name (ASCIIZ) */
    uint32_t cookie;		/* fixed first four option bytes (99, 130, 83, 99 dec) */
    uint8_t options[DHCP_OPTIONS_BUF_MAX];
};

/* IP packet with DHCP */
struct ip_udp_dhcp_packet {
    struct iphdr ip;			/* IP header */
    struct udphdr udp;			/* UDP header */
    struct dhcp_packet data;	/* UDP payload */
};

/* UDP packet with DHCP */
struct udp_dhcp_packet {
    struct udphdr udp;			/* UDP header */
    struct dhcp_packet data;	/* UDP payload */
};

/* Packets size */
enum {
    IP_UDP_DHCP_SIZE = sizeof(struct ip_udp_dhcp_packet),
    UDP_DHCP_SIZE    = sizeof(struct udp_dhcp_packet),
    DHCP_SIZE        = sizeof(struct dhcp_packet),
};

/* DHCP options codes */
#define DHCP_PADDING 			0x00
#define DHCP_SUBNET 			0x01
#define DHCP_ROUTER				0x03
#define DHCP_DNS				0x06
#define DHCP_BROADCAST			0x1c
#define DHCP_STATIC				0x21
#define DHCP_NTP				0x2a
#define DHCP_VENDOR				0x2b
#define DHCP_NETBIOS_NAME_SRV	0x2c
#define DHCP_LEASE_TIME 		0x33
#define DHCP_OVERLOAD			0x34
#define DHCP_MESSAGE_TYPE		0x35
#define DHCP_SERVER_ID			0x36 /* DHCP server IP */
#define DHCP_PARAM_REQ			0x37 /* list of options client wants */
#define DHCP_MAX_SIZE			0x39
#define DHCP_RENEWAL_TIME		0x3a
#define DHCP_REBINDING_TIME		0x3b
#define DHCP_VENDOR_CLASS_ID	0x3c
#define DHCP_CLIENT_ID			0x3d /* client's MAC addr*/
#define DHCP_SIP				0x78
#define DHCP_CLASSLESS_STATIC	0x79
#define DHCP_END				0xff

/* DHCP_MESSAGE_TYPE values */
#define DHCPDISCOVER	1 /* client -> server */
#define DHCPOFFER		2 /* client <- server */

/* Offsets in option byte sequence */
#define OPT_CODE                0
#define OPT_LEN                 1
#define OPT_DATA                2

/* Bits in "overload" option */
#define OPTION_FIELD			0
#define FILE_FIELD				1
#define SNAME_FIELD				2

static int dhcp_send_discover(int fd, int ifindex, uint8_t *hwaddr, uint32_t id);
static void dhcp_init_packet(struct dhcp_packet *packet, uint8_t *hwaddr);
static int dhcp_end_option(uint8_t *optionptr);
static int dhcp_recv_offer(int fd,  uint32_t id, uint8_t *hwaddr, json_t *result);
static uint8_t *dhcp_get_option(struct dhcp_packet *packet, int code);
static void handler(int sig);

static volatile sig_atomic_t got_alarm = 0;

/**
 * Search DHCP server.
 *
 * @param ifname Network interface name.
 * @param time Wait time.
 * @param result JSON object with result.
 *
 * @return 1 on success, 0 on time is out, -2 on invalid json object for result,
 * -1 on other errors.
 */
int scan_dhcp(const char *ifname, unsigned int time, json_t *result)
{
    int ifindex;
    uint8_t hwaddr[ETH_ALEN];
    struct sigaction sa;
    uid_t euid;
    uint32_t id;
    int fd = -1;
    int ret = -1;

    /* Check pointer for result */
    if (!json_is_object(result)) {
		ret = - 2;
        goto err_exit;
    }

    /* Check superuser priveleges */
    if ((euid = geteuid()) != 0) {
		s_set_err(result, "You must be root");
        goto err_exit;
    }

    /* Check input data */
    /* Check wait time */
    if (time == 0)
        time = 1;
    if (time > MAX_WAIT_TIME) {
		s_set_err(result, "Max wait time is %d", MAX_WAIT_TIME); 
        goto err_exit;
    }
    /* Check interface name */
    if (!ifname || *ifname == '\0') {
        s_set_err(result, "Empty interface name");
        goto err_exit;
    }
    /* Check interface name length */
    if (strlen(ifname) > IFNAMSIZ) {
        s_set_err(result, "Interface name is too long");
        goto err_exit;
    }
    /* Get interface index */
    if ((ifindex = s_get_ifindex(ifname)) == 0) {
        s_set_err(result, "No interface found");
        goto err_exit;
    }
    /* Get MAC address */
    if ((s_get_hw_address(ifname, hwaddr)) < 0) {
        s_set_err(result, "Can't get MAC address");
        goto err_exit;
    }

    /* Create socket */
	fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));

    if (fd < 0) {
        s_set_err(result, "Can't create socket");
        goto err_exit;
    }

    /* Establish handler for notification signal */
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handler;
    if ((sigaction(SIGALRM, &sa, NULL)) == -1) {
        s_set_err(result, "Can't set handler for timer");
        goto err_exit2;
    }

    /* Send Request */
    id = s_random_id();
	ret = dhcp_send_discover(fd, ifindex, hwaddr, id);
    if (ret < 0) {
        s_set_err(result, "Can't send request");
        goto err_exit2;
    }

	json_object_clear(result);

    /* Start timer */
    alarm(time);

    /* Loop, recv packets && search answer for us */
    while(1) {
		ret = dhcp_recv_offer(fd, id, hwaddr, result);

        /* Answer received */
        if (ret == 0) {
			ret = 1;
            break;
        }
        /* Read error */
        if (ret == -1) {
            s_set_err(result, "Read socket error");
            break;
        }
        /* Check timer */
        if (got_alarm == 1) {
            ret = 0;
            break;
        }
    }
    /* Cancel timer */
    alarm(0);
err_exit2:
    close(fd);
err_exit:
    return ret;
}

/**
 * Search DHCP server.
 *
 * @param ifname Network interface name.
 * @param time Wait time.
 *
 * @return 1 on success, 0 on time is out, -1 on error.
 */
int scan_dhcp_result(const char *ifname, unsigned int time) {

	int ret;
	json_t *result = json_object();

	ret = scan_dhcp(ifname, time, result);
	if (ret < 0)
		ret = -1;

	json_decref(result);
	return ret;
}

/**
 * Send DHCP DISCOVER
 *
 * @param fd Socket descriptor.
 * @param ifindex Interface index.
 * @param hwaddr MAC address of interface.
 * @param id Unique ID.
 *
 * @return Number of bytes sent on success, -1 on error.
 */
static int dhcp_send_discover(int fd, int ifindex, uint8_t *hwaddr, uint32_t id)
{
    struct sockaddr_ll sa;
    struct ip_udp_dhcp_packet packet;
    unsigned padding;
    int result = -1;

    /* Bind */
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_ifindex = ifindex;
    sa.sll_halen = ETH_ALEN;
    memset(&sa.sll_addr, 0xff, ETH_ALEN);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        return result;
    }

    /* Craft packet */
    memset(&packet, 0, sizeof(packet));
    dhcp_init_packet(&packet.data, hwaddr);
    packet.data.xid = id;

    /* For badly configured servers (they drop DHCP packets > 576 octets (with ethernet header),
	 * but they may only drop packets > 576 octets without ethernet header (590 with ethernet header).
	 * RFC 1542: minimal BOOTP header 300 octets. 
	 */
    padding = DHCP_OPTIONS_BUF_MAX - 1 - dhcp_end_option(packet.data.options);
  	if (padding > DHCP_SIZE - 300)
        padding = DHCP_SIZE - 300;

    /* IP and UDP headers */
    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.saddr = htonl(INADDR_ANY);
    packet.ip.daddr = htonl(INADDR_BROADCAST);
    packet.udp.source = htons(CLIENT_PORT);
    packet.udp.dest = htons(SERVER_PORT);
    /* size, excluding IP header */
    packet.udp.len = htons(UDP_DHCP_SIZE - padding);
    /* for UDP checksumming, ip.len is set to UDP packet len */
    packet.ip.tot_len = packet.udp.len;

    packet.udp.check = s_inet_cksum((uint16_t *)&packet,
                                  IP_UDP_DHCP_SIZE - padding);
    /* for sending, it is set to IP packet len */
    packet.ip.tot_len = htons(IP_UDP_DHCP_SIZE - padding);
    packet.ip.version = IPVERSION;
    packet.ip.ihl = sizeof(packet.ip) >> 2;
    packet.ip.ttl = IPDEFTTL;
    packet.ip.check = s_inet_cksum((uint16_t *)&packet.ip, sizeof(packet.ip));

    /* Send packet */
    result = sendto(fd, &packet, IP_UDP_DHCP_SIZE - padding, 0,
                    (struct sockaddr *)&sa, sizeof(sa));

    return result;
}

/**
 * Fill DHCP Packet.
 *
 * @param packet DHCP packet.
 * @param hwaddr MAC address of interface.
 * @return Void.
 */
static void dhcp_init_packet(struct dhcp_packet *packet, uint8_t *hwaddr)
{
    unsigned index = 0;

    /* DHCP header */
    memset(packet, 0, sizeof(*packet));
    packet->op = BOOTREQUEST;
    packet->htype = 1; /* ethernet */
    packet->hlen = ETH_ALEN;
    packet->cookie = htonl(DHCP_MAGIC);
    packet->secs = 0;
    memcpy(packet->chaddr, hwaddr, ETH_ALEN);

    /* DHCP options */
    /* Message type */
    packet->options[index++] = DHCP_MESSAGE_TYPE;
    packet->options[index++] = 1; //length of option data
    packet->options[index++] = DHCPDISCOVER;

    /* Requested parameters */
    packet->options[index++] = DHCP_PARAM_REQ;
    packet->options[index++] = 9; // number of options
    packet->options[index++] = DHCP_SUBNET;
    packet->options[index++] = DHCP_ROUTER;
    packet->options[index++] = DHCP_DNS;
    packet->options[index++] = DHCP_BROADCAST;
    packet->options[index++] = DHCP_STATIC;
    packet->options[index++] = DHCP_NTP;
    packet->options[index++] = DHCP_VENDOR;
    packet->options[index++] = DHCP_SIP;
    packet->options[index++] = DHCP_CLASSLESS_STATIC;

    /* client id */
    packet->options[index++] = DHCP_CLIENT_ID;
    packet->options[index++] = ETH_ALEN + 1;
    packet->options[index++] = 1; //ethernet
    memcpy(&packet->options[index], hwaddr, ETH_ALEN);
    index += ETH_ALEN;

    /* end option */
    packet->options[index] = DHCP_END;
}

/**
 * Calculate position of the END option.
 *
 * @param optionptr Beginning of dhcp options.
 * @return Position of 'end' option.
 */
static int dhcp_end_option(uint8_t *optionptr)
{
    int i = 0;
    while (optionptr[i] != DHCP_END) {
        if (optionptr[i] != DHCP_PADDING)
            i += optionptr[i + OPT_LEN] + OPT_DATA - 1;
        i++;
    }
    return i;
}

/**

 * Receive OFFER
 *
 * @param fd Socket descriptor.
 * @param id Unique ID.
 * @param hwaddr MAC address of interface.
 * @param result JSON object for result.
 *
 * @return 0 on success, -1 on read error,
 * -2 packet is not correct, -3 on EINTR (time is out).
 */
static int dhcp_recv_offer(int fd,  uint32_t id, uint8_t *hwaddr, json_t *result)
{
    int bytes;
    struct ip_udp_dhcp_packet packet;
    struct dhcp_packet data;

    uint8_t *opt_data;
    uint16_t check;
    char ip_str[INET_ADDRSTRLEN];
    uint32_t ip_addr;
	int i;

    memset(&packet, 0, sizeof(packet));
    memset(&data, 0, sizeof(data));

    /* Read packet */
    bytes = read(fd, &packet, sizeof(packet));

    if (bytes < 0) {
        if (errno == EINTR) {
            return -3;
        } else {
            return -1;
        }
    }
    /* Packet is too short */
    if (bytes < (int) (sizeof(packet.ip) + sizeof(packet.udp)))
        return -2;
    /* Oversized packet */
    if (bytes < (int) ntohs(packet.ip.tot_len))
        return -2;

    /* Ignore any extra garbage bytes */
    bytes = ntohs(packet.ip.tot_len);

    /* Unrelated/bogus packet */
    if (packet.ip.protocol != IPPROTO_UDP
            || packet.ip.version != IPVERSION
            || packet.ip.ihl != (sizeof(packet.ip) >> 2)
            || packet.udp.dest != htons(CLIENT_PORT)
            || ntohs(packet.udp.len) != (uint16_t)(bytes - sizeof(packet.ip))
       )
        return -2;

    /* Verify IP checksum */
    check = packet.ip.check;
    packet.ip.check = 0;
    if (check != s_inet_cksum((uint16_t *)&packet.ip, sizeof(packet.ip)))
        return -2;

    /* Verify UDP checksum, IP header has to be modified for this */
    memset(&packet.ip, 0, offsetof(struct iphdr, protocol));
    /* ip.xx fields which are not memset: protocol, check, saddr, daddr */
    packet.ip.tot_len = packet.udp.len;
    check = packet.udp.check;
    packet.udp.check = 0;
    if (check && check != s_inet_cksum((uint16_t *)&packet, bytes))
        return -2;

    memcpy(&data, &packet.data, sizeof(data));

    /* Check DHCP magic */
    if (bytes < (int)offsetof(struct dhcp_packet, options)
            || data.cookie != htonl(DHCP_MAGIC))
        return	-2;

    /* Check xid */
    if (data.xid != id)
        return -2;

    /* Ignore packets that aren't for us */
    if (data.hlen != ETH_ALEN || memcmp(&data.chaddr, hwaddr, ETH_ALEN))
        return -2;

    /* Check message type */
    opt_data = dhcp_get_option(&data, DHCP_MESSAGE_TYPE);
    if (!opt_data || *opt_data != DHCPOFFER)
        return -2;

    /* Fill result */
    /* Get DHCP server ID */
    opt_data = dhcp_get_option(&data, DHCP_SERVER_ID);
    if (opt_data) {
        ip_addr = *(uint32_t *)opt_data;
        if (inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str)))
            json_object_set_new_nocheck(result, "server", json_string(ip_str));
    }

    /* Get netmask */
    opt_data = dhcp_get_option(&data, DHCP_SUBNET);
    if (opt_data) {
        ip_addr = *(uint32_t *)opt_data;
        if (inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str)))
            json_object_set_new_nocheck(result, "mask", json_string(ip_str));
    }

    /* Get router */
    opt_data = dhcp_get_option(&data, DHCP_ROUTER);
    if (opt_data) {
        ip_addr = *(uint32_t *)opt_data;
        if (inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str)))
            json_object_set_new_nocheck(result, "router", json_string(ip_str));
    }
    /* Get DNS servers */
    opt_data = dhcp_get_option(&data, DHCP_DNS);
    if (opt_data) {
        json_t *dns_list = json_array();
        int num = *(opt_data - 1) >> 2; /* get number of servers */
        for (i = 0; i < num; i++) {
            ip_addr = (*((uint32_t *)opt_data + i));
            if (inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str)))
                json_array_append_new(dns_list, json_string(ip_str));
            else
                break;
        }
        json_object_set_new_nocheck(result, "dns", dns_list);
    }
    /* Get Broadcast address */
    opt_data = dhcp_get_option(&data, DHCP_BROADCAST);
    if (opt_data) {
        ip_addr = *(uint32_t *)opt_data;
        if (inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str)))
            json_object_set_new_nocheck(result, "broadcast", json_string(ip_str));
    }
    /* Get NETBIOS Name servers */
    opt_data = dhcp_get_option(&data, DHCP_NETBIOS_NAME_SRV);
    if (opt_data) {
        json_t *netbios_list = json_array();
        int num = *(opt_data - 1) >> 2; /* get number of servers */
        for (i = 0; i < num; i++) {
            ip_addr = *((uint32_t *)opt_data + i);
            if (inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str)))
                json_array_append_new(netbios_list, json_string(ip_str));
            else
                break;
        }
        json_object_set_new_nocheck(result, "netbios", netbios_list);
    }
    return 0;
}

/**
 * Get an option with bounds checking
 *
 * @param packet DHCP packet.
 * @param code Option code.
 *
 * @return NULL or pointer to beginning of the option data.
 */
static uint8_t *dhcp_get_option(struct dhcp_packet *packet, int code)
{
    uint8_t *optionptr;
    int len;
    int rem;
	int overload = 0;
	enum {
		FILE_FIELD101 = FILE_FIELD * 0x101,
		SNAME_FIELD101 = SNAME_FIELD * 0x101,
	};

    /* option bytes: [code][len][data1][data2]...[dataLEN] */
    optionptr = packet->options;
    rem = sizeof(packet->options);
    while (1) {
        if (rem <= 0) {
            return NULL;
        }
        if (optionptr[OPT_CODE] == DHCP_PADDING) {
            rem--;
            optionptr++;
            continue;
        }
        if (optionptr[OPT_CODE] == DHCP_END) {
			if ((overload & FILE_FIELD101) == FILE_FIELD) {
				/* we can use packet->file */
				overload |= FILE_FIELD101;
				optionptr = packet->file;
				rem = sizeof(packet->file);
				continue;
			}
			if ((overload & SNAME_FIELD101) == SNAME_FIELD) {
				/* we can use packet->sname */
				overload |= SNAME_FIELD101;
				optionptr = packet->sname;
				rem = sizeof(packet->sname);
				continue;
			}
            break;
        }
        len = OPT_DATA + optionptr[OPT_LEN];
        rem -= len;
        if (rem < 0)
            continue;

        if (optionptr[OPT_CODE] == code)
            return optionptr + OPT_DATA;

		if (optionptr[OPT_CODE] == DHCP_OVERLOAD)
			overload |= optionptr[OPT_DATA];

        optionptr += len;
    }

    return NULL;
}

/**
 * Signal handler
 * @param Signal value.
 *
 * @return Void.
 */
static void handler(int sig)
{
    if (sig == SIGALRM)
        got_alarm = 1;
}



