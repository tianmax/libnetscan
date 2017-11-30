/*
 * Copyright (C) 2017 Konstantin Vasin
 *
 * Licensed under GPLv2, see file LICENSE for more information.
 */
#include "scan_common.h"

/* PPPoE Codes. RFC 2516 */
#define CODE_PADI				0x09
#define CODE_PADO				0x07

/* PPPoE Tags */
#define TAG_END_OF_LIST			0x0000
#define TAG_SERVICE_NAME		0x0101
#define TAG_AC_NAME				0x0102
#define TAG_HOST_UNIQ			0x0103

/* PPPoE Default Tag and Version */
#define PPPOE_TYPE_VERSION 0x11

/* PPPoE Packet including Ethernet headers */
struct pppoe_packet {
    struct		ethhdr eth_header;			/* Ethernet header */
    uint8_t		type_ver; 					/* PPPoE type and version */
    uint8_t 	code;						/* PPPoE code */
    uint16_t 	sid;						/* PPPoE session_ID */
    uint16_t 	len;						/* Payload length */
    uint8_t 	payload[ETH_DATA_LEN];		/* PPPoE payload */
};
#define PPPOE_OVERHEAD 6 /* type, code, session, length */
#define L2_HDR_SIZE (sizeof(struct ethhdr) + PPPOE_OVERHEAD)
#define MAX_PPPOE_PAYLOAD (ETH_DATA_LEN - PPPOE_OVERHEAD)

/* PPPoE Tag */
struct pppoe_tag {
    uint16_t 	type;						/* Tag type */
    uint16_t 	len;						/* Length of value */
    uint8_t 	payload[ETH_DATA_LEN];		/* Tag payload */
};
#define TAG_HDR_SIZE 4 /* Header size of a PPPoE tag */

static int pppoe_send_padi(int fd, int ifindex, uint8_t *hwaddr, const char *service, uint32_t id);
static int pppoe_recv_pado(int fd, uint32_t id, uint8_t *hwaddr, json_t *result);
static int pppoe_parse_packet(struct pppoe_packet *pkt, uint32_t id, json_t *result);
static uint8_t *pppoe_extract_tag(struct pppoe_packet *pkt, uint16_t type, struct pppoe_tag *tag);
static void handler(int sig);

static volatile sig_atomic_t got_alarm = 0;

/**
 * Search PPPoE server.
 *
 * @param ifname Network interface name
 * @param time Wait time.
 * @param result JSON object with result.
 *
 * @return 1 on success, 0 on time is out, -2 on invalid json object for result,
 * -1 on other errors.
 */
int scan_pppoe(const char *ifname, unsigned int time, json_t *result)
{
    int ifindex;
    uint8_t hwaddr[ETH_ALEN];
    struct sigaction sa;
    uid_t euid;
    uint32_t id;
	const char *service;
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
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PPP_DISC));

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

	/* Try extract service name */
	service = json_string_value(json_object_get(result, "service"));

    /* Send Request */
    id = s_random_id();
	ret = pppoe_send_padi(fd, ifindex, hwaddr, service, id);
    if (ret <  0) {
		if (ret == -2)
        	s_set_err(result, "Very long service name");
		else
        	s_set_err(result, "Can't send request");
		ret = -1;
        goto err_exit2;
    }
	
	json_object_clear(result);

    /* Start timer */
    alarm(time);

    /* Loop, recv packets && search answer for us */
    while(1) {
		ret = pppoe_recv_pado(fd, id, hwaddr, result);

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
 * Search PPPoE server.
 *
 * @param ifname Network interface name
 * @param time Wait time.
 *
 * @return 1 on success, 0 on time is out, -1 on error.
 */
int scan_pppoe_result(const char *ifname, unsigned int time) {

	int ret;
	json_t *result = json_object();

	ret = scan_pppoe(ifname, time, result);
	if (ret < 0)
		ret = -1;

	json_decref(result);
	return ret;
}

/**
 * Send PPPoE PADI
 *
 * @param fd Socket descriptor.
 * @param ifindex Interface index.
 * @param hwaddr MAC address of interface.
 * @param service Service Name.
 * @param id Host Uniq.
 *
 * @return Number of bytes send on success, -1 on error, -2 on too long service name.
 */
static int pppoe_send_padi(int fd, int ifindex, uint8_t *hwaddr, const char *service, uint32_t id)
{
    struct sockaddr_ll sa;
    struct pppoe_packet packet;
    struct pppoe_tag *tag_hu = (struct pppoe_tag *)&packet.payload;
    struct pppoe_tag sv_name;
    unsigned char *cursor = packet.payload;
    uint16_t pack_len;
    uint16_t namelen = 0;
    int result = -1;

    /* Bind */
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_PPP_DISC);
    sa.sll_ifindex = ifindex;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        return result;
    }

    /* fill packet */
    memset(&packet, 0, sizeof(struct pppoe_packet));
    /* ethernet fields */
    memset(packet.eth_header.h_dest, 0xff, ETH_ALEN);
    memcpy(packet.eth_header.h_source, hwaddr, ETH_ALEN);
    packet.eth_header.h_proto = htons(ETH_P_PPP_DISC);
    /* pppoe fields */
    packet.type_ver = PPPOE_TYPE_VERSION;
    packet.code = CODE_PADI;
    packet.sid = 0;

    /* PPPoE Tags */
    /* Add Host-Uniq value */
    tag_hu->type = htons(TAG_HOST_UNIQ);
    tag_hu->len = htons(sizeof(uint32_t));
    memcpy(tag_hu->payload, &id, sizeof(id));
    cursor += (TAG_HDR_SIZE + sizeof(id));
    pack_len = sizeof(id) + TAG_HDR_SIZE;

    /* Service name */
    if (service) {
        namelen = (uint16_t) strlen(service);
    }
    if (namelen < MAX_PPPOE_PAYLOAD - pack_len) {
        memset(&sv_name, 0, sizeof(struct pppoe_tag));
        pack_len += TAG_HDR_SIZE + namelen;
        sv_name.type = htons(TAG_SERVICE_NAME);
        sv_name.len = htons(namelen);

        if (service) {
            memcpy(&sv_name.payload, service, namelen);
        }
        memcpy(cursor, &sv_name, namelen + TAG_HDR_SIZE);
    } else {
        return -2;
    }

    /* Add pppoe packet length value */
    packet.len = htons(pack_len);

    /* Send packet */
    result = send(fd, &packet, (int)(pack_len + L2_HDR_SIZE), 0);

    return result;
}


/**
 * Recv PADO.
 *
 * @param fd Socket descriptor.
 * @param id Host Uniq.
 * @param hwaddr - MAC address of interface.
 * @param result JSON object for result.
 *
 * @return -1 on read error, 0 on success, -2 if packet is not correct,
 * -3 if time is out.
 */
static int pppoe_recv_pado(int fd, uint32_t id, uint8_t *hwaddr, json_t *result)
{
    struct pppoe_packet pkt;
    int bytes;

    memset(&pkt, 0, sizeof(struct pppoe_packet));

    /* Read packet */
    bytes = read(fd, &pkt, sizeof(pkt));

    if (bytes < 0) {
        if (errno == EINTR) {
            return -3;
        } else {
            return -1;
        }
    }

    /* Check length */
    if ((ntohs(pkt.len) + PPPOE_OVERHEAD) > ETH_DATA_LEN)
        return -2;

    /* Check protocol */
    if (ETH_P_PPP_DISC != ntohs(pkt.eth_header.h_proto))
        return -2;

    /* Check pppoe type and version */
    if (PPPOE_TYPE_VERSION != (pkt.type_ver))
        return -2;

    /* Check pado code in pppoe packet */
    if (CODE_PADO != pkt.code)
        return -2;

    /* Check dest MAC address */
    if (memcmp(pkt.eth_header.h_dest, hwaddr, ETH_ALEN))
        return -2;

    if (pppoe_parse_packet(&pkt, id, result))
        return -2;

    return 0;
}

/**
 * Parse PPPoE packet.
 *
 * @param pkt PPPoE packet.
 * @param id Host Uniq.
 * @param result JSON object for result.
 *
 * @return zero on success, -1 on error.
 */
static int pppoe_parse_packet(struct pppoe_packet *pkt, uint32_t id, json_t *result)
{
    struct pppoe_tag tag;
    uint32_t host_uniq;
    char buf[ETH_DATA_LEN];

    memset(&tag, 0, sizeof(struct pppoe_tag));

    /* Check Host Uniq */
    if (pppoe_extract_tag(pkt, TAG_HOST_UNIQ, &tag)) {
        memcpy(&host_uniq, tag.payload, tag.len);
        if (host_uniq != id)
            return -1;
    }

    /* Extract AC Name */
    if (pppoe_extract_tag(pkt, TAG_AC_NAME, &tag)) {
        if (tag.len < ETH_DATA_LEN) {
            memcpy(buf, tag.payload, tag.len);
            buf[tag.len] = '\0';
        }
        json_object_set_new_nocheck(result, "ac", json_string(buf));
    }

    /* Extract Service Name */
    if (pppoe_extract_tag(pkt, TAG_SERVICE_NAME, &tag)) {
        if (tag.len < ETH_DATA_LEN) {
            memcpy(buf, tag.payload, tag.len);
            buf[tag.len] = '\0';
        }
        json_object_set_new_nocheck(result, "service", json_string(buf));
    }
    return 0;
}


/**
 * Extract TAG.
 *
 * @param pkt PPPoE packet.
 * @param type Required tag type.
 * @param tag Buffer for tag.
 *
 * @return Pointer on tag value if tag is found, NULL otherwise.
 */
static uint8_t *pppoe_extract_tag(struct pppoe_packet *pkt, uint16_t type, struct pppoe_tag *tag)
{
    uint16_t len = ntohs(pkt->len);
    uint8_t  *cur_tag;

    cur_tag = pkt->payload;

    while ((cur_tag - pkt->payload) < len) {
        /* Alignment */
        uint16_t tag_type = (((uint16_t) cur_tag[0]) << 8) + (uint16_t) cur_tag[1];
        uint16_t tag_len = (((uint16_t) cur_tag[2]) << 8) + (uint16_t) cur_tag[3];

        if (TAG_END_OF_LIST == tag_type)
            return NULL;

        if (((cur_tag - pkt->payload) + tag_len + TAG_HDR_SIZE) > len )
            return NULL;

        if (type == tag_type) {
            tag->type = tag_type;
            tag->len = tag_len;
            cur_tag += TAG_HDR_SIZE;
            memcpy(tag->payload, cur_tag, tag_len);
            return cur_tag;
        }
        cur_tag = cur_tag + TAG_HDR_SIZE + tag_len;
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
