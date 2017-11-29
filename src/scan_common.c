/*
 * Copyright (C) 2017 Konstantin Vasin
 *
 * Licensed under GPLv2, see file LICENSE for more information.
 */
#include "scan_common.h"

/* Endianness check */
#define IS_BIG_ENDIAN (*(uint16_t *)"\0\xff" < 0x100)

/**
 * Get MAC address of interface.
 *
 * @param ifname Interface name.
 * @param addr Array for MAC address.
 *
 * @return -1 on failure, 0 on success.
 */
int s_get_hw_address(const char *ifname, uint8_t addr[ETH_ALEN])
{
    /* Copy interface name into ifreq */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));

    size_t if_name_len = strlen(ifname);

    if (if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, ifname, if_name_len);
        ifr.ifr_name[if_name_len] = 0;
    } else {
        return -1;
    }

    /* Create socket */
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    if (fd < 0) {
        return -1;
    }

    /* Get hw address */
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close (fd);
        return -1;
    }

    close(fd);
    memcpy (addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    return 0;
}


/**
 * Get Interface index.
 *
 * @param ifname Interface name.
 *
 * @return Interface index on success, zero on failure.
 */
unsigned int s_get_ifindex(const char *ifname)
{
    /* Copy interface name into ifreq */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));

    size_t if_name_len = strlen(ifname);

    if (if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, ifname, if_name_len);
        ifr.ifr_name[if_name_len] = 0;
    } else {
        return -1;
    }

    /* Create socket */
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    if (fd < 0) {
        return 0;
    }

    /* Get interface index */
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close (fd);
        return 0;
    }

    close(fd);
    return ifr.ifr_ifindex;
}

/**
 * Calculate internet checksum.
 *
 * @param addr Start address.
 * @param nleft Length in bytes.
 *
 * @return Checksum.
 */
uint16_t s_inet_cksum(uint16_t *addr, int nleft)
{
    /*
     * Algorithm is simple, using a 32 bit accumulator,
     * we add sequential 16 bit words to it, and at the end, fold
     * back all the carry bits from the top 16 bits into the lower
     * 16 bits.
     */
    unsigned sum = 0;
    while (nleft > 1) {
        sum += *addr++;
        nleft -= 2;
    }
    /* Mop up an odd byte, if necessary */
    if (nleft == 1) {
        if (IS_BIG_ENDIAN)
            sum += *(uint8_t *)addr << 8;
        else
            sum += *(uint8_t *)addr;
    }

    /* Add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */

    return (uint16_t)~sum;
}

/**
 * Calculate random id (unsigned 32-bit value).
 *
 * @param Void.
 * @return id
 */
uint32_t s_random_id(void)
{
    srand(time(NULL));
    return rand();
}

/**
 * Add error value in result.
 *
 * @param JSON object.
 * @param msg Error message 
 *
 * @return 0 on success, -1 on failure.
 */
int s_set_err(json_t *result, const char *msg, ...)
{
	va_list ap;
	char buf[MAX_ERROR_LENGTH];
	int ret = -1;


	va_start(ap, msg);
	if (msg != NULL)
		ret = vsnprintf(buf, sizeof(buf), msg, ap);
	va_end(ap);

	if (ret > 0)
		ret = json_object_set_new_nocheck(result, "error", json_string(buf));
	else
		ret = -1;

	return ret;
}
