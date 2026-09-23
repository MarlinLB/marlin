/*
 * SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
 *
 * Definitions for conf_value.h.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <marlin/abi/defines.h>
#include <marlind/conf_value.h>

bool conf_parse_ipv4(const char *str, __be32 *out)
{
    struct in_addr addr;

    if(inet_pton(AF_INET, str, &addr) != 1) {
        return false;
    }
    *out = addr.s_addr;
    return true;
}

bool conf_parse_ipv6(const char *str, __u8 out[16])
{
    struct in6_addr addr;

    if(inet_pton(AF_INET6, str, &addr) != 1) {
        return false;
    }
    memcpy(out, &addr, 16);
    return true;
}

static int hex_nibble(char ch)
{
    if(ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if(ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if(ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

bool conf_parse_mac(const char *str, __u8 out[6])
{
    if(strlen(str) != 17) {
        return false;
    }

    for(size_t i = 0; i < 6; i++) {
        int hi = hex_nibble(str[i * 3]);
        int lo = hex_nibble(str[i * 3 + 1]);

        if(hi < 0 || lo < 0) {
            return false;
        }
        if(i < 5 && str[i * 3 + 2] != ':') {
            return false;
        }
        out[i] = (__u8)((hi << 4) | lo);
    }
    return true;
}

bool conf_parse_hexkey16(const char *str, __u8 out[16])
{
    size_t len = strlen(str);

    if(len != 32) {
        return false;
    }

    for(size_t i = 0; i < 16; i++) {
        int hi = hex_nibble(str[2 * i]);
        int lo = hex_nibble(str[2 * i + 1]);

        if(hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (__u8)((hi << 4) | lo);
    }
    return true;
}

bool conf_parse_proto(const char *str, __u8 *out)
{
    if(strcmp(str, "tcp") == 0) {
        *out = IPPROTO_TCP;
        return true;
    }
    if(strcmp(str, "udp") == 0) {
        *out = IPPROTO_UDP;
        return true;
    }
    if(strcmp(str, "sctp") == 0) {
        *out = IPPROTO_SCTP;
        return true;
    }
    return false;
}

bool conf_parse_mode(const char *str, __u8 *out)
{
    if(strcmp(str, "l2dsr") == 0) {
        *out = MARLIN_MODE_L2DSR;
        return true;
    }
    if(strcmp(str, "ipip") == 0) {
        *out = MARLIN_MODE_IPIP;
        return true;
    }
    if(strcmp(str, "gue") == 0) {
        *out = MARLIN_MODE_GUE;
        return true;
    }
    if(strcmp(str, "vxlan") == 0) {
        *out = MARLIN_MODE_VXLAN;
        return true;
    }
    return false;
}

bool conf_parse_state(const char *str, bool *up)
{
    if(strcmp(str, "up") == 0) {
        *up = true;
        return true;
    }
    if(strcmp(str, "down") == 0) {
        *up = false;
        return true;
    }
    return false;
}

bool conf_parse_cidr(const char *str, bool *is_v6, __u32 *prefixlen, __u8 addr[16])
{
    char buf[64];
    char *slash;
    char *end;
    unsigned long plen;
    int width;

    if(strlen(str) >= sizeof(buf)) {
        return false;
    }
    (void)snprintf(buf, sizeof(buf), "%s", str);

    slash = strchr(buf, '/');
    if(slash == NULL) {
        return false;
    }
    *slash = '\0';

    errno = 0;
    plen = strtoul(slash + 1, &end, 10);
    if(*(slash + 1) == '\0' || *end != '\0' || errno != 0) {
        return false;
    }

    memset(addr, 0, 16);
    if(conf_parse_ipv4(buf, (__be32 *)addr)) {
        *is_v6 = false;
        width = 4;
    } else if(conf_parse_ipv6(buf, addr)) {
        *is_v6 = true;
        width = 16;
    } else {
        return false;
    }

    if(plen > (unsigned long)width * 8) {
        return false;
    }
    *prefixlen = (__u32)plen;
    return true;
}

/*
 * True if any bit at or beyond prefixlen is set. conf_parse_cidr() reports
 * the address exactly as given -- docs/design/20-configuration-validation.md
 * rejects a set host bit rather than silently masking it, since 10.1.2.3/8
 * and 10.0.0.0/8 would otherwise become the same trie key with no sign a
 * rule was lost -- so the caller checks this before storing the prefix.
 */
bool conf_cidr_host_bits_set(const __u8 addr[16], __u32 prefixlen, bool is_v6)
{
    int width = is_v6 ? 16 : 4;

    for(int byte = 0; byte < width; byte++) {
        __u32 bit_base = (__u32)byte * 8;

        if(bit_base >= prefixlen) {
            if(addr[byte] != 0) {
                return true;
            }
        } else if(bit_base + 8 > prefixlen) {
            __u32 keep = prefixlen - bit_base;
            __u8 mask = (__u8)(0xff << (8 - keep));

            if((addr[byte] & (__u8)~mask) != 0) {
                return true;
            }
        }
    }
    return false;
}
