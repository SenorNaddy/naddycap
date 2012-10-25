#ifndef _PROCESS_ANONYMIZE_H
#define _PROCESS_ANONYMIZE_H

#include "libtrace.h"
#include <stdio.h>
#include "../includes/plugin.h"
#include <string.h>
#include <arpa/inet.h>

static void update_in_cksum(uint16_t *csum, uint16_t old, uint16_t new);
static void update_in_cksum32(uint16_t *csum, uint32_t old, uint32_t new);
uint32_t enc_ip4(uint32_t old_ip);
void enc_ip6(uint8_t old_ip[], void **new_ip);
void replace_ip6(struct libtrace_ip6 *ip6, libtrace_packet_t *p, int enc_src, int enc_dst);
void replace_ip4(struct libtrace_ip *ip, int enc_src, int enc_dst);

extern int simple_remove;
extern int enc_source;
extern int enc_dest;
extern int prefix_replace;
extern int prefix_preserve;
extern uint32_t prefix4;
extern uint32_t netmask4;
extern uint32_t netmask6[4];
extern uint8_t prefix6[16];

extern uint32_t masks[33];
#endif
