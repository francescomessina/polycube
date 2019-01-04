/*
 * Copyright 2017 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <bcc/helpers.h>
#include <bcc/proto.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/if_arp.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#define RULES_MAP_DIM 256
#define SLOWPATH_ARP 1

struct eth_hdr {
  __be64 dst : 48;
  __be64 src : 48;
  __be16 proto;
} __attribute__((packed));
struct arp_hdr {
  __be16 ar_hrd;        /* format of hardware address	*/
  __be16 ar_pro;        /* format of protocol address	*/
  unsigned char ar_hln; /* length of hardware address	*/
  unsigned char ar_pln; /* length of protocol address	*/
  __be16 ar_op;         /* ARP opcode (command)		*/
  __be64 ar_sha : 48;   /* sender hardware address	*/
  __be32 ar_sip;        /* sender IP address		*/
  __be64 ar_tha : 48;   /* target hardware address	*/
  __be32 ar_tip;        /* target IP address		*/
} __attribute__((packed));

// Session table
struct st_k {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t proto;
};

// Session table
BPF_TABLE_SHARED("hash", struct st_k, int, session_table, RULES_MAP_DIM);

// BPF map of single element that saves the action to be applied in packets
BPF_ARRAY(action_map, uint8_t, 1);

// BPF map where the ids of the ports are saved. This module supports at most two ports
BPF_ARRAY(ports_map, uint16_t, 2);

enum {
  DROP,       // drop packet
  LINUX,      // send packet to host stack (Linux)
  POLYCUBE,   // send packet to Polycube chain
};

static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  pcn_log(ctx, LOG_TRACE, "ingress: receiving packet from port %d", md->in_port);

  unsigned int zero = 0;
  unsigned int one = 1;
  uint8_t *action = action_map.lookup(&zero);
  if (!action) {
    goto DROP;
  }

  // Get ports ids
  uint16_t *interface = ports_map.lookup(&zero);
  if (!interface) {
    goto DROP;
  }
  uint16_t *polycube = ports_map.lookup(&one);
  if (!polycube) {
    goto DROP;
  }

  // Parse packet
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct eth_hdr *eth = data;
  if (data + sizeof(*eth) > data_end)
    goto DROP;

  switch (eth->proto) {
    case htons(ETH_P_IP):   // Packet is IP
      goto IP;
    case htons(ETH_P_ARP): { // Packet is ARP
      struct arp_hdr *arp = data + sizeof(*eth);
      if (data + sizeof(*eth) + sizeof(*arp) > data_end)
        goto DROP;
      u32 mdata[3];
      mdata[0] = arp->ar_sip;
      return pcn_pkt_controller_with_metadata_stack(ctx, md, SLOWPATH_ARP, mdata);
    }
    default:
      pcn_log(ctx, LOG_TRACE, "ingress: unknown eth proto: %d, dropping", bpf_ntohs(eth->proto));
      goto DROP;
  }

IP:;  // ipv4 packet

  // Packet data
  uint32_t srcIp = 0;
  uint32_t dstIp = 0;
  uint16_t srcPort = 0;
  uint16_t dstPort = 0;
  uint8_t proto = 0;

  struct iphdr *ip = data + sizeof(*eth);
  if (data + sizeof(*eth) + sizeof(*ip) > data_end)
    goto DROP;

  pcn_log(ctx, LOG_TRACE, "ingress: processing IP packet: src %I, dst: %I", ip->saddr, ip->daddr);

  srcIp = ip->saddr;
  dstIp = ip->daddr;
  proto = ip->protocol;

  switch (ip->protocol) {
    case IPPROTO_TCP: {
      struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
      if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        goto DROP;
      pcn_log(ctx, LOG_TRACE, "ingress: packet is TCP: src_port %P, dst_port %P", tcp->source, tcp->dest);
      srcPort = tcp->source;
      dstPort = tcp->dest;
      break;
    }
    case IPPROTO_UDP: {
      struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip);
      if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        goto DROP;
      pcn_log(ctx, LOG_TRACE, "ingress: packet is UDP: src_port %P, dst_port %P", udp->source, udp->dest);
      srcPort = udp->source;
      dstPort = udp->dest;
      break;
    }
    case IPPROTO_ICMP: {
      struct icmphdr *icmp = data + sizeof(*eth) + sizeof(*ip);
      if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) > data_end)
        goto DROP;
      pcn_log(ctx, LOG_TRACE, "ingress: packet is ICMP: type %d, id %d", icmp->type, icmp->un.echo.id);

      // Consider the ICMP ID as a "port" number for easier handling
      srcPort = icmp->un.echo.id;
      dstPort = icmp->un.echo.id;
      break;
    }
    default:
      pcn_log(ctx, LOG_TRACE, "ingress: unknown L4 proto %d, dropping", ip->protocol);
      goto DROP;
  }

  struct st_k key = {0, 0, 0, 0, 0};

  if (md->in_port == 1) { // Packet received from Polycube
    key.src_ip = srcIp;
    key.dst_ip = dstIp;
    key.src_port = srcPort;
    key.dst_port = dstPort;
    key.proto = proto;

    int *value = session_table.lookup(&key);
    if (!value) { // There is no rule, it is added
      pcn_log(ctx, LOG_DEBUG, "ingress: src %I, dst: %I, src_port %P, dst_port %P", srcIp, dstIp, srcPort, dstPort);
      int port_ = 1;
      session_table.update(&key, &port_);
    }
    return pcn_pkt_redirect(ctx, md, *interface);

  } else {  // Packet received from Linux or extern
    key.src_ip = dstIp;
    key.dst_ip = srcIp;
    key.src_port = dstPort;
    key.dst_port = srcPort;
    key.proto = proto;

    int *value = session_table.lookup(&key);
    if (!value) { // There is no rule, send to Linux
      pcn_log(ctx, LOG_DEBUG, "ingress: src %I, dst: %I, src_port %P, dst_port %P", srcIp, dstIp, srcPort, dstPort);
      goto END;
    } else { // There is rule, send to Polycube
      return pcn_pkt_redirect(ctx, md, *polycube);
    }

  }

END:;
  pcn_log(ctx, LOG_TRACE, "ingress: RX_OK on packet");
  return RX_OK;

DROP:;
  pcn_log(ctx, LOG_TRACE, "ingress: dropping packet");
  return RX_DROP;
}






/*******************************************************************************/

/*
DEFAULT:;  // default action
  // what action should be performed in the packet?
  switch (*action) {
  case DROP:
    pcn_log(ctx, LOG_DEBUG, "dropping packet");
    goto DROP;
  case LINUX:
    pcn_log(ctx, LOG_DEBUG, "sending packet to host stack (Linux)");
    return RX_OK;
  case POLYCUBE:
    pcn_log(ctx, LOG_DEBUG, "sending packet to Polycube chain");
    if (md->in_port == *interface)
      return pcn_pkt_redirect(ctx, md, *polycube);
    else if (md->in_port == *polycube)
      return pcn_pkt_redirect(ctx, md, *interface);
    else {
      pcn_log(ctx, LOG_ERR, "bad in_port: %d", md->in_port);
      goto DROP;
    }
  default:
    pcn_log(ctx, LOG_ERR, "bad action %d", *action);
    goto DROP;
  }
*/
