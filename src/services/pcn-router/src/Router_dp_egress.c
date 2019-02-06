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
#include <uapi/linux/udp.h>

enum {
  SLOWPATH_ARP_REPLY = 1,
  SLOWPATH_ARP_LOOKUP_MISS,
  SLOWPATH_TTL_EXCEEDED,
  SLOWPATH_PKT_FOR_ROUTER,
  INGRESS_TRAFFIC_FOR_LINUX,
  EGRESS_TRAFFIC_FOR_LINUX
};

// BPF table of single element that saves the shadow attribute
BPF_TABLE("extern", int, bool, shadow_, 1);

static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  pcn_log(ctx, LOG_DEBUG, "EGRESS: Packet ongoing on port %d", md->in_port);

// in realtà credo che questa funzione serva solo per il traffico in egress su un interfaccia fisica
// quando si tratta di interfaccie interne, quelle sono chiamate a funzioni ebpf che questa funzione non cattura
// bisogna trovare un altro modo

  unsigned int zero = 0;
  bool *shadow = shadow_.lookup(&zero);
  if (!shadow) {
    return RX_DROP;
  }

  if (*shadow) {
    pcn_log(ctx, LOG_INFO, "EGRESS: shadow true, Packet ongoing on port %d", md->in_port);
    u32 mdata[3];
    mdata[0] = md->in_port;
    return pcn_pkt_controller_with_metadata_stack(ctx, md, EGRESS_TRAFFIC_FOR_LINUX, mdata);
  }

  return RX_OK;
}
