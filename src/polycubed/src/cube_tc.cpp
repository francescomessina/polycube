/*
 * Copyright 2016 PLUMgrid
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

#include "cube_tc.h"
#include "datapath_log.h"
#include "exceptions.h"
#include "patchpanel.h"
#include "port.h"

#include "utils.h"

#include <iostream>

namespace polycube {
namespace polycubed {

CubeTC::CubeTC(const std::string &name,
               const std::string &service_name,
               const std::vector<std::string> &ingress_code,
               const std::vector<std::string> &egress_code,
               LogLevel level, bool shadow)
    : Cube(name, service_name,
           PatchPanel::get_tc_instance(),
           PatchPanel::get_tc_instance(),
           level, CubeType::TC, shadow) {
  // it has to be done here becuase it needs the load, compile methods
  // to be ready
  Cube::init(ingress_code, egress_code);

  if (shadow) {
    auto res = ingress_programs_[0]->open_perf_buffer("shadow_slowpath", call_back_proxy, nullptr, this);
    if (res.code() != 0) {
      logger->error("cannot open perf ring buffer for shadow_slowpath: {0}", res.msg());
      throw BPFError("cannot open shadow_slowpath perf buffer");
    }
    start();
  }
}

void CubeTC::call_back_proxy(void *cb_cookie, void *data, int data_size) {
  PacketIn *md = static_cast<PacketIn *>(data);

  uint8_t *data_ = static_cast<uint8_t *>(data);
  data_ += sizeof(PacketIn);

  CubeTC *cube = static_cast<CubeTC *>(cb_cookie);
  if (cube == nullptr)
    throw std::runtime_error("Bad cube");

  std::vector<uint8_t> packet(data_, data_ + md->packet_len);

  auto in_port = cube->ports_by_index_.at(md->port_id);

  //check if the interface is a tail call
  if (cube->is_a_tap(in_port->name())) 
    polycube::polycubed::utils::send_packet_linux(in_port->name(), packet);
}

void CubeTC::start() {
  // create a thread that polls the perf ring buffer
  auto f = [&]() -> void {
    stop_ = false;
    while (!stop_) {
      ingress_programs_[0]->poll_perf_buffer("shadow_slowpath", 500);
    }

    // TODO: this causes a segmentation fault
    //  logger->debug("controller: stopping");
  };

  std::unique_ptr<std::thread> uptr(new std::thread(f));
  pkt_in_thread_ = std::move(uptr);
}

void CubeTC::stop() {
  //  logger->debug("controller stop()");
  stop_ = true;
  if (pkt_in_thread_) {
    //  logger->debug("trying to join controller thread");
    pkt_in_thread_->join();
  }
}

CubeTC::~CubeTC() {
  // it cannot be done in Cube::~Cube() because calls a virtual method
  if (shadow_)
    stop();
  Cube::uninit();
}

void CubeTC::do_compile(int id, ProgramType type, LogLevel level_,
                        ebpf::BPF &bpf, const std::string &code, int index, bool shadow) {
  // compile ebpf program
  std::string all_code(CUBE_H + WRAPPERC + \
   DatapathLog::get_instance().parse_log(code));

#ifdef LOG_COMPILEED_CODE
  Cube::log_compileed_code(all_code);
#endif

  std::vector<std::string> cflags_(cflags);
  cflags_.push_back("-DCUBE_ID=" + std::to_string(id));
  cflags_.push_back("-DSHADOW=" + std::to_string(shadow));
  cflags_.push_back("-DLOG_LEVEL=LOG_" + logLevelString(level_));
  cflags_.push_back(std::string("-DCTXTYPE=") + std::string("__sk_buff"));

#ifdef LOG_COMPILATION_TIME
  auto start = std::chrono::high_resolution_clock::now();
#endif

  std::lock_guard<std::mutex> guard(bcc_mutex);
  auto init_res = bpf.init(all_code, cflags_);

#ifdef LOG_COMPILATION_TIME
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> elapsed_seconds = end - start;
  logger->info("+bpf.init: {0}s", elapsed_seconds.count());
#endif

  if (init_res.code() != 0) {
    //logger->error("failed to init bpf program: {0}", init_res.msg());
    throw BPFError("failed to init ebpf program: " + init_res.msg());
  }
}

int CubeTC::do_load(ebpf::BPF &bpf) {
 int fd_;

#ifdef LOG_COMPILATION_TIME
  auto start = std::chrono::high_resolution_clock::now();
#endif

  std::lock_guard<std::mutex> guard(bcc_mutex);
  auto load_res =
      bpf.load_func("handle_rx_wrapper", BPF_PROG_TYPE_SCHED_CLS, fd_);

#ifdef LOG_COMPILATION_TIME
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> elapsed_seconds = end - start;
  logger->info("+bpf.load_func: {0}s", elapsed_seconds.count());
#endif

  if (load_res.code() != 0) {
    //logger->error("failed to load bpf program: {0}", load_res.msg());
    throw BPFError("failed to load bpf program: " + load_res.msg());
  }

  return fd_;
}

void CubeTC::do_unload(ebpf::BPF &bpf) {
#ifdef LOG_COMPILATION_TIME
  auto start = std::chrono::high_resolution_clock::now();
#endif

  std::lock_guard<std::mutex> guard(bcc_mutex);
  auto load_res = bpf.unload_func("handle_rx_wrapper");

#ifdef LOG_COMPILATION_TIME
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> elapsed_seconds = end - start;
  logger->info("+bpf.unload_func: {0}s", elapsed_seconds.count());
#endif
  // TODO: what to do with load_res?
}

void CubeTC::compile(ebpf::BPF &bpf, const std::string &code, int index,
                     ProgramType type) {
  do_compile(get_id(), type, level_, bpf, code, index, shadow_);
}

int CubeTC::load(ebpf::BPF &bpf, ProgramType type) {
  return do_load(bpf);
}

void CubeTC::unload(ebpf::BPF &bpf, ProgramType type) {
  do_unload(bpf);
}

const std::string CubeTC::WRAPPERC = R"(
BPF_TABLE("extern", int, int, nodes, _POLYCUBE_MAX_NODES);
BPF_PERF_OUTPUT(shadow_slowpath);

static __always_inline
int to_controller_shadow(struct CTXTYPE *skb, struct pkt_metadata md) {
  int r = shadow_slowpath.perf_submit_skb(skb, md.packet_len, &md, sizeof(md));
  if (r != 0) {
    bpf_trace_printk("Shadow controller error: %d\n", r);
  }
  return r;
}

static __always_inline
int forward(struct CTXTYPE *skb, u32 out_port) {
  u32 *next = forward_chain_.lookup(&out_port);
  if (next) {

    if (SHADOW) {
      struct pkt_metadata md = {};
      md.in_port = out_port;
      md.cube_id = CUBE_ID;
      md.packet_len = skb->len;
      to_controller_shadow(skb, md);
    }

    skb->cb[0] = *next;
    //bpf_trace_printk("fwd: port: %d, next: 0x%x\n", out_port, *next);
    nodes.call(skb, *next & 0xffff);
  }
  //bpf_trace_printk("fwd:%d=0\n", out_port);
  return TC_ACT_SHOT;
}

static __always_inline
int to_controller(struct CTXTYPE *skb, u16 reason) {
  skb->cb[1] = reason;
  nodes.call(skb, CONTROLLER_MODULE_INDEX);
  //bpf_trace_printk("to controller miss\n");
  return TC_ACT_OK;
}

int handle_rx_wrapper(struct CTXTYPE *skb) {
  //bpf_trace_printk("" MODULE_UUID_SHORT ": rx:%d\n", skb->cb[0]);
  struct pkt_metadata md = {};
  volatile u32 x = skb->cb[0]; // volatile to avoid a rare verifier error
  md.in_port = x >> 16;
  md.cube_id = CUBE_ID;
  md.packet_len = skb->len;
  skb->cb[0] = md.in_port << 16 | CUBE_ID;

  if (SHADOW)
    to_controller_shadow(skb, md);

  int rc = handle_rx(skb, &md);

  switch (rc) {
    case RX_REDIRECT:
      // FIXME: reason is right, we are reusing the field
      return forward(skb, md.reason);
    case RX_DROP:
      return TC_ACT_SHOT;
    case RX_CONTROLLER:
      return to_controller(skb, md.reason);
    case RX_OK:
      //to_controller_shadow(skb, md);
      return TC_ACT_OK;
  }
  return TC_ACT_SHOT;
}

static __always_inline
int pcn_pkt_redirect(struct CTXTYPE *skb,
                     struct pkt_metadata *md, u32 port) {
  // FIXME: this is just to reuse this field
  md->reason = port;
  return RX_REDIRECT;
}

static __always_inline
int pcn_pkt_drop(struct CTXTYPE *skb, struct pkt_metadata *md) {
  return RX_DROP;
}

static __always_inline
int pcn_pkt_controller(struct CTXTYPE *skb, struct pkt_metadata *md,
                       u16 reason) {
  md->reason = reason;
  return RX_CONTROLLER;
}

static __always_inline
int pcn_pkt_controller_with_metadata_stack(struct CTXTYPE *skb,
                                           struct pkt_metadata *md,
                                           u16 reason,
                                           u32 metadata[3]) {
  skb->cb[0] |= 0x8000;
  skb->cb[2] = metadata[0];
  skb->cb[3] = metadata[1];
  skb->cb[4] = metadata[2];
  return pcn_pkt_controller(skb, md, reason);
}

static __always_inline
int pcn_pkt_controller_with_metadata(struct CTXTYPE *skb,
                                     struct pkt_metadata *md,
                                     u16 reason,
                                     u32 metadata[3]) {
  skb->cb[2] = metadata[0];
  skb->cb[3] = metadata[1];
  skb->cb[4] = metadata[2];
  return pcn_pkt_controller(skb, md, reason);
}

/* checksum related */
static __always_inline
int pcn_l3_csum_replace(struct CTXTYPE *ctx, u32 csum_offset,
                        u32 old_value, u32 new_value, u32 flags) {
  return bpf_l3_csum_replace(ctx, csum_offset, old_value, new_value, flags);
}

static __always_inline
int pcn_l4_csum_replace(struct CTXTYPE *ctx, u32 csum_offset,
                        u32 old_value, u32 new_value, u32 flags) {
  return bpf_l4_csum_replace(ctx, csum_offset, old_value, new_value, flags);
}

static __always_inline
__wsum pcn_csum_diff(__be32 *from, u32 from_size, __be32 *to,
                     u32 to_size, __wsum seed) {
  return bpf_csum_diff(from, from_size, to, to_size, seed);
}
)";

}  // namespace polycubed
}  // namespace polycube
