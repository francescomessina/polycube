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

#include "Router.h"
#include "Utils.h"

/*utility methods*/

std::string from_int_to_hex(int t) {
  std::stringstream stream;
  stream << "0x" << std::hex << t;
  return stream.str();
}

uint32_t get_netmask_length(const std::string &netmask_string) {
  struct in_addr buf;
  char address[100];
  int res = inet_pton(
      AF_INET, netmask_string.c_str(),
      &buf); /*convert ip address in binary form in network byte order */

  if (res == 1) {
    uint32_t counter = 0;
    int n = buf.s_addr;
    while (n) {
      counter++;
      n &= (n - 1);
    }
    return counter;
  } else
    throw std::runtime_error("IP Address is not in a valide format");
}

unsigned int ip_to_int(const char *ip) {
  unsigned value = 0;
  // bytes processed.
  int i;
  // next digit to process.
  const char *start;

  start = ip;
  for (i = 0; i < 4; i++) {
    char c;
    int n = 0;
    while (1) {
      c = *start;
      start++;
      if (c >= '0' && c <= '9') {
        n *= 10;
        n += c - '0';
      }
      /* We insist on stopping at "." if we are still parsing
         the first, second, or third numbers. If we have reached
         the end of the numbers, we will allow any character. */
      else if ((i < 3 && c == '.') || i == 3) {
        break;
      } else {
        std::string to_ip(ip);
        throw std::runtime_error("Ip address is not in a valide format");
      }
    }
    if (n >= 256) {
      throw std::runtime_error("Ip address is not in a valide format");
    }
    value *= 256;
    value += n;
  }
  return value;
}

bool address_in_subnet(const std::string &ip,
                               const std::string &netmask,
                               const std::string &network) {
  uint32_t ipAddress = ip_to_int(ip.c_str());
  uint32_t mask = ip_to_int(netmask.c_str());
  uint32_t net = ip_to_int(network.c_str());
  if ((ipAddress & mask) == (net & mask))
    return true;
  else
    return false;
}

std::string get_network_from_ip(const std::string &ip,
                                        const std::string &netmask) {
  // get the network from ip
  uint32_t address = ip_to_int(ip.c_str());
  uint32_t mask = ip_to_int(netmask.c_str());
  uint32_t net = address & mask;
  char buffer[100];
  sprintf(buffer, "%d.%d.%d.%d", (net >> 24) & 0xFF, (net >> 16) & 0xFF,
          (net >> 8) & 0xFF, (net)&0xFF);
  std::string network(buffer);
  return network;
}

bool is_netmask_valid(const std::string &netmask) {
  uint32_t mask = ip_to_int(netmask.c_str());
  /*if (mask == 0)
    return false;*/
  if (mask & (~mask >> 1)) {
    return false;
  } else {
    return true;
  }
}

std::string get_netmask_from_CIDR(const int cidr) {
  uint32_t ipv4Netmask;

  ipv4Netmask = 0xFFFFFFFF;
  ipv4Netmask <<= 32 - cidr;
  ipv4Netmask = ntohl(ipv4Netmask);
  struct in_addr addr = {ipv4Netmask};

  return inet_ntoa(addr);
}

std::string read_routing_table_linux() {
  // variable to be returned
  std::string routing_table_linux;

  // buffer to hold the RTNETLINK request
  struct {
    struct nlmsghdr nl;
    struct rtmsg rt;
    char buf[8192];
  } req;

  // variables used for socket communications
  int sock;
  struct sockaddr_nl la;
  struct sockaddr_nl pa;
  struct msghdr msg;
  struct iovec iov;
  int rtn;

  // buffer to hold the RTNETLINK reply(ies)
  char buf[8192];

  // RTNETLINK message pointers and lengths used when processing messages
  struct nlmsghdr *nlp;
  int nll;
  struct rtmsg *rtp;
  int rtl;
  struct rtattr *rtap;

  // open netlink socket;
  sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  // setup local address and bind using this address
  bzero(&la, sizeof(la));
  la.nl_family = AF_NETLINK;
  la.nl_pid = getpid();
  bind(sock, (struct sockaddr *)&la, sizeof(la));

  // form request for the linux routing table
  // initialize the request buffer
  bzero(&req, sizeof(req));

  // set the NETLINK header
  req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nl.nlmsg_type = RTM_GETROUTE;

  // set the routing message header
  req.rt.rtm_family = AF_INET;
  req.rt.rtm_table = RT_TABLE_MAIN;

  // create the remote address to communicate
  bzero(&pa, sizeof(pa));
  pa.nl_family = AF_NETLINK;

  // initialize and create the struct msghdr supplied to the sendmsg() function
  bzero(&msg, sizeof(msg));
  msg.msg_name = (void *)&pa;
  msg.msg_namelen = sizeof(pa);

  // place the pointer and size of the RTNETLINK
  // message in the struct msghdr
  iov.iov_base = (void *)&req.nl;
  iov.iov_len = req.nl.nlmsg_len;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  // send the RTNETLINK message to kernel
  rtn = sendmsg(sock, &msg, 0);

  // receive reply after form_request
  // initialize the socket read buffer
  bzero(buf, sizeof(buf));

  char *p;
  p = buf;
  nll = 0;

  // read from the socket until the NLMSG_DONE is returned
  while (1) {
    rtn = recv(sock, p, sizeof(buf) - nll, 0);

    nlp = (struct nlmsghdr *)p;

    if (nlp->nlmsg_type == NLMSG_DONE)
      break;

    // increment the buffer pointer to place next message
    p += rtn;

    // increment the total size by the size of the last received message
    nll += rtn;

    if ((la.nl_groups & RTMGRP_IPV4_ROUTE) == RTMGRP_IPV4_ROUTE)
      break;
  }

  // strings to hold content of the route table
  char dsts[24], gws[24], ifs[16], ms[24];

  // outer loop: loops thru all the NETLINK headers that also include the route
  // entry header
  nlp = (struct nlmsghdr *)buf;
  for (; NLMSG_OK(nlp, nll); nlp = NLMSG_NEXT(nlp, nll)) {
    // get route entry header
    rtp = (struct rtmsg *)NLMSG_DATA(nlp);

    // we are only concerned about the main route table
    if (rtp->rtm_table != RT_TABLE_MAIN)
      continue;

    // init all the strings
    bzero(dsts, sizeof(dsts));
    bzero(gws, sizeof(gws));
    bzero(ifs, sizeof(ifs));
    bzero(ms, sizeof(ms));

    // inner loop: loop thru all the attributes of one route entry
    rtap = (struct rtattr *)RTM_RTA(rtp);
    rtl = RTM_PAYLOAD(nlp);
    for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
      switch (rtap->rta_type) {
      // destination IPv4 address
      case RTA_DST:
        inet_ntop(AF_INET, RTA_DATA(rtap), dsts, 24);
        break;

      // next hop IPv4 address
      case RTA_GATEWAY:
        inet_ntop(AF_INET, RTA_DATA(rtap), gws, 24);
        break;

      // unique ID associated with the network interface
      case RTA_OIF:
        sprintf(ifs, "%d", *((int *)RTA_DATA(rtap)));
      default:
        break;
      }
    }
    sprintf(ms, "%d", rtp->rtm_dst_len);

    char temp[200];
    char name_interface[20];
    if_indextoname(std::stoi(ifs), name_interface);

    std::string dest(dsts);
    if (dest == "") {
      sprintf(dsts, "0.0.0.0");
      sprintf(ms, "0");
    }

    std::string gw(gws);
    if (gw == "") {
      sprintf(gws, "0.0.0.0");
    }
    sprintf(temp, "%s %s %s %s %s\n", name_interface, ifs, dsts, ms, gws);

    routing_table_linux.append(temp);
  }

  // close socket
  close(sock);

  return routing_table_linux;
}
