/*
 * Copyright 2018 The Polycube Authors
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


//Modify these methods with your own implementation


#include "Router.h"
#include "Router_dp.h"

using utils::ip_string_to_be_uint;
using utils::be_uint_to_ip_string;

enum {
  SLOWPATH_ARP_REPLY = 1,
  SLOWPATH_ARP_LOOKUP_MISS,
  SLOWPATH_TTL_EXCEEDED,
  SLOWPATH_PKT_FOR_ROUTER
};

Router::Router(const std::string name, const RouterJsonObject &conf,
               CubeType type)
  : Cube(name, {generate_code()}, {}, type, conf.getPolycubeLoglevel()) {
  logger()->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [Router] [%n] [%l] %v");
  logger()->info("creating Router instance");

  addArpEntryList(conf.getArpEntry());
  addRouteList(conf.getRoute());

  addPortsList(conf.getPorts());

  // netlink notification
  netlink_notification_index_route_added = netlink_instance.registerObserver(
    polycube::polycubed::Netlink::Event::ROUTE_ADDED,
    std::bind(&Router::netlink_notification_route_added, this,
              std::placeholders::_1, std::placeholders::_2));

  netlink_notification_index_route_deleted = netlink_instance.registerObserver(
    polycube::polycubed::Netlink::Event::ROUTE_DELETED,
    std::bind(&Router::netlink_notification_route_deleted, this,
              std::placeholders::_1, std::placeholders::_2));

  netlink_notification_index_link_added = netlink_instance.registerObserver(
    polycube::polycubed::Netlink::Event::LINK_ADDED,
    std::bind(&Router::netlink_notification_link_added, this,
              std::placeholders::_1, std::placeholders::_2));

  netlink_notification_index_link_deleted = netlink_instance.registerObserver(
    polycube::polycubed::Netlink::Event::LINK_DELETED,
    std::bind(&Router::netlink_notification_link_deleted, this,
              std::placeholders::_1, std::placeholders::_2));

  netlink_notification_index_new_address = netlink_instance.registerObserver(
    polycube::polycubed::Netlink::Event::NEW_ADDRESS,
    std::bind(&Router::netlink_notification_new_address, this,
              std::placeholders::_1, std::placeholders::_2));
}

Router::~Router() {
  netlink_instance.unregisterObserver(
      polycube::polycubed::Netlink::Event::ROUTE_ADDED,
      netlink_notification_index_route_added);
  netlink_instance.unregisterObserver(
      polycube::polycubed::Netlink::Event::ROUTE_DELETED,
      netlink_notification_index_route_deleted);
  netlink_instance.unregisterObserver(
      polycube::polycubed::Netlink::Event::LINK_ADDED,
      netlink_notification_index_link_added);
  netlink_instance.unregisterObserver(
      polycube::polycubed::Netlink::Event::LINK_DELETED,
      netlink_notification_index_link_deleted);
  netlink_instance.unregisterObserver(
      polycube::polycubed::Netlink::Event::NEW_ADDRESS,
      netlink_notification_index_new_address);
}

void Router::update(const RouterJsonObject &conf) {
  //This method updates all the object/parameter in Router object specified in the conf JsonObject.
  //You can modify this implementation.

  if(conf.loglevelIsSet()) {
    setLoglevel(conf.getLoglevel());
  }

  if(conf.arpEntryIsSet()) {
    for(auto &i : conf.getArpEntry()){
      auto address = i.getAddress();
      auto m = getArpEntry(address);
      m->update(i);
    }
  }

  if(conf.routeIsSet()) {
    for(auto &i : conf.getRoute()){
      auto network = i.getNetwork();
      auto netmask = i.getNetmask();
      auto nexthop = i.getNexthop();
      auto m = getRoute(network, netmask, nexthop);
      m->update(i);
    }
  }

  if(conf.portsIsSet()) {
    for(auto &i : conf.getPorts()){
      auto name = i.getName();
      auto m = getPorts(name);
      m->update(i);
    }
  }
}

RouterJsonObject Router::toJsonObject(){
  RouterJsonObject conf;

  conf.setName(getName());

  conf.setLoglevel(getLoglevel());

  for(auto &i : getArpEntryList()){
    conf.addArpEntry(i->toJsonObject());
  }

  for(auto &i : getRouteList()){
    conf.addRoute(i->toJsonObject());
  }

  conf.setType(getType());

  for(auto &i : getPortsList()){
    conf.addPorts(i->toJsonObject());
  }

  conf.setUuid(getUuid());

  return conf;
}

std::string Router::generate_code(){
  return router_code;
}

std::vector<std::string> Router::generate_code_vector(){
  throw std::runtime_error("method Router::generate_code_vector not implemented");
}

void Router::packet_in(Ports &port,
                       PacketInMetadata &md,
                       const std::vector<uint8_t> &packet){
  logger()->debug("packet received from port {0}", port.name());

  switch (md.reason) {
  case SLOWPATH_TTL_EXCEEDED:
    generate_icmp_ttlexceed(port, md, packet);
    break;

  case SLOWPATH_ARP_LOOKUP_MISS:
    generate_arp_request(port, md, packet);
    break;

  case SLOWPATH_ARP_REPLY:
    generate_arp_reply(port, md, packet);
    break;

  case SLOWPATH_PKT_FOR_ROUTER:
    handle_router_pkt(port, md, packet);
    break;

  default:
    logger()->error("not valid reason {0} received", md.reason);
  }
}

/*
* Methods to manage routing table in the datapath
*/

/*
* Given a nexthop, selects the proper interface of the router to reach it
*/
std::string Router::search_interface_from_nexthop(const std::string &nexthop) {

  for (auto item : routes_) {
    auto &network_  = std::get<0>(item.first);
    auto &netmask_ = std::get<1>(item.first);
    auto &nexthop_ = std::get<2>(item.first);
    // ignore non directly reachable routes
    if (nexthop_ != "local" && nexthop_ != "0.0.0.0") {
      continue;
    }

    if (address_in_subnet(network_, netmask_, nexthop)) {
      return item.second.getInterface();
    }
  }

  throw std::runtime_error("Non reacheable " + nexthop + " network");
}

/*
* Given a route, add it to the datapath in case its cost is the best one
* towards the given destination
*/
void Router::add_active_nexthop_in_ebpf_map(const std::string &network,
                                       const std::string &netmask,
                                       const std::string &nexthop,
                                       int32_t new_pathcost,
                                       const int &port_id) {

  int index = port_id;
  std::string new_nexthop = nexthop;
  int32_t min = INT32_MAX;

  //Iterate over the current elements of the routing table

  for (auto elem : routes_) {
    if (elem.second.getNetwork() == network &&
        elem.second.getNetmask() == netmask) {
      if (elem.second.getNexthop() == "local") {
        logger()->debug("there is a local entry. Route do not added to the datapath");
        return; // there is a local entry yet
      }

      if (elem.second.pathcostIsSet() && elem.second.getPathcost() < min) {
        new_nexthop = elem.second.getNexthop();
        min = elem.second.getPathcost();
      }
    }
  }

  if (new_pathcost < min) {
    logger()->debug("the new path cost '{0}' is better than the previous '{1}'",
                     new_pathcost, min);
    new_nexthop = nexthop;  //the new path is better than the old one, so we update the nexthop
  } else {
    //in this case we don't update the nexthop, as the old one is better than the new
    logger()->debug("the new path cost '{0}' is worse than the previous '{1}'",
                    new_pathcost, min);
    index = get_port(search_interface_from_nexthop(new_nexthop))->index();
  }

  // the key in the datapath is given by "network" and "mask length".
  // then, if the nexthop changes, we just replace its value.
  // Please, note that the pathcost is not provided to the datapath, which only keeps the best route
  // for each destination

  auto routing_table = get_hash_table<rt_k, rt_v>("routing_table");

  rt_k key {
    .netmask_len = get_netmask_length(netmask),
    .network = ip_string_to_be_uint(network),
  };

  rt_v value {
    .port = uint32_t(index),
    .nexthop = ip_string_to_be_uint(nexthop),
    .type = TYPE_NOLOCALINTERFACE,
  };

  routing_table.set(key, value);
}

/*
* Remove a route. The route is removed from the control plane and, if it is also in the data plane, from the data plane as well.
* If the control plane has another route for the involved network, such a route is then added to the data plane.
*/
void Router::remove_route(const std::string &network,
                          const std::string &netmask,
                          const std::string &nexthop) {

  std::tuple<string,string,string> key (network,netmask,nexthop);

  if (routes_.count(key) == 0)
    throw std::runtime_error("Route does not exist");

  routes_.erase(key);
  logger()->debug("removed route from control plane [network: {0} - netmask: {1} - nexthop: {2}]",
                  network, netmask, nexthop);

  find_new_active_nexthop(network, netmask, nexthop);
}

/*
* Remove all routes but those that are local
*/
void Router::remove_all_routes() {

  if (routes_.size() == 0)
    throw std::runtime_error("No entry found in routing table");

  logger()->debug("the routing table in the control plane has {0} entries",
                  routes_.size());

  auto routing_table = get_hash_table<rt_k, rt_v>("routing_table");

  for (auto it = routes_.begin(); it != routes_.end();) {
    if ((it->second.getNexthop()) != "local") {
      std::string network = it->second.getNetwork();
      std::string netmask = it->second.getNetmask();
      std::string nexthop = it->second.getNexthop();
      routes_.erase(it++);
      logger()->debug("removed route from control plane [network: {0} - netmask: {1} - nexthop: {2}]",
                      network, netmask, nexthop);

      //retrieve the entry from the fast path for the "netmask" "network", and get the nexthop in order to check whether the route is also in the fast path
      try {
        rt_k key {
          .netmask_len = get_netmask_length(netmask),
          .network = ip_string_to_be_uint(network),
        };

        rt_v value = routing_table.get(key);

        if (value.nexthop == ip_string_to_be_uint(nexthop)) {
          //  the nexthop in the fast path corresponds to that just removed in the control path
          //  then, the entry in the fast path is removed
          logger()->debug("route found in the data path");
          routing_table.remove(key);
        }
        else
          logger()->debug("route not found in the data path");
      }
      catch (...) {
        logger()->debug("route not found in the data path");
      }
    }
    else
    {
      logger()->debug("local route not removed [network: {0} - netmask: {1} - nexthop: {2}]",
                      it->second.getNetwork(), it->second.getNetmask(),
                      it->second.getNexthop());
      it++;
    }
  }
}

/*
* Add two local routes to the routing table
*/
void Router::add_local_route(const std::string &interface_ip,
                             const std::string &interface_netmask,
                             const std::string &port_name, const int port_index) {

  /*
  * Add the route to interface_ip/32 in the data path
  * The entry has key ("port ip address" "32") and value ("0.0.0.0" "local interface")
  */

  auto routing_table = get_hash_table<rt_k, rt_v>("routing_table");

  rt_k key {
    .netmask_len = 32, /* /32 -> 255.255.255.255 */
    .network = ip_string_to_be_uint(interface_ip),
  };

  rt_v value {
    .port = uint32_t(port_index),
    .nexthop = 0, /* 0.0.0.0 */
    .type = TYPE_LOCALINTERFACE,
  };

  routing_table.set(key, value);

  logger()->info("added route [network: {0} - netmask: {1} - nexthop: {2} - interface: {3}]",
                interface_ip, "255.255.255.255", "0.0.0.0", port_name);

  /*
  * Add a route to the local network, i.e., to the network directly reachable through the inteface
  */

  // Add the route in the fast path
  uint32_t networkDec = ip_string_to_be_uint(interface_ip) & ip_string_to_be_uint(interface_netmask);
  std::string network = be_uint_to_ip_string(networkDec);
  rt_k key2 {
    .netmask_len = get_netmask_length(interface_netmask),
    .network = networkDec,
  };

  rt_v value2 {
    .port = uint32_t(port_index),
    .nexthop = 0, /* 0.0.0.0 */
    .type = TYPE_NOLOCALINTERFACE,
  };

  routing_table.set(key2, value2);

  logger()->info("added route [network: {0} - netmask: {1} - nexthop: {2} - interface: {3}]",
                 network, interface_netmask, "0.0.0.0", port_name);

  // Add the route in the table of the control plane

  std::string nexthop("local");
  std::tuple<string,string,string> keyF (network,interface_netmask,nexthop);
  uint32_t pathcost = 0;

  routes_.emplace(std::piecewise_construct,std::forward_as_tuple(keyF),
    std::forward_as_tuple(*this, network, interface_netmask,
                          nexthop, port_name, pathcost));

  //FIXME: add also the /32 route?

  }

/*
* Remove two local route from the routing table
*/
void Router::remove_local_route(const std::string &interface_ip,
                             const std::string &interface_netmask,
                             const std::string &port_name) {

  std::string network = get_network_from_ip(interface_ip, interface_netmask);

  logger()->debug("removing routes involving the port {0} and the network {1}",
                  port_name, network);

  /*
  * Delete the route corresponding to the network directly connected to the port
  * The route is deleted both from the control plane and from the data plane
  */
  for (auto it = routes_.begin(); it != routes_.end();) {
    if (it->second.getNexthop() == "local" &&
        it->second.getInterface() == port_name &&
        it->second.getNetwork() == network) {
      routes_.erase(it++); //remove the route from the control plane
      logger()->debug("removed local route from the control plane [network: {0} - netmask: {1} - nexthop: {2} - interface: {3}]",
                      network, interface_netmask, "0.0.0.0", port_name);

      // Remove or update the route in the data path
      find_new_active_nexthop(network, interface_netmask, "0.0.0.0");
      break;
    }

    else
      ++it;
  }


  /*
  * Delete the routes having the next hop in the same network of the address that we are going to remove
  * If the route is also in the fast path, then
  * - delete it if there is no other route for the same network
  * - update it if there is, in the control plane, another route for the same network
  */

  logger()->debug("looking for other routes involving the port to be removed");

  for (auto it = routes_.begin(); it != routes_.end();) {
    if (it->second.getNexthop() != "local" /*"local" are those networks directly connected*/ &&
      address_in_subnet(it->second.getNexthop(), interface_netmask, network)) {
    //  it->second.getInterface() == port_name) {

      // If the nexthop is the same network of the address we are going to remove, then the route must be removed as well

      std::string cur_network(it->second.getNetwork());
      std::string cur_netmask(it->second.getNetmask());
      std::string cur_nexthop(it->second.getNexthop());
      std::string cur_interface(it->second.getInterface());

      routes_.erase(it++);

      logger()->debug("removed local route from the control plane [network: {0} - netmask: {1} - nexthop: {2} - interface: {3}]",
                      cur_network, cur_netmask, cur_nexthop, cur_interface);

      // check if the entry is also in the fast path and either remove or update it, according to the
      // fact that there is another nexthop for that network or not
      find_new_active_nexthop(cur_network, cur_netmask, cur_nexthop);
    }
    else
      ++it;
  }

  // Finally, remove the port_ip/32 route from the data path
  auto routing_table = get_hash_table<rt_k, rt_v>("routing_table");

  struct rt_k key {
    .netmask_len = 32, /* /32 -> 255.255.255.255 */
    .network = ip_string_to_be_uint(interface_ip),
  };

  routing_table.remove(key);
}

/*
* Looks for a nex nexthop for a destination network.
* If it is found, the route in the fastpath is updated, otherwise it is removed
*/
void Router::find_new_active_nexthop(const std::string &network,
                                     const std::string &netmask,
                                     const std::string &nexthop) {
  auto routing_table = get_hash_table<rt_k, rt_v>("routing_table");

  rt_k key {
    .netmask_len = get_netmask_length(netmask),
    .network = ip_string_to_be_uint(network),
  };
  rt_v value = routing_table.get(key);

  if (value.nexthop == ip_string_to_be_uint(nexthop)) {
    //  the nexthop in the fast path corresponds to that just removed in the control path
    //  then, the entry in the fast path is removed if no other nexthop is found, otherwise it is just updated
    //  if more than one other nexthop exists, we use that with smallest cost

    logger()->debug("route found in the data path");

    int32_t min = INT32_MAX;
    std::string new_nexthop;
    for (auto elem : routes_) {
      if (elem.second.getNetwork() == network &&
          elem.second.getNetmask() == netmask) {

        logger()->debug("alternative route found for network [network: {0} - netmask: {1} - nexthop: {2} - interface: {3} - cost: {4}]",
                        elem.second.getNetwork(), elem.second.getNetmask(),
                        elem.second.getNexthop(),elem.second.getInterface(),
                        elem.second.getPathcost());

        // these entry is for the network we are considering

        if (elem.second.getNexthop() == "local") {
          // a local entry is found for such a network. However it is very strange. In fact,
          // a network directly connected should have the smallest cost, then be alway active
          new_nexthop = "0.0.0.0";
          min = 0;
          break;
        }

        if (elem.second.pathcostIsSet() && elem.second.getPathcost() < min) {
          //the cost is better then the current one, then this is a candidate nexthop
          new_nexthop = elem.second.getNexthop();
          min = elem.second.getPathcost();
        }
      }
    }

    if (new_nexthop.empty()){
      //  no alternative nexthop is found, then the route is removed from the fastpath
      routing_table.remove(key);
      return;
    }

    else {
      int port_id =  get_port(search_interface_from_nexthop(new_nexthop))->index();
      routing_table.set(key, rt_v {.port = uint32_t(port_id),
                                   .nexthop = ip_string_to_be_uint(new_nexthop),
                                   .type = TYPE_NOLOCALINTERFACE});
    }
  }
  else
    logger()->debug("route not found in the data path");
}

/*
* Methods to manage packets coming from the fast path
*/

void Router::handle_router_pkt(Port &port, PacketInMetadata &md,
                               const std::vector<uint8_t> &packet) {

  EthernetII p(&packet[0], packet.size());
  IPv4Address src_ip(md.metadata[0]);
  IPv4Address dst_ip(md.metadata[1]);
  int protocol = md.metadata[2];

  /*check the packet protocol to prepare the correct response*/
  /*To implement: handle other type of pkts */
  if (protocol == IPPROTO_ICMP) {
    // Retrieve the ICMP MESSAGE and check what kind of message it is
    ICMP &icmp_payload = p.rfind_pdu<ICMP>();

    if (icmp_payload.type() == ICMP::ECHO_REQUEST) {
      /*echo request for one router interface, prepare the response */
      logger()->info("new echo request arrived from {0} to {1}",
                   src_ip.to_string(), dst_ip.to_string());
      EthernetII echoreply_packet =
          make_echo_reply(p, src_ip, dst_ip, icmp_payload);

      port.send_packet_out(echoreply_packet);
    }
  }

  return;
}


EthernetII Router::make_echo_reply(EthernetII &origin,
                                   const IPv4Address &src_ip,
                                   const IPv4Address &dst_ip, ICMP &old_icmp) {
  EthernetII echoreply_packet(origin.src_addr(), origin.dst_addr());

  IP ip_header = IP(src_ip, dst_ip);
  ip_header.ttl(64);

  echoreply_packet /= ip_header;

  // FLAG ECHO REPLY
  ICMP::Flags fl = ICMP::ECHO_REPLY;

  old_icmp.type(fl);

  echoreply_packet /= old_icmp;

  return echoreply_packet;
}


void Router::generate_icmp_ttlexceed(Port &port, PacketInMetadata &md,
                         const std::vector<uint8_t> &packet) {
  /* packet is dropped and the router sends an ICMP TTL exceeded packet */

  EthernetII p(&packet[0], packet.size());

  IP &ip = p.rfind_pdu<IP>();
  IPv4Address dst_ip(ip.src_addr());
  IPv4Address src_ip(md.metadata[0]);

  logger()->info("send ICMP packet TIME_EXCEDEED code to host {0}",
               dst_ip.to_string());
  // take the upper layer PDU and create a new PDU with the first 8 bytes
  PDU::serialization_type pdu = ip.inner_pdu()->serialize();

  ip.inner_pdu(RawPDU(&pdu[0], 8));

  // prepare the ICMP packet
  EthernetII icmp_packet(p.src_addr(), p.dst_addr());
  /* the src_addr become the destinationaddress,
   * the same for dst_addr
   */

  // IP HEADER: source is src_ip, destination is dst_ip
  IP ip_header = IP(dst_ip, src_ip);

  ip_header.ttl(64); // default 128

  icmp_packet /= ip_header;

  // ICMP MESSAGE
  ICMP::Flags fl = (ICMP::Flags)11;

  ICMP icmp = ICMP(fl); // FLAG TIME_EXCEDEED

  // add the old IP header in the ICMP message
  icmp.inner_pdu(ip);

  // add ICMP message in the response packet
  icmp_packet /= icmp;

  port.send_packet_out(icmp_packet);
}


void Router::generate_arp_request(Port &port, PacketInMetadata &md,
                         const std::vector<uint8_t> &packet) {
  /*target ip is the nexhtop of a routing table entry or the destination host if
   * the route is local, passed from datapath*/

  unsigned int target_ip = md.metadata[0]; // in network byte order
  int index = md.metadata[1];              // out port index

  unsigned int src_ip = md.metadata[2]; // the primary or one of the secondary
                                        // addresses of the port

  auto port_out = get_port(index);
  std::string src_mac = port_out->getMac();

  // save packet using the target_ip for send it after the arp reply
  mu.lock();
  auto iter = arp_request_map.find(target_ip);
  if (iter == arp_request_map.end()) { // no queue present, create one
    CircularBuffer q;
    q.enQueue(packet);
    arp_request_map[target_ip] = q;
  }

  else { // queue exists, add element
    CircularBuffer q = iter->second;
    q.enQueue(packet);
    arp_request_map[target_ip] = q;
  }
  mu.unlock();
  /* prepare the arp request

     source mac is port src_mac
     source ip is src_ip
     target ip is target_ip
 */

  IPv4Address target_ip_addr(target_ip);
  IPv4Address src_ip_addr(src_ip);
  HWAddress<6> src_mac_addr(src_mac);
  logger()->debug("sending ARP request on port {0} 'who has {1} tell MAC to {2}",
                port_out->name(), target_ip_addr.to_string(),
                src_ip_addr.to_string());
  EthernetII arp_request_packet = ARP::make_arp_request(
      target_ip_addr, src_ip_addr,
      src_mac_addr); // check if parameters format are correct

  port_out->send_packet_out(arp_request_packet);
}


void Router::generate_arp_reply(Port &port, PacketInMetadata &md,
                       const std::vector<uint8_t> &packet) {
  EthernetII arp_reply(&packet[0], packet.size());

  unsigned int src_ip = md.metadata[0];
  logger()->debug("ARP reply '{0} is at {1}'",
               IPv4Address(src_ip).to_string(),
               arp_reply.src_addr().to_string());

  // find the packet to send
  mu.lock();
  auto iter = arp_request_map.find(src_ip);

  if (iter != arp_request_map.end()) {
    // queue found, send a packet to the port
    CircularBuffer q = iter->second;

    if (q.isEmpty()) { // the buffer is empty, delete the value from the map
      logger()->info("packets buffer is empty");
      arp_request_map.erase(src_ip);
    }

    else {
      std::vector<uint8_t> reply_packet = q.deQueue();

      if (q.isEmpty()) // the buffer is empty, delete the value from the map
        arp_request_map.erase(src_ip);
      else
        arp_request_map[src_ip] = q; // update the queue

      // update the mac addresses and send packet
      EthernetII ethframe(&reply_packet[0], reply_packet.size());

      ethframe.src_addr(arp_reply.dst_addr());
      ethframe.dst_addr(arp_reply.src_addr());

      port.send_packet_out(ethframe);
    }
  } else {
    // no packet found, don't reply
    logger()->debug("no packet found for ARP reply, if it is a mirror port it will reply linux");
  }
  mu.unlock();
}

PortsJsonObject Router::attachInterface(const PortsJsonObject &conf) {
  std::lock_guard<std::mutex> guard(router_mutex);

  PortsJsonObject conf_ret;
  std::string port_name = conf.getName();
  std::string interface = conf.getMirror();
  std::string ipv4_addr;

  auto ifaces = polycube::polycubed::Netlink::getInstance().get_available_ifaces();
  for (auto &it : ifaces) {
    auto name = it.second.get_name();
    if (name == interface) {
      logger()->debug("the interface exists, mirror can be done");
      mirror_interfaces.insert({interface, port_name});

      // Find ip address
      ipv4_addr = "-";
      for (auto addr : it.second.get_addresses()) {
        std::stringstream ss(addr);
        std::string item;
        std::vector<std::string> splittedStrings;
        while (std::getline(ss, item, '/')) {
          splittedStrings.push_back(item);
        }

        unsigned char buf[sizeof(struct in_addr)];
        int ip = inet_pton(AF_INET, splittedStrings[0].c_str(), buf);
        if (ip == 1) {
          // set ip
          conf_ret.setIp(splittedStrings[0]);
          // set netmask
          conf_ret.setNetmask(get_netmask_from_CIDR(std::stoi(splittedStrings[1])));
          // break when find first ipv4 address
          break;
        }
      }

      conf_ret.setName(port_name);
      conf_ret.setMirror(interface);
      conf_ret.setPeer(interface);

      // Find mac address
      unsigned char mac[IFHWADDRLEN];
      int i;

      struct ifreq ifr;
      int fd;
      int rv;  // return value

      // determines the MAC address
      strcpy(ifr.ifr_name, interface.c_str());
      fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
      if (fd < 0) {
        logger()->error("error opening socket: {0}", std::strerror(errno));
        return conf_ret;
      } else {
        rv = ioctl(fd, SIOCGIFHWADDR, &ifr);
        if (rv >= 0)  // ok
          memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
        else {
          logger()->error("error determining the MAC address: {0}", std::strerror(errno));
          close(fd);
          return conf_ret;
        }
      }
      close(fd);

      uint64_t mac_;
      memcpy(&mac_, mac, sizeof mac_);
      conf_ret.setMac(polycube::service::utils::be_uint_to_mac_string(mac_));

      break;  // break because found interface with that name
    }
  }
  return conf_ret;
}

// Add linux route to the routing table
void Router::add_linux_route(const std::string &network,
                             const std::string &netmask_length,
                             const std::string &nexthop,
                             const std::string &port_name,
                             const int port_index) {
  // Add the network reachable through the inteface
  uint32_t nmask_lenght = std::stoi(netmask_length);
  auto routing_table = get_hash_table<rt_k, rt_v>("routing_table");

  rt_k key{
      .netmask_len = nmask_lenght,
      .network = ip_string_to_be_uint(network),
  };

  try {
    rt_v value1 = routing_table.get(key);

    if (value1.nexthop == ip_string_to_be_uint(nexthop)) {
      logger()->trace("this route already exists, it is not added");
      return;
    } else
      logger()->trace("route not found in the data path");
  } catch (...) {
    logger()->trace("route not found in the data path");
  }

  // add route because not found in the data path
  rt_v value{
      .port = uint32_t(port_index),
      .nexthop = ip_string_to_be_uint(nexthop),
      .type = TYPE_NOLOCALINTERFACE,
  };

  routing_table.set(key, value);

  std::string interface_netmask =
      get_netmask_from_CIDR(std::stoi(netmask_length));

  logger()->info("added linux route [network: {0} - netmask: {1} - nexthop: {2} - interface: {3}]",
                  network, interface_netmask, nexthop, port_name);

  // Add the route in the table of the control plane
  std::tuple<string, string, string> keyF(network, interface_netmask, nexthop);
  uint32_t pathcost = 1;

  routes_.emplace(std::piecewise_construct, std::forward_as_tuple(keyF),
                  std::forward_as_tuple(*this, network, interface_netmask,
                                        nexthop, port_name, pathcost));
}

// delete all routes for this interface
void Router::remove_all_routes_for_interface(const std::string &port_name) {
  if (routes_.size() == 0) {
    throw std::runtime_error("No entry found in routing table");
  }

  logger()->debug("the routing table in the control plane has {0} entries",
                 routes_.size());

  auto routing_table = get_hash_table<rt_k, rt_v>("routing_table");

  for (auto it = routes_.begin(); it != routes_.end();) {
    // check name port
    if (it->second.getInterface() == port_name) {
      if ((it->second.getNexthop()) != "local") {
        std::string network = it->second.getNetwork();
        std::string netmask = it->second.getNetmask();
        std::string nexthop = it->second.getNexthop();
        routes_.erase(it++);
        logger()->info(
            "removed route from control plane [network: {0} - netmask: {1} - "
            "nexthop: {2}]",
            network, netmask, nexthop);

        /*retrieve the entry from the fast path for the "netmask" "network",
         and get the nexthop in order to check whether the route is also in the
         fast path */
        try {
          rt_k key{
              .netmask_len = get_netmask_length(netmask),
              .network = ip_string_to_be_uint(network),
          };

          rt_v value = routing_table.get(key);

          if (value.nexthop == ip_string_to_be_uint(nexthop)) {
            /* the nexthop in the fast path corresponds to that just removed
             in the control path then, the entry in the fast path is removed */
            logger()->debug("route found in the data path");
            routing_table.remove(key);
          } else
            logger()->debug("route not found in the data path");
        } catch (...) {
          logger()->debug("route not found in the data path");
        }
      } else {
        it++;
      }
    } else {
      logger()->debug(
          "route not removed, it is not of this interface [network: {0} - "
          "netmask: {1} - nexthop: {2}]",
          it->second.getNetwork(), it->second.getNetmask(),
          it->second.getNexthop());
      it++;
    }
  }
}

bool Router::check_interface_is_mirror(const std::string &name_interface) {
  return mirror_interfaces.find(name_interface) != mirror_interfaces.end();
}

bool Router::check_ports_in_the_same_network(const std::string &ip, const std::string &netmask) {
  // check all the ports
  auto ports = get_ports();
  for (auto it : ports) {
    // check if the port is in the same network
    if (address_in_subnet(ip, netmask, get_network_from_ip(it->getIp(), it->getNetmask()))) {
      return true;
    }
  }
  return false;
}

void Router::netlink_notification_route_added(int ifindex, const std::string &info_route) {
  std::lock_guard<std::mutex> guard(router_mutex);

  char name_interface_tmp[50];
  if_indextoname(ifindex, name_interface_tmp);
  std::string name_interface(name_interface_tmp);

  if (check_interface_is_mirror(name_interface)) {
    logger()->info("netlink notification received, route add for interface: {0}",
        name_interface);

    // update the routing table
    // info_route = network/netmasklength/gateway
    std::istringstream split(info_route);
    std::vector<std::string> info;

    char split_char = '/';
    for (std::string each; std::getline(split, each, split_char);
         info.push_back(each))
      ;
    std::string network = info[0];
    std::string netmask_len = info[1];
    std::string gateway = info[2];

    if (gateway == "-") {
      gateway = "0.0.0.0";
    }

    std::unordered_map<std::string, std::string>::const_iterator it =
        mirror_interfaces.find(name_interface);
    std::string port_name = it->second;

    // find index port
    int index = -1;
    auto ports = get_ports();
    for (auto it : ports) {
      if (it->name() == port_name) {
        index = it->index();
        break;
      }
    }
    if (index != -1) {
      // es : add_linux_route("30.30.30.0", "24","10.1.1.1", "port1",
      // index_port);
      add_linux_route(network, netmask_len, gateway, port_name, index);
    }
  }
}

void Router::netlink_notification_route_deleted(int ifindex, const std::string &info_route) {
  std::lock_guard<std::mutex> guard(router_mutex);

  char name_interface_tmp[50];
  if_indextoname(ifindex, name_interface_tmp);
  std::string name_interface(name_interface_tmp);

  if (check_interface_is_mirror(name_interface)) {
    logger()->info("netlink notification received, route delete for interface: {0}",
        name_interface);

    // update the routing table
    // info_route = network/netmasklength/gateway
    std::istringstream split(info_route);
    std::vector<std::string> info;

    char split_char = '/';
    for (std::string each; std::getline(split, each, split_char);
         info.push_back(each))
      ;
    std::string network = info[0];
    std::string netmask_len = info[1];
    std::string gateway = info[2];

    if (gateway == "-") {
      gateway = "0.0.0.0";
    }

    std::string netmask = get_netmask_from_CIDR(std::stoi(netmask_len));

    // remove route
    std::tuple<string,string,string> key (network, netmask, gateway);

    if (routes_.count(key) != 0)
      routes_.erase(key);

  }
}

void Router::netlink_notification_link_added(int ifindex, const std::string &iface) {
  std::lock_guard<std::mutex> guard(router_mutex);

  if (check_interface_is_mirror(iface)) {
    logger()->info("netlink notification received, link {0} changed", iface);

    std::unordered_map<std::string, std::string>::const_iterator it_port = mirror_interfaces.find(iface);
    std::string port_name = it_port->second;

    std::string string_ipv4_addr = "";
    std::string string_netmask = "";
    std::string string_mac = "";

    auto ifaces = polycube::polycubed::Netlink::getInstance().get_available_ifaces();
    for (auto &it : ifaces) {
      auto name = it.second.get_name();
      if (name == iface) {
        // Find ipv4 address
        for (auto addr : it.second.get_addresses()) {
          std::stringstream ss(addr);
          std::string item;
          std::vector<std::string> splittedStrings;
          while (std::getline(ss, item, '/')) {
            splittedStrings.push_back(item);
          }

          unsigned char buf[sizeof(struct in_addr)];
          int flag = inet_pton(AF_INET, splittedStrings[0].c_str(), buf);
          if (flag == 1) {
            string_ipv4_addr = splittedStrings[0];
            string_netmask = get_netmask_from_CIDR(std::stoi(splittedStrings[1]));
            // break when find first ipv4 address
            break;
          }
        }

        // Find mac address
        unsigned char mac[IFHWADDRLEN];
        int i;

        struct ifreq ifr;
        int fd;
        int rv;  // return value

        // determines the MAC address
        strcpy(ifr.ifr_name, iface.c_str());
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (fd < 0) {
          logger()->error("error opening socket: {0}", std::strerror(errno));
        } else {
          rv = ioctl(fd, SIOCGIFHWADDR, &ifr);
          if (rv >= 0)  // ok
            memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
          else {
            logger()->error("error determining the MAC address: {0}", std::strerror(errno));
            close(fd);
          }
        }
        close(fd);

        uint64_t mac_;
        memcpy(&mac_, mac, sizeof mac_);
        string_mac = polycube::service::utils::be_uint_to_mac_string(mac_);

        break;  // break because found interface
      }
    }

    auto ports = get_ports();
    for (auto it : ports) {
      if (it->name() == port_name) {
        bool flag = false;
        if (it->getIp() != string_ipv4_addr) {
          logger()->info("changed IP address on the port {0}", port_name);
          it->setIp(string_ipv4_addr);
          flag = true;
        }
        if (it->getNetmask() != string_netmask) {
          logger()->info("changed netmask on the port {0}", port_name);
          it->setNetmask(string_netmask);
          flag = true;
        }
        if (it->getMac() != string_mac) {
          logger()->info("chanded mac address on the port {0}", port_name);
          it->setMac(string_mac);
        }

        if (flag) {
          // remove all routes local and not local
          for (auto it2 = routes_.begin(); it2 != routes_.end();) {
            if (it2->second.getInterface() == port_name)
              routes_.erase(it2++); //remove the route from the control plane
            else
              ++it2;
          }

          if (string_ipv4_addr != "" && string_netmask != "")
            add_local_route(string_ipv4_addr, string_netmask, port_name, it->index());

        }
        break;
      }
    }
  }
}

void Router::netlink_notification_link_deleted(int ifindex, const std::string &iface) {
  std::lock_guard<std::mutex> guard(router_mutex);

  if (check_interface_is_mirror(iface)) {
    logger()->info("netlink notification received, link {0} delete", iface);

    std::unordered_map<std::string, std::string>::const_iterator it = mirror_interfaces.find(iface);
    std::string port_name = it->second;

    remove_all_routes_for_interface(port_name);

    Ports::removeEntry(*this, port_name);
    mirror_interfaces.erase(it);
  }
}

void Router::netlink_notification_new_address(int ifindex, const std::string &info_address) {
  std::lock_guard<std::mutex> guard(router_mutex);

  // info_address = ip_address/netmask_len
  std::istringstream split(info_address);
  std::vector<std::string> info;

  char split_char = '/';
  for (std::string each; std::getline(split, each, split_char);
       info.push_back(each));
  std::string new_address = info[0];
  std::string new_netmask = get_netmask_from_CIDR(std::stoi(info[1]));

  char name_interface_tmp[50];
  if_indextoname(ifindex, name_interface_tmp);
  std::string name_interface(name_interface_tmp);

  if (check_interface_is_mirror(name_interface)) {
    logger()->info("netlink notification received, new address {0} on the interface {1}", info_address, name_interface);

    std::unordered_map<std::string, std::string>::const_iterator it =
        mirror_interfaces.find(name_interface);
    std::string port_name = it->second;

    uint16_t index;
    auto ports = get_ports();
    for (auto it : ports) {
      if (it->name() == port_name) {
        index = it->index();
        // remove all routes local and not local
        for (auto it2 = routes_.begin(); it2 != routes_.end();) {
          if (it2->second.getInterface() == port_name)
            routes_.erase(it2++); //remove the route from the control plane
          else
            ++it2;
        }

        // change IP address and netmask of the port
        it->setIp(new_address);
        it->setNetmask(new_netmask);
        add_local_route(new_address, new_netmask, port_name, index);
        break;
      }
    }
  }
}

bool Router::checkNamePort(const std::string &port_name) {
  auto ifaces = polycube::polycubed::Netlink::getInstance().get_available_ifaces();
  for (auto &it : ifaces) {
    auto name = it.second.get_name();
    if (name == port_name) {
      return true;
    }
  }
  return false;
}
