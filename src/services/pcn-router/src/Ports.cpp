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


#include "Ports.h"
#include "Router.h"
#include "Utils.h"

Ports::Ports(polycube::service::Cube<Ports> &parent,
             std::shared_ptr<polycube::service::PortIface> port,
             const PortsJsonObject &conf)
  : Port(port), parent_(static_cast<Router&>(parent)) {
  logger()->debug("start creating Ports instance");

  std::string routing_table_linux;

  // Check if it is a mirror port
  if (conf.mirrorIsSet()) {
    logger()->debug("it is a mirror port");

    // Get the interface parameters
    PortsJsonObject conf_ret = parent_.attachInterface(conf);

    // Check if the interface can be mirrored
    if (!(conf_ret.ipIsSet() && conf_ret.macIsSet() && conf_ret.mirrorIsSet() &&
          conf_ret.netmaskIsSet())) {
      throw std::runtime_error(
          "the interface can't be mirrored, check if the interface exists");
    }

    mirror_ = conf_ret.getMirror();
    mac_ = conf_ret.getMac();
    ip_ = conf_ret.getIp();
    netmask_ = conf_ret.getNetmask();
    setPeer(conf_ret.getPeer());

    // Read linux routing table and update polycube routing table
    // These method is in Utils.cpp
    routing_table_linux = read_routing_table_linux();

  } else {
    logger()->debug("it is not a mirror port");
    if (conf.ipIsSet() && conf.netmaskIsSet()) {
      ip_ = conf.getIp();
      netmask_ = conf.getNetmask();

      if (!is_netmask_valid(conf.getNetmask())) {
        throw std::runtime_error("netmask is in invalid format");
      }

    } else {
      throw std::runtime_error(
          "ip and netmask are mandatory, or mirror an existing interface");
    }

    if (conf.macIsSet())
      mac_ = conf.getMac();
    else
      mac_ = polycube::service::utils::get_random_mac();

    mirror_ = "None";

    if (conf.peerIsSet()) {
      setPeer(conf.getPeer());
    }
  }

  std::string port_name(getName());

  // check that no other router port exists in the same network
  if (parent_.check_ports_in_the_same_network(ip_, netmask_))
    throw std::runtime_error("A port already exists in the same network");

  /*
  * Add the port to the datapath
  */

  auto router_port = parent.get_hash_table<uint16_t, r_port>("router_port");
  r_port value {
    .ip = utils::ip_string_to_be_uint(ip_),
    .netmask = utils::ip_string_to_be_uint(netmask_),
    .secondary_ip = {},
    .secondary_netmask = {},
    .mac = utils::mac_string_to_be_uint(mac_),
    .mirror = conf.mirrorIsSet(),
  };

  uint16_t index = port->index();
  const std::vector<PortsSecondaryipJsonObject> secondary_ips = conf.getSecondaryip();
  int i = 0;
  for (auto &addr : secondary_ips) {
    value.secondary_ip[i] = utils::ip_string_to_be_uint(addr.getIp());
    value.secondary_netmask[i] = utils::ip_string_to_be_uint(addr.getNetmask());
    i++;
  }

  router_port.set(index, value);

  logger()->info("added new port: {0} (index: {4}) [mac: {1} - ip: {2} - netmask: {3}]",getName(),mac_,ip_,netmask_,index);
  for(auto &addr : secondary_ips)
    logger()->info("\t secondary address: [ip: {0} - netmask: {1}]",addr.getIp(),addr.getNetmask());

  /*
  * Add two routes in the routing table
  */
  parent_.add_local_route(ip_, netmask_, getName(), index);

  // Only for mirror port take information from the linux routing table
  if (conf.mirrorIsSet()) {
    // Split routing table and take only some information
    std::istringstream split(routing_table_linux);
    std::vector<std::string> rows;
    char split_char = '\n';
    for (std::string each; std::getline(split, each, split_char);
         rows.push_back(each))
      ;

    for (auto row : rows) {
      std::istringstream split2(row);
      std::vector<std::string> words;
      split_char = ' ';
      for (std::string each; std::getline(split2, each, split_char);
           words.push_back(each))
        ;

      if (words[0] == mirror_) {
        // parent_.add_linux_route(network, netmask_length, nexthop, port_name, port_index);
        parent_.add_linux_route(words[2], words[3], words[4], getName(), index);
      }
    }
  }

  /*
  * Create an object representing the secondary IP and add the routes related to the secondary ips
  */

  for (auto &addr : secondary_ips) {
    PortsSecondaryip::createInControlPlane(*this, addr.getIp(), addr.getNetmask(), addr);
  }
}

Ports::~Ports() { }

void Ports::update(const PortsJsonObject &conf) {
  //This method updates all the object/parameter in Ports object specified in the conf JsonObject.
  //You can modify this implementation.

  logger()->info("updating port");

  if (conf.ipIsSet()) {
    setIp(conf.getIp());
  }

  if (conf.netmaskIsSet()) {
    setNetmask(conf.getNetmask());
  }

  if(conf.macIsSet()) {
    setMac(conf.getMac());
  }

  if(conf.peerIsSet()) {
    setPeer(conf.getPeer());
  }

  if (conf.secondaryipIsSet()) {
    for (auto &i : conf.getSecondaryip()) {
      auto ip = i.getIp();
      auto netmask = i.getNetmask();
      auto m = getSecondaryip(ip, netmask);
      m->update(i);
    }
  }

  if (conf.mirrorIsSet()) {
    setMirror(conf.getMirror());
  }

}

PortsJsonObject Ports::toJsonObject() {
  PortsJsonObject conf;


  conf.setStatus(getStatus());

  conf.setName(getName());

  conf.setIp(getIp());

  conf.setNetmask(getNetmask());

  conf.setMac(getMac());

  conf.setPeer(getPeer());


  //Remove comments when you implement all sub-methods
  for (auto &i : getSecondaryipList()) {
    conf.addPortsSecondaryip(i->toJsonObject());
  }

  conf.setUuid(getUuid());

  conf.setMirror(getMirror());

  return conf;
}


void Ports::create(Router &parent, const std::string &name, const PortsJsonObject &conf){

  //This method creates the actual Ports object given thee key param.
  //Please remember to call here the create static method for all sub-objects of Ports.

  parent.add_port<PortsJsonObject>(name, conf);
}

std::shared_ptr<Ports> Ports::getEntry(Router &parent, const std::string &name){
  //This method retrieves the pointer to Ports object specified by its keys.
  parent.logger()->debug("getting port: {0}", name);
  return parent.get_port(name);
}

void Ports::removeEntry(Router &parent, const std::string &name){
  //This method removes the single Ports object specified by its keys.
  //Remember to call here the remove static method for all-sub-objects of Ports.

  parent.logger()->info("remove port {0}", name);


  auto port = parent.get_port(name);

  //remove the secondary addresses of the port (and the related routes in the routing table)
  PortsSecondaryip::remove(*port);

  parent.remove_local_route(port->getIp(), port->getNetmask(), name);

  auto router_port = parent.get_hash_table<uint16_t, r_port>("router_port");

  // remove the ArpEntry from the datapath, for this port
  auto arp_table = parent.get_hash_table<uint32_t, arp_entry>("arp_table");
  auto arp_entries = arp_table.get_all();
  for (auto &entry : arp_entries) {
    auto key = entry.first;
    auto value = entry.second;
    auto port = parent.get_port(value.port);

    if (port->name() == name) {
      arp_table.remove(key);
    }
  }

  //remove the port from the datapath
  uint16_t index = port->index();
  router_port.remove(index);
  parent.logger()->debug("removed from 'router_port' - key: {0}",from_int_to_hex(index));

  parent.remove_port(name);

  parent.logger()->info("port {0} was removed", name);
}

std::vector<std::shared_ptr<Ports>> Ports::get(Router &parent){
  //This methods get the pointers to all the Ports objects in Router.
  parent.logger()->debug("getting all the ports");
  return parent.get_ports();
}

void Ports::remove(Router &parent){
  //This method removes all Ports objects in Router.
  //Remember to call here the remove static method for all-sub-objects of Ports.

  parent.logger()->info("removing all the ports");

  auto ports = parent.get_ports();
  for (auto it : ports) {
    removeEntry(parent, it->name());
  }
}



std::string Ports::getIp(){
  //This method retrieves the ip value.

  return ip_;
}

void Ports::setIp(const std::string &value){
  //This method set the ip value.
  throw std::runtime_error("method Ports::setIp not implemented");
}


std::string Ports::getNetmask(){
  //This method retrieves the netmask value.
  return netmask_;
}

void Ports::setNetmask(const std::string &value){
  //This method set the netmask value.
  throw std::runtime_error("method Ports::setNetmask not implemented");
}


std::string Ports::getMac(){
  //This method retrieves the mac value.
  return mac_;
}

void Ports::setMac(const std::string &value){
  //This method set the mac value.
  throw std::runtime_error("method Ports::setMac not implemented");
}

std::string Ports::getMirror() {
  // This method retrieves the mirror value.
  return mirror_;
}

void Ports::setMirror(const std::string &value) {
  // This method set the mirror value.
  throw std::runtime_error("method Ports::setMirror not implemented");
}

std::shared_ptr<spdlog::logger> Ports::logger() {
  return parent_.logger();
}
