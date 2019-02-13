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

/*****************************************************************************/
  if (parent_.getShadow()) {
    auto ifaces = polycube::polycubed::Netlink::getInstance().get_available_ifaces();
    bool find_interface = false;
    for (auto &it : ifaces) {
      auto name_iface = it.second.get_name();
      bool flag_update_linux_iface = false;
      if (name_iface == getName()) {
        find_interface = true;
        if (conf.ipIsSet() && conf.netmaskIsSet() && is_netmask_valid(conf.getNetmask())) {
          ip_ = conf.getIp();
          netmask_ = conf.getNetmask();
          flag_update_linux_iface = true;
        } else {
          bool flag_ip = false;
          // Find ip address
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
              flag_ip = true;
              // set ip
              ip_ = splittedStrings[0];
              // set netmask
              netmask_ = (get_netmask_from_CIDR(std::stoi(splittedStrings[1])));
              // break when find first ipv4 address
              break;
            }
          }
          if (!flag_ip)
            throw std::runtime_error("The interface is already present in Linux but has no an IP address, IP and netmask are mandatory");
        }

        if (conf.macIsSet()) {
          mac_ = conf.getMac();
          flag_update_linux_iface = true;
        } else {
          // Find mac address
          bool flag_mac = false;
          unsigned char mac[IFHWADDRLEN];
          int i;

          struct ifreq ifr;
          int fd;
          int rv;  // return value

          // determines the MAC address
          strcpy(ifr.ifr_name, name_iface.c_str());
          fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
          if (fd < 0) {
            logger()->error("error opening socket: {0}", std::strerror(errno));
          } else {
            rv = ioctl(fd, SIOCGIFHWADDR, &ifr);
            if (rv >= 0) {
              memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
              flag_mac = true;
            }
          }
          close(fd);

          if (flag_mac) {
            uint64_t mac_uint;
            memcpy(&mac_uint, mac, sizeof mac_uint);
            mac_ = polycube::service::utils::be_uint_to_mac_string(mac_uint);
          } else {
            mac_ = polycube::service::utils::get_random_mac();
            flag_update_linux_iface = true;
          }
        }
      }
      if (flag_update_linux_iface) {
        change_ip_linux(name_iface, ip_);
        change_netmask_linux(name_iface, netmask_);
        change_mac_linux(name_iface, mac_);
      }
      if (find_interface) {
        break;
      }
    }
    if (!find_interface) {
      throw std::runtime_error("The interface is no longer present in linux, there was a problem");
    }

  } else { // if shadow is false
    if(conf.macIsSet())
      mac_ = conf.getMac();
    else
      mac_ = polycube::service::utils::get_random_mac();

    if (conf.ipIsSet())
      ip_ = conf.getIp();
    else
      throw std::runtime_error("IP address is mandatory");

    if (conf.netmaskIsSet()) {
      if (!is_netmask_valid(conf.getNetmask()))
        throw std::runtime_error("Netmask is in invalid format");
      netmask_ = conf.getNetmask();
    } else
      throw std::runtime_error("netmask is mandatory");
  }

/****************************************************************************/

  std::string port_name(getName());

  //TODO: check that no other router port exists in the same network

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
  };

  uint16_t index = this->index();
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

  /*
  * Create an object representing the secondary IP and add the routes related to the secondary ips
  */

  for(auto &addr : secondary_ips)
  {
    PortsSecondaryip::createInControlPlane(*this, addr.getIp(), addr.getNetmask(), addr);
  }

  if(conf.peerIsSet()) {
    setPeer(conf.getPeer());
  }
}

Ports::~Ports() { }

void Ports::update(const PortsJsonObject &conf) {
  //This method updates all the object/parameter in Ports object specified in the conf JsonObject.
  //You can modify this implementation.

  logger()->debug("updating port {0}", getName());

  if (conf.peerIsSet()) {

    setPeer(conf.getPeer());
  }
  if (conf.ipIsSet()) {

    setIp(conf.getIp());
  }
  if (conf.netmaskIsSet()) {

    setNetmask(conf.getNetmask());
  }
  if (conf.secondaryipIsSet()) {
    for(auto &i : conf.getSecondaryip()){
      auto ip = i.getIp();      auto netmask = i.getNetmask();
      auto m = getSecondaryip(ip, netmask);
      m->update(i);
    }
  }
  if (conf.macIsSet()) {

    setMac(conf.getMac());
  }
}

PortsJsonObject Ports::toJsonObject(){
  PortsJsonObject conf;

  conf.setName(getName());

  conf.setUuid(getUuid());

  conf.setStatus(getStatus());

  conf.setPeer(getPeer());

  conf.setIp(getIp());

  conf.setNetmask(getNetmask());

  //Remove comments when you implement all sub-methods
  for(auto &i : getSecondaryipList()){
    conf.addPortsSecondaryip(i->toJsonObject());
  }

  conf.setMac(getMac());

  return conf;
}

/***************************************************************************************/
void Ports::create(Router &parent, const std::string &name, const PortsJsonObject &conf){

  //This method creates the actual Ports object given thee key param.
  //Please remember to call here the create static method for all sub-objects of Ports.

  parent.add_port<PortsJsonObject>(name, conf);
}
/*********************************************************************************/

std::shared_ptr<Ports> Ports::getEntry(Router &parent, const std::string &name){
  // This method retrieves the pointer to Ports object specified by its keys.
  parent.logger()->debug("getting port: {0}", name);
  return parent.get_port(name);
}

void Ports::removeEntry(Router &parent, const std::string &name){
  //This method removes the single Ports object specified by its keys.
  //Remember to call here the remove static method for all-sub-objects of Ports.

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

    if (port->index() == value.port)
      arp_table.remove(key);
  }

  //remove the port from the datapath
  uint16_t index = port->index();
  router_port.remove(index);
  parent.logger()->debug("removed from 'router_port' - key: {0}",from_int_to_hex(index));

  parent.remove_port(name);

  parent.logger()->info("port {0} was removed", name);
}

std::vector<std::shared_ptr<Ports>> Ports::get(Router &parent){
  // This methods get the pointers to all the Ports objects in Router.
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
  // This method set the ip value.
  if (value == ip_)
    return;
  parent_.remove_local_route(ip_, netmask_, getName());
  ip_ = value;
  parent_.add_local_route(ip_, netmask_, getName(), this->index());
  if (parent_.getShadow())
    change_ip_linux(getName(), ip_);
}

std::string Ports::getNetmask(){
  // This method retrieves the netmask value.
  return netmask_;
}

void Ports::setNetmask(const std::string &value){
  // This method set the netmask value.
  if (!is_netmask_valid(value)) {
    parent_.logger()->error("netmask is not valid");
    return;
  }
  if (value == netmask_)
    return;
  parent_.remove_local_route(ip_, netmask_, getName());
  netmask_ = value;
  parent_.add_local_route(ip_, netmask_, getName(), this->index());
  if (parent_.getShadow())
    change_netmask_linux(getName(), netmask_);
}

std::string Ports::getMac(){
  // This method retrieves the mac value.
  return mac_;
}

void Ports::setMac(const std::string &value){
  // This method set the mac value.
  if (value == mac_)
    return;
  mac_ = value;
  if (parent_.getShadow())
    change_mac_linux(getName(), mac_);
}

std::shared_ptr<spdlog::logger> Ports::logger() {
  return parent_.logger();
}

/**********************/
// Is the best way?
void Ports::change_ip_linux(const std::string &name_iface,
                            const std::string &ip_) {
  std::string cmd_string = "ifconfig " + name_iface + " " + ip_ + " netmask " + netmask_;
  system(cmd_string.c_str());
}

void Ports::change_netmask_linux(const std::string &name_iface,
                                 const std::string &netmask_) {
  std::string cmd_string = "ifconfig " + name_iface + " netmask " + netmask_;
  system(cmd_string.c_str());
}

void Ports::change_mac_linux(const std::string &name_iface,
                             const std::string &mac_) {
  std::string cmd_string = "ifconfig " + name_iface + " down";
  system(cmd_string.c_str());

  cmd_string = "ifconfig " + name_iface + " hw ether " + mac_;
  system(cmd_string.c_str());

  cmd_string = "ifconfig " + name_iface + " up";
  system(cmd_string.c_str());
}


void Ports::setIp_polycube(const std::string &value){
  // This method set the ip value only on polycube
  ip_ = value;
}
void Ports::setNetmask_polycube(const std::string &value){
  // This method set the netmask value only on polycube
  if (!is_netmask_valid(value)) {
    parent_.logger()->error("netmask is not valid");
    return;
  }
  netmask_ = value;
}
void Ports::setMac_polycube(const std::string &value){
  // This method set the mac value only on polycube
  mac_ = value;
}
