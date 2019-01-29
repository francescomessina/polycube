/**
* router API
* Router Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* PortsInterface.h
*
*
*/

#pragma once

#include "../serializer/PortsJsonObject.h"

#include "../PortsSecondaryip.h"

using namespace io::swagger::server::model;

class PortsInterface {
public:

  virtual void update(const PortsJsonObject &conf) = 0;
  virtual PortsJsonObject toJsonObject() = 0;

  /// <summary>
  /// Port Name
  /// </summary>
  virtual std::string getName() = 0;

  /// <summary>
  /// UUID of the port
  /// </summary>
  virtual std::string getUuid() = 0;

  /// <summary>
  /// Status of the port (UP or DOWN)
  /// </summary>
  virtual PortsStatusEnum getStatus() = 0;

  /// <summary>
  /// Peer name, such as a network interfaces (e.g., &#39;veth0&#39;) or another cube (e.g., &#39;br1:port2&#39;)
  /// </summary>
  virtual std::string getPeer() = 0;
  virtual void setPeer(const std::string &value) = 0;

  /// <summary>
  /// IP address of the port
  /// </summary>
  virtual std::string getIp() = 0;
  virtual void setIp(const std::string &value) = 0;

  /// <summary>
  /// Netmask of the port
  /// </summary>
  virtual std::string getNetmask() = 0;
  virtual void setNetmask(const std::string &value) = 0;

  /// <summary>
  /// Secondary IP address for the port
  /// </summary>
  virtual std::shared_ptr<PortsSecondaryip> getSecondaryip(const std::string &ip, const std::string &netmask) = 0;
  virtual std::vector<std::shared_ptr<PortsSecondaryip>> getSecondaryipList() = 0;
  virtual void addSecondaryip(const std::string &ip, const std::string &netmask, const PortsSecondaryipJsonObject &conf) = 0;
  virtual void addSecondaryipList(const std::vector<PortsSecondaryipJsonObject> &conf) = 0;
  virtual void replaceSecondaryip(const std::string &ip, const std::string &netmask, const PortsSecondaryipJsonObject &conf) = 0;
  virtual void delSecondaryip(const std::string &ip,const std::string &netmask) = 0;
  virtual void delSecondaryipList() = 0;

  /// <summary>
  /// MAC address of the port
  /// </summary>
  virtual std::string getMac() = 0;
  virtual void setMac(const std::string &value) = 0;
};

