/**
* router API
* router API generated from router.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* RouterJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"

#include "RouteJsonObject.h"
#include "PortsJsonObject.h"
#include <vector>
#include "ArpEntryJsonObject.h"
#include "polycube/services/cube.h"

namespace io {
namespace swagger {
namespace server {
namespace model {


/// <summary>
///
/// </summary>
class  RouterJsonObject : public JsonObjectBase {
public:
  RouterJsonObject();
  RouterJsonObject(const nlohmann::json &json);
  ~RouterJsonObject() final = default;
  nlohmann::json toJson() const final;


  /// <summary>
  /// Name of the router service
  /// </summary>
  std::string getName() const;
  void setName(std::string value);
  bool nameIsSet() const;

  /// <summary>
  /// Defines if the service is visible in Linux
  /// </summary>
  bool getShadow() const;
  void setShadow(bool value);
  bool shadowIsSet() const;
  void unsetShadow();

  /// <summary>
  /// Entry of the ports table
  /// </summary>
  const std::vector<PortsJsonObject>& getPorts() const;
  void addPorts(PortsJsonObject value);
  bool portsIsSet() const;
  void unsetPorts();

  /// <summary>
  /// Entry associated with the routing table
  /// </summary>
  const std::vector<RouteJsonObject>& getRoute() const;
  void addRoute(RouteJsonObject value);
  bool routeIsSet() const;
  void unsetRoute();

  /// <summary>
  /// Entry associated with the ARP table
  /// </summary>
  const std::vector<ArpEntryJsonObject>& getArpEntry() const;
  void addArpEntry(ArpEntryJsonObject value);
  bool arpEntryIsSet() const;
  void unsetArpEntry();

private:
  std::string m_name;
  bool m_nameIsSet;
  std::vector<PortsJsonObject> m_ports;
  bool m_portsIsSet;
  std::vector<RouteJsonObject> m_route;
  bool m_routeIsSet;
  std::vector<ArpEntryJsonObject> m_arpEntry;
  bool m_arpEntryIsSet;
  bool m_shadow;
  bool m_shadowIsSet;
};

}
}
}
}
