/**
* simplebridge API
* simplebridge API generated from simplebridge.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "SimplebridgeJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

SimplebridgeJsonObject::SimplebridgeJsonObject() {
  m_nameIsSet = false;
  m_portsIsSet = false;
  m_fdbIsSet = false;
  m_shadow = false;
  m_shadowIsSet = true;
}

SimplebridgeJsonObject::SimplebridgeJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_nameIsSet = false;
  m_portsIsSet = false;
  m_fdbIsSet = false;
  m_shadowIsSet = false;

  if (val.count("shadow")) {
    setShadow(val.at("shadow").get<bool>());
  }

  if (val.count("name")) {
    setName(val.at("name").get<std::string>());
  }

  if (val.count("ports")) {
    for (auto& item : val["ports"]) {
      PortsJsonObject newItem{ item };
      m_ports.push_back(newItem);
    }

    m_portsIsSet = true;
  }

  if (val.count("fdb")) {
    if (!val["fdb"].is_null()) {
      FdbJsonObject newItem { val["fdb"] };
      setFdb(newItem);
    }
  }
}

nlohmann::json SimplebridgeJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  if (!getBase().is_null()) {
    val.update(getBase());
  }

  if (m_nameIsSet) {
    val["name"] = m_name;
  }

  if (m_shadowIsSet) {
    val["shadow"] = m_shadow;
  }

  {
    nlohmann::json jsonArray;
    for (auto& item : m_ports) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["ports"] = jsonArray;
    }
  }

  if (m_fdbIsSet) {
    val["fdb"] = JsonObjectBase::toJson(m_fdb);
  }

  return val;
}

std::string SimplebridgeJsonObject::getName() const {
  return m_name;
}

void SimplebridgeJsonObject::setName(std::string value) {
  m_name = value;
  m_nameIsSet = true;
}

bool SimplebridgeJsonObject::nameIsSet() const {
  return m_nameIsSet;
}



const std::vector<PortsJsonObject>& SimplebridgeJsonObject::getPorts() const{
  return m_ports;
}

void SimplebridgeJsonObject::addPorts(PortsJsonObject value) {
  m_ports.push_back(value);
  m_portsIsSet = true;
}


bool SimplebridgeJsonObject::portsIsSet() const {
  return m_portsIsSet;
}

void SimplebridgeJsonObject::unsetPorts() {
  m_portsIsSet = false;
}

FdbJsonObject SimplebridgeJsonObject::getFdb() const {
  return m_fdb;
}

void SimplebridgeJsonObject::setFdb(FdbJsonObject value) {
  m_fdb = value;
  m_fdbIsSet = true;
}

bool SimplebridgeJsonObject::fdbIsSet() const {
  return m_fdbIsSet;
}

void SimplebridgeJsonObject::unsetFdb() {
  m_fdbIsSet = false;
}

bool SimplebridgeJsonObject::getShadow() const {
  return m_shadow;
}

void SimplebridgeJsonObject::setShadow(bool value) {
  m_shadow = value;
  m_shadowIsSet = true;
}

bool SimplebridgeJsonObject::shadowIsSet() const {
  return m_shadowIsSet;
}

void SimplebridgeJsonObject::unsetShadow() {
  m_shadowIsSet = false;
}

}
}
}
}
