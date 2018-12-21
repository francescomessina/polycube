/**
* simplebridge API
* Simple L2 Bridge Service
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "FdbFlushOutputJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

FdbFlushOutputJsonObject::FdbFlushOutputJsonObject() {

  m_flushedIsSet = false;
}

FdbFlushOutputJsonObject::~FdbFlushOutputJsonObject() {}

void FdbFlushOutputJsonObject::validateKeys() {

}

void FdbFlushOutputJsonObject::validateMandatoryFields() {

  if (!m_flushedIsSet) {
    throw std::runtime_error("Variable flushed is required");
  }
}

void FdbFlushOutputJsonObject::validateParams() {

}

nlohmann::json FdbFlushOutputJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  val["flushed"] = m_flushed;

  return val;
}

void FdbFlushOutputJsonObject::fromJson(nlohmann::json& val) {
  for(nlohmann::json::iterator it = val.begin(); it != val.end(); ++it) {
    std::string key = it.key();
    bool found = (std::find(allowedParameters_.begin(), allowedParameters_.end(), key) != allowedParameters_.end());
    if (!found) {
      throw std::runtime_error(key + " is not a valid parameter");
      return;
    }
  }

  if (val.find("flushed") != val.end()) {
    setFlushed(val.at("flushed"));
  }
}

nlohmann::json FdbFlushOutputJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

nlohmann::json FdbFlushOutputJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["flushed"]["name"] = "flushed";
  val["flushed"]["type"] = "leaf"; // Suppose that type is leaf
  val["flushed"]["simpletype"] = "boolean";
  val["flushed"]["description"] = R"POLYCUBE(Returns true if the Filtering database has been flushed. False otherwise)POLYCUBE";
  val["flushed"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json FdbFlushOutputJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["flushed"]["name"] = "flushed";
  val["flushed"]["simpletype"] = "boolean";
  val["flushed"]["description"] = R"POLYCUBE(Returns true if the Filtering database has been flushed. False otherwise)POLYCUBE";
  val["flushed"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json FdbFlushOutputJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> FdbFlushOutputJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

bool FdbFlushOutputJsonObject::getFlushed() const {
  return m_flushed;
}

void FdbFlushOutputJsonObject::setFlushed(bool value) {
  m_flushed = value;
  m_flushedIsSet = true;
}

bool FdbFlushOutputJsonObject::flushedIsSet() const {
  return m_flushedIsSet;
}

void FdbFlushOutputJsonObject::unsetFlushed() {
  m_flushedIsSet = false;
}




}
}
}
}
