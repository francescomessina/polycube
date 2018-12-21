/**
* helloworld API
* Helloworld Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


// These methods have a default implementation. Your are free to keep it or add your own


#include "../Helloworld.h"




std::string Helloworld::getName(){
  // This method retrieves the name value.
  return Cube::get_name();
}


std::string Helloworld::getUuid(){
  // This method retrieves the uuid value.
  return Cube::get_uuid().str();
}


CubeType Helloworld::getType(){
  // This method retrieves the type value.
  return Cube::get_type();
}


HelloworldLoglevelEnum Helloworld::getLoglevel(){
  // This method retrieves the loglevel value.
    switch(Cube::get_log_level()){
      case polycube::LogLevel::TRACE:
        return HelloworldLoglevelEnum::TRACE;
      case polycube::LogLevel::DEBUG:
        return HelloworldLoglevelEnum::DEBUG;
      case polycube::LogLevel::INFO:
        return HelloworldLoglevelEnum::INFO;
      case polycube::LogLevel::WARN:
        return HelloworldLoglevelEnum::WARN;
      case polycube::LogLevel::ERR:
        return HelloworldLoglevelEnum::ERR;
      case polycube::LogLevel::CRITICAL:
        return HelloworldLoglevelEnum::CRITICAL;
      case polycube::LogLevel::OFF:
        return HelloworldLoglevelEnum::OFF;
    }
}

void Helloworld::setLoglevel(const HelloworldLoglevelEnum &value){
  // This method sets the loglevel value.
    switch(value){
      case HelloworldLoglevelEnum::TRACE:
        Cube::set_log_level(polycube::LogLevel::TRACE);
        break;
      case HelloworldLoglevelEnum::DEBUG:
        Cube::set_log_level(polycube::LogLevel::DEBUG);
        break;
      case HelloworldLoglevelEnum::INFO:
        Cube::set_log_level(polycube::LogLevel::INFO);
        break;
      case HelloworldLoglevelEnum::WARN:
        Cube::set_log_level(polycube::LogLevel::WARN);
        break;
      case HelloworldLoglevelEnum::ERR:
        Cube::set_log_level(polycube::LogLevel::ERR);
        break;
      case HelloworldLoglevelEnum::CRITICAL:
        Cube::set_log_level(polycube::LogLevel::CRITICAL);
        break;
      case HelloworldLoglevelEnum::OFF:
        Cube::set_log_level(polycube::LogLevel::OFF);
        break;
    }
}

std::shared_ptr<Ports> Helloworld::getPorts(const std::string &name){
  return Ports::getEntry(*this, name);
}

std::vector<std::shared_ptr<Ports>> Helloworld::getPortsList(){
  return Ports::get(*this);
}

void Helloworld::addPorts(const std::string &name, const PortsJsonObject &conf){
  Ports::create(*this, name, conf);
}

void Helloworld::addPortsList(const std::vector<PortsJsonObject> &conf){
  for(auto &i : conf){
    std::string name_ = i.getName();
    Ports::create(*this, name_,  i);
  }
}

void Helloworld::replacePorts(const std::string &name, const PortsJsonObject &conf){
  Ports::removeEntry(*this, name);
  std::string name_ = conf.getName();
  Ports::create(*this, name_, conf);

}

void Helloworld::delPorts(const std::string &name){
  Ports::removeEntry(*this, name);
}

void Helloworld::delPortsList(){
  Ports::remove(*this);
}



