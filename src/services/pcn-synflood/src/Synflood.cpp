/**
* synflood API generated from synflood.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


// TODO: Modify these methods with your own implementation


#include "Synflood.h"
#include "Synflood_dp.h"

Synflood::Synflood(const std::string name, const SynfloodJsonObject &conf)
  : TransparentCube(conf.getBase(), { synflood_code }, {}),
    SynfloodBase(name) {
  logger()->debug("Creating Synflood instance");
}


Synflood::~Synflood() {
  logger()->debug("Destroying Synflood instance");
}

void Synflood::packet_in(polycube::service::Sense sense,
  polycube::service::PacketInMetadata &md,
  const std::vector<uint8_t> &packet) {
  logger()->debug("Packet received");
}

std::shared_ptr<Stats> Synflood::getStats() {
  StatsJsonObject sjo;
  return std::make_shared<Stats>(*this, sjo);
}

void Synflood::addStats(const StatsJsonObject &value) {}

// Basic default implementation, place your extension here (if needed)
void Synflood::replaceStats(const StatsJsonObject &conf) {}

void Synflood::delStats() {}


