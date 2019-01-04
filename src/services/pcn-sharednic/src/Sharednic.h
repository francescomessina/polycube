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

#pragma once


#include "../interface/SharednicInterface.h"

#include "polycube/services/cube.h"
#include "polycube/services/port.h"
#include "polycube/services/utils.h"

#include <spdlog/spdlog.h>

#include "Ports.h"


using namespace io::swagger::server::model;
using polycube::service::CubeType;

class Sharednic : public polycube::service::Cube<Ports>, public SharednicInterface {
  friend class Ports;
public:
  Sharednic(const std::string name, const SharednicJsonObject &conf, CubeType type = CubeType::TC);
  virtual ~Sharednic();
  std::string generate_code();
  std::vector<std::string> generate_code_vector();
  void packet_in(Ports &port, polycube::service::PacketInMetadata &md, const std::vector<uint8_t> &packet) override;

  void update(const SharednicJsonObject &conf) override;
  SharednicJsonObject toJsonObject() override;

  /// <summary>
  /// Name of the sharednic service
  /// </summary>
  std::string getName() override;

  /// <summary>
  /// UUID of the Cube
  /// </summary>
  std::string getUuid() override;

  /// <summary>
  /// Type of the Cube (TC, XDP_SKB, XDP_DRV)
  /// </summary>
  CubeType getType() override;

  /// <summary>
  /// Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE)
  /// </summary>
  SharednicLoglevelEnum getLoglevel() override;
  void setLoglevel(const SharednicLoglevelEnum &value) override;

  /// <summary>
  /// Entry of the ports table
  /// </summary>
  std::shared_ptr<Ports> getPorts(const std::string &name) override;
  std::vector<std::shared_ptr<Ports>> getPortsList() override;
  void addPorts(const std::string &name, const PortsJsonObject &conf) override;
  void addPortsList(const std::vector<PortsJsonObject> &conf) override;
  void replacePorts(const std::string &name, const PortsJsonObject &conf) override;
  void delPorts(const std::string &name) override;
  void delPortsList() override;

  /// <summary>
  /// Action performed on the received packet (i.e., DROP, LINUX, or POLYCUBE; default: DROP)
  /// </summary>
  SharednicActionEnum getAction() override;
  void setAction(const SharednicActionEnum &value) override;
};
