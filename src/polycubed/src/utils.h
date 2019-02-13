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

#include <string>
#include <vector>

#include <tins/ethernetII.h>
#include <tins/tins.h>
#include <net/if.h>

namespace polycube {
namespace polycubed {
namespace utils {

bool check_kernel_version(const std::string &version);
void send_packet_linux(const std::string &name_iface, const std::vector<uint8_t> &packet);

}  // namespace utils
}  // namespace polycubed
}  // namespace polycube
