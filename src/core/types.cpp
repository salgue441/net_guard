/**
 * @file types.hpp
 * @author Carlos Salguero
 * @brief Core types implementation
 * @version 0.1
 * @date 2025-08-28
 *
 * @copyright Copyright (c) 2025
 *
 */

#include <arpa/inet.h>
#include <format>
#include <netguard/core/expected.hpp>
#include <netguard/core/types.hpp>

namespace netguard::core {
std::string NetworkAddress::to_string() const {
  char buffer[INET6_ADDRSTRLEN];
  if (type == Type::IPv4) {
    std::uint32_t addr;
    std::memcpy(&addr, data.data(), sizeof(addr));

    if (inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN)) {
      return std::string{buffer};
    }
  } else if (type == Type::IPv6) {
    if (inet_ntop(AF_INET6, data.data(), buffer, INET6_ADDRSTRLEN)) {
      return std::string{buffer};
    }
  }

  return "invalid_address";
}

std::size_t FlowId::hash() const noexcept {
  std::size_t seed = 0;

  seed ^= std::hash<NetworkAddress>{}(src_addr) + 0x9e3779b9 + (seed << 6) +
          (seed >> 2);

  seed ^= std::hash<NetworkAddress>{}(dst_addr) + 0x9e3779b9 + (seed << 6) +
          (seed >> 2);

  seed ^= std::hash<Port>{}(src_port) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  seed ^= std::hash<Port>{}(dst_port) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  seed ^= std::hash<std::uint8_t>{}(protocol) + 0x9e3779b9 + (seed << 6) +
          (seed >> 2);

  return seed;
}
} // namespace netguard::core