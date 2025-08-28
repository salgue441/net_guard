/**
 * @file ethernet.hpp
 * @author Carlos Salguero
 * @brief Ethernet (IEEE 802.3) protocol parser implementation
 * @version 0.1
 * @date 2025-08-28
 *
 * @copyright Copyright (c) 2025
 *
 * This file implements parsing and analysis of Ethernet frames, including
 * support for VLAN tags and jumbo frames.
 */

#pragma once

#include "../core/types.hpp"
#include "../utils/expected.hpp"
#include <array>
#include <string>

namespace netguard::protocol {
/**
 * @brief MAC address representation
 *
 * Stores a 48-bit MAC address with utilities for parsing and formatting.
 * Uses std::array for efficient storage and manipulation.
 */
class MacAddress {
public:
  using octets_t = std::array<std::uint8_t, 6>;

public:
  /**
   * @brief Default constructor (creates null MAC 00:00:00:00:00:00)
   */
  constexpr MacAddress() noexcept = default;

  /**
   * @brief Construct from octet array
   */
  constexpr explicit MacAddress(const octets_t &octets) noexcept
      : m_octets{octets} {}

  /**
   * @brief Construct from individual octets
   */
  constexpr MacAddress(std::uint8_t o1, std::uint8_t o2, std::uint8_t o3,
                       std::uint8_t o4, std::uint8_t o5,
                       std::uint8_t o6) noexcept
      : m_octets{{o1, o2, o3, o4, o5, o6}} {}

  /**
   * @brief Parse MAC address from byte span
   */
  [[nodiscard]] static utils::Expected<MacAddress>
  parse(core::ByteSpan data) noexcept {
    if (data.size() < 6) {
      return tl::unexpected{
          utils::make_protocol_error("Insufficient data for Mac Address")};
    }

    octets_t octets;
    for (std::size_t i = 0; i < 6; ++i) {
      octets[i] = static_cast<std::uint8_t>(data[i]);
    }

    return MacAddress{octets};
  }

  /**
   * @brief Parse MAC address from string (e.g., "aa:bb:cc:dd:ee:ff")
   */
  [[nodiscard]] static core::Expected<MacAddress>
  from_string(std::string_view str);

  /**
   * @brief Get octet array
   */
  [[nodiscard]] constexpr auto octets_t &octets() const noexcept {
    return m_octets;
  }

  /**
   * @brief Get individual octet
   */
  [[nodiscard]] constexpr std::uint8_t
  operator[](std::size_t index) const noexcept {
    return m_octets[index];
  }

  /**
   * @brief Convert to string representation
   */
  [[nodiscard]] std::string to_string() const;

  /**
   * @brief Convert to string with custom separator
   */
  [[nodiscard]] std::string to_string(char separator) const;

  /**
   * @brief Check if this is a broadcast MAC (ff:ff:ff:ff:ff:ff)
   */
  [[nodiscard]] constexpr bool is_broadcast() const noexcept {
    return m_octets == m_octets{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
  }

  /**
   * @brief Check if this is a null MAC (00:00:00:00:00:00)
   */
  [[nodiscard]] constexpr bool is_null() const noexcept {
    return m_octets == octets_t{};
  }

  /**
   * @brief Check if this is a multicast MAC (first bit set)
   */
  [[nodiscard]] constexpr bool is_multicast() const noexcept {
    return (m_octets[0] & 0x01) != 0;
  }

  /**
   * @brief Check if this is a unicast MAC (not multicast)
   */
  [[nodiscard]] constexpr bool is_unicast() const noexcept {
    return !is_multicast();
  }

  /**
   * @brief Check if this is a locally administered MAC (second bit set)
   */
  [[nodiscard]] constexpr bool is_local() const noexcept {
    return (m_octets[0] & 0x02) != 0;
  }

  /**
   * @brief Check if this is a globally unique MAC (not locally administered)
   */
  [[nodiscard]] constexpr bool is_global() const noexcept {
    return !is_local();
  }

  /**
   * @brief Get OUI (Organizationally Unique Identifier) - first 3 octets
   */
  [[nodiscard]] constexpr std::uint32_t oui() const noexcept {
    return (static_cast<std::uint32_t>(m_octets[0]) << 16) |
           (static_cast<std::uint32_t>(m_octets[1]) << 8) |
           static_cast<std::uint32_t>(m_octets[2]);
  }

  /**
   * @brief Comparison operators
   */
  [[nodiscard]] constexpr bool
  operator==(const MacAddress &) const noexcept = default;
  [[nodiscard]] constexpr auto
  operator<=>(const MacAddress &) const noexcept = default;

  /**
   * @brief Hash function for use in containers
   */
  [[nodiscard]] std::size_t hash() const noexcept {
    std::size_t seed = 0;
    for (auto octet : m_octets) {
      seed ^= std::hash<std::uint8_t>{}(octet) + 0x9e3779b9 + (seed << 6) +
              (seed >> 2);
    }

    return seed;
  }

private:
  octets_t m_octets{};
};

/**
 * @brief EtherType enumeration for common protocols
 *
 * Defines standard EtherType values used in Ethernet frames
 * to identify the next layer protocol.
 */
enum class EtherType : std::uint16_t {
  IPv4 = 0x0800,            ///< Internet Protocol version 4
  ARP = 0x0806,             ///< Address Resolution Protocol
  RARP = 0x8035,            ///< Reverse Address Resolution Protocol
  VLAN = 0x8100,            ///< VLAN-tagged frame (IEEE 802.1Q)
  IPv6 = 0x86DD,            ///< Internet Protocol version 6
  MPLS = 0x8847,            ///< MPLS unicast
  PPPoE_Discovery = 0x8863, ///< PPPoE Discovery Stage
  PPPoE_Session = 0x8864,   ///< PPPoE Session Stage
  LLDP = 0x88CC,            ///< Link Layer Discovery Protocol

  // Custom/experimental range
  Custom_Start = 0x8800,
  Custom_End = 0xFFFF
};

/**
 * @brief Convert EtherType to human-readable string
 */
[[nodiscard]] std::string_view ethertype_to_string(EtherType type) noexcept;

/**
 * @brief VLAN tag information (IEEE 802.1Q)
 *
 * Represents a single VLAN tag with priority, CFI, and VLAN ID.
 */
struct VlanTag {
  std::uint8_t priority : 3; ///< Priority Code Point (PCP)
  std::uint8_t cfi : 1;      ///< Canonical Format Indicator
  std::uint8_t vlan_id : 12; ///< VLAN Identifier

  /**
   * @brief Parse VLAN tag from 16-bit value
   */
  [[nodiscard]] static constexpr VlanTag from_raw(std::uint16_t raw) noexcept {
    return VlanTag{.priority = static_cast<std::uint8_t>((raw >> 13) & 0x07),
                   .cfi = static_cast<std::uint8_t>((raw >> 12) & 0x01),
                   .vlan_id = static_cast<std::uint16_t>(raw & 0x0FFF)};
  }

  /**
   * @brief Convert to 16-bit raw value
   */
  [[nodiscard]] constexpr std::uint16_t to_raw() const noexcept {
    return (static_cast<std::uint16_t>(priority) << 13) |
           (static_cast<std::uint16_t>(cfi) << 12) | vlan_id;
  }

  /**
   * @brief Check if this is a valid VLAN ID (1-4094)
   */
  [[nodiscard]] constexpr bool is_valid() const noexcept {
    return vlan_id > 0 && vlan_id < 4095;
  }
};

/**
 * @brief Ethernet frame header representation
 *
 * Represents a parsed Ethernet frame header with support for
 * VLAN tags and various EtherTypes. Provides zero-copy access
 * to header fields and payload data.
 */
struct EthernetHeader {
  MacAddress destination; ///< Destination MAC address
  MacAddress source;      ///< Source MAC address
  EtherType ethertype;    ///< EtherType or length field

  /// VLAN tags (can have multiple for QinQ)
  std::vector<VlanTag> vlan_tags;

  /// Offset to payload start (accounts for variable VLAN tags)
  std::size_t payload_offset{14};

  /**
   * @brief Parse Ethernet header from byte span
   *
   * Supports standard Ethernet frames and VLAN-tagged frames.
   * Handles QinQ (multiple VLAN tags) correctly.
   */
  [[nodiscard]] static core::Expected<EthernetHeader>
  parse(core::ByteSpan data) noexcept;

  /**
   * @brief Get header size including any VLAN tags
   */
  [[nodiscard]] constexpr std::size_t header_size() const noexcept {
    return payload_offset;
  }

  /**
   * @brief Get payload data (everything after Ethernet header)
   */
  [[nodiscard]] core::ByteSpan
  payload(core::ByteSpan packet_data) const noexcept {
    if (payload_offset >= packet_data.size()) {
      return {};
    }

    return packet_data.subspan(payload_offset);
  }

  /**
   * @brief Check if frame has VLAN tags
   */
  [[nodiscard]] bool has_vlan_tags() const noexcept {
    return !vlan_tags.empty();
  }

  /**
   * @brief Get outermost VLAN ID (0 if no VLAN tags)
   */
  [[nodiscard]] std::uint16_t outer_vlan_id() const noexcept {
    return vlan_tags.empty() ? 0 : vlan_tags.front().vlan_id;
  }

  /**
   * @brief Get innermost VLAN ID (0 if no VLAN tags)
   */
  [[nodiscard]] std::uint16_t inner_vlan_id() const noexcept {
    return vlan_tags.empty() ? 0 : vlan_tags.back().vlan_id;
  }

  /**
   * @brief Check if this is a broadcast frame
   */
  [[nodiscard]] bool is_broadcast() const noexcept {
    return destination.is_broadcast();
  }

  /**
   * @brief Check if this is a multicast frame
   */
  [[nodiscard]] bool is_multicast() const noexcept {
    return destination.is_multicast();
  }

  /**
   * @brief Check if this is a unicast frame
   */
  [[nodiscard]] bool is_unicast() const noexcept {
    return destination.is_unicast();
  }

  /**
   * @brief Get frame type description
   */
  [[nodiscard]] std::string frame_type() const noexcept {
    if (is_broadcast())
      return "broadcast";

    if (is_multicast())
      return "multicast";

    return "unicast";
  }

  /**
   * @brief Validate header integrity
   */
  [[nodiscard]] core::Expected<void> validate() const noexcept;

  /**
   * @brief Get human-readable summary
   */
  [[nodiscard]] std::string to_string() const;

  /**
   * @brief Serialize header to bytes
   */
  [[nodiscard]] core::Expected<std::size_t>
  serialize(core::MutableByteSpan buffer) const noexcept;

  /**
   * @brief Calculate serialized size
   */
  [[nodiscard]] std::size_t serialized_size() const noexcept {
    return 12 + (vlan_tags.size() * 4) +
           2; // 12 for MACs + VLAN tags + EtherType
  }
};

/**
 * @brief Ethernet frame analysis utilities
 */
namespace ethernet_utils {
/**
 * @brief Common well-known MAC addresses
 */
namespace mac_addresses {
inline constexpr MacAddress BROADCAST{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
inline constexpr MacAddress NULL_MAC{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Multicast addresses
inline constexpr MacAddress STP_BRIDGE{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};
inline constexpr MacAddress LLDP_MULTICAST{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};
} // namespace mac_addresses

/**
 * @brief Detect frame format based on EtherType/Length field
 */
enum class FrameFormat {
  EthernetII, ///< Modern Ethernet (EtherType >= 1536)
  IEEE_802_3, ///< Legacy 802.3 frame (Length < 1536)
  Invalid     ///< Invalid format
};

/**
 * @brief Determine Ethernet frame format
 */
[[nodiscard]] FrameFormat
detect_frame_format(std::uint16_t ethertype_or_length) noexcept;

/**
 * @brief Check if EtherType value is valid
 */
[[nodiscard]] constexpr bool is_valid_ethertype(std::uint16_t value) noexcept {
  return value >= 1536;
}

/**
 * @brief Get vendor name from MAC address OUI
 */
[[nodiscard]] std::string_view get_vendor_by_oui(std::uint32_t oui) noexcept;

/**
 * @brief Calculate Ethernet frame overhead
 */
[[nodiscard]] constexpr std::size_t
frame_overhead(std::size_t vlan_count = 0) noexcept {
  return 14 + (vlan_count * 4) + 4;
}

/**
 * @brief Maximum Transmission Unit for Ethernet
 */
inline constexpr std::size_t STANDARD_MTU = 1500;
inline constexpr std::size_t JUMBO_MTU = 9000;

/**
 * @brief Check if frame size is within valid range
 */
[[nodiscard]] constexpr bool is_valid_frame_size(std::size_t size) noexcept {
  return size >= 64 && size <= 1518;
}

/**
 * @brief Check if frame is jumbo frame
 */
[[nodiscard]] constexpr bool is_jumbo_frame(std::size_t size) noexcept {
  return size > 1518 && size <= 9018;
}
} // namespace ethernet_utils
} // namespace netguard::protocol

// Hash support for Mac Address
template <> struct std::hash<netguard::protocol::MacAddress> {
  std::size_t
  operator()(const netguard::protocol::MacAddress &mac) const noexcept {
    return mac.hash();
  }
}

// Format support for Ethernet Types
template <>
struct std::formatter<netguard::protocol::MacAddress> {
  constexpr auto parse(format_parse_context &ctx) { return ctx.begin(); }

  template <typename FormatContext>
  auto format(const netguard::protocol::MacAddress &mac, FormatContext &ctx) {
    return format_to(ctx.out(), "{}", mac.to_string());
  }
};

template <> struct std::formatter<netguard::protocol::EtherType> {
  constexpr auto parse(format_parse_context &ctx) { return ctx.begin(); }

  template <typename FormatContext>
  auto format(netguard::protocol::EtherType type, FormatContext &ctx) {
    return format_to(ctx.out(), "{} (0x{:04x})", ethertype_to_string(type),
                     static_cast<std::uint16_t>(type));
  }
};