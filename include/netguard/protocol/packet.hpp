/**
 * @file packet.hpp
 * @author Carlos Salguero
 * @brief Base packet structure and metadata for NetGuard
 * @version 0.1
 * @date 2025-08-28
 *
 * @copyright Copyright (c) 2025
 *
 * This file defines the fundamental packet representation used throughout
 * NetGuard for zero-copy packet procesing and analysis.
 */

#pragma once

#include "../core/types.hpp"
#include "../utils/expected.hpp"
#include <memory>
#include <variant>

namespace netguard::protocol {
/**
 * @brief Packet capture metadata
 *
 * Contains information about when and how a packet was captured,
 * separate from the packet data itself.
 */
struct CaptureInfo {
  Timestamp timestamp;           ///< When the packet was captured
  PacketSize original_length;    ///< Original packet length before truncation
  PacketSize captured_length;    ///< Actually captured length
  std::uint32_t interface_id{0}; ///< Network interface index

  /**
   * @brief Check if packet was truncated during capture
   */
  [[nodiscard]] bool is_truncated() const noexcept {
    return captured_length < original_length;
  }
}

/**
 * @brief Forward declarations for protocol types
 */
struct EthernetHeader;
struct IPv4Header;
struct IPv6Header;
struct TcpHeader;
struct UdpHeader;
struct IcmpHeader;

/**
 * @brief Variant type for different protocol headers
 *
 * Provides type-safe access to parsed protocol headers without
 * dynamic allocation or virtual function calls.
 */
using ProtocolHeader =
    std::variant<std::monostate, EthernetHeader, IPv4Header, IPv6Header,
                 TcpHeader, UdpHeader, IcmpHeader>;

/**
 * @brief Core packet representation for zero-copy processing.
 *
 * Represents a network packet with its raw data and parsed headers.
 * Uses spans for zero-copy data access and variants for type-safe header
 * access.
 */
class Packet : public core::NonCopyable {
public:
  /**
   * @brief Construct packet from raw data
   */
  explicit Packet(core::ByteSpan data, CaptureInfo capture_info) noexcept
      : m_data{data}, m_capture_info{capture_info},
        m_packet_id{next_packet_id()} {}

  /**
   * @brief Move constructor
   */
  Packet(Packet &&) noexcept = default;
  Packet &operator=(Packet &&) noexcept = default;

  // Basic Packet Information
  /**
   * @brief Get unique packet identifier
   */
  [[nodiscard]] core::PacketId id() const noexcept { return m_packet_id; }

  /**
   * @brief Get packet capture information
   */
  [[nodiscard]] const CaptureInfo &capture_info() const noexcept {
    return m_capture_info;
  }

  /**
   * @brief Get raw packet data
   */
  [[nodiscard]] core::ByteSpan data() const noexcept { return m_data; }

  /**
   * @brief Get packet size
   */
  [[nodiscard]] core::PacketSize size() const noexcept {
    return static_cast<core::PacketSize>(m_data.size());
  }

  /**
   * @brief Get the packet timestamp
   */
  [[nodiscard]] core::Timestamp timestamp() const noexcept {
    return m_capture_info.timestamp;
  }

  // Protocol header access
  /**
   * @brief Get specific protocol header
   *
   * Returns pointer to header if it exists and has been parsed,
   * nullptr otherwise. Type-safe alternative to dynamic_cast.
   */
  template <typename T> [[nodiscard]] const T *get_header() const noexcept {
    if (auto it = m_headers.find(std::type_index{typeid(T)});
        it != m_headers.end()) {
      return std::get_if<T>(&it->second);
    }

    return nullptr;
  }

  /**
   * @brief Check if packet has specific protocol header
   */
  template <typename T> [[nodiscard]] bool has_header() const noexcept {
    return get_header<T>() != nullptr;
  }

  /**
   * @brief Add parsed protocol header
   */
  template <typename T> void add_header(T header) {
    m_headers[std::type_index{typeid(T)}] = std::move(header);
  }

  /**
   * @brief Get all parsed headers
   */
  [[nodiscard]] const std::unordered_map<std::type_index, ProtocolHeader> &
  headers() const noexcept {
    return m_headers;
  }

  // Protocol Detection and Parsing
  /**
   * @brief Parse all protocol headers in the packet
   *
   * Performs complete protocol stack parsing starting from layer 2.
   * Results are cached in the packet for efficient repeated access.
   */
  [[nodiscard]] utils::Expected<void> parse_headers();

  /**
   * @brief Get protocol stack as string (e.g., "Ethernet/IPv4/TCP/HTTP")
   */
  [[nodiscard]] std::string protocol_stack() const;

  /**
   * @brief Check if packet matches a specific protocol stack
   */
  [[nodiscard]] bool
  matches_protocol(std::span<const std::type_index> protocols) const noexcept;

  // Flow information
  /**
   * @brief Extract flow identifier from packet
   *
   * Returns flow ID if packet contains sufficient information (typically
   * requires at least IP + transport layer headers)
   */
  [[nodiscard]] utils::Expected<core::FlowId> extract_flow_id() const;

  /**
   * @brief Check if this is the first packet of a flow
   */
  [[nodiscard]] bool is_flow_start() const noexcept;

  /**
   * @brief Check if this is the last packet of a flow
   */
  [[nodiscard]] bool is_flow_end() const noexcept;

  // Payload Access
  /**
   * @brief Get application layer payload
   *
   * Returns the data after all parsed protocol headers. May be emtpy
   * if packet contains only headers.
   */
  [[nodiscard]] core::ByteSpan payload() const noexcept;

  /**
   * @brief Get payload for specific protocol layer
   *
   * Returns the payload that comes after the specified protocol header.
   */
  template <typename T>
  [[nodiscard]] core::ByteSpan payload_after() const noexcept {
    const auto *header = get_header<T>();
    if (!header) {
      return {};
    }

    auto header_end = calculate_header_end<T>(header);
    if (header_end >= m_data.size()) {
      return {};
    }

    return m_data.subspan(header_end);
  }

  // Utility methods
  /**
   * @brief Create a deep copy of the packet
   *
   * Necessary when packet data needs to outlive the original capture buffer.
   * Allocates new storage for packet data.
   */
  [[nodiscard]] std::unique_ptr<Packet> clone() const;

  /**
   * @brief Get human-readable packet summary
   */
  [[nodiscard]] std::string summary() const;

  /**
   * @brief Validate packet integrity
   *
   * Checks for common packet corruption indicators like:
   * - Insufficient data for claimed headers
   * - Invalid header lengths
   * - Checksum mismatches (when available)
   */
  [[nodiscard]] utils::Expected<void> validate() const;

private:
  core::ByteSpan m_data;      ///< Raw packet data (zero-copy)
  CaptureInfo m_capture_info; ///< Capture metadata
  core::PacketId m_packet_id; ///< Unique identifier

  /// Parsed protocol headers (cached after first parse)
  std::unordered_map<std::type_index, ProtocolHeader> m_headers;

  /// Cached payload span (calculated after header parsing)
  mutable std::optional<core::ByteSpan> m_cached_payload;

private:
  /**
   * @brief Calculate end offset of a specific header type
   */
  template <typename T>
  [[nodiscard]] std::size_t
  calculate_header_end(const T *header) const noexcept;

  /**
   * @brief Generate next unique packet ID.
   */
  [[nodiscard]] static core::PacketId next_packet_id() noexcept {
    static std::atomic<std::uint64_t> counter{1};
    static core::PacketId{counter.fetch_add(1, std::memory_order_relaxed)};
  }
};

/**
 * @brief Packet parsing utilities
 */
namespace packet_utils {
/**
 * @brief Parse packet from raw capture data
 *
 * Creates a Packet object with capture metadata and performs initial
 * validation of raw data.
 */
[[nodiscard]] utils::Expected<std::unique_ptr<Packet>>
parse_from_capture(core::ByteSpan data, CaptureInfo capture_info);

/**
 * @brief Parse packet from PCAP record
 *
 * Handles PCAP-specific metadata extraction and creates appropriate
 * CaptureInfo structure.
 */
[[nodiscard]] utils::Expected<std::unique_ptr<Packet>>
parse_from_pcap(core::ByteSpan pcap_record);

/**
 * @brief Batch parse multiple packets
 *
 * Efficiently parses multiple packets in parallel where possible.
 * Returns vector of successfully parsed packets, logs failures.
 */
[[nodiscard]] utils::Expected<std::vector<std::unique_ptr<Packet>>>
parse_batch(std::span<const core::ByteSpan> packet_data,
            std::span<const CaptureInfo> capture_infos);

/**
 * @brief Extract common packet statistics
 */
struct PacketStats {
  core::PacketSize min_size{std::numeric_limits<core::PacketSize>::max()};
  core::PacketSize max_size{0};
  core::PacketSize avg_size{0};
  std::uint64_t total_packets{0};
  std::uint64_t total_bytes{0};

  /// Protocol distribution
  std::unordered_map<std::string, std::uint64_t> protocol_counts;

  /// Packet size distribution (in buckets)
  std::array<std::uint64_t, 10> size_distribution{};

  void update(const Packet &packet) noexcept;
  [[nodiscard]] std::string to_string() const;
};

/**
 * @brief Calculate statistics for a batch of packets
 */
[[nodiscard]] PacketStats
calculate_stats(std::span<const std::unique_ptr<Packet>> packets);

} // namespace packet_utils

} // namespace netguard::protocol

// Template specialization for header end calculation
namespace netguard::protocol {
template <>
inline std::size_t Packet::calculate_header_end<EthernetHeader>(
    const EthernetHeader *header) const noexcept {
  return 14;
}

// TODO: Add specialization for other protocols when they're defined
} // namespace netguard::protocol