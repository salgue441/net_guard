/**
 * @file types.hpp
 * @author Carlos Salguero
 * @brief Core types, concepts, and utilities for NetGuard
 * @version 0.1
 * @date 2025-08-28
 *
 * @copyright Copyright (c) 2025@date 2025
 *
 * This file defines fundamental types, concepts, and utilities used
 * throughout the NetGuard system. All headers should include this
 * file to access common types and concepts.
 */

#pragma once

#include "netguard/utils/expected.hpp"
#include <array>
#include <chrono>
#include <concepts>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

namespace netguard::core {
// Fundamental types
/**
 * @brief Type-safe byte representation
 *
 * Used for all raw network data to prevent confusion with char/uint8_t
 */
using Byte = std::byte;

/**
 * @brief Span of bytes for zero-copy data handling
 *
 * Primary type for passing network data without copying
 */
using ByteSpan = std::span<const Byte>;

/**
 * @brief Mutable span of bytes
 */
using MutableByteSpan = std::span<Byte>;

/**
 * @brief High-resolution timestamp type
 *
 * Used for all timing measurements in packet analysis
 */
using Timestamp = std::chrono::time_point<std::chrono::high_resolution_clock>;

/**
 * @brief Duration type for time intervals
 */
using Duration = std::chrono::nanoseconds;

/**
 * @brief Network address representation (IPv4/IPv6 agnostic)
 */
struct NetworkAddress {
  enum class Type : std::uint8_t { IPv4 = 4, IPv6 = 6 };
  Type type;
  std::array<std::byte, 16> data{}; ///< IPv6 size, IPv4 uses first 4 bytes

  /**
   * @brief Construct IPv4 address
   */
  static NetworkAddress ipv4(std::uint32_t addr) noexcept {
    NetworkAddress result{.type = Type::IPv4};

    std::memcpy(result.data.data(), &addr, sizeof(addr));
    return result;
  }

  /**
   * @brief Construct IPv6 address
   */
  static NetworkAddress ipv6(const std::array<std::byte, 16> &addr) noexcept {
    return NetworkAddress{.type = Type::IPv6, .data = addr};
  }

  /**
   * @brief Get address as string representation
   */
  [[nodiscard]] std::string to_string() const;

  /**
   * @brief Equality comparison
   */
  [[nodiscard]] bool
  operator==(const NetworkAddress &other) const noexcept = default;
};

/**
 * @brief Network port number (host byte order)
 */
using Port = std::uint16_t;

/**
 * @brief Network flow identifier
 *
 * Uniquely identifies a network flow for connection tracking
 */
struct FlowId {
  NetworkAddress src_addr;
  NetworkAddress dst_addr;
  Port src_port{0};
  Port dst_port{0};
  std::uint8_t protocol{0};

  /**
   * @brief Generate hash for use in containers
   */
  [[nodiscard]] std::size_t hash() const noexcept;

  /**
   * @brief Equality comparison
   */
  [[nodiscard]] bool operator==(const FlowId &other) const noexcept = default;

  /**
   * @brief Get reverse flow (dst->src)
   */
  [[nodiscard]] FlowId reverse() const noexcept {
    return FlowId{.src_addr = dst_addr,
                  .dst_addr = src_addr,
                  .src_port = dst_port,
                  .dst_port = src_port,
                  .protocol = protocol};
  }
};

/**
 * @brief Packet size type
 */
using PacketSize = std::uint32_t;

/**
 * @brief Sequence number type (for TCP, etc.)
 */
using SequenceNumber = std::uint32_t;

// Strong Types for Type Safety
/**
 * @brief Template for creating strong types.
 *
 * Prevents accidental mixing of different numeric types.
 */
template <typename T, typename Tag> class StrongType {
public:
  explicit StrongType(T value) noexcept : m_value{value} {}

  [[nodiscard]] T get() const noexcept { return m_value; }
  [[nodiscard]] T &get() noexcept { return m_value; }

  [[nodiscard]] bool operator==(const StrongType &) const noexcept = default;
  [[nodiscard]] bool operator<=>(const StrongType &) const noexcept = default;

private:
  T m_value;
};

/**
 * @brief Strong type for packet identifiers
 */
struct PacketIdTag {};
using PacketId = StrongType<std::uint64_t, PacketIdTag>;

/**
 * @brief Strong type for rule identifiers
 */
struct RuleIdTag {};
using RuleId = StrongType<std::uint32_t, RuleIdTag>;

/**
 * @brief Strong type for alert identifiers
 */
struct AlertIdTag {};
using AlertId = StrongType<std::uint64_t, AlertIdTag>;

// Concepts for Generic Programming
/**
 * @brief Concept for types that can be parsed from bytes
 */
template <typename T>
concept Parsable = requires(ByteSpan data) {
  { T::parse(data) } -> std::same_as<utils::Expected<T>>;
};

/**
 * @brief Concept for types that can be serialized to bytes
 */
template <typename T>
concept Serializable = requires(const T &obj, MutableByteSpan buffer) {
  { obj.serialize(buffer) } -> std::same_as<utils::Expected<std::size_t>>;
  { obj.serialized_size() } -> std::same_as<std::size_t>;
};

/**
 * @brief Concept for protocol types
 */
template <typename T>
concept Protocol = Parsable<T> && requires(const T &proto) {
  { proto.header_size() } -> std::same_as<std::size_t>;
  { proto.payload() } -> std::same_as<ByteSpan>;
};

/**
 * @brief Concept for network capture sources
 */
template <typename T>
concept CaptureSource = requires(T &source) {
  { source.next_packet() } -> std::same_as<utils::Expected<ByteSpan>>;
  { source.is_open() } -> std::same_as<bool>;
  { source.close() } -> std::same_as<Result>;
};

/**
 * @brief Concept for detection rules
 */
template <typename T>
concept DetectionRule = requires(const T &rule, ByteSpan packet) {
  { rule.matches(packet) } -> std::same_as<bool>;
  { rule.rule_id() } -> std::same_as<RuleId>;
  { rule.severity() } -> std::same_as<std::uint8_t>;
};

/**
 * @brief Concept for hashable types
 */
template <typename T>
concept Hashable = requires(const T &obj) {
  { obj.hash() } -> std::same_as<std::size_t>;
};

// Utility types and functions
/**
 * @brief Non-copyable base class
 *
 * Inherit from this to make a class move-only
 */
class NonCopyable {
protected:
  NonCopyable() = default;
  ~NonCopyable() = default;
  NonCopyable(const NonCopyable &) = delete;
  NonCopyable &operator=(const NonCopyable &) = delete;
  NonCopyable(NonCopyable &&) = default;
  NonCopyable &operator=(NonCopyable &&) = default;
};

/**
 * @brief RAII wrapper for file descriptors
 */
class FileDescriptor : public NonCopyable {
public:
  explicit FileDescriptor(int fd = -1) noexcept : m_fd{fd} {}

  ~FileDescriptor() noexcept { close(); }
  FileDescriptor(FileDescriptor &&other) noexcept : m_fd{other.m_fd} {
    other.m_fd = -1;
  }

  FileDescriptor &operator=(FileDescriptor &&other) noexcept {
    if (this != &other) {
      close();

      m_fd = other.m_fd;
      other.m_fd = -1;
    }

    return *this;
  }

  [[nodiscard]] int get() const noexcept { return m_fd; }
  [[nodiscard]] bool is_valid() const noexcept { return m_fd >= 0; }

  void close() noexcept {
    if (is_valid()) {
      ::close(m_fd);
      m_fd = -1;
    }
  }

  int release() noexcept {
    int fd = m_fd;
    m_fd = -1;

    return fd;
  }

private:
  int m_fd{-1};
};

/**
 * @brief Endianness conversion utilities
 */
namespace endian {
/**
 * @brief Convert from network byte order (big endian) to host byte order.
 */
template <std::integral T>
[[nodiscard]] constexpr T from_network(T value) noexcept {
  if constexpr (std::endian::native == std::endian::big) {
    return value;
  } else {
    return std::byteswap(value);
  }
}

/**
 * @brief Convert from host byte order to network byte order (big endian)
 */
template <std::integral T>
[[nodiscard]] constexpr T to_network(T value) noexcept {
  return from_network(value);
}
} // namespace endian

/**
 * @brief Byte manipulation utils
 */
namespace bytes {
/**
 * @brief Safely read integer from byte span
 */
template <std::integral T>
[[nodiscard]] utils::Expected<T> read(ByteSpan data,
                                      std::size_f offset = 0) noexcept {
  if (offset + sizeof(T) > data.size()) {
    return tl::unexpected{
        utils::make_protocol_error("Insufficient data for read operation")};
  }

  T value{};
  std::memcpy(&value, data.data() + offset, sizeof(T));
  return endian::from_network(value);
}

/**
 * @brief Safely write integer to byte span
 */
template <std::integral T>
[[nodiscard]] utils::Expected<void> write(MutableByteSpan data, T value,
                                          std::size_t offset = 0) noexcept {
  if (offset + sizeof(T) > data.size()) {
    return tl::unexpected{utils::make_protocol_error(
        "Insufficient buffer space for write operation")};
  }

  T network_value = endian::to_network(value);
  std::memcpy(data.data() + offset, &network_value, sizeof(T));
  return {};
}

/**
 * @brief Create ByteSpan from string data
 */
[[nodiscard]] inline ByteSpan from_string(std::string_view str) noexcept {
  return ByteSpan{reinterpret_cast<const Byte *>(str.data()), str.size()};
}

/**
 * @brief Create string view from ByteSpan (unsafe - no encoding validation)
 */
[[nodiscard]] inline std::string_view to_string_view(ByteSpan data) noexcept {
  return std::string_view{reinterpret_cast<const char *>(data.data()),
                          data.size()};
}
} // namespace bytes

// Thread Satefy utils
/**
 * @brief Lock-free atomic flag for high-performance signaling
 */
class AtomicFlag {
public:
  void set() noexcept { m_flag.test_and_set(std::memory_order_release); }
  bool test() const noexcept { return m_flag.test(std::memory_order_acquire); }
  void clear() noexcept { m_flag.clear(std::memory_order_release); }

  bool test_and_set() noexcept {
    return m_flag.test_and_set(std::memory_order_acq_rel);
  }

private:
  mutable std::atomic_flag m_flag{};
};

/**
 * @brief Thread-safe reference counter for shared resources
 */
class RefCounter {
public:
  void increment() noexcept { m_count.fetch_add(1, std::memory_order_relaxed); }
  [[nodiscard]] bool decrement() noexcept {
    return m_count.fetch_sub(1, std::memory_order_acq_rel) == 1;
  }

  [[nodiscard]] std::size_t count() const noexcept {
    return m_count.load(std::memory_order_acquire);
  }

private:
  std::atomic<std::size_t> m_count{1};
};
} // namespace netguard::core

// Hash Support for Custom Types
template <> struct std::hash<netguard::core::NetworkAddress> {
  std::size_t
  operator()(const netguard::core::NetworkAddress &addr) const noexcept {
    std::size_t seed =
        std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(addr.type));

    std::size_t data_size =
        (addr.type == netguard::core::NetworkAddress::Type::IPv4) ? 4 : 16;

    for (std::size_t i = 0; i < data_size; ++i) {
      seed ^= std::hash<std::byte>{}(addr.data[i]) + 0x9e3779b9 + (seed << 6) +
              (seed >> 2);
    }

    return seed;
  }
};

template <> struct std::hash<netguard::core::FlowId> {
  std::size_t operator()(const netguard::core::FlowId &flow) const noexcept {
    return flow.hash();
  }
};

template <> struct std::hash<netguard::core::StrongType<T, Tag>> {
  std::size_t operator()(
      const netguard::core::StrongType<T, Tag> &strong_type) const noexcept {
    return std::hash<T>{}(strong_type.get());
  }
};