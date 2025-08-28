/**
 * @file packet_capture.hpp
 * @author Carlos Salguero
 * @brief High-level packet capture interface for NetGuard
 * @version 0.1
 * @date 2025-08-28
 *
 * @copyright Copyright (c) 2025
 *
 * This file defines the main interface for packet capture operations,
 * supporting live capture from network interfaces and reading from PCAP files
 * with unified API.
 */

#pragma once

#include "../core/types.hpp"
#include "../protocol/packet.hpp"
#include "../utils/expected.hpp"
#include <coroutine>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

namespace netguard::capture {
/**
 * @brief Network interface information
 */
struct NetworkInterface {
  std::uint32_t index{0};  ///< System interface index
  std::string name;        ///< Interface name (e.g., "eth0")
  std::string description; ///< Human-readable description
  std::vector<core::NetworkAddress> addresses; ///< Assigned addresses
  bool is_up{false};                           ///< Interface is up
  bool is_loopback{false};                     ///< Loopback interface
  bool supports_promiscuous{false};            ///< Supports promiscuous mode
  std::uint32_t mtu{1500};                     ///< Maximum Transmission Unit

  [[nodiscard]] std::string to_string() const;
};

/**
 * @brief Packet capture statistics
 */
struct CaptureStatistics {
  std::uint64_t packets_received{0};   ///< Total packets received
  std::uint64_t packets_dropped{0};    ///< Packets dropped by kernel
  std::uint64_t packets_if_dropped{0}; ///< Packets dropped by interface
  std::uint64_t bytes_received{0};     ///< Total bytes received

  core::Duration capture_duration{}; ///< Total capture time
  double packets_per_second{0.0};    ///< Packet rate
  double bytes_per_second{0.0};      ///< Byte rate

  void update(const protocol::Packet &packet) noexcept;
  [[nodiscard]] std::string to_string() const;
};

/**
 * @brief Capture filter for packet selection
 *
 * Supports Berkeley Packet Filter (BPF) expressions for
 * efficient kernel-level packet filtering.
 */
class CaptureFilter {
public:
  /**
   * @brief Create filter from BPF expression
   */
  [[nodiscard]] static utils::Expected<CaptureFilter>
  from_bpf(std::string_view expression);

  /**
   * @brief Common predefined filters
   */
  [[nodiscard]] static CaptureFilter tcp() { return from_bpf("tcp").value(); }
  [[nodiscard]] static CaptureFilter udp() { return from_bpf("udp").value(); }
  [[nodiscard]] static CaptureFilter icmp() { return from_bpf("icmp").value(); }

  [[nodiscard]] static CaptureFilter http() {
    return from_bpf("tcp port 80 or tcp port 443").value();
  }

  [[nodiscard]] static CaptureFilter dns() {
    return from_bpf("udp port 53 or tcp port 53").value();
  }

  /**
   * @brief Create filter for specific host
   */
  [[nodiscard]] static utils::Expected<CaptureFilter>
  host(const core::NetworkAddress &addr);

  /**
   * @brief Create filter for specific port
   */
  [[nodiscard]] static CaptureFilter port(core::Port port_num);

  /**
   * @brief Combine filters with logical AND
   */
  [[nodiscard]] CaptureFilter operator&&(const CaptureFilter &other) const;

  /**
   * @brief Combine filters with logical OR
   */
  [[nodiscard]] CaptureFilter operator||(const CaptureFilter &other) const;

  /**
   * @brief Get BPF expression
   */
  [[nodiscard]] const std::string &expression() const noexcept {
    return m_expression;
  }

private:
  std::string m_expression;

private:
  explicit CaptureFilter(std::string expression)
      : m_expression{std::move(expression)} {}
};

/**
 * @brief Packet capture configuration
 */
struct CaptureConfig {
  std::string interface_name;          ///< Network interface to capture from
  std::optional<CaptureFilter> filter; ///< Packet filter (optional)
  std::uint32_t snaplen{65535};        ///< Maximum packet capture length
  bool promiscuous_mode{false};        ///< Enable promiscuous mode
  std::uint32_t buffer_size{2 * 1024 * 1024}; ///< Capture buffer size
  core::Duration timeout{std::chrono::milliseconds{100}}; ///< Read timeout

  /// File-specific options
  std::string pcap_file; ///< PCAP file to read from
  bool loop_file{false}; ///< Loop file reading infinitely
};

/**
 * @brief Packet handler callback type
 *
 * Called for each captured packet. Return false to stop capture.
 */
using PacketHandler = std::function<bool(std::unique_ptr<protocol::Packet>)>;

/**
 * @brief Abstract base class for packet capture sources
 *
 * Provides unified interface for live capture and file reading.
 * Uses CRTP for zero-cost abstractions where possible.
 */
class PacketCaptureSource : public core::NonCopyable {
public:
  virtual ~PacketCaptureSource() = default;

  /**
   * @brief Start packet capture
   */
  [[nodiscard]] virtual utils::Expected<void> start() = 0;

  /**
   * @brief Stop packet capture
   */
  virtual void stop() = 0;

  /**
   * @brief Check if capture is currently running
   */
  [[nodiscard]] virtual bool is_running() const noexcept = 0;

  /**
   * @brief Get next packet (blocking)
   */
  [[nodiscard]] virtual utils::Expected<std::unique_ptr<protocol::Packet>>
  next_packet() = 0;

  /**
   * @brief Get capture statistics
   */
  [[nodiscard]] virtual CaptureStatistics statistics() const = 0;

  /**
   * @brief Set packet filter
   */
  [[nodiscard]] virtual utils::Expected<void>
  set_filter(const CaptureFilter &filter) = 0;
};

/**
 * @brief Main packet capture class
 *
 * High-level interface for packet capture operations with support
 * for both callback-based and coroutine-based processing.
 */
class PacketCapture : public core::NonCopyable {
public:
  /**
   * @brief Coroutine generator for packet streaming
   *
   * Usage:
   *   auto capture = PacketCapture::create_live("eth0").value();
   *   for (auto packet : capture->packet_stream()) {
   *       // Process packet
   *   }
   */
  struct PacketStream {
    struct promise_type {
      std::unique_ptr<protocol::Packet> current_packet;

      PacketStream get_return_object() {
        return PacketStream{
            std::coroutine_handle<promise_type>::from_promise(*this)};
      }

      std::suspend_never initial_suspend() { return {}; }
      std::suspend_always final_suspend() noexcept { return {}; }
      std::suspend_always
      yield_value(std::unique_ptr<protocol::Packet> packet) {
        current_packet = std::move(packet);
        return {};
      }

      void return_void() {}
      void unhandled_exception() { std::terminate(); }
    };

    using handle_type = std::coroutine_handler<promise_type>;
    explicit PacketStream(handle_type h) : m_handle{h} {}

    ~PacketStream() {
      if (m_handle) {
        m_handle.destroy()
      }
    }

    // Move-only type
    PacketStream(const PacketStream &) = delete;
    PacketStream &operator=(const PacketStream &) = delete;
    PacketStream(PacketStream &&other) noecept : m_handle{other.m_handle} {
      other.m_handle = {};
    }

    PacketStream &operator=(PacketStream &&other) noexcept {
      if (this != &other) {
        if (m_handle) {
          m_handle.destroy()
        }

        m_handle = other.m_handle;
        other.m_handle = {};
      }

      return *this;
    }

    struct iterator {
      handle_type m_handle;

      iterator &operator++() {
        if (m_handle) {
          m_handle.resume();

          if (m_handle.done()) {
            m_handle = {};
          }
        }

        return *this;
      }

      std::unique_ptr<protocol::Packet> operator*() const {
        return std::move(m_handle.promise().current_packet);
      }

      bool operator==(const iterator &other) const {
        return m_handle == other.m_handle;
      }
    };

    iterator begin() {
      if (m_handle) {
        m_handle.resume();

        if (m_handle.done()) {
          return iterator{{}};
        }
      }

      return iterator{m_handle};
    }

    iterator end() { return iterator{{}}; }

  private:
    handle_type m_handle;
  };

public:
  /**
   * @brief Create capture from configuration
   */
  [[nodiscard]] static utils::Expected<std::unique_ptr<PacketCapture>>
  create(Capture config);

  /**
   * @brief Create live capture from interface
   */
  [[nodiscard]] static utils::Expected<std::unique_ptr<PacketCapture>>
  create_live(
      std::string_view interface_name,
      const CaptureFilter &filter = CaptureFilter::from_bpf("").value());

  /**
   * @brief Create capture from PCAP file
   */
  [[nodiscard]] static utils::Expected<std::unique_ptr<PacketCapture>>
  create_from_file(std::string_view filename);

  virtual ~PacketCapture() = default;

  // Capture control
  /**
   * @brief Start packet capture with callback handler
   */
  [[nodiscard]] virtual utils::Expected<void> start(PacketHandler handler) = 0;

  /**
   * @brief Start capture with coroutine-based processing
   */
  [[nodiscard]] virtual utils::Expected<void>
  start_async(std::stop_token stop_token) = 0;

  /**
   * @brief Stop packet capture
   */
  virtual void stop() = 0;

  /**
   * @brief Check if capture is running
   */
  [[nodiscard]] virtual bool is_running() const noexcept = 0;

  // Packet access
  /**
   * @brief Get next packet (blocking with timeout)
   */
  [[nodiscard]] virtual utils::Expected<std::unique_ptr<protocol::Packet>>
  next_packet(core::Duration timeout = std::chrono::milliseconds{100}) = 0;

  [[nodiscard]] virtual PacketStream packet_stream() = 0;

  // Configuration and Statistics
  /**
   * @brief Get capture statistics
   */
  [[nodiscard]] virtual CaptureStatistics statistics() const = 0;

  /**
   * @brief Set packet filter
   */
  [[nodiscard]] virtual utils::Expected<void>
  set_filter(const CaptureFilter &filter) = 0;

  /**
   * @brief Get current configuration
   */
  [[nodiscard]] virtual const CaptureConfig &config() const noexcept = 0;

  /**
   * @brief Update capture configuration (may require restart)
   */
  [[nodiscard]] virtual utils::Expected<void>
  update_config(const CaptureConfig &new_config) = 0;

protected:
  PocketCapture() = default;
};

/**
 * @brief Utilities for network interface discovery and management
 */
namespace interface_utils {
/**
 * @brief Get list of available network interfaces
 */
[[nodiscard]] utils::Expected<std::vector<NetworkInterface>> list_interfaces();

/**
 * @brief Find network interface by name
 */
[[nodiscard]] utils::Expected<NetworkInterface>
find_interface(std::string_view name);

/**
 * @brief Find default network interface (usually the one with default route)
 */
[[nodiscard]] utils::Expected<NetworkInterface> find_default_interface();

/**
 * @brief Check if interface supports packet capture
 */
[[nodiscard]] bool supports_capture(const NetworkInterface &interface) noexcept;

/**
 * @brief Get interface statistics
 */
struct InterfaceStats {
  std::uint64_t rx_packets{0};
  std::uint64_t tx_packets{0};
  std::uint64_t rx_bytes{0};
  std::uint64_t tx_bytes{0};
  std::uint64_t rx_errors{0};
  std::uint64_t tx_errors{0};
  std::uint64_t rx_dropped{0};
  std::uint64_t tx_dropped{0};

  [[nodiscard]] std::string to_string() const;
};

[[nodiscard]] utils::Expected<InterfaceStats>
get_interface_stats(const NetworkInterface &interface);
} // namespace interface_utils

/**
 * @brief PCAP file utilities
 */
namespace pcap_utils {
/**
 * @brief PCAP file header information
 */
struct PcapFileInfo {
  std::uint32_t magic_number{0};
  std::uint16_t version_major{0};
  std::uint16_t version_minor{0};
  std::uint32_t snaplen{0};
  std::uint32_t data_link_type{0};
  std::uint64_t file_size{0};
  std::uint64_t packet_count{0};
  core::Timestamp first_packet_time{};
  core::Timestamp last_packet_time{};

  [[nodiscard]] std::string to_string() const;
  [[nodiscard]] bool is_valid() const noexcept;
};

/**
 * @brief Read PCAP file information without loading all packets
 */
[[nodiscard]] utils::Expected<PcapFileInfo>
get_pcap_info(std::string_view filename);

/**
 * @brief Validate PCAP file integrity
 */
[[nodiscard]] utils::Expected<void>
validate_pcap_file(std::string_view filename);

/**
 * @brief Convert between PCAP formats
 */
[[nodiscard]] utils::Expected<void>
convert_pcap_format(std::string_view input_file, std::string_view output_file,
                    std::uint32_t new_snaplen = 65535);

/**
 * @brief Split large PCAP file into smaller files
 */
[[nodiscard]] utils::Expected<std::vector<std::string>>
split_pcap_file(std::string_view input_file, std::size_t max_packets_per_file,
                std::string_view output_prefix = "split_");

/**
 * @brief Merge multiple PCAP files
 */
[[nodiscard]] utils::Expected<void>
merge_pcap_files(std::span<const std::string> input_files,
                 std::string_view output_file);
} // namespace pcap_utils

/**
 * @brief Batch packet processing utils
 */
namespace batch_utils {
/**
 * @brief Batch processor for high-throughput packet analysis
 */
class BatchProcessor {
public:
  using BatchHandler =
      std::function<void(std::vector<std::unique_ptr<protocol::Packet>>)>;

public:
  /**
   * @brief Add packet to current batch
   */
  void add_packet(std::unique_ptr<protocol::Packet> packet);

  /**
   * @brief Force flush current batch
   */
  void flush();

  /**
   * @brief Get batch processing statistics
   */
  struct BatchStats {
    std::uint64_t batches_processed{0};
    std::uint64_t packets_processed{0};
    core::Duration total_processing_time{};
    core::Duration avg_batch_time{};

    [[nodiscard]] std::string to_string() const;
  };

  [[nodiscard]] BatchStats statistics() const;

private:
  std::size_t m_batch_size;
  BatchHandler m_handler;
  std::vector<std::unique_ptr<protocol::Packet>> m_current_batch;
  BatchStats m_stats;
};

/**
 * @brief Parallel packet processing with work queues
 */
class ParallelProcessor {
public:
  using PacketProcessor =
      std::function<void(std::unique_ptr<protocol::Packet>)>;

public:
  explicit ParallelProcessor(std::size_t num_threads, PacketProcessor processor,
                             std::size_t queue_size = 10000);

  ~ParallelProcessor();

  /**
   * @brief Submit packet for processing
   */
  [[nodiscard]] bool submit_packet(std::unique_ptr<protocol::Packet> packet);

  /**
   * @brief Wait for all pending packets to be processed
   */
  void wait_for_completion();

  /**
   * @brief Get processing statistics
   */
  struct ProcessingStats {
    std::uint64_t packets_submitted{0};
    std::uint64_t packets_processed{0};
    std::uint64_t packets_dropped{0};
    std::uint32_t queue_depth{0};

    [[nodiscard]] std::string to_string() const;
  };

  [[nodiscard]] ProcessingStats statistics() const;

private:
  class Implementation;
  std::unique_ptr<Implementation> m_impl;
}
} // namespace batch_utils
} // namespace netguard::capture