/**
 * @file logger.hpp
 * @author Carlos Salguero
 * @brief High-performance structured logging system for NetGuard
 * @version 0.1
 * @date 2025-08-28
 *
 * @copyright Copyright (c) 2025
 *
 * This provides a thread-safe, high-performance logging system
 * built on spdlog with structured logging capabilities and automatic
 * log rotation.
 */

#pragma once

#include "types.hpp"
#include "utils/expected.hpp"

#include <memory>
#include <source_location>
#include <spdlog/fmt/fmt.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <string_view>

namespace netguard::core {
/**
 * @brief Log level enumeration
 *
 * Maps to spdlog levels but provides NetGuard-specific semantics
 */
enum class LogLevel : std::uint8_t {
  Trace = 0,    ///< Very detailed debug information
  Debug = 1,    ///< General debug information
  Info = 2,     ///< Informational messages
  Warning = 3,  ///< Warning conditions
  Error = 4,    ///< Error conditions
  Critical = 5, ///< Critical error conditions
  Off = 6       ///< Disable logging
};

/**
 * @brief Structured log context for adding metadata to log entries.
 *
 * Provides a fluent interface for adding contextual information to log entries
 * without runtime overhead when logging is disabled.
 */
class LogContext {
public:
  LogContext() = default;

  /**
   * @brief Add key-value pair to log context
   */
  template <typename T> LogContext &with(std::string_view key, T &&value) & {
    if constexpr (std::is_arithmetic_v<std::decay_t<T>>) {
      m_context += fmt::format(" {}={}", key, value);
    } else {
      m_context += fmt::format(" {}=\"{}\"", key, value);
    }

    return *this;
  }

  /**
   * @brief Add key-value pair to log context (rvalue overload)
   */
  template <typename T> LogContext &&with(std::string_view key, T &&value) && {
    return std::move(with(key, std::forward<T>(value)));
  }

  /**
   * @brief Add packet information to context
   */
  LogContext &with_packet(PacketId id, PacketSize size) & {
    return with("packet_id", id.get()).with("packet_size", size);
  }

  LogContext &&with_packet(PacketId id, PacketSize size) && {
    return std::move(with_packet(id, size));
  }

  /**
   * @brief Add flow information to context
   */
  LogContext &with_flow(const FlowId &flow) & {
    return with("src_addr", flow.src_addr.to_string())
        .with("dst_addr", flow.dst_addr.to_string())
        .with("src_port", flow.src_port)
        .with("dst_port", flow.dst_port)
        .with("protocol", static_cast<int>(flow.protocol));
  }

  LogContext &&with_flow(const FlowId &flow) && {
    return std::move(with_flow(flow));
  }

  /**
   * @brief Add error information to context
   */
  LogContext &with_error(const Error &error) & {
    return with("error_category", error.category_name())
        .with("error_message", error.message);
  }

  LogContext &&with_error(const Error &error) && {
    return std::move(with_error(error));
  }

  /**
   * @brief Get formatted context string
   */
  [[nodiscard]] const std::string &str() const noexcept { return m_context; }

private:
  std::string m_context;
};

/**
 * @brief Logger configuration
 */
struct LoggerConfig {
  LogLevel level{LogLevel::Info};
  std::string log_file{"netguard.log"};
  std::size_t max_file_size{10 * 1024 * 1024}; ///< 10MB default
  std::size_t max_files{5};
  bool enable_console{true};
  bool enable_file{true};
  std::string pattern{"[%Y-%m-%d %H:%M:%S.%f] [%l] [%t] %v"};
};

/**
 * @brief High-performance logger with structured logging support
 *
 * Thread-safe logger built on spdlog with NetGuard-specific features:
 * - Structured logging with context
 * - Automatic log rotation
 * - Zero-copy message formatting where possible
 * - Source location tracking in debug builds
 */
class Logger : public NonCopyable {
public:
  /**
   * @brief Initialize global logger with configuration
   */
  [[nodiscard]] static utils::Expected<void>
  initialize(const LoggerConfig &config);

  /**
   * @brief Get global logger instance
   */
  [[nodiscard]] static Logger &instance() noexcept;

  /**
   * @brief Check if logging is enabled for given level
   */
  [[nodiscard]] bool should_log(LogLevel level) const noexcept {
    return level >= m_current_level;
  }

  /**
   * @brief Log message with context
   */
  template <typename... Args>
  void log(LogLevel level, const LogContext &context,
           fmt::format_string<Args...> format, Args &&...args,
           std::source_location loc = std::source_location::current()) {
    if (!should_log(level)) [[likely]] {
      return;
    }

    auto message = fmt::format(format, std::forward<Args>(args)...);

#ifdef NG_DEBUG
    auto full_message = fmt::format("[{}:{}] {}{}", loc.file_name(), loc.line(),
                                    message, context.str());
#else
    auto full_message = fmt::format("{}{}", message, context.str());
#endif

    m_spdlog_logger->log(to_spdlog_level(level), full_message);
  }

  /**
   * @brief Log message without context
   */
  template <typename... Args>
  void log(LogLevel level, fmt::format_string<Args...> format, Args &&...args,
           std::source_location loc = std::source_location::current()) {
    log(level, LogContext{}, format, std::forward<Args>(args)..., loc);
  }

  // Convenience methods for different log levels
  template <typename... Args>
  void trace(fmt::format_string<Args...> format, Args &&...args) {
    log(LogLevel::Trace, format, std::forward<Args>(args)...);
  }

  template <typename... Args>
  void trace(const LogContext &context, fmt::format_string<Args...> format,
             Args &&...args) {
    log(LogLevel::Trace, context, format, std::forward<Args>(args)...);
  }

  template <typename... Args>
  void debug(fmt::format_string<Args...> format, Args &&...args) {
    log(LogLevel::Debug, format, std::forward<Args>(args)...);
  }

  template <typename... Args>
  void debug(const LogContext &context, fmt::format_string<Args...> format,
             Args &&...args) {
    log(LogLevel::Debug, context, format, std::forward<Args>(args)...);
  }

  template <typename... Args>
  void info(fmt::format_string<Args...> format, Args &&...args) {
    log(LogLevel::Info, format, std::forward<Args>(args)...);
  }

  template <typename... Args>
  void info(const LogContext &context, fmt::format_string<Args...> format,
            Args &&...args) {
    log(LogLevel::Info, context, format, std::forward<Args>(args)...);
  }

  template <typename... Args>
  void warning(fmt::format_string<Args...> format, Args &&...args) {
    log(LogLevel::Warning, format, std::forward<Args>(args)...);
  }

  template <typename... Args>
  void warning(const LogContext &context, fmt::format_string<Args...> format,
               Args &&...args) {
    log(LogLevel::Warning, context, format, std::forward<Args>(args)...);
  }

  template <typename... Args>
  void error(fmt::format_string<Args...> format, Args &&...args) {
    log(LogLevel::Error, format, std::forward<Args>(args)...);
  }

  template <typename... Args>
  void error(const LogContext &context, fmt::format_string<Args...> format,
             Args &&...args) {
    log(LogLevel::Error, context, format, std::forward<Args>(args)...);
  }

  template <typename... Args>
  void critical(fmt::format_string<Args...> format, Args &&...args) {
    log(LogLevel::Critical, format, std::forward<Args>(args)...);
  }

  template <typename... Args>
  void critical(const LogContext &context, fmt::format_string<Args...> format,
                Args &&...args) {
    log(LogLevel::Critical, context, format, std::forward<Args>(args)...);
  }

  /**
   * @brief Flush all pending log messages
   */
  void flush() {
    if (m_spdlog_logger) {
      m_spdlog_logger->flush();
    }
  }

  /**
   * @brief Set log level at runtime
   */
  void set_level(LogLevel level) {
    m_current_level = level;
    if (m_spdlog_logger) {
      m_spdlog_logger->set_level(to_spdlog_level(level));
    }
  }

private:
  std::shared_ptr<spdlog::logger> m_spdlog_logger;
  LogLevel m_current_level{LogLevel::Info};

private:
  static inline std::unique_ptr<Logger> m_instance;

private:
  explicit Logger(std::shared_ptr<spdlog::logger> logger, LogLevel level)
      : m_spdlog_logger{std::move(logger)}, m_current_level{level} {}

  [[nodiscard]] static spdlog::level::level_enum
  to_spdlog_level(LogLevel level) noexcept {
    switch (level) {
    case LogLevel::Trace:
      return spdlog::level::trace;
    case LogLevel::Debug:
      return spdlog::level::debug;
    case LogLevel::Info:
      return spdlog::level::info;
    case LogLevel::Warning:
      return spdlog::level::warn;
    case LogLevel::Error:
      return spdlog::level::err;
    case LogLevel::Critical:
      return spdlog::level::critical;
    case LogLevel::Off:
      return spdlog::level::off;
    }

    return spdlog::level::info;
  }
};

// Convenience macros for logging
/**
 * @brief Get global logger instance
 */
#define NG_LOG() ::netguard::core::Logger::instance()

/**
 * @brief Convenience macros for different log levels
 */
#define NG_TRACE(...) NG_LOG().trace(__VA_ARGS__)
#define NG_DEBUG(...) NG_LOG().debug(__VA_ARGS__)
#define NG_INFO(...) NG_LOG().info(__VA_ARGS__)
#define NG_WARNING(...) NG_LOG().warning(__VA_ARGS__)
#define NG_ERROR_LOG(...) NG_LOG().error(__VA_ARGS__)
#define NG_CRITICAL(...) NG_LOG().critical(__VA_ARGS__)

/**
 * @brief Log error and return it (for error propagation)
 */
#define NG_LOG_AND_RETURN_ERROR(error)                                         \
  do {                                                                         \
    NG_ERROR_LOG(::netguard::core::LogContext{}.with_error(error),             \
                 "Operation failed: {}", (error).what());                      \
    return tl::unexpected{error};                                              \
  } while (0)

/**
 * @brief Log result of an operation and return error if failed
 */
#define NG_LOG_TRY(expr, message)                                              \
  ({                                                                           \
    auto &&_ng_result = (expr);                                                \
    if (!_ng_result) [[unlikely]] {                                            \
      NG_ERROR_LOG(                                                            \
          ::netguard::core::LogContext{}.with_error(_ng_result.error()),       \
          "{}: {}", message, _ng_result.error().what());                       \
      return tl::unexpected{std::move(_ng_result.error())};                    \
    }                                                                          \
    std::move(*_ng_result);                                                    \
  })
} // namespace netguard::core