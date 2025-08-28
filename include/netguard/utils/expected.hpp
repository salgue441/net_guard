/**
 * @file expected.hpp
 * @author Carlos Salguero
 * @brief Error handling utilities using tl::expected
 * @version 0.1
 * @date 2025-08-28
 *
 * @copyright Copyright (c) 2025
 *
 * This file provides Go-style error handling for NetGuard using the
 * tl::expected library. All fallible operations should return
 * Expected<T, Error> instead of throwing exceptions.
 */

#pragma once

#include <format>
#include <source_location>
#include <string>
#include <string_view>
#include <system_error>
#include <tl/expected.hpp>

namespace netguard::utils {
/**
 * @brief Error categories for different subsystems.
 *
 * Each category represents a different area of the system where
 * errors can occur, allowing for structured error handling.
 */
enum class ErrorCategory : std::uint8_t {
  Unknown = 0,
  Network,       ///< Network-related errors (socket, capture)
  Protocol,      ///< Protocol parsing errors
  Detection,     ///< Detection engine errors
  Configuration, ///< Configuration parsing errors
  FileSystem,    ///< File I/O errors
  Memory,        ///< Memory allocation errors
  Threading,     ///< Thread synchronization errors
  Validation     ///< Input validation errors
};

/**
 * @brief Detailed error information with context
 *
 * Provides rich error information including category, message,
 * source location, and optional system error code.
 */
struct Error {
  ErrorCategory category{ErrorCategory::Unknown};
  std::string message;
  std::source_location location{std::source_location::current()};
  std::error_code system_error;

  /**
   * @brief Construct error with message and category
   */
  explicit Error(
      ErrorCategory cat, std::string_view msg,
      std::source_location loc = std::source_location::current()) noexcept
      : category{cat}, message{msg}, location{loc} {}

  /**
   * @brief Construct error with system error code
   */
  Error(ErrorCategory cat, std::string_view msg, std::error_code ec,
        std::source_location loc = std::source_location::current()) noexcept
      : category{cat}, message{msg}, location{loc}, system_error{ec} {}

  /**
   * @brief Get formatted error message with context
   */
  [[nodiscard]] std::string what() const noexcept {
    std::string result = std::format("[{}:{}] {}: {}", location.file_name(),
                                     location.line(), category_name(), message);

    if (system_error) {
      result += std::format(" (system: {})", system_error.message());
    }

    return result;
  }

  /**
   * @brief Get human-readable category name
   */
  [[nodiscard]] std::string_view category_name() const noexcept {
    switch (category) {
    case ErrorCategory::Network:
      return "Network";
    case ErrorCategory::Protocol:
      return "Protocol";
    case ErrorCategory::Detection:
      return "Detection";
    case ErrorCategory::Configuration:
      return "Configuration";
    case ErrorCategory::FileSystem:
      return "FileSystem";
    case ErrorCategory::Memory:
      return "Memory";
    case ErrorCategory::Threading:
      return "Threading";
    case ErrorCategory::Validation:
      return "Validation";
    case ErrorCategory::Unknown:
    default:
      return "Unknown";
    }
  }
};

/**
 * @brief Type alias for expected value with NetGuard errors.
 *
 * This is the primary return type for all fallible operations. Use this
 * instead of exceptions for better performance and explicit error handling.
 */
template <typename T> using Expected = tl::expected<T, Error>;

/**
 * @brief Type alias for operations that can fail without returning a value.
 */
using Result = Expected<void>;

/**
 * @brief Helper macro for creating errors with automatic source location.
 *
 * Usage: NG_ERROR(ErrorCategory::Network, "Failed to bind socket")
 */
#define NG_ERROR(category, message)                                            \
  ::netguard::utils::Error {                                                   \
    category, message, std::source_location::current()                         \
  }

/**
 * @brief Helper macro for creating errors with system error code
 *
 * Usage: NG_SYSTEM_ERROR(ErrorCategory::Network, "bind failed", error)
 */
#define NG_SYSTEM_ERROR(category, message, error_code)                         \
  ::netguard::utils::Error {                                                   \
    category, message, std::make_error_code(std::errc{error_code}),            \
        std::source_location::current()                                        \
  }

/**
 * @brief Try macro for early return on error (Go-style error handling)
 *
 * If the expression returns an error, immediately return that error.
 * Otherwise, unwrap the value and continue.
 *
 * Usage:
 *  auto socket = NG_TRY(create_socket());
 *  NG_TRY(bind_socket(socket));
 */
#define NG_TRY(expr)                                                           \
  ({                                                                           \
    auto &&_ng_result = (expr);                                                \
    if (!_ng_result) [[unlikely]] {                                            \
      return tl::unexpected{std::move(_ng_result.error())};                    \
    }                                                                          \
    std::move(*_ng_result);                                                    \
  })

/**
 * @brief Try macro that only checks for errors without unwrapping value
 *
 * Usage: NG_TRY_VOID(configure_logging());
 */
#define NG_TRY_VOID(expr)                                                      \
  do {                                                                         \
    auto &&_ng_result = (expr);                                                \
    if (!ng_result) [[unlikely]] {                                             \
      return tl::unexpected{std::move(_ng_result.error())};                    \
    }                                                                          \
  } while (0)

/**
 * @brief Convert system error codes to NetGuard errors
 */
[[nodiscard]] inline Error make_system_error(
    ErrorCategory category, std::string_view message, int error_code,
    std::source_location loc = std::source_location::current()) noexcept {
  return Error{category, message, std::make_error_code(std::errc{error_code}),
               loc};
}

/**
 * @brief Convert errno to NetGuard error
 */
[[nodiscard]] inline Error make_errno_error(
    ErrorCategory category, std::string_view message,
    std::source_location loc = std::source_location::current()) noexcept {
  return make_system_error(category, message, errno, loc);
}

/**
 * @brief Create validation error for invalid input
 */
[[nodiscard]] inline Error make_validation_error(
    std::string_view message,
    std::source_location loc = std::source_location::current()) noexcept {
  return Error{ErrorCategory::Validation, message, loc};
}

/**
 * @brief Create network error
 */
[[nodiscard]] inline Error make_network_error(
    std::string_view message,
    std::source_location loc = std::source_location::current()) noexcept {
  return Error{ErrorCategory::Network, message, loc};
}

/**
 * @brief Create protocol parsing error
 */
[[nodiscard]] inline Error make_protocol_error(
    std::string_view message,
    std::source_location loc = std::source_location::current()) noexcept {
  return Error{ErrorCategory::Protocol, message, loc};
}
} // namespace netguard::utils

/**
 * @brief Format support for Error type
 *
 * Allows using Error objects with std::format and fmt library
 */
template <> struct std::formatter<netguard::utils::Error> {
  constexpr auto parse(format_parse_context &ctx) { return ctx.begin(); }

  template <typename FormatContext>
  auto format(const netguard::utils::Error &error, FormatContext &ctx) {
    return format_to(ctx.out(), "{}", error.what());
  }
}