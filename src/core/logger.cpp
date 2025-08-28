/**
 * @file logger.cpp
 * @author Carlos Salguero
 * @brief Logger implementation
 * @version 0.1
 * @date 2025-08-28
 *
 * @copyright Copyright (c) 2025
 *
 */

#include <netguard/core/logger.hpp>
#include <netguard/utils/expected.hpp>
#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace netguard::core {
std::unique_ptr<Logger> Logger : m_instance;

utils::Expected<void> Logger::initialize(const LoggerConfig &config) {
  try {
    std::vector<spdlog::sink_ptr> sinks;
    if (config.enable_console) {
      auto console_sink =
          std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

      console_sink->set_pattern(config.pattern);
      sinks.push_back(console_sink);
    }

    if (config.enable_file) {
      auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
          config.log_file, config.max_file_size, config.max_files);

      file_sink->set_pattern(config.pattern);
      sinks.push_back(file_sink);
    }

    auto logger = std::make_shared<spdlog::async_logger>(
        "netguard", sinks.begin(), sinks.end(), spdlog::thread_pool(),
        spdlog::async_overflow_policy::block);

    logger->set_level(to_spdlog_level(config.level));
    logger->flush_on(spdlog::level::err);

    spdlog::register_logger(logger);
    spdlog::set_default_logger(logger);

    m_instance = std::unique_ptr<Logger>(new Logger(logger, config.level));
    return {};
  } catch (const spdlog::spdlog_ex &ex) {
    return tl::unexpected{utils::make_system_error(
        ErrorCategory::Configuration,
        std::format("Failed to initialize logger: {}", ex.what()), 0)};
  }
}

Logger &Logger::instance() noexcept {
  if (!m_instance) {
    LoggerConfig default_config;
    initialize(default_config).value();
  }

  return *m_instance;
}
} // namespace netguard::core