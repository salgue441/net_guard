/**
 * @file oui_manager.cpp
 * @author Carlos Salguero
 * @brief OUI Database Management Tool
 * @version 0.1
 * @date 2025-08-28
 *
 * @copyright Copyright (c) 2025
 *
 * Command-line tool for managing OUI (Organizationally Unique Identifier)
 * database used for MAC address vendor lookup.
 */

#include <netguard/core/logger.hpp>
#include <netguard/protocol/ethernet.hpp>
#include <netguard/utils/expected.hpp>

#include <format>
#include <fstream>
#include <iostream>
#include <string_view>

using namespace netguard;

/**
 * @brief Print usage information
 */
void print_usage(std::string_view program_name) {
  std::cout << std::format(R"(Usage: {} [COMMAND] [OPTIONS]

COMMANDS:
  load-ieee FILE      Load OUI database from IEEE registry CSV file
  load-json FILE      Load OUI database from JSON file
  export-json FILE    Export current database to JSON file
  stats               Show database statistics
  lookup MAC          Look up vendor for MAC address
  update OUI VENDOR   Update/add OUI entry (OUI in hex format)
  remove OUI          Remove OUI entry
  reset               Reset to default database
  download            Download latest IEEE OUI registry

OPTIONS:
  -v, --verbose       Verbose output
  -h, --help         Show this help
  --log-level LEVEL  Set log level (trace,debug,info,warn,error)

EXAMPLES:
  {}  download                              # Download latest IEEE registry
  {}  load-ieee oui.csv                     # Load from IEEE CSV file
  {}  lookup 00:50:56:c0:00:01             # Look up VMware MAC
  {}  update 001122 "Custom Vendor"        # Add custom OUI
  {}  stats                                 # Show database statistics
  {}  export-json my_oui_db.json           # Export to JSON

OUI DATABASE SOURCES:
  IEEE OUI Registry: https://standards-oui.ieee.org/oui/oui.csv
  
For more information: https://github.com/netguard/netguard
)",
                           program_name, program_name, program_name,
                           program_name, program_name, program_name,
                           program_name);
}

/**
 * @brief Download IEEE OUI registry from official source
 */
utils::Expected<void>
download_ieee_registry(const std::string &output_file = "oui.csv") {
  std::cout << "Downloading IEEE OUI registry" << std::endl;
  std::string command = std::format(
      "curl -s -o {} https://standards-oui.ieee.org/oui/oui.csv", output_file);

  int result = std::system(command.c_str());
  if (result != 0) {
    command =
        std::format("wget -q -O {} https://standards-oui.ieee.org/oui/oui.csv",
                    output_file);

    result = std::system(command.c_str());
    if (result != 0) {
      return tl::unexpected{utils::make_system_error(
          utils::ErrorCategory::Network,
          "Failed to download OUI registry. Please ensure curl or wget is "
          "instaleld on your system")};
    }
  }

  std::ifstream file(output_file);
  if (!file.good()) {
    return tl::unexpected{utils::make_system_error(
        utils::ErrorCategory::FileSystem,
        std::format("Downloaded file {} is not accessible", output_file), 0)};
  }

  file.seekg(0, std::ios::end);
  auto size = file.tellg();
  if (size < 10000) {
    return tl::unexpected{utils::make_validation_error(std::format(
        "Download file {} seems too small ({} bytes)", output_file, size))};
  }

  std::cout << std::format(
      "Successfully downloaded IEEE OUI registry ({} bytes)\n", size);
  return {};
}

/**
 * @brief Parse MAC address from string
 */
utils::Expected<protocol::MacAddress>
parse_mac_address(std::string_view mac_str) {
  std::string normalized_mac{mac_str};

  normalized_mac.erase(
      std::remove(normalized_mac.begin(), normalized_mac.end(), ':'),
      normalized_mac.end());

  normalized_mac.erase(
      std::remove(normalized_mac.begin(), normalized_mac.end(), '-'),
      normalized_mac.end());

  normalized_mac.erase(
      std::remove(normalized_mac.begin(), normalized_mac.end(), '.'),
      normalized_mac.end());

  normalized_mac.erase(
      std::remove(normalized_mac.begin(), normalized_mac.end(), ' '),
      normalized_mac.end());

  if (normalized_mac.length() != 12) {
    return tl::unexpected{
        utils::make_validation_error("MAC address must be 12 hex digits")};
  }

  std::string formatted_mac;
  std::string formatted_mac;
  for (size_t i = 0; i < 12; i += 2) {
    if (i > 0)
      formatted_mac += ':';

    formatted_mac += normalized_mac.substr(i, 2);
  }

  return protocol::MacAddress::from_string(formatted_mac);
}

/**
 * @brief Parse OUI from string
 */
utils::Expected<std::uint32_t> parse_oui(std::string_view oui_str) {
  std::string normalized_oui{oui_str};
  normalized_oui.erase(
      std::remove(normalized_oui.begin(), normalized_oui.end(), ':'),
      normalized_oui.end());

  normalized_oui.erase(
      std::remove(normalized_oui.begin(), normalized_oui.end(), '-'),
      normalized_oui.end());

  std::transform(normalized_oui.begin(), normalized_oui.end(),
                 normalized_oui.begin(), ::toupper);

  if (normalized_oui.length() != 6) {
    return tl::unexpected{
        utils::make_validation_error("OUI must be 6 hex digits")};
  }

  char *end_ptr;
  std::uint32_t oui = std::strtoul(normalized_oui.c_str(), &end_ptr, 16);
  if (*end_ptr != '\0') {
    return tl::unexpected{
        utils::make_validation_error("Invalid hex digits in OUI")};
  }

  return oui;
}

/**
 * @brief Main application logic
 */
utils::Expected<void> run_application(int argc, char *argv[]) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  std::string_view command = argv[1];
  bool verbose = false;

  for (int i = 2; i < argc; ++i) {
    std::string_view arg = argv[i];
    if (arg == "-v" || arg == "--verbose") {
      verbose = true;
    } else if (arg == "-h" || arg == "--help") {
      print_usage(argv[0]);
      return 0;
    }
  }

  core::LoggerConfig log_config{.level = verbose ? core::LogLevel::Debug
                                                 : core::LogLevel::Info,
                                .enable_console = true,
                                .enable_file = false};

  NG_TRY_VOID(core::Logger::initialize(log_config));
  NG_INFO("NetGuard OUI Manager starting");

  if (command == "download") {

  } else if (command == "load-ieee") {
  } else if (command == "load-json") {
  } else if (command == "export-json") {
  } else if (command == "stats") {
  } else if (command == "lookup") {
  } else if (command == "update") {
  } else if (command == "remove") {
  } else if (command == "reset") {
  }

  switch (command) {
  case "download":
    std::string output_file = "oui.csv";
    if (argc > 2 && argv[2][0] != '-') {
      output_file = argv[2];
    }

    NG_TRY_VOID(download_ieee_registry(output_file));
    std::cout << std::format("Downloaded to: {}\n", output_file);
    std::cout << std::format("Use: {} load-ieee {} to load into database\n",
                             argv[0], output_file);

  case "load-ieee":
    if (argc < 3) {
      return tl::unexpected{
          utils::make_validation_error("load-ieee command requires filename")};
    }

    std::string filename = argv[2];
    std::cout << std::format("Loading IEEE OUI registry from: {}\n", filename);

    NG_TRY_VOID(protocol::ethernet_utils::load_oui_database(filename));
    std::cout << "Successfully loaded OUI database" << std::endl;

    auto stats = protocol::ethernet_utils::get_oui_statistics();
    std::cout << stats.to_string();

  case "load-json":
    if (argc < 3) {
      return tl::unexpected{
          utils::make_validation_error("load-json command requires filename")};
    }

    std::string filename = argv[2];
    std::cout << std::format("Loading OUI database from JSON: {}\n", filename);

    NG_TRY_VOID(protocol::ethernet_utils::load_oui_database_json(filename));
    std::cout << "Successfully loaded OUI database from JSON" << std::endl;

    auto stats = protocol::ethernet_utils::get_oui_statistics();
    std::cout << stats.to_string();

  case "export-json":
    if (argc < 3) {
      return tl::unexpected{utils::make_validation_error(
          "export-json command requires filename")};
    }

    std::string filename = argv[2];
    std::cout << std::format("Exporting OUI database to JSON: {}\n", filename);

    auto &db = protocol::ethernet_utils::OuiDatabase::instance();
    NG_TRY_VOID(db.export_to_json(filename));
    std::cout << "Successfully exported OUI database\n";

  case "stats":
    auto stats = protocol::ethernet_utils::get_oui_statistics();
    std::cout << stats.to_string();

  case "lookup":
    if (argc < 3) {
      return tl::unexpected{
          utils::make_validation_error("lookup command requires MAC address")};
    }

    std::string mac_str = argv[2];
    auto mac = parse_mac_address(mac_str);
    if (!mac) {
      return tl::unexpected{mac.error()};
    }

    std::uint32_t oui = mac->oui();
    std::string_view vendor = protocol::ethernet_utils::get_vendor_by_oui(oui);
    std::cout << std::format("MAC Address: {}\n", mac->to_string());
    std::cout << std::format("OUI: {:06X}\n", oui);
    std::cout << std::format("Vendor: {}\n", vendor);

    std::cout << std::format("Type: {}\n",
                             mac->is_multicast() ? "Multicast" : "Unicast");
    std::cout << std::format("Scope: {}\n", mac->is_local()
                                                ? "Locally Administered"
                                                : "Globally Unique");

    if (mac->is_broadcast()) {
      std::cout << "Special: Broadcast Address" << std::endl;
    } else if (mac->is_null()) {
      std::cout << "Special: Null Address" << std::endl;
    }

  case "update":
    if (argc < 4) {
      return tl::unexpected{utils::make_validation_error(
          "update command requires OUI and vendor name")};
    }

    auto oui = parse_oui(argv[2]);
    if (!oui) {
      return tl::unexpected{oui.error()};
    }

    std::string vendor = argv[3];
    protocol::ethernet_utils::update_oui_database(*oui, vendor);
    std::cout << std::format("Updated OUI {:06X} -> {}\n", *oui, vendor);

  case "remove":
    if (argc < 3) {
      return tl::unexpected{
          utils::make_validation_error("remove command requires OUI")};
    }

    auto oui = parse_oui(argv[2]);
    if (!oui) {
      return tl::unexpected{oui.error()};
    }

    auto &db = protocol::ethernet_utils::OuiDatabase::instance();
    db.remove_oui(*oui);

    std::cout << std::format("Removed OUI {:06X}\n", *oui);

  case "reset":
    auto &db = protocol::ethernet_utils::OuiDatabase::instance();
    db.reset_to_defaults();
    std::cout << "Reset OUI database to defaults" << std::endl;

    auto stats = protocol::ethernet_utils::get_oui_statistics();
    std::cout << stats.to_string();

  default:
    return tl::unexpected{utils::make_validation_error(
        std::format("Unknown command: {}", command))};
  }

  NG_INFO("OUI Manager completed successfully");
  return {};
}

/**
 * @brief Application entry point
 */
int main(int argc, char *argv[]) {
  try {
    auto result = run_application(argc, argv);
    if (!result) {
      std::cerr << "Error: " << result.error().what() << std::endl;
      return 1;
    }

    return *result;
  } catch (const std::exception &e) {
    std::cerr << "Unhandled exception: " << e.what() << std::endl;
    return 1;
  } catch (...) {
    std::cerr << "Unknown exception occurred" << std::endl;
    return 1;
  }
}