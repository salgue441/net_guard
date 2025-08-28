/**
 * @file ethernet.cpp
 * @author Carlos Salguero
 * @brief Ethernet protocol implementation
 * @version 0.1
 * @date 2025-08-28
 *
 * @copyright Copyright (c) 2025
 *
 */

#include <format>
#include <iomanip>
#include <netguard/core/logger.hpp>
#include <netguard/protocol/ethernet.hpp>
#include <netguard/utils/expected.hpp>
#include <sstream>

namespace netguard::protocol {
// MacAddress implementation
utils::Expected<MacAddress> MacAddress::from_string(std::string_view str) {
  if (str.length() != 17) {
    return tl::unexpected{
        utils::make_validation_error("Invalid MAC address length")};
  }

  m_octetst octets;
  std::size_t octet_index = 0;

  for (std::size_t i = 0; i < str.length(); i += 3) {
    if (octet_index >= 6) {
      return tl::unexpected{
          utils::make_validation_error("Too many octets in MAC address")};
    }

    if (octet_index < 5 && str[i + 2] != ":") {
      return tl::unexpected{utils::make_validation_error(
          "Invalid MAC address format, missing colon")};
    }

    std::string octet_str{str.substr(i, 2)};
    char *end_ptr;
    unsigned long octet_val = std::strtoul(octet_str.c_str(), &end_ptr, 16);

    if (*end_ptr != '\0' || octet_val > 255) {
      return tl::unexpected{utils::make_validation_error(
          std::format("Invalid hex value in MAC address: {}", octet_str))};
    }

    octets[octet_index++] = static_cast<std::uint8_t>(octet_val);
  }

  return MacAddress{octets};
}

std::string MacAddress::to_string() const { return to_string(':'); }
std::string MacAddress::to_string(char separator) const {
  return std::format("{:02x}{}{:02x}{}{:02x}{}{:02x}{}{:02x}{}{:02x}",
                     m_octets[0], separator, m_octets[1], separator,
                     m_octets[2], separator, m_octets[3], separator,
                     m_octets[4], separator, m_octets[5]);
}

// EtherType utilities
std::string_view ethertype_to_string(EtherType type) noexcept {
  switch (type) {
  case EtherType::IPv4:
    return "IPv4";
  case EtherType::ARP:
    return "ARP";
  case EtherType::RARP:
    return "RARP";
  case EtherType::VLAN:
    return "VLAN";
  case EtherType::IPv6:
    return "IPv6";
  case EtherType::MPLS:
    return "MPLS";
  case EtherType::PPPoE_Discovery:
    return "PPPoE-Discovery";
  case EtherType::PPPoE_Session:
    return "PPPoE-Session";
  case EtherType::LLDP:
    return "LLDP";
  default:
    return "Unknown";
  }
}

// EthernetHeader Implementation
utils::Expected<EthernetHeader>
EthernetHeader::parse(core::ByteSpan data) noexcept {
  if (data.size() < 14) {
    return tl::unexpected{
        utils::make_protocol_error("Insufficient data for Ethernet Header")};
  }

  EthernetHeader header;
  std::size_t offset = 0;

  auto dst_mac = MacAddress::parse(data.subspan(offset, 6));
  if (!dst_mac) {
    return tl::unexpected{dst_mac.error()};
  }

  header.destination += *dst_mac;
  offset += 6;

  auto src_mac = MacAddress::parse(data.subspan(offset, 6));
  if (!src_mac) {
    return tl::unexpected{src_mac.error()};
  }

  header.source = *src_mac;
  offset += 6;

  auto ethertype_raw = core::bytes::read<std::uint16_t>(data, offset);
  if (!ethertype_raw) {
    return tl::unexpected{ethertype_raw.error()};
  }

  offset += 2;
  std::uint16_t current_ethertype = *ethertype_raw;
  while (current_ethertype == static_cast<std::uint16_t>(EtherType::VLAN)) {
    if (offset + 2 > data.size()) {
      return tl::unexpected{
          utils::make_protocol_error("Insufficient data for VLAN tag")};
    }

    auto vlan_raw = core::bytes::read<std::uint16_t>(data, offset);
    if (!vlan_raw) {
      return tl::unexpected{vlan_raw.error()};
    }

    VlanTag vlan = VlanTag::from_raw(*vlan_raw);
    header.vlan_tags.push_back(vlan);
    offset += 2;

    if (offset + 2 > data.size()) {
      return tl::unexpected{
          utils::make_protocol_error("Insufficient data after Vlan tag")};
    }

    auto next_ethertype = core::bytes::read<std::uint16_t>(data, offset);
    if (!next_ethertype) {
      return tl::unexpected{next_ethertype.error()};
    }

    current_ethertype = *next_ethertype;
    offset += 2;
  }

  header.ethertype = static_cast<EtherType>(current_ethertype);
  header.payload_offset = offset;

  return header;
}

utils::Expected<void> EthernetHeader::validate() const noexcept {
  if (source.is_null()) {
    return tl::unexpected{
        utils::make_protocol_error("Invalid null source MAC address")};
  }

  for (const auto &vlan : vlan_tags) {
    if (!vlan.is_valid()) {
      return tl::unexpected{utils::make_protocol_error(
          std::format("Invalid VLAN ID: {}", vlan.vlan_id))};
    }
  }

  if (ethernet_utils::is_valid_ethertype(
          static_cast<std::uint16_t>(ethertype))) {
    // Valid EtherType
  } else {
    NG_DEBUG("Detected IEEE 802.3 frame with length field: {}",
             static_cast<std::uint16_t>(ethertype));
  }

  return {};
}

std::string EthernetHeader::to_string() const {
  std::string result =
      std::format("Ethernet: {} -> {} [{}]", source.to_string(),
                  destination.to_string(), ethertype_to_string(ethertype));

  if (!vlan_tags.empty()) {
    result += " VLANs:";
    for (const auto &vlan : vlan_tags) {
      result += std::format(" {}", vlan.vlan_id);
    }
  }

  result += std::format(" ({})", frame_type());
  return result;
}

utils::Expected<std::size_t>
EthernetHeader::serialize(core::MutableByteSpan buffer) const noexcept {
  const std::size_t required_size = serialized_size();
  if (buffer.size() < required_size) {
    return tl::unexpected{utils::make_protocol_error(
        "Insufficient buffer space for Ethernet header")};
  }

  std::size_t offset = 0;

  std::memcpy(buffer.data() + offset, destination.octets().data(), 6);
  offset += 6;

  std::memcpy(buffer.data() + offset, source.octets().data(), 6);
  offset += 6;

  for (const auto &vlan : vlan_tags) {
    NG_TRY_VOID(core::bytes::write(
        buffer, static_cast<std::uint16_t>(EtherType::VLAN), offset));
    offset += 2;

    NG_TRY_VOID(core::bytes::write(buffer, vlan.to_raw(), offset));
    offset += 2;
  }

  NG_TRY_VOID(core::bytes::write(buffer, static_cast<std::uint16_t>(ethertype),
                                 offset));
  offset += 2;

  return offset;
}

// Ethernet utilites implementation
namespace ethernet_utils {
FrameFormat detect_frame_format(std::uint16_t ethertype_or_length) noexcept {
  if (ethertype_or_length >= 1536) {
    return FrameFormat::EthernetII;
  } else if (ethertype_or_length <= 1500) {
    return FrameFormat::IEEE_802_3;
  } else {
    return FrameFormat::Invalid;
  }
}

/**
 * @brief Thread-safe OUI database manager
 *
 * Manages OUI-to-vendor mappings with support for loading from external
 * sources and runtime updates. Thread-safe for concurrent access.
 */
class OuiDatabase {
public:
  /**
   * @brief Get database statistics
   */
  struct Statistics {
    std::size_t total_entries{0};
    std::size_t cisco_entries{0};
    std::size_t intel_entries{0};
    std::size_t apple_entries{0};
    std::vector<std::pair<std::string, std::size_t>> top_vendors;

    std::string to_string() const {
      std::string result =
          std::format("OUI Database: {} total entries\n", total_entries);

      result += std::format(" Cisco: {}, Intel: {}, Apple: {}\n", cisco_entries,
                            intel_entries, apple_entries);

      result += "Top vendors: \n";
      for (const auto &[vendor, count] : top_vendors) {
        result += std::format("  {}: {}\n", vendor, count);
      }

      return result;
    }
  };

public:
  /**
   * @brief Get singleton instance
   */
  static OuiDatabase &instance() noexcept {
    static OuiDatabase db;
    return db;
  }

  /**
   * @brief Look up vendor by OUI
   */
  std::string_view get_vendor(std::uint32_t oui) const noexcept {
    std::shared_lock lock(m_mutex);
    oui &= 0xFFFFFF;

    auto it = m_database.find(oui);
    return (it != m_database.end()) ? it->second : "Unknown";
  }

  /**
   * @brief Load OUI database from IEEE registry file
   *
   * Supports standard IEEE OUI registry CSV format:
   * "Assignment,Organization Name,Organization Address"
   */
  utils::Expected<void> load_from_ieee_file(std::string_view filename) {
    try {
      std::ifstream file{std::string{filename}};
      if (!file.is_open()) {
        return tl::unexpected{utils::make_system_error(
            utils::ErrorCategory::FileSystem,
            std::format("Failed to open OUI fiel: {}", filename), errno)};
      }

      std::unordered_map<std::uint32_t, std::string> new_database;
      std::string line;
      std::size_t line_num = 0, loaded_count = 0;

      if (std::getline(file, line) &&
          line.find("Assignment") != std::string::npos) {
        line_num++;
      } else {
        file.seekg(0);
      }

      while (std::getline(file, line)) {
        line_num++;
        if (line.empty() || line[0] == '#') {
          continue;
        }

        auto parsed = parse_ieee_line(line);
        if (parsed) {
          auto [oui, vendor] = *parsed;

          new_database[oui] = std::move(vendor);
          loaded_count++;
        } else {
          NG_WARNING("Failed to parse OUI line {}: {}", line_num, line);
        }
      }

      {
        std::unique_lock lock(m_mutex);
        m_database = std::move(new_database);
      }

      NG_INFO("Loaded {} OUI entries from {}", loaded_count, filename);
      return {};
    } catch (const std::exception &e) {
      return tl::unexpected{utils::make_system_error(
          utils::ErrorCategory::FileSystem,
          std::format("Exception loading OUI file {}: {}", filename, e.what()),
          0)};
    }
  }

  /**
   * @brief Load OUI database from custom JSON format
   *
   * JSON format: {"oui": "vendor_name", ...}
   * Example: {"000000": "Xerox", "000001": "Xerox"}
   */
  utils::Expected<void> load_from_json_file(std::string_view filename) {
    try {
      std::ifstream file{std::string{filename}};
      if (!file.is_open()) {
        return tl::unexpected{utils::make_system_error(
            utils::ErrorCategory::FileSystem,
            std::format("Failed to open JSON OUI file: {}", filename), errno)};
      }

      std::string content((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());

      auto parsed = parse_json_oui_data(content);
      if (!parsed) {
        return tl::unexpected{parsed.error()};
      }

      {
        std::unique_lock lock(m_mutex);
        m_database = std::move(*parsed);
      }

      NG_INFO("Loaded {} OUI entries from JSON file {}", m_database.size(),
              filename);
      return {};
    } catch (const std::exception &e) {
      return tl::unexpected{utils::make_system_error(
          utils::ErrorCategory::FileSystem,
          std::format("Exception loading JSON OUI file {}: {}", filename,
                      e.what()),
          0)};
    }
  }

  /**
   * @brief Update single OUI entry
   */
  void update_oui(std::uint32_t oui, std::string_view vendor) {
    std::unique_lock lock(m_mutex);
    oui &= 0xFFFFFF;
    m_database[oui] = std::string{vendor};
  }

  /**
   * @brief Batch update multiple OUI entries
   */
  void update_oui_batch(
      const std::unordered_map<std::uint32_t, std::string> &updates) {
    std::unique_lock lock(m_mutex);
    for (const auto &[oui, vendor] : updates) {
      m_database[oui & 0xFFFFFF] = vendor;
    }
  }

  /**
   * @brief Remove OUI entry
   */
  void remove_oui(std::uint32_t oui) {
    std::unique_lock lock(m_mutex);
    m_database.erase(oui & 0xFFFFFF);
  }

  [[nodiscard]] Statistics get_statistics() const {
    std::shared_lock lock(m_mutex);
    Statistics stats;
    stats.total_entries = m_database.size();

    std::unordered_map<std::string, std::size_t> vendor_counts;
    for (const auto &[oui, vendor] : m_database) {
      vendor_counts[vendor]++;

      if (vendor == "Cisco")
        stats.cisco_entries++;

      else if (vendor == "Intel")
        stats.intel_entries++;

      else if (vendor == "Apple")
        stats.apple_entries++;
    }

    std::vector<std::pair<std::string, std::size_t>> vendor_list(
        vendor_counts.begin(), vendor_counts.end());

    std::partial_sort(
        vendor_list.begin(),
        vendor_list.begin() + std::min(size_t{10}, vendor_list.size()),
        vendor_list.end(),
        [](const auto &a, const auto &b) { return a.second > b.second; });

    stats.top_vendors.assign(vendor_list.begin(),
                             vendor_list.begin() +
                                 std::min(size_t{10}, vendor_list.size()));

    return stats;
  }

  /**
   * @brief Export database to JSON format
   */
  utils::Expected<void> export_to_json(std::string_view filename) const {
    try {
      std::ofstream file{std::string(filename)};
      if (!file.is_open()) {
        return tl::unexpected{utils::make_system_error(
            utils::ErrorCategory::FileSystem,
            std::format("Failed to create export file: {}", filename), errno)};
      }

      std::shared_lock lock(m_mutex);
      file << "{\n";

      bool first = true;
      for (const auto &[oui, vendor] : database_) {
        if (!first)
          file << ",\n";

        file << std::format("  \"{:06X}\": \"{}\"", oui, vendor);
        first = false;
      }

      file << "\n}\n";
      NG_INFO("Exported {} OUI entries to {}", m_database.size(), filename);
      return {};
    } catch (const std::exception &e) {
      return tl::unexpected{utils::make_system_error(
          utils::ErrorCategory::FileSystem,
          std::format("Exception exporting OUI database: {}", e.what()), 0)};
    }
  }

  /**
   * @brief Clear database and load defaults
   */
  void reset_to_defaults() {
    std::unique_lock lock(m_mutex);
    m_database = get_default_database();
  }

private:
  mutable std::shared_mutex m_mutex; ///< Thread synchronization
  std::unordered_map<std::uint32_t, std::string> m_database; ///< OUI mappings

private:
  OuiDatabase() : m_database(get_default_database()) {
    return {
      {0x000000, "Xerox"}, {0x000001, "Xerox"}, {0x000102, "BBN"},
          {0x000578, "SGI"}, {0x00005E, "IANA"}, {0x0000F8, "DEC"},
          {0x000142, "Cisco"}, {0x0001C8, "Thomas-Conrad"}, {0x0002B3, "Intel"},
          {0x000347, "Cabletron"}, {0x0004AC, "IBM"}, {0x000502, "Apple"},
          {0x00055D, "SGI"}, {0x0005DC, "Lexmark"}, {0x000691, "Compaq"},
          {0x0007E9, "Intel"}, {0x000874, "IBM"}, {0x0008C7, "Compaq"},
          {0x00090F, "Extreme Networks"}, {0x000A27, "Intel"},
          {0x000B0C, "Cisco"}, {0x000C29, "VMware"}, {0x000D3A, "Cisco"},
          {0x000E38, "D-Link"}, {0x000F23, "Cisco"}, {0x001018, "Broadcom"},
          {0x0013D3, "Micro-Star"}, {0x001560, "Apple"}, {0x001731, "Cisco"},
          {0x0019B9, "Cisco"}, {0x001C23, "Cisco"}, {0x001E37, "Cisco"},
          {0x0020AF, "3Com"}, {0x002369, "Cisco"}, {0x0025B3, "Apple"},
          {0x002710, "Belkin"}, {0x0029A7, "Cisco"}, {0x002B67, "Cisco"},
          {0x002D26, "Cisco"}, {0x003094, "Apple"}, {0x0032CB, "Apple"},
          {0x003517, "Cisco"}, {0x0037A0, "Cisco"}, {0x003A9D, "Cisco"},
          {0x003D67, "Cisco"}, {0x004096, "Cisco"}, {0x0043D6, "Cisco"},
          {0x004665, "Cisco"}, {0x0049AD, "Cisco"}, {0x004C83, "Cisco"},
          {0x004F4E, "Cisco"}, {0x005254, "Realtek"}, {0x0055DA, "Cisco"},
          {0x005884, "Cisco"}, {0x005B94, "Cisco"}, {0x005E50, "Cisco"},
          {0x006100, "Cisco"}, {0x006467, "Cisco"}, {0x00677D, "Cisco"},
          {0x006A8A, "Cisco"}, {0x006D97, "Cisco"}, {0x0070B3, "Cisco"},
          {0x007376, "Cisco"}, {0x007689, "Cisco"}, {0x0079E4, "Cisco"},
          {0x007D45, "Cisco"}, {0x00A0C9, "Intel"}, {0x00B0D0, "Dell"},
          {0x00C04F, "Dell"}, {0x00E018, "AST"}, {0x001B21, "Intel"},
          {0x002219, "Intel"}, {0x002655, "Intel"}, {0x0CC47A, "Intel"},
          {0x001CC0, "Lantiq"}, {0x0019E3, "Netgear"}, {0x002722, "Netgear"},
          {0x00146C, "Netgear"}, {0x001E2A, "Netgear"}, {0x000FB5, "Netgear"},
          {0x00095B, "Netgear"}, {0x001F33, "Netgear"}, {0x20CF30, "Netgear"},
          {0x44D9E7, "Netgear"}, {0x9C3DCF, "Netgear"}, {0x000C41, "Linksys"},
          {0x001217, "Linksys"}, {0x001310, "Linksys"}, {0x0014BF, "Linksys"},
          {0x00169B, "Linksys"}, {0x001801, "Linksys"}, {0x001A70, "Linksys"},
          {0x001C10, "Linksys"}, {0x001E37, "Linksys"}, {0x0020E0, "Linksys"},
          {0x002129, "Linksys"}, {0x0022A1, "Linksys"}, {0x002354, "Linksys"},
          {0x002369, "Linksys"},
    }
  }

  /**
   * @brief Parse IEEE OUI registry line
   * Format: "AB-CD-EF,Vendor Name, Address info..."
   */
  std::optional<std::pair<std::uint32_t, std::string>>
  parse_ieee_line(std::string_view line) const {
    auto command_pos = line.find(',');
    if (comma_pos == std::string_view::npos) {
      return std::nullopt;
    }

    std::string oui_str{line.substr(0, comma_pos)};
    oui_str.erase(std::remove(oui_str.begin(), oui_str.end(), '-'),
                  oui_str.end());
    std::transform(oui_str.begin(), oui_str.end(), oui_str.begin(), ::touper);

    if (oui_str.length != 6) {
      return std::nullopt;
    }

    char *end_ptr;
    std::uint32_t oui = std::strtoul(oui_str.c_str(), &end_ptr, 16);
    if (*end_ptr != "\0") {
      return std::nullopt;
    }

    auto start_pos = comma_pos + 1;
    auto end_pos = line.find(',', start_pos);
    if (end_pos == std::string_view::npos) {
      end_pos = line.length();
    }

    std::string vendor{line.substr(start_pos, end_pos - start_pos)};
    vendor.erase(0, vendor.find_first_not_of(" \t\r\n"));
    vendor.erase(vendor.find_last_not_of(" \t\r\n") + 1);

    if (vendor.empty()) {
      return std::nullopt;
    }

    return std::make_pair(oui, std::move(vendor));
  }

  /**
   * @brief Parse JSON OUI data
   */
  utils::Expected<std::unordered_map<std::uint32_t, std::string>>
  parse_json_oui_data(const std::string &json_content) const {
    std::unordered_map<std::uint32_t, std::string> result;
    std::size_t pos = json_content.find('{');

    if (pos == std::string::npos) {
      return tl::unexpected{
          utils::make_validation_error("Invalid JSON format")};
    }

    pos++;
    while (pos < json_content.size()) {
      while (pos < json_content.size() && std::isspace(json_content[pos]))
        pos++;

      if (pos >= json_content.size() || json_content[pos] == '}')
        break;

      if (json_content[pos] != '"') {
        return tl::unexpected{
            utils::make_validation_error("Expected quoted OUI key")};
      }

      pos++;
      std::size_t key_start = pos;
      while (pos < json_content.size() && json_content[pos] != '"')
        pos++;

      if (pos >= json_content.size()) {
        return tl::unexpected{
            utils::make_validation_error("Unterminated OUI key string")};
      }

      std::string oui_str = json_content.substr(key_start, pos - key_start);
      pos++;

      char *end_ptr;
      std::uint32_t oui = std::strtoul(oui_str.c_str(), &end_ptr, 16);
      if (*end_ptr != '\0') {
        return tl::unexpected{utils::make_validation_error(
            std::format("Invalid OUI hex value: {}", oui_str))};
      }

      while (pos < json_content.size() && std::isspace(json_content[pos]))
        pos++;

      if (pos >= json_contentl.size() || json_content[pos] != ':') {
        return tl::unexpected{
            utils::make_validation_error("Expected colon after OUI")};
      }

      pos++;
      while (pos < json_content.size() && std::isspace(json_content[pos]))
        pos++;

      if (pos >= json_content.size() || json_content[pos] != '"') {
        return tl::unexpected{
            utils::make_validation_error("Expected quoted vendor name")};
      }

      pos++;
      std::size_t value_start = pos;
      while (pos < json_content.size() && json_content[pos] != '"') {
        if (json_content[pos] == '\\')
          pos++;

        pos++;
      }

      if (pos >= json_content.size()) {
        return tl::unexpected{
            utils::make_validation_error("Unterminated vendor name")};
      }

      std::string vendor = json_content.substr(value_start, pos - value_start);
      pos++;

      result[out] = std::move(vendor);
      while (pos < json_content.size() && std::isspace(json_content[pos]))
        pos++;

      if (pos < json_content.size() && json_content[pos] == ',')
        pos++;
    }

    return result;
  }

private:
  /**
   * @brief Default OUI database
   */
  static std::unordered_map<std::uint32_t, std::string> get_default_database() {
  }
};

std::string_view get_vendor_by_oui(std::uint32_t oui) noexcept {
  return OuiDatabase::instance().get_vendor(oui);
}

/**
 * @brief Load OUI database from IEEE registry file
 */
[[nodiscard]] core::Expected<void>
load_oui_database(std::string_view filename) {
  return OuiDatabase::instance().load_from_ieee_file(filename);
}

/**
 * @brief Load OUI database from JSON file
 */
[[nodiscard]] core::Expected<void>
load_oui_m_databasejson(std::string_view filename) {
  return OuiDatabase::instance().load_from_json_file(filename);
}

/**
 * @brief Update single OUI entry
 */
void update_oui_database(std::uint32_t oui, std::string_view vendor) {
  OuiDatabase::instance().update_oui(oui, vendor);
}

/**
 * @brief Get OUI database statistics
 */
[[nodiscard]] OuiDatabase::Statistics get_oui_statistics() {
  return OuiDatabase::instance().get_statistics();
}
} // namespace ethernet_utils
} // namespace netguard::protocol