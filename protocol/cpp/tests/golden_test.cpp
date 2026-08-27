#include "forge_protocol_v1.hpp"
#include "forge_event_payload_v1.hpp"
#include "forge_direct_pod_record_release_v1.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace protocol = forge::protocol::v1;
namespace events = forge::protocol::events::v1;
namespace release = forge::direct_pod_record_release::v1;

std::vector<std::uint8_t> read_hex(const std::filesystem::path& path) {
  std::ifstream stream(path);
  if (!stream) throw std::runtime_error("cannot open " + path.string());
  std::string text{std::istreambuf_iterator<char>{stream}, {}};
  text.erase(std::remove_if(text.begin(), text.end(), [](unsigned char ch) {
               return std::isspace(ch) != 0;
             }), text.end());
  if (text.size() % 2 != 0) throw std::runtime_error("odd hex length");
  std::vector<std::uint8_t> bytes;
  bytes.reserve(text.size() / 2);
  for (std::size_t index = 0; index < text.size(); index += 2) {
    bytes.push_back(static_cast<std::uint8_t>(
        std::stoul(text.substr(index, 2), nullptr, 16)));
  }
  return bytes;
}

void write_u32(std::vector<std::uint8_t>& bytes, std::size_t offset,
               std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
  }
}

void write_u16(std::vector<std::uint8_t>& bytes, std::size_t offset,
               std::uint16_t value) {
  for (std::size_t index = 0; index < 2; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
  }
}

void write_u64(std::vector<std::uint8_t>& bytes, std::size_t offset,
               std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
  }
}

void refresh_control_crc(std::vector<std::uint8_t>& bytes) {
  write_u32(bytes, 72, protocol::crc32c(
      std::span<const std::uint8_t>{bytes}.subspan(80)));
  write_u32(bytes, 76, protocol::crc32c(
      std::span<const std::uint8_t>{bytes}.first(76)));
}

void refresh_release_request_integrity(std::vector<std::uint8_t>& bytes) {
  std::array<std::uint8_t, 340> evidence{};
  constexpr char tag[] = "FORGE-DIRECT-POD-RECORD-RELEASE-EVIDENCE-V1";
  std::size_t length = 0;
  for (char ch : tag) {
    if (ch) evidence[length++] = static_cast<std::uint8_t>(ch);
  }
  evidence[length++] = 0;
  for (const auto offset : {16U, 48U, 80U, 96U, 112U, 128U}) {
    for (std::size_t index = 0; index < (offset < 80 ? 32 : 16); ++index) {
      evidence[length++] = bytes[offset + index];
    }
  }
  for (const auto offset : {144U, 152U, 160U, 168U}) {
    for (std::size_t index = 0; index < 8; ++index) {
      evidence[length++] = bytes[offset + index];
    }
  }
  for (const auto offset : {176U, 178U}) {
    for (std::size_t index = 0; index < 2; ++index) {
      evidence[length++] = bytes[offset + index];
    }
  }
  for (const auto offset : {184U, 192U, 200U}) {
    for (std::size_t index = 0; index < 8; ++index) {
      evidence[length++] = bytes[offset + index];
    }
  }
  for (const auto offset : {208U, 240U}) {
    for (std::size_t index = 0; index < 32; ++index) {
      evidence[length++] = bytes[offset + index];
    }
  }
  const auto hash = release::sha256(
      std::span<const std::uint8_t>{evidence}.first(length));
  std::copy(hash.begin(), hash.end(), bytes.begin() + 272);
  write_u32(bytes, 308, protocol::crc32c(
      std::span<const std::uint8_t>{bytes}.first(308)));
}

int require(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << message << '\n';
    return 1;
  }
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: golden_test <golden-dir>\n";
    return 2;
  }
  const std::filesystem::path root{argv[1]};
  int failures = 0;
  failures += require(protocol::crc32c(std::span<const std::uint8_t>{
      reinterpret_cast<const std::uint8_t*>("123456789"), 9}) == 0xe306'9283U,
      "CRC-32C standard vector failed");

  for (const auto* name : {"direct_pod_record_release_request_v1",
                           "direct_pod_record_release_reply_v1"}) {
    const auto wire = read_hex(root / (std::string{name} + ".hex"));
    const auto parsed = std::string{name}.find("request") != std::string::npos
        ? release::parse_request(wire) : release::parse_reply(wire);
    failures += require(static_cast<bool>(parsed), std::string{name} + " golden rejected: " + std::to_string(static_cast<int>(parsed.error)));
    for (std::size_t length = 0; length < wire.size(); ++length) {
      const auto truncated = std::span<const std::uint8_t>{wire}.first(length);
      failures += require(!(std::string{name}.find("request") != std::string::npos
          ? release::parse_request(truncated) : release::parse_reply(truncated)),
          std::string{name} + " truncation accepted at " + std::to_string(length));
    }
    for (std::size_t index = 0; index < wire.size(); ++index) {
      auto mutated = wire; mutated[index] ^= 1U;
      failures += require(!(std::string{name}.find("request") != std::string::npos
          ? release::parse_request(mutated) : release::parse_reply(mutated)),
          std::string{name} + " mutation accepted at " + std::to_string(index));
    }
  }
  const auto release_request = read_hex(
      root / "direct_pod_record_release_request_v1.hex");
  const auto with_release_range = [&](std::uint64_t first, std::uint64_t last,
                                      std::uint16_t count) {
    auto request = release_request;
    write_u64(request, 160, first);
    write_u64(request, 168, last);
    write_u16(request, 176, count);
    refresh_release_request_integrity(request);
    return request;
  };
  const auto max_singleton = with_release_range(UINT64_MAX, UINT64_MAX, 1);
  failures += require(static_cast<bool>(release::parse_request(max_singleton)),
                      "UINT64_MAX singleton release range rejected");
  const auto max_pair = with_release_range(UINT64_MAX, UINT64_MAX, 2);
  failures += require(!release::parse_request(max_pair),
                      "overflowed UINT64_MAX/count=2 release range accepted");
  const auto max_ending_pair = with_release_range(
      UINT64_MAX - 1, UINT64_MAX, 2);
  failures += require(static_cast<bool>(release::parse_request(max_ending_pair)),
                      "UINT64_MAX-ending count=2 release range rejected");
  const auto mismatched_last = with_release_range(
      UINT64_MAX - 1, UINT64_MAX - 1, 2);
  failures += require(!release::parse_request(mismatched_last),
                      "mismatched release range last accepted");
  const auto id16 = [](std::uint8_t value) {
    protocol::Id16 id{}; id.fill(value); return id;
  };
  const std::array release_records{
      release::RetainedCanonicalRecord{13, std::span<const std::uint8_t>{
          reinterpret_cast<const std::uint8_t*>("retained-13"), 11}},
      release::RetainedCanonicalRecord{14, std::span<const std::uint8_t>{
          reinterpret_cast<const std::uint8_t*>("retained-14"), 11}},
  };
  const auto store_hash = release::store_state_hash(
      std::array<protocol::Id16, 4>{id16(1), id16(2), id16(3), id16(4)},
      7, release::kHasReleased | release::kHasRetained | release::kHasCommitted,
      12, 13, 14, 2, release_records);
  const auto expected_store_hash = read_hex(root / "direct_pod_record_store_state_v1.hex");
  failures += require(static_cast<bool>(store_hash) &&
      std::equal(store_hash.value.begin(), store_hash.value.end(), expected_store_hash.begin(), expected_store_hash.end()),
      "direct-Pod record-store state hash golden rejected");

  auto record = read_hex(root / "canonical_record_envelope_v1.hex");
  const auto decoded_record = protocol::decode_record(record);
  failures += require(static_cast<bool>(decoded_record), "record golden rejected");
  const auto sample_block = read_hex(root / "sample_block_v1.hex");
  failures += require(
      std::equal(decoded_record.value.payload.begin(),
                 decoded_record.value.payload.end(), sample_block.begin(),
                 sample_block.end()),
      "standalone sample-block golden differs from record payload");
  failures += require(decoded_record.value.record_sequence == 7,
                      "record sequence endian mismatch");
  failures += require(decoded_record.value.channel_layout_id == 0x1122'3344U,
                      "channel layout endian mismatch");
  for (std::size_t length = 0; length < record.size(); ++length) {
    failures += require(
        !protocol::decode_record(
            std::span<const std::uint8_t>{record}.first(length)),
        "record truncation accepted at " + std::to_string(length));
  }

  constexpr std::array control_names{
      "device_capabilities_v1", "run_command_v1", "safety_profile_v1",
      "stim_intent_v1", "stim_command_v1", "stim_receipt_v1",
      "worker_token_lease_v1", "ack_v1", "nack_v1", "replay_request_v1"};
  for (const auto* name : control_names) {
    const auto wire = read_hex(root / (std::string{name} + ".hex"));
    const auto decoded = protocol::decode_low_speed(wire);
    failures += require(static_cast<bool>(decoded),
                        std::string{name} + " golden rejected");
    for (std::size_t length = 0; length < wire.size(); ++length) {
      failures += require(
          !protocol::decode_low_speed(
              std::span<const std::uint8_t>{wire}.first(length)),
          std::string{name} + " truncation accepted at " +
              std::to_string(length));
    }
  }

  constexpr std::array event_names{
      "marker_payload_v1", "fault_payload_v1", "gap_payload_v1",
      "online_analysis_payload_v1"};
  for (const auto* name : event_names) {
    const auto payload = read_hex(root / (std::string{name} + ".hex"));
    failures += require(static_cast<bool>(events::parse(payload)),
                        std::string{name} + " golden rejected");
    for (std::size_t length = 0; length < payload.size(); ++length) {
      failures += require(
          !events::parse(std::span<const std::uint8_t>{payload}.first(length)),
          std::string{name} + " truncation accepted at " +
              std::to_string(length));
    }
  }
  auto event_hash_mismatch = read_hex(root / "marker_payload_v1.hex");
  event_hash_mismatch[24] ^= 1U;
  failures += require(events::parse(event_hash_mismatch).error ==
                          events::Error::kContractHash,
                      "event contract hash mutation accepted");
  auto event_reserved = read_hex(root / "marker_payload_v1.hex");
  event_reserved[96] = 1U;
  failures += require(events::parse(event_reserved).error ==
                          events::Error::kReserved,
                      "event reserved mutation accepted");
  auto event_utf8 = read_hex(root / "marker_payload_v1.hex");
  event_utf8[104] = 0xffU;
  failures += require(events::parse(event_utf8).error == events::Error::kUtf8,
                      "event UTF-8 mutation accepted");

  for (std::size_t index = 0; index < record.size(); ++index) {
    auto mutated = record;
    mutated[index] ^= 1U;
    failures += require(!protocol::decode_record(mutated),
                        "record CRC mutation accepted at " + std::to_string(index));
  }
  for (const auto* name : control_names) {
    const auto original = read_hex(root / (std::string{name} + ".hex"));
    for (std::size_t index = 0; index < original.size(); ++index) {
      auto mutated = original;
      mutated[index] ^= 1U;
      failures += require(!protocol::decode_low_speed(mutated),
                          std::string{name} + " mutation accepted at " +
                              std::to_string(index));
    }
  }

  auto bad_magic = record;
  bad_magic[0] ^= 1U;
  failures += require(protocol::decode_record(bad_magic).error ==
                          protocol::CodecError::kBadMagic,
                      "bad magic not classified");
  auto bad_payload = record;
  bad_payload.back() ^= 1U;
  failures += require(protocol::decode_record(bad_payload).error ==
                          protocol::CodecError::kPayloadCrc,
                      "bad payload CRC not classified");
  auto unknown_flags = record;
  unknown_flags[19] |= 0x80U;
  write_u32(unknown_flags, 172, protocol::crc32c(
      std::span<const std::uint8_t>{unknown_flags}.first(172)));
  failures += require(protocol::decode_record(unknown_flags).error ==
                          protocol::CodecError::kUnknownFlags,
                      "unknown record flags accepted");

  auto control = read_hex(root / "device_capabilities_v1.hex");
  auto protocol_mismatch = control;
  protocol_mismatch[40] ^= 1U;
  write_u32(protocol_mismatch, 76, protocol::crc32c(
      std::span<const std::uint8_t>{protocol_mismatch}.first(76)));
  failures += require(protocol::decode_low_speed(protocol_mismatch).error ==
                          protocol::CodecError::kProtocolHash,
                      "protocol mismatch accepted");
  auto unknown_kind = control;
  unknown_kind[16] = 0xffU;
  unknown_kind[17] = 0xffU;
  write_u32(unknown_kind, 76, protocol::crc32c(
      std::span<const std::uint8_t>{unknown_kind}.first(76)));
  failures += require(protocol::decode_low_speed(unknown_kind).error ==
                          protocol::CodecError::kUnknownKind,
                      "unknown kind accepted");
  auto oversized = control;
  write_u32(oversized, 0, 1'048'577U);
  write_u32(oversized, 76, protocol::crc32c(
      std::span<const std::uint8_t>{oversized}.first(76)));
  failures += require(protocol::decode_low_speed(oversized).error ==
                          protocol::CodecError::kLengthLimit,
                      "oversized message accepted");

  constexpr std::array reserved_fields{
      std::pair{"safety_profile_v1", std::size_t{68}},
      std::pair{"stim_intent_v1", std::size_t{212}},
      std::pair{"worker_token_lease_v1", std::size_t{54}},
      std::pair{"ack_v1", std::size_t{24}},
      std::pair{"nack_v1", std::size_t{23}},
      std::pair{"replay_request_v1", std::size_t{62}},
  };
  for (const auto& [name, offset] : reserved_fields) {
    auto wire = read_hex(root / (std::string{name} + ".hex"));
    wire[80 + offset] = 1U;
    refresh_control_crc(wire);
    failures += require(protocol::decode_low_speed(wire).error ==
                            protocol::CodecError::kReserved,
                        std::string{name} + " reserved field accepted");
  }

  std::ifstream manifest(root / "illegal_vectors.json");
  const std::string manifest_text{std::istreambuf_iterator<char>{manifest}, {}};
  constexpr std::array illegal_names{
      "record_bad_magic", "record_unknown_flags", "record_bad_payload_crc",
      "control_oversize", "control_protocol_mismatch", "control_unknown_kind",
      "stim_rhd_only", "stim_missing_profile", "stim_unapproved_profile",
      "stim_interlock_open", "stim_wrong_epoch", "stim_expired",
      "stim_hash_mismatch", "stim_limit_exceeded"};
  for (const auto* name : illegal_names) {
    failures += require(manifest_text.find(name) != std::string::npos,
                        std::string{"illegal vector manifest drift: "} + name);
  }

  if (failures == 0) {
    std::cout << "C++20 protocol verifier passed: 16 golden vectors, exhaustive base truncations/CRC mutations, event truncations/semantic mutations, 14-vector manifest\n";
  }
  return failures == 0 ? 0 : 1;
}
