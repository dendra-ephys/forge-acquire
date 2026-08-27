#ifndef FORGE_EVENT_PAYLOAD_V1_HPP
#define FORGE_EVENT_PAYLOAD_V1_HPP

#include "forge_protocol_v1.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace forge::protocol::events::v1 {

namespace core = forge::protocol::v1;

inline constexpr core::Hash32 kContractHash{
    0x68, 0xad, 0x1b, 0xf0, 0xc1, 0x6c, 0x57, 0xdd, 0xca, 0xd7, 0x9c,
    0xc8, 0xe5, 0xa9, 0x50, 0x51, 0x3d, 0x8e, 0x54, 0xa2, 0xc8, 0x74,
    0xcb, 0xe4, 0xb5, 0x6c, 0xea, 0x05, 0x4b, 0x7d, 0xd6, 0xd8,
};
inline constexpr std::size_t kCommonHeaderBytes = 80;
inline constexpr std::size_t kMaximumBodyBytes = 65'536;

enum class Kind : std::uint16_t {
  kMarker = 1,
  kFault = 2,
  kGap = 3,
  kOnlineAnalysis = 4,
};

enum class Error {
  kNone,
  kLength,
  kLengthLimit,
  kMagic,
  kVersion,
  kUnknownKind,
  kUnknownEnum,
  kUnknownFlags,
  kReserved,
  kContractHash,
  kIdentity,
  kUtf8,
  kInvariant,
};

struct EventView {
  Kind kind{};
  core::Id16 event_id{};
  std::uint64_t marker_sequence{};
  std::uint32_t marker_flags{};
  std::span<const std::uint8_t> label{};
  std::span<const std::uint8_t> note{};
  std::uint16_t fault_or_gap_code{};
  std::uint8_t severity{};
  std::uint8_t layer{};
  std::uint32_t event_flags{};
  std::uint64_t occurrence_count{};
  std::span<const std::uint8_t> detail{};
  std::uint64_t missing_record_count{};
  std::uint64_t missing_frame_count{};
  std::uint64_t missing_sample_count{};
  core::Id16 worker_id{};
  core::Hash32 worker_build_hash{};
  core::Hash32 algorithm_hash{};
  core::Hash32 config_hash{};
  core::Hash32 result_schema_hash{};
  std::uint64_t source_record_sequence{};
  std::uint32_t channel_id{};
  std::span<const std::uint8_t> result{};
};

struct ParseResult {
  Error error{Error::kNone};
  EventView value{};
  [[nodiscard]] explicit operator bool() const noexcept {
    return error == Error::kNone;
  }
};

[[nodiscard]] inline bool all_zero(
    std::span<const std::uint8_t> bytes) noexcept {
  for (const auto byte : bytes) {
    if (byte != 0) return false;
  }
  return true;
}

[[nodiscard]] inline bool valid_utf8_no_nul(
    std::span<const std::uint8_t> bytes) noexcept {
  std::size_t index = 0;
  while (index < bytes.size()) {
    const auto first = bytes[index];
    if (first == 0) return false;
    if (first < 0x80U) {
      ++index;
      continue;
    }
    std::size_t count = 0;
    std::uint32_t codepoint = 0;
    std::uint32_t minimum = 0;
    if ((first & 0xe0U) == 0xc0U) {
      count = 2;
      codepoint = first & 0x1fU;
      minimum = 0x80U;
    } else if ((first & 0xf0U) == 0xe0U) {
      count = 3;
      codepoint = first & 0x0fU;
      minimum = 0x800U;
    } else if ((first & 0xf8U) == 0xf0U) {
      count = 4;
      codepoint = first & 0x07U;
      minimum = 0x1'0000U;
    } else {
      return false;
    }
    if (index + count > bytes.size()) return false;
    for (std::size_t offset = 1; offset < count; ++offset) {
      const auto continuation = bytes[index + offset];
      if ((continuation & 0xc0U) != 0x80U) return false;
      codepoint = (codepoint << 6U) | (continuation & 0x3fU);
    }
    if (codepoint < minimum || codepoint > 0x10'ffffU ||
        (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
      return false;
    }
    index += count;
  }
  return true;
}

[[nodiscard]] inline bool known_layer(std::uint8_t value) noexcept {
  return value >= 1 && value <= 10;
}

[[nodiscard]] inline ParseResult parse(
    std::span<const std::uint8_t> payload) noexcept {
  ParseResult parsed{};
  if (payload.size() < kCommonHeaderBytes) {
    parsed.error = Error::kLength;
    return parsed;
  }
  if (!core::has_magic(payload, 0, "FGREVT01")) {
    parsed.error = Error::kMagic;
    return parsed;
  }
  if (core::read_u16(payload, 8) != 1) {
    parsed.error = Error::kVersion;
    return parsed;
  }
  const auto raw_kind = core::read_u16(payload, 10);
  if (raw_kind < 1 || raw_kind > 4) {
    parsed.error = Error::kUnknownKind;
    return parsed;
  }
  const auto header_bytes = static_cast<std::size_t>(core::read_u16(payload, 12));
  const auto total_bytes = static_cast<std::size_t>(core::read_u32(payload, 16));
  const auto body_bytes = static_cast<std::size_t>(core::read_u32(payload, 20));
  if (body_bytes > kMaximumBodyBytes) {
    parsed.error = Error::kLengthLimit;
    return parsed;
  }
  if (header_bytes > SIZE_MAX - body_bytes || total_bytes != payload.size() ||
      header_bytes + body_bytes != total_bytes) {
    parsed.error = Error::kLength;
    return parsed;
  }
  if (core::read_u16(payload, 14) != 0 ||
      !all_zero(payload.subspan(72, 8))) {
    parsed.error = Error::kReserved;
    return parsed;
  }
  if (core::read_array<32>(payload, 24) != kContractHash) {
    parsed.error = Error::kContractHash;
    return parsed;
  }
  const auto event_id = core::read_array<16>(payload, 56);
  if (!core::nonzero(event_id)) {
    parsed.error = Error::kIdentity;
    return parsed;
  }
  parsed.value.kind = static_cast<Kind>(raw_kind);
  parsed.value.event_id = event_id;

  if (parsed.value.kind == Kind::kMarker) {
    if (header_bytes != 104 || !all_zero(payload.subspan(96, 8))) {
      parsed.error = Error::kReserved;
      return parsed;
    }
    const auto label_bytes = core::read_u16(payload, 88);
    const auto note_bytes = core::read_u16(payload, 90);
    const auto flags = core::read_u32(payload, 92);
    if (label_bytes < 1 || label_bytes > 256 || note_bytes > 2'048 ||
        static_cast<std::size_t>(label_bytes) + note_bytes != body_bytes ||
        (flags != 1 && flags != 2)) {
      parsed.error = Error::kInvariant;
      return parsed;
    }
    parsed.value.marker_sequence = core::read_u64(payload, 80);
    parsed.value.marker_flags = flags;
    parsed.value.label = payload.subspan(104, label_bytes);
    parsed.value.note = payload.subspan(104 + label_bytes, note_bytes);
    if (!valid_utf8_no_nul(parsed.value.label) ||
        !valid_utf8_no_nul(parsed.value.note)) {
      parsed.error = Error::kUtf8;
    }
    return parsed;
  }

  if (parsed.value.kind == Kind::kFault) {
    if (header_bytes != 104 || !all_zero(payload.subspan(98, 6))) {
      parsed.error = Error::kReserved;
      return parsed;
    }
    const auto code = core::read_u16(payload, 80);
    const auto severity = payload[82];
    const auto layer = payload[83];
    const auto flags = core::read_u32(payload, 84);
    const auto count = core::read_u64(payload, 88);
    const auto detail_bytes = core::read_u16(payload, 96);
    if (code < 1 || code > 16 || severity < 1 || severity > 4 ||
        !known_layer(layer)) {
      parsed.error = Error::kUnknownEnum;
      return parsed;
    }
    if ((flags & ~3U) != 0) {
      parsed.error = Error::kUnknownFlags;
      return parsed;
    }
    if (count == 0 || detail_bytes > 2'048 || detail_bytes != body_bytes) {
      parsed.error = Error::kInvariant;
      return parsed;
    }
    parsed.value.fault_or_gap_code = code;
    parsed.value.severity = severity;
    parsed.value.layer = layer;
    parsed.value.event_flags = flags;
    parsed.value.occurrence_count = count;
    parsed.value.detail = payload.subspan(104, detail_bytes);
    if (!valid_utf8_no_nul(parsed.value.detail)) parsed.error = Error::kUtf8;
    return parsed;
  }

  if (parsed.value.kind == Kind::kGap) {
    if (header_bytes != 112 || body_bytes != 0 || payload[83] != 0) {
      parsed.error = Error::kReserved;
      return parsed;
    }
    const auto reason = core::read_u16(payload, 80);
    const auto layer = payload[82];
    const auto flags = core::read_u32(payload, 84);
    const auto records = core::read_u64(payload, 88);
    const auto frames = core::read_u64(payload, 96);
    const auto samples = core::read_u64(payload, 104);
    if (reason < 1 || reason > 6 || !known_layer(layer)) {
      parsed.error = Error::kUnknownEnum;
      return parsed;
    }
    if ((flags & ~3U) != 0) {
      parsed.error = Error::kUnknownFlags;
      return parsed;
    }
    if (records == 0 && frames == 0 && samples == 0) {
      parsed.error = Error::kInvariant;
      return parsed;
    }
    parsed.value.fault_or_gap_code = reason;
    parsed.value.layer = layer;
    parsed.value.event_flags = flags;
    parsed.value.missing_record_count = records;
    parsed.value.missing_frame_count = frames;
    parsed.value.missing_sample_count = samples;
    return parsed;
  }

  if (header_bytes != 248 || core::read_u32(payload, 244) != 0) {
    parsed.error = Error::kReserved;
    return parsed;
  }
  parsed.value.worker_id = core::read_array<16>(payload, 80);
  parsed.value.worker_build_hash = core::read_array<32>(payload, 96);
  parsed.value.algorithm_hash = core::read_array<32>(payload, 128);
  parsed.value.config_hash = core::read_array<32>(payload, 160);
  parsed.value.result_schema_hash = core::read_array<32>(payload, 192);
  if (!core::nonzero(parsed.value.worker_id) ||
      all_zero(parsed.value.worker_build_hash) ||
      all_zero(parsed.value.algorithm_hash) || all_zero(parsed.value.config_hash) ||
      all_zero(parsed.value.result_schema_hash)) {
    parsed.error = Error::kIdentity;
    return parsed;
  }
  parsed.value.source_record_sequence = core::read_u64(payload, 224);
  parsed.value.channel_id = core::read_u32(payload, 232);
  parsed.value.event_flags = core::read_u32(payload, 236);
  const auto result_bytes = core::read_u32(payload, 240);
  if ((parsed.value.event_flags & ~3U) != 0) {
    parsed.error = Error::kUnknownFlags;
    return parsed;
  }
  if (result_bytes == 0 || result_bytes > 4'096 || result_bytes != body_bytes) {
    parsed.error = Error::kInvariant;
    return parsed;
  }
  parsed.value.result = payload.subspan(248, result_bytes);
  if (!valid_utf8_no_nul(parsed.value.result)) parsed.error = Error::kUtf8;
  return parsed;
}

}  // namespace forge::protocol::events::v1

#endif
