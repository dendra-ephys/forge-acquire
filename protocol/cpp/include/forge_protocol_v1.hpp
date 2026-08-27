#ifndef FORGE_PROTOCOL_V1_HPP
#define FORGE_PROTOCOL_V1_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>

namespace forge::protocol::v1 {

using Id16 = std::array<std::uint8_t, 16>;
using Hash32 = std::array<std::uint8_t, 32>;

inline constexpr std::uint16_t kVersion = 1;
inline constexpr std::size_t kRecordHeaderLen = 176;
inline constexpr std::size_t kLowSpeedHeaderLen = 80;
inline constexpr std::size_t kMaxRecordPayloadLen = 1'048'576;
inline constexpr std::size_t kMaxLowSpeedMessageLen = 1'048'576;
inline constexpr std::uint32_t kRecordFlagsAll = 0x0000'003f;
inline constexpr std::uint32_t kCapabilityFlagsAll = 0x0000'03ff;
inline constexpr std::uint32_t kRuntimeFlagsAll = 0x0000'007f;
inline constexpr std::uint32_t kRequiredStimCapabilities = 0x0000'03ff;
inline constexpr std::uint32_t kRequiredStimRuntime = 0x0000'007f;
inline constexpr Hash32 kProtocolHash{
    0x4e, 0x3d, 0xb2, 0x3e, 0x15, 0xa1, 0x48, 0x07, 0x07, 0x13, 0x2d,
    0x28, 0xbd, 0xc8, 0x20, 0xf3, 0x6f, 0xda, 0xbb, 0xb5, 0xd2, 0x0d,
    0x9d, 0x84, 0x85, 0x0a, 0xe8, 0x91, 0x66, 0xb3, 0xef, 0xa0,
};

enum class CodecError {
  kNone,
  kLength,
  kLengthLimit,
  kBadMagic,
  kVersion,
  kUnknownKind,
  kUnknownFlags,
  kReserved,
  kHeaderCrc,
  kPayloadCrc,
  kBodyCrc,
  kProtocolHash,
  kInvariant,
};

enum class RecordKind : std::uint16_t {
  kSampleBlock = 1,
  kMarker = 2,
  kFault = 3,
  kOnlineAnalysis = 4,
  kStimIntent = 5,
  kStimReceipt = 6,
};

enum class MessageKind : std::uint16_t {
  kDeviceCapabilities = 1,
  kRunCommand = 2,
  kSafetyProfile = 3,
  kStimIntent = 4,
  kStimCommand = 5,
  kStimReceipt = 6,
  kWorkerTokenLease = 7,
  kAck = 8,
  kNack = 9,
  kReplayRequest = 10,
};

struct DecodedRecordView {
  RecordKind kind{};
  std::uint32_t flags{};
  Id16 run_id{};
  Id16 pod_id{};
  Id16 headstage_id{};
  std::uint64_t record_sequence{};
  std::uint64_t frame_start{};
  std::uint64_t frame_end_exclusive{};
  std::uint64_t sample_start{};
  std::uint64_t sample_end_exclusive{};
  std::uint64_t global_time_start_ns{};
  std::uint64_t global_time_end_exclusive_ns{};
  std::uint32_t channel_layout_id{};
  std::uint16_t channel_count{};
  std::uint16_t sample_format{};
  std::span<const std::uint8_t> payload{};
};

struct DecodedControlView {
  MessageKind kind{};
  std::uint64_t request_id{};
  std::uint64_t epoch{};
  std::span<const std::uint8_t> body{};
};

struct ParseRecordResult {
  CodecError error{CodecError::kNone};
  DecodedRecordView value{};
  [[nodiscard]] constexpr explicit operator bool() const noexcept {
    return error == CodecError::kNone;
  }
};

struct ParseControlResult {
  CodecError error{CodecError::kNone};
  DecodedControlView value{};
  [[nodiscard]] constexpr explicit operator bool() const noexcept {
    return error == CodecError::kNone;
  }
};

[[nodiscard]] inline std::uint16_t read_u16(std::span<const std::uint8_t> data,
                                            std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(data[offset]) |
         static_cast<std::uint16_t>(data[offset + 1]) << 8U;
}

[[nodiscard]] inline std::uint32_t read_u32(std::span<const std::uint8_t> data,
                                            std::size_t offset) noexcept {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(data[offset + index]) << (index * 8U);
  }
  return value;
}

[[nodiscard]] inline std::uint64_t read_u64(std::span<const std::uint8_t> data,
                                            std::size_t offset) noexcept {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(data[offset + index]) << (index * 8U);
  }
  return value;
}

template <std::size_t Size>
[[nodiscard]] inline std::array<std::uint8_t, Size> read_array(
    std::span<const std::uint8_t> data, std::size_t offset) noexcept {
  std::array<std::uint8_t, Size> out{};
  for (std::size_t index = 0; index < Size; ++index) {
    out[index] = data[offset + index];
  }
  return out;
}

[[nodiscard]] inline std::uint32_t crc32c(
    std::span<const std::uint8_t> data) noexcept {
  std::uint32_t crc = std::numeric_limits<std::uint32_t>::max();
  for (const auto byte : data) {
    crc ^= byte;
    for (unsigned bit = 0; bit < 8; ++bit) {
      const auto mask = std::uint32_t{0} - (crc & 1U);
      crc = (crc >> 1U) ^ (0x82f6'3b78U & mask);
    }
  }
  return ~crc;
}

[[nodiscard]] inline bool has_magic(std::span<const std::uint8_t> data,
                                    std::size_t offset,
                                    std::string_view magic) noexcept {
  if (data.size() < offset + magic.size()) {
    return false;
  }
  for (std::size_t index = 0; index < magic.size(); ++index) {
    if (data[offset + index] != static_cast<std::uint8_t>(magic[index])) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] inline bool nonzero(const Id16& value) noexcept {
  for (const auto byte : value) {
    if (byte != 0) return true;
  }
  return false;
}

[[nodiscard]] inline std::size_t body_len(MessageKind kind) noexcept {
  switch (kind) {
    case MessageKind::kDeviceCapabilities: return 84;
    case MessageKind::kRunCommand: return 80;
    case MessageKind::kSafetyProfile: return 288;
    case MessageKind::kStimIntent: return 240;
    case MessageKind::kStimCommand: return 232;
    case MessageKind::kStimReceipt: return 168;
    case MessageKind::kWorkerTokenLease: return 288;
    case MessageKind::kAck:
    case MessageKind::kNack: return 60;
    case MessageKind::kReplayRequest: return 96;
  }
  return 0;
}

[[nodiscard]] inline bool known_record_kind(std::uint16_t raw) noexcept {
  return raw >= 1 && raw <= 6;
}

[[nodiscard]] inline bool known_message_kind(std::uint16_t raw) noexcept {
  return raw >= 1 && raw <= 10;
}

[[nodiscard]] inline CodecError validate_body(
    MessageKind kind, std::span<const std::uint8_t> body) noexcept {
  if (body.size() != body_len(kind) || read_u16(body, 0) != kVersion ||
      read_u16(body, 2) != body.size()) {
    return CodecError::kLength;
  }
  switch (kind) {
    case MessageKind::kDeviceCapabilities: {
      const auto transport = body[20];
      const auto max_pods = body[21];
      const auto channels = read_u16(body, 22);
      const auto stim_kind = read_u16(body, 36);
      const auto stim_channels = read_u16(body, 38);
      if (transport < 1 || transport > 3 || max_pods < 1 || max_pods > 8 ||
          (transport == 1 && max_pods != 1) || channels < 1 || channels > 256 ||
          read_u32(body, 24) != 1 || read_u32(body, 28) == 0 ||
          read_u32(body, 28) > read_u32(body, 32) || stim_kind > 1 ||
          (stim_kind == 0 && stim_channels != 0) ||
          (stim_kind == 1 && stim_channels != 16) || read_u32(body, 40) == 0 ||
          (read_u32(body, 44) & ~kCapabilityFlagsAll) != 0 ||
          (read_u32(body, 48) & ~kRuntimeFlagsAll) != 0) {
        return CodecError::kInvariant;
      }
      break;
    }
    case MessageKind::kRunCommand:
      if (read_u16(body, 4) < 1 || read_u16(body, 4) > 7 ||
          read_u16(body, 6) < 1 || read_u16(body, 6) > 2 ||
          !nonzero(read_array<16>(body, 8)) ||
          !nonzero(read_array<16>(body, 24)) || read_u64(body, 40) == 0) {
        return CodecError::kInvariant;
      }
      break;
    case MessageKind::kSafetyProfile:
      if (read_u32(body, 68) != 0) return CodecError::kReserved;
      if (body[20] > 2 || !((body[21] <= 5) || body[21] == 255) ||
          read_u16(body, 22) < 1 || read_u16(body, 22) > 2 ||
          read_u32(body, 32) > read_u32(body, 36)) {
        return CodecError::kInvariant;
      }
      break;
    case MessageKind::kStimIntent:
      if (read_u32(body, 212) != 0) return CodecError::kReserved;
      if (read_u16(body, 206) == 0 || read_u32(body, 208) != 0 ||
          read_u64(body, 216) <= read_u64(body, 68)) {
        return CodecError::kInvariant;
      }
      break;
    case MessageKind::kStimCommand:
      if (read_u16(body, 166) == 0 || read_u32(body, 168) == 0 ||
          read_u32(body, 172) == 0 || read_u32(body, 176) == 0 ||
          read_u32(body, 180) == 0 || read_u32(body, 184) == 0 ||
          read_u32(body, 188) == 0 || read_u64(body, 192) == 0 ||
          read_u64(body, 200) == 0 || read_u64(body, 200) > read_u64(body, 192) ||
          read_u64(body, 208) == 0) {
        return CodecError::kInvariant;
      }
      break;
    case MessageKind::kStimReceipt:
      if (read_u16(body, 68) < 1 || read_u16(body, 68) > 8 ||
          read_u16(body, 74) == 0 || read_u32(body, 100) != 0 ||
          read_u64(body, 112) == 0) {
        return CodecError::kInvariant;
      }
      break;
    case MessageKind::kWorkerTokenLease:
      if (read_u16(body, 54) != 0) return CodecError::kReserved;
      break;
    case MessageKind::kAck:
      if (read_u32(body, 24) != 0) return CodecError::kReserved;
      break;
    case MessageKind::kNack:
      if (body[23] != 0) return CodecError::kReserved;
      break;
    case MessageKind::kReplayRequest:
      if (read_u16(body, 62) != 0) return CodecError::kReserved;
      break;
  }
  return CodecError::kNone;
}

[[nodiscard]] inline ParseRecordResult decode_record(
    std::span<const std::uint8_t> wire) noexcept {
  ParseRecordResult result{};
  if (wire.size() < kRecordHeaderLen) { result.error = CodecError::kLength; return result; }
  if (!has_magic(wire, 0, "FGRREC01")) { result.error = CodecError::kBadMagic; return result; }
  if (read_u16(wire, 8) != kVersion) { result.error = CodecError::kVersion; return result; }
  if (read_u16(wire, 10) != kRecordHeaderLen) { result.error = CodecError::kLength; return result; }
  const auto raw_kind = read_u16(wire, 12);
  if (!known_record_kind(raw_kind)) { result.error = CodecError::kUnknownKind; return result; }
  if (read_u16(wire, 14) != 0) { result.error = CodecError::kReserved; return result; }
  const auto flags = read_u32(wire, 16);
  if ((flags & ~kRecordFlagsAll) != 0) { result.error = CodecError::kUnknownFlags; return result; }
  const auto payload_len = static_cast<std::size_t>(read_u32(wire, 20));
  if (payload_len > kMaxRecordPayloadLen) { result.error = CodecError::kLengthLimit; return result; }
  if (wire.size() != kRecordHeaderLen + payload_len) { result.error = CodecError::kLength; return result; }
  if (read_array<32>(wire, 136) != kProtocolHash) { result.error = CodecError::kProtocolHash; return result; }
  if (read_u32(wire, 172) != crc32c(wire.first(172))) { result.error = CodecError::kHeaderCrc; return result; }
  const auto payload = wire.subspan(kRecordHeaderLen);
  if (read_u32(wire, 168) != crc32c(payload)) { result.error = CodecError::kPayloadCrc; return result; }
  result.value = {
      static_cast<RecordKind>(raw_kind), flags, read_array<16>(wire, 24),
      read_array<16>(wire, 40), read_array<16>(wire, 56), read_u64(wire, 72),
      read_u64(wire, 80), read_u64(wire, 88), read_u64(wire, 96),
      read_u64(wire, 104), read_u64(wire, 112), read_u64(wire, 120),
      read_u32(wire, 128), read_u16(wire, 132), read_u16(wire, 134), payload};
  if (!nonzero(result.value.run_id) || !nonzero(result.value.pod_id) ||
      !nonzero(result.value.headstage_id) ||
      result.value.frame_start >= result.value.frame_end_exclusive ||
      result.value.sample_start >= result.value.sample_end_exclusive ||
      result.value.global_time_start_ns >= result.value.global_time_end_exclusive_ns ||
      result.value.channel_layout_id == 0 || result.value.channel_count == 0 ||
      result.value.sample_format != 1 || payload.empty()) {
    result.error = CodecError::kInvariant;
    return result;
  }
  return result;
}

[[nodiscard]] inline ParseControlResult decode_low_speed(
    std::span<const std::uint8_t> wire) noexcept {
  ParseControlResult result{};
  if (wire.size() < kLowSpeedHeaderLen) { result.error = CodecError::kLength; return result; }
  const auto total_len = static_cast<std::size_t>(read_u32(wire, 0));
  if (total_len > kMaxLowSpeedMessageLen) { result.error = CodecError::kLengthLimit; return result; }
  if (total_len != wire.size()) { result.error = CodecError::kLength; return result; }
  if (!has_magic(wire, 4, "FGRCTL01")) { result.error = CodecError::kBadMagic; return result; }
  if (read_u16(wire, 12) != kVersion) { result.error = CodecError::kVersion; return result; }
  if (read_u16(wire, 14) != kLowSpeedHeaderLen) { result.error = CodecError::kLength; return result; }
  const auto raw_kind = read_u16(wire, 16);
  if (!known_message_kind(raw_kind)) { result.error = CodecError::kUnknownKind; return result; }
  if (read_u16(wire, 18) != 0) { result.error = CodecError::kUnknownFlags; return result; }
  const auto kind = static_cast<MessageKind>(raw_kind);
  const auto expected_body_len = body_len(kind);
  if (read_u32(wire, 20) != expected_body_len ||
      total_len != kLowSpeedHeaderLen + expected_body_len) {
    result.error = CodecError::kLength;
    return result;
  }
  const auto request_id = read_u64(wire, 24);
  const auto epoch = read_u64(wire, 32);
  if (request_id == 0 || epoch == 0) { result.error = CodecError::kInvariant; return result; }
  if (read_array<32>(wire, 40) != kProtocolHash) { result.error = CodecError::kProtocolHash; return result; }
  if (read_u32(wire, 76) != crc32c(wire.first(76))) { result.error = CodecError::kHeaderCrc; return result; }
  const auto body = wire.subspan(kLowSpeedHeaderLen);
  if (read_u32(wire, 72) != crc32c(body)) { result.error = CodecError::kBodyCrc; return result; }
  result.error = validate_body(kind, body);
  if (result.error != CodecError::kNone) return result;
  result.value = {kind, request_id, epoch, body};
  return result;
}

}  // namespace forge::protocol::v1

#endif
