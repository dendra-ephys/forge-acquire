#ifndef FORGE_ANALYSIS_RING_V1_HPP
#define FORGE_ANALYSIS_RING_V1_HPP

#include "forge_protocol_v1.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace forge::workers::ring::v1 {

namespace wire = forge::protocol::v1;

inline constexpr std::array<std::uint8_t, 32> kSchemaHash{
    0x96, 0xa5, 0xc4, 0xe0, 0x77, 0x94, 0xb2, 0xea, 0x7b, 0xe3, 0x00,
    0x1e, 0x07, 0x43, 0x6b, 0x5e, 0x3a, 0x3c, 0xd7, 0x2d, 0x6e, 0x67,
    0x90, 0x98, 0xba, 0x27, 0x77, 0x1c, 0x64, 0x0c, 0xb3, 0x6e,
};
inline constexpr std::size_t kGlobalHeaderBytes = 256;
inline constexpr std::size_t kSlotHeaderBytes = 64;
inline constexpr std::uint64_t kEmptySlot = UINT64_MAX;

enum class Error {
  kNone,
  kLength,
  kMagic,
  kLayout,
  kReserved,
  kProtocolHash,
  kHeaderCrc,
  kIdentity,
  kSequenceWindow,
  kFaultFlags,
  kSlotContradiction,
  kSlotCrc,
  kCanonical,
  kSampleBlock,
  kCacheMismatch,
};

struct RecordView {
  std::uint64_t ring_sequence{};
  std::uint64_t journal_sequence{};
  wire::DecodedRecordView canonical{};
  std::span<const std::uint8_t> encoded_record{};
};

struct SnapshotView {
  wire::Id16 run_id{};
  wire::Id16 consumer_id{};
  std::uint64_t producer_epoch{};
  std::uint32_t slot_count{};
  std::uint32_t payload_capacity{};
  std::uint64_t slot_stride{};
  std::uint64_t published_sequence{};
  std::uint64_t consumed_sequence{};
  std::uint64_t dropped_records{};
  std::uint64_t producer_heartbeat_monotonic_ns{};
  std::uint64_t consumer_heartbeat_monotonic_ns{};
  std::uint64_t fault_flags{};
  std::vector<RecordView> records{};
  bool snapshot_only{true};
};

struct ParseResult {
  Error error{Error::kNone};
  SnapshotView value{};
  [[nodiscard]] explicit operator bool() const noexcept {
    return error == Error::kNone;
  }
};

[[nodiscard]] inline bool all_zero(std::span<const std::uint8_t> bytes) noexcept {
  for (const auto byte : bytes) {
    if (byte != 0) return false;
  }
  return true;
}

[[nodiscard]] inline bool valid_sample_block(
    const wire::DecodedRecordView& envelope) noexcept {
  const auto payload = envelope.payload;
  if (envelope.kind != wire::RecordKind::kSampleBlock || payload.size() < 32U ||
      wire::read_u16(payload, 0) != 1 || wire::read_u16(payload, 2) != 32U) {
    return false;
  }
  const auto flags = wire::read_u32(payload, 4);
  const auto sample_count = wire::read_u32(payload, 8);
  const auto channel_count = wire::read_u16(payload, 12);
  const auto sample_format = wire::read_u16(payload, 14);
  const auto rate_numerator = wire::read_u32(payload, 16);
  const auto rate_denominator = wire::read_u32(payload, 20);
  const auto first_sample = wire::read_u64(payload, 24);
  const auto values = static_cast<std::size_t>(sample_count) * channel_count;
  return (flags & ~0x03U) == 0 && sample_count != 0 && channel_count != 0 &&
         sample_format == 1 && rate_numerator != 0 && rate_denominator != 0 &&
         first_sample == envelope.sample_start &&
         sample_count == envelope.sample_end_exclusive - envelope.sample_start &&
         channel_count == envelope.channel_count && envelope.sample_format == 1 &&
         (channel_count == 0 || values / channel_count == sample_count) &&
         values <= (wire::kMaxRecordPayloadLen - 32U) / sizeof(std::int16_t) &&
         payload.size() == 32U + values * sizeof(std::int16_t);
}

[[nodiscard]] inline ParseResult parse(
    std::span<const std::uint8_t> snapshot) noexcept {
  ParseResult result{};
  if (snapshot.size() < kGlobalHeaderBytes) {
    result.error = Error::kLength;
    return result;
  }
  if (!wire::has_magic(snapshot, 0, "FGRRNG01")) {
    result.error = Error::kMagic;
    return result;
  }
  if (wire::read_u16(snapshot, 8) != 1 ||
      wire::read_u16(snapshot, 10) != kGlobalHeaderBytes ||
      wire::read_u16(snapshot, 12) != kSlotHeaderBytes ||
      wire::read_u16(snapshot, 14) != 0) {
    result.error = Error::kLayout;
    return result;
  }
  const auto slot_count = wire::read_u32(snapshot, 16);
  const auto payload_capacity = wire::read_u32(snapshot, 20);
  const auto stride = wire::read_u64(snapshot, 104);
  if (slot_count < 2 || slot_count > 65'536 ||
      payload_capacity < wire::kRecordHeaderLen ||
      payload_capacity > wire::kRecordHeaderLen + wire::kMaxRecordPayloadLen ||
      stride < kSlotHeaderBytes + payload_capacity || stride % 64 != 0) {
    result.error = Error::kLayout;
    return result;
  }
  if (wire::read_u32(snapshot, 24) != 0 || wire::read_u32(snapshot, 28) != 0 ||
      !all_zero(snapshot.subspan(116, 12)) ||
      !all_zero(snapshot.subspan(176, 80))) {
    result.error = Error::kReserved;
    return result;
  }
  if (wire::read_array<32>(snapshot, 32) != wire::kProtocolHash) {
    result.error = Error::kProtocolHash;
    return result;
  }
  const auto run_id = wire::read_array<16>(snapshot, 64);
  const auto consumer_id = wire::read_array<16>(snapshot, 80);
  const auto epoch = wire::read_u64(snapshot, 96);
  if (!wire::nonzero(run_id) || !wire::nonzero(consumer_id) || epoch == 0) {
    result.error = Error::kIdentity;
    return result;
  }
  if (wire::read_u32(snapshot, 112) != wire::crc32c(snapshot.first(112))) {
    result.error = Error::kHeaderCrc;
    return result;
  }
  if (slot_count > (SIZE_MAX - kGlobalHeaderBytes) / stride ||
      snapshot.size() != kGlobalHeaderBytes + slot_count * stride) {
    result.error = Error::kLength;
    return result;
  }

  const auto published = wire::read_u64(snapshot, 128);
  const auto consumed = wire::read_u64(snapshot, 136);
  const auto fault_flags = wire::read_u64(snapshot, 168);
  if (consumed > published || published - consumed > slot_count) {
    result.error = Error::kSequenceWindow;
    return result;
  }
  if ((fault_flags & ~UINT64_C(3)) != 0) {
    result.error = Error::kFaultFlags;
    return result;
  }

  result.value = SnapshotView{
      run_id,
      consumer_id,
      epoch,
      slot_count,
      payload_capacity,
      stride,
      published,
      consumed,
      wire::read_u64(snapshot, 144),
      wire::read_u64(snapshot, 152),
      wire::read_u64(snapshot, 160),
      fault_flags,
      {},
      true,
  };
  result.value.records.reserve(static_cast<std::size_t>(published - consumed));
  for (auto sequence = consumed; sequence < published; ++sequence) {
    const auto base = kGlobalHeaderBytes + (sequence % slot_count) * stride;
    const auto committed = wire::read_u64(snapshot, base);
    const auto encoded_bytes = wire::read_u32(snapshot, base + 8);
    const auto encoded_crc = wire::read_u32(snapshot, base + 12);
    const auto journal_sequence = wire::read_u64(snapshot, base + 16);
    const auto cached_record_sequence = wire::read_u64(snapshot, base + 24);
    const auto cached_global_time = wire::read_u64(snapshot, base + 32);
    const auto cached_flags = wire::read_u32(snapshot, base + 40);
    if (committed != sequence || wire::read_u64(snapshot, base + 48) != ~sequence ||
        wire::read_u32(snapshot, base + 44) != 0 ||
        wire::read_u64(snapshot, base + 56) != 0 ||
        encoded_bytes < wire::kRecordHeaderLen || encoded_bytes > payload_capacity) {
      result.error = Error::kSlotContradiction;
      return result;
    }
    const auto encoded = snapshot.subspan(base + kSlotHeaderBytes, encoded_bytes);
    if (wire::crc32c(encoded) != encoded_crc) {
      result.error = Error::kSlotCrc;
      return result;
    }
    const auto canonical = wire::decode_record(encoded);
    if (!canonical) {
      result.error = Error::kCanonical;
      return result;
    }
    if (!valid_sample_block(canonical.value)) {
      result.error = Error::kSampleBlock;
      return result;
    }
    if (canonical.value.run_id != run_id ||
        canonical.value.record_sequence != cached_record_sequence ||
        canonical.value.global_time_start_ns != cached_global_time ||
        canonical.value.flags != cached_flags) {
      result.error = Error::kCacheMismatch;
      return result;
    }
    result.value.records.push_back(
        RecordView{sequence, journal_sequence, canonical.value, encoded});
  }
  return result;
}

}  // namespace forge::workers::ring::v1

#endif
