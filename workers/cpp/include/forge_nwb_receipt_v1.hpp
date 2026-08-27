#ifndef FORGE_NWB_RECEIPT_V1_HPP
#define FORGE_NWB_RECEIPT_V1_HPP

#include "forge_protocol_v1.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace forge::workers::nwb::v1 {

using forge::protocol::v1::Hash32;
using forge::protocol::v1::Id16;

inline constexpr std::size_t kReceiptLen = 544;
inline constexpr std::uint32_t kRequiredValidationFlags = 0x0000'00ff;
inline constexpr std::uint32_t kPublicationAuthorized = 0x0000'0100;
inline constexpr Hash32 kReceiptContractHash{
    0x6d, 0xfd, 0x22, 0x30, 0xe7, 0x35, 0xb8, 0x44, 0xc6, 0xd0, 0x31,
    0xaa, 0x9a, 0x19, 0xaa, 0x86, 0xa1, 0x4e, 0xfb, 0x98, 0xec, 0x54,
    0xe2, 0x07, 0x66, 0x27, 0xa7, 0x6e, 0xb4, 0xf7, 0x2f, 0x93,
};

struct ReceiptView {
  std::uint32_t validation_flags{};
  Id16 run_id{};
  std::uint32_t generation{};
  std::uint16_t pod_count{};
  std::uint64_t expected_last_journal_sequence{};
  std::uint64_t checked_blocks{};
  std::uint64_t total_samples{};
  std::uint64_t validated_at_unix_ns{};
  std::uint64_t journal_bytes{};
  std::uint64_t nwb_bytes{};
  Hash32 host_protocol_hash{};
  Hash32 receipt_contract_hash{};
  Hash32 journal_sha256{};
  Hash32 journal_seal_sha256{};
  Hash32 durable_checkpoint_set_sha256{};
  Hash32 nwb_sha256{};
  Hash32 schema_plan_sha256{};
  Hash32 dependency_lock_sha256{};
  Hash32 materializer_build_sha256{};
  Hash32 validation_report_sha256{};
  Hash32 samples_manifest_sha256{};
  Hash32 session_manifest_sha256{};
  Hash32 run_ledger_seal_evidence_sha256{};
  std::uint64_t validation_sequence{};
};

struct ParseResult {
  ReceiptView value{};
  bool ok{};
};

[[nodiscard]] inline ParseResult parse(
    std::span<const std::uint8_t> wire) noexcept {
  using namespace forge::protocol::v1;
  ParseResult result{};
  if (wire.size() != kReceiptLen || !has_magic(wire, 0, "FGRNWB01") ||
      read_u16(wire, 8) != 1 || read_u16(wire, 10) != kReceiptLen ||
      read_u16(wire, 38) != 0 || read_u32(wire, 100) != 0 ||
      read_u32(wire, 540) != crc32c(wire.first(540))) {
    return result;
  }
  for (std::size_t offset = 528; offset < 540; ++offset) {
    if (wire[offset] != 0) return result;
  }

  result.value = {
      read_u32(wire, 12), read_array<16>(wire, 16), read_u32(wire, 32),
      read_u16(wire, 36), read_u64(wire, 40), read_u64(wire, 48),
      read_u64(wire, 56), read_u64(wire, 64), read_u64(wire, 72),
      read_u64(wire, 80), read_array<32>(wire, 104),
      read_array<32>(wire, 136), read_array<32>(wire, 168),
      read_array<32>(wire, 200), read_array<32>(wire, 232),
      read_array<32>(wire, 264), read_array<32>(wire, 296),
      read_array<32>(wire, 328), read_array<32>(wire, 360),
      read_array<32>(wire, 392), read_array<32>(wire, 424),
      read_array<32>(wire, 456), read_array<32>(wire, 488),
      read_u64(wire, 520),
  };
  const auto expected_blocks =
      result.value.expected_last_journal_sequence ==
              std::numeric_limits<std::uint64_t>::max()
          ? 0
          : result.value.expected_last_journal_sequence + 1;
  const auto hash_nonzero = [](const Hash32& hash) {
    for (const auto byte : hash) {
      if (byte != 0) return true;
    }
    return false;
  };
  const std::array<Hash32, 13> hashes{
      result.value.host_protocol_hash,
      result.value.receipt_contract_hash,
      result.value.journal_sha256,
      result.value.journal_seal_sha256,
      result.value.durable_checkpoint_set_sha256,
      result.value.nwb_sha256,
      result.value.schema_plan_sha256,
      result.value.dependency_lock_sha256,
      result.value.materializer_build_sha256,
      result.value.validation_report_sha256,
      result.value.samples_manifest_sha256,
      result.value.session_manifest_sha256,
      result.value.run_ledger_seal_evidence_sha256,
  };
  if (result.value.validation_flags != kRequiredValidationFlags ||
      (result.value.validation_flags & kPublicationAuthorized) != 0 ||
      !nonzero(result.value.run_id) || result.value.pod_count < 1 ||
      result.value.pod_count > 8 ||
      result.value.checked_blocks != expected_blocks ||
      result.value.validated_at_unix_ns == 0 ||
      result.value.journal_bytes == 0 || result.value.nwb_bytes == 0 ||
      result.value.validation_sequence == 0 ||
      result.value.host_protocol_hash != kProtocolHash ||
      result.value.receipt_contract_hash != kReceiptContractHash) {
    return result;
  }
  for (const auto& hash : hashes) {
    if (!hash_nonzero(hash)) return result;
  }
  if (read_u32(wire, 88) != 0 || read_u32(wire, 92) != 0 ||
      read_u32(wire, 96) != 0) {
    return result;
  }
  result.ok = true;
  return result;
}

}  // namespace forge::workers::nwb::v1

#endif
