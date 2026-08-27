#ifndef FORGE_ANALYSIS_MAPPING_WINDOWS_HPP
#define FORGE_ANALYSIS_MAPPING_WINDOWS_HPP

#ifndef _WIN32
#error "Forge live analysis mappings are currently a Windows-only contract"
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "forge_analysis_ring_v1.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace forge::workers::ring::v1 {

enum class LiveError {
  kNone,
  kName,
  kOpen,
  kMap,
  kRegion,
  kHeader,
  kExpectedIdentity,
  kSequenceWindow,
  kSlot,
};

struct OwnedLiveRecord {
  std::uint64_t ring_sequence{};
  std::uint64_t journal_sequence{};
  std::vector<std::uint8_t> encoded_record{};
};

struct LiveConsumeResult {
  LiveError error{LiveError::kNone};
  std::optional<OwnedLiveRecord> record{};

  [[nodiscard]] explicit operator bool() const noexcept {
    return error == LiveError::kNone;
  }
};

class WindowsMappedConsumer final {
 public:
  WindowsMappedConsumer(const WindowsMappedConsumer&) = delete;
  WindowsMappedConsumer& operator=(const WindowsMappedConsumer&) = delete;

  WindowsMappedConsumer(WindowsMappedConsumer&& other) noexcept
      : handle_(std::exchange(other.handle_, nullptr)),
        view_(std::exchange(other.view_, nullptr)),
        region_bytes_(other.region_bytes_),
        slot_count_(other.slot_count_),
        payload_capacity_(other.payload_capacity_),
        slot_stride_(other.slot_stride_),
        run_id_(other.run_id_),
        consumer_id_(other.consumer_id_),
        producer_epoch_(other.producer_epoch_) {}

  WindowsMappedConsumer& operator=(WindowsMappedConsumer&& other) noexcept {
    if (this != &other) {
      close();
      handle_ = std::exchange(other.handle_, nullptr);
      view_ = std::exchange(other.view_, nullptr);
      region_bytes_ = other.region_bytes_;
      slot_count_ = other.slot_count_;
      payload_capacity_ = other.payload_capacity_;
      slot_stride_ = other.slot_stride_;
      run_id_ = other.run_id_;
      consumer_id_ = other.consumer_id_;
      producer_epoch_ = other.producer_epoch_;
    }
    return *this;
  }

  ~WindowsMappedConsumer() { close(); }

  [[nodiscard]] static std::unique_ptr<WindowsMappedConsumer> open(
      std::wstring_view mapping_name, const wire::Id16& expected_run_id,
      const wire::Id16& expected_consumer_id,
      std::uint64_t expected_producer_epoch, LiveError& error) noexcept {
    error = LiveError::kNone;
    if (!valid_name(mapping_name) || !wire::nonzero(expected_run_id) ||
        !wire::nonzero(expected_consumer_id) || expected_producer_epoch == 0) {
      error = LiveError::kName;
      return nullptr;
    }
    const std::wstring terminated(mapping_name);
    HANDLE handle = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE,
                                     terminated.c_str());
    if (handle == nullptr) {
      error = LiveError::kOpen;
      return nullptr;
    }
    auto* view = static_cast<std::uint8_t*>(
        MapViewOfFile(handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0));
    if (view == nullptr) {
      CloseHandle(handle);
      error = LiveError::kMap;
      return nullptr;
    }
    MEMORY_BASIC_INFORMATION region{};
    if (VirtualQuery(view, &region, sizeof(region)) != sizeof(region) ||
        region.RegionSize < kGlobalHeaderBytes) {
      UnmapViewOfFile(view);
      CloseHandle(handle);
      error = LiveError::kRegion;
      return nullptr;
    }
    const auto header = std::span<const std::uint8_t>(view, kGlobalHeaderBytes);
    std::uint32_t slot_count{};
    std::uint32_t payload_capacity{};
    std::uint64_t slot_stride{};
    std::size_t total_bytes{};
    if (!validate_header(header, expected_run_id, expected_consumer_id,
                         expected_producer_epoch, slot_count,
                         payload_capacity, slot_stride, total_bytes)) {
      UnmapViewOfFile(view);
      CloseHandle(handle);
      error = LiveError::kHeader;
      return nullptr;
    }
    if (total_bytes > region.RegionSize) {
      UnmapViewOfFile(view);
      CloseHandle(handle);
      error = LiveError::kRegion;
      return nullptr;
    }
    return std::unique_ptr<WindowsMappedConsumer>(new WindowsMappedConsumer(
        handle, view, total_bytes, slot_count, payload_capacity, slot_stride,
        expected_run_id, expected_consumer_id, expected_producer_epoch));
  }

  [[nodiscard]] LiveConsumeResult try_consume(
      std::uint64_t consumer_heartbeat_monotonic_ns) noexcept {
    LiveConsumeResult result{};
    if (!immutable_header_still_matches()) {
      latch_contradiction();
      result.error = LiveError::kHeader;
      return result;
    }
    const auto published = atomic_load(128);
    const auto consumed = atomic_load(136);
    if (published == consumed) {
      atomic_store(160, consumer_heartbeat_monotonic_ns);
      return result;
    }
    if (consumed > published || published - consumed > slot_count_) {
      latch_contradiction();
      result.error = LiveError::kSequenceWindow;
      return result;
    }
    const auto base = kGlobalHeaderBytes +
                      static_cast<std::size_t>(consumed % slot_count_) * slot_stride_;
    if (atomic_load(base) != consumed || wire::read_u64(bytes(), base + 48) != ~consumed) {
      latch_contradiction();
      result.error = LiveError::kSlot;
      return result;
    }
    const auto encoded_bytes = wire::read_u32(bytes(), base + 8);
    if (encoded_bytes < wire::kRecordHeaderLen ||
        encoded_bytes > payload_capacity_ || wire::read_u32(bytes(), base + 44) != 0 ||
        wire::read_u64(bytes(), base + 56) != 0) {
      latch_contradiction();
      result.error = LiveError::kSlot;
      return result;
    }
    const auto encoded = bytes().subspan(base + kSlotHeaderBytes, encoded_bytes);
    const auto decoded = wire::decode_record(encoded);
    if (wire::crc32c(encoded) != wire::read_u32(bytes(), base + 12) || !decoded ||
        !valid_sample_block(decoded.value) || decoded.value.run_id != run_id_ ||
        decoded.value.record_sequence != wire::read_u64(bytes(), base + 24) ||
        decoded.value.global_time_start_ns != wire::read_u64(bytes(), base + 32) ||
        decoded.value.flags != wire::read_u32(bytes(), base + 40)) {
      latch_contradiction();
      result.error = LiveError::kSlot;
      return result;
    }
    OwnedLiveRecord owned{consumed, wire::read_u64(bytes(), base + 16),
                          std::vector<std::uint8_t>(encoded.begin(), encoded.end())};
    atomic_store(base, kEmptySlot);
    atomic_store(136, consumed + 1);
    atomic_store(160, consumer_heartbeat_monotonic_ns);
    result.record = std::move(owned);
    return result;
  }

  [[nodiscard]] std::uint64_t dropped_records() const noexcept {
    return atomic_load(144);
  }

  [[nodiscard]] std::uint64_t fault_flags() const noexcept {
    return atomic_load(168);
  }

 private:
  WindowsMappedConsumer(HANDLE handle, std::uint8_t* view,
                        std::size_t region_bytes, std::uint32_t slot_count,
                        std::uint32_t payload_capacity,
                        std::uint64_t slot_stride, wire::Id16 run_id,
                        wire::Id16 consumer_id,
                        std::uint64_t producer_epoch) noexcept
      : handle_(handle),
        view_(view),
        region_bytes_(region_bytes),
        slot_count_(slot_count),
        payload_capacity_(payload_capacity),
        slot_stride_(slot_stride),
        run_id_(run_id),
        consumer_id_(consumer_id),
        producer_epoch_(producer_epoch) {}

  static bool valid_name(std::wstring_view name) noexcept {
    constexpr std::wstring_view prefix = L"Local\\ForgeAnalysisRing-";
    if (!name.starts_with(prefix) || name.size() <= prefix.size() ||
        name.size() >= 192) {
      return false;
    }
    for (const auto value : name.substr(prefix.size())) {
      if (!((value >= L'a' && value <= L'z') ||
            (value >= L'A' && value <= L'Z') ||
            (value >= L'0' && value <= L'9') || value == L'-')) {
        return false;
      }
    }
    return true;
  }

  static bool validate_header(std::span<const std::uint8_t> header,
                              const wire::Id16& expected_run_id,
                              const wire::Id16& expected_consumer_id,
                              std::uint64_t expected_epoch,
                              std::uint32_t& slot_count,
                              std::uint32_t& payload_capacity,
                              std::uint64_t& slot_stride,
                              std::size_t& total_bytes) noexcept {
    if (header.size() != kGlobalHeaderBytes ||
        !wire::has_magic(header, 0, "FGRRNG01") || wire::read_u16(header, 8) != 1 ||
        wire::read_u16(header, 10) != kGlobalHeaderBytes ||
        wire::read_u16(header, 12) != kSlotHeaderBytes ||
        wire::read_u16(header, 14) != 0 || wire::read_u32(header, 24) != 0 ||
        wire::read_u32(header, 28) != 0 ||
        wire::read_array<32>(header, 32) != wire::kProtocolHash ||
        wire::read_array<16>(header, 64) != expected_run_id ||
        wire::read_array<16>(header, 80) != expected_consumer_id ||
        wire::read_u64(header, 96) != expected_epoch ||
        wire::read_u32(header, 112) != wire::crc32c(header.first(112)) ||
        !all_zero(header.subspan(116, 12)) ||
        !all_zero(header.subspan(176, 80))) {
      return false;
    }
    slot_count = wire::read_u32(header, 16);
    payload_capacity = wire::read_u32(header, 20);
    slot_stride = wire::read_u64(header, 104);
    if (slot_count < 2 || slot_count > 65'536 ||
        payload_capacity < wire::kRecordHeaderLen ||
        payload_capacity > wire::kRecordHeaderLen + wire::kMaxRecordPayloadLen ||
        slot_stride < kSlotHeaderBytes + payload_capacity || slot_stride % 64 != 0 ||
        slot_count > (SIZE_MAX - kGlobalHeaderBytes) / slot_stride) {
      return false;
    }
    total_bytes = kGlobalHeaderBytes +
                  static_cast<std::size_t>(slot_count) * slot_stride;
    return total_bytes <= 1024ULL * 1024ULL * 1024ULL;
  }

  [[nodiscard]] bool immutable_header_still_matches() const noexcept {
    std::uint32_t slot_count{};
    std::uint32_t payload_capacity{};
    std::uint64_t slot_stride{};
    std::size_t total_bytes{};
    return validate_header(bytes().first(kGlobalHeaderBytes), run_id_, consumer_id_,
                           producer_epoch_, slot_count,
                           payload_capacity, slot_stride, total_bytes) &&
           slot_count == slot_count_ && payload_capacity == payload_capacity_ &&
           slot_stride == slot_stride_ && total_bytes == region_bytes_;
  }

  [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept {
    return {view_, region_bytes_};
  }

  [[nodiscard]] volatile LONG64* atomic_at(std::size_t offset) const noexcept {
    return reinterpret_cast<volatile LONG64*>(view_ + offset);
  }

  [[nodiscard]] std::uint64_t atomic_load(std::size_t offset) const noexcept {
    return static_cast<std::uint64_t>(
        InterlockedCompareExchange64(atomic_at(offset), 0, 0));
  }

  void atomic_store(std::size_t offset, std::uint64_t value) noexcept {
    InterlockedExchange64(atomic_at(offset), static_cast<LONG64>(value));
  }

  void latch_contradiction() noexcept {
    InterlockedOr64(atomic_at(168), static_cast<LONG64>(2));
  }

  void close() noexcept {
    if (view_ != nullptr) {
      UnmapViewOfFile(view_);
      view_ = nullptr;
    }
    if (handle_ != nullptr) {
      CloseHandle(handle_);
      handle_ = nullptr;
    }
  }

  HANDLE handle_{};
  std::uint8_t* view_{};
  std::size_t region_bytes_{};
  std::uint32_t slot_count_{};
  std::uint32_t payload_capacity_{};
  std::uint64_t slot_stride_{};
  wire::Id16 run_id_{};
  wire::Id16 consumer_id_{};
  std::uint64_t producer_epoch_{};
};

}  // namespace forge::workers::ring::v1

#endif
