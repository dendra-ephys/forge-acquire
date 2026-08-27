#pragma once

// Downstream-only adapters over the normative Forge host protocol v1.
// This header contains no second wire contract, transport, register write,
// StimCommand constructor, authorization shortcut, or actuator API.

#include "forge_protocol_v1.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace forge::workers {

namespace wire = forge::protocol::v1;

struct RunIdentity {
    wire::Id16 run_id{};
    std::uint64_t generation{};

    friend bool operator==(const RunIdentity&, const RunIdentity&) = default;
};

// Redundant M1 chunk-header cache supplied by a durability-bounded journal
// reader. Every field is checked against the canonical M0 envelope.
struct JournalChunkCacheV1 {
    std::uint64_t journal_sequence{};
    std::uint16_t pod_slot{};
    std::uint64_t record_sequence{};
    std::uint64_t frame_start{};
    std::uint64_t frame_end_exclusive{};
    std::uint64_t sample_start{};
    std::uint64_t sample_end_exclusive{};
    std::uint64_t global_time_start_ns{};
    std::uint64_t global_time_end_exclusive_ns{};
};

enum class AdapterError {
    kNone,
    kNullRecord,
    kCanonicalRecord,
    kNotSampleBlock,
    kJournalCacheMismatch,
    kSampleBlockHeader,
    kSampleBlockInvariant,
};

struct SampleBlockLease {
    RunIdentity run{};
    wire::Id16 canonical_pod_id{};
    wire::Id16 headstage_id{};
    std::uint16_t pod_slot{};
    std::uint64_t journal_sequence{};
    std::uint64_t record_sequence{};
    std::uint64_t frame_start{};
    std::uint64_t frame_end_exclusive{};
    std::uint64_t sample_start{};
    std::uint64_t sample_end_exclusive{};
    std::uint64_t global_time_start_ns{};
    std::uint64_t global_time_end_exclusive_ns{};
    std::uint32_t channel_layout_id{};
    std::uint16_t channel_count{};
    std::uint32_t sample_count{};
    std::uint32_t sample_rate_numerator_hz{};
    std::uint32_t sample_rate_denominator{};
    std::uint32_t record_flags{};
    std::uint32_t sample_block_flags{};
    std::shared_ptr<const std::vector<std::uint8_t>> encoded_record;

    [[nodiscard]] double sample_rate_hz() const noexcept {
        return sample_rate_denominator == 0
                   ? 0.0
                   : static_cast<double>(sample_rate_numerator_hz) /
                         static_cast<double>(sample_rate_denominator);
    }

    [[nodiscard]] bool valid() const noexcept {
        if (!encoded_record || channel_count == 0 || sample_count == 0 ||
            sample_rate_numerator_hz == 0 || sample_rate_denominator == 0 ||
            sample_end_exclusive - sample_start != sample_count) {
            return false;
        }
        const auto values = static_cast<std::size_t>(sample_count) * channel_count;
        if (channel_count != 0 && values / channel_count != sample_count) return false;
        return encoded_record->size() ==
               wire::kRecordHeaderLen + 32U + values * sizeof(std::int16_t);
    }

    [[nodiscard]] std::optional<std::int16_t> sample(
        std::uint32_t sample_index, std::uint16_t channel_index) const noexcept {
        if (!valid() || sample_index >= sample_count || channel_index >= channel_count) {
            return std::nullopt;
        }
        const auto linear = static_cast<std::size_t>(sample_index) * channel_count +
                            channel_index;
        const auto offset = wire::kRecordHeaderLen + 32U + linear * 2U;
        const auto raw = static_cast<std::uint32_t>((*encoded_record)[offset]) |
                         static_cast<std::uint32_t>((*encoded_record)[offset + 1]) << 8U;
        const auto signed_value = raw <= 0x7fffU
                                      ? static_cast<std::int32_t>(raw)
                                      : static_cast<std::int32_t>(raw) - 0x1'0000;
        return static_cast<std::int16_t>(signed_value);
    }
};

struct SampleBlockAdapterResult {
    AdapterError error{AdapterError::kNone};
    SampleBlockLease value{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == AdapterError::kNone;
    }
};

[[nodiscard]] inline std::uint16_t pod_slot_for(const wire::Id16& pod_id) noexcept {
    return static_cast<std::uint16_t>(wire::crc32c(pod_id) & 0xffffU);
}

[[nodiscard]] inline SampleBlockAdapterResult adapt_sample_block(
    std::shared_ptr<const std::vector<std::uint8_t>> encoded_record,
    const JournalChunkCacheV1& cache, std::uint64_t generation) noexcept {
    SampleBlockAdapterResult result{};
    if (!encoded_record) {
        result.error = AdapterError::kNullRecord;
        return result;
    }
    const auto decoded = wire::decode_record(*encoded_record);
    if (!decoded) {
        result.error = AdapterError::kCanonicalRecord;
        return result;
    }
    const auto& envelope = decoded.value;
    if (envelope.kind != wire::RecordKind::kSampleBlock) {
        result.error = AdapterError::kNotSampleBlock;
        return result;
    }
    if (cache.pod_slot != pod_slot_for(envelope.pod_id) ||
        cache.record_sequence != envelope.record_sequence ||
        cache.frame_start != envelope.frame_start ||
        cache.frame_end_exclusive != envelope.frame_end_exclusive ||
        cache.sample_start != envelope.sample_start ||
        cache.sample_end_exclusive != envelope.sample_end_exclusive ||
        cache.global_time_start_ns != envelope.global_time_start_ns ||
        cache.global_time_end_exclusive_ns != envelope.global_time_end_exclusive_ns) {
        result.error = AdapterError::kJournalCacheMismatch;
        return result;
    }
    const auto payload = envelope.payload;
    if (payload.size() < 32U || wire::read_u16(payload, 0) != wire::kVersion ||
        wire::read_u16(payload, 2) != 32U) {
        result.error = AdapterError::kSampleBlockHeader;
        return result;
    }
    const auto flags = wire::read_u32(payload, 4);
    const auto sample_count = wire::read_u32(payload, 8);
    const auto channel_count = wire::read_u16(payload, 12);
    const auto sample_format = wire::read_u16(payload, 14);
    const auto rate_numerator = wire::read_u32(payload, 16);
    const auto rate_denominator = wire::read_u32(payload, 20);
    const auto first_sample = wire::read_u64(payload, 24);
    const auto values = static_cast<std::size_t>(sample_count) * channel_count;
    if ((flags & ~0x0000'0003U) != 0 || sample_count == 0 || channel_count == 0 ||
        sample_format != 1 || rate_numerator == 0 || rate_denominator == 0 ||
        first_sample != envelope.sample_start ||
        sample_count != envelope.sample_end_exclusive - envelope.sample_start ||
        channel_count != envelope.channel_count || envelope.sample_format != 1 ||
        (channel_count != 0 && values / channel_count != sample_count) ||
        payload.size() != 32U + values * sizeof(std::int16_t)) {
        result.error = AdapterError::kSampleBlockInvariant;
        return result;
    }
    result.value = SampleBlockLease{
        RunIdentity{envelope.run_id, generation},
        envelope.pod_id,
        envelope.headstage_id,
        cache.pod_slot,
        cache.journal_sequence,
        envelope.record_sequence,
        envelope.frame_start,
        envelope.frame_end_exclusive,
        envelope.sample_start,
        envelope.sample_end_exclusive,
        envelope.global_time_start_ns,
        envelope.global_time_end_exclusive_ns,
        envelope.channel_layout_id,
        envelope.channel_count,
        sample_count,
        rate_numerator,
        rate_denominator,
        envelope.flags,
        flags,
        std::move(encoded_record),
    };
    if (!result.value.valid()) result.error = AdapterError::kSampleBlockInvariant;
    return result;
}

struct AnalysisAnnotation {
    std::string worker_id;
    std::string algorithm_id;
    std::string algorithm_version;
    RunIdentity run;
    wire::Id16 canonical_pod_id{};
    std::uint16_t pod_slot{};
    std::uint64_t sample_index{};
    std::optional<std::uint32_t> channel_id;
    std::string kind;
    std::string payload_json;
    bool reference_only{true};
};

class AnalysisWorker {
  public:
    virtual ~AnalysisWorker() = default;
    [[nodiscard]] virtual std::vector<AnalysisAnnotation>
    process(const SampleBlockLease& block) = 0;
};

// One producer and one consumer only. Capacity includes one sentinel slot, so
// usable depth is Capacity - 1. Full queues reject the newest item.
template <typename T, std::size_t Capacity>
class SpscBoundedConsumer {
    static_assert(Capacity >= 2, "Capacity must reserve at least one data slot");

  public:
    SpscBoundedConsumer() = default;
    SpscBoundedConsumer(const SpscBoundedConsumer&) = delete;
    SpscBoundedConsumer& operator=(const SpscBoundedConsumer&) = delete;

    [[nodiscard]] bool try_push(T item) noexcept(noexcept(T(std::move(item)))) {
        const auto head = head_.load(std::memory_order_relaxed);
        const auto next = increment(head);
        if (next == tail_.load(std::memory_order_acquire)) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        slots_[head].emplace(std::move(item));
        head_.store(next, std::memory_order_release);
        return true;
    }

    [[nodiscard]] std::optional<T> try_pop() noexcept(
        noexcept(T(std::declval<T&&>()))) {
        const auto tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_.load(std::memory_order_acquire)) return std::nullopt;
        std::optional<T> item{std::move(slots_[tail])};
        slots_[tail].reset();
        tail_.store(increment(tail), std::memory_order_release);
        return item;
    }

    [[nodiscard]] std::uint64_t dropped() const noexcept {
        return dropped_.load(std::memory_order_relaxed);
    }

    static constexpr std::size_t usable_capacity() noexcept { return Capacity - 1; }

  private:
    static constexpr std::size_t increment(std::size_t value) noexcept {
        return (value + 1) % Capacity;
    }

    std::array<std::optional<T>, Capacity> slots_{};
    alignas(64) std::atomic<std::size_t> head_{0};
    alignas(64) std::atomic<std::size_t> tail_{0};
    std::atomic<std::uint64_t> dropped_{0};
};

// The C++ M0 binding is intentionally read-only. Algorithms can forward a
// decoded StimIntentV1 body to the authenticated service boundary, but this
// SDK cannot construct or locally "authorize" a stimulation command.
[[nodiscard]] inline bool is_protocol_stim_intent(
    const wire::DecodedControlView& message) noexcept {
    return message.kind == wire::MessageKind::kStimIntent && message.body.size() == 240U;
}

}  // namespace forge::workers
