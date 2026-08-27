#include "forge_worker_sdk.hpp"
#include "forge_nwb_receipt_v1.hpp"
#include "forge_analysis_ring_v1.hpp"
#include "forge_analysis_mapping_windows.hpp"

#include <cassert>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <cstring>
#include <vector>

namespace {

std::vector<std::uint8_t> read_hex(const char* path) {
    std::ifstream input(path);
    assert(input.good());
    std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    std::string compact;
    for (const auto value : text) {
        if (!std::isspace(static_cast<unsigned char>(value))) compact.push_back(value);
    }
    assert(compact.size() % 2 == 0);
    std::vector<std::uint8_t> result;
    result.reserve(compact.size() / 2);
    for (std::size_t offset = 0; offset < compact.size(); offset += 2) {
        result.push_back(static_cast<std::uint8_t>(
            std::stoul(compact.substr(offset, 2), nullptr, 16)));
    }
    return result;
}

std::vector<std::uint8_t> read_binary(const char* path) {
    std::ifstream input(path, std::ios::binary);
    assert(input.good());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

}  // namespace

int main(int argc, char** argv) {
    assert(argc == 5);
    namespace workers = forge::workers;
    namespace wire = forge::protocol::v1;

    auto record = std::make_shared<const std::vector<std::uint8_t>>(read_hex(argv[1]));
    const auto canonical = wire::decode_record(*record);
    assert(canonical);
    const auto& envelope = canonical.value;
    workers::JournalChunkCacheV1 cache{
        9,
        workers::pod_slot_for(envelope.pod_id),
        envelope.record_sequence,
        envelope.frame_start,
        envelope.frame_end_exclusive,
        envelope.sample_start,
        envelope.sample_end_exclusive,
        envelope.global_time_start_ns,
        envelope.global_time_end_exclusive_ns,
    };
    const auto adapted = workers::adapt_sample_block(record, cache, 7);
    assert(adapted);
    assert(adapted.value.valid());
    assert(adapted.value.journal_sequence == 9);
    assert(adapted.value.record_sequence == envelope.record_sequence);
    assert(adapted.value.sample(0, 0).has_value());

    auto mismatched = cache;
    ++mismatched.sample_end_exclusive;
    assert(!workers::adapt_sample_block(record, mismatched, 7));

    workers::SpscBoundedConsumer<workers::SampleBlockLease, 3> consumer;
    assert(consumer.try_push(adapted.value));
    assert(consumer.try_push(adapted.value));
    assert(!consumer.try_push(adapted.value));
    assert(consumer.dropped() == 1);
    assert(consumer.try_pop().has_value());
    assert(consumer.try_pop().has_value());
    assert(!consumer.try_pop().has_value());

    const auto intent_wire = read_hex(argv[2]);
    const auto intent = wire::decode_low_speed(intent_wire);
    assert(intent);
    assert(workers::is_protocol_stim_intent(intent.value));

    const auto nwb_receipt_wire = read_hex(argv[3]);
    const auto nwb_receipt = forge::workers::nwb::v1::parse(nwb_receipt_wire);
    assert(nwb_receipt.ok);
    assert(nwb_receipt.value.checked_blocks == 4);
    assert(nwb_receipt.value.total_samples == 240);
    auto corrupted_receipt = nwb_receipt_wire;
    corrupted_receipt[264] ^= 1;
    assert(!forge::workers::nwb::v1::parse(corrupted_receipt).ok);

    const auto ring_wire = read_binary(argv[4]);
    const auto ring = forge::workers::ring::v1::parse(ring_wire);
    assert(ring);
    assert(ring.value.snapshot_only);
    assert(ring.value.records.size() == 2);
    assert(ring.value.records[0].journal_sequence == 41);
    assert(ring.value.records[1].journal_sequence == 42);
    auto corrupted_ring = ring_wire;
    corrupted_ring[256 + 64 + 180] ^= 1;
    assert(!forge::workers::ring::v1::parse(corrupted_ring));

    const auto mapping_name = std::wstring(L"Local\\ForgeAnalysisRing-CppSmoke-") +
                              std::to_wstring(GetCurrentProcessId());
    const auto mapping_size = static_cast<std::uint64_t>(ring_wire.size());
    HANDLE mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
        static_cast<DWORD>(mapping_size >> 32U),
        static_cast<DWORD>(mapping_size), mapping_name.c_str());
    assert(mapping != nullptr);
    assert(GetLastError() != ERROR_ALREADY_EXISTS);
    auto* mapped = static_cast<std::uint8_t*>(
        MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, ring_wire.size()));
    assert(mapped != nullptr);
    std::memcpy(mapped, ring_wire.data(), ring_wire.size());

    forge::workers::ring::v1::LiveError live_error{};
    auto live = forge::workers::ring::v1::WindowsMappedConsumer::open(
        mapping_name, ring.value.run_id, ring.value.consumer_id,
        ring.value.producer_epoch, live_error);
    assert(live != nullptr);
    assert(live_error == forge::workers::ring::v1::LiveError::kNone);
    const auto live_first = live->try_consume(1'000);
    assert(live_first);
    assert(live_first.record.has_value());
    assert(live_first.record->journal_sequence == 41);
    const auto live_second = live->try_consume(1'001);
    assert(live_second);
    assert(live_second.record.has_value());
    assert(live_second.record->journal_sequence == 42);
    const auto live_empty = live->try_consume(1'002);
    assert(live_empty);
    assert(!live_empty.record.has_value());
    assert(live->dropped_records() == 0);
    assert(live->fault_flags() == 0);
    assert(forge::protocol::v1::read_u64(
               std::span<const std::uint8_t>(mapped, ring_wire.size()), 136) == 2);
    live.reset();
    assert(UnmapViewOfFile(mapped) != 0);
    assert(CloseHandle(mapping) != 0);
    return 0;
}
