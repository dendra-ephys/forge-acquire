#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "forge_analysis_mapping_windows.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace {

using Consumer = forge::workers::ring::v1::WindowsMappedConsumer;
using Id16 = forge::protocol::v1::Id16;

constexpr char kCapsuleName[] = "forge.analysis_mapping_consumer.v1";
constexpr std::size_t kMaximumPipeFrame = 1024U * 1024U;

struct ConsumerHolder {
  std::unique_ptr<Consumer> consumer;
};

void destroy_consumer(PyObject* capsule) noexcept {
  auto* holder = static_cast<ConsumerHolder*>(
      PyCapsule_GetPointer(capsule, kCapsuleName));
  if (holder != nullptr) {
    delete holder;
  } else {
    PyErr_Clear();
  }
}

ConsumerHolder* require_holder(PyObject* capsule) {
  auto* holder = static_cast<ConsumerHolder*>(
      PyCapsule_GetPointer(capsule, kCapsuleName));
  if (holder == nullptr) {
    return nullptr;
  }
  if (!holder->consumer) {
    PyErr_SetString(PyExc_RuntimeError, "analysis mapping consumer is closed");
    return nullptr;
  }
  return holder;
}

bool parse_id16(PyObject* value, const char* field, Id16& output) {
  char* bytes = nullptr;
  Py_ssize_t length = 0;
  if (PyBytes_AsStringAndSize(value, &bytes, &length) != 0) {
    return false;
  }
  if (length != static_cast<Py_ssize_t>(output.size())) {
    PyErr_Format(PyExc_ValueError, "%s must contain exactly 16 bytes", field);
    return false;
  }
  for (Py_ssize_t index = 0; index < length; ++index) {
    output[static_cast<std::size_t>(index)] =
        static_cast<std::uint8_t>(bytes[index]);
  }
  return true;
}

const char* live_error_name(forge::workers::ring::v1::LiveError error) noexcept {
  using Error = forge::workers::ring::v1::LiveError;
  switch (error) {
    case Error::kNone:
      return "none";
    case Error::kName:
      return "name";
    case Error::kOpen:
      return "open";
    case Error::kMap:
      return "map";
    case Error::kRegion:
      return "region";
    case Error::kHeader:
      return "header";
    case Error::kExpectedIdentity:
      return "identity";
    case Error::kSequenceWindow:
      return "sequence_window";
    case Error::kSlot:
      return "slot";
  }
  return "unknown";
}

class OwnedHandle final {
 public:
  explicit OwnedHandle(HANDLE value = nullptr) noexcept : value_(value) {}
  OwnedHandle(const OwnedHandle&) = delete;
  OwnedHandle& operator=(const OwnedHandle&) = delete;
  ~OwnedHandle() {
    if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
      CloseHandle(value_);
    }
  }
  [[nodiscard]] HANDLE get() const noexcept { return value_; }

 private:
  HANDLE value_;
};

bool valid_pipe_name(const std::wstring& name) noexcept {
  constexpr std::wstring_view prefix = L"\\\\.\\pipe\\";
  if (!name.starts_with(prefix) || name.size() <= prefix.size() ||
      name.size() >= 256) {
    return false;
  }
  return name.find(L'\\', prefix.size()) == std::wstring::npos;
}

std::uint32_t remaining_milliseconds(
    std::chrono::steady_clock::time_point deadline) noexcept {
  const auto now = std::chrono::steady_clock::now();
  if (now >= deadline) {
    return 0;
  }
  const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
      deadline - now);
  return static_cast<std::uint32_t>(
      std::min<std::int64_t>(remaining.count() + 1,
                             std::numeric_limits<std::uint32_t>::max() - 1));
}

bool overlapped_transfer(HANDLE pipe, bool write, std::uint8_t* bytes,
                         std::uint32_t length,
                         std::chrono::steady_clock::time_point deadline,
                         std::uint32_t& transferred,
                         std::uint32_t& error) noexcept {
  OwnedHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (event.get() == nullptr) {
    error = GetLastError();
    return false;
  }
  OVERLAPPED overlapped{};
  overlapped.hEvent = event.get();
  DWORD immediate = 0;
  const BOOL started = write
                           ? WriteFile(pipe, bytes, length, &immediate, &overlapped)
                           : ReadFile(pipe, bytes, length, &immediate, &overlapped);
  if (started != FALSE) {
    transferred = immediate;
    return true;
  }
  const auto start_error = GetLastError();
  if (start_error != ERROR_IO_PENDING) {
    error = start_error;
    return false;
  }
  const auto wait_ms = remaining_milliseconds(deadline);
  const auto wait_result =
      WaitForSingleObject(event.get(), wait_ms == 0 ? 0 : wait_ms);
  if (wait_result != WAIT_OBJECT_0) {
    static_cast<void>(CancelIoEx(pipe, &overlapped));
    static_cast<void>(WaitForSingleObject(event.get(), INFINITE));
    DWORD ignored = 0;
    static_cast<void>(GetOverlappedResult(pipe, &overlapped, &ignored, FALSE));
    error = wait_result == WAIT_TIMEOUT ? ERROR_SEM_TIMEOUT : GetLastError();
    return false;
  }
  DWORD completed = 0;
  if (GetOverlappedResult(pipe, &overlapped, &completed, FALSE) == FALSE) {
    error = GetLastError();
    return false;
  }
  transferred = completed;
  return true;
}

bool transfer_exact(HANDLE pipe, bool write, std::uint8_t* bytes,
                    std::size_t length,
                    std::chrono::steady_clock::time_point deadline,
                    std::uint32_t& error) noexcept {
  std::size_t offset = 0;
  while (offset < length) {
    const auto requested = static_cast<std::uint32_t>(std::min<std::size_t>(
        length - offset, std::numeric_limits<std::uint32_t>::max()));
    std::uint32_t transferred = 0;
    if (!overlapped_transfer(pipe, write, bytes + offset, requested, deadline,
                             transferred, error)) {
      return false;
    }
    if (transferred == 0) {
      error = write ? ERROR_WRITE_FAULT : ERROR_HANDLE_EOF;
      return false;
    }
    offset += transferred;
  }
  return true;
}

struct PipeResult {
  std::vector<std::uint8_t> response;
  std::uint32_t error{};
};

PipeResult transact_pipe_bounded(const std::wstring& pipe_name,
                                 const std::vector<std::uint8_t>& request,
                                 std::uint32_t timeout_ms) noexcept {
  PipeResult result{};
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeout_ms);
  if (WaitNamedPipeW(pipe_name.c_str(), timeout_ms) == FALSE) {
    result.error = GetLastError();
    return result;
  }
  OwnedHandle pipe(CreateFileW(
      pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr));
  if (pipe.get() == INVALID_HANDLE_VALUE) {
    result.error = GetLastError();
    return result;
  }
  auto mutable_request = request;
  if (!transfer_exact(pipe.get(), true, mutable_request.data(),
                      mutable_request.size(), deadline, result.error)) {
    return result;
  }
  std::array<std::uint8_t, 4> prefix{};
  if (!transfer_exact(pipe.get(), false, prefix.data(), prefix.size(), deadline,
                      result.error)) {
    return result;
  }
  const auto response_length = static_cast<std::uint32_t>(prefix[0]) |
                               (static_cast<std::uint32_t>(prefix[1]) << 8U) |
                               (static_cast<std::uint32_t>(prefix[2]) << 16U) |
                               (static_cast<std::uint32_t>(prefix[3]) << 24U);
  if (response_length < prefix.size() || response_length > kMaximumPipeFrame) {
    result.error = ERROR_INVALID_DATA;
    return result;
  }
  result.response.resize(response_length);
  std::memcpy(result.response.data(), prefix.data(), prefix.size());
  if (!transfer_exact(pipe.get(), false,
                      result.response.data() + prefix.size(),
                      result.response.size() - prefix.size(), deadline,
                      result.error)) {
    result.response.clear();
  }
  return result;
}

PyObject* open_mapping(PyObject*, PyObject* args) {
  PyObject* name_object = nullptr;
  PyObject* run_id_object = nullptr;
  PyObject* consumer_id_object = nullptr;
  unsigned long long producer_epoch = 0;
  if (!PyArg_ParseTuple(args, "UOOK:open_mapping", &name_object,
                        &run_id_object, &consumer_id_object, &producer_epoch)) {
    return nullptr;
  }

  Py_ssize_t name_length = 0;
  wchar_t* name_chars = PyUnicode_AsWideCharString(name_object, &name_length);
  if (name_chars == nullptr) {
    return nullptr;
  }
  const std::wstring mapping_name(name_chars,
                                  static_cast<std::size_t>(name_length));
  PyMem_Free(name_chars);

  Id16 run_id{};
  Id16 consumer_id{};
  if (!parse_id16(run_id_object, "run_id", run_id) ||
      !parse_id16(consumer_id_object, "consumer_id", consumer_id)) {
    return nullptr;
  }

  forge::workers::ring::v1::LiveError error{};
  auto consumer = Consumer::open(mapping_name, run_id, consumer_id,
                                 static_cast<std::uint64_t>(producer_epoch),
                                 error);
  if (!consumer) {
    PyErr_Format(PyExc_RuntimeError, "analysis mapping open failed: %s",
                 live_error_name(error));
    return nullptr;
  }
  auto holder = std::make_unique<ConsumerHolder>();
  holder->consumer = std::move(consumer);
  PyObject* capsule =
      PyCapsule_New(holder.get(), kCapsuleName, destroy_consumer);
  if (capsule == nullptr) {
    return nullptr;
  }
  static_cast<void>(holder.release());
  return capsule;
}

PyObject* transact_pipe(PyObject*, PyObject* args) {
  PyObject* name_object = nullptr;
  PyObject* request_object = nullptr;
  unsigned int timeout_ms = 0;
  if (!PyArg_ParseTuple(args, "UOI:transact_pipe", &name_object,
                        &request_object, &timeout_ms)) {
    return nullptr;
  }
  if (timeout_ms == 0 || timeout_ms > 60'000) {
    PyErr_SetString(PyExc_ValueError, "timeout_ms must be in 1..60000");
    return nullptr;
  }
  char* request_bytes = nullptr;
  Py_ssize_t request_length = 0;
  if (PyBytes_AsStringAndSize(request_object, &request_bytes, &request_length) !=
      0) {
    return nullptr;
  }
  if (request_length < 4 ||
      request_length > static_cast<Py_ssize_t>(kMaximumPipeFrame)) {
    PyErr_SetString(PyExc_ValueError, "request is not a bounded pipe frame");
    return nullptr;
  }
  const auto declared = static_cast<std::uint32_t>(
      static_cast<std::uint8_t>(request_bytes[0])) |
                        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(
                             request_bytes[1]))
                         << 8U) |
                        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(
                             request_bytes[2]))
                         << 16U) |
                        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(
                             request_bytes[3]))
                         << 24U);
  if (declared != static_cast<std::uint32_t>(request_length)) {
    PyErr_SetString(PyExc_ValueError, "request length prefix is inconsistent");
    return nullptr;
  }

  Py_ssize_t name_length = 0;
  wchar_t* name_chars = PyUnicode_AsWideCharString(name_object, &name_length);
  if (name_chars == nullptr) {
    return nullptr;
  }
  const std::wstring pipe_name(name_chars,
                               static_cast<std::size_t>(name_length));
  PyMem_Free(name_chars);
  if (!valid_pipe_name(pipe_name)) {
    PyErr_SetString(PyExc_ValueError, "invalid local analysis pipe name");
    return nullptr;
  }
  const std::vector<std::uint8_t> request(
      reinterpret_cast<const std::uint8_t*>(request_bytes),
      reinterpret_cast<const std::uint8_t*>(request_bytes) + request_length);
  PipeResult result{};
  Py_BEGIN_ALLOW_THREADS
  result = transact_pipe_bounded(pipe_name, request, timeout_ms);
  Py_END_ALLOW_THREADS
  if (result.error != 0) {
    PyErr_Format(PyExc_RuntimeError,
                 "analysis registration pipe transaction failed: win32=%lu",
                 static_cast<unsigned long>(result.error));
    return nullptr;
  }
  return PyBytes_FromStringAndSize(
      reinterpret_cast<const char*>(result.response.data()),
      static_cast<Py_ssize_t>(result.response.size()));
}

PyObject* try_consume(PyObject*, PyObject* args) {
  PyObject* capsule = nullptr;
  unsigned long long heartbeat = 0;
  if (!PyArg_ParseTuple(args, "OK:try_consume", &capsule, &heartbeat)) {
    return nullptr;
  }
  auto* holder = require_holder(capsule);
  if (holder == nullptr) {
    return nullptr;
  }
  auto result = holder->consumer->try_consume(
      static_cast<std::uint64_t>(heartbeat));
  if (!result) {
    PyErr_Format(PyExc_RuntimeError, "analysis mapping consume failed: %s",
                 live_error_name(result.error));
    return nullptr;
  }
  if (!result.record) {
    Py_RETURN_NONE;
  }
  PyObject* encoded = PyBytes_FromStringAndSize(
      reinterpret_cast<const char*>(result.record->encoded_record.data()),
      static_cast<Py_ssize_t>(result.record->encoded_record.size()));
  if (encoded == nullptr) {
    return nullptr;
  }
  PyObject* tuple = PyTuple_New(3);
  if (tuple == nullptr) {
    Py_DECREF(encoded);
    return nullptr;
  }
  PyObject* ring_sequence =
      PyLong_FromUnsignedLongLong(result.record->ring_sequence);
  PyObject* journal_sequence =
      PyLong_FromUnsignedLongLong(result.record->journal_sequence);
  if (ring_sequence == nullptr || journal_sequence == nullptr) {
    Py_XDECREF(ring_sequence);
    Py_XDECREF(journal_sequence);
    Py_DECREF(encoded);
    Py_DECREF(tuple);
    return nullptr;
  }
  PyTuple_SET_ITEM(tuple, 0, ring_sequence);
  PyTuple_SET_ITEM(tuple, 1, journal_sequence);
  PyTuple_SET_ITEM(tuple, 2, encoded);
  return tuple;
}

PyObject* dropped_records(PyObject*, PyObject* capsule) {
  auto* holder = require_holder(capsule);
  if (holder == nullptr) {
    return nullptr;
  }
  return PyLong_FromUnsignedLongLong(holder->consumer->dropped_records());
}

PyObject* fault_flags(PyObject*, PyObject* capsule) {
  auto* holder = require_holder(capsule);
  if (holder == nullptr) {
    return nullptr;
  }
  return PyLong_FromUnsignedLongLong(holder->consumer->fault_flags());
}

PyObject* close_mapping(PyObject*, PyObject* capsule) {
  auto* holder = static_cast<ConsumerHolder*>(
      PyCapsule_GetPointer(capsule, kCapsuleName));
  if (holder == nullptr) {
    return nullptr;
  }
  holder->consumer.reset();
  Py_RETURN_NONE;
}

PyMethodDef kMethods[] = {
    {"open_mapping", open_mapping, METH_VARARGS,
     "Open and validate a protected Forge analysis mapping."},
    {"transact_pipe", transact_pipe, METH_VARARGS,
     "Perform one bounded transaction on a protected local worker pipe."},
    {"try_consume", try_consume, METH_VARARGS,
     "Copy and consume at most one validated canonical record."},
    {"dropped_records", dropped_records, METH_O,
     "Return the producer-latched display/analysis drop counter."},
    {"fault_flags", fault_flags, METH_O,
     "Return the ring fault flags."},
    {"close_mapping", close_mapping, METH_O,
     "Close the mapping handle and invalidate this consumer."},
    {nullptr, nullptr, 0, nullptr},
};

PyModuleDef kModule = {
    PyModuleDef_HEAD_INIT,
    "_forge_analysis_native",
    "Native Windows Forge analysis-ring consumer.",
    -1,
    kMethods,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
};

}  // namespace

PyMODINIT_FUNC PyInit__forge_analysis_native() { return PyModule_Create(&kModule); }
