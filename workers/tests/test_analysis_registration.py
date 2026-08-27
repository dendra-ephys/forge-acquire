from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import struct
import sys
import threading
import unittest
import uuid

from forge_workers.analysis_registration import (
    AnalysisWorkerRegisterRequestV1,
    AnalysisWorkerRegisterResponseV1,
    CONTRACT_HASH_HEX,
    RegistrationCodecError,
    register_observer,
)
from forge_workers.shared_ring import parse_ring_snapshot
from forge_protocol_v1 import crc32c


def _accepted_response(
    request: AnalysisWorkerRegisterRequestV1,
    encoded_request: bytes,
    mapping_name: str,
    slot_stride: int,
    total_mapping_bytes: int,
) -> bytes:
    output = bytearray(384)
    struct.pack_into("<I8sHHHH", output, 0, 384, b"FGANRS01", 1, 384, 1, 0)
    struct.pack_into("<QQ", output, 20, request.request_id, request.producer_epoch)
    output[36:52] = request.run_id
    output[52:68] = request.consumer_id
    name = mapping_name.encode("ascii")
    struct.pack_into("<H", output, 68, len(name))
    output[72 : 72 + len(name)] = name
    struct.pack_into(
        "<IIQQ",
        output,
        200,
        request.slot_count,
        request.payload_capacity,
        slot_stride,
        total_mapping_bytes,
    )
    from forge_protocol_v1 import PROTOCOL_HASH
    from forge_workers.shared_ring import SCHEMA_HASH

    output[224:256] = PROTOCOL_HASH
    output[256:288] = SCHEMA_HASH
    output[288:320] = hashlib.sha256(encoded_request).digest()
    output[320:352] = request.worker_build_hash
    struct.pack_into("<I", output, 352, 3)
    struct.pack_into("<I", output, 380, crc32c(output[:380]))
    return bytes(output)


class AnalysisRegistrationCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = os.environ.get("FORGE_ANALYSIS_RING_FIXTURE")
        if not fixture:
            raise RuntimeError("FORGE_ANALYSIS_RING_FIXTURE is required")
        cls.ring_bytes = Path(fixture).read_bytes()
        cls.snapshot = parse_ring_snapshot(cls.ring_bytes)

    def request(self) -> AnalysisWorkerRegisterRequestV1:
        return AnalysisWorkerRegisterRequestV1(
            request_id=17,
            producer_epoch=self.snapshot.producer_epoch,
            run_id=self.snapshot.run_id,
            consumer_id=self.snapshot.consumer_id,
            worker_build_hash=bytes([0x73]) * 32,
            slot_count=self.snapshot.slot_count,
            payload_capacity=self.snapshot.payload_capacity,
        )

    def test_contract_hash_and_request_round_trip(self) -> None:
        contract = (
            Path(__file__).parents[1]
            / "schema"
            / "forge_analysis_worker_ipc_v1.idl"
        ).read_text(encoding="utf-8")
        canonical = contract.replace("\r\n", "\n").replace("\r", "\n")
        self.assertEqual(hashlib.sha256(canonical.encode()).hexdigest(), CONTRACT_HASH_HEX)
        request = self.request()
        self.assertEqual(
            AnalysisWorkerRegisterRequestV1.decode(request.encode()), request
        )

    def test_request_mutation_and_crc_valid_reserved_data_fail_closed(self) -> None:
        encoded = bytearray(self.request().encode())
        for offset in (0, 4, 20, 68, 108, 140, 252):
            mutated = bytearray(encoded)
            mutated[offset] ^= 1
            with self.assertRaises(RegistrationCodecError):
                AnalysisWorkerRegisterRequestV1.decode(bytes(mutated))
        encoded[180] = 1
        struct.pack_into("<I", encoded, 252, crc32c(encoded[:252]))
        with self.assertRaises(RegistrationCodecError):
            AnalysisWorkerRegisterRequestV1.decode(bytes(encoded))

    @unittest.skipUnless(sys.platform == "win32", "Windows protected pipe contract")
    def test_native_pipe_registration_binds_response_and_consumes_mapping(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_mapping = kernel32.CreateFileMappingW
        create_mapping.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPCWSTR,
        ]
        create_mapping.restype = wintypes.HANDLE
        map_view = kernel32.MapViewOfFile
        map_view.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_size_t,
        ]
        map_view.restype = ctypes.c_void_p
        create_pipe = kernel32.CreateNamedPipeW
        create_pipe.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        create_pipe.restype = wintypes.HANDLE
        connect_pipe = kernel32.ConnectNamedPipe
        connect_pipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        connect_pipe.restype = wintypes.BOOL
        read_file = kernel32.ReadFile
        read_file.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        read_file.restype = wintypes.BOOL
        write_file = kernel32.WriteFile
        write_file.argtypes = read_file.argtypes
        write_file.restype = wintypes.BOOL
        flush_pipe = kernel32.FlushFileBuffers
        flush_pipe.argtypes = [wintypes.HANDLE]
        flush_pipe.restype = wintypes.BOOL
        disconnect_pipe = kernel32.DisconnectNamedPipe
        disconnect_pipe.argtypes = [wintypes.HANDLE]
        disconnect_pipe.restype = wintypes.BOOL
        unmap_view = kernel32.UnmapViewOfFile
        unmap_view.argtypes = [ctypes.c_void_p]
        unmap_view.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        suffix = f"{os.getpid()}-{uuid.uuid4().hex}"
        mapping_name = f"Local\\ForgeAnalysisRing-PythonRegister-{suffix}"
        pipe_name = f"\\\\.\\pipe\\forge-analysis-register-python-{suffix}"
        invalid_handle = ctypes.c_void_p(-1).value
        mapping = create_mapping(
            invalid_handle, None, 0x04, 0, len(self.ring_bytes), mapping_name
        )
        self.assertTrue(mapping, ctypes.get_last_error())
        view = map_view(mapping, 0x000F001F, 0, 0, len(self.ring_bytes))
        self.assertTrue(view, ctypes.get_last_error())
        ctypes.memmove(view, self.ring_bytes, len(self.ring_bytes))
        pipe = create_pipe(pipe_name, 0x00000003, 0, 1, 4096, 4096, 5_000, None)
        self.assertNotEqual(pipe, invalid_handle, ctypes.get_last_error())

        request = self.request()
        encoded_request = request.encode()
        encoded_response = _accepted_response(
            request,
            encoded_request,
            mapping_name,
            self.snapshot.slot_stride,
            len(self.ring_bytes),
        )
        errors: list[BaseException] = []

        def serve_once() -> None:
            try:
                if not connect_pipe(pipe, None) and ctypes.get_last_error() != 535:
                    raise OSError(ctypes.get_last_error(), "ConnectNamedPipeW")
                request_buffer = ctypes.create_string_buffer(len(encoded_request))
                received = wintypes.DWORD()
                if not read_file(
                    pipe,
                    request_buffer,
                    len(encoded_request),
                    ctypes.byref(received),
                    None,
                ):
                    raise OSError(ctypes.get_last_error(), "ReadFile")
                if request_buffer.raw[: received.value] != encoded_request:
                    raise AssertionError("worker request bytes changed in transit")
                response_buffer = ctypes.create_string_buffer(encoded_response)
                written = wintypes.DWORD()
                if not write_file(
                    pipe,
                    response_buffer,
                    len(encoded_response),
                    ctypes.byref(written),
                    None,
                ) or written.value != len(encoded_response):
                    raise OSError(ctypes.get_last_error(), "WriteFile")
                flush_pipe(pipe)
                disconnect_pipe(pipe)
            except BaseException as error:
                errors.append(error)

        server = threading.Thread(target=serve_once, daemon=True)
        server.start()
        try:
            observer = register_observer(pipe_name, request, timeout_ms=5_000)
            try:
                self.assertEqual(observer.response.mapping_name, mapping_name)
                first = observer.consumer.try_consume(201)
                second = observer.consumer.try_consume(202)
                self.assertEqual(first.journal_sequence, 41)
                self.assertEqual(second.journal_sequence, 42)
                self.assertIsNone(observer.consumer.try_consume(203))
            finally:
                observer.close()
            server.join(5)
            self.assertFalse(server.is_alive())
            if errors:
                raise errors[0]
        finally:
            close_handle(pipe)
            unmap_view(view)
            close_handle(mapping)


if __name__ == "__main__":
    unittest.main()
