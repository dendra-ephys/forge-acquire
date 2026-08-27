import hashlib
import pathlib
import unittest
from dataclasses import replace

from forge_protocol_v1 import PROTOCOL_HASH
from forge_direct_pod_record_release_v1 import (
    CONTRACT_HASH, LENGTH, HAS_COMMITTED, HAS_RELEASED, HAS_RETAINED, SEQUENCE_TERMINAL,
    CodecError, DirectPodRecordReleaseReplyV1, DirectPodRecordReleaseRequestV1, Status,
    record_prefix_hash, store_state_hash,
)

ROOT=pathlib.Path(__file__).resolve().parents[2]
SCHEMA=ROOT.parent / "recording-daemon" / "schema" / "forge_direct_pod_record_release_v1.idl"
GOLDEN=ROOT / "golden"
def request():
    value=DirectPodRecordReleaseRequestV1(bytes([1])*16,bytes([2])*16,bytes([3])*16,bytes([4])*16,7,9,11,12,2,2,13,14,15,bytes([5])*32,bytes([6])*32,bytes(32))
    return replace(value, completion_evidence_hash=value.completion_hash())
def reply():
    wire=request().encode(); flags=HAS_RELEASED|HAS_RETAINED|HAS_COMMITTED; state=store_state_hash(bytes([1])*16,bytes([2])*16,bytes([3])*16,bytes([4])*16,7,flags,12,13,14,2,[(13,b"retained-13"),(14,b"retained-14")]); value=DirectPodRecordReleaseReplyV1(Status.APPLIED,flags,bytes([1])*16,bytes([2])*16,bytes([3])*16,bytes([4])*16,7,7,9,hashlib.sha256(wire).digest(),12,13,14,2,2,state,bytes(32))
    return replace(value, receipt_hash=value.computed_receipt_hash())
def crc(data):
    from forge_protocol_v1 import crc32c
    data=bytearray(data); data[308:]=crc32c(data[:308]).to_bytes(4,"little"); return bytes(data)

class RecordReleaseTests(unittest.TestCase):
    def test_schema_and_goldens(self):
        self.assertEqual(hashlib.sha256(SCHEMA.read_bytes().replace(b"\r\n",b"\n").replace(b"\r",b"\n")).digest(),CONTRACT_HASH)
        for name,value,decoder in (("direct_pod_record_release_request_v1.hex",request(),DirectPodRecordReleaseRequestV1.decode),("direct_pod_record_release_reply_v1.hex",reply(),DirectPodRecordReleaseReplyV1.decode)):
            wire=value.encode(); self.assertEqual(wire,bytes.fromhex((GOLDEN/name).read_text().strip())); self.assertEqual(decoder(wire),value)
    def test_all_truncations_and_bit_mutations(self):
        for wire,decoder in ((request().encode(),DirectPodRecordReleaseRequestV1.decode),(reply().encode(),DirectPodRecordReleaseReplyV1.decode)):
            for size in range(LENGTH):
                with self.assertRaises(CodecError): decoder(wire[:size])
            for offset in range(LENGTH):
                changed=bytearray(wire); changed[offset]^=1
                with self.assertRaises(CodecError): decoder(bytes(changed))
    def test_crc_valid_semantic_negatives(self):
        wire=request().encode()
        for offset,size in ((16,32),(48,32),(80,16),(208,32),(240,32),(272,32)):
            changed=bytearray(wire); changed[offset:offset+size]=bytes(size)
            with self.assertRaises(CodecError): DirectPodRecordReleaseRequestV1.decode(crc(changed))
        for offset,value in ((176,0),(178,3),(200,0)):
            changed=bytearray(wire); changed[offset:offset+2 if offset<180 else offset+8]=value.to_bytes(2 if offset<180 else 8,"little")
            with self.assertRaises(CodecError): DirectPodRecordReleaseRequestV1.decode(crc(changed))
        wire=reply().encode()
        for mutation in ((14,0x80),(228,1),(12,9)):
            changed=bytearray(wire); changed[mutation[0]] = mutation[1]
            with self.assertRaises(CodecError): DirectPodRecordReleaseReplyV1.decode(crc(changed))
        changed=bytearray(wire); changed[14]=HAS_RELEASED; changed[200:208]=(0).to_bytes(8,"little")
        with self.assertRaises(CodecError): DirectPodRecordReleaseReplyV1.decode(crc(changed))
    def test_recomputed_semantic_negative_matrix(self):
        base=request()
        for changes in (
            {"device_id":bytes(16)}, {"release_record_count":0}, {"expected_store_depth":3},
            {"release_record_count":2,"expected_store_depth":1}, {"last_record_sequence_inclusive":13},
            {"durable_record_count":1}, {"durable_checkpoint_generation":0}, {"durable_prefix_hash":bytes(32)},
            {"durable_checkpoint_hash":bytes(32)}, {"completion_evidence_hash":bytes(32)},
        ):
            value=replace(base,**changes)
            if "completion_evidence_hash" not in changes: value=replace(value,completion_evidence_hash=value.completion_hash())
            with self.assertRaises(CodecError): value.encode()
        self.assertRaises(CodecError,record_prefix_hash,11,12,2,[b"one"])
        base=reply()
        for changes in (
            {"state_flags":0,"released_through_inclusive":1}, {"state_flags":HAS_RELEASED},
            {"state_flags":HAS_RETAINED|HAS_COMMITTED,"retained_count":0},
            {"state_flags":HAS_COMMITTED|SEQUENCE_TERMINAL,"newest_committed_sequence_inclusive":1},
            {"status":Status.APPLIED,"state_flags":HAS_COMMITTED}, {"store_depth":0},
            {"retained_count":3}, {"request_hash":bytes(32)}, {"store_state_hash":bytes(32)},
            {"receipt_hash":bytes(32)},
        ):
            value=replace(base,**changes)
            if "receipt_hash" not in changes: value=replace(value,receipt_hash=value.computed_receipt_hash())
            with self.assertRaises(CodecError): value.encode()
    def test_max_singleton_prefix_and_request_crc_hash(self):
        value=request(); value=value.__class__(value.device_id,value.run_id,value.pod_id,value.headstage_id,value.transport_epoch,value.request_id,2**64-1,2**64-1,1,1,value.durable_journal_sequence,1,value.durable_checkpoint_generation,value.durable_prefix_hash,value.durable_checkpoint_hash,bytes(32)); value=replace(value,completion_evidence_hash=value.completion_hash())
        self.assertEqual(DirectPodRecordReleaseRequestV1.decode(value.encode()),value)
        self.assertEqual(record_prefix_hash(2**64-1,2**64-1,1,[b"canonical"]),record_prefix_hash(2**64-1,2**64-1,1,[b"canonical"]))
        self.assertEqual(request().request_hash(),hashlib.sha256(request().encode()).digest())
        self.assertNotEqual(reply().request_hash,hashlib.sha256(request().encode()[:-4]).digest())
    def test_store_state_golden_mutation_and_canonical_states(self):
        ids=(bytes([1])*16,bytes([2])*16,bytes([3])*16,bytes([4])*16)
        flags=HAS_RELEASED|HAS_RETAINED|HAS_COMMITTED
        state=store_state_hash(*ids,7,flags,12,13,14,2,[(13,b"retained-13"),(14,b"retained-14")])
        self.assertEqual(state,bytes.fromhex((GOLDEN/"direct_pod_record_store_state_v1.hex").read_text().strip()))
        self.assertNotEqual(state,store_state_hash(*ids,7,flags,12,13,14,2,[(13,b"retained-13!"),(14,b"retained-14")]))
        with self.assertRaises(CodecError): store_state_hash(*ids,7,flags,12,13,14,2,[(13,b"a"),(15,b"b")])
        def make(status,flags,released,oldest,newest,depth,records):
            state=store_state_hash(*ids,7,flags,released,oldest,newest,depth,records)
            value=DirectPodRecordReleaseReplyV1(status,flags,*ids,7,7,9,request().request_hash(),released,oldest,newest,depth,len(records),state,bytes(32))
            return replace(value,receipt_hash=value.computed_receipt_hash())
        states=(
            make(Status.APPLIED,HAS_RELEASED|HAS_COMMITTED,0,0,0,1,[]),
            make(Status.STALE,HAS_RETAINED|HAS_COMMITTED,0,0,0,1,[(0,b"one")]),
            make(Status.STALE,HAS_RETAINED|HAS_COMMITTED,0,0,1,2,[(0,b"one"),(1,b"two")]),
            make(Status.APPLIED,HAS_RELEASED|HAS_RETAINED|HAS_COMMITTED,0,1,2,2,[(1,b"one"),(2,b"two")]),
            make(Status.APPLIED,HAS_RELEASED|HAS_COMMITTED|SEQUENCE_TERMINAL,2**64-1,0,2**64-1,1,[]),
        )
        for value in states: self.assertEqual(DirectPodRecordReleaseReplyV1.decode(value.encode()),value)
    def test_state_holes_terminal_overflow_and_integer_bounds_reject(self):
        base=reply()
        for changes in (
            {"oldest_retained_sequence":14}, {"newest_committed_sequence_inclusive":15},
            {"released_through_inclusive":14}, {"newest_committed_sequence_inclusive":2**64-1},
            {"state_flags":base.state_flags|SEQUENCE_TERMINAL,"newest_committed_sequence_inclusive":14},
            {"oldest_retained_sequence":2**64-1,"newest_committed_sequence_inclusive":0},
        ):
            value=replace(base,**changes); value=replace(value,receipt_hash=value.computed_receipt_hash())
            with self.assertRaises(CodecError): value.encode()
        for value in (replace(request(),request_id=-1),replace(request(),request_id=2**64),replace(request(),release_record_count=-1),replace(reply(),store_depth=2**16)):
            with self.assertRaises(CodecError): value.encode()
        with self.assertRaises(CodecError): store_state_hash(bytes([1])*16,bytes([2])*16,bytes([3])*16,bytes([4])*16,-1,HAS_RELEASED|HAS_COMMITTED,0,0,0,1,[])

if __name__ == "__main__": unittest.main()
