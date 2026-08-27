"""Exact 312-byte direct-Pod record-release companion; intentionally outside M0/DHL."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from hashlib import sha256
from struct import pack, unpack_from
from typing import Sequence

from forge_protocol_v1 import PROTOCOL_HASH, crc32c

LENGTH = 312
CONTRACT_HASH_HEX = "512d2fb554d4bc9bb2d56f46c3e25bd8d12548c93fa3eec62ae98800af067285"
CONTRACT_HASH = bytes.fromhex(CONTRACT_HASH_HEX)
HAS_RELEASED, HAS_RETAINED, HAS_COMMITTED, SEQUENCE_TERMINAL = 1, 2, 4, 8
_FLAGS = HAS_RELEASED | HAS_RETAINED | HAS_COMMITTED | SEQUENCE_TERMINAL
_REQUEST_MAGIC, _REPLY_MAGIC = b"FGRREL01", b"FGRRLR01"

class CodecError(ValueError): pass
class Status(IntEnum): APPLIED=1; DUPLICATE=2; STALE=3; FUTURE=4; WRONG_EPOCH=5; WRONG_HASH=6; REJECTED=7; ABORTED=8

def _hash(value: bytes) -> bytes:
    if len(value) != 32: raise CodecError("hash_length")
    return value
def _id(value: bytes) -> bytes:
    if len(value) != 16: raise CodecError("id_length")
    return value
def _nonzero(value: bytes) -> bool: return any(value)
def _u(value: int,bits: int) -> int:
    if not isinstance(value,int) or value<0 or value>=1<<bits: raise CodecError("integer_range")
    return value
def _range(first: int, last: int, count: int) -> None:
    _u(first,64); _u(last,64); _u(count,16)
    if not 1 <= count <= 2 or last < first or first + count - 1 != last: raise CodecError("range")
def _base(magic: bytes) -> bytearray:
    out=bytearray(LENGTH); out[:8]=magic; out[8:12]=pack("<HH",1,LENGTH); out[16:48]=CONTRACT_HASH; out[48:80]=PROTOCOL_HASH; return out
def _finish(out: bytearray) -> bytes: out[308:312]=pack("<I",crc32c(bytes(out[:308]))); return bytes(out)
def _framing(data: bytes, magic: bytes) -> None:
    if len(data)!=LENGTH or data[:8]!=magic or unpack_from("<HH",data,8)!=(1,LENGTH) or data[16:48]!=CONTRACT_HASH or data[48:80]!=PROTOCOL_HASH or unpack_from("<I",data,308)[0]!=crc32c(data[:308]): raise CodecError("framing")

def record_prefix_hash(first: int,last: int,count: int,canonical_records: Sequence[bytes]) -> bytes:
    _range(first,last,count)
    if len(canonical_records)!=count: raise CodecError("hash_list_length")
    return sha256(b"FORGE-DIRECT-POD-RECORD-RELEASE-PREFIX-V1\0"+pack("<QQH",first,last,count)+b"".join(sha256(record).digest() for record in canonical_records)).digest()

def store_state_hash(device_id: bytes,run_id: bytes,pod_id: bytes,headstage_id: bytes,current_epoch: int,state_flags: int,released_through_inclusive: int,oldest_retained_sequence: int,newest_committed_sequence_inclusive: int,store_depth: int,retained_records: Sequence[tuple[int,bytes]]) -> bytes:
    retained_count=len(retained_records); _u(retained_count,16)
    _validate_store_state(device_id,run_id,pod_id,headstage_id,current_epoch,state_flags,released_through_inclusive,oldest_retained_sequence,newest_committed_sequence_inclusive,store_depth,retained_count)
    for index,(sequence,record) in enumerate(retained_records):
        if _u(sequence,64) != oldest_retained_sequence+index: raise CodecError("retained_sequence")
        if not isinstance(record,bytes): raise CodecError("record_bytes")
    return sha256(b"FORGE-DIRECT-POD-RECORD-STORE-STATE-V1\0"+CONTRACT_HASH+PROTOCOL_HASH+_id(device_id)+_id(run_id)+_id(pod_id)+_id(headstage_id)+pack("<QHQQQHH",current_epoch,state_flags,released_through_inclusive,oldest_retained_sequence,newest_committed_sequence_inclusive,store_depth,retained_count)+b"".join(pack("<Q",sequence)+sha256(record).digest() for sequence,record in retained_records)).digest()

@dataclass(frozen=True)
class DirectPodRecordReleaseRequestV1:
    device_id: bytes; run_id: bytes; pod_id: bytes; headstage_id: bytes; transport_epoch: int; request_id: int
    first_record_sequence: int; last_record_sequence_inclusive: int; release_record_count: int; expected_store_depth: int
    durable_journal_sequence: int; durable_record_count: int; durable_checkpoint_generation: int; durable_prefix_hash: bytes; durable_checkpoint_hash: bytes; completion_evidence_hash: bytes
    def completion_hash(self) -> bytes:
        return sha256(b"FORGE-DIRECT-POD-RECORD-RELEASE-EVIDENCE-V1\0"+CONTRACT_HASH+PROTOCOL_HASH+_id(self.device_id)+_id(self.run_id)+_id(self.pod_id)+_id(self.headstage_id)+pack("<QQQQHHQQQ",self.transport_epoch,self.request_id,self.first_record_sequence,self.last_record_sequence_inclusive,self.release_record_count,self.expected_store_depth,self.durable_journal_sequence,self.durable_record_count,self.durable_checkpoint_generation)+_hash(self.durable_prefix_hash)+_hash(self.durable_checkpoint_hash)).digest()
    def request_hash(self) -> bytes: return sha256(self.encode()).digest()
    def validate(self) -> None:
        for value,bits in ((self.transport_epoch,64),(self.request_id,64),(self.first_record_sequence,64),(self.last_record_sequence_inclusive,64),(self.release_record_count,16),(self.expected_store_depth,16),(self.durable_journal_sequence,64),(self.durable_record_count,64),(self.durable_checkpoint_generation,64)): _u(value,bits)
        if not all(_nonzero(_id(value)) for value in (self.device_id,self.run_id,self.pod_id,self.headstage_id)) or self.transport_epoch<=0 or self.request_id<=0 or not 1<=self.expected_store_depth<=2 or self.release_record_count>self.expected_store_depth or self.durable_record_count<self.release_record_count or self.durable_checkpoint_generation<=0 or not _nonzero(_hash(self.durable_prefix_hash)) or not _nonzero(_hash(self.durable_checkpoint_hash)) or _hash(self.completion_evidence_hash)!=self.completion_hash(): raise CodecError("semantics")
        _range(self.first_record_sequence,self.last_record_sequence_inclusive,self.release_record_count)
    def encode(self) -> bytes:
        self.validate(); out=_base(_REQUEST_MAGIC); out[80:144]=_id(self.device_id)+_id(self.run_id)+_id(self.pod_id)+_id(self.headstage_id); out[144:180]=pack("<QQQQHH",self.transport_epoch,self.request_id,self.first_record_sequence,self.last_record_sequence_inclusive,self.release_record_count,self.expected_store_depth); out[184:208]=pack("<QQQ",self.durable_journal_sequence,self.durable_record_count,self.durable_checkpoint_generation); out[208:304]=_hash(self.durable_prefix_hash)+_hash(self.durable_checkpoint_hash)+_hash(self.completion_evidence_hash); return _finish(out)
    @classmethod
    def decode(cls,data: bytes) -> "DirectPodRecordReleaseRequestV1":
        _framing(data,_REQUEST_MAGIC)
        if unpack_from("<I",data,12)[0]!=0 or unpack_from("<I",data,180)[0]!=0 or unpack_from("<I",data,304)[0]!=0: raise CodecError("reserved")
        a=unpack_from("<QQQQHH",data,144); b=unpack_from("<QQQ",data,184); value=cls(data[80:96],data[96:112],data[112:128],data[128:144],*a,*b,data[208:240],data[240:272],data[272:304]); value.validate(); return value

@dataclass(frozen=True)
class DirectPodRecordReleaseReplyV1:
    status: Status; state_flags: int; device_id: bytes; run_id: bytes; pod_id: bytes; headstage_id: bytes; requested_epoch: int; current_epoch: int; request_id: int; request_hash: bytes; released_through_inclusive: int; oldest_retained_sequence: int; newest_committed_sequence_inclusive: int; store_depth: int; retained_count: int; store_state_hash: bytes; receipt_hash: bytes
    def computed_receipt_hash(self) -> bytes:
        return sha256(b"FORGE-DIRECT-POD-RECORD-RELEASE-RECEIPT-V1\0"+CONTRACT_HASH+PROTOCOL_HASH+_id(self.device_id)+_id(self.run_id)+_id(self.pod_id)+_id(self.headstage_id)+pack("<HHQQQ",int(self.status),self.state_flags,self.requested_epoch,self.current_epoch,self.request_id)+_hash(self.request_hash)+pack("<QQQHH",self.released_through_inclusive,self.oldest_retained_sequence,self.newest_committed_sequence_inclusive,self.store_depth,self.retained_count)+_hash(self.store_state_hash)).digest()
    def validate(self) -> None:
        released=self.state_flags&HAS_RELEASED!=0; retained=self.state_flags&HAS_RETAINED!=0; committed=self.state_flags&HAS_COMMITTED!=0; terminal=self.state_flags&SEQUENCE_TERMINAL!=0
        for value,bits in ((int(self.status),16),(self.state_flags,16),(self.requested_epoch,64),(self.current_epoch,64),(self.request_id,64),(self.released_through_inclusive,64),(self.oldest_retained_sequence,64),(self.newest_committed_sequence_inclusive,64),(self.store_depth,16),(self.retained_count,16)): _u(value,bits)
        try: Status(self.status)
        except ValueError as exc: raise CodecError("status") from exc
        if not _validate_store_state(self.device_id,self.run_id,self.pod_id,self.headstage_id,self.current_epoch,self.state_flags,self.released_through_inclusive,self.oldest_retained_sequence,self.newest_committed_sequence_inclusive,self.store_depth,self.retained_count) or self.requested_epoch<=0 or self.request_id<=0 or not _nonzero(_hash(self.request_hash)) or not _nonzero(_hash(self.store_state_hash)) or (self.status in (Status.APPLIED,Status.DUPLICATE) and not released) or _hash(self.receipt_hash)!=self.computed_receipt_hash(): raise CodecError("semantics")
    def encode(self) -> bytes:
        self.validate(); out=_base(_REPLY_MAGIC); out[12:16]=pack("<HH",int(self.status),self.state_flags); out[80:144]=_id(self.device_id)+_id(self.run_id)+_id(self.pod_id)+_id(self.headstage_id); out[144:168]=pack("<QQQ",self.requested_epoch,self.current_epoch,self.request_id); out[168:200]=_hash(self.request_hash); out[200:228]=pack("<QQQHH",self.released_through_inclusive,self.oldest_retained_sequence,self.newest_committed_sequence_inclusive,self.store_depth,self.retained_count); out[240:304]=_hash(self.store_state_hash)+_hash(self.receipt_hash); return _finish(out)
    @classmethod
    def decode(cls,data: bytes) -> "DirectPodRecordReleaseReplyV1":
        _framing(data,_REPLY_MAGIC)
        if any(data[228:240]) or unpack_from("<I",data,304)[0]: raise CodecError("reserved")
        try: status=Status(unpack_from("<H",data,12)[0])
        except ValueError as exc: raise CodecError("status") from exc
        a=unpack_from("<QQQ",data,144); b=unpack_from("<QQQHH",data,200); value=cls(status,unpack_from("<H",data,14)[0],data[80:96],data[96:112],data[112:128],data[128:144],*a,data[168:200],*b,data[240:272],data[272:304]); value.validate(); return value

def _validate_store_state(device_id: bytes,run_id: bytes,pod_id: bytes,headstage_id: bytes,current_epoch: int,state_flags: int,released_through: int,oldest_retained: int,newest_committed: int,store_depth: int,retained_count: int) -> bool:
    for value,bits in ((current_epoch,64),(state_flags,16),(released_through,64),(oldest_retained,64),(newest_committed,64),(store_depth,16),(retained_count,16)): _u(value,bits)
    released=state_flags&HAS_RELEASED!=0; retained=state_flags&HAS_RETAINED!=0; committed=state_flags&HAS_COMMITTED!=0; terminal=state_flags&SEQUENCE_TERMINAL!=0
    if not all(_nonzero(_id(value)) for value in (device_id,run_id,pod_id,headstage_id)) or current_epoch==0 or state_flags&~_FLAGS or not 1<=store_depth<=2 or retained_count>store_depth or retained != (retained_count>0) or terminal != (committed and newest_committed==2**64-1) or (not committed and (released or retained or terminal or released_through or oldest_retained or newest_committed or retained_count)) or (retained and (not committed or oldest_retained+retained_count-1>2**64-1 or newest_committed != oldest_retained+retained_count-1 or (released and released_through+1 != oldest_retained) or (not released and oldest_retained != 0))) or (not retained and oldest_retained != 0) or (committed and retained_count==0 and (not released or released_through != newest_committed)) or (released and (not committed or released_through>newest_committed)): raise CodecError("store_state")
    return True
