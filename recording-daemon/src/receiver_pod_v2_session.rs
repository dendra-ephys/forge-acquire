//! Host encoder and local sequencing owner for Receiver Pod V2 `RPS2` control.
//!
//! This is deliberately distinct from the historic Host-internal M0
//! `RunCommandV1` wire.  A V2 Pod consumes fixed 64-byte frames directly from
//! the FT600 OUT stream, so no M0 wrapper is placed on that physical wire.

use std::io;

use forge_protocol_v1::crc32c;

pub const RPS2_FRAME_LEN: usize = 64;
pub const RPS2_VERSION: u8 = 1;

/// The only Host-to-Pod operation required by the V2 session owner.
///
/// This keeps `RPS2` physically separate from the historical M0
/// `DirectPodByteTransport::write_control` method.  The Windows D3XX adapter
/// implements it for the FT600 OUT endpoint; tests can use a small in-memory
/// transport without pretending that a USB device was exercised.
pub trait Rps2FrameTransport {
    fn write_rps2_session_frame(&mut self, frame: &[u8]) -> io::Result<()>;
}

/// The production-side owner of one V2 Pod control session and its FT600 OUT
/// transport.  It is intentionally not an adapter for the historical M0
/// `DirectPodByteTransport`: a V2 run selects this owner at admission and can
/// only emit the exact fixed-size RPS2 frames accepted by the FPGA.
#[derive(Debug)]
pub struct Rps2SessionRuntime<T: Rps2FrameTransport> {
    transport: T,
    session: Option<Rps2SessionControl>,
    transport_failed: bool,
}

impl<T: Rps2FrameTransport> Rps2SessionRuntime<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            session: None,
            transport_failed: false,
        }
    }

    pub fn active(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(Rps2SessionControl::active)
    }

    pub fn transport_failed(&self) -> bool {
        self.transport_failed
    }

    pub fn establish(
        &mut self,
        session_id: u64,
        ticket: Rps2TicketV1,
    ) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        self.require_available()?;
        if self.session.is_some() {
            return Err(invalid_input("RPS2 runtime already owns a session"));
        }
        let mut session = Rps2SessionControl::new(session_id)?;
        match session.send_begin(&mut self.transport, ticket) {
            Ok(frame) => {
                self.session = Some(session);
                Ok(frame)
            }
            Err(error) => {
                self.transport_failed = true;
                Err(error)
            }
        }
    }

    pub fn start(&mut self) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        self.send(|session, transport| session.send_start(transport))
    }

    pub fn stop(&mut self) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        self.send(|session, transport| session.send_stop(transport))
    }

    pub fn abort(&mut self) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        self.send(|session, transport| session.send_abort(transport))
    }

    pub fn grant(&mut self, first: u64, last: u64) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        self.send(|session, transport| session.send_grant(transport, first, last))
    }

    pub fn end(&mut self) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        self.require_available()?;
        let Some(session) = self.session.as_mut() else {
            return Err(invalid_input("RPS2 runtime has no active session"));
        };
        match session.send_end(&mut self.transport) {
            Ok(frame) => {
                self.session = None;
                Ok(frame)
            }
            Err(error) => {
                self.transport_failed = true;
                Err(error)
            }
        }
    }

    pub fn into_transport(self) -> io::Result<T> {
        if self.session.is_some() || self.transport_failed {
            return Err(invalid_input(
                "RPS2 runtime may release its transport only after a successful END",
            ));
        }
        Ok(self.transport)
    }

    fn send(
        &mut self,
        operation: impl FnOnce(&mut Rps2SessionControl, &mut T) -> io::Result<[u8; RPS2_FRAME_LEN]>,
    ) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        self.require_available()?;
        let Some(session) = self.session.as_mut() else {
            return Err(invalid_input("RPS2 runtime has no active session"));
        };
        match operation(session, &mut self.transport) {
            Ok(frame) => Ok(frame),
            Err(error) => {
                self.transport_failed = true;
                Err(error)
            }
        }
    }

    fn require_available(&self) -> io::Result<()> {
        if self.transport_failed {
            Err(invalid_input(
                "RPS2 runtime is terminal after a transport write failure",
            ))
        } else {
            Ok(())
        }
    }
}

const OPCODE_BEGIN: u8 = 1;
const OPCODE_START: u8 = 2;
const OPCODE_STOP: u8 = 3;
const OPCODE_ABORT: u8 = 4;
const OPCODE_GRANT: u8 = 5;
const OPCODE_END: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rps2TicketV1 {
    pub ticket_sequence: u32,
    pub link_epoch: u64,
    pub descriptor_sequence: u64,
    pub inventory_sequence: u64,
    pub config_epoch: u32,
    pub profile_id: u8,
}

impl Rps2TicketV1 {
    fn validate(self) -> io::Result<Self> {
        if self.ticket_sequence == 0 || self.config_epoch == 0 || self.profile_id == 0 {
            return Err(invalid_input("RPS2 BEGIN ticket has a required zero field"));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rps2Opcode {
    Begin,
    Start,
    Stop,
    Abort,
    Grant { first: u64, last: u64 },
    End,
}

impl Rps2Opcode {
    fn wire(self) -> u8 {
        match self {
            Self::Begin => OPCODE_BEGIN,
            Self::Start => OPCODE_START,
            Self::Stop => OPCODE_STOP,
            Self::Abort => OPCODE_ABORT,
            Self::Grant { .. } => OPCODE_GRANT,
            Self::End => OPCODE_END,
        }
    }
}

/// One local, exclusive Host-side owner.  A transport failure invalidates its
/// connection epoch, so advancing the local sequence while preparing a frame
/// cannot make a retry ambiguous: retry requires a new admitted connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rps2SessionControl {
    session_id: u64,
    next_sequence: u32,
    active: bool,
    transport_failed: bool,
}

impl Rps2SessionControl {
    pub fn new(session_id: u64) -> io::Result<Self> {
        if session_id == 0 {
            return Err(invalid_input("RPS2 session ID must be nonzero"));
        }
        Ok(Self {
            session_id,
            next_sequence: 1,
            active: false,
            transport_failed: false,
        })
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn active(&self) -> bool {
        self.active
    }

    pub fn transport_failed(&self) -> bool {
        self.transport_failed
    }

    pub fn begin(&mut self, ticket: Rps2TicketV1) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        if self.active {
            return Err(invalid_input("RPS2 BEGIN cannot replace an active session"));
        }
        let ticket = ticket.validate()?;
        let frame = self.encode(Rps2Opcode::Begin, Some(ticket))?;
        self.active = true;
        Ok(frame)
    }

    pub fn start(&mut self) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        self.encode_active(Rps2Opcode::Start)
    }

    pub fn stop(&mut self) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        self.encode_active(Rps2Opcode::Stop)
    }

    pub fn abort(&mut self) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        self.encode_active(Rps2Opcode::Abort)
    }

    pub fn grant(&mut self, first: u64, last: u64) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        if first >= last {
            return Err(invalid_input("RPS2 GRANT requires first < last"));
        }
        self.encode_active(Rps2Opcode::Grant { first, last })
    }

    pub fn end(&mut self) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        let frame = self.encode_active(Rps2Opcode::End)?;
        self.active = false;
        Ok(frame)
    }

    /// Encode and write `BEGIN` as one typed operation.
    ///
    /// If the driver reports a write failure, the owner is terminal because
    /// the Host cannot know whether the Pod observed that sequence number.
    /// The caller must reconnect and establish a new session ID instead of
    /// retrying an ambiguous command.
    pub fn send_begin<T: Rps2FrameTransport>(
        &mut self,
        transport: &mut T,
        ticket: Rps2TicketV1,
    ) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        let frame = self.begin(ticket)?;
        self.write_frame(transport, frame)
    }

    pub fn send_start<T: Rps2FrameTransport>(
        &mut self,
        transport: &mut T,
    ) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        let frame = self.start()?;
        self.write_frame(transport, frame)
    }

    pub fn send_stop<T: Rps2FrameTransport>(
        &mut self,
        transport: &mut T,
    ) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        let frame = self.stop()?;
        self.write_frame(transport, frame)
    }

    pub fn send_abort<T: Rps2FrameTransport>(
        &mut self,
        transport: &mut T,
    ) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        let frame = self.abort()?;
        self.write_frame(transport, frame)
    }

    pub fn send_grant<T: Rps2FrameTransport>(
        &mut self,
        transport: &mut T,
        first: u64,
        last: u64,
    ) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        let frame = self.grant(first, last)?;
        self.write_frame(transport, frame)
    }

    pub fn send_end<T: Rps2FrameTransport>(
        &mut self,
        transport: &mut T,
    ) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        let frame = self.end()?;
        self.write_frame(transport, frame)
    }

    fn encode_active(&mut self, opcode: Rps2Opcode) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        if !self.active {
            return Err(invalid_input("RPS2 command requires an active session"));
        }
        self.encode(opcode, None)
    }

    fn write_frame<T: Rps2FrameTransport>(
        &mut self,
        transport: &mut T,
        frame: [u8; RPS2_FRAME_LEN],
    ) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        if let Err(error) = transport.write_rps2_session_frame(&frame) {
            self.transport_failed = true;
            return Err(error);
        }
        Ok(frame)
    }

    fn encode(
        &mut self,
        opcode: Rps2Opcode,
        ticket: Option<Rps2TicketV1>,
    ) -> io::Result<[u8; RPS2_FRAME_LEN]> {
        if self.transport_failed {
            return Err(invalid_input(
                "RPS2 session is terminal after a transport write failure",
            ));
        }
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| invalid_input("RPS2 command sequence overflow"))?;
        let mut frame = [0_u8; RPS2_FRAME_LEN];
        frame[0..4].copy_from_slice(b"RPS2");
        frame[4] = RPS2_VERSION;
        frame[5] = opcode.wire();
        frame[8..16].copy_from_slice(&self.session_id.to_le_bytes());
        frame[16..20].copy_from_slice(&sequence.to_le_bytes());
        match opcode {
            Rps2Opcode::Begin => {
                let ticket = ticket.ok_or_else(|| invalid_input("RPS2 BEGIN lacks a ticket"))?;
                frame[20..24].copy_from_slice(&ticket.ticket_sequence.to_le_bytes());
                frame[24..32].copy_from_slice(&ticket.link_epoch.to_le_bytes());
                frame[32..40].copy_from_slice(&ticket.descriptor_sequence.to_le_bytes());
                frame[40..48].copy_from_slice(&ticket.inventory_sequence.to_le_bytes());
                frame[48..52].copy_from_slice(&ticket.config_epoch.to_le_bytes());
                frame[52] = ticket.profile_id;
            }
            Rps2Opcode::Grant { first, last } => {
                frame[20..28].copy_from_slice(&first.to_le_bytes());
                frame[28..36].copy_from_slice(&last.to_le_bytes());
            }
            Rps2Opcode::Start | Rps2Opcode::Stop | Rps2Opcode::Abort | Rps2Opcode::End => {}
        }
        let frame_crc32c = crc32c(&frame[..60]);
        frame[60..64].copy_from_slice(&frame_crc32c.to_le_bytes());
        validate_rps2_frame(&frame)?;
        Ok(frame)
    }
}

/// Validates the exact physical FT600 payload consumed by the V2 FPGA.
pub fn validate_rps2_frame(frame: &[u8]) -> io::Result<()> {
    if frame.len() != RPS2_FRAME_LEN
        || frame[0..4] != *b"RPS2"
        || frame[4] != RPS2_VERSION
        || frame[6] != 0
        || frame[7] != 0
    {
        return Err(invalid_data("RPS2 frame header is invalid"));
    }
    let opcode = frame[5];
    if !(OPCODE_BEGIN..=OPCODE_END).contains(&opcode)
        || le_u64(frame, 8) == 0
        || le_u32(frame, 16) == 0
        || le_u32(frame, 60) != crc32c(&frame[..60])
    {
        return Err(invalid_data(
            "RPS2 frame identity, opcode or CRC is invalid",
        ));
    }
    match opcode {
        OPCODE_BEGIN => {
            if le_u32(frame, 20) == 0
                || le_u32(frame, 48) == 0
                || frame[52] == 0
                || frame[53..60].iter().any(|byte| *byte != 0)
            {
                return Err(invalid_data("RPS2 BEGIN payload is invalid"));
            }
        }
        OPCODE_GRANT => {
            if le_u64(frame, 20) >= le_u64(frame, 28) || frame[36..60].iter().any(|byte| *byte != 0)
            {
                return Err(invalid_data("RPS2 GRANT payload is invalid"));
            }
        }
        _ if frame[20..60].iter().any(|byte| *byte != 0) => {
            return Err(invalid_data("RPS2 simple-command payload is invalid"));
        }
        _ => {}
    }
    Ok(())
}

fn le_u32(frame: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        frame[offset..offset + 4]
            .try_into()
            .expect("fixed RPS2 bounds"),
    )
}

fn le_u64(frame: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        frame[offset..offset + 8]
            .try_into()
            .expect("fixed RPS2 bounds"),
    )
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryTransport {
        frames: Vec<[u8; RPS2_FRAME_LEN]>,
        fail_next: bool,
    }

    impl Rps2FrameTransport for MemoryTransport {
        fn write_rps2_session_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            validate_rps2_frame(frame)?;
            if self.fail_next {
                self.fail_next = false;
                return Err(io::Error::other("injected write failure"));
            }
            self.frames
                .push(frame.try_into().expect("exact RPS2 frame"));
            Ok(())
        }
    }

    fn ticket() -> Rps2TicketV1 {
        Rps2TicketV1 {
            ticket_sequence: 7,
            link_epoch: 0x1100,
            descriptor_sequence: 0x2200,
            inventory_sequence: 0x3300,
            config_epoch: 9,
            profile_id: 0x21,
        }
    }

    #[test]
    fn session_frames_match_the_fpga_fixed_layout_and_monotonic_contract() {
        let mut session = Rps2SessionControl::new(0xA55A).unwrap();
        let begin = session.begin(ticket()).unwrap();
        assert_eq!(&begin[0..4], b"RPS2");
        assert_eq!(begin[5], OPCODE_BEGIN);
        assert_eq!(le_u64(&begin, 8), 0xA55A);
        assert_eq!(le_u32(&begin, 16), 1);
        assert_eq!(le_u32(&begin, 20), 7);
        assert_eq!(le_u64(&begin, 24), 0x1100);
        validate_rps2_frame(&begin).unwrap();

        let start = session.start().unwrap();
        let grant = session.grant(100, 123).unwrap();
        let end = session.end().unwrap();
        assert_eq!(le_u32(&start, 16), 2);
        assert_eq!(le_u32(&grant, 16), 3);
        assert_eq!(le_u64(&grant, 20), 100);
        assert_eq!(le_u64(&grant, 28), 123);
        assert_eq!(le_u32(&end, 16), 4);
        assert_eq!(end[5], OPCODE_END);
        assert!(!session.active());
        assert!(session.start().is_err());
    }

    #[test]
    fn malformed_or_unsequenced_payloads_are_rejected_before_d3xx() {
        let mut session = Rps2SessionControl::new(1).unwrap();
        assert!(session.start().is_err());
        assert!(session
            .begin(Rps2TicketV1 {
                profile_id: 0,
                ..ticket()
            })
            .is_err());
        let mut begin = session.begin(ticket()).unwrap();
        begin[52] = 0;
        assert!(validate_rps2_frame(&begin).is_err());
        let mut crc_bad = session.stop().unwrap();
        crc_bad[23] = 1;
        assert!(validate_rps2_frame(&crc_bad).is_err());
        assert!(session.grant(9, 9).is_err());
    }

    #[test]
    fn typed_transport_writes_only_rps2_frames_and_failure_requires_new_session() {
        let mut transport = MemoryTransport::default();
        let mut session = Rps2SessionControl::new(0x55).unwrap();
        session.send_begin(&mut transport, ticket()).unwrap();
        session.send_start(&mut transport).unwrap();
        session.send_grant(&mut transport, 8, 16).unwrap();
        session.send_end(&mut transport).unwrap();
        assert_eq!(transport.frames.len(), 4);
        assert_eq!(transport.frames[0][5], OPCODE_BEGIN);
        assert_eq!(transport.frames[3][5], OPCODE_END);
        assert!(!session.transport_failed());

        let mut failed_transport = MemoryTransport {
            fail_next: true,
            ..Default::default()
        };
        let mut failed_session = Rps2SessionControl::new(0x66).unwrap();
        assert!(failed_session
            .send_begin(&mut failed_transport, ticket())
            .is_err());
        assert!(failed_session.transport_failed());
        assert!(failed_session.start().is_err());
    }

    #[test]
    fn runtime_selects_rps2_at_admission_and_releases_transport_only_after_end() {
        let mut runtime = Rps2SessionRuntime::new(MemoryTransport::default());
        runtime.establish(0x77, ticket()).unwrap();
        runtime.start().unwrap();
        runtime.grant(40, 80).unwrap();
        runtime.stop().unwrap();
        assert!(runtime.active());
        assert!(runtime.into_transport().is_err());

        let mut runtime = Rps2SessionRuntime::new(MemoryTransport::default());
        runtime.establish(0x88, ticket()).unwrap();
        runtime.abort().unwrap();
        runtime.end().unwrap();
        let transport = runtime.into_transport().unwrap();
        assert_eq!(transport.frames.len(), 3);
        assert_eq!(transport.frames[0][5], OPCODE_BEGIN);
        assert_eq!(transport.frames[1][5], OPCODE_ABORT);
        assert_eq!(transport.frames[2][5], OPCODE_END);

        let mut failed = Rps2SessionRuntime::new(MemoryTransport {
            fail_next: true,
            ..Default::default()
        });
        assert!(failed.establish(0x99, ticket()).is_err());
        assert!(failed.transport_failed());
        assert!(failed.establish(0x9A, ticket()).is_err());
    }
}
