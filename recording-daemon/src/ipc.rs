use serde::Serialize;

pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\forge-acqd-v2";
#[cfg(windows)]
pub const SOFTWARE_REPLAY_PIPE_PREFIX: &str = r"\\.\pipe\forge-acqd-software-replay-";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IpcBoundary {
    pub pipe_name: &'static str,
    pub available: bool,
    pub sid_acl_verified: bool,
    pub secure_pipe_primitives_available: bool,
    pub service_control_manager_verified: bool,
    pub reason: &'static str,
}

/// Returns an honest deployment capability snapshot. The primitives and SCM
/// host exist, but this process does not claim that the service is installed
/// or release-qualified on the current machine.
pub fn ipc_boundary() -> IpcBoundary {
    IpcBoundary {
        pipe_name: DEFAULT_PIPE_NAME,
        available: false,
        sid_acl_verified: false,
        secure_pipe_primitives_available: cfg!(windows),
        service_control_manager_verified: false,
        reason: "secure pipe and SCM host tests exist, but the Windows service is not installed or deployment-qualified on this machine",
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use forge_protocol_v1::MAX_LOW_SPEED_MESSAGE_LEN;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_CANNOT_IMPERSONATE,
        ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER,
        ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED,
        ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, FILETIME, HANDLE,
        INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        ConvertStringSidToSidW,
    };
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    use windows_sys::Win32::Security::{
        CheckTokenMembership, EqualSid, GetTokenInformation, LookupAccountNameW, RevertToSelf,
        TokenUser, SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        ImpersonateNamedPipeClient, WaitNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_WAIT,
    };
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, GetCurrentThread, GetProcessTimes, OpenProcess,
        OpenProcessToken, OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResultEx, OVERLAPPED};

    const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
    const CLIENT_PIPE_RIGHTS: u32 = FILE_READ_DATA | FILE_WRITE_DATA;
    const RETIRED_V1_PIPE_NAMES: [&str; 3] = [
        r"\\.\pipe\forge-acqd-v1",
        r"\\.\pipe\forge-acqd-hardware-v1",
        r"\\.\pipe\forge-acqd-analysis-v1",
    ];
    const SERVER_TRANSACTION_IO_TIMEOUT: Duration = Duration::from_secs(5);
    const OVERLAPPED_WAIT_SLICE_MS: u32 = 25;
    const CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
    // Private named-pipe transport v2 framing. The frozen low-speed IDL frame
    // and its contract hash are unchanged; v2 appends a per-transaction
    // challenge and challenge-bound consumption ACK outside that frame.
    const RESPONSE_ACK_MAGIC: [u8; 4] = *b"FACK";
    const RESPONSE_CHALLENGE_LEN: usize = 16;
    const RESPONSE_ACK_LEN: usize = RESPONSE_ACK_MAGIC.len() + RESPONSE_CHALLENGE_LEN;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum PendingIoStage {
        Connect,
        PrefixRead,
        BodyRead,
        ResponseWrite,
        AckRead,
        TerminalClientClose,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct PendingIoObservation {
        pub stage: PendingIoStage,
        pub client_process_id: Option<u32>,
    }

    /// Qualification-only fact emitted only after the server has verified the
    /// challenge-bound `FACK`.  It is deliberately crate-private and changes
    /// neither the frozen low-speed message nor v2 wire bytes.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct CompletedTransactionObservation {
        pub client: AuthenticatedPipeClient,
        pub request: Vec<u8>,
        pub response: Vec<u8>,
    }

    #[derive(Clone, Default)]
    struct PendingStageObserver {
        sender: Option<mpsc::Sender<PendingIoStage>>,
        detailed_sender: Option<mpsc::Sender<PendingIoObservation>>,
    }

    impl PendingStageObserver {
        fn publish(&self, stage: PendingIoStage) {
            if let Some(sender) = &self.sender {
                let _ = sender.send(stage);
            }
        }

        fn publish_for_client(&self, stage: PendingIoStage, client_process_id: Option<u32>) {
            if let Some(sender) = &self.sender {
                let _ = sender.send(stage);
            }
            if let Some(sender) = &self.detailed_sender {
                let _ = sender.send(PendingIoObservation {
                    stage,
                    client_process_id,
                });
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct SecurePipeOptions {
        pub pipe_name: String,
        pub service_sid: String,
        pub allowed_client_sid: String,
    }

    /// A single-instance, local-only server endpoint. Production construction
    /// requires an NT SERVICE SID that is actually enabled in the current
    /// process token. This prevents an interactive process from claiming the
    /// production pipe merely by supplying an SDDL string.
    pub struct SecurePipeServer {
        handle: OwnedHandle,
        allowed_client_sid: String,
        stop_requested: Arc<AtomicBool>,
        pipe_name: String,
        poisoned: bool,
        pending_observer: PendingStageObserver,
        completion_observer: Option<mpsc::Sender<CompletedTransactionObservation>>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AuthenticatedPipeClient {
        pub token_user_sid: String,
        pub process_id: u32,
        pub process_creation_time_100ns: u64,
    }

    #[derive(Clone)]
    pub struct SecurePipeStopHandle {
        stop_requested: Arc<AtomicBool>,
        pipe_name: String,
    }

    enum TransactionFailure {
        Stopped,
        ClientFault(io::Error),
        Fatal(io::Error),
        Poisoned(io::Error),
    }

    impl TransactionFailure {
        fn into_io_error(self) -> io::Error {
            match self {
                Self::Stopped => {
                    io::Error::new(io::ErrorKind::Interrupted, "named-pipe transaction stopped")
                }
                Self::ClientFault(error) | Self::Fatal(error) | Self::Poisoned(error) => error,
            }
        }
    }

    impl SecurePipeStopHandle {
        /// Sets the stop flag first, then best-effort connects to accelerate an
        /// idle overlapped accept. The listener also polls the flag while every
        /// pending server I/O is in flight.
        pub fn request_stop(&self) -> io::Result<()> {
            self.stop_requested.store(true, Ordering::Release);
            wake_pipe(&self.pipe_name)
        }
    }

    impl SecurePipeServer {
        pub fn bind_service(options: &SecurePipeOptions) -> io::Result<Self> {
            if !options.service_sid.starts_with("S-1-5-80-") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "production pipe requires an NT SERVICE SID",
                ));
            }
            bind(options, true)
        }

        /// Binds a deliberately non-SCM, current-user-only endpoint for the
        /// software/synthetic operator replay daemon.  Its namespace cannot
        /// overlap the production service pipes, and both the server token
        /// and every client TokenUser must equal the supplied interactive
        /// operator SID.
        pub fn bind_software_replay(pipe_name: &str, operator_sid: &str) -> io::Result<Self> {
            if !pipe_name.starts_with(super::SOFTWARE_REPLAY_PIPE_PREFIX)
                || pipe_name.len() == super::SOFTWARE_REPLAY_PIPE_PREFIX.len()
                || pipe_name[super::SOFTWARE_REPLAY_PIPE_PREFIX.len()..]
                    .chars()
                    .any(|value| !value.is_ascii_alphanumeric() && value != '-')
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "software replay pipe must use the dedicated forge-acqd-software-replay namespace",
                ));
            }
            let requested = canonical_sid_string(operator_sid)?;
            let current = current_process_user_sid()?;
            if requested != current {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "software replay operator SID does not match the current process user",
                ));
            }
            bind(
                &SecurePipeOptions {
                    pipe_name: pipe_name.to_owned(),
                    service_sid: current.clone(),
                    allowed_client_sid: current,
                },
                false,
            )
        }

        #[cfg(test)]
        pub(crate) fn bind_test(options: &SecurePipeOptions) -> io::Result<Self> {
            bind(options, false)
        }

        /// Binds the deliberately non-deployed endpoint used only by the
        /// GUI-kill qualification harness.  It has the same local-only,
        /// first-instance, explicit-DACL and bounded-v2 transport properties
        /// as the service endpoint, but does **not** assert an NT SERVICE SID
        /// or an installed SCM service.  Callers must report this as SCM
        /// emulation, never as deployment evidence.
        #[cfg(feature = "qualification-harness")]
        pub(crate) fn bind_scm_emulation(options: &SecurePipeOptions) -> io::Result<Self> {
            bind(options, false)
        }

        /// Crate-private qualification observer. It publishes a stage only
        /// after the corresponding operation truly returned ERROR_IO_PENDING;
        /// it neither changes transport behavior nor exposes endpoint state to
        /// pipe clients.
        #[cfg(test)]
        pub(crate) fn install_pending_stage_observer(&mut self) -> mpsc::Receiver<PendingIoStage> {
            let (sender, receiver) = mpsc::channel();
            self.pending_observer.sender = Some(sender);
            receiver
        }

        /// Qualification-only local observer. It reports a pending I/O stage
        /// and, for a genuinely pending authenticated ACK read, the Windows
        /// named-pipe client PID. It changes no client-visible wire bytes.
        #[cfg(feature = "qualification-harness")]
        pub(crate) fn install_pending_observation_observer(
            &mut self,
        ) -> mpsc::Receiver<PendingIoObservation> {
            let (sender, receiver) = mpsc::channel();
            self.pending_observer.detailed_sender = Some(sender);
            receiver
        }

        /// Installs a qualification-only completion observer. The receiver
        /// gets one record only after the exact response challenge was echoed
        /// correctly; client faults never publish an observation.
        #[cfg(any(test, feature = "qualification-harness"))]
        pub(crate) fn install_completion_observer(
            &mut self,
        ) -> mpsc::Receiver<CompletedTransactionObservation> {
            let (sender, receiver) = mpsc::channel();
            self.completion_observer = Some(sender);
            receiver
        }

        /// Accept exactly one request. The server reads only the four-byte
        /// bounded length prefix before impersonating and comparing the
        /// client's TokenUser SID. It always reverts before calling privileged
        /// application logic.
        pub fn stop_handle(&self) -> SecurePipeStopHandle {
            SecurePipeStopHandle {
                stop_requested: Arc::clone(&self.stop_requested),
                pipe_name: self.pipe_name.clone(),
            }
        }

        pub fn transact_once<F>(&mut self, handler: F) -> io::Result<bool>
        where
            F: FnOnce(&[u8]) -> io::Result<Vec<u8>>,
        {
            self.transact_once_authenticated(|_, request| handler(request))
        }

        pub fn transact_once_authenticated<F>(&mut self, handler: F) -> io::Result<bool>
        where
            F: FnOnce(&AuthenticatedPipeClient, &[u8]) -> io::Result<Vec<u8>>,
        {
            match self.transact_once_classified_authenticated(handler) {
                Ok(completed) => Ok(completed),
                Err(TransactionFailure::Stopped) => Ok(false),
                Err(failure) => Err(failure.into_io_error()),
            }
        }

        fn transact_once_classified_authenticated<F>(
            &mut self,
            handler: F,
        ) -> Result<bool, TransactionFailure>
        where
            F: FnOnce(&AuthenticatedPipeClient, &[u8]) -> io::Result<Vec<u8>>,
        {
            self.transact_once_classified_authenticated_with_terminal_close(None, handler)
        }

        fn transact_once_classified_authenticated_with_terminal_close<F>(
            &mut self,
            terminal_response: Option<&AtomicBool>,
            handler: F,
        ) -> Result<bool, TransactionFailure>
        where
            F: FnOnce(&AuthenticatedPipeClient, &[u8]) -> io::Result<Vec<u8>>,
        {
            if self.poisoned {
                return Err(TransactionFailure::Fatal(io::Error::other(
                    "named-pipe server is poisoned by an unconfirmed cancelled I/O",
                )));
            }
            let result =
                self.transact_once_classified_authenticated_inner(terminal_response, handler);
            if matches!(&result, Err(TransactionFailure::Poisoned(_))) {
                self.poisoned = true;
            }
            result
        }

        fn transact_once_classified_authenticated_inner<F>(
            &mut self,
            terminal_response: Option<&AtomicBool>,
            handler: F,
        ) -> Result<bool, TransactionFailure>
        where
            F: FnOnce(&AuthenticatedPipeClient, &[u8]) -> io::Result<Vec<u8>>,
        {
            connect_server_pipe(self.handle.0, &self.stop_requested, &self.pending_observer)?;
            let _connection = PipeConnection(self.handle.0);
            if self.stop_requested.load(Ordering::Acquire) {
                return Ok(false);
            }
            let request_io_deadline = Instant::now()
                .checked_add(SERVER_TRANSACTION_IO_TIMEOUT)
                .ok_or_else(|| {
                    TransactionFailure::Fatal(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "server request I/O deadline overflow",
                    ))
                })?;

            let mut prefix = [0_u8; 4];
            read_exact_server(
                self.handle.0,
                &mut prefix,
                request_io_deadline,
                &self.stop_requested,
                &self.pending_observer,
                PendingIoStage::PrefixRead,
                None,
            )?;
            let request_len = u32::from_le_bytes(prefix) as usize;
            if !(4..=MAX_LOW_SPEED_MESSAGE_LEN).contains(&request_len) {
                return Err(TransactionFailure::ClientFault(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPC request length is outside the frozen low-speed bound",
                )));
            }

            let token_user_sid =
                authenticate_client_classified(self.handle.0, &self.allowed_client_sid)?;
            let client = client_process_instance_classified(self.handle.0, token_user_sid)?;

            let mut request = vec![0_u8; request_len];
            request[..4].copy_from_slice(&prefix);
            read_exact_server(
                self.handle.0,
                &mut request[4..],
                request_io_deadline,
                &self.stop_requested,
                &self.pending_observer,
                PendingIoStage::BodyRead,
                None,
            )?;
            let response = handler(&client, &request).map_err(TransactionFailure::Fatal)?;
            // Dispatcher work owns its own command deadline (Stop-and-seal may
            // legitimately take longer than one pipe I/O window). Starting the
            // response/FACK budget after that work prevents a durable terminal
            // transition from consuming the entire transport deadline before
            // its authenticated response can be delivered.
            let response_io_deadline = Instant::now()
                .checked_add(SERVER_TRANSACTION_IO_TIMEOUT)
                .ok_or_else(|| {
                    TransactionFailure::Fatal(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "server response I/O deadline overflow",
                    ))
                })?;
            if !(4..=MAX_LOW_SPEED_MESSAGE_LEN).contains(&response.len())
                || u32::from_le_bytes(response[..4].try_into().map_err(|_| {
                    TransactionFailure::Fatal(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "IPC response has no length prefix",
                    ))
                })?) as usize
                    != response.len()
            {
                return Err(TransactionFailure::Fatal(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPC response is not a bounded self-framed low-speed message",
                )));
            }
            let challenge = fresh_response_challenge().map_err(TransactionFailure::Fatal)?;
            write_all_server(
                self.handle.0,
                &response,
                response_io_deadline,
                &self.stop_requested,
                &self.pending_observer,
                PendingIoStage::ResponseWrite,
            )?;
            write_all_server(
                self.handle.0,
                &challenge,
                response_io_deadline,
                &self.stop_requested,
                &self.pending_observer,
                PendingIoStage::ResponseWrite,
            )?;
            let mut acknowledgement = [0_u8; RESPONSE_ACK_LEN];
            read_exact_server(
                self.handle.0,
                &mut acknowledgement,
                response_io_deadline,
                &self.stop_requested,
                &self.pending_observer,
                PendingIoStage::AckRead,
                Some(client.process_id),
            )?;
            if acknowledgement[..RESPONSE_ACK_MAGIC.len()] != RESPONSE_ACK_MAGIC
                || acknowledgement[RESPONSE_ACK_MAGIC.len()..] != challenge
            {
                return Err(TransactionFailure::ClientFault(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "client response-consumption ACK magic/challenge is invalid",
                )));
            }
            if terminal_response.is_some_and(|terminal| terminal.load(Ordering::Acquire)) {
                wait_for_terminal_client_close(
                    self.handle.0,
                    response_io_deadline,
                    &self.stop_requested,
                    &self.pending_observer,
                    client.process_id,
                )?;
            }
            if let Some(observer) = &self.completion_observer {
                // A disconnected observer is intentionally non-fatal: it is
                // test/qualification evidence only and must not alter the
                // transport's completed transaction semantics.
                let _ = observer.send(CompletedTransactionObservation {
                    client: client.clone(),
                    request: request.clone(),
                    response: response.clone(),
                });
            }
            // Echoing an unpredictable challenge proves consumption through
            // the response byte stream, not understanding or acceptance of
            // the response's business semantics.
            // The handler may already have durably acted before an ACK is
            // lost. Retrying is safe only through the upper-layer
            // request-id/epoch idempotence contract; this is not exactly-once.
            Ok(true)
        }

        /// Reuses the first-instance server handle across bounded sequential
        /// transactions. Authenticated client abandonment or malformed input
        /// drops that connection and reaccepts; handler, response-contract,
        /// counter, and listener failures remain service-fatal.
        pub fn run_until_stopped<F>(&mut self, mut handler: F) -> io::Result<u64>
        where
            F: FnMut(&[u8]) -> io::Result<Vec<u8>>,
        {
            self.run_until_stopped_authenticated(|_, request| handler(request))
        }

        pub fn run_until_stopped_authenticated<F>(&mut self, mut handler: F) -> io::Result<u64>
        where
            F: FnMut(&AuthenticatedPipeClient, &[u8]) -> io::Result<Vec<u8>>,
        {
            let mut completed = 0_u64;
            while !self.stop_requested.load(Ordering::Acquire) {
                match self.transact_once_classified_authenticated(|client, request| {
                    handler(client, request)
                }) {
                    Ok(false) => break,
                    Ok(true) => {
                        completed = completed.checked_add(1).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "IPC transaction counter overflow",
                            )
                        })?;
                    }
                    Err(TransactionFailure::ClientFault(_)) => continue,
                    Err(TransactionFailure::Stopped) => break,
                    Err(TransactionFailure::Poisoned(error)) => {
                        self.poisoned = true;
                        return Err(error);
                    }
                    Err(TransactionFailure::Fatal(error)) => return Err(error),
                }
            }
            Ok(completed)
        }

        /// Operator-daemon variant whose handler may request exit after one
        /// transaction. The request becomes effective only after the response
        /// challenge receives its exact FACK and the one-transaction client
        /// closes after observing that write complete. If that response is
        /// abandoned, clear the request and reaccept so a durable idempotent
        /// Stop can be retried; a disconnected GUI must never become an
        /// implicit Stop.
        pub(crate) fn run_until_acknowledged_transaction_flag_authenticated<F>(
            &mut self,
            stop_after_transaction: &AtomicBool,
            mut handler: F,
        ) -> io::Result<u64>
        where
            F: FnMut(&AuthenticatedPipeClient, &[u8]) -> io::Result<Vec<u8>>,
        {
            let mut completed = 0_u64;
            while !self.stop_requested.load(Ordering::Acquire) {
                match self.transact_once_classified_authenticated_with_terminal_close(
                    Some(stop_after_transaction),
                    |client, request| handler(client, request),
                ) {
                    Ok(false) => break,
                    Ok(true) => {
                        completed = completed.checked_add(1).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "IPC transaction counter overflow",
                            )
                        })?;
                        if stop_after_transaction.load(Ordering::Acquire) {
                            break;
                        }
                    }
                    Err(TransactionFailure::ClientFault(_)) => {
                        stop_after_transaction.store(false, Ordering::Release);
                    }
                    Err(TransactionFailure::Stopped) => break,
                    Err(TransactionFailure::Poisoned(error)) => {
                        self.poisoned = true;
                        return Err(error);
                    }
                    Err(TransactionFailure::Fatal(error)) => return Err(error),
                }
            }
            Ok(completed)
        }

        /// Private supervisor/owner variant: a handler may latch
        /// `stop_after_transaction`, but the loop exits only after the exact
        /// response challenge has been acknowledged. If the shutdown handler
        /// ran and the client then abandoned the response/FACK, return that
        /// client fault instead of silently accepting another command.
        #[cfg(test)]
        pub(crate) fn run_until_transaction_flag_authenticated<F>(
            &mut self,
            stop_after_transaction: &AtomicBool,
            handler: F,
        ) -> io::Result<u64>
        where
            F: FnMut(&AuthenticatedPipeClient, &[u8]) -> io::Result<Vec<u8>>,
        {
            self.run_until_transaction_flag_authenticated_with_completion(
                stop_after_transaction,
                handler,
                || Ok(()),
            )
        }

        /// Extends the private transaction boundary with a completion hook
        /// that runs only after the exact response challenge has received its
        /// FACK. Business state that must not become visible on a lost FACK
        /// (for example public IPC activation) belongs in this hook.
        pub(crate) fn run_until_transaction_flag_authenticated_with_completion<F, C>(
            &mut self,
            stop_after_transaction: &AtomicBool,
            mut handler: F,
            mut after_fack: C,
        ) -> io::Result<u64>
        where
            F: FnMut(&AuthenticatedPipeClient, &[u8]) -> io::Result<Vec<u8>>,
            C: FnMut() -> io::Result<()>,
        {
            let mut completed = 0_u64;
            while !self.stop_requested.load(Ordering::Acquire) {
                match self.transact_once_classified_authenticated(|client, request| {
                    handler(client, request)
                }) {
                    Ok(false) => break,
                    Ok(true) => {
                        after_fack()?;
                        completed = completed.checked_add(1).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "IPC transaction counter overflow",
                            )
                        })?;
                        if stop_after_transaction.load(Ordering::Acquire) {
                            break;
                        }
                    }
                    Err(TransactionFailure::ClientFault(error)) => {
                        if stop_after_transaction.load(Ordering::Acquire) {
                            return Err(io::Error::new(
                                error.kind(),
                                format!(
                                    "shutdown response was not consumption-acknowledged: {error}"
                                ),
                            ));
                        }
                    }
                    Err(TransactionFailure::Stopped) => break,
                    Err(TransactionFailure::Poisoned(error)) => {
                        self.poisoned = true;
                        return Err(error);
                    }
                    Err(TransactionFailure::Fatal(error)) => return Err(error),
                }
            }
            Ok(completed)
        }
    }

    /// Synchronous compatibility/test primitive for the local control plane;
    /// production UI callers use `call_secure_pipe_bounded`. It requests only
    /// FILE_READ_DATA | FILE_WRITE_DATA, deliberately excluding
    /// FILE_CREATE_PIPE_INSTANCE which GENERIC_WRITE would otherwise imply.
    pub fn call_secure_pipe(
        pipe_name: &str,
        request: &[u8],
        wait_timeout_ms: u32,
    ) -> io::Result<Vec<u8>> {
        validate_pipe_name(pipe_name)?;
        validate_frame(request, "request")?;
        let wide = wide(pipe_name);
        if unsafe { WaitNamedPipeW(wide.as_ptr(), wait_timeout_ms) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                CLIENT_PIPE_RIGHTS,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        let handle = OwnedHandle::new(handle)?;
        write_all(handle.0, request)?;
        let mut prefix = [0_u8; 4];
        read_exact(handle.0, &mut prefix)?;
        let response_len = u32::from_le_bytes(prefix) as usize;
        if !(4..=MAX_LOW_SPEED_MESSAGE_LEN).contains(&response_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPC response length is outside the frozen low-speed bound",
            ));
        }
        let mut response = vec![0_u8; response_len];
        response[..4].copy_from_slice(&prefix);
        read_exact(handle.0, &mut response[4..])?;
        let mut challenge = [0_u8; RESPONSE_CHALLENGE_LEN];
        read_exact(handle.0, &mut challenge)?;
        let acknowledgement = response_ack(&challenge);
        write_all(handle.0, &acknowledgement)?;
        Ok(response)
    }

    /// Read-only availability probe used by the SCM supervisor before its
    /// first non-idempotent owner-control request. A failed probe sends no
    /// application bytes, so retrying this function cannot consume a private
    /// protocol sequence number.
    pub(crate) fn wait_for_secure_pipe(pipe_name: &str, wait_timeout_ms: u32) -> io::Result<()> {
        validate_pipe_name(pipe_name)?;
        if wait_timeout_ms == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "named-pipe availability timeout must be nonzero",
            ));
        }
        let wide = wide(pipe_name);
        if unsafe { WaitNamedPipeW(wide.as_ptr(), wait_timeout_ms) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Bounded client transaction for UI/control-plane callers. Every read and
    /// write uses overlapped I/O and is cancelled before returning on timeout,
    /// so a wedged service cannot pin a Tauri worker thread indefinitely.
    pub fn call_secure_pipe_bounded(
        pipe_name: &str,
        request: &[u8],
        wait_timeout_ms: u32,
        io_timeout_ms: u32,
    ) -> io::Result<Vec<u8>> {
        validate_pipe_name(pipe_name)?;
        validate_frame(request, "request")?;
        if io_timeout_ms == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPC I/O timeout must be nonzero",
            ));
        }
        let wide = wide(pipe_name);
        if unsafe { WaitNamedPipeW(wide.as_ptr(), wait_timeout_ms) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                CLIENT_PIPE_RIGHTS,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        let handle = OwnedHandle::new(handle)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(u64::from(io_timeout_ms)))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "IPC timeout overflow"))?;
        write_all_bounded(handle.0, request, deadline)?;
        let mut prefix = [0_u8; 4];
        read_exact_bounded(handle.0, &mut prefix, deadline)?;
        let response_len = u32::from_le_bytes(prefix) as usize;
        if !(4..=MAX_LOW_SPEED_MESSAGE_LEN).contains(&response_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPC response length is outside the frozen low-speed bound",
            ));
        }
        let mut response = vec![0_u8; response_len];
        response[..4].copy_from_slice(&prefix);
        read_exact_bounded(handle.0, &mut response[4..], deadline)?;
        let mut challenge = [0_u8; RESPONSE_CHALLENGE_LEN];
        read_exact_bounded(handle.0, &mut challenge, deadline)?;
        let acknowledgement = response_ack(&challenge);
        write_all_bounded(handle.0, &acknowledgement, deadline)?;
        Ok(response)
    }

    /// Completes a bounded v2 request and consumes the complete response plus
    /// its challenge, but deliberately retains the pipe handle before the
    /// challenge ACK.  This is crate-private qualification plumbing for a
    /// real client-process death test; it must never be used by a UI because
    /// dropping it reports an expected client fault to the server.
    #[cfg(feature = "qualification-harness")]
    pub(crate) fn call_secure_pipe_bounded_hold_before_ack(
        pipe_name: &str,
        request: &[u8],
        wait_timeout_ms: u32,
        io_timeout_ms: u32,
    ) -> io::Result<PendingResponseAck> {
        validate_pipe_name(pipe_name)?;
        validate_frame(request, "request")?;
        if io_timeout_ms == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPC I/O timeout must be nonzero",
            ));
        }
        let wide = wide(pipe_name);
        if unsafe { WaitNamedPipeW(wide.as_ptr(), wait_timeout_ms) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                CLIENT_PIPE_RIGHTS,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        let handle = OwnedHandle::new(handle)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(u64::from(io_timeout_ms)))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "IPC timeout overflow"))?;
        write_all_bounded(handle.0, request, deadline)?;
        let mut prefix = [0_u8; 4];
        read_exact_bounded(handle.0, &mut prefix, deadline)?;
        let response_len = u32::from_le_bytes(prefix) as usize;
        if !(4..=MAX_LOW_SPEED_MESSAGE_LEN).contains(&response_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPC response length is outside the frozen low-speed bound",
            ));
        }
        let mut response = vec![0_u8; response_len];
        response[..4].copy_from_slice(&prefix);
        read_exact_bounded(handle.0, &mut response[4..], deadline)?;
        let mut challenge = [0_u8; RESPONSE_CHALLENGE_LEN];
        read_exact_bounded(handle.0, &mut challenge, deadline)?;
        Ok(PendingResponseAck {
            _handle: handle,
            response,
            challenge,
        })
    }

    #[cfg(feature = "qualification-harness")]
    pub(crate) struct PendingResponseAck {
        _handle: OwnedHandle,
        response: Vec<u8>,
        challenge: [u8; RESPONSE_CHALLENGE_LEN],
    }

    #[cfg(feature = "qualification-harness")]
    impl PendingResponseAck {
        pub(crate) fn response(&self) -> &[u8] {
            &self.response
        }

        pub(crate) fn challenge(&self) -> &[u8; RESPONSE_CHALLENGE_LEN] {
            &self.challenge
        }
    }

    pub fn current_process_user_sid() -> io::Result<String> {
        let mut token: HANDLE = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle::new(token)?;
        token_user_sid_string(token.0)
    }

    pub fn lookup_account_sid(account_name: &str) -> io::Result<String> {
        if account_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "account name is empty",
            ));
        }
        let account = wide(account_name);
        let mut sid_bytes = 0_u32;
        let mut domain_chars = 0_u32;
        let mut sid_use: SID_NAME_USE = 0;
        unsafe {
            LookupAccountNameW(
                null(),
                account.as_ptr(),
                null_mut(),
                &mut sid_bytes,
                null_mut(),
                &mut domain_chars,
                &mut sid_use,
            );
        }
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || sid_bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let sid_words = (sid_bytes as usize).div_ceil(size_of::<usize>());
        let mut sid = vec![0_usize; sid_words];
        let mut domain = vec![0_u16; (domain_chars as usize).max(1)];
        let mut actual_sid_bytes = sid_words
            .checked_mul(size_of::<usize>())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "account SID is oversized")
            })?;
        let mut actual_domain_chars = domain.len() as u32;
        if unsafe {
            LookupAccountNameW(
                null(),
                account.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut actual_sid_bytes,
                domain.as_mut_ptr(),
                &mut actual_domain_chars,
                &mut sid_use,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        sid_to_string(sid.as_mut_ptr().cast())
    }

    /// Parses a Windows SID string and returns its canonical string form.
    /// Callers use this before persisting an operator identity in an SCM
    /// launch configuration so a malformed SID cannot be discovered only
    /// after the service has been installed.
    pub fn canonical_sid_string(value: &str) -> io::Result<String> {
        let sid = ParsedSid::parse(value)?;
        sid_to_string(sid.0)
    }

    fn bind(
        options: &SecurePipeOptions,
        require_service_sid: bool,
    ) -> io::Result<SecurePipeServer> {
        validate_pipe_name(&options.pipe_name)?;
        if require_service_sid && !token_has_sid(&options.service_sid)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "configured NT SERVICE SID is not enabled in the current process token",
            ));
        }
        if !require_service_sid && !token_has_sid(&options.service_sid)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test server SID is not enabled in the current process token",
            ));
        }
        let _client_sid = ParsedSid::parse(&options.allowed_client_sid)?;
        let sddl = format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;{})(A;;0x00120083;;;{})",
            options.service_sid, options.allowed_client_sid
        );
        let descriptor = SecurityDescriptor::from_sddl(&sddl)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let wide_name = wide(&options.pipe_name);
        let handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                &attributes,
            )
        };
        let handle = OwnedHandle::new(handle)?;
        Ok(SecurePipeServer {
            handle,
            allowed_client_sid: options.allowed_client_sid.clone(),
            stop_requested: Arc::new(AtomicBool::new(false)),
            pipe_name: options.pipe_name.clone(),
            poisoned: false,
            pending_observer: PendingStageObserver::default(),
            completion_observer: None,
        })
    }

    fn wake_pipe(pipe_name: &str) -> io::Result<()> {
        validate_pipe_name(pipe_name)?;
        let wide = wide(pipe_name);
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                CLIENT_PIPE_RIGHTS,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            if error.raw_os_error().is_some_and(|value| {
                value as u32 == ERROR_FILE_NOT_FOUND || value as u32 == ERROR_PIPE_BUSY
            }) {
                // The listener either observed the stop flag before blocking,
                // or is completing an active transaction and will observe it
                // at the top of the next loop.
                return Ok(());
            }
            return Err(error);
        }
        let _handle = OwnedHandle::new(handle)?;
        Ok(())
    }

    fn is_pipe_client_disconnect_code(code: u32) -> bool {
        matches!(
            code,
            ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
        )
    }

    fn is_pipe_client_disconnect(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::NotConnected
        ) || error
            .raw_os_error()
            .is_some_and(|code| is_pipe_client_disconnect_code(code as u32))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum IdentityOperation {
        ImpersonatePipeClient,
        OpenThreadToken,
        QueryPipeProcessId,
        OpenClientProcess,
        QueryClientProcessTimes,
    }

    fn classify_identity_error(
        operation: IdentityOperation,
        error: io::Error,
    ) -> TransactionFailure {
        let code = error.raw_os_error().map(|value| value as u32);
        let expected_client_race = match operation {
            IdentityOperation::ImpersonatePipeClient => code.is_some_and(|value| {
                is_pipe_client_disconnect_code(value) || value == ERROR_CANNOT_IMPERSONATE
            }),
            IdentityOperation::QueryPipeProcessId => {
                code.is_some_and(is_pipe_client_disconnect_code)
            }
            // OpenProcess documents ERROR_INVALID_PARAMETER for a PID that no
            // longer exists. Access denied, memory pressure, and all other
            // failures remain service-fatal by default.
            IdentityOperation::OpenClientProcess => code == Some(ERROR_INVALID_PARAMETER),
            IdentityOperation::OpenThreadToken | IdentityOperation::QueryClientProcessTimes => {
                false
            }
        };
        if expected_client_race {
            TransactionFailure::ClientFault(error)
        } else {
            TransactionFailure::Fatal(error)
        }
    }

    fn authenticate_client_classified(
        pipe: HANDLE,
        allowed_sid: &str,
    ) -> Result<String, TransactionFailure> {
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(classify_identity_error(
                IdentityOperation::ImpersonatePipeClient,
                io::Error::last_os_error(),
            ));
        }
        let guard = RevertGuard(true);
        let authenticated = (|| {
            let mut token: HANDLE = null_mut();
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
                return Err(classify_identity_error(
                    IdentityOperation::OpenThreadToken,
                    io::Error::last_os_error(),
                ));
            }
            let token = OwnedHandle::new(token).map_err(TransactionFailure::Fatal)?;
            let actual_buffer = token_user_buffer(token.0).map_err(TransactionFailure::Fatal)?;
            let actual_user = unsafe { &*(actual_buffer.as_ptr().cast::<TOKEN_USER>()) };
            let expected = ParsedSid::parse(allowed_sid).map_err(TransactionFailure::Fatal)?;
            if unsafe { EqualSid(actual_user.User.Sid, expected.0) } == 0 {
                return Err(TransactionFailure::ClientFault(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "named-pipe client TokenUser SID does not match the allowed operator SID",
                )));
            }
            sid_to_string(actual_user.User.Sid).map_err(TransactionFailure::Fatal)
        })();
        // Continuing while still impersonating an untrusted client would be a
        // service-wide security failure, never a recoverable client fault.
        guard.revert().map_err(TransactionFailure::Fatal)?;
        authenticated
    }

    fn client_process_instance_classified(
        pipe: HANDLE,
        token_user_sid: String,
    ) -> Result<AuthenticatedPipeClient, TransactionFailure> {
        let mut process_id = 0_u32;
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut process_id) } == 0 {
            return Err(classify_identity_error(
                IdentityOperation::QueryPipeProcessId,
                io::Error::last_os_error(),
            ));
        }
        if process_id == 0 {
            return Err(TransactionFailure::Fatal(io::Error::new(
                io::ErrorKind::InvalidData,
                "named-pipe client process ID is zero",
            )));
        }
        let process_handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if process_handle.is_null() || process_handle == INVALID_HANDLE_VALUE {
            return Err(classify_identity_error(
                IdentityOperation::OpenClientProcess,
                io::Error::last_os_error(),
            ));
        }
        let process = OwnedHandle(process_handle);
        let mut creation: FILETIME = unsafe { std::mem::zeroed() };
        let mut exit: FILETIME = unsafe { std::mem::zeroed() };
        let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
        let mut user: FILETIME = unsafe { std::mem::zeroed() };
        if unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) }
            == 0
        {
            return Err(classify_identity_error(
                IdentityOperation::QueryClientProcessTimes,
                io::Error::last_os_error(),
            ));
        }
        let process_creation_time_100ns =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if process_creation_time_100ns == 0 {
            return Err(TransactionFailure::Fatal(io::Error::new(
                io::ErrorKind::InvalidData,
                "named-pipe client has a zero process creation time",
            )));
        }
        Ok(AuthenticatedPipeClient {
            token_user_sid,
            process_id,
            process_creation_time_100ns,
        })
    }

    pub(crate) fn token_has_sid(sid: &str) -> io::Result<bool> {
        let sid = ParsedSid::parse(sid)?;
        let mut member = 0;
        if unsafe { CheckTokenMembership(null_mut(), sid.0, &mut member) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(member != 0)
    }

    fn token_user_sid_string(token: HANDLE) -> io::Result<String> {
        let buffer = token_user_buffer(token)?;
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        sid_to_string(user.User.Sid)
    }

    fn token_user_buffer(token: HANDLE) -> io::Result<Vec<usize>> {
        let mut required = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut required);
        }
        if required < size_of::<TOKEN_USER>() as u32 {
            return Err(io::Error::last_os_error());
        }
        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        let buffer_bytes = words
            .checked_mul(size_of::<usize>())
            .and_then(|bytes| u32::try_from(bytes).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TokenUser is oversized"))?;
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                buffer_bytes,
                &mut required,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }

    fn sid_to_string(sid: *mut c_void) -> io::Result<String> {
        let mut value = null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0;
        unsafe {
            while *value.add(len) != 0 {
                len += 1;
            }
        }
        let text = String::from_utf16(unsafe { std::slice::from_raw_parts(value, len) })
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SID is not UTF-16"));
        unsafe {
            LocalFree(value.cast());
        }
        text
    }

    fn validate_pipe_name(pipe_name: &str) -> io::Result<()> {
        let suffix = pipe_name.strip_prefix(r"\\.\pipe\").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "only local named pipes are allowed",
            )
        })?;
        if suffix.is_empty() || suffix.contains('\\') || pipe_name.encode_utf16().count() >= 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pipe name must be one bounded local namespace component",
            ));
        }
        if RETIRED_V1_PIPE_NAMES
            .iter()
            .any(|retired| pipe_name.eq_ignore_ascii_case(retired))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "named-pipe transport v1 names are retired; v2 has no compatibility fallback",
            ));
        }
        Ok(())
    }

    fn validate_frame(bytes: &[u8], kind: &str) -> io::Result<()> {
        if !(4..=MAX_LOW_SPEED_MESSAGE_LEN).contains(&bytes.len())
            || u32::from_le_bytes(bytes[..4].try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("IPC {kind} is truncated"),
                )
            })?) as usize
                != bytes.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("IPC {kind} is not a bounded self-framed message"),
            ));
        }
        Ok(())
    }

    fn fresh_response_challenge() -> io::Result<[u8; RESPONSE_CHALLENGE_LEN]> {
        let mut challenge = [0_u8; RESPONSE_CHALLENGE_LEN];
        let status = unsafe {
            BCryptGenRandom(
                null_mut(),
                challenge.as_mut_ptr(),
                challenge.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 || challenge == [0; RESPONSE_CHALLENGE_LEN] {
            Err(io::Error::other(
                "failed to obtain a nonzero named-pipe v2 ACK challenge",
            ))
        } else {
            Ok(challenge)
        }
    }

    fn response_ack(challenge: &[u8; RESPONSE_CHALLENGE_LEN]) -> [u8; RESPONSE_ACK_LEN] {
        let mut acknowledgement = [0_u8; RESPONSE_ACK_LEN];
        acknowledgement[..RESPONSE_ACK_MAGIC.len()].copy_from_slice(&RESPONSE_ACK_MAGIC);
        acknowledgement[RESPONSE_ACK_MAGIC.len()..].copy_from_slice(challenge);
        acknowledgement
    }

    fn connect_server_pipe(
        handle: HANDLE,
        stop_requested: &AtomicBool,
        observer: &PendingStageObserver,
    ) -> Result<(), TransactionFailure> {
        if stop_requested.load(Ordering::Acquire) {
            return Err(TransactionFailure::Stopped);
        }
        let mut pending = PendingOverlapped::new(Vec::new()).map_err(TransactionFailure::Fatal)?;
        let connected = unsafe { ConnectNamedPipe(handle, pending.overlapped_mut()) };
        if connected != 0 {
            return Ok(());
        }
        let code = unsafe { GetLastError() };
        if code == ERROR_PIPE_CONNECTED {
            return Ok(());
        }
        if code != ERROR_IO_PENDING {
            let error = io::Error::from_raw_os_error(code as i32);
            if code == ERROR_OPERATION_ABORTED && stop_requested.load(Ordering::Acquire) {
                return Err(TransactionFailure::Stopped);
            }
            if is_pipe_client_disconnect_code(code) {
                reset_abandoned_server_connection(handle)?;
                return Err(TransactionFailure::ClientFault(error));
            }
            return Err(TransactionFailure::Fatal(error));
        }
        observer.publish(PendingIoStage::Connect);
        match wait_pending_server(handle, pending, None, stop_requested) {
            Ok(_) => Ok(()),
            Err(TransactionFailure::ClientFault(error)) => {
                reset_abandoned_server_connection(handle)?;
                Err(TransactionFailure::ClientFault(error))
            }
            Err(failure) => Err(failure),
        }
    }

    fn reset_abandoned_server_connection(handle: HANDLE) -> Result<(), TransactionFailure> {
        if unsafe { DisconnectNamedPipe(handle) } != 0 {
            return Ok(());
        }
        let code = unsafe { GetLastError() };
        if is_pipe_client_disconnect_code(code) {
            Ok(())
        } else {
            Err(TransactionFailure::Fatal(io::Error::from_raw_os_error(
                code as i32,
            )))
        }
    }

    fn read_exact_server(
        handle: HANDLE,
        mut output: &mut [u8],
        deadline: Instant,
        stop_requested: &AtomicBool,
        observer: &PendingStageObserver,
        stage: PendingIoStage,
        client_process_id: Option<u32>,
    ) -> Result<(), TransactionFailure> {
        while !output.is_empty() {
            preflight_server_transfer(deadline, stop_requested)?;
            let mut pending = PendingOverlapped::new(vec![0_u8; output.len()])
                .map_err(TransactionFailure::Fatal)?;
            let mut transferred = 0_u32;
            let transfer_len = pending.buffer().len().min(u32::MAX as usize) as u32;
            let buffer = pending.buffer_mut().as_mut_ptr();
            let overlapped = pending.overlapped_mut();
            let started =
                unsafe { ReadFile(handle, buffer, transfer_len, &mut transferred, overlapped) };
            let (read, buffer) = if started != 0 {
                (transferred, pending.take_buffer())
            } else {
                let code = unsafe { GetLastError() };
                if code != ERROR_IO_PENDING {
                    return Err(classify_server_transfer_error(
                        io::Error::from_raw_os_error(code as i32),
                    ));
                }
                if client_process_id.is_some() {
                    observer.publish_for_client(stage, client_process_id);
                } else {
                    observer.publish(stage);
                }
                wait_pending_server(handle, pending, Some(deadline), stop_requested)?
            };
            if read == 0 {
                return Err(TransactionFailure::ClientFault(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "named pipe closed",
                )));
            }
            let read = read as usize;
            if read > output.len() || read > buffer.len() {
                return Err(TransactionFailure::Fatal(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "named-pipe read reported an oversized transfer",
                )));
            }
            output[..read].copy_from_slice(&buffer[..read]);
            output = &mut output[read..];
        }
        Ok(())
    }

    fn write_all_server(
        handle: HANDLE,
        mut input: &[u8],
        deadline: Instant,
        stop_requested: &AtomicBool,
        observer: &PendingStageObserver,
        stage: PendingIoStage,
    ) -> Result<(), TransactionFailure> {
        while !input.is_empty() {
            preflight_server_transfer(deadline, stop_requested)?;
            let mut pending =
                PendingOverlapped::new(input.to_vec()).map_err(TransactionFailure::Fatal)?;
            let mut transferred = 0_u32;
            let transfer_len = pending.buffer().len().min(u32::MAX as usize) as u32;
            let buffer = pending.buffer().as_ptr();
            let overlapped = pending.overlapped_mut();
            let started =
                unsafe { WriteFile(handle, buffer, transfer_len, &mut transferred, overlapped) };
            let (written, _buffer) = if started != 0 {
                (transferred, pending.take_buffer())
            } else {
                let code = unsafe { GetLastError() };
                if code != ERROR_IO_PENDING {
                    return Err(classify_server_transfer_error(
                        io::Error::from_raw_os_error(code as i32),
                    ));
                }
                observer.publish(stage);
                wait_pending_server(handle, pending, Some(deadline), stop_requested)?
            };
            if written == 0 {
                return Err(TransactionFailure::Fatal(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "named pipe stalled",
                )));
            }
            let written = written as usize;
            if written > input.len() {
                return Err(TransactionFailure::Fatal(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "named-pipe write reported an oversized transfer",
                )));
            }
            input = &input[written..];
        }
        Ok(())
    }

    /// A terminal server must not disconnect the pipe immediately after it
    /// reads FACK: on Windows that can race the client's overlapped FACK write
    /// completion and turn an authenticated response into ERROR_NO_DATA or
    /// ERROR_PIPE_NOT_CONNECTED at the caller. The official clients use one
    /// connection per transaction and close it only after their FACK write has
    /// completed, so observing that close is a byte-free completion barrier.
    /// Extra bytes are rejected and a missing close remains a bounded client
    /// fault; neither case can promote an unread or unauthenticated response.
    fn wait_for_terminal_client_close(
        handle: HANDLE,
        deadline: Instant,
        stop_requested: &AtomicBool,
        observer: &PendingStageObserver,
        client_process_id: u32,
    ) -> Result<(), TransactionFailure> {
        preflight_server_transfer(deadline, stop_requested)?;
        let mut pending =
            PendingOverlapped::new(vec![0_u8; 1]).map_err(TransactionFailure::Fatal)?;
        let mut transferred = 0_u32;
        let buffer = pending.buffer_mut().as_mut_ptr();
        let overlapped = pending.overlapped_mut();
        let started = unsafe { ReadFile(handle, buffer, 1, &mut transferred, overlapped) };
        let read = if started != 0 {
            transferred
        } else {
            let code = unsafe { GetLastError() };
            if is_pipe_client_disconnect_code(code) {
                return Ok(());
            }
            if code != ERROR_IO_PENDING {
                return Err(classify_server_transfer_error(
                    io::Error::from_raw_os_error(code as i32),
                ));
            }
            observer
                .publish_for_client(PendingIoStage::TerminalClientClose, Some(client_process_id));
            match wait_pending_server(handle, pending, Some(deadline), stop_requested) {
                Ok((read, _buffer)) => read,
                Err(TransactionFailure::ClientFault(error))
                    if is_pipe_client_disconnect(&error) =>
                {
                    return Ok(())
                }
                Err(failure) => return Err(failure),
            }
        };
        if read == 0 {
            Ok(())
        } else {
            Err(TransactionFailure::ClientFault(io::Error::new(
                io::ErrorKind::InvalidData,
                "client sent trailing bytes after terminal response FACK",
            )))
        }
    }

    fn preflight_server_transfer(
        deadline: Instant,
        stop_requested: &AtomicBool,
    ) -> Result<(), TransactionFailure> {
        if stop_requested.load(Ordering::Acquire) {
            return Err(TransactionFailure::Stopped);
        }
        if deadline <= Instant::now() {
            return Err(TransactionFailure::ClientFault(io::Error::new(
                io::ErrorKind::TimedOut,
                "server named-pipe transaction exceeded its I/O deadline",
            )));
        }
        Ok(())
    }

    fn wait_pending_server(
        handle: HANDLE,
        pending: PendingOverlapped,
        deadline: Option<Instant>,
        stop_requested: &AtomicBool,
    ) -> Result<(u32, Vec<u8>), TransactionFailure> {
        loop {
            if stop_requested.load(Ordering::Acquire) {
                return match pending.cancel_and_drain(handle) {
                    Ok(()) => Err(TransactionFailure::Stopped),
                    Err(error) => Err(TransactionFailure::Poisoned(error)),
                };
            }
            let wait_ms = if let Some(deadline) = deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return match pending.cancel_and_drain(handle) {
                        Ok(()) => Err(TransactionFailure::ClientFault(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "server named-pipe transaction exceeded its I/O deadline",
                        ))),
                        Err(error) => Err(TransactionFailure::Poisoned(error)),
                    };
                }
                remaining
                    .as_millis()
                    .clamp(1, u128::from(OVERLAPPED_WAIT_SLICE_MS)) as u32
            } else {
                OVERLAPPED_WAIT_SLICE_MS
            };
            let mut transferred = 0_u32;
            if unsafe {
                GetOverlappedResultEx(handle, pending.overlapped(), &mut transferred, wait_ms, 0)
            } != 0
            {
                return Ok((transferred, pending.take_buffer()));
            }
            let code = unsafe { GetLastError() };
            if code == WAIT_TIMEOUT || code == ERROR_IO_INCOMPLETE {
                continue;
            }
            if code == ERROR_OPERATION_ABORTED && stop_requested.load(Ordering::Acquire) {
                return Err(TransactionFailure::Stopped);
            }
            return Err(classify_server_transfer_error(
                io::Error::from_raw_os_error(code as i32),
            ));
        }
    }

    fn classify_server_transfer_error(error: io::Error) -> TransactionFailure {
        if is_pipe_client_disconnect(&error) || error.kind() == io::ErrorKind::TimedOut {
            TransactionFailure::ClientFault(error)
        } else {
            TransactionFailure::Fatal(error)
        }
    }

    struct PendingOverlapped {
        state: Option<Box<OVERLAPPED>>,
        event: Option<OwnedHandle>,
        buffer: Option<Vec<u8>>,
    }

    impl PendingOverlapped {
        fn new(buffer: Vec<u8>) -> io::Result<Self> {
            let event = OwnedHandle::new(unsafe { CreateEventW(null(), 1, 0, null()) })?;
            let state = Box::new(OVERLAPPED {
                Internal: 0,
                InternalHigh: 0,
                Anonymous: unsafe { std::mem::zeroed() },
                hEvent: event.0,
            });
            Ok(Self {
                state: Some(state),
                event: Some(event),
                buffer: Some(buffer),
            })
        }

        fn overlapped(&self) -> *const OVERLAPPED {
            self.state.as_deref().expect("pending state is present")
        }

        fn overlapped_mut(&mut self) -> *mut OVERLAPPED {
            self.state.as_deref_mut().expect("pending state is present")
        }

        fn buffer(&self) -> &[u8] {
            self.buffer.as_deref().expect("pending buffer is present")
        }

        fn buffer_mut(&mut self) -> &mut [u8] {
            self.buffer
                .as_deref_mut()
                .expect("pending buffer is present")
        }

        fn take_buffer(mut self) -> Vec<u8> {
            self.buffer.take().expect("pending buffer is present")
        }

        fn cancel_and_drain(mut self, handle: HANDLE) -> io::Result<()> {
            unsafe {
                CancelIoEx(handle, self.overlapped());
            }
            let Some(deadline) = Instant::now().checked_add(CANCEL_DRAIN_TIMEOUT) else {
                self.quarantine();
                return Err(io::Error::other(
                    "cancel drain deadline overflow; pending I/O quarantined",
                ));
            };
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    self.quarantine();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "cancelled named-pipe I/O did not reach terminal completion; server poisoned",
                    ));
                }
                let wait_ms = remaining
                    .as_millis()
                    .clamp(1, u128::from(OVERLAPPED_WAIT_SLICE_MS))
                    as u32;
                let mut transferred = 0_u32;
                if unsafe {
                    GetOverlappedResultEx(handle, self.overlapped(), &mut transferred, wait_ms, 0)
                } != 0
                {
                    return Ok(());
                }
                let code = unsafe { GetLastError() };
                if code == WAIT_TIMEOUT || code == ERROR_IO_INCOMPLETE {
                    continue;
                }
                if code == ERROR_OPERATION_ABORTED || is_pipe_client_disconnect_code(code) {
                    return Ok(());
                }
                self.quarantine();
                return Err(io::Error::other(format!(
                    "cancelled named-pipe I/O completion could not be confirmed: {}",
                    io::Error::from_raw_os_error(code as i32)
                )));
            }
        }

        fn quarantine(&mut self) {
            // Kernel ownership could not be proven released. Keep every
            // referenced allocation/event alive permanently; the caller marks
            // the pipe instance poisoned so it is never reused. This is a
            // process-fatal containment path, not normal client recovery.
            if let Some(state) = self.state.take() {
                Box::leak(state);
            }
            if let Some(event) = self.event.take() {
                std::mem::forget(event);
            }
            if let Some(buffer) = self.buffer.take() {
                std::mem::forget(buffer);
            }
        }
    }

    fn read_exact(handle: HANDLE, mut output: &mut [u8]) -> io::Result<()> {
        while !output.is_empty() {
            let mut read = 0;
            if unsafe {
                ReadFile(
                    handle,
                    output.as_mut_ptr(),
                    output.len().min(u32::MAX as usize) as u32,
                    &mut read,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "named pipe closed",
                ));
            }
            output = &mut output[read as usize..];
        }
        Ok(())
    }

    fn write_all(handle: HANDLE, mut input: &[u8]) -> io::Result<()> {
        while !input.is_empty() {
            let mut written = 0;
            if unsafe {
                WriteFile(
                    handle,
                    input.as_ptr(),
                    input.len().min(u32::MAX as usize) as u32,
                    &mut written,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "named pipe stalled",
                ));
            }
            input = &input[written as usize..];
        }
        Ok(())
    }

    fn read_exact_bounded(
        handle: HANDLE,
        mut output: &mut [u8],
        deadline: Instant,
    ) -> io::Result<()> {
        while !output.is_empty() {
            if deadline <= Instant::now() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "named-pipe transaction exceeded its I/O deadline",
                ));
            }
            let mut pending = PendingOverlapped::new(vec![0_u8; output.len()])?;
            let transfer_len = pending.buffer().len().min(u32::MAX as usize) as u32;
            let buffer = pending.buffer_mut().as_mut_ptr();
            let overlapped = pending.overlapped_mut();
            let mut transferred = 0_u32;
            let started =
                unsafe { ReadFile(handle, buffer, transfer_len, &mut transferred, overlapped) };
            let (read, buffer) = if started != 0 {
                (transferred, pending.take_buffer())
            } else {
                let code = unsafe { GetLastError() };
                if code != ERROR_IO_PENDING {
                    return Err(io::Error::from_raw_os_error(code as i32));
                }
                wait_pending_client(handle, pending, deadline)?
            };
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "named pipe closed",
                ));
            }
            let read = read as usize;
            if read > output.len() || read > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "named-pipe read reported an oversized transfer",
                ));
            }
            output[..read].copy_from_slice(&buffer[..read]);
            output = &mut output[read..];
        }
        Ok(())
    }

    fn write_all_bounded(handle: HANDLE, mut input: &[u8], deadline: Instant) -> io::Result<()> {
        while !input.is_empty() {
            if deadline <= Instant::now() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "named-pipe transaction exceeded its I/O deadline",
                ));
            }
            let mut pending = PendingOverlapped::new(input.to_vec())?;
            let transfer_len = pending.buffer().len().min(u32::MAX as usize) as u32;
            let buffer = pending.buffer().as_ptr();
            let overlapped = pending.overlapped_mut();
            let mut transferred = 0_u32;
            let started =
                unsafe { WriteFile(handle, buffer, transfer_len, &mut transferred, overlapped) };
            let (written, _buffer) = if started != 0 {
                (transferred, pending.take_buffer())
            } else {
                let code = unsafe { GetLastError() };
                if code != ERROR_IO_PENDING {
                    return Err(io::Error::from_raw_os_error(code as i32));
                }
                wait_pending_client(handle, pending, deadline)?
            };
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "named pipe stalled",
                ));
            }
            let written = written as usize;
            if written > input.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "named-pipe write reported an oversized transfer",
                ));
            }
            input = &input[written..];
        }
        Ok(())
    }

    fn wait_pending_client(
        handle: HANDLE,
        pending: PendingOverlapped,
        deadline: Instant,
    ) -> io::Result<(u32, Vec<u8>)> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                pending.cancel_and_drain(handle)?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "named-pipe transaction exceeded its I/O deadline",
                ));
            }
            let wait_ms = remaining
                .as_millis()
                .clamp(1, u128::from(OVERLAPPED_WAIT_SLICE_MS)) as u32;
            let mut transferred = 0_u32;
            if unsafe {
                GetOverlappedResultEx(handle, pending.overlapped(), &mut transferred, wait_ms, 0)
            } != 0
            {
                return Ok((transferred, pending.take_buffer()));
            }
            let code = unsafe { GetLastError() };
            if code == WAIT_TIMEOUT || code == ERROR_IO_INCOMPLETE {
                continue;
            }
            return Err(io::Error::from_raw_os_error(code as i32));
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct OwnedHandle(HANDLE);
    // SAFETY: this RAII owner is unique, performs no thread-affine operation,
    // and the Win32 kernel HANDLE may be transferred to another thread. The
    // type is intentionally not Clone, so only one Drop closes it.
    unsafe impl Send for OwnedHandle {}
    impl OwnedHandle {
        fn new(handle: HANDLE) -> io::Result<Self> {
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(handle))
            }
        }
    }
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    struct PipeConnection(HANDLE);
    impl Drop for PipeConnection {
        fn drop(&mut self) {
            unsafe {
                DisconnectNamedPipe(self.0);
            }
        }
    }

    struct ParsedSid(*mut c_void);
    impl ParsedSid {
        fn parse(value: &str) -> io::Result<Self> {
            let mut sid = null_mut();
            if unsafe { ConvertStringSidToSidW(wide(value).as_ptr(), &mut sid) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid SID: {}", io::Error::last_os_error()),
                ));
            }
            Ok(Self(sid))
        }
    }
    impl Drop for ParsedSid {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    struct SecurityDescriptor(*mut c_void);
    impl SecurityDescriptor {
        fn from_sddl(sddl: &str) -> io::Result<Self> {
            let mut descriptor = null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(sddl).as_ptr(),
                    SECURITY_DESCRIPTOR_REVISION,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "invalid pipe security descriptor: {}",
                        io::Error::last_os_error()
                    ),
                ));
            }
            Ok(Self(descriptor))
        }
    }
    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    struct RevertGuard(bool);
    impl RevertGuard {
        fn revert(mut self) -> io::Result<()> {
            if unsafe { RevertToSelf() } == 0 {
                return Err(io::Error::last_os_error());
            }
            self.0 = false;
            Ok(())
        }
    }
    impl Drop for RevertGuard {
        fn drop(&mut self) {
            if self.0 {
                unsafe {
                    RevertToSelf();
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::mpsc;
        use std::sync::Arc;
        use std::thread;
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_NOT_ENOUGH_MEMORY};

        static PIPE_ID: AtomicU64 = AtomicU64::new(1);

        #[test]
        fn production_bind_rejects_non_service_sid_even_when_it_is_current_user() {
            let sid = current_process_user_sid().unwrap();
            let result = SecurePipeServer::bind_service(&SecurePipeOptions {
                pipe_name: unique_pipe_name(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            });
            assert_eq!(
                result.err().unwrap().kind(),
                io::ErrorKind::PermissionDenied
            );
        }

        #[test]
        fn local_acl_and_token_user_round_trip_are_enforced() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let request = framed(b"authenticated request");
            let expected = framed(b"bounded response");
            let server_expected = expected.clone();
            let join = thread::spawn(move || {
                server.transact_once(|actual| {
                    assert_eq!(actual, request);
                    Ok(server_expected)
                })
            });
            let response = call_secure_pipe_bounded(
                &pipe_name,
                &framed(b"authenticated request"),
                5_000,
                5_000,
            )
            .unwrap();
            assert_eq!(response, expected);
            assert!(join.join().unwrap().unwrap());
        }

        #[test]
        fn client_connected_before_accept_exercises_error_pipe_connected_path() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            // Open before the server calls ConnectNamedPipe. The subsequent
            // overlapped accept must recognize ERROR_PIPE_CONNECTED as a
            // completed connection, not an I/O failure.
            let client = open_raw_pipe(&pipe_name).unwrap();
            let join = thread::spawn(move || server.transact_once(|request| Ok(request.to_vec())));
            let request = framed(b"preconnected client");
            write_all(client.0, &request).unwrap();
            let mut prefix = [0_u8; 4];
            read_exact(client.0, &mut prefix).unwrap();
            let mut response = vec![0_u8; u32::from_le_bytes(prefix) as usize];
            response[..4].copy_from_slice(&prefix);
            read_exact(client.0, &mut response[4..]).unwrap();
            let mut challenge = [0_u8; RESPONSE_CHALLENGE_LEN];
            read_exact(client.0, &mut challenge).unwrap();
            write_all(client.0, &response_ack(&challenge)).unwrap();
            assert_eq!(response, request);
            assert!(join.join().unwrap().unwrap());
        }

        #[test]
        fn bounded_client_cancels_a_wedged_transaction() {
            let sid = current_process_user_sid().unwrap();
            assert_eq!(canonical_sid_string(&sid).unwrap(), sid);
            assert!(canonical_sid_string("not-a-sid").is_err());
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let join = thread::spawn(move || {
                server.transact_once(|request| {
                    thread::sleep(Duration::from_millis(100));
                    Ok(request.to_vec())
                })
            });
            let error = call_secure_pipe_bounded(&pipe_name, &framed(b"must time out"), 5_000, 10)
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(join.join().unwrap().is_err());
        }

        #[test]
        fn persistent_listener_handles_multiple_transactions_and_stops_while_idle() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let stop = server.stop_handle();
            let join =
                thread::spawn(move || server.run_until_stopped(|request| Ok(request.to_vec())));
            for payload in [b"first".as_slice(), b"second".as_slice()] {
                let request = framed(payload);
                let response = call_secure_pipe(&pipe_name, &request, 5_000).unwrap();
                assert_eq!(response, request);
            }
            let reaccept_barrier = open_raw_pipe(&pipe_name).unwrap();
            stop.request_stop().unwrap();
            drop(reaccept_barrier);
            assert_eq!(join.join().unwrap().unwrap(), 2);
        }

        #[test]
        fn transaction_flag_exits_only_after_response_consumption_ack() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let stop_after = Arc::new(AtomicBool::new(false));
            let server_stop_after = Arc::clone(&stop_after);
            let join = thread::spawn(move || {
                server.run_until_transaction_flag_authenticated(&server_stop_after, |_, request| {
                    server_stop_after.store(true, Ordering::Release);
                    Ok(request.to_vec())
                })
            });
            let request = framed(b"shutdown-after-fack");
            assert_eq!(
                call_secure_pipe_bounded(&pipe_name, &request, 5_000, 5_000).unwrap(),
                request
            );
            assert_eq!(join.join().unwrap().unwrap(), 1);
            assert!(stop_after.load(Ordering::Acquire));
        }

        #[test]
        fn response_io_budget_starts_after_slow_dispatcher_work() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let request = framed(b"slow durable terminal work still gets a response");
            let expected = request.clone();
            let join = thread::spawn(move || {
                server.transact_once(move |_| {
                    thread::sleep(SERVER_TRANSACTION_IO_TIMEOUT + Duration::from_millis(100));
                    Ok(expected)
                })
            });

            let response = call_secure_pipe_bounded(&pipe_name, &request, 5_000, 7_000).unwrap();
            assert_eq!(response, request);
            assert!(join.join().unwrap().unwrap());
        }

        #[test]
        fn terminal_fack_waits_for_client_write_completion_close_before_exit() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let pending_stages = server.install_pending_stage_observer();
            let stop_after = Arc::new(AtomicBool::new(false));
            let server_stop_after = Arc::clone(&stop_after);
            let join = thread::spawn(move || {
                server.run_until_acknowledged_transaction_flag_authenticated(
                    &server_stop_after,
                    |_, request| {
                        server_stop_after.store(true, Ordering::Release);
                        Ok(request.to_vec())
                    },
                )
            });

            let client = open_raw_pipe(&pipe_name).unwrap();
            let request = framed(b"terminal response close barrier");
            write_all(client.0, &request).unwrap();
            let (response, challenge) = read_raw_response_v2(client.0).unwrap();
            assert_eq!(response, request);
            write_all(client.0, &response_ack(&challenge)).unwrap();
            wait_for_pending_stage(
                &pending_stages,
                PendingIoStage::TerminalClientClose,
                Duration::from_secs(2),
            )
            .unwrap();
            assert!(
                !join.is_finished(),
                "terminal listener exited before the FACK-writing client observed completion"
            );

            drop(client);
            assert_eq!(join.join().unwrap().unwrap(), 1);
            assert!(stop_after.load(Ordering::Acquire));
        }

        #[test]
        fn transaction_flag_reports_lost_shutdown_fack() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let stop_after = Arc::new(AtomicBool::new(false));
            let server_stop_after = Arc::clone(&stop_after);
            let join = thread::spawn(move || {
                server.run_until_transaction_flag_authenticated(&server_stop_after, |_, request| {
                    server_stop_after.store(true, Ordering::Release);
                    Ok(request.to_vec())
                })
            });

            let client = open_raw_pipe(&pipe_name).unwrap();
            let request = framed(b"shutdown-without-fack");
            write_all(client.0, &request).unwrap();
            let mut prefix = [0_u8; 4];
            read_exact(client.0, &mut prefix).unwrap();
            let mut response = vec![0_u8; u32::from_le_bytes(prefix) as usize];
            response[..4].copy_from_slice(&prefix);
            read_exact(client.0, &mut response[4..]).unwrap();
            let mut challenge = [0_u8; RESPONSE_CHALLENGE_LEN];
            read_exact(client.0, &mut challenge).unwrap();
            drop(client);

            let error = join.join().unwrap().unwrap_err();
            assert!(error.to_string().contains("not consumption-acknowledged"));
            assert!(stop_after.load(Ordering::Acquire));
        }

        #[test]
        fn acknowledged_transaction_flag_reaccepts_after_lost_fack() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let stop_after = Arc::new(AtomicBool::new(false));
            let server_stop_after = Arc::clone(&stop_after);
            let join = thread::spawn(move || {
                server.run_until_acknowledged_transaction_flag_authenticated(
                    &server_stop_after,
                    |_, request| {
                        server_stop_after.store(true, Ordering::Release);
                        Ok(request.to_vec())
                    },
                )
            });

            let client = open_raw_pipe(&pipe_name).unwrap();
            let first = framed(b"stop-response-without-fack");
            write_all(client.0, &first).unwrap();
            let mut prefix = [0_u8; 4];
            read_exact(client.0, &mut prefix).unwrap();
            let mut response = vec![0_u8; u32::from_le_bytes(prefix) as usize];
            response[..4].copy_from_slice(&prefix);
            read_exact(client.0, &mut response[4..]).unwrap();
            let mut challenge = [0_u8; RESPONSE_CHALLENGE_LEN];
            read_exact(client.0, &mut challenge).unwrap();
            drop(client);

            let retried = framed(b"retried-stop-response-with-fack");
            assert_eq!(
                call_secure_pipe_bounded(&pipe_name, &retried, 5_000, 5_000).unwrap(),
                retried
            );
            assert_eq!(join.join().unwrap().unwrap(), 1);
            assert!(stop_after.load(Ordering::Acquire));
        }

        #[test]
        fn persistent_listener_survives_bounded_client_timeout_and_reaccepts() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let stop = server.stop_handle();
            let handler_calls = Arc::new(AtomicU64::new(0));
            let server_calls = Arc::clone(&handler_calls);
            let join = thread::spawn(move || {
                server.run_until_stopped(|request| {
                    if server_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Ok(request.to_vec())
                })
            });

            let error = call_secure_pipe_bounded(
                &pipe_name,
                &framed(b"cancel this client only"),
                5_000,
                10,
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(
                !join.is_finished(),
                "client timeout terminated the listener"
            );

            let second = framed(b"independent second client");
            // WaitNamedPipe inside this call cannot report availability until
            // the first handler returns, its response/ACK exchange observes the
            // cancelled client, and PipeConnection disconnects that instance.
            assert_eq!(
                call_secure_pipe_bounded(&pipe_name, &second, 5_000, 5_000).unwrap(),
                second
            );
            let reaccept_barrier = open_raw_pipe(&pipe_name).unwrap();
            stop.request_stop().unwrap();
            drop(reaccept_barrier);
            assert_eq!(join.join().unwrap().unwrap(), 1);
            assert_eq!(handler_calls.load(Ordering::Relaxed), 2);
        }

        #[test]
        fn persistent_listener_keeps_handler_errors_fatal() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let join = thread::spawn(move || {
                server.run_until_stopped(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "dispatcher persistence failed",
                    ))
                })
            });
            assert!(call_secure_pipe(&pipe_name, &framed(b"fatal handler"), 5_000).is_err());
            let failure = join.join().unwrap().unwrap_err();
            assert_eq!(failure.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(failure.to_string(), "dispatcher persistence failed");
        }

        #[test]
        fn persistent_listener_rejects_invalid_client_length_then_reaccepts() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let stop = server.stop_handle();
            let join =
                thread::spawn(move || server.run_until_stopped(|request| Ok(request.to_vec())));

            write_raw_pipe_bytes(&pipe_name, &3_u32.to_le_bytes()).unwrap();
            let valid = framed(b"valid after malformed client");
            assert_eq!(call_secure_pipe(&pipe_name, &valid, 5_000).unwrap(), valid);
            let reaccept_barrier = open_raw_pipe(&pipe_name).unwrap();
            stop.request_stop().unwrap();
            drop(reaccept_barrier);
            assert_eq!(join.join().unwrap().unwrap(), 1);
        }

        #[test]
        fn partial_prefix_cannot_block_stop_or_pin_overlapped_state() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let pending_stages = server.install_pending_stage_observer();
            let stop = server.stop_handle();
            // Preconnect and place only part of the prefix in the byte stream
            // before the listener starts. No PrefixRead observation can be
            // stale: the observed ERROR_IO_PENDING must be the read for the
            // still-missing suffix of this prefix.
            let raw_client = open_raw_pipe(&pipe_name).unwrap();
            write_all(raw_client.0, &[8_u8, 0]).unwrap();
            let (finished_tx, finished_rx) = mpsc::sync_channel(1);
            let join = thread::spawn(move || {
                let outcome = server.run_until_stopped(|request| Ok(request.to_vec()));
                finished_tx.send(outcome).unwrap();
            });

            let completed = assert_pending_stage_then_stop_and_reap(
                &pending_stages,
                PendingIoStage::PrefixRead,
                &stop,
                raw_client,
                finished_rx,
                join,
                "partial-prefix listener",
            );
            assert_eq!(completed, 0);
        }

        #[test]
        fn partial_body_cannot_block_stop_or_pin_overlapped_state() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let pending_stages = server.install_pending_stage_observer();
            let stop = server.stop_handle();
            let raw_client = open_raw_pipe(&pipe_name).unwrap();
            let request = framed(b"body remains pending");
            // As in the prefix case, buffer the complete prefix plus only one
            // body byte before accept. The BodyRead notification therefore
            // belongs to the still-missing body suffix and remains active.
            write_all(raw_client.0, &request[..5]).unwrap();
            let (finished_tx, finished_rx) = mpsc::sync_channel(1);
            let join = thread::spawn(move || {
                let outcome = server.run_until_stopped(|request| Ok(request.to_vec()));
                finished_tx.send(outcome).unwrap();
            });

            let completed = assert_pending_stage_then_stop_and_reap(
                &pending_stages,
                PendingIoStage::BodyRead,
                &stop,
                raw_client,
                finished_rx,
                join,
                "partial-body listener",
            );
            assert_eq!(completed, 0);
        }

        #[test]
        fn pending_response_ack_read_cannot_block_stop() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let pending_stages = server.install_pending_stage_observer();
            let stop = server.stop_handle();
            let (finished_tx, finished_rx) = mpsc::sync_channel(1);
            let join = thread::spawn(move || {
                let outcome = server.run_until_stopped(|request| Ok(request.to_vec()));
                finished_tx.send(outcome).unwrap();
            });

            let raw_client = open_raw_pipe_overlapped(&pipe_name, 2_000).unwrap();
            let raw_deadline = Instant::now().checked_add(Duration::from_secs(2)).unwrap();
            let request = framed(b"read response and challenge but withhold ACK");
            write_all_bounded(raw_client.0, &request, raw_deadline).unwrap();
            let (response, challenge) =
                read_raw_response_v2_bounded(raw_client.0, raw_deadline).unwrap();
            assert_eq!(response, request);
            assert_ne!(challenge, [0; RESPONSE_CHALLENGE_LEN]);
            let completed = assert_pending_stage_then_stop_and_reap(
                &pending_stages,
                PendingIoStage::AckRead,
                &stop,
                raw_client,
                finished_rx,
                join,
                "pending-ACK listener",
            );
            assert_eq!(completed, 0);
        }

        #[test]
        fn missing_response_ack_is_client_fault_and_listener_reaccepts() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let stop = server.stop_handle();
            let join =
                thread::spawn(move || server.run_until_stopped(|request| Ok(request.to_vec())));

            let first = framed(b"read response then disappear before ACK");
            assert_eq!(
                raw_round_trip(&pipe_name, &first, RawAckMode::Missing).unwrap(),
                first
            );
            let second = framed(b"valid client after missing ACK");
            assert_eq!(
                call_secure_pipe(&pipe_name, &second, 5_000).unwrap(),
                second
            );
            let reaccept_barrier = open_raw_pipe(&pipe_name).unwrap();
            stop.request_stop().unwrap();
            drop(reaccept_barrier);
            assert_eq!(join.join().unwrap().unwrap(), 1);
        }

        #[test]
        fn invalid_response_ack_is_client_fault_and_listener_reaccepts() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let stop = server.stop_handle();
            let join =
                thread::spawn(move || server.run_until_stopped(|request| Ok(request.to_vec())));

            let first = framed(b"wrong ACK");
            assert_eq!(
                raw_round_trip(&pipe_name, &first, RawAckMode::WrongMagic).unwrap(),
                first
            );
            let second = framed(b"valid client after wrong ACK");
            assert_eq!(
                call_secure_pipe(&pipe_name, &second, 5_000).unwrap(),
                second
            );
            let reaccept_barrier = open_raw_pipe(&pipe_name).unwrap();
            stop.request_stop().unwrap();
            drop(reaccept_barrier);
            assert_eq!(join.join().unwrap().unwrap(), 1);
        }

        #[test]
        fn completion_observer_emits_only_after_valid_challenge_ack_and_reaccepts() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let completions = server.install_completion_observer();
            let stop = server.stop_handle();
            let join =
                thread::spawn(move || server.run_until_stopped(|request| Ok(request.to_vec())));

            let first = framed(b"completion observer first valid transaction");
            assert_eq!(call_secure_pipe(&pipe_name, &first, 5_000).unwrap(), first);
            let first_observation = completions
                .recv_timeout(Duration::from_secs(2))
                .expect("valid FACK must publish exactly one completion");
            assert_eq!(first_observation.client.process_id, std::process::id());
            assert_ne!(first_observation.client.process_creation_time_100ns, 0);
            assert_eq!(first_observation.request, first);
            assert_eq!(first_observation.response, first);
            assert!(matches!(
                completions.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));

            for (payload, mode) in [
                (
                    b"completion observer missing ACK".as_slice(),
                    RawAckMode::Missing,
                ),
                (
                    b"completion observer wrong ACK".as_slice(),
                    RawAckMode::WrongMagic,
                ),
            ] {
                let request = framed(payload);
                assert_eq!(raw_round_trip(&pipe_name, &request, mode).unwrap(), request);
                assert!(matches!(
                    completions.try_recv(),
                    Err(mpsc::TryRecvError::Empty)
                ));
            }
            let guessing_client = open_raw_pipe(&pipe_name).unwrap();
            let guessed = framed(b"completion observer guessed ACK");
            let mut pipelined = guessed.clone();
            pipelined.extend_from_slice(&response_ack(&[0_u8; RESPONSE_CHALLENGE_LEN]));
            write_all(guessing_client.0, &pipelined).unwrap();
            drop(guessing_client);
            assert!(matches!(
                completions.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));

            let second = framed(b"completion observer valid after client faults");
            assert_eq!(
                call_secure_pipe(&pipe_name, &second, 5_000).unwrap(),
                second
            );
            let second_observation = completions
                .recv_timeout(Duration::from_secs(2))
                .expect("later valid FACK must publish after client faults");
            assert_eq!(second_observation.client.process_id, std::process::id());
            assert_eq!(
                second_observation.client.process_creation_time_100ns,
                first_observation.client.process_creation_time_100ns
            );
            assert_eq!(second_observation.request, second);
            assert_eq!(second_observation.response, second);
            assert!(matches!(
                completions.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));
            let reaccept_barrier = open_raw_pipe(&pipe_name).unwrap();
            stop.request_stop().unwrap();
            drop(reaccept_barrier);
            assert_eq!(join.join().unwrap().unwrap(), 2);
        }

        #[test]
        fn pre_sent_guessed_ack_is_rejected_before_listener_reaccepts() {
            let sid = current_process_user_sid().unwrap();
            let pipe_name = unique_pipe_name();
            let mut server = SecurePipeServer::bind_test(&SecurePipeOptions {
                pipe_name: pipe_name.clone(),
                service_sid: sid.clone(),
                allowed_client_sid: sid,
            })
            .unwrap();
            let stop = server.stop_handle();
            let join =
                thread::spawn(move || server.run_until_stopped(|request| Ok(request.to_vec())));

            let guessing_client = open_raw_pipe(&pipe_name).unwrap();
            let first = framed(b"pre-send an ACK without consuming the response challenge");
            let impossible_zero_challenge = [0_u8; RESPONSE_CHALLENGE_LEN];
            let guessed_ack = response_ack(&impossible_zero_challenge);
            let mut pipelined = first;
            pipelined.extend_from_slice(&guessed_ack);
            write_all(guessing_client.0, &pipelined).unwrap();

            // The server refuses an all-zero generated challenge, so this
            // pre-sent guess cannot match the challenge bound to transaction 1.
            // A valid v2 exchange succeeding next proves the listener treated
            // the guess as a per-client fault and reaccepted.
            let second = framed(b"valid client after pre-sent guessed ACK");
            assert_eq!(
                call_secure_pipe(&pipe_name, &second, 5_000).unwrap(),
                second
            );
            drop(guessing_client);
            let reaccept_barrier = open_raw_pipe(&pipe_name).unwrap();
            stop.request_stop().unwrap();
            drop(reaccept_barrier);
            assert_eq!(join.join().unwrap().unwrap(), 1);
        }

        #[test]
        fn identity_error_classifier_is_allowlist_not_error_kind_guessing() {
            assert!(matches!(
                classify_identity_error(
                    IdentityOperation::ImpersonatePipeClient,
                    io::Error::from_raw_os_error(ERROR_CANNOT_IMPERSONATE as i32),
                ),
                TransactionFailure::ClientFault(_)
            ));
            assert!(matches!(
                classify_identity_error(
                    IdentityOperation::QueryPipeProcessId,
                    io::Error::from_raw_os_error(ERROR_BROKEN_PIPE as i32),
                ),
                TransactionFailure::ClientFault(_)
            ));
            assert!(matches!(
                classify_identity_error(
                    IdentityOperation::OpenClientProcess,
                    io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32),
                ),
                TransactionFailure::ClientFault(_)
            ));

            for (operation, code) in [
                (
                    IdentityOperation::ImpersonatePipeClient,
                    ERROR_ACCESS_DENIED,
                ),
                (IdentityOperation::OpenThreadToken, ERROR_BROKEN_PIPE),
                (IdentityOperation::OpenClientProcess, ERROR_ACCESS_DENIED),
                (
                    IdentityOperation::QueryClientProcessTimes,
                    ERROR_INVALID_PARAMETER,
                ),
                (
                    IdentityOperation::QueryPipeProcessId,
                    ERROR_NOT_ENOUGH_MEMORY,
                ),
            ] {
                assert!(matches!(
                    classify_identity_error(operation, io::Error::from_raw_os_error(code as i32),),
                    TransactionFailure::Fatal(_)
                ));
            }
        }

        #[test]
        fn framing_and_remote_or_nested_names_fail_closed() {
            assert!(call_secure_pipe(r"\\remote\pipe\forge", &[4, 0, 0, 0], 1).is_err());
            assert!(call_secure_pipe(r"\\.\pipe\forge\nested", &[4, 0, 0, 0], 1).is_err());
            assert!(call_secure_pipe(r"\\.\pipe\forge", &[5, 0, 0, 0], 1).is_err());
            for retired in RETIRED_V1_PIPE_NAMES {
                assert_eq!(
                    validate_pipe_name(retired).unwrap_err().kind(),
                    io::ErrorKind::InvalidInput
                );
                assert_eq!(
                    validate_pipe_name(&retired.to_ascii_uppercase())
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput
                );
            }
        }

        fn unique_pipe_name() -> String {
            format!(
                r"\\.\pipe\forge-acqd-test-{}-{}",
                std::process::id(),
                PIPE_ID.fetch_add(1, Ordering::Relaxed)
            )
        }

        fn framed(payload: &[u8]) -> Vec<u8> {
            let len = 4 + payload.len();
            let mut frame = Vec::with_capacity(len);
            frame.extend_from_slice(&(len as u32).to_le_bytes());
            frame.extend_from_slice(payload);
            frame
        }

        fn write_raw_pipe_bytes(pipe_name: &str, bytes: &[u8]) -> io::Result<()> {
            let handle = open_raw_pipe(pipe_name)?;
            write_all(handle.0, bytes)
        }

        fn open_raw_pipe(pipe_name: &str) -> io::Result<OwnedHandle> {
            let wide_name = wide(pipe_name);
            if unsafe { WaitNamedPipeW(wide_name.as_ptr(), 5_000) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let handle = unsafe {
                CreateFileW(
                    wide_name.as_ptr(),
                    CLIENT_PIPE_RIGHTS,
                    0,
                    null(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            OwnedHandle::new(handle)
        }

        fn open_raw_pipe_overlapped(
            pipe_name: &str,
            wait_timeout_ms: u32,
        ) -> io::Result<OwnedHandle> {
            let wide_name = wide(pipe_name);
            if unsafe { WaitNamedPipeW(wide_name.as_ptr(), wait_timeout_ms) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let handle = unsafe {
                CreateFileW(
                    wide_name.as_ptr(),
                    CLIENT_PIPE_RIGHTS,
                    0,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    null_mut(),
                )
            };
            OwnedHandle::new(handle)
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum RawAckMode {
            Missing,
            WrongMagic,
        }

        fn raw_round_trip(
            pipe_name: &str,
            request: &[u8],
            acknowledgement: RawAckMode,
        ) -> io::Result<Vec<u8>> {
            let handle = open_raw_pipe(pipe_name)?;
            write_all(handle.0, request)?;
            let (response, challenge) = read_raw_response_v2(handle.0)?;
            if challenge == [0; RESPONSE_CHALLENGE_LEN] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "server emitted the forbidden all-zero response challenge",
                ));
            }
            match acknowledgement {
                RawAckMode::Missing => {}
                RawAckMode::WrongMagic => {
                    let mut invalid = response_ack(&challenge);
                    invalid[..RESPONSE_ACK_MAGIC.len()].copy_from_slice(b"NOPE");
                    write_all(handle.0, &invalid)?;
                }
            }
            Ok(response)
        }

        fn read_raw_response_v2(
            handle: HANDLE,
        ) -> io::Result<(Vec<u8>, [u8; RESPONSE_CHALLENGE_LEN])> {
            let mut prefix = [0_u8; 4];
            read_exact(handle, &mut prefix)?;
            let response_len = u32::from_le_bytes(prefix) as usize;
            if !(4..=MAX_LOW_SPEED_MESSAGE_LEN).contains(&response_len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "raw test response length is invalid",
                ));
            }
            let mut response = vec![0_u8; response_len];
            response[..4].copy_from_slice(&prefix);
            read_exact(handle, &mut response[4..])?;
            let mut challenge = [0_u8; RESPONSE_CHALLENGE_LEN];
            read_exact(handle, &mut challenge)?;
            Ok((response, challenge))
        }

        fn read_raw_response_v2_bounded(
            handle: HANDLE,
            deadline: Instant,
        ) -> io::Result<(Vec<u8>, [u8; RESPONSE_CHALLENGE_LEN])> {
            let mut prefix = [0_u8; 4];
            read_exact_bounded(handle, &mut prefix, deadline)?;
            let response_len = u32::from_le_bytes(prefix) as usize;
            if !(4..=MAX_LOW_SPEED_MESSAGE_LEN).contains(&response_len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "raw test response length is invalid",
                ));
            }
            let mut response = vec![0_u8; response_len];
            response[..4].copy_from_slice(&prefix);
            read_exact_bounded(handle, &mut response[4..], deadline)?;
            let mut challenge = [0_u8; RESPONSE_CHALLENGE_LEN];
            read_exact_bounded(handle, &mut challenge, deadline)?;
            Ok((response, challenge))
        }

        fn wait_for_pending_stage(
            receiver: &mpsc::Receiver<PendingIoStage>,
            expected: PendingIoStage,
            timeout: Duration,
        ) -> Result<(), String> {
            let deadline = Instant::now()
                .checked_add(timeout)
                .ok_or_else(|| "pending-stage test deadline overflow".to_owned())?;
            let mut observed = Vec::new();
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(format!(
                        "timed out waiting for {expected:?}; observed {observed:?}"
                    ));
                }
                match receiver.recv_timeout(remaining) {
                    Ok(stage) if stage == expected => return Ok(()),
                    Ok(stage) => observed.push(stage),
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        return Err(format!(
                            "timed out waiting for {expected:?}; observed {observed:?}"
                        ));
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(format!(
                            "pending-stage observer disconnected while waiting for {expected:?}; observed {observed:?}"
                        ));
                    }
                }
            }
        }

        fn assert_pending_stage_then_stop_and_reap(
            receiver: &mpsc::Receiver<PendingIoStage>,
            expected: PendingIoStage,
            stop: &SecurePipeStopHandle,
            raw_client: OwnedHandle,
            finished_rx: mpsc::Receiver<io::Result<u64>>,
            join: thread::JoinHandle<()>,
            context: &str,
        ) -> u64 {
            if let Err(stage_error) =
                wait_for_pending_stage(receiver, expected, Duration::from_secs(2))
            {
                let _ = stop.request_stop();
                drop(raw_client);
                if finished_rx.recv_timeout(Duration::from_secs(2)).is_ok() {
                    join.join().expect("listener cleanup thread panicked");
                }
                panic!("{context} never reached a real pending I/O: {stage_error}");
            }

            let stop_result = stop.request_stop();
            match finished_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(outcome) => {
                    // Keep the client handle alive until cancellation has been
                    // observed and drained by the listener under test.
                    drop(raw_client);
                    join.join().expect("stopped listener thread panicked");
                    stop_result.expect("failed to request listener stop");
                    outcome.expect("listener returned an error while stopping pending I/O")
                }
                Err(wait_error) => {
                    drop(raw_client);
                    let cleanup = finished_rx.recv_timeout(Duration::from_secs(2));
                    if cleanup.is_ok() {
                        join.join().expect("listener cleanup thread panicked");
                    }
                    panic!("{context} did not stop within the hard bound: {wait_error}");
                }
            }
        }
    }
}

#[cfg(windows)]
pub use windows::{
    call_secure_pipe, call_secure_pipe_bounded, canonical_sid_string, current_process_user_sid,
    lookup_account_sid, AuthenticatedPipeClient, SecurePipeOptions, SecurePipeServer,
    SecurePipeStopHandle,
};

#[cfg(windows)]
pub(crate) use windows::{token_has_sid, wait_for_secure_pipe};

#[cfg(all(windows, feature = "qualification-harness"))]
pub(crate) use windows::{
    call_secure_pipe_bounded_hold_before_ack, CompletedTransactionObservation,
    PendingIoObservation, PendingIoStage,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_fails_closed_instead_of_opening_an_unsecured_pipe() {
        let boundary = ipc_boundary();
        assert!(!boundary.available);
        assert!(!boundary.sid_acl_verified);
        assert!(!boundary.service_control_manager_verified);
        assert_eq!(boundary.secure_pipe_primitives_available, cfg!(windows));
    }
}
