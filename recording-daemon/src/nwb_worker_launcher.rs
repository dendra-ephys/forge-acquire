//! Contained Windows launcher for the optional Forge NWB worker.
//!
//! This is a process primitive, not an installed-worker qualification.  The
//! production constructors deliberately require the deployment/root proofs;
//! the qualification constructor is available only to tests and the local
//! qualification harness and marks its evidence as non-production.

#![cfg(windows)]

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::nwb_supervisor::{NwbGenerationLaunchV1, NwbWorkerHandle, NwbWorkerLauncher};
use crate::windows_contained_process::{
    ContainedProcess, ContainedProcessLaunchOptions, ContainedProcessWaitEvidence,
    TerminalObservationV1,
};
use crate::windows_deployment_security::{
    inspect_stable_deployment_path, require_canonical_deployment_path, DeploymentFileIdentityV1,
    LockedDeploymentAncestorChain, LockedDeploymentFileProof,
};

const STOP_BUDGET: Duration = Duration::from_secs(2);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn permission(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

fn hex_digest(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn validate_poll_interval_ms(value: u16) -> io::Result<()> {
    if (1..=2_000).contains(&value) {
        Ok(())
    } else {
        Err(invalid("poll interval must be within 1..2000 ms"))
    }
}

/// Dedicated executable evidence.  The executable must be a retained,
/// handle-bound proof; pathname/PATH/PYTHONPATH resolution is never accepted.
pub(crate) struct WindowsNwbWorkerImageProofV1 {
    executable: LockedDeploymentFileProof,
    worker_manifest: LockedDeploymentFileProof,
    expected_executable_identity: DeploymentFileIdentityV1,
    expected_executable_sha256: String,
    expected_executable_bytes: u64,
    expected_manifest_identity: DeploymentFileIdentityV1,
    expected_manifest_sha256: String,
    expected_manifest_bytes: u64,
}

impl WindowsNwbWorkerImageProofV1 {
    pub(crate) fn new(
        executable: LockedDeploymentFileProof,
        worker_manifest: LockedDeploymentFileProof,
        expected_executable_identity: DeploymentFileIdentityV1,
        expected_executable_sha256: String,
        expected_executable_bytes: u64,
        expected_manifest_identity: DeploymentFileIdentityV1,
        expected_manifest_sha256: String,
        expected_manifest_bytes: u64,
    ) -> io::Result<Self> {
        let proof = Self {
            executable,
            worker_manifest,
            expected_executable_identity,
            expected_executable_sha256,
            expected_executable_bytes,
            expected_manifest_identity,
            expected_manifest_sha256,
            expected_manifest_bytes,
        };
        proof.validate_expectations()?;
        Ok(proof)
    }

    fn validate_expectations(&self) -> io::Result<()> {
        if !self.expected_executable_identity.is_directory
            && !self.expected_manifest_identity.is_directory
            && self.expected_executable_bytes > 0
            && self.expected_manifest_bytes > 0
            && valid_sha256_hex(&self.expected_executable_sha256)
            && valid_sha256_hex(&self.expected_manifest_sha256)
        {
            Ok(())
        } else {
            Err(permission(
                "NWB worker image proof has invalid identity/hash/size expectation",
            ))
        }
    }

    fn reverify(&mut self) -> io::Result<()> {
        self.validate_expectations()?;
        self.executable.require_expected(
            &self.expected_executable_identity,
            &self.expected_executable_sha256,
            self.expected_executable_bytes,
        )?;
        self.worker_manifest.require_expected(
            &self.expected_manifest_identity,
            &self.expected_manifest_sha256,
            self.expected_manifest_bytes,
        )?;
        Ok(())
    }

    pub(crate) fn executable_path(&self) -> &Path {
        self.executable.path()
    }

    pub(crate) fn worker_manifest_path(&self) -> &Path {
        self.worker_manifest.path()
    }
}

/// Retained generation-root evidence.  `relative_handle_resolution_qualified`
/// is intentionally explicit: a root identity alone is not production trust.
pub(crate) struct WindowsNwbGenerationRootProofV1 {
    root: PathBuf,
    root_identity: DeploymentFileIdentityV1,
    ancestors: LockedDeploymentAncestorChain,
    run_id: [u8; 16],
    relative_handle_resolution_qualified: bool,
}

/// Intentionally has no constructor or public fields.  No production code can
/// mint this token until the relative-handle-resolution gate is actually closed.
pub(crate) struct RelativeHandleResolutionQualifiedV1 {
    _private: (),
}

impl WindowsNwbGenerationRootProofV1 {
    pub(crate) fn new_production(
        root: PathBuf,
        root_identity: DeploymentFileIdentityV1,
        ancestors: LockedDeploymentAncestorChain,
        run_id: [u8; 16],
        _qualified: RelativeHandleResolutionQualifiedV1,
    ) -> io::Result<Self> {
        if !root.is_absolute() || !root_identity.is_directory || !run_id.iter().any(|b| *b != 0) {
            return Err(invalid(
                "NWB generation root proof requires absolute directory and nonzero Run ID",
            ));
        }
        let proof = Self {
            root,
            root_identity,
            ancestors,
            run_id,
            relative_handle_resolution_qualified: true,
        };
        proof.verify_root()
    }

    #[cfg(any(test, feature = "qualification-harness"))]
    pub(crate) fn new_engineering(
        root: PathBuf,
        root_identity: DeploymentFileIdentityV1,
        ancestors: LockedDeploymentAncestorChain,
        run_id: [u8; 16],
    ) -> io::Result<Self> {
        if !root.is_absolute() || !root_identity.is_directory || !run_id.iter().any(|b| *b != 0) {
            return Err(invalid(
                "NWB engineering root requires absolute directory and nonzero Run ID",
            ));
        }
        let proof = Self {
            root,
            root_identity,
            ancestors,
            run_id,
            relative_handle_resolution_qualified: false,
        };
        proof.verify_root()
    }

    fn verify_root(self) -> io::Result<Self> {
        if !self
            .ancestors
            .identities()
            .any(|identity| identity == &self.root_identity)
        {
            return Err(permission(
                "generation root is absent from retained ancestor proof",
            ));
        }
        Ok(self)
    }

    fn verify_for_launch(&self) -> io::Result<()> {
        if !self.relative_handle_resolution_qualified {
            // Engineering launches are permitted only under the explicitly
            // gated constructor; this flag is surfaced and never upgraded.
            #[cfg(not(any(test, feature = "qualification-harness")))]
            return Err(permission(
                "NWB generation root is not production-qualified",
            ));
        }
        if !self.root.is_absolute()
            || !self.root_identity.is_directory
            || !self.run_id.iter().any(|b| *b != 0)
        {
            return Err(permission("NWB generation root proof is invalid"));
        }
        require_canonical_deployment_path(&self.root, &self.root_identity)?;
        if inspect_stable_deployment_path(&self.root)? != self.root_identity {
            return Err(permission("generation root identity changed"));
        }
        Ok(())
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn run_id(&self) -> [u8; 16] {
        self.run_id
    }
    pub(crate) fn production_qualified(&self) -> bool {
        self.relative_handle_resolution_qualified
    }
}

pub(crate) struct WindowsNwbWorkerHandleV1 {
    process: Option<ContainedProcess>,
    identity: String,
    cached_wait: Option<ContainedProcessWaitEvidence>,
    cached_stop: Option<TerminalObservationV1>,
    engineering_evidence: bool,
}

impl WindowsNwbWorkerHandleV1 {
    fn new(process: ContainedProcess, engineering_evidence: bool) -> io::Result<Self> {
        let id = process.identity();
        let identity = format!(
            "pid={};creation_time_100ns={};exe_sha256={}",
            id.pid,
            id.creation_time_100ns,
            hex_digest(id.executable_sha256),
        );
        if identity.is_empty() {
            return Err(permission("contained worker identity is empty"));
        }
        Ok(Self {
            process: Some(process),
            identity,
            cached_wait: None,
            cached_stop: None,
            engineering_evidence,
        })
    }

    pub(crate) fn typed_identity(
        &self,
    ) -> &crate::windows_contained_process::ContainedProcessIdentity {
        self.process
            .as_ref()
            .expect("active worker process retained")
            .identity()
    }
    pub(crate) fn cached_wait_evidence(&self) -> Option<ContainedProcessWaitEvidence> {
        self.cached_wait
    }
    pub(crate) fn cached_stop_observation(&self) -> Option<&TerminalObservationV1> {
        self.cached_stop.as_ref()
    }
    pub(crate) fn engineering_evidence(&self) -> bool {
        self.engineering_evidence
    }
}

impl NwbWorkerHandle for WindowsNwbWorkerHandleV1 {
    fn identity(&self) -> &str {
        &self.identity
    }

    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        let process = self
            .process
            .as_mut()
            .ok_or_else(|| invalid("worker handle already terminal"))?;
        match process.query_exit_code()? {
            None => Ok(None),
            Some(_) => {
                let evidence = process.wait_for_exit(Duration::from_secs(2))?;
                let code = evidence.exit_code as i32;
                self.cached_wait = Some(evidence);
                Ok(Some(code))
            }
        }
    }

    fn request_stop(&mut self) -> io::Result<()> {
        let process = self
            .process
            .as_mut()
            .ok_or_else(|| invalid("worker handle already terminal"))?;
        if process.query_exit_code()?.is_some() {
            let evidence = process.wait_for_exit(STOP_BUDGET)?;
            self.cached_wait = Some(evidence);
            return Ok(());
        }
        let observation = process.terminate_and_observe(STOP_BUDGET);
        let success = observation.primary_wait_observed
            && observation.job_active_processes == Some(0)
            && observation.query_error.is_none()
            && observation.terminate_error.is_none()
            && observation.wait_error.is_none();
        self.cached_stop = Some(observation);
        if success {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "contained NWB worker stop was not proven",
            ))
        }
    }
}

pub(crate) struct WindowsNwbWorkerLauncherV1 {
    image: WindowsNwbWorkerImageProofV1,
    session_manifest: Option<LockedDeploymentFileProof>,
    root: WindowsNwbGenerationRootProofV1,
    environment: Vec<(OsString, OsString)>,
    current_directory: PathBuf,
    poll_interval_ms: u16,
}

impl WindowsNwbWorkerLauncherV1 {
    pub(crate) fn new(
        image: WindowsNwbWorkerImageProofV1,
        session_manifest: LockedDeploymentFileProof,
        root: WindowsNwbGenerationRootProofV1,
        environment: Vec<(OsString, OsString)>,
        current_directory: PathBuf,
        poll_interval_ms: u16,
    ) -> io::Result<Self> {
        validate_poll_interval_ms(poll_interval_ms)?;
        if !current_directory.is_absolute() {
            return Err(invalid("worker current directory must be absolute"));
        }
        let _ = ContainedProcessLaunchOptions::explicit(
            environment.clone(),
            current_directory.clone(),
        )?;
        Ok(Self {
            image,
            session_manifest: Some(session_manifest),
            root,
            environment,
            current_directory,
            poll_interval_ms,
        })
    }

    fn command_for(
        &mut self,
        request: &NwbGenerationLaunchV1,
    ) -> io::Result<(Vec<OsString>, ContainedProcessLaunchOptions)> {
        self.root.verify_for_launch()?;
        self.image.reverify()?;
        if request.run_id != self.root.run_id() {
            return Err(permission("NWB launch Run ID differs from root proof"));
        }
        if request.generation == 0 || request.rebuild_from_journal_sequence != 0 {
            return Err(invalid("NWB launch generation/rebuild cursor invalid"));
        }
        let dir = request
            .paths
            .nwb_inprogress
            .parent()
            .ok_or_else(|| invalid("NWB inprogress path has no parent"))?;
        if !dir.is_absolute() || dir.parent() != Some(self.root.root()) {
            return Err(permission("generation directory is outside retained root"));
        }
        let expected_dir = format!("generation-{:08}", request.generation);
        if dir.file_name().and_then(|v| v.to_str()) != Some(expected_dir.as_str()) {
            return Err(invalid("generation directory is non-canonical"));
        }
        for path in [
            &request.paths.nwb_inprogress,
            &request.paths.session_manifest,
            &request.paths.validation_report,
            &request.paths.receipt,
        ] {
            if !path.is_absolute() || path.parent() != Some(dir) {
                return Err(invalid(
                    "NWB launch artifact path is not same-directory absolute",
                ));
            }
        }
        if !request.paths.session_manifest.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "session manifest must pre-exist",
            ));
        }
        let session_manifest = self
            .session_manifest
            .as_mut()
            .ok_or_else(|| invalid("session manifest proof was already consumed"))?;
        if session_manifest.path() != request.paths.session_manifest {
            return Err(permission(
                "session manifest proof does not match launch path",
            ));
        }
        let manifest_bytes = session_manifest.read_bounded(1_048_576)?;
        verify_session_manifest(&manifest_bytes, request)?;
        let options = ContainedProcessLaunchOptions::explicit(
            self.environment.clone(),
            self.current_directory.clone(),
        )?;
        let args = vec![
            OsString::from("--manifest"),
            request.paths.session_manifest.as_os_str().to_owned(),
            OsString::from("--mode"),
            OsString::from("live"),
            OsString::from("--checkpoint"),
            OsString::from(format!(
                "{}.checkpoint.json",
                request.paths.nwb_inprogress.display()
            )),
            OsString::from("--report"),
            request.paths.validation_report.as_os_str().to_owned(),
            OsString::from("--receipt"),
            request.paths.receipt.as_os_str().to_owned(),
            OsString::from("--validation-sequence"),
            OsString::from(request.generation.to_string()),
            OsString::from("--poll-interval-ms"),
            OsString::from(self.poll_interval_ms.to_string()),
        ];
        Ok((args, options))
    }
}

/// Semantic verification of the already proof-bound session manifest.  This
/// intentionally does not claim canonical JSON: the retained bytes/hash prove
/// stability, while these checks prove the values used by this launch.
fn verify_session_manifest(bytes: &[u8], request: &NwbGenerationLaunchV1) -> io::Result<()> {
    const MAX_SESSION_MANIFEST_BYTES: usize = 1_048_576;
    if request.run_id == [0; 16]
        || request.generation == 0
        || request.rebuild_from_journal_sequence != 0
        || !request.paths.journal.is_absolute()
        || !request.paths.nwb_inprogress.is_absolute()
    {
        return Err(invalid(
            "launch request identity, rebuild cursor, or paths are invalid",
        ));
    }
    if bytes.len() > MAX_SESSION_MANIFEST_BYTES {
        return Err(invalid("session manifest exceeds bounded size"));
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("session manifest JSON is invalid: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("session manifest must be a JSON object"))?;
    if object.get("manifest_version").and_then(Value::as_u64) != Some(1) {
        return Err(permission("session manifest version is not 1"));
    }
    if object.get("protocol_contract_hash").and_then(Value::as_str)
        != Some(forge_protocol_v1::PROTOCOL_HASH_HEX)
    {
        return Err(permission(
            "session manifest protocol contract hash is not Forge v1",
        ));
    }
    if object
        .get("pods")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        return Err(invalid("session manifest pods must be a nonempty array"));
    }
    let string = |name: &str| -> io::Result<&str> {
        object
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("session manifest field {name} must be a string")))
    };
    if string("run_id")? != format_run_id(request.run_id) {
        return Err(permission("session manifest Run ID differs from launch"));
    }
    if object.get("generation").and_then(Value::as_u64) != Some(u64::from(request.generation)) {
        return Err(permission(
            "session manifest generation differs from launch",
        ));
    }
    if !paths_equal(string("journal_path")?, &request.paths.journal)? {
        return Err(permission(
            "session manifest journal path differs from launch",
        ));
    }
    if !paths_equal(string("inprogress_path")?, &request.paths.nwb_inprogress)? {
        return Err(permission(
            "session manifest inprogress path differs from launch",
        ));
    }
    let final_path = PathBuf::from(string("final_path")?);
    if !final_path.is_absolute() || final_path.extension().and_then(|v| v.to_str()) != Some("nwb") {
        return Err(invalid(
            "session manifest final_path must be absolute and end in .nwb",
        ));
    }
    if final_path.parent() != request.paths.nwb_inprogress.parent() {
        return Err(permission(
            "session manifest final_path is not generation-local",
        ));
    }
    let expected_inprogress = format!(
        "{}.g{:04}.nwb.inprogress",
        final_path
            .file_stem()
            .and_then(|v| v.to_str())
            .ok_or_else(|| invalid("final_path has no UTF-8 stem"))?,
        request.generation
    );
    if request
        .paths
        .nwb_inprogress
        .file_name()
        .and_then(|v| v.to_str())
        != Some(expected_inprogress.as_str())
    {
        return Err(permission(
            "inprogress filename does not match manifest final_path/generation",
        ));
    }
    Ok(())
}

fn format_run_id(run_id: [u8; 16]) -> String {
    let bytes = run_id;
    format!(
        "{}-{}-{}-{}-{}",
        bytes[0..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        bytes[4..6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        bytes[6..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        bytes[8..10]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        bytes[10..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )
}

fn paths_equal(manifest: &str, expected: &Path) -> io::Result<bool> {
    let supplied = PathBuf::from(manifest);
    if !supplied.is_absolute() || supplied != expected {
        return Ok(false);
    }
    Ok(true)
}

impl NwbWorkerLauncher for WindowsNwbWorkerLauncherV1 {
    fn launch(&mut self, request: &NwbGenerationLaunchV1) -> io::Result<Box<dyn NwbWorkerHandle>> {
        let (args, options) = self.command_for(request)?;
        // Consume the generation-specific proof before process creation. A
        // failed CreateProcess/Job/image-reverify attempt must not be retried
        // against the same generation or manifest; the owner has to reserve a
        // new generation and construct a fresh one-shot launcher.
        let mut session_manifest = self
            .session_manifest
            .take()
            .ok_or_else(|| invalid("session manifest proof was already consumed"))?;
        self.image.reverify()?;
        let process = ContainedProcess::spawn_verified_with_options(
            &mut self.image.executable,
            &args,
            &options,
        )?;
        self.image.reverify()?;
        session_manifest.reverify()?;
        let handle = WindowsNwbWorkerHandleV1::new(process, !self.root.production_qualified())?;
        Ok(Box::new(handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nwb_receipt::NwbValidationBundlePaths;

    fn request() -> NwbGenerationLaunchV1 {
        let directory = PathBuf::from(r"C:\forge\generations\generation-00000007");
        NwbGenerationLaunchV1 {
            run_id: [1; 16],
            generation: 7,
            rebuild_from_journal_sequence: 0,
            paths: NwbValidationBundlePaths::for_generation(
                directory.join("validation.receipt"),
                PathBuf::from(r"C:\forge\run.wal"),
                directory.join("session.g0007.nwb.inprogress"),
                directory.join("session.g0007.json"),
                directory.join("validation-report.json"),
            ),
        }
    }

    fn manifest(request: &NwbGenerationLaunchV1) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "manifest_version": 1,
            "run_id": format_run_id(request.run_id),
            "generation": request.generation,
            "protocol_contract_hash": forge_protocol_v1::PROTOCOL_HASH_HEX,
            "journal_path": request.paths.journal,
            "inprogress_path": request.paths.nwb_inprogress,
            "final_path": r"C:\forge\generations\generation-00000007\session.nwb",
            "pods": [{"canonical_pod_id": "00000000000000000000000000000001"}],
        }))
        .unwrap()
    }

    #[test]
    fn valid_manifest_is_accepted() {
        let request = request();
        assert!(verify_session_manifest(&manifest(&request), &request).is_ok());
    }

    #[test]
    fn manifest_identity_and_path_mismatches_are_rejected() {
        let request = request();
        for (field, value) in [
            ("run_id", "00000000-0000-0000-0000-000000000000"),
            ("journal_path", r"C:\wrong.wal"),
            ("inprogress_path", r"C:\wrong.nwb.inprogress"),
        ] {
            let mut value_json: Value = serde_json::from_slice(&manifest(&request)).unwrap();
            value_json[field] = Value::String(value.to_owned());
            assert!(
                verify_session_manifest(&serde_json::to_vec(&value_json).unwrap(), &request)
                    .is_err()
            );
        }
        let mut wrong_generation: Value = serde_json::from_slice(&manifest(&request)).unwrap();
        wrong_generation["generation"] = Value::from(8_u64);
        assert!(
            verify_session_manifest(&serde_json::to_vec(&wrong_generation).unwrap(), &request)
                .is_err()
        );
    }

    #[test]
    fn manifest_version_protocol_pods_and_final_stem_are_admission_fields() {
        let request = request();
        for (field, value) in [
            ("manifest_version", Value::from(2_u64)),
            ("protocol_contract_hash", Value::String("00".repeat(32))),
            ("pods", Value::Array(Vec::new())),
            ("final_path", Value::String(r"relative.nwb".to_owned())),
            (
                "final_path",
                Value::String(r"C:\forge\generations\generation-00000007\other.nwb".to_owned()),
            ),
        ] {
            let mut value_json: Value = serde_json::from_slice(&manifest(&request)).unwrap();
            value_json[field] = value;
            assert!(
                verify_session_manifest(&serde_json::to_vec(&value_json).unwrap(), &request)
                    .is_err()
            );
        }
    }

    #[test]
    fn invalid_or_oversized_json_is_rejected() {
        let request = request();
        assert!(verify_session_manifest(b"not-json", &request).is_err());
        assert!(verify_session_manifest(&vec![b' '; 1_048_577], &request).is_err());
    }

    #[test]
    fn launcher_input_and_sha256_validators_are_fail_closed() {
        assert!(valid_sha256_hex(&"a".repeat(64)));
        assert!(!valid_sha256_hex(&"0".repeat(64)));
        assert!(!valid_sha256_hex(&"A".repeat(64)));
        assert!(!valid_sha256_hex(&format!("{}g", "a".repeat(63))));
        assert!(validate_poll_interval_ms(1).is_ok());
        assert!(validate_poll_interval_ms(2_000).is_ok());
        assert!(validate_poll_interval_ms(0).is_err());
        assert!(validate_poll_interval_ms(2_001).is_err());

        let mut invalid_request = request();
        invalid_request.generation = 0;
        assert!(verify_session_manifest(&manifest(&request()), &invalid_request).is_err());
        invalid_request = request();
        invalid_request.rebuild_from_journal_sequence = 1;
        assert!(verify_session_manifest(&manifest(&request()), &invalid_request).is_err());
    }
}
