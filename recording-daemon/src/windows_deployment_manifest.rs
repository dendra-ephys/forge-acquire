//! Immutable Windows service deployment identity for Forge Acquire.
//!
//! The manifest binds an SCM launch to the exact executable bytes and protected
//! deployment paths approved at install time. Its SHA-256 is local integrity
//! evidence only; it is neither a signature nor an attestation. Callers must
//! independently verify the DACL contracts named by this file.

#![cfg(windows)]

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use forge_protocol_v1::sha256;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

use crate::windows_deployment_security::{
    inspect_stable_deployment_path, lock_deployment_file_proof, DeploymentFileIdentityV1,
    LockedDeploymentAncestorChain, LockedDeploymentFileProof,
};
use crate::windows_service_host::{ServiceHostConfig, SERVICE_NAME};

pub const DEPLOYMENT_MANIFEST_SCHEMA: &str = "forge.windows-deployment-manifest.v1";
// MoveFileExW documents this as the rename write-through barrier.  It does
// not prove directory-metadata survival through a real power cut; NTFS/PLP
// power-cut qualification remains an external administrative release gate.
const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentDaclBindingsV1 {
    pub service_object_contract_sha256_hex: String,
    pub executable_parent_contract_sha256_hex: String,
    pub executable_contract_sha256_hex: String,
    pub data_root_contract_sha256_hex: String,
    pub manifest_contract_sha256_hex: String,
    pub service_object_protected_and_exact: bool,
    pub executable_parent_protected_and_exact: bool,
    pub executable_protected_and_exact: bool,
    pub data_root_protected_and_exact: bool,
    pub manifest_protected_and_exact: bool,
    /// Runtime named-pipe ACL readback is a later live-SCM gate and must not be
    /// inferred from an install-time filesystem manifest.
    pub runtime_pipe_dacl_qualified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsDeploymentManifestV1 {
    pub schema: String,
    pub service_name: String,
    pub service_sid: String,
    pub manifest_path: String,
    pub executable_path: String,
    pub executable_sha256_hex: String,
    pub executable_bytes: u64,
    pub executable_file_identity: DeploymentFileIdentityV1,
    pub data_root: String,
    pub operator_sid: String,
    pub public_control_pipe_name: String,
    pub public_hardware_pipe_name: String,
    pub analysis_worker_sid: Option<String>,
    pub public_analysis_pipe_name: Option<String>,
    pub direct_pod_policy_path: Option<String>,
    pub direct_pod_policy_sha256_hex: Option<String>,
    pub internal_approval_authority_sha256_hex: Option<String>,
    pub dacl: DeploymentDaclBindingsV1,
    pub evidence_sha256_hex: String,
    pub evidence_hash_is_signature_or_attestation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsDeploymentManifestExpectationV1 {
    pub manifest_path: PathBuf,
    pub executable_path: PathBuf,
    pub executable_sha256_hex: String,
    pub executable_bytes: u64,
    pub service_sid: String,
    pub service_config: ServiceHostConfig,
}

pub struct LockedWindowsDeploymentManifestV1 {
    manifest: WindowsDeploymentManifestV1,
    _file_proof: LockedDeploymentFileProof,
}

impl LockedWindowsDeploymentManifestV1 {
    pub fn manifest(&self) -> &WindowsDeploymentManifestV1 {
        &self.manifest
    }
}

impl WindowsDeploymentManifestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        manifest_path: &Path,
        executable_path: &Path,
        executable_sha256_hex: &str,
        executable_bytes: u64,
        service_sid: &str,
        service_config: &ServiceHostConfig,
        dacl: DeploymentDaclBindingsV1,
    ) -> io::Result<Self> {
        let manifest_path = absolute_utf8_path(manifest_path, false)?;
        let executable_path = canonical_utf8_path(executable_path, true)?;
        let executable_file_identity = inspect_stable_deployment_path(Path::new(&executable_path))?;
        Self::build_with_executable_identity(
            manifest_path,
            executable_path,
            executable_sha256_hex,
            executable_bytes,
            executable_file_identity,
            service_sid,
            service_config,
            dacl,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_with_executable_identity(
        manifest_path: String,
        executable_path: String,
        executable_sha256_hex: &str,
        executable_bytes: u64,
        executable_file_identity: DeploymentFileIdentityV1,
        service_sid: &str,
        service_config: &ServiceHostConfig,
        dacl: DeploymentDaclBindingsV1,
    ) -> io::Result<Self> {
        if executable_file_identity.bytes != executable_bytes
            || executable_file_identity.link_count != 1
        {
            return Err(invalid_data(
                "deployment executable stable identity is unsafe or size-mismatched",
            ));
        }
        let data_root = canonical_utf8_path(&service_config.data_root, false)?;
        let direct = service_config.direct_pod_policy.as_ref();
        let mut value = Self {
            schema: DEPLOYMENT_MANIFEST_SCHEMA.to_owned(),
            service_name: SERVICE_NAME.to_owned(),
            service_sid: service_sid.to_owned(),
            manifest_path,
            executable_path,
            executable_sha256_hex: executable_sha256_hex.to_owned(),
            executable_bytes,
            executable_file_identity,
            data_root,
            operator_sid: service_config.operator_sid.clone(),
            public_control_pipe_name: service_config.pipe_name.clone(),
            public_hardware_pipe_name: service_config.hardware_pipe_name.clone(),
            analysis_worker_sid: service_config.analysis_worker_sid.clone(),
            public_analysis_pipe_name: service_config
                .analysis_worker_sid
                .as_ref()
                .map(|_| service_config.analysis_pipe_name.clone()),
            direct_pod_policy_path: direct
                .map(|policy| canonical_utf8_path(policy.path(), true))
                .transpose()?,
            direct_pod_policy_sha256_hex: direct.map(|policy| policy.expected_file_sha256_hex()),
            internal_approval_authority_sha256_hex: direct
                .map(|policy| policy.expected_approval_authority_sha256_hex()),
            dacl,
            evidence_sha256_hex: String::new(),
            evidence_hash_is_signature_or_attestation: false,
        };
        value.evidence_sha256_hex = evidence_hash(&value)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.schema != DEPLOYMENT_MANIFEST_SCHEMA
            || self.service_name != SERVICE_NAME
            || self.evidence_hash_is_signature_or_attestation
            || !is_service_sid(&self.service_sid)
            || !is_lower_hex(&self.executable_sha256_hex, 64, true)
            || self.executable_bytes == 0
            || self.executable_file_identity.is_directory
            || self.executable_file_identity.canonical_path != self.executable_path
            || self.executable_file_identity.bytes != self.executable_bytes
            || self.executable_file_identity.link_count != 1
            || !is_absolute_path_string(&self.manifest_path)
            || !is_absolute_path_string(&self.executable_path)
            || !is_absolute_path_string(&self.data_root)
            || !is_local_pipe(&self.public_control_pipe_name)
            || !is_local_pipe(&self.public_hardware_pipe_name)
            || self
                .public_control_pipe_name
                .eq_ignore_ascii_case(&self.public_hardware_pipe_name)
            || !is_lower_hex(&self.evidence_sha256_hex, 64, true)
            || self.evidence_sha256_hex != evidence_hash(self)?
        {
            return Err(invalid_data(
                "Windows deployment manifest identity is invalid",
            ));
        }
        let analysis_enabled = self.analysis_worker_sid.is_some();
        if analysis_enabled != self.public_analysis_pipe_name.is_some()
            || self.public_analysis_pipe_name.as_ref().is_some_and(|pipe| {
                !is_local_pipe(pipe)
                    || pipe.eq_ignore_ascii_case(&self.public_control_pipe_name)
                    || pipe.eq_ignore_ascii_case(&self.public_hardware_pipe_name)
            })
        {
            return Err(invalid_data(
                "deployment analysis endpoint binding is invalid",
            ));
        }
        let direct_shape = (
            self.direct_pod_policy_path.is_some(),
            self.direct_pod_policy_sha256_hex.is_some(),
            self.internal_approval_authority_sha256_hex.is_some(),
        );
        if !matches!(direct_shape, (false, false, false) | (true, true, true))
            || self
                .direct_pod_policy_path
                .as_ref()
                .is_some_and(|path| !is_absolute_path_string(path))
            || self
                .direct_pod_policy_sha256_hex
                .as_ref()
                .is_some_and(|hash| !is_lower_hex(hash, 64, true))
            || self
                .internal_approval_authority_sha256_hex
                .as_ref()
                .is_some_and(|hash| !is_lower_hex(hash, 64, true))
        {
            return Err(invalid_data(
                "deployment direct-Pod policy binding is invalid",
            ));
        }
        for hash in [
            &self.dacl.service_object_contract_sha256_hex,
            &self.dacl.executable_parent_contract_sha256_hex,
            &self.dacl.executable_contract_sha256_hex,
            &self.dacl.data_root_contract_sha256_hex,
            &self.dacl.manifest_contract_sha256_hex,
        ] {
            if !is_lower_hex(hash, 64, true) {
                return Err(invalid_data("deployment DACL contract hash is invalid"));
            }
        }
        if !self.dacl.service_object_protected_and_exact
            || !self.dacl.executable_parent_protected_and_exact
            || !self.dacl.executable_protected_and_exact
            || !self.dacl.data_root_protected_and_exact
            || !self.dacl.manifest_protected_and_exact
        {
            return Err(invalid_data(
                "deployment manifest cannot bind an unverified protected DACL",
            ));
        }
        Ok(())
    }
}

pub(crate) fn publish_windows_deployment_manifest_v1(
    manifest: &WindowsDeploymentManifestV1,
    ancestors: &LockedDeploymentAncestorChain,
) -> io::Result<()> {
    manifest.validate()?;
    let path = Path::new(&manifest.manifest_path);
    if path.exists() || path.parent().is_none_or(|parent| !parent.is_dir()) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "deployment manifest path exists or has no existing parent",
        ));
    }
    let pending = path.with_extension("pending");
    if pending.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "deployment manifest pending path already exists",
        ));
    }
    let bytes = serde_json::to_vec(manifest).map_err(json_error)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(&bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    rename_no_overwrite(&pending, path)?;
    let proof = lock_deployment_file_proof(path, ancestors)?;
    let loaded = load_canonical_locked(proof)?;
    if loaded.manifest != *manifest {
        return Err(invalid_data(
            "published deployment manifest differs from the requested bytes",
        ));
    }
    Ok(())
}

pub(crate) fn load_and_verify_windows_deployment_manifest_v1(
    expected: &WindowsDeploymentManifestExpectationV1,
    mut manifest_proof: LockedDeploymentFileProof,
    executable_proof: &mut LockedDeploymentFileProof,
) -> io::Result<LockedWindowsDeploymentManifestV1> {
    validate_expectation(expected)?;
    if !manifest_proof.proves_path(&expected.manifest_path)?
        || !executable_proof.proves_path(&expected.executable_path)?
        || executable_proof.sha256_hex() != expected.executable_sha256_hex
        || executable_proof.identity().bytes != expected.executable_bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment file proofs differ from the trusted startup paths or executable bytes",
        ));
    }
    let locked = load_canonical_locked(manifest_proof)?;
    let value = &locked.manifest;
    let config = &expected.service_config;
    let direct = config.direct_pod_policy.as_ref();
    let expected_executable = canonical_utf8_path(&expected.executable_path, true)?;
    let observed_identity = executable_proof.identity();
    let expected_data_root = canonical_utf8_path(&config.data_root, false)?;
    if value.manifest_path != absolute_utf8_path(&expected.manifest_path, true)?
        || value.executable_path != expected_executable
        || value.executable_sha256_hex != expected.executable_sha256_hex
        || value.executable_bytes != expected.executable_bytes
        || &value.executable_file_identity != observed_identity
        || value.service_sid != expected.service_sid
        || value.data_root != expected_data_root
        || value.operator_sid != config.operator_sid
        || value.public_control_pipe_name != config.pipe_name
        || value.public_hardware_pipe_name != config.hardware_pipe_name
        || value.analysis_worker_sid != config.analysis_worker_sid
        || value.public_analysis_pipe_name
            != config
                .analysis_worker_sid
                .as_ref()
                .map(|_| config.analysis_pipe_name.clone())
        || value.direct_pod_policy_path
            != direct
                .map(|policy| canonical_utf8_path(policy.path(), true))
                .transpose()?
        || value.direct_pod_policy_sha256_hex
            != direct.map(|policy| policy.expected_file_sha256_hex())
        || value.internal_approval_authority_sha256_hex
            != direct.map(|policy| policy.expected_approval_authority_sha256_hex())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment manifest differs from the frozen SCM/runtime expectation",
        ));
    }
    executable_proof.require_expected(
        &value.executable_file_identity,
        &value.executable_sha256_hex,
        value.executable_bytes,
    )?;
    Ok(locked)
}

fn load_canonical_locked(
    mut proof: LockedDeploymentFileProof,
) -> io::Result<LockedWindowsDeploymentManifestV1> {
    let bytes = proof.read_bounded(1024 * 1024)?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(invalid_data("deployment manifest is empty or oversized"));
    }
    let manifest: WindowsDeploymentManifestV1 =
        serde_json::from_slice(&bytes).map_err(json_error)?;
    if serde_json::to_vec(&manifest).map_err(json_error)? != bytes {
        return Err(invalid_data("deployment manifest JSON is not canonical"));
    }
    manifest.validate()?;
    Ok(LockedWindowsDeploymentManifestV1 {
        manifest,
        _file_proof: proof,
    })
}

fn validate_expectation(expected: &WindowsDeploymentManifestExpectationV1) -> io::Result<()> {
    if !expected.manifest_path.is_absolute()
        || !expected.executable_path.is_absolute()
        || !is_lower_hex(&expected.executable_sha256_hex, 64, true)
        || expected.executable_bytes == 0
        || !is_service_sid(&expected.service_sid)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "deployment manifest expectation is malformed",
        ));
    }
    Ok(())
}

fn evidence_hash(value: &WindowsDeploymentManifestV1) -> io::Result<String> {
    let mut normalized = value.clone();
    normalized.evidence_sha256_hex.clear();
    Ok(hex(&sha256(
        &serde_json::to_vec(&normalized).map_err(json_error)?,
    )))
}

fn canonical_utf8_path(path: &Path, require_file: bool) -> io::Result<String> {
    let canonical = std::fs::canonicalize(path)?;
    let metadata = canonical.metadata()?;
    if (require_file && !metadata.is_file()) || (!require_file && !metadata.is_dir()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "deployment path has the wrong filesystem type",
        ));
    }
    canonical
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not Unicode"))
}

fn absolute_utf8_path(path: &Path, require_existing_file: bool) -> io::Result<String> {
    if !path.is_absolute() || path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "manifest path must be absolute Unicode without NUL",
        ));
    }
    if require_existing_file && !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "manifest path is not an existing file",
        ));
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not Unicode"))
}

fn rename_no_overwrite(source: &Path, destination: &Path) -> io::Result<()> {
    let source = wide(source)?;
    let destination = wide(destination)?;
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains NUL",
        ));
    }
    value.push(0);
    Ok(value)
}

fn is_absolute_path_string(value: &str) -> bool {
    !value.is_empty() && !value.contains('\0') && Path::new(value).is_absolute()
}

fn is_local_pipe(value: &str) -> bool {
    value
        .strip_prefix(r"\\.\pipe\")
        .is_some_and(|suffix| !suffix.is_empty() && !suffix.contains('\\') && suffix.len() <= 220)
}

fn is_service_sid(value: &str) -> bool {
    let fields = value.split('-').collect::<Vec<_>>();
    fields.len() == 9
        && fields[..4] == ["S", "1", "5", "80"]
        && fields[4..]
            .iter()
            .all(|field| !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_lower_hex(value: &str, length: usize, require_nonzero: bool) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && (!require_nonzero || value.bytes().any(|byte| byte != b'0'))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn json_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_deployment_security::{
        lock_test_deployment_ancestor_chain, LockedDeploymentFileProof,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "forge-deployment-manifest-{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn config(root: &Path) -> ServiceHostConfig {
        ServiceHostConfig {
            data_root: root.to_path_buf(),
            operator_sid: "S-1-5-21-1-2-3-4".to_owned(),
            pipe_name: r"\\.\pipe\forge-manifest-control".to_owned(),
            hardware_pipe_name: r"\\.\pipe\forge-manifest-hardware".to_owned(),
            analysis_worker_sid: None,
            analysis_pipe_name: r"\\.\pipe\forge-manifest-analysis".to_owned(),
            direct_pod_policy: None,
        }
    }

    fn dacl() -> DeploymentDaclBindingsV1 {
        DeploymentDaclBindingsV1 {
            service_object_contract_sha256_hex: "11".repeat(32),
            executable_parent_contract_sha256_hex: "22".repeat(32),
            executable_contract_sha256_hex: "33".repeat(32),
            data_root_contract_sha256_hex: "44".repeat(32),
            manifest_contract_sha256_hex: "55".repeat(32),
            service_object_protected_and_exact: true,
            executable_parent_protected_and_exact: true,
            executable_protected_and_exact: true,
            data_root_protected_and_exact: true,
            manifest_protected_and_exact: true,
            runtime_pipe_dacl_qualified: false,
        }
    }

    fn proof(path: &Path) -> LockedDeploymentFileProof {
        let ancestors = lock_test_deployment_ancestor_chain(path.parent().unwrap()).unwrap();
        lock_deployment_file_proof(path, &ancestors).unwrap()
    }

    fn load_test(
        expected: &WindowsDeploymentManifestExpectationV1,
    ) -> io::Result<LockedWindowsDeploymentManifestV1> {
        let mut executable_proof = proof(&expected.executable_path);
        load_and_verify_windows_deployment_manifest_v1(
            expected,
            proof(&expected.manifest_path),
            &mut executable_proof,
        )
    }

    #[test]
    fn manifest_publish_load_and_expectation_are_exact_and_no_overwrite() {
        let root = test_root("roundtrip");
        let executable = root.join("forge-acqd.exe");
        std::fs::write(&executable, b"fixture executable").unwrap();
        let path = root.join("deployment-v1.json");
        let config = config(&root);
        let manifest = WindowsDeploymentManifestV1::build(
            &path,
            &executable,
            &hex(&sha256(b"fixture executable")),
            18,
            "S-1-5-80-1-2-3-4-5",
            &config,
            dacl(),
        )
        .unwrap();
        let ancestors = lock_test_deployment_ancestor_chain(&root).unwrap();
        publish_windows_deployment_manifest_v1(&manifest, &ancestors).unwrap();
        assert!(publish_windows_deployment_manifest_v1(&manifest, &ancestors).is_err());
        let wrong_executable = root.join("wrong-forge-acqd.exe");
        std::fs::write(&wrong_executable, b"fixture executable").unwrap();
        let expected_identity = WindowsDeploymentManifestExpectationV1 {
            manifest_path: path.clone(),
            executable_path: executable.clone(),
            executable_sha256_hex: hex(&sha256(b"fixture executable")),
            executable_bytes: 18,
            service_sid: "S-1-5-80-1-2-3-4-5".to_owned(),
            service_config: config.clone(),
        };
        let mut wrong_proof = proof(&wrong_executable);
        assert!(load_and_verify_windows_deployment_manifest_v1(
            &expected_identity,
            proof(&path),
            &mut wrong_proof,
        )
        .is_err());
        drop(wrong_proof);
        assert!(load_test(&WindowsDeploymentManifestExpectationV1 {
            manifest_path: path.clone(),
            executable_path: executable.clone(),
            executable_sha256_hex: hex(&sha256(b"fixture executable")),
            executable_bytes: 18,
            service_sid: "S-1-5-80-6-7-8-9-10".to_owned(),
            service_config: config.clone(),
        })
        .is_err());
        let locked = load_test(&WindowsDeploymentManifestExpectationV1 {
            manifest_path: path.clone(),
            executable_path: executable.clone(),
            executable_sha256_hex: hex(&sha256(b"fixture executable")),
            executable_bytes: 18,
            service_sid: "S-1-5-80-1-2-3-4-5".to_owned(),
            service_config: config,
        })
        .unwrap();
        assert_eq!(locked.manifest(), &manifest);
        drop(locked);
        drop(ancestors);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(wrong_executable).unwrap();
        std::fs::remove_file(executable).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn manifest_tamper_unknown_fields_and_unqualified_dacl_fail_closed() {
        let root = test_root("tamper");
        let executable = root.join("forge-acqd.exe");
        std::fs::write(&executable, b"fixture executable").unwrap();
        let path = root.join("deployment-v1.json");
        let config = config(&root);
        let mut manifest = WindowsDeploymentManifestV1::build(
            &path,
            &executable,
            &hex(&sha256(b"fixture executable")),
            18,
            "S-1-5-80-1-2-3-4-5",
            &config,
            dacl(),
        )
        .unwrap();
        manifest.dacl.executable_protected_and_exact = false;
        assert!(manifest.validate().is_err());
        manifest.dacl.executable_protected_and_exact = true;
        manifest.evidence_sha256_hex = evidence_hash(&manifest).unwrap();
        let mut value = serde_json::to_value(&manifest).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::json!(true));
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load_canonical_locked(proof(&path)).is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(executable).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn service_sid_requires_exact_service_authority_shape() {
        assert!(is_service_sid("S-1-5-80-1-2-3-4-5"));
        assert!(!is_service_sid("S-1-5-80-1-2-3-4"));
        assert!(!is_service_sid("S-1-5-80-1-2-3-4-5-6"));
        assert!(!is_service_sid("S-1-5-81-1-2-3-4-5"));
        assert!(!is_service_sid("S-1-5-80-1-2-3-4-x"));
    }
}
