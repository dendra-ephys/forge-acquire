//! Fail-closed deployment ACL qualification for Forge Acquire on Windows.
//!
//! This module intentionally operates on already-existing objects.  It never
//! creates a service, a directory, or a file, and it never invokes a shell.
//! The caller must still bind the verified executable and data root to a
//! protected deployment volume before treating this evidence as a deployment
//! gate.  A file SHA-256 returned here is a handle-bound local-integrity
//! observation, **not** a signature or an authorization decision.

#![cfg(windows)]

use std::ffi::c_void;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, IsValidSecurityDescriptor, IsValidSid, ACL,
    DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PRESENT, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileAttributeTagInfo, FileDispositionInfo, FlushFileBuffers, GetDriveTypeW,
    GetFileAttributesW, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, ReadFile, SetFileInformationByHandle,
    SetFilePointerEx, WriteFile, BY_HANDLE_FILE_INFORMATION, CREATE_NEW, DELETE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_BEGIN,
    FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, OPEN_EXISTING,
    READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Services::{
    QueryServiceObjectSecurity, SetServiceObjectSecurity, SERVICE_INTERROGATE,
    SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STOP,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};

const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const MAX_SID_U16: usize = 256;
const MAX_SERVICE_SECURITY_DESCRIPTOR_BYTES: usize = 128 * 1024;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;
const DRIVE_FIXED: u32 = 3;
const FILE_WRITE_DATA_OR_ADD_FILE: u32 = 0x0000_0002;
const FILE_APPEND_DATA_OR_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
const FILE_WRITE_EA: u32 = 0x0000_0010;
const FILE_DELETE_CHILD: u32 = 0x0000_0040;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE_RIGHT: u32 = 0x0001_0000;
const WRITE_DAC_MASK: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const DANGEROUS_REPLACEMENT_RIGHTS: u32 = GENERIC_ALL
    | GENERIC_WRITE
    | DELETE_RIGHT
    | WRITE_DAC_MASK
    | WRITE_OWNER
    | FILE_WRITE_DATA_OR_ADD_FILE
    | FILE_APPEND_DATA_OR_ADD_SUBDIRECTORY
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES;

/// The sole operator rights intentionally granted on the service object.
///
/// This omits `CHANGE_CONFIG`, `WRITE_DAC`, `WRITE_OWNER`, `DELETE`, Pause,
/// and user-defined controls.  `READ_CONTROL` is included so an operator can
/// inspect the service security descriptor without becoming able to alter it.
pub const OPERATOR_SERVICE_RIGHTS: u32 = SERVICE_QUERY_CONFIG
    | SERVICE_QUERY_STATUS
    | SERVICE_START
    | SERVICE_STOP
    | SERVICE_INTERROGATE
    | READ_CONTROL;

/// Immutable principals used to generate exact protected DACLs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentSecuritySpec {
    service_sid: String,
    operator_sid: String,
}

impl DeploymentSecuritySpec {
    /// Validates and canonicalizes the service and operator SIDs.  They must
    /// be different: otherwise a supposedly read-only operator would obtain
    /// the service's full file and directory rights.
    pub fn new(service_sid: &str, operator_sid: &str) -> io::Result<Self> {
        let service_sid = canonical_sid(service_sid)?;
        let operator_sid = canonical_sid(operator_sid)?;
        if service_sid.eq_ignore_ascii_case(&operator_sid) {
            return Err(invalid_input(
                "service SID and operator SID must be distinct principals",
            ));
        }
        if service_sid.eq_ignore_ascii_case(SYSTEM_SID)
            || service_sid.eq_ignore_ascii_case(ADMINISTRATORS_SID)
            || operator_sid.eq_ignore_ascii_case(SYSTEM_SID)
            || operator_sid.eq_ignore_ascii_case(ADMINISTRATORS_SID)
        {
            return Err(invalid_input(
                "service/operator SID must not duplicate a built-in full-control principal",
            ));
        }
        Ok(Self {
            service_sid,
            operator_sid,
        })
    }

    pub fn service_sid(&self) -> &str {
        &self.service_sid
    }

    pub fn operator_sid(&self) -> &str {
        &self.operator_sid
    }

    /// A protected service-object DACL.  Full control is limited to Local
    /// System and Builtin Administrators.  The operator's explicit mask is
    /// deliberately numeric so Windows cannot silently map it to unrelated
    /// generic service rights.
    pub fn service_object_sddl(&self) -> String {
        format!(
            "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{OPERATOR_SERVICE_RIGHTS:08X};;;{})",
            self.operator_sid
        )
    }

    /// A protected DACL for a deployment leaf file or directory. The service
    /// receives only read/execute access: the immutable installed artifacts
    /// never need service-SID write, ACL, owner, delete, or child-create
    /// authority. Directories use inheritable ACEs for future read-only leaf
    /// objects; the protected parent itself still has only the listed ACEs.
    pub fn file_or_directory_sddl(&self, is_directory: bool) -> String {
        let inherit = if is_directory { "OICI" } else { "" };
        format!(
            "D:P(A;{inherit};FA;;;SY)(A;{inherit};FA;;;BA)(A;{inherit};FRFX;;;{})(A;{inherit};FRFX;;;{})",
            self.service_sid, self.operator_sid
        )
    }

    /// Existing data-root ancestors are never service-SID exceptions. The
    /// service runs as LocalSystem; granting its service SID replacement
    /// rights on a pre-existing parent would make the ancestor proof
    /// self-contradictory. Only a newly created deployment leaf is qualified
    /// with `file_or_directory_sddl` below.
    pub fn ancestor_directory_sddl(&self) -> String {
        format!(
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;TI)(A;OICI;FRFX;;;{})",
            self.operator_sid
        )
    }

    pub fn service_object_contract_sha256_hex(&self) -> String {
        sha256_hex(self.service_object_sddl().as_bytes())
    }

    pub fn file_or_directory_contract_sha256_hex(&self, is_directory: bool) -> String {
        sha256_hex(self.file_or_directory_sddl(is_directory).as_bytes())
    }

    pub fn ancestor_directory_contract_sha256_hex(&self) -> String {
        sha256_hex(self.ancestor_directory_sddl().as_bytes())
    }
}

/// Readback evidence for one protected deployment object.  `object_sha256_hex`
/// is present only for a regular file and is computed from the opened handle.
/// It is local integrity evidence, never a code-signing assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentSecurityEvidence {
    pub target: PathBuf,
    pub is_directory: bool,
    pub object_sha256_hex: Option<String>,
    pub expected_dacl_sha256_hex: String,
    pub protected: bool,
    pub matches: bool,
    pub owner_system: bool,
    pub stable_identity: Option<DeploymentFileIdentityV1>,
}

/// Handle-observed NTFS object identity. This is a local replacement/rollback
/// guard, not an authorization primitive or a signature.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeploymentFileIdentityV1 {
    pub canonical_path: String,
    pub volume_serial_number: u32,
    pub file_index: u64,
    pub link_count: u32,
    pub bytes: u64,
    pub is_directory: bool,
}

pub fn inspect_stable_deployment_path(
    path: impl AsRef<Path>,
) -> io::Result<DeploymentFileIdentityV1> {
    let checked = CheckedPath::open(path.as_ref(), false)?;
    checked.identity()
}

/// Refuses an alias spelling after an object has been handle-resolved. This is
/// intentionally byte-for-byte Unicode equality: callers must propagate the
/// single `GetFinalPathNameByHandleW` representation into manifests and SCM
/// commands instead of treating a different lexical path as equivalent.
pub fn require_canonical_deployment_path(
    path: &Path,
    identity: &DeploymentFileIdentityV1,
) -> io::Result<()> {
    if path
        .to_str()
        .is_none_or(|value| value != identity.canonical_path)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment path spelling differs from its handle-derived canonical path",
        ));
    }
    Ok(())
}

pub fn verify_deployment_root_ancestors(
    path: impl AsRef<Path>,
    operator_sid: &str,
) -> io::Result<()> {
    let _locked = lock_deployment_ancestor_chain(path, operator_sid)?;
    Ok(())
}

/// Locks every existing directory from a deployment root to the volume root
/// while checking its final handle path, object identity and protected ACL
/// boundary.  Windows' public Win32 API does not provide an audited
/// open-relative-to-directory-handle primitive for this transaction; callers
/// therefore retain this chain and revalidate each opened handle, but an
/// administrator must still qualify the remaining pathname-resolution race on
/// the target Windows/NTFS configuration before release.
pub fn lock_deployment_ancestor_chain(
    path: impl AsRef<Path>,
    operator_sid: &str,
) -> io::Result<LockedDeploymentAncestorChain> {
    let path = path.as_ref();
    validate_absolute_local_ntfs_path(path, false)?;
    // The supplied operator must still be a canonical SID, but it is not a
    // privileged deployment principal and receives no exception below.
    let _operator_sid = canonical_sid(operator_sid)?;
    let mut handles: Vec<LockedDeploymentAncestor> = Vec::new();
    for ancestor in deployment_ancestor_paths_including_volume_root(path) {
        let checked = CheckedPath::open_ancestor(&ancestor)?;
        let identity = checked.identity()?;
        if !identity.is_directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "deployment ancestor handle is not a directory",
            ));
        }
        let snapshot = ancestor_security_snapshot(checked.handle.0)?;
        evaluate_ancestor_security(&snapshot)?;
        if let Some(child) = handles.last() {
            let child_parent = Path::new(&child.identity.canonical_path).parent();
            if child_parent != Some(Path::new(&identity.canonical_path)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "opened deployment ancestor handles do not form a parent chain",
                ));
            }
        }
        handles.push(LockedDeploymentAncestor {
            identity,
            _handle: checked.handle,
        });
    }
    Ok(LockedDeploymentAncestorChain { handles })
}

/// Locks a freshly-created deployment leaf after strictly qualifying every
/// pre-existing ancestor. The service SID is allowed only because the leaf is
/// separately proven LocalSystem-owned and exactly matches this install
/// transaction's protected DACL. It is never fed to the generic ancestor
/// evaluator, and no parent may inherit this exception.
pub fn lock_exact_deployment_leaf_chain(
    leaf: impl AsRef<Path>,
    operator_sid: &str,
    spec: &DeploymentSecuritySpec,
) -> io::Result<LockedDeploymentAncestorChain> {
    let leaf = leaf.as_ref();
    let parent_path = leaf.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "deployment leaf has no parent directory",
        )
    })?;
    let mut chain = lock_deployment_ancestor_chain(parent_path, operator_sid)?;
    let parent = CheckedPath::open_ancestor(parent_path)?;
    let parent_identity = parent.identity()?;
    if !chain.contains_directory_identity(&parent_identity) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment leaf parent is not covered by strict ancestor proof",
        ));
    }
    let checked = CheckedPath::open_ancestor(leaf)?;
    if !checked.is_directory {
        return Err(invalid_input("deployment leaf must be a directory"));
    }
    let leaf_identity = checked.identity()?;
    if Path::new(&leaf_identity.canonical_path).parent()
        != Some(Path::new(&parent_identity.canonical_path))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment leaf handle does not bind to the qualified parent",
        ));
    }
    let expected_sddl = spec.file_or_directory_sddl(true);
    let expected = SecurityDescriptor::from_sddl(&expected_sddl)?;
    verify_file_handle(
        &checked.path,
        checked.handle.0,
        true,
        expected.as_ptr(),
        sha256_hex(expected_sddl.as_bytes()),
    )?;
    chain.handles.push(LockedDeploymentAncestor {
        identity: leaf_identity,
        _handle: checked.handle,
    });
    Ok(chain)
}

/// Retained deployment-ancestor handles.  Dropping this value ends the
/// best-effort Win32 handle-chain protection; it is deliberately not a claim
/// that Win32 has eliminated every relative-path resolution race.
pub struct LockedDeploymentAncestorChain {
    handles: Vec<LockedDeploymentAncestor>,
}

struct LockedDeploymentAncestor {
    identity: DeploymentFileIdentityV1,
    _handle: OwnedHandle,
}

impl LockedDeploymentAncestorChain {
    pub fn identities(&self) -> impl ExactSizeIterator<Item = &DeploymentFileIdentityV1> {
        self.handles.iter().map(|locked| &locked.identity)
    }

    fn contains_directory_identity(&self, identity: &DeploymentFileIdentityV1) -> bool {
        identity.is_directory
            && self
                .handles
                .iter()
                .any(|locked| locked.identity == *identity)
    }
}

/// Crate-private proof that a deployment file was opened only after its
/// ancestor chain had been retained and qualified.  Private fields prevent a
/// caller from manufacturing path/hash evidence without the stable handle.
/// The token is local-integrity evidence only; it says nothing about the
/// already-mapped image, Authenticode, WDAC, or remote provenance.
pub(crate) struct LockedDeploymentFileProof {
    path: PathBuf,
    checked: CheckedPath,
    identity: DeploymentFileIdentityV1,
    sha256_hex: String,
    _ancestor_directory_identity: DeploymentFileIdentityV1,
}

impl LockedDeploymentFileProof {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn identity(&self) -> &DeploymentFileIdentityV1 {
        &self.identity
    }

    pub(crate) fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }

    pub(crate) fn sha256_bytes(&self) -> [u8; 32] {
        let mut result = [0_u8; 32];
        for (index, pair) in self.sha256_hex.as_bytes().chunks_exact(2).enumerate() {
            result[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        result
    }

    /// Rechecks both the retained object and the live pathname. The retained
    /// handle denies write/delete sharing; the second open proves the path has
    /// not been substituted for a different file object.
    pub(crate) fn reverify(&mut self) -> io::Result<()> {
        let retained_identity = self.checked.identity()?;
        let retained_hash = sha256_open_file(self.checked.handle.0)?;
        let reopened = CheckedPath::open(&self.path, false)?;
        let reopened_identity = reopened.identity()?;
        if retained_identity != self.identity
            || reopened_identity != self.identity
            || retained_hash != self.sha256_hex
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "deployment stable-file proof changed or its pathname was substituted",
            ));
        }
        Ok(())
    }

    pub(crate) fn require_expected(
        &mut self,
        expected_identity: &DeploymentFileIdentityV1,
        expected_sha256_hex: &str,
        expected_bytes: u64,
    ) -> io::Result<()> {
        self.reverify()?;
        if &self.identity != expected_identity
            || self.sha256_hex != expected_sha256_hex
            || self.identity.bytes != expected_bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "deployment stable-file proof differs from the trusted expectation",
            ));
        }
        Ok(())
    }

    pub(crate) fn proves_path(&mut self, expected_path: &Path) -> io::Result<bool> {
        self.reverify()?;
        let expected = CheckedPath::open(expected_path, false)?;
        Ok(expected.identity()? == self.identity)
    }

    pub(crate) fn read_bounded(&mut self, maximum_bytes: usize) -> io::Result<Vec<u8>> {
        self.reverify()?;
        let bytes = read_open_file_bounded(self.checked.handle.0, maximum_bytes)?;
        self.reverify()?;
        Ok(bytes)
    }

    #[cfg(test)]
    pub(crate) fn ancestor_directory_identity(&self) -> &DeploymentFileIdentityV1 {
        &self._ancestor_directory_identity
    }
}

/// Opens a deployment file through an already-retained, security-qualified
/// ancestor chain. No production caller can obtain a proof from a bare path.
pub(crate) fn lock_deployment_file_proof(
    path: &Path,
    ancestors: &LockedDeploymentAncestorChain,
) -> io::Result<LockedDeploymentFileProof> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "deployment proof target has no parent directory",
        )
    })?;
    let parent = CheckedPath::open_ancestor(parent)?;
    let parent_identity = parent.identity()?;
    if !ancestors.contains_directory_identity(&parent_identity) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment file parent is not covered by the retained ancestor proof",
        ));
    }
    let checked = CheckedPath::open(path, false)?;
    if checked.is_directory {
        return Err(invalid_input(
            "deployment stable-file proof requires a regular file",
        ));
    }
    let identity = checked.identity()?;
    let sha256_hex = sha256_open_file(checked.handle.0)?;
    Ok(LockedDeploymentFileProof {
        path: path.to_path_buf(),
        checked,
        identity,
        sha256_hex,
        _ancestor_directory_identity: parent_identity,
    })
}

#[cfg(any(test, feature = "qualification-harness"))]
pub(crate) fn lock_test_deployment_ancestor_chain(
    path: &Path,
) -> io::Result<LockedDeploymentAncestorChain> {
    let checked = CheckedPath::open_ancestor(path)?;
    Ok(LockedDeploymentAncestorChain {
        handles: vec![LockedDeploymentAncestor {
            identity: checked.identity()?,
            _handle: checked.handle,
        }],
    })
}

/// Opens a qualification executable through a retained handle proof without
/// manufacturing a production deployment/ACL approval.  The qualification
/// harness deliberately runs against ordinary user-owned temporary paths; its
/// process-containment evidence is therefore separate from installed-service
/// deployment security.
#[cfg(feature = "qualification-harness")]
pub(crate) fn lock_qualification_file_proof(path: &Path) -> io::Result<LockedDeploymentFileProof> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "qualification executable has no parent directory",
        )
    })?;
    let ancestors = lock_test_deployment_ancestor_chain(parent)?;
    lock_deployment_file_proof(path, &ancestors)
}

fn deployment_ancestor_paths_including_volume_root(path: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let mut current = Some(path);
    while let Some(value) = current {
        result.push(value.to_path_buf());
        current = value.parent();
    }
    result
}

/// A stable, handle-retained executable copy.  The handle denies write/delete
/// sharing, preventing replacement of the created destination until the
/// installer has completed DACL and manifest binding.
pub struct LockedDeploymentCopyArtifact {
    destination: PathBuf,
    destination_handle: OwnedHandle,
    destination_identity: DeploymentFileIdentityV1,
}

impl LockedDeploymentCopyArtifact {
    pub fn destination_identity(&self) -> &DeploymentFileIdentityV1 {
        &self.destination_identity
    }

    pub fn destination_path(&self) -> &Path {
        &self.destination
    }
}

/// Applies and reads back the exact executable DACL through the still-locked
/// destination handle.  This is intentionally separate from the pathname
/// helper: opening a second WRITE_DAC handle would defeat the copy artifact's
/// no-replacement sharing contract.
pub fn apply_and_verify_locked_copy_dacl(
    artifact: &LockedDeploymentCopyArtifact,
    spec: &DeploymentSecuritySpec,
) -> io::Result<DeploymentSecurityEvidence> {
    let expected_sddl = spec.file_or_directory_sddl(false);
    let expected = SecurityDescriptor::from_sddl(&expected_sddl)?;
    let fixed_owner = LocalAllocation::sid_from_string(SYSTEM_SID)?;
    win32_status(
        unsafe {
            SetSecurityInfo(
                artifact.destination_handle.0,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION
                    | OWNER_SECURITY_INFORMATION,
                fixed_owner.0.cast(),
                null_mut(),
                expected.dacl()?,
                null(),
            )
        },
        "SetSecurityInfo(locked deployment executable)",
    )?;
    verify_file_handle(
        &artifact.destination,
        artifact.destination_handle.0,
        false,
        expected.as_ptr(),
        sha256_hex(expected_sddl.as_bytes()),
    )
}

/// Reads the frozen source from one stable source handle and writes a new
/// destination through one exclusive handle.  Both identities and hashes are
/// verified while their handles are still held; no pathname re-open is used
/// for the byte-for-byte comparison.
pub fn copy_new_durable_from_locked_source(
    source: &Path,
    destination: &Path,
    expected_source_identity: &DeploymentFileIdentityV1,
    expected_sha256_hex: &str,
    expected_bytes: u64,
) -> io::Result<LockedDeploymentCopyArtifact> {
    let source = CheckedPath::open(source, false)?;
    if source.is_directory {
        return Err(invalid_input("deployment source must be a regular file"));
    }
    let source_identity = source.identity()?;
    if &source_identity != expected_source_identity
        || source_identity.bytes != expected_bytes
        || sha256_open_file(source.handle.0)? != expected_sha256_hex
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source executable changed from the plan's stable identity",
        ));
    }
    let destination = open_new_regular_file(destination)?;
    copy_handle_to_handle(source.handle.0, destination.handle.0)?;
    bool_result(
        unsafe { FlushFileBuffers(destination.handle.0) },
        "FlushFileBuffers(destination)",
    )?;
    let destination_identity = destination.identity()?;
    if destination_identity.is_directory
        || destination_identity.link_count != 1
        || destination_identity.bytes != expected_bytes
        || sha256_open_file(destination.handle.0)? != expected_sha256_hex
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "destination executable copy differs from frozen source identity",
        ));
    }
    Ok(LockedDeploymentCopyArtifact {
        destination: destination.path,
        destination_handle: destination.handle,
        destination_identity,
    })
}

/// Copies from the already-opened source proof into a create-new destination.
/// The source handle remains held for the complete bounded copy and is
/// reverified before and after the transfer.  This qualification-only helper
/// intentionally does not grant or infer any production deployment ACL.
#[cfg(feature = "qualification-harness")]
pub(crate) fn copy_new_durable_from_proof(
    source: &mut LockedDeploymentFileProof,
    destination: &Path,
) -> io::Result<LockedDeploymentCopyArtifact> {
    source.reverify()?;
    let expected_identity = source.identity.clone();
    let expected_sha256_hex = source.sha256_hex.clone();
    let expected_bytes = expected_identity.bytes;
    let destination = open_new_regular_file(destination)?;
    copy_handle_to_handle(source.checked.handle.0, destination.handle.0)?;
    bool_result(
        unsafe { FlushFileBuffers(destination.handle.0) },
        "FlushFileBuffers(qualification destination)",
    )?;
    source.reverify()?;
    let destination_identity = destination.identity()?;
    if destination_identity.is_directory
        || destination_identity.link_count != 1
        || destination_identity.bytes != expected_bytes
        || sha256_open_file(destination.handle.0)? != expected_sha256_hex
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "qualification executable copy differs from frozen source proof",
        ));
    }
    Ok(LockedDeploymentCopyArtifact {
        destination: destination.path,
        destination_handle: destination.handle,
        destination_identity,
    })
}

/// Deletes a single object only after opening it with DELETE, comparing the
/// opened object to the installer-recorded identity, and setting disposition
/// on that same handle.  It never recurses and never follows reparse points.
pub fn remove_exact_deployment_object(
    path: &Path,
    expected: &DeploymentFileIdentityV1,
) -> io::Result<()> {
    let checked = CheckedPath::open_for_delete(path, expected.is_directory)?;
    let observed = checked.identity()?;
    if &observed != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "rollback identity mismatch; refusing to delete a replaced deployment object",
        ));
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    bool_result(
        unsafe {
            SetFileInformationByHandle(
                checked.handle.0,
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        },
        "SetFileInformationByHandle(FileDispositionInfo)",
    )
}

/// Apply then read back the exact protected DACL to an existing local NTFS
/// file or directory.  The mutation and readback both use the same opened
/// handle, so replacing the final pathname after open cannot retarget either
/// operation.  The function rejects a target reparse point and scans existing
/// lexical ancestors for reparse points before opening it.
pub fn apply_and_verify_file_or_directory_dacl(
    path: impl AsRef<Path>,
    spec: &DeploymentSecuritySpec,
) -> io::Result<DeploymentSecurityEvidence> {
    let checked = CheckedPath::open(path.as_ref(), true)?;
    let expected_sddl = spec.file_or_directory_sddl(checked.is_directory);
    apply_and_verify_open_file_or_directory_dacl(checked, expected_sddl)
}

/// Applies the strict, no-service-SID contract used only for a pre-existing
/// data root before any deployment leaf is created.
pub fn apply_and_verify_deployment_ancestor_dacl(
    path: impl AsRef<Path>,
    spec: &DeploymentSecuritySpec,
) -> io::Result<DeploymentSecurityEvidence> {
    let checked = CheckedPath::open(path.as_ref(), true)?;
    if !checked.is_directory {
        return Err(invalid_input(
            "deployment ancestor target must be a directory",
        ));
    }
    apply_and_verify_open_file_or_directory_dacl(checked, spec.ancestor_directory_sddl())
}

fn apply_and_verify_open_file_or_directory_dacl(
    checked: CheckedPath,
    expected_sddl: String,
) -> io::Result<DeploymentSecurityEvidence> {
    let expected = SecurityDescriptor::from_sddl(&expected_sddl)?;
    let expected_dacl_sha256_hex = sha256_hex(expected_sddl.as_bytes());
    let expected_dacl = expected.dacl()?;
    let fixed_owner = LocalAllocation::sid_from_string(SYSTEM_SID)?;
    let security_information = DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION
        | OWNER_SECURITY_INFORMATION;
    win32_status(
        unsafe {
            SetSecurityInfo(
                checked.handle.0,
                SE_FILE_OBJECT,
                security_information,
                fixed_owner.0.cast(),
                null_mut(),
                expected_dacl,
                null(),
            )
        },
        "SetSecurityInfo(file)",
    )?;
    verify_open_file_or_directory(checked, expected.as_ptr(), expected_dacl_sha256_hex)
}

/// Read-only startup-gate verification for an existing file or directory.  It
/// never modifies the object.
pub fn verify_file_or_directory_dacl(
    path: impl AsRef<Path>,
    spec: &DeploymentSecuritySpec,
) -> io::Result<DeploymentSecurityEvidence> {
    let checked = CheckedPath::open(path.as_ref(), false)?;
    let expected_sddl = spec.file_or_directory_sddl(checked.is_directory);
    verify_open_file_or_directory_sddl(checked, expected_sddl)
}

/// Read-only counterpart to `apply_and_verify_deployment_ancestor_dacl`.
/// It deliberately has no service-SID allowance.
pub fn verify_deployment_ancestor_dacl(
    path: impl AsRef<Path>,
    spec: &DeploymentSecuritySpec,
) -> io::Result<DeploymentSecurityEvidence> {
    let checked = CheckedPath::open(path.as_ref(), false)?;
    if !checked.is_directory {
        return Err(invalid_input(
            "deployment ancestor target must be a directory",
        ));
    }
    verify_open_file_or_directory_sddl(checked, spec.ancestor_directory_sddl())
}

fn verify_open_file_or_directory_sddl(
    checked: CheckedPath,
    expected_sddl: String,
) -> io::Result<DeploymentSecurityEvidence> {
    let expected = SecurityDescriptor::from_sddl(&expected_sddl)?;
    verify_open_file_or_directory(
        checked,
        expected.as_ptr(),
        sha256_hex(expected_sddl.as_bytes()),
    )
}

/// Apply then read back the service object's exact protected DACL.
///
/// `raw_service_handle` is an `SC_HANDLE` represented as `*mut c_void` to
/// avoid coupling this crate's `windows-sys 0.59` ABI to `windows-service`
/// 0.8.1's transitive `windows-sys 0.61` type alias.  The caller must hold a
/// live handle with `WRITE_OWNER | WRITE_DAC | READ_CONTROL`; passing an invalid or stale
/// handle is unsafe.
///
/// # Safety
///
/// `raw_service_handle` must be a live `SC_HANDLE` obtained from the local
/// SCM and must remain valid for this call.
pub unsafe fn apply_and_verify_service_object_dacl(
    raw_service_handle: *mut c_void,
    spec: &DeploymentSecuritySpec,
) -> io::Result<DeploymentSecurityEvidence> {
    if raw_service_handle.is_null() {
        return Err(invalid_input("service handle must not be null"));
    }
    let expected_sddl = spec.service_object_sddl();
    let expected = SecurityDescriptor::from_sddl(&expected_sddl)?;
    let security_information = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;
    if SetServiceObjectSecurity(raw_service_handle, security_information, expected.as_ptr()) == 0 {
        return Err(last_error("SetServiceObjectSecurity"));
    }
    verify_service_object_dacl_inner(raw_service_handle, expected.as_ptr(), &expected_sddl)
}

/// Read-only startup-gate verification for a service object.  See
/// [`apply_and_verify_service_object_dacl`] for the raw-handle safety rule.
///
/// # Safety
///
/// `raw_service_handle` must be a live `SC_HANDLE` obtained from the local
/// SCM and must remain valid for this call.
pub unsafe fn verify_service_object_dacl(
    raw_service_handle: *mut c_void,
    spec: &DeploymentSecuritySpec,
) -> io::Result<DeploymentSecurityEvidence> {
    let expected_sddl = spec.service_object_sddl();
    let expected = SecurityDescriptor::from_sddl(&expected_sddl)?;
    verify_service_object_dacl_inner(raw_service_handle, expected.as_ptr(), &expected_sddl)
}

unsafe fn verify_service_object_dacl_inner(
    raw_service_handle: *mut c_void,
    expected_descriptor: PSECURITY_DESCRIPTOR,
    expected_sddl: &str,
) -> io::Result<DeploymentSecurityEvidence> {
    if raw_service_handle.is_null() {
        return Err(invalid_input("service handle must not be null"));
    }
    let actual = query_service_security_descriptor(raw_service_handle)?;
    let dacl_matches =
        descriptors_have_identical_protected_dacl(actual.as_ptr(), expected_descriptor)?;
    let owner_system = descriptors_have_identical_owner(actual.as_ptr(), expected_descriptor)?
        && descriptor_owner_is_sid(actual.as_ptr(), SYSTEM_SID)?;
    if !dacl_matches || !owner_system {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "service object owner/DACL readback differs from the exact Forge deployment contract",
        ));
    }
    Ok(DeploymentSecurityEvidence {
        target: PathBuf::from("SC_HANDLE"),
        is_directory: false,
        object_sha256_hex: None,
        expected_dacl_sha256_hex: sha256_hex(expected_sddl.as_bytes()),
        protected: true,
        matches: dacl_matches,
        owner_system,
        stable_identity: None,
    })
}

fn verify_open_file_or_directory(
    checked: CheckedPath,
    expected_descriptor: PSECURITY_DESCRIPTOR,
    expected_dacl_sha256_hex: String,
) -> io::Result<DeploymentSecurityEvidence> {
    verify_file_handle(
        &checked.path,
        checked.handle.0,
        checked.is_directory,
        expected_descriptor,
        expected_dacl_sha256_hex,
    )
}

fn verify_file_handle(
    path: &Path,
    handle: HANDLE,
    is_directory: bool,
    expected_descriptor: PSECURITY_DESCRIPTOR,
    expected_dacl_sha256_hex: String,
) -> io::Result<DeploymentSecurityEvidence> {
    let actual = get_file_security_descriptor(handle)?;
    let matches = descriptors_have_identical_protected_dacl(actual.as_ptr(), expected_descriptor)?;
    if !matches {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file or directory DACL readback differs from the exact Forge deployment DACL",
        ));
    }
    if !file_owner_is_system(handle)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment object owner is not LocalSystem",
        ));
    }
    let object_sha256_hex = if is_directory {
        None
    } else {
        Some(sha256_open_file(handle)?)
    };
    let stable_identity = identity_from_handle(path, handle, is_directory)?;
    Ok(DeploymentSecurityEvidence {
        target: path.to_path_buf(),
        is_directory,
        object_sha256_hex,
        expected_dacl_sha256_hex,
        protected: true,
        matches: true,
        owner_system: true,
        stable_identity: Some(stable_identity),
    })
}

fn file_owner_is_system(handle: HANDLE) -> io::Result<bool> {
    let mut owner = null_mut();
    let mut descriptor = null_mut();
    win32_status(
        unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        },
        "GetSecurityInfo(owner)",
    )?;
    let _descriptor = LocalAllocation(descriptor);
    if owner.is_null() {
        return Ok(false);
    }
    let mut text = null_mut();
    bool_result(
        unsafe { ConvertSidToStringSidW(owner, &mut text) },
        "ConvertSidToStringSidW(owner)",
    )?;
    let text = LocalAllocation(text.cast());
    let units = unsafe { nul_terminated_wide(text.0.cast(), MAX_SID_U16) }?;
    Ok(String::from_utf16(units)
        .ok()
        .is_some_and(|value| value.eq_ignore_ascii_case(SYSTEM_SID)))
}

struct CheckedPath {
    path: PathBuf,
    handle: OwnedHandle,
    is_directory: bool,
}

impl CheckedPath {
    fn open(path: &Path, require_write_dac: bool) -> io::Result<Self> {
        Self::open_inner(path, require_write_dac, false, false)
    }

    fn open_ancestor(path: &Path) -> io::Result<Self> {
        Self::open_inner(path, false, true, false)
    }

    fn open_for_delete(path: &Path, expect_directory: bool) -> io::Result<Self> {
        let checked = Self::open_inner(path, false, false, true)?;
        if checked.is_directory != expect_directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rollback target changed filesystem type",
            ));
        }
        Ok(checked)
    }

    fn open_inner(
        path: &Path,
        require_write_dac: bool,
        allow_volume_root: bool,
        for_delete: bool,
    ) -> io::Result<Self> {
        validate_absolute_local_ntfs_path(path, allow_volume_root)?;
        reject_lexical_reparse_ancestors(path)?;
        let attributes = attributes(path)?;
        let is_directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let dacl_access = if require_write_dac { WRITE_DAC } else { 0 };
        let delete_access = if for_delete { DELETE } else { 0 };
        let desired_access = if is_directory {
            READ_CONTROL | dacl_access | delete_access | FILE_READ_ATTRIBUTES
        } else {
            READ_CONTROL | dacl_access | delete_access | FILE_READ_ATTRIBUTES | FILE_GENERIC_READ
        };
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if is_directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            };
        let wide = wide(path)?;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                desired_access,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                flags,
                null_mut(),
            )
        };
        let handle = OwnedHandle::new(raw, "CreateFileW")?;
        let mut tag = MaybeUninit::<FILE_ATTRIBUTE_TAG_INFO>::zeroed();
        bool_result(
            unsafe {
                GetFileInformationByHandleEx(
                    handle.0,
                    FileAttributeTagInfo,
                    tag.as_mut_ptr().cast(),
                    size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
                )
            },
            "GetFileInformationByHandleEx(FileAttributeTagInfo)",
        )?;
        let tag = unsafe { tag.assume_init() };
        if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid_input("deployment target is a reparse point"));
        }
        let opened_is_directory = tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if opened_is_directory != is_directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "deployment target changed type while it was being opened",
            ));
        }
        verify_open_handle_is_ntfs(handle.0)?;
        Ok(Self {
            path: path.to_path_buf(),
            handle,
            is_directory,
        })
    }

    fn identity(&self) -> io::Result<DeploymentFileIdentityV1> {
        identity_from_handle(&self.path, self.handle.0, self.is_directory)
    }
}

fn identity_from_handle(
    _path: &Path,
    handle: HANDLE,
    is_directory: bool,
) -> io::Result<DeploymentFileIdentityV1> {
    let mut info = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    bool_result(
        unsafe { GetFileInformationByHandle(handle, info.as_mut_ptr()) },
        "GetFileInformationByHandle",
    )?;
    let info = unsafe { info.assume_init() };
    let bytes = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    let file_index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    if !is_directory && info.nNumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment regular file must not be a hardlink",
        ));
    }
    let canonical_path = final_path_from_handle(handle)?;
    Ok(DeploymentFileIdentityV1 {
        canonical_path,
        volume_serial_number: info.dwVolumeSerialNumber,
        file_index,
        link_count: info.nNumberOfLinks,
        bytes,
        is_directory,
    })
}

/// Returns the final Unicode path associated with an already-open object.
/// This is intentionally handle-derived rather than `canonicalize(path)` so
/// the identity never follows the mutable pathname again after open.
fn final_path_from_handle(handle: HANDLE) -> io::Result<String> {
    let mut capacity = 512_u32;
    loop {
        if capacity > 32_767 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "final deployment path exceeds the Win32 path bound",
            ));
        }
        let mut units = vec![0_u16; capacity as usize];
        let written = unsafe { GetFinalPathNameByHandleW(handle, units.as_mut_ptr(), capacity, 0) };
        if written == 0 {
            return Err(last_error("GetFinalPathNameByHandleW"));
        }
        if written < capacity {
            units.truncate(written as usize);
            return String::from_utf16(&units).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "final deployment path is not valid UTF-16",
                )
            });
        }
        capacity = written.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "final deployment path length overflow",
            )
        })?;
    }
}

fn open_new_regular_file(path: &Path) -> io::Result<CheckedPath> {
    validate_absolute_local_ntfs_path(path, false)?;
    // The leaf is intentionally absent for CREATE_NEW; inspect only existing
    // ancestors before opening it.  The returned handle is then checked for
    // type/reparse status before any bytes are written.
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "new deployment destination has no parent directory",
        )
    })?;
    reject_lexical_reparse_ancestors(parent)?;
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "deployment destination already exists",
        ));
    }
    let wide = wide(path)?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            null(),
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    let handle = OwnedHandle::new(raw, "CreateFileW(CREATE_NEW)")?;
    verify_open_handle_is_ntfs(handle.0)?;
    let mut tag = MaybeUninit::<FILE_ATTRIBUTE_TAG_INFO>::zeroed();
    bool_result(
        unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                FileAttributeTagInfo,
                tag.as_mut_ptr().cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        },
        "GetFileInformationByHandleEx(new destination)",
    )?;
    let tag = unsafe { tag.assume_init() };
    if tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(invalid_input(
            "new deployment destination is not a regular file",
        ));
    }
    Ok(CheckedPath {
        path: path.to_path_buf(),
        handle,
        is_directory: false,
    })
}

fn copy_handle_to_handle(source: HANDLE, destination: HANDLE) -> io::Result<()> {
    bool_result(
        unsafe { SetFilePointerEx(source, 0, null_mut(), FILE_BEGIN) },
        "SetFilePointerEx(source start)",
    )?;
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let mut read = 0_u32;
        bool_result(
            unsafe {
                ReadFile(
                    source,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut read,
                    null_mut(),
                )
            },
            "ReadFile(stable source)",
        )?;
        if read == 0 {
            return Ok(());
        }
        let mut written = 0_usize;
        while written < read as usize {
            let mut current = 0_u32;
            bool_result(
                unsafe {
                    WriteFile(
                        destination,
                        buffer[written..read as usize].as_ptr(),
                        (read as usize - written) as u32,
                        &mut current,
                        null_mut(),
                    )
                },
                "WriteFile(stable destination)",
            )?;
            if current == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "WriteFile returned success with zero bytes",
                ));
            }
            written += current as usize;
        }
    }
}

struct OwnedHandle(HANDLE);

// A Win32 kernel handle may be moved between threads. This wrapper owns one
// reference and closes it exactly once; moving a retained deployment proof to
// the service owner's background supervisor therefore does not duplicate or
// weaken the underlying file-object lock.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE, operation: &'static str) -> io::Result<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(last_error(operation));
        }
        Ok(Self(handle))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// LocalAlloc-backed security descriptor/SID allocation.  Every pointer
/// returned by the SDDL conversion APIs is freed exactly once with LocalFree.
struct LocalAllocation(*mut c_void);

impl LocalAllocation {
    fn security_descriptor_from_sddl(sddl: &str) -> io::Result<Self> {
        let wide = wide_str(sddl)?;
        let mut pointer = null_mut();
        let mut size = 0_u32;
        bool_result(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    1,
                    &mut pointer,
                    &mut size,
                )
            },
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        )?;
        if pointer.is_null() || size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SDDL conversion returned an empty security descriptor",
            ));
        }
        Ok(Self(pointer))
    }

    fn sid_from_string(sid: &str) -> io::Result<Self> {
        let wide = wide_str(sid)?;
        let mut pointer = null_mut();
        bool_result(
            unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut pointer) },
            "ConvertStringSidToSidW",
        )?;
        if pointer.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SID conversion returned a null SID",
            ));
        }
        Ok(Self(pointer))
    }
}

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

struct SecurityDescriptor(LocalAllocation);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        Ok(Self(LocalAllocation::security_descriptor_from_sddl(sddl)?))
    }

    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        let allocation = &self.0;
        allocation.0
    }

    fn dacl(&self) -> io::Result<*mut ACL> {
        dacl_from_descriptor(self.as_ptr())
    }
}

struct ServiceSecurityDescriptor(Vec<u8>);

impl ServiceSecurityDescriptor {
    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0.as_ptr().cast_mut().cast()
    }
}

fn get_file_security_descriptor(handle: HANDLE) -> io::Result<SecurityDescriptor> {
    let mut descriptor = null_mut();
    let mut dacl = null_mut();
    win32_status(
        unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        },
        "GetSecurityInfo(file)",
    )?;
    if descriptor.is_null() || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GetSecurityInfo(file) returned no DACL security descriptor",
        ));
    }
    Ok(SecurityDescriptor(LocalAllocation(descriptor)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AncestorAce {
    Allow {
        sid: String,
        mask: u32,
        inherited: bool,
    },
    Deny,
    /// Object, callback, resource-attribute and unrecognised ACE forms are
    /// intentionally not interpreted as safe: some can grant access after
    /// conditional evaluation, so an installer must fail closed.
    UnknownPotentialGrant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AncestorSecuritySnapshot {
    owner_sid: String,
    aces: Vec<AncestorAce>,
}

fn ancestor_security_snapshot(handle: HANDLE) -> io::Result<AncestorSecuritySnapshot> {
    let mut owner = null_mut();
    let mut descriptor = null_mut();
    let mut dacl = null_mut();
    win32_status(
        unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        },
        "GetSecurityInfo(deployment ancestor)",
    )?;
    let _descriptor = LocalAllocation(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "deployment ancestor security descriptor lacks owner or DACL",
        ));
    }
    let owner_sid = sid_text(owner.cast())?;
    let acl_bytes = unsafe { checked_acl_bytes(dacl)? };
    let ace_ranges = validate_acl_layout(acl_bytes)?;
    let mut aces = Vec::with_capacity(ace_ranges.len());
    for (offset, length) in ace_ranges {
        let bytes = &acl_bytes[offset..offset + length];
        let header = unsafe {
            &*(bytes
                .as_ptr()
                .cast::<windows_sys::Win32::Security::ACE_HEADER>())
        };
        match header.AceType as u32 {
            ACCESS_ALLOWED_ACE_TYPE => {
                validate_standard_ace_sid_extent(bytes, "deployment ancestor allowed ACE")?;
                let sid_ptr = unsafe { bytes.as_ptr().add(8) }.cast_mut().cast::<c_void>();
                aces.push(AncestorAce::Allow {
                    sid: sid_text(sid_ptr)?,
                    mask: u32::from_le_bytes(
                        bytes[4..8].try_into().expect("ACE mask length checked"),
                    ),
                    inherited: header.AceFlags & INHERITED_ACE as u8 != 0,
                });
            }
            // A deny ACE cannot create replacement authority. We deliberately
            // do not try to use it to offset an allow ACE above, but its SID
            // must still occupy the exact standard ACE extent so malformed
            // descriptors never pass by being classified as harmless.
            ACCESS_DENIED_ACE_TYPE => {
                validate_standard_ace_sid_extent(bytes, "deployment ancestor deny ACE")?;
                aces.push(AncestorAce::Deny);
            }
            _ => aces.push(AncestorAce::UnknownPotentialGrant),
        }
    }
    Ok(AncestorSecuritySnapshot { owner_sid, aces })
}

fn validate_standard_ace_sid_extent(bytes: &[u8], label: &'static str) -> io::Result<()> {
    if bytes.len() < 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} is undersized"),
        ));
    }
    let sid = unsafe { bytes.as_ptr().add(8) }.cast_mut().cast::<c_void>();
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} has an invalid SID"),
        ));
    }
    let sid_len = unsafe { GetLengthSid(sid) as usize };
    if sid_len == 0 || 8 + sid_len != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} has an invalid SID extent"),
        ));
    }
    Ok(())
}

fn evaluate_ancestor_security(snapshot: &AncestorSecuritySnapshot) -> io::Result<()> {
    if ![SYSTEM_SID, ADMINISTRATORS_SID, TRUSTED_INSTALLER_SID]
        .iter()
        .any(|allowed| snapshot.owner_sid.eq_ignore_ascii_case(allowed))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "deployment ancestor owner is not an approved privileged principal",
        ));
    }
    for ace in &snapshot.aces {
        match ace {
            AncestorAce::Allow {
                sid,
                mask,
                inherited,
            } if ![SYSTEM_SID, ADMINISTRATORS_SID, TRUSTED_INSTALLER_SID]
                .iter()
                .any(|privileged| sid.eq_ignore_ascii_case(privileged))
                && mask & DANGEROUS_REPLACEMENT_RIGHTS != 0 =>
            {
                // Inherited allows are deliberately just as dangerous: no
                // deny ACE is used to "cancel" a potentially replaceable
                // path in this conservative evaluator.
                let _applies_through_inheritance = inherited;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "deployment ancestor grants a non-privileged principal replacement-capable access",
                ));
            }
            AncestorAce::Allow { .. } | AncestorAce::Deny => {}
            AncestorAce::UnknownPotentialGrant => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "deployment ancestor contains an uninterpretable ACE that may grant access",
                ));
            }
        }
    }
    Ok(())
}

/// SAFETY: callers pass a DACL pointer returned by GetSecurityInfo.  The ACL
/// header itself is inspected only after the descriptor-owning allocation is
/// retained by the caller.  `AclSize` is bounded before a slice is formed.
unsafe fn checked_acl_bytes<'a>(dacl: *mut ACL) -> io::Result<&'a [u8]> {
    if dacl.is_null() {
        return Err(invalid_input("DACL pointer is null"));
    }
    let acl_size = usize::from((*dacl).AclSize);
    if acl_size < size_of::<ACL>() || acl_size > MAX_SERVICE_SECURITY_DESCRIPTOR_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DACL has an invalid declared size",
        ));
    }
    Ok(std::slice::from_raw_parts(dacl.cast::<u8>(), acl_size))
}

/// Validates every ACE extent before any SID pointer is taken from an ACL.
/// This deliberately rejects malformed padding, truncated ACEs and an ACE
/// count that cannot be represented by the declared ACL byte extent.
fn validate_acl_layout(acl: &[u8]) -> io::Result<Vec<(usize, usize)>> {
    if acl.len() < size_of::<ACL>() {
        return Err(invalid_input("ACL is shorter than its header"));
    }
    let declared_size = usize::from(u16::from_le_bytes([acl[2], acl[3]]));
    let ace_count = usize::from(u16::from_le_bytes([acl[4], acl[5]]));
    if declared_size != acl.len() || declared_size < size_of::<ACL>() {
        return Err(invalid_input(
            "ACL declared size does not match supplied extent",
        ));
    }
    let mut offset = size_of::<ACL>();
    let mut ranges = Vec::with_capacity(ace_count);
    for _ in 0..ace_count {
        if offset
            .checked_add(size_of::<windows_sys::Win32::Security::ACE_HEADER>())
            .is_none_or(|end| end > acl.len())
        {
            return Err(invalid_input("ACL contains a truncated ACE header"));
        }
        let ace_size = usize::from(u16::from_le_bytes([acl[offset + 2], acl[offset + 3]]));
        if ace_size < 8 || ace_size % 4 != 0 {
            return Err(invalid_input("ACL ACE size is malformed"));
        }
        let end = offset
            .checked_add(ace_size)
            .filter(|end| *end <= acl.len())
            .ok_or_else(|| invalid_input("ACL ACE exceeds declared ACL extent"))?;
        ranges.push((offset, ace_size));
        offset = end;
    }
    // `AclSize` is an allocation extent, not necessarily bytes-in-use; legal
    // ACLs may retain unused trailing capacity after their final ACE. Every
    // ACE declared by `AceCount` was nevertheless bounded above.
    Ok(ranges)
}

fn sid_text(sid: *mut c_void) -> io::Result<String> {
    let mut text = null_mut();
    bool_result(
        unsafe { ConvertSidToStringSidW(sid, &mut text) },
        "ConvertSidToStringSidW",
    )?;
    let text = LocalAllocation(text.cast());
    let units = unsafe { nul_terminated_wide(text.0.cast(), MAX_SID_U16) }?;
    String::from_utf16(units)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SID is invalid UTF-16"))
}

unsafe fn query_service_security_descriptor(
    raw_service_handle: *mut c_void,
) -> io::Result<ServiceSecurityDescriptor> {
    let mut needed = 0_u32;
    let security_information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let result = QueryServiceObjectSecurity(
        raw_service_handle,
        security_information,
        null_mut(),
        0,
        &mut needed,
    );
    if result != 0 || needed == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QueryServiceObjectSecurity did not report a bounded DACL descriptor size",
        ));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || needed as usize > MAX_SERVICE_SECURITY_DESCRIPTOR_BYTES
    {
        return Err(io::Error::new(
            error.kind(),
            format!("QueryServiceObjectSecurity size probe failed: {error}"),
        ));
    }
    let mut bytes = vec![0_u8; needed as usize];
    if QueryServiceObjectSecurity(
        raw_service_handle,
        security_information,
        bytes.as_mut_ptr().cast(),
        needed,
        &mut needed,
    ) == 0
    {
        return Err(last_error("QueryServiceObjectSecurity readback"));
    }
    if needed == 0 || needed as usize > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QueryServiceObjectSecurity returned an invalid descriptor length",
        ));
    }
    bytes.truncate(needed as usize);
    Ok(ServiceSecurityDescriptor(bytes))
}

fn descriptors_have_identical_protected_dacl(
    actual: PSECURITY_DESCRIPTOR,
    expected: PSECURITY_DESCRIPTOR,
) -> io::Result<bool> {
    let actual_control = descriptor_control(actual)?;
    let expected_control = descriptor_control(expected)?;
    let required = SE_DACL_PRESENT | SE_DACL_PROTECTED;
    if actual_control & required != required || expected_control & required != required {
        return Ok(false);
    }
    let actual_entries = acl_entries(dacl_from_descriptor(actual)?)?;
    let expected_entries = acl_entries(dacl_from_descriptor(expected)?)?;
    Ok(actual_entries == expected_entries)
}

fn descriptors_have_identical_owner(
    actual: PSECURITY_DESCRIPTOR,
    expected: PSECURITY_DESCRIPTOR,
) -> io::Result<bool> {
    let actual = owner_from_descriptor(actual)?;
    let expected = owner_from_descriptor(expected)?;
    if unsafe { IsValidSid(actual) } == 0 || unsafe { IsValidSid(expected) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "security descriptor owner SID is invalid",
        ));
    }
    let actual_len = unsafe { GetLengthSid(actual) as usize };
    let expected_len = unsafe { GetLengthSid(expected) as usize };
    Ok(actual_len != 0
        && actual_len == expected_len
        && unsafe {
            std::slice::from_raw_parts(actual.cast::<u8>(), actual_len)
                == std::slice::from_raw_parts(expected.cast::<u8>(), expected_len)
        })
}

fn descriptor_owner_is_sid(
    descriptor: PSECURITY_DESCRIPTOR,
    expected_sid: &str,
) -> io::Result<bool> {
    let owner = owner_from_descriptor(descriptor)?;
    Ok(sid_text(owner)?.eq_ignore_ascii_case(expected_sid))
}

fn owner_from_descriptor(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<*mut c_void> {
    if descriptor.is_null() || unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Err(invalid_input("security descriptor is null or invalid"));
    }
    let mut owner = null_mut();
    let mut defaulted = 0_i32;
    bool_result(
        unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) },
        "GetSecurityDescriptorOwner",
    )?;
    if owner.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "security descriptor does not contain an owner SID",
        ));
    }
    Ok(owner)
}

fn descriptor_control(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<u16> {
    if descriptor.is_null() || unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Err(invalid_input("security descriptor is null or invalid"));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    bool_result(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
        "GetSecurityDescriptorControl",
    )?;
    Ok(control)
}

fn dacl_from_descriptor(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<*mut ACL> {
    if descriptor.is_null() || unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Err(invalid_input("security descriptor is null or invalid"));
    }
    let mut present = 0_i32;
    let mut defaulted = 0_i32;
    let mut dacl = null_mut();
    bool_result(
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) },
        "GetSecurityDescriptorDacl",
    )?;
    if present == 0 || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "security descriptor does not contain an explicit DACL",
        ));
    }
    Ok(dacl)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExactAllowedAce {
    flags: u8,
    mask: u32,
    sid: Vec<u8>,
}

fn acl_entries(dacl: *mut ACL) -> io::Result<Vec<ExactAllowedAce>> {
    let acl = unsafe { checked_acl_bytes(dacl)? };
    let ace_ranges = validate_acl_layout(acl)?;
    let mut result = Vec::with_capacity(ace_ranges.len());
    for (offset, length) in ace_ranges {
        let bytes = &acl[offset..offset + length];
        let header = unsafe {
            &*(bytes
                .as_ptr()
                .cast::<windows_sys::Win32::Security::ACE_HEADER>())
        };
        if header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE
            || header.AceFlags & INHERITED_ACE as u8 != 0
            || bytes.len() < 8
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DACL contains a non-canonical, inherited, or undersized ACE",
            ));
        }
        let mask = u32::from_le_bytes(bytes[4..8].try_into().expect("checked ACE mask length"));
        validate_standard_ace_sid_extent(bytes, "DACL allowed ACE")?;
        result.push(ExactAllowedAce {
            flags: header.AceFlags,
            mask,
            sid: bytes[8..].to_vec(),
        });
    }
    Ok(result)
}

fn validate_absolute_local_ntfs_path(path: &Path, allow_volume_root: bool) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(invalid_input("deployment target must be an absolute path"));
    }
    let mut components = path.components();
    let prefix = match components.next() {
        Some(Component::Prefix(prefix)) => prefix.kind(),
        _ => {
            return Err(invalid_input(
                "deployment target must have a drive-letter prefix",
            ))
        }
    };
    if !matches!(prefix, Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        || !matches!(components.next(), Some(Component::RootDir))
    {
        return Err(invalid_input(
            "deployment target must be rooted on a local drive letter, never UNC or device path",
        ));
    }
    let mut has_normal_component = false;
    for component in components {
        if matches!(component, Component::CurDir | Component::ParentDir) {
            return Err(invalid_input(
                "deployment path may not contain dot or parent traversal components",
            ));
        }
        has_normal_component |= matches!(component, Component::Normal(_));
    }
    if !has_normal_component && !allow_volume_root {
        return Err(invalid_input(
            "deployment target must not be the volume root",
        ));
    }
    let root = volume_root(path)?;
    if unsafe { GetDriveTypeW(root.as_ptr()) } != DRIVE_FIXED {
        return Err(invalid_input(
            "deployment target must be on a local fixed volume",
        ));
    }
    Ok(())
}

fn reject_lexical_reparse_ancestors(path: &Path) -> io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new("\\")),
            Component::Normal(part) => {
                current.push(part);
                if attributes(&current)? & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(invalid_input("deployment path traverses a reparse point"));
                }
            }
            Component::CurDir | Component::ParentDir => unreachable!("validated earlier"),
        }
    }
    Ok(())
}

fn attributes(path: &Path) -> io::Result<u32> {
    let wide = wide(path)?;
    let result = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if result == u32::MAX {
        return Err(last_error("GetFileAttributesW"));
    }
    Ok(result)
}

fn verify_open_handle_is_ntfs(handle: HANDLE) -> io::Result<()> {
    let mut filesystem_name = [0_u16; 32];
    bool_result(
        unsafe {
            GetVolumeInformationByHandleW(
                handle,
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                null_mut(),
                filesystem_name.as_mut_ptr(),
                filesystem_name.len() as u32,
            )
        },
        "GetVolumeInformationByHandleW",
    )?;
    let length = filesystem_name
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "filesystem name lacks NUL"))?;
    let filesystem = String::from_utf16(&filesystem_name[..length]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "filesystem name is invalid UTF-16",
        )
    })?;
    if !filesystem.eq_ignore_ascii_case("NTFS") {
        return Err(invalid_input("deployment target must be on NTFS"));
    }
    Ok(())
}

fn sha256_open_file(handle: HANDLE) -> io::Result<String> {
    bool_result(
        unsafe { SetFilePointerEx(handle, 0, null_mut(), FILE_BEGIN) },
        "SetFilePointerEx(file start)",
    )?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let mut read = 0_u32;
        bool_result(
            unsafe {
                ReadFile(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut read,
                    null_mut(),
                )
            },
            "ReadFile(handle-bound SHA-256)",
        )?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read as usize]);
    }
    let digest = hasher.finalize();
    Ok(hex_digest(&digest))
}

fn read_open_file_bounded(handle: HANDLE, maximum_bytes: usize) -> io::Result<Vec<u8>> {
    if maximum_bytes == 0 {
        return Err(invalid_input("deployment file read bound must be nonzero"));
    }
    bool_result(
        unsafe { SetFilePointerEx(handle, 0, null_mut(), FILE_BEGIN) },
        "SetFilePointerEx(bounded file start)",
    )?;
    let mut result = Vec::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES.min(maximum_bytes)];
    loop {
        let mut read = 0_u32;
        bool_result(
            unsafe {
                ReadFile(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut read,
                    null_mut(),
                )
            },
            "ReadFile(stable bounded deployment file)",
        )?;
        if read == 0 {
            return Ok(result);
        }
        let next = result
            .len()
            .checked_add(read as usize)
            .filter(|next| *next <= maximum_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "deployment file exceeds its bounded read limit",
                )
            })?;
        result.extend_from_slice(&buffer[..read as usize]);
        debug_assert_eq!(result.len(), next);
    }
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn canonical_sid(input: &str) -> io::Result<String> {
    if input.is_empty() || input.encode_utf16().count() > MAX_SID_U16 || input.contains('\0') {
        return Err(invalid_input("SID is empty, oversized, or contains NUL"));
    }
    let sid = LocalAllocation::sid_from_string(input)?;
    let mut string_sid = null_mut();
    bool_result(
        unsafe { ConvertSidToStringSidW(sid.0, &mut string_sid) },
        "ConvertSidToStringSidW",
    )?;
    let text = LocalAllocation(string_sid.cast());
    if text.0.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SID canonicalization returned a null string",
        ));
    }
    let units = unsafe { nul_terminated_wide(text.0.cast(), MAX_SID_U16) }?;
    let canonical = String::from_utf16(units)
        .map_err(|_| invalid_input("SID canonicalization is not UTF-16"))?;
    if !canonical.starts_with("S-")
        || !canonical
            .bytes()
            .all(|byte| byte == b'S' || byte == b'-' || byte.is_ascii_digit())
    {
        return Err(invalid_input(
            "SID canonicalization produced an unexpected SID spelling",
        ));
    }
    Ok(canonical)
}

fn volume_root(path: &Path) -> io::Result<Vec<u16>> {
    let wide_path = wide(path)?;
    let mut root = vec![0_u16; 512];
    let result = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetVolumePathNameW(
            wide_path.as_ptr(),
            root.as_mut_ptr(),
            root.len() as u32,
        )
    };
    if result == 0 {
        return Err(last_error("GetVolumePathNameW"));
    }
    if !root.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "volume root lacks NUL terminator",
        ));
    }
    Ok(root)
}

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if units.contains(&0) {
        return Err(invalid_input("Windows path contains NUL"));
    }
    let mut result = units;
    result.push(0);
    Ok(result)
}

fn wide_str(value: &str) -> io::Result<Vec<u16>> {
    if value.contains('\0') {
        return Err(invalid_input("Windows string contains NUL"));
    }
    let mut result = value.encode_utf16().collect::<Vec<_>>();
    result.push(0);
    Ok(result)
}

unsafe fn nul_terminated_wide<'a>(pointer: *const u16, maximum: usize) -> io::Result<&'a [u16]> {
    if pointer.is_null() {
        return Err(invalid_input("wide string pointer is null"));
    }
    for length in 0..maximum {
        if *pointer.add(length) == 0 {
            return Ok(std::slice::from_raw_parts(pointer, length));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "wide string exceeds its fail-closed bound",
    ))
}

fn bool_result(result: i32, operation: &'static str) -> io::Result<()> {
    if result == 0 {
        Err(last_error(operation))
    } else {
        Ok(())
    }
}

fn win32_status(status: u32, operation: &'static str) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::Error::from_raw_os_error(status as i32).kind(),
            format!("{operation} failed with Win32 status {status}"),
        ))
    }
}

fn last_error(operation: &'static str) -> io::Error {
    let error = io::Error::last_os_error();
    io::Error::new(error.kind(), format!("{operation} failed: {error}"))
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_digest(&digest)
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn spec_rejects_duplicate_or_malformed_principals() {
        assert!(DeploymentSecuritySpec::new("S-1-5-21-1", "S-1-5-21-1").is_err());
        assert!(DeploymentSecuritySpec::new("not-a-sid", "S-1-5-21-2").is_err());
        assert!(DeploymentSecuritySpec::new("S-1-5-18", "S-1-5-21-2").is_err());
    }

    #[test]
    fn exact_sddl_has_only_intended_operator_service_rights() {
        let spec =
            DeploymentSecuritySpec::new("S-1-5-21-101-202-303-404", "S-1-5-21-101-202-303-405")
                .unwrap();
        let service = spec.service_object_sddl();
        assert!(service.starts_with("O:SYD:P"));
        assert!(service.contains(&format!("0x{OPERATOR_SERVICE_RIGHTS:08X}")));
        assert!(!service.contains("WD"));
        let directory = spec.file_or_directory_sddl(true);
        assert!(directory.contains("(A;OICI;FA;;;SY)"));
        assert!(directory.contains("(A;OICI;FRFX;;;S-1-5-21-101-202-303-405)"));
    }

    #[test]
    fn service_sid_is_strict_on_ancestors_and_read_only_on_exact_leaf() {
        let service_sid = "S-1-5-80-101-202-303-404-505";
        let other_service_sid = "S-1-5-80-601-702-803-904-1005";
        let spec = DeploymentSecuritySpec::new(service_sid, "S-1-5-21-1-2-3-4").unwrap();
        let mut parent = safe_ancestor_snapshot();
        parent.aces.push(AncestorAce::Allow {
            sid: service_sid.to_owned(),
            mask: FILE_WRITE_DATA_OR_ADD_FILE,
            inherited: false,
        });
        assert_eq!(
            evaluate_ancestor_security(&parent).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let ancestor = spec.ancestor_directory_sddl();
        assert!(!ancestor.contains(service_sid));
        let exact_leaf = spec.file_or_directory_sddl(true);
        assert!(exact_leaf.contains(&format!("(A;OICI;FRFX;;;{service_sid})")));
        assert!(!exact_leaf.contains(other_service_sid));
        let exact = SecurityDescriptor::from_sddl(&exact_leaf).unwrap();
        let other =
            SecurityDescriptor::from_sddl(&exact_leaf.replace(service_sid, other_service_sid))
                .unwrap();
        let extra = SecurityDescriptor::from_sddl(&format!(
            "{exact_leaf}(A;OICI;0x{WRITE_DAC_MASK:08X};;;{service_sid})"
        ))
        .unwrap();
        assert!(
            !descriptors_have_identical_protected_dacl(exact.as_ptr(), other.as_ptr()).unwrap()
        );
        assert!(
            !descriptors_have_identical_protected_dacl(exact.as_ptr(), extra.as_ptr()).unwrap()
        );
    }

    #[test]
    fn handle_canonical_path_spelling_rejects_aliases() {
        let identity = DeploymentFileIdentityV1 {
            canonical_path: r"\\?\F:\Forge\部署\forge-acqd.exe".to_owned(),
            volume_serial_number: 1,
            file_index: 2,
            link_count: 1,
            bytes: 3,
            is_directory: false,
        };
        require_canonical_deployment_path(Path::new(&identity.canonical_path), &identity).unwrap();
        assert!(require_canonical_deployment_path(
            Path::new(r"F:\Forge\部署\forge-acqd.exe"),
            &identity,
        )
        .is_err());
        assert!(require_canonical_deployment_path(
            Path::new(r"\\server\share\forge-acqd.exe"),
            &identity,
        )
        .is_err());
    }

    fn safe_ancestor_snapshot() -> AncestorSecuritySnapshot {
        AncestorSecuritySnapshot {
            owner_sid: SYSTEM_SID.to_owned(),
            aces: vec![AncestorAce::Allow {
                sid: ADMINISTRATORS_SID.to_owned(),
                mask: 0x0012_0000,
                inherited: false,
            }],
        }
    }

    #[test]
    fn ancestor_walk_includes_the_volume_root() {
        let values = deployment_ancestor_paths_including_volume_root(Path::new(r"F:\forge\data"));
        assert_eq!(values.first(), Some(&PathBuf::from(r"F:\forge\data")));
        assert_eq!(values.last(), Some(&PathBuf::from(r"F:\")));
    }

    #[test]
    fn ancestor_evaluator_rejects_inherited_dangerous_allow() {
        let mut snapshot = safe_ancestor_snapshot();
        snapshot.aces.push(AncestorAce::Allow {
            sid: "S-1-5-11".to_owned(),
            mask: 0x0000_0040,
            inherited: true,
        });
        let error = evaluate_ancestor_security(&snapshot).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn ancestor_evaluator_rejects_operator_owner_and_unknown_ace() {
        let mut owner = safe_ancestor_snapshot();
        owner.owner_sid = "S-1-5-21-1-2-3-4".to_owned();
        assert_eq!(
            evaluate_ancestor_security(&owner).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut unknown = safe_ancestor_snapshot();
        unknown.aces.push(AncestorAce::UnknownPotentialGrant);
        assert_eq!(
            evaluate_ancestor_security(&unknown).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn ancestor_evaluator_accepts_safe_allow() {
        evaluate_ancestor_security(&safe_ancestor_snapshot()).unwrap();
    }

    #[test]
    fn ancestor_evaluator_rejects_any_unknown_group_with_ea_or_attribute_write() {
        for mask in [FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES] {
            let mut snapshot = safe_ancestor_snapshot();
            snapshot.aces.push(AncestorAce::Allow {
                sid: "S-1-5-21-991-992-993-994".to_owned(),
                mask,
                inherited: false,
            });
            assert_eq!(
                evaluate_ancestor_security(&snapshot).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn acl_layout_rejects_truncated_and_overrunning_ace_extents() {
        let truncated_header = [2, 0, 8, 0, 1, 0, 0, 0];
        assert!(validate_acl_layout(&truncated_header).is_err());
        let overrun_ace = [2, 0, 12, 0, 1, 0, 0, 0, 0, 0, 8, 0];
        assert!(validate_acl_layout(&overrun_ace).is_err());
        let malformed_ace_size = [2, 0, 16, 0, 1, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0];
        assert!(validate_acl_layout(&malformed_ace_size).is_err());
        let malformed_deny_sid = [1, 0, 20, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(validate_standard_ace_sid_extent(&malformed_deny_sid, "test deny ACE").is_err());
    }

    #[test]
    fn service_descriptor_owner_must_be_system() {
        let expected = SecurityDescriptor::from_sddl("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)").unwrap();
        let wrong = SecurityDescriptor::from_sddl("O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)").unwrap();
        assert!(descriptors_have_identical_owner(expected.as_ptr(), expected.as_ptr()).unwrap());
        assert!(!descriptors_have_identical_owner(wrong.as_ptr(), expected.as_ptr()).unwrap());
        assert!(descriptor_owner_is_sid(expected.as_ptr(), SYSTEM_SID).unwrap());
        assert!(!descriptor_owner_is_sid(wrong.as_ptr(), SYSTEM_SID).unwrap());
    }

    #[test]
    fn stable_file_proof_rejects_wrong_identity_and_blocks_replacement() {
        let root = std::env::temp_dir().join(format!(
            "forge-acqd-stable-proof-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("artifact.bin");
        let other = root.join("other.bin");
        std::fs::write(&file, b"artifact").unwrap();
        std::fs::write(&other, b"other").unwrap();
        let ancestors = lock_test_deployment_ancestor_chain(&root).unwrap();
        let mut proof = lock_deployment_file_proof(&file, &ancestors).unwrap();
        let other_identity = inspect_stable_deployment_path(&other).unwrap();
        assert!(proof
            .require_expected(&other_identity, &sha256_hex(b"other"), 5)
            .is_err());
        assert_eq!(
            proof.ancestor_directory_identity(),
            ancestors.identities().next().unwrap()
        );
        assert!(std::fs::remove_file(&file).is_err());
        proof.reverify().unwrap();
        drop(proof);
        std::fs::remove_file(file).unwrap();
        std::fs::remove_file(other).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(feature = "qualification-harness")]
    #[test]
    fn qualification_copy_is_create_new_and_handle_bound() {
        let root = std::env::temp_dir().join(format!(
            "forge-acqd-qualification-copy-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source.exe");
        let destination = root.join("qualified.exe");
        std::fs::write(&source, b"stable qualification source").unwrap();
        std::fs::write(&destination, b"pre-existing").unwrap();
        let mut proof = lock_qualification_file_proof(&source).unwrap();
        let error = match copy_new_durable_from_proof(&mut proof, &destination) {
            Ok(_) => panic!("pre-existing qualification destination was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        std::fs::remove_file(&destination).unwrap();
        let artifact = copy_new_durable_from_proof(&mut proof, &destination)
            .unwrap_or_else(|error| panic!("copy after destination removal failed: {error:?}"));
        assert_eq!(artifact.destination_identity().link_count, 1);
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"stable qualification source"
        );
        drop(artifact);
        drop(proof);
        std::fs::remove_file(source).unwrap();
        std::fs::remove_file(destination).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn exact_rollback_refuses_path_replacement_and_deletes_matching_file() {
        let root = std::env::temp_dir().join(format!(
            "forge-acqd-exact-rollback-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("artifact.bin");
        std::fs::write(&file, b"original").unwrap();
        let identity = inspect_stable_deployment_path(&file).unwrap();
        std::fs::remove_file(&file).unwrap();
        std::fs::write(&file, b"replacement").unwrap();
        assert!(remove_exact_deployment_object(&file, &identity).is_err());
        assert!(file.exists());
        std::fs::remove_file(&file).unwrap();
        std::fs::write(&file, b"matching").unwrap();
        let matching = inspect_stable_deployment_path(&file).unwrap();
        remove_exact_deployment_object(&file, &matching).unwrap();
        assert!(!file.exists());
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn exact_rollback_directory_refuses_nonempty_target() {
        let root = std::env::temp_dir().join(format!(
            "forge-acqd-nonempty-rollback-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let identity = inspect_stable_deployment_path(&root).unwrap();
        std::fs::write(root.join("child"), b"child").unwrap();
        assert!(remove_exact_deployment_object(&root, &identity).is_err());
        assert!(root.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn protected_temp_file_round_trips_with_handle_bound_hash() {
        let root = std::env::temp_dir().join(format!(
            "forge-acqd-deployment-security-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("fixture.bin");
        std::fs::write(&file, b"forge deployment ACL fixture").unwrap();
        let current_user = crate::ipc::current_process_user_sid().unwrap();
        let spec = DeploymentSecuritySpec::new(&current_user, "S-1-5-21-101-202-303-405").unwrap();
        match apply_and_verify_file_or_directory_dacl(&file, &spec) {
            Ok(evidence) => {
                assert!(evidence.protected && evidence.matches);
                let expected_hash = sha256_hex(b"forge deployment ACL fixture");
                assert_eq!(
                    evidence.object_sha256_hex.as_deref(),
                    Some(expected_hash.as_str())
                );
                let verified = verify_file_or_directory_dacl(&file, &spec).unwrap();
                assert_eq!(verified, evidence);
            }
            // Non-elevated CI cannot transfer ownership to SYSTEM. Rejection
            // is expected and proves the production installer cannot silently
            // claim a protected owner contract without that authority.
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
        }
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}
