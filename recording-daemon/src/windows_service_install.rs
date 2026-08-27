#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceSidType, ServiceStartType, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::ipc::{canonical_sid_string, lookup_account_sid, DEFAULT_PIPE_NAME};
use crate::windows_deployment_manifest::{
    publish_windows_deployment_manifest_v1, DeploymentDaclBindingsV1, WindowsDeploymentManifestV1,
};
use crate::windows_deployment_security::{
    apply_and_verify_deployment_ancestor_dacl, apply_and_verify_file_or_directory_dacl,
    apply_and_verify_locked_copy_dacl, apply_and_verify_service_object_dacl,
    copy_new_durable_from_locked_source, inspect_stable_deployment_path,
    lock_deployment_ancestor_chain, lock_exact_deployment_leaf_chain,
    remove_exact_deployment_object, verify_service_object_dacl, DeploymentFileIdentityV1,
    DeploymentSecuritySpec,
};
use crate::windows_service_host::{
    ServiceHostConfig, DEFAULT_ANALYSIS_PIPE_NAME, DEFAULT_HARDWARE_PIPE_NAME,
    SCM_FAILURE_RESET_SECONDS, SCM_RESTART_DELAYS_SECONDS, SERVICE_ACCOUNT_NAME, SERVICE_NAME,
};
use crate::ProtectedDirectPodPolicyReference;

pub const INSTALL_CONFIRMATION: &str = "INSTALL-FORGE-ACQUIRE-SERVICE";
const DISPLAY_NAME: &str = "Forge Acquire Data Plane";
const DESCRIPTION: &str =
    "Independent Forge neural acquisition journal and authenticated local control plane";

pub(crate) struct ScmServiceContractExpectation<'a> {
    pub launch_command_line: &'a OsStr,
    pub start_type: ServiceStartType,
    pub failure_actions: &'a ServiceFailureActions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScmServiceContractEvidence {
    pub binary_path_readback_verified: bool,
    pub service_type_verified: bool,
    pub start_type_verified: bool,
    pub error_control_verified: bool,
    pub account_verified: bool,
    pub dependencies_empty_verified: bool,
    pub load_order_group_empty_verified: bool,
    pub tag_id_zero_verified: bool,
    pub service_sid_type_verified: bool,
    pub failure_actions_verified: bool,
    pub non_crash_failures_enabled: bool,
    pub service_object_owner_system_verified: bool,
    pub service_object_dacl_verified: bool,
    pub full_service_contract_verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScmConfigChecks {
    binary_path: bool,
    service_type: bool,
    start_type: bool,
    error_control: bool,
    account: bool,
    dependencies_empty: bool,
    load_order_group_empty: bool,
    tag_id_zero: bool,
}

impl ScmConfigChecks {
    fn complete(self) -> bool {
        self.binary_path
            && self.service_type
            && self.start_type
            && self.error_control
            && self.account
            && self.dependencies_empty
            && self.load_order_group_empty
            && self.tag_id_zero
    }
}

fn evaluate_scm_config(
    actual: &windows_service::service::ServiceConfig,
    expected: &ScmServiceContractExpectation<'_>,
) -> ScmConfigChecks {
    ScmConfigChecks {
        binary_path: actual.executable_path.as_os_str() == expected.launch_command_line,
        service_type: actual.service_type == ServiceType::OWN_PROCESS,
        start_type: actual.start_type == expected.start_type,
        error_control: actual.error_control == ServiceErrorControl::Normal,
        account: actual
            .account_name
            .as_ref()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("LocalSystem")),
        dependencies_empty: actual.dependencies.is_empty(),
        load_order_group_empty: actual.load_order_group.is_none(),
        tag_id_zero: actual.tag_id == 0,
    }
}

/// Single fail-closed SCM contract verifier shared by install-time Disabled,
/// install-time OnDemand, and runtime pre-spawn gates.
pub(crate) fn verify_scm_service_contract(
    service: &windows_service::service::Service,
    expected: &ScmServiceContractExpectation<'_>,
    spec: &DeploymentSecuritySpec,
) -> io::Result<ScmServiceContractEvidence> {
    let actual = service
        .query_config()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let config = evaluate_scm_config(&actual, expected);
    let sid = service
        .get_config_service_sid_info()
        .map_err(|error| io::Error::other(error.to_string()))?
        == ServiceSidType::Unrestricted;
    let failure_actions = service
        .get_failure_actions()
        .map_err(|error| io::Error::other(error.to_string()))?
        == *expected.failure_actions;
    let non_crash = service
        .get_failure_actions_on_non_crash_failures()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let security = unsafe { verify_service_object_dacl(service.raw_handle().cast(), spec) }?;
    let mut evidence = ScmServiceContractEvidence {
        binary_path_readback_verified: config.binary_path,
        service_type_verified: config.service_type,
        start_type_verified: config.start_type,
        error_control_verified: config.error_control,
        account_verified: config.account,
        dependencies_empty_verified: config.dependencies_empty,
        load_order_group_empty_verified: config.load_order_group_empty,
        tag_id_zero_verified: config.tag_id_zero,
        service_sid_type_verified: sid,
        failure_actions_verified: failure_actions,
        non_crash_failures_enabled: non_crash,
        service_object_owner_system_verified: security.owner_system,
        service_object_dacl_verified: security.protected && security.matches,
        full_service_contract_verified: false,
    };
    evidence.full_service_contract_verified = config.complete()
        && evidence.service_sid_type_verified
        && evidence.failure_actions_verified
        && evidence.non_crash_failures_enabled
        && evidence.service_object_owner_system_verified
        && evidence.service_object_dacl_verified;
    if !evidence.full_service_contract_verified {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SCM service object drifted from the complete ForgeAcquire contract",
        ));
    }
    Ok(evidence)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceInstallPlan {
    pub service_name: String,
    pub display_name: String,
    /// Unprotected build artifact copied exactly once during installation.
    pub source_executable_path: PathBuf,
    /// Protected installed artifact used by the SCM binary path.
    pub executable_path: PathBuf,
    pub deployment_directory: PathBuf,
    pub deployment_manifest_path: PathBuf,
    pub executable_sha256_hex: String,
    pub executable_bytes: u64,
    /// Stable source identity frozen when the plan is created. Installation
    /// reopens the source by handle and requires this exact identity.
    pub source_executable_identity: DeploymentFileIdentityV1,
    pub launch_command_line: String,
    pub data_root: PathBuf,
    pub operator_sid: String,
    pub pipe_name: String,
    pub hardware_pipe_name: String,
    pub analysis_worker_sid: Option<String>,
    pub analysis_pipe_name: Option<String>,
    pub direct_pod_policy_path: Option<PathBuf>,
    pub direct_pod_policy_sha256: Option<String>,
    pub internal_approval_authority_sha256: Option<String>,
    pub start_type: String,
    pub account: String,
    pub service_sid_type: String,
    pub restart_delays_seconds: [u64; 3],
    pub failure_reset_seconds: u64,
    pub starts_service: bool,
}

impl ServiceInstallPlan {
    pub fn new(
        executable_path: impl AsRef<Path>,
        data_root: impl AsRef<Path>,
        operator_sid: &str,
    ) -> io::Result<Self> {
        Self::new_with_analysis_worker(executable_path, data_root, operator_sid, None)
    }

    pub fn new_with_analysis_worker(
        executable_path: impl AsRef<Path>,
        data_root: impl AsRef<Path>,
        operator_sid: &str,
        analysis_worker_sid: Option<&str>,
    ) -> io::Result<Self> {
        Self::new_with_hardware_policy(
            executable_path,
            data_root,
            operator_sid,
            analysis_worker_sid,
            None,
        )
    }

    pub fn new_with_hardware_policy(
        executable_path: impl AsRef<Path>,
        data_root: impl AsRef<Path>,
        operator_sid: &str,
        analysis_worker_sid: Option<&str>,
        direct_pod_policy: Option<&ProtectedDirectPodPolicyReference>,
    ) -> io::Result<Self> {
        let source_executable_path = executable_path.as_ref();
        let data_root = data_root.as_ref();
        if !source_executable_path.is_absolute() || !source_executable_path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "service executable must be an existing absolute file",
            ));
        }
        if !data_root.is_absolute() || !data_root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "service data root must be an existing absolute directory",
            ));
        }
        let source_executable_identity = inspect_stable_deployment_path(source_executable_path)?;
        if source_executable_identity.is_directory || source_executable_identity.link_count != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "service executable must be a non-hardlinked regular file",
            ));
        }
        let data_root_identity = inspect_stable_deployment_path(data_root)?;
        if !data_root_identity.is_directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "service data root stable handle is not a directory",
            ));
        }
        // Freeze one handle-derived spelling before any plan field, manifest
        // input, or SCM command is rendered. `GetFinalPathNameByHandleW` may
        // use an extended DOS spelling; that is intentionally retained rather
        // than compared later against an arbitrary user spelling.
        let source_executable_path = PathBuf::from(&source_executable_identity.canonical_path);
        let data_root = PathBuf::from(&data_root_identity.canonical_path);
        let deployment_directory = data_root.join(".forge-deployment");
        if deployment_directory.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Forge deployment directory already exists; reinstall never overwrites it",
            ));
        }
        let deployed_executable_path = deployment_directory.join("forge-acqd.exe");
        let deployment_manifest_path = deployment_directory.join("forge-acqd.deployment.v1.json");
        let mut arguments = vec![
            OsString::from("--data-root"),
            data_root.as_os_str().to_owned(),
            OsString::from("--operator-sid"),
            OsString::from(operator_sid),
        ];
        if let Some(worker_sid) = analysis_worker_sid {
            arguments.extend([
                OsString::from("--analysis-worker-sid"),
                OsString::from(worker_sid),
            ]);
        }
        if let Some(policy) = direct_pod_policy {
            arguments.extend([
                OsString::from("--direct-pod-policy"),
                policy.path().as_os_str().to_owned(),
                OsString::from("--direct-pod-policy-sha256"),
                OsString::from(policy.expected_file_sha256_hex()),
                OsString::from("--internal-approval-authority-sha256"),
                OsString::from(policy.expected_approval_authority_sha256_hex()),
            ]);
        }
        let config = ServiceHostConfig::parse(arguments)?;
        let configured_policy = config.direct_pod_policy.as_ref();
        let executable_sha256_hex = sha256_file_hex(&source_executable_path)?;
        let executable_bytes = source_executable_identity.bytes;
        let mut plan = Self {
            service_name: SERVICE_NAME.to_owned(),
            display_name: DISPLAY_NAME.to_owned(),
            source_executable_path,
            executable_path: deployed_executable_path,
            deployment_directory,
            deployment_manifest_path,
            executable_sha256_hex,
            executable_bytes,
            source_executable_identity,
            launch_command_line: String::new(),
            data_root: config.data_root,
            operator_sid: canonical_sid_string(&config.operator_sid)?,
            pipe_name: DEFAULT_PIPE_NAME.to_owned(),
            hardware_pipe_name: DEFAULT_HARDWARE_PIPE_NAME.to_owned(),
            analysis_worker_sid: config.analysis_worker_sid,
            analysis_pipe_name: analysis_worker_sid.map(|_| DEFAULT_ANALYSIS_PIPE_NAME.to_owned()),
            direct_pod_policy_path: configured_policy.map(|policy| policy.path().to_path_buf()),
            direct_pod_policy_sha256: configured_policy
                .map(ProtectedDirectPodPolicyReference::expected_file_sha256_hex),
            internal_approval_authority_sha256: configured_policy
                .map(ProtectedDirectPodPolicyReference::expected_approval_authority_sha256_hex),
            start_type: "on_demand_until_deployment_qualified".to_owned(),
            account: "LocalSystem".to_owned(),
            service_sid_type: "unrestricted".to_owned(),
            restart_delays_seconds: SCM_RESTART_DELAYS_SECONDS,
            failure_reset_seconds: SCM_FAILURE_RESET_SECONDS,
            starts_service: false,
        };
        plan.launch_command_line = render_launch_command(&plan.service_info())?;
        Ok(plan)
    }

    /// Rehashes the exact executable named by the plan.  Call this immediately
    /// before every privileged install/start transition; a plan is evidence,
    /// not a lock on a mutable filesystem path.
    pub fn verify_executable_unchanged(&self) -> io::Result<()> {
        let identity = inspect_stable_deployment_path(&self.source_executable_path)?;
        if identity != self.source_executable_identity
            || identity.bytes != self.executable_bytes
            || sha256_file_hex(&self.source_executable_path)? != self.executable_sha256_hex
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "service executable changed after the install plan was frozen",
            ));
        }
        Ok(())
    }

    fn service_info(&self) -> ServiceInfo {
        self.service_info_with_start(ServiceStartType::OnDemand)
    }

    fn service_info_with_start(&self, start_type: ServiceStartType) -> ServiceInfo {
        let mut launch_arguments = vec![
            OsString::from("service-dispatch"),
            OsString::from("--data-root"),
            self.data_root.as_os_str().to_owned(),
            OsString::from("--operator-sid"),
            OsString::from(&self.operator_sid),
            OsString::from("--pipe"),
            OsString::from(&self.pipe_name),
            OsString::from("--hardware-pipe"),
            OsString::from(&self.hardware_pipe_name),
            OsString::from("--deployment-manifest"),
            self.deployment_manifest_path.as_os_str().to_owned(),
        ];
        if let (Some(worker_sid), Some(pipe_name)) =
            (&self.analysis_worker_sid, &self.analysis_pipe_name)
        {
            launch_arguments.extend([
                OsString::from("--analysis-worker-sid"),
                OsString::from(worker_sid),
                OsString::from("--analysis-pipe"),
                OsString::from(pipe_name),
            ]);
        }
        if let (Some(path), Some(policy_hash), Some(authority_hash)) = (
            &self.direct_pod_policy_path,
            &self.direct_pod_policy_sha256,
            &self.internal_approval_authority_sha256,
        ) {
            launch_arguments.extend([
                OsString::from("--direct-pod-policy"),
                path.as_os_str().to_owned(),
                OsString::from("--direct-pod-policy-sha256"),
                OsString::from(policy_hash),
                OsString::from("--internal-approval-authority-sha256"),
                OsString::from(authority_hash),
            ]);
        }
        ServiceInfo {
            name: OsString::from(&self.service_name),
            display_name: OsString::from(&self.display_name),
            service_type: ServiceType::OWN_PROCESS,
            start_type,
            error_control: ServiceErrorControl::Normal,
            executable_path: self.executable_path.clone(),
            launch_arguments,
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        }
    }

    fn host_config(&self) -> io::Result<ServiceHostConfig> {
        let mut arguments = vec![
            OsString::from("--data-root"),
            self.data_root.as_os_str().to_owned(),
            OsString::from("--operator-sid"),
            OsString::from(&self.operator_sid),
            OsString::from("--pipe"),
            OsString::from(&self.pipe_name),
            OsString::from("--hardware-pipe"),
            OsString::from(&self.hardware_pipe_name),
        ];
        if let (Some(worker_sid), Some(pipe_name)) =
            (&self.analysis_worker_sid, &self.analysis_pipe_name)
        {
            arguments.extend([
                OsString::from("--analysis-worker-sid"),
                OsString::from(worker_sid),
                OsString::from("--analysis-pipe"),
                OsString::from(pipe_name),
            ]);
        }
        if let (Some(path), Some(policy_hash), Some(authority_hash)) = (
            &self.direct_pod_policy_path,
            &self.direct_pod_policy_sha256,
            &self.internal_approval_authority_sha256,
        ) {
            arguments.extend([
                OsString::from("--direct-pod-policy"),
                path.as_os_str().to_owned(),
                OsString::from("--direct-pod-policy-sha256"),
                OsString::from(policy_hash),
                OsString::from("--internal-approval-authority-sha256"),
                OsString::from(authority_hash),
            ]);
        }
        ServiceHostConfig::parse(arguments)
    }

    fn failure_actions(&self) -> ServiceFailureActions {
        ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(
                self.failure_reset_seconds,
            )),
            reboot_msg: None,
            command: None,
            actions: Some(
                self.restart_delays_seconds
                    .into_iter()
                    .map(|seconds| ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(seconds),
                    })
                    .collect(),
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceInstallReceipt {
    pub service_name: String,
    pub executable_path: PathBuf,
    pub executable_sha256_hex: String,
    pub executable_bytes: u64,
    pub launch_command_line: String,
    pub binary_path_readback_verified: bool,
    pub service_type_verified: bool,
    pub start_type_verified: bool,
    pub error_control_verified: bool,
    pub account_verified: bool,
    pub dependencies_empty_verified: bool,
    pub service_sid: String,
    pub service_sid_type_verified: bool,
    pub failure_actions_verified: bool,
    pub non_crash_failures_enabled: bool,
    pub deployment_directory_dacl_verified: bool,
    pub deployed_executable_dacl_verified: bool,
    pub deployment_manifest_dacl_verified: bool,
    pub service_object_dacl_verified: bool,
    pub service_object_owner_system_verified: bool,
    pub full_service_contract_verified: bool,
    pub data_root_dacl_verified: bool,
    pub runtime_pipe_dacl_verified: bool,
    pub service_started: bool,
}

#[derive(Default)]
struct InstallCreatedArtifacts {
    deployment_directory: Option<DeploymentFileIdentityV1>,
    executable: Option<DeploymentFileIdentityV1>,
    manifest: Option<DeploymentFileIdentityV1>,
    manifest_publication_started: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceRollbackStep {
    ChangeDisabled,
    VerifyDisabled,
    Delete,
}

fn service_rollback_order() -> [ServiceRollbackStep; 3] {
    [
        ServiceRollbackStep::ChangeDisabled,
        ServiceRollbackStep::VerifyDisabled,
        ServiceRollbackStep::Delete,
    ]
}

/// Installs a new service and refuses to overwrite an existing one. This
/// privileged operation is deliberately separate from the GUI and requires an
/// exact confirmation token. It configures but does not start the service;
/// data-root ACL qualification and deployment HIL remain separate gates.
/// A failed install may leave `data_root` more restrictive after its exact
/// DACL is applied; this is fail-closed hardening, not a transactional claim.
pub fn install_service(
    plan: &ServiceInstallPlan,
    confirmation: &str,
) -> windows_service::Result<ServiceInstallReceipt> {
    if confirmation != INSTALL_CONFIRMATION {
        return Err(windows_service::Error::Winapi(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "exact service-install confirmation token is required",
        )));
    }
    plan.verify_executable_unchanged()
        .map_err(windows_service::Error::Winapi)?;
    // Do not create or configure an SCM object until the user-selected data
    // root's existing ancestry is proven non-replaceable by broad principals.
    let _locked_data_root_ancestors =
        lock_deployment_ancestor_chain(&plan.data_root, &plan.operator_sid)
            .map_err(windows_service::Error::Winapi)?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let disabled_service_info = plan.service_info_with_start(ServiceStartType::Disabled);
    validate_local_system_creation_info(&disabled_service_info)
        .map_err(windows_service::Error::Winapi)?;
    let access = ServiceAccess::QUERY_CONFIG
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::DELETE
        | ServiceAccess::READ_CONTROL
        | ServiceAccess::WRITE_DAC
        | ServiceAccess::WRITE_OWNER;
    let service = manager.create_service(&disabled_service_info, access)?;
    let mut created = InstallCreatedArtifacts::default();
    let configured = (|| {
        service.set_config_service_sid_info(ServiceSidType::Unrestricted)?;
        let service_sid =
            lookup_account_sid(SERVICE_ACCOUNT_NAME).map_err(windows_service::Error::Winapi)?;
        let spec = DeploymentSecuritySpec::new(&service_sid, &plan.operator_sid)
            .map_err(windows_service::Error::Winapi)?;
        // Lock the service object before any subsequent deployment work.
        let service_evidence =
            unsafe { apply_and_verify_service_object_dacl(service.raw_handle().cast(), &spec) }
                .map_err(windows_service::Error::Winapi)?;
        service.set_description(DESCRIPTION)?;
        let expected_failure_actions = plan.failure_actions();
        service.update_failure_actions(expected_failure_actions.clone())?;
        service.set_failure_actions_on_non_crash_failures(true)?;

        plan.verify_executable_unchanged()
            .map_err(windows_service::Error::Winapi)?;
        let disabled_expectation = ScmServiceContractExpectation {
            launch_command_line: OsStr::new(&plan.launch_command_line),
            start_type: ServiceStartType::Disabled,
            failure_actions: &expected_failure_actions,
        };
        let _disabled_contract =
            verify_scm_service_contract(&service, &disabled_expectation, &spec)
                .map_err(windows_service::Error::Winapi)?;
        if plan.deployment_directory.exists()
            || plan.executable_path.exists()
            || plan.deployment_manifest_path.exists()
        {
            return Err(windows_service::Error::Winapi(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "deployment target already exists; install refuses overwrite",
            )));
        }
        // Harden the parent before creating the child directory. Failure here
        // intentionally leaves the root restricted rather than permitting an
        // unprotected deployment window; rollback never recursively changes
        // user-owned data-root contents.
        let data_root_evidence = apply_and_verify_deployment_ancestor_dacl(&plan.data_root, &spec)
            .map_err(windows_service::Error::Winapi)?;
        std::fs::create_dir(&plan.deployment_directory).map_err(windows_service::Error::Winapi)?;
        let deployment_directory_identity =
            inspect_stable_deployment_path(&plan.deployment_directory)
                .map_err(windows_service::Error::Winapi)?;
        if deployment_directory_identity.canonical_path
            != strict_unicode_path(&plan.deployment_directory, "deployment directory path")
                .map_err(windows_service::Error::Winapi)?
        {
            return Err(windows_service::Error::Winapi(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "created deployment directory spelling differs from frozen handle path",
            )));
        }
        created.deployment_directory = Some(deployment_directory_identity);
        let directory_evidence =
            apply_and_verify_file_or_directory_dacl(&plan.deployment_directory, &spec)
                .map_err(windows_service::Error::Winapi)?;
        // Retain a second, post-create chain through the new deployment
        // directory for the rest of this transaction.  Win32 does not offer
        // a fully auditable handle-relative create/resolve primitive here;
        // this is verified handle-chain revalidation, not a power-cut or
        // administrator qualification claim.
        let locked_deployment_ancestors =
            lock_exact_deployment_leaf_chain(&plan.deployment_directory, &plan.operator_sid, &spec)
                .map_err(windows_service::Error::Winapi)?;
        plan.verify_executable_unchanged()
            .map_err(windows_service::Error::Winapi)?;
        let deployed_artifact = copy_new_durable_from_locked_source(
            &plan.source_executable_path,
            &plan.executable_path,
            &plan.source_executable_identity,
            &plan.executable_sha256_hex,
            plan.executable_bytes,
        )
        .map_err(windows_service::Error::Winapi)?;
        if deployed_artifact.destination_identity().canonical_path
            != strict_unicode_path(&plan.executable_path, "deployment executable path")
                .map_err(windows_service::Error::Winapi)?
        {
            return Err(windows_service::Error::Winapi(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "created deployment executable spelling differs from frozen handle path",
            )));
        }
        created.executable = Some(deployed_artifact.destination_identity().clone());
        let deployed_evidence = apply_and_verify_locked_copy_dacl(&deployed_artifact, &spec)
            .map_err(windows_service::Error::Winapi)?;
        if deployed_evidence.object_sha256_hex.as_deref()
            != Some(plan.executable_sha256_hex.as_str())
            || deployed_evidence
                .stable_identity
                .as_ref()
                .is_none_or(|identity| identity != deployed_artifact.destination_identity())
        {
            return Err(windows_service::Error::Winapi(io::Error::new(
                io::ErrorKind::InvalidData,
                "deployed executable hash or byte count differs from frozen source",
            )));
        }
        let manifest = WindowsDeploymentManifestV1::build_with_executable_identity(
            strict_unicode_path(&plan.deployment_manifest_path, "deployment manifest path")
                .map_err(windows_service::Error::Winapi)?,
            deployed_artifact
                .destination_identity()
                .canonical_path
                .clone(),
            &plan.executable_sha256_hex,
            plan.executable_bytes,
            deployed_artifact.destination_identity().clone(),
            &service_sid,
            &plan.host_config().map_err(windows_service::Error::Winapi)?,
            DeploymentDaclBindingsV1 {
                service_object_contract_sha256_hex: spec.service_object_contract_sha256_hex(),
                executable_parent_contract_sha256_hex: spec
                    .file_or_directory_contract_sha256_hex(true),
                executable_contract_sha256_hex: spec.file_or_directory_contract_sha256_hex(false),
                data_root_contract_sha256_hex: spec.ancestor_directory_contract_sha256_hex(),
                manifest_contract_sha256_hex: spec.file_or_directory_contract_sha256_hex(false),
                service_object_protected_and_exact: service_evidence.protected
                    && service_evidence.matches,
                executable_parent_protected_and_exact: directory_evidence.protected
                    && directory_evidence.matches,
                executable_protected_and_exact: deployed_evidence.protected
                    && deployed_evidence.matches,
                data_root_protected_and_exact: data_root_evidence.protected
                    && data_root_evidence.matches,
                // The deployment directory is already protected before the
                // create-new/no-replace manifest publication. The manifest
                // itself is immediately hardened and read back below.
                manifest_protected_and_exact: true,
                runtime_pipe_dacl_qualified: false,
            },
        )
        .map_err(windows_service::Error::Winapi)?;
        created.manifest_publication_started = true;
        publish_windows_deployment_manifest_v1(&manifest, &locked_deployment_ancestors)
            .map_err(windows_service::Error::Winapi)?;
        let manifest_evidence =
            apply_and_verify_file_or_directory_dacl(&plan.deployment_manifest_path, &spec)
                .map_err(windows_service::Error::Winapi)?;
        if !manifest_evidence.protected || !manifest_evidence.matches {
            return Err(windows_service::Error::Winapi(io::Error::other(
                "deployment manifest DACL readback did not prove exact protection",
            )));
        }
        created.manifest = manifest_evidence.stable_identity.clone();
        service.change_config(&plan.service_info())?;
        let final_expectation = ScmServiceContractExpectation {
            launch_command_line: OsStr::new(&plan.launch_command_line),
            start_type: ServiceStartType::OnDemand,
            failure_actions: &expected_failure_actions,
        };
        let final_contract = verify_scm_service_contract(&service, &final_expectation, &spec)
            .map_err(windows_service::Error::Winapi)?;
        Ok(ServiceInstallReceipt {
            service_name: plan.service_name.clone(),
            executable_path: plan.executable_path.clone(),
            executable_sha256_hex: plan.executable_sha256_hex.clone(),
            executable_bytes: plan.executable_bytes,
            launch_command_line: plan.launch_command_line.clone(),
            binary_path_readback_verified: final_contract.binary_path_readback_verified,
            service_type_verified: final_contract.service_type_verified,
            start_type_verified: final_contract.start_type_verified,
            error_control_verified: final_contract.error_control_verified,
            account_verified: final_contract.account_verified,
            dependencies_empty_verified: final_contract.dependencies_empty_verified,
            service_sid,
            service_sid_type_verified: final_contract.service_sid_type_verified,
            failure_actions_verified: final_contract.failure_actions_verified,
            non_crash_failures_enabled: final_contract.non_crash_failures_enabled,
            // These are deliberately separate deployment gates.  Installation
            // must never imply runtime token/DACL qualification.
            deployment_directory_dacl_verified: directory_evidence.protected
                && directory_evidence.matches,
            deployed_executable_dacl_verified: deployed_evidence.protected
                && deployed_evidence.matches,
            deployment_manifest_dacl_verified: manifest_evidence.protected
                && manifest_evidence.matches,
            service_object_dacl_verified: final_contract.service_object_dacl_verified,
            service_object_owner_system_verified: final_contract
                .service_object_owner_system_verified,
            full_service_contract_verified: final_contract.full_service_contract_verified,
            data_root_dacl_verified: data_root_evidence.protected && data_root_evidence.matches,
            runtime_pipe_dacl_verified: false,
            service_started: false,
        })
    })();
    if let Err(error) = configured {
        let service_rollback = rollback_service_disabled_then_delete(&service, plan).err();
        let deployment_rollback = remove_exact_install_targets(plan, &created).err();
        if service_rollback.is_none() && deployment_rollback.is_none() {
            return Err(error);
        }
        return Err(windows_service::Error::Winapi(io::Error::other(format!(
            "service installation failed ({error}); service rollback={service_rollback:?}; exact deployment rollback={deployment_rollback:?}"
        ))));
    }
    configured
}

/// Roll back only objects this install recorded after create/open identity
/// observation.  Missing records (notably an interrupted `.pending` manifest)
/// are deliberately retained rather than guessed at.  Each delete is bound to
/// one checked handle; the directory removal naturally fails when non-empty.
fn remove_exact_install_targets(
    plan: &ServiceInstallPlan,
    created: &InstallCreatedArtifacts,
) -> io::Result<()> {
    let unproven_manifest = created.manifest_publication_started && created.manifest.is_none();
    if let Some(identity) = &created.manifest {
        remove_exact_deployment_object(&plan.deployment_manifest_path, identity)?;
    }
    if let Some(identity) = &created.executable {
        remove_exact_deployment_object(&plan.executable_path, identity)?;
    }
    if unproven_manifest {
        return Err(io::Error::other(
            "manifest publication began without a recorded stable identity; retaining manifest/pending path and deployment directory",
        ));
    }
    if let Some(identity) = &created.deployment_directory {
        remove_exact_deployment_object(&plan.deployment_directory, identity)?;
    }
    Ok(())
}

fn rollback_service_disabled_then_delete(
    service: &windows_service::service::Service,
    plan: &ServiceInstallPlan,
) -> windows_service::Result<()> {
    debug_assert_eq!(
        service_rollback_order(),
        [
            ServiceRollbackStep::ChangeDisabled,
            ServiceRollbackStep::VerifyDisabled,
            ServiceRollbackStep::Delete,
        ]
    );
    service.change_config(&plan.service_info_with_start(ServiceStartType::Disabled))?;
    let readback = service.query_config()?;
    if readback.start_type != ServiceStartType::Disabled {
        return Err(windows_service::Error::Winapi(io::Error::other(
            "SCM rollback refused deletion because Disabled readback was not proven",
        )));
    }
    match service.delete() {
        Ok(()) => Ok(()),
        Err(error) => Err(windows_service::Error::Winapi(io::Error::other(format!(
            "SCM delete failed after Disabled readback; service remains Disabled: {error}"
        )))),
    }
}

fn strict_unicode_path(path: &Path, label: &'static str) -> io::Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} is not valid Unicode"),
        )
    })
}

fn validate_local_system_creation_info(info: &ServiceInfo) -> io::Result<()> {
    if info.service_type != ServiceType::OWN_PROCESS
        || info.error_control != ServiceErrorControl::Normal
        || !info.dependencies.is_empty()
        || info.account_name.is_some()
        || info.account_password.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "LocalSystem service creation must use OwnProcess, Normal error control, no dependencies, and no account/password material",
        ));
    }
    Ok(())
}

fn render_launch_command(info: &ServiceInfo) -> io::Result<String> {
    let mut encoded =
        crate::windows_service_host::quote_windows_scm_argument(info.executable_path.as_os_str())?;
    for argument in &info.launch_arguments {
        encoded.push(' ');
        encoded.push_str(&crate::windows_service_host::quote_windows_scm_argument(
            argument,
        )?);
    }
    Ok(encoded)
}

fn sha256_file_hex(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows_service::service::{ServiceConfig, ServiceDependency};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn plan_is_exact_bounded_and_never_starts_the_service() {
        let root = std::env::temp_dir().join(format!(
            "forge-service-install-plan-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("forge-acqd.exe");
        std::fs::write(&executable, b"test-only").unwrap();
        let sid = crate::ipc::current_process_user_sid().unwrap();
        let plan = ServiceInstallPlan::new(&executable, &root, &sid).unwrap();
        assert_eq!(plan.operator_sid, sid);
        assert_eq!(plan.executable_bytes, 9);
        assert_eq!(plan.executable_sha256_hex.len(), 64);
        assert!(plan
            .executable_sha256_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert!(plan.launch_command_line.contains("service-dispatch"));
        assert!(plan.launch_command_line.contains("--data-root"));
        assert!(plan.launch_command_line.contains("--deployment-manifest"));
        let canonical_source = PathBuf::from(
            inspect_stable_deployment_path(&executable)
                .unwrap()
                .canonical_path,
        );
        let canonical_root = PathBuf::from(
            inspect_stable_deployment_path(&root)
                .unwrap()
                .canonical_path,
        );
        assert_eq!(plan.source_executable_path, canonical_source);
        assert_eq!(plan.data_root, canonical_root);
        assert_eq!(
            plan.executable_path,
            plan.data_root
                .join(".forge-deployment")
                .join("forge-acqd.exe")
        );
        assert_eq!(
            plan.deployment_manifest_path,
            plan.data_root
                .join(".forge-deployment")
                .join("forge-acqd.deployment.v1.json")
        );
        assert!(plan.launch_command_line.contains(
            plan.executable_path
                .to_str()
                .expect("handle-derived deployment path is Unicode")
        ));
        assert!(plan.launch_command_line.contains(
            plan.deployment_manifest_path
                .to_str()
                .expect("handle-derived manifest path is Unicode")
        ));
        plan.verify_executable_unchanged().unwrap();
        assert_eq!(plan.pipe_name, DEFAULT_PIPE_NAME);
        assert_eq!(plan.hardware_pipe_name, DEFAULT_HARDWARE_PIPE_NAME);
        assert_eq!(plan.analysis_worker_sid, None);
        assert_eq!(plan.restart_delays_seconds, [5, 15, 60]);
        assert!(!plan.starts_service);
        let info = plan.service_info();
        assert_eq!(info.executable_path, plan.executable_path);
        assert!(info
            .launch_arguments
            .iter()
            .any(|argument| argument == plan.deployment_manifest_path.as_os_str()));
        assert_eq!(info.launch_arguments.len(), 11);
        validate_local_system_creation_info(&info).unwrap();
        assert!(info.account_name.is_none());
        assert!(info.account_password.is_none());
        assert!(info.dependencies.is_empty());
        let with_worker =
            ServiceInstallPlan::new_with_analysis_worker(&executable, &root, &sid, Some(&sid))
                .unwrap();
        assert_eq!(
            with_worker.analysis_worker_sid.as_deref(),
            Some(sid.as_str())
        );
        assert_eq!(with_worker.service_info().launch_arguments.len(), 15);
        let policy_path = root.join("direct-pod-policy.json");
        std::fs::write(&policy_path, b"test-only").unwrap();
        let policy =
            ProtectedDirectPodPolicyReference::new(&policy_path, [1; 32], [2; 32]).unwrap();
        let with_policy = ServiceInstallPlan::new_with_hardware_policy(
            &executable,
            &root,
            &sid,
            None,
            Some(&policy),
        )
        .unwrap();
        assert_eq!(
            with_policy.direct_pod_policy_path.as_deref(),
            Some(policy_path.as_path())
        );
        assert_eq!(with_policy.service_info().launch_arguments.len(), 17);
        assert_eq!(plan.failure_actions().actions.unwrap().len(), 3);
        assert!(ServiceInstallPlan::new("relative.exe", &root, &sid).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn complete_scm_config_rejects_dependencies_and_final_phase_drift() {
        let failure_actions = ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            }]),
        };
        let expected = ScmServiceContractExpectation {
            launch_command_line: OsStr::new(r#""C:\Forge\forge-acqd.exe" service-dispatch"#),
            start_type: ServiceStartType::OnDemand,
            failure_actions: &failure_actions,
        };
        let mut actual = ServiceConfig {
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: PathBuf::from(expected.launch_command_line),
            load_order_group: None,
            tag_id: 0,
            dependencies: Vec::new(),
            account_name: Some(OsString::from("LocalSystem")),
            display_name: OsString::from("Forge Acquire Data Plane"),
        };
        assert!(evaluate_scm_config(&actual, &expected).complete());
        actual
            .dependencies
            .push(ServiceDependency::Service(OsString::from(
                "UntrustedDependency",
            )));
        let dependency_drift = evaluate_scm_config(&actual, &expected);
        assert!(!dependency_drift.dependencies_empty);
        assert!(!dependency_drift.complete());
        actual.dependencies.clear();
        actual.start_type = ServiceStartType::Disabled;
        let phase_drift = evaluate_scm_config(&actual, &expected);
        assert!(!phase_drift.start_type);
        assert!(!phase_drift.complete());
    }

    #[test]
    fn local_system_creation_rejects_any_password_or_dependency() {
        let root = std::env::temp_dir().join(format!(
            "forge-service-install-secrets-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("forge-acqd.exe");
        std::fs::write(&executable, b"test-only").unwrap();
        let sid = crate::ipc::current_process_user_sid().unwrap();
        let plan = ServiceInstallPlan::new(&executable, &root, &sid).unwrap();
        let mut info = plan.service_info_with_start(ServiceStartType::Disabled);
        info.account_password = Some(OsString::from("must-never-exist"));
        assert!(validate_local_system_creation_info(&info).is_err());
        info.account_password = None;
        info.dependencies
            .push(ServiceDependency::Service(OsString::from("OtherService")));
        assert!(validate_local_system_creation_info(&info).is_err());
        std::fs::remove_file(executable).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn plan_refuses_any_preexisting_deployment_target() {
        let root = std::env::temp_dir().join(format!(
            "forge-service-install-existing-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("forge-acqd.exe");
        std::fs::write(&executable, b"test-only").unwrap();
        let sid = crate::ipc::current_process_user_sid().unwrap();
        std::fs::create_dir(root.join(".forge-deployment")).unwrap();
        let error = ServiceInstallPlan::new(&executable, &root, &sid).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        std::fs::remove_dir(root.join(".forge-deployment")).unwrap();
        std::fs::remove_file(executable).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn windows_argument_quoting_matches_scm_contract() {
        let quote = |value: &str| {
            crate::windows_service_host::quote_windows_scm_argument(std::ffi::OsStr::new(value))
                .unwrap()
        };
        assert_eq!(quote("forge-acqd.exe"), "forge-acqd.exe");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("two words"), "\"two words\"");
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(
            quote("C:\\Program Files\\Forge\\"),
            "\"C:\\Program Files\\Forge\\\\\""
        );
        assert!(
            crate::windows_service_host::quote_windows_scm_argument(std::ffi::OsStr::new(
                "bad\0argument"
            ))
            .is_err()
        );
    }

    #[test]
    fn manifest_path_rejects_invalid_utf16_without_lossy_substitution() {
        use std::os::windows::ffi::OsStringExt;

        let non_unicode = PathBuf::from(OsString::from_wide(&[0xD800]));
        assert!(strict_unicode_path(&non_unicode, "test manifest").is_err());
    }

    #[test]
    fn artifact_drift_is_rejected_before_privileged_scm_access() {
        let root = std::env::temp_dir().join(format!(
            "forge-service-install-drift-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("forge-acqd.exe");
        std::fs::write(&executable, b"before").unwrap();
        let sid = crate::ipc::current_process_user_sid().unwrap();
        let plan = ServiceInstallPlan::new(&executable, &root, &sid).unwrap();

        std::fs::write(&executable, b"after-drift").unwrap();
        let error = plan.verify_executable_unchanged().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("changed after"));

        // The same check is the first operation performed by install_service,
        // before opening the privileged SCM manager or creating any service.
        let error = install_service(&plan, INSTALL_CONFIRMATION).unwrap_err();
        match error {
            windows_service::Error::Winapi(source) => {
                assert_eq!(source.kind(), io::ErrorKind::InvalidData);
                assert!(source.to_string().contains("changed after"));
            }
            other => panic!("unexpected service-install error: {other}"),
        }

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn plan_rejects_hardlinked_source_artifact() {
        let root = std::env::temp_dir().join(format!(
            "forge-service-install-hardlink-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("forge-acqd.exe");
        let link = root.join("forge-acqd-copy.exe");
        std::fs::write(&source, b"test-only").unwrap();
        std::fs::hard_link(&source, &link).unwrap();
        let sid = crate::ipc::current_process_user_sid().unwrap();
        let error = ServiceInstallPlan::new(&source, &root, &sid).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(source).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn rollback_order_proves_disabled_before_delete() {
        assert_eq!(
            service_rollback_order(),
            [
                ServiceRollbackStep::ChangeDisabled,
                ServiceRollbackStep::VerifyDisabled,
                ServiceRollbackStep::Delete,
            ]
        );
    }

    #[test]
    fn rollback_reports_and_retains_manifest_without_proven_identity() {
        let root = std::env::temp_dir().join(format!(
            "forge-service-install-unproven-manifest-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("forge-acqd.exe");
        std::fs::write(&executable, b"test-only").unwrap();
        let sid = crate::ipc::current_process_user_sid().unwrap();
        let plan = ServiceInstallPlan::new(&executable, &root, &sid).unwrap();
        let error = remove_exact_install_targets(
            &plan,
            &InstallCreatedArtifacts {
                manifest_publication_started: true,
                ..InstallCreatedArtifacts::default()
            },
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("without a recorded stable identity"));
        std::fs::remove_file(executable).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
