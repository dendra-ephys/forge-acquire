use std::path::PathBuf;
use std::time::Duration;
use std::{fs::OpenOptions, io::Write};

use forge_acqd::ipc::ipc_boundary;
use forge_acqd::journal::crc32c;
use forge_acqd::source::{DeterministicReplayConfig, DeterministicReplaySource};
#[cfg(feature = "qualification-harness")]
use forge_acqd::{finalize_nwb_publication, publish_nwb_generation};
use forge_acqd::{
    run_journal_qualification, run_protected_replay, verify_journal_qualification_receipt,
    verify_nwb_validation_bundle, AnalysisRing, JournalQualificationOptions,
    JournalQualificationSourceProfile, NwbValidationBundlePaths, ProtectedReplayOptions,
};

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "{}",
            serde_json::json!({
                "schema": "forge.acqd-error.v1",
                "status": "error",
                "message": error,
                "hardware_transport_available": false
            })
        );
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--self-check") if args.next().is_none() => {
            let actual = crc32c(b"123456789");
            let expected = 0xe306_9283;
            if actual != expected {
                return Err(format!("CRC32C self-check failed: {actual:08x}"));
            }
            println!(
                "{}",
                serde_json::json!({
                    "schema": "forge.acqd-self-check.v1",
                    "status": "ok",
                    "crc32c": format!("{actual:08x}"),
                    "hardware_transport_available": false,
                    "secure_ipc_available": false
                })
            );
            Ok(())
        }
        Some("--version") if args.next().is_none() => {
            println!("forge-acqd {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        #[cfg(windows)]
        Some("d3xx-probe") => {
            let mut library_path = None;
            while let Some(argument) = args.next() {
                match argument.as_str() {
                    "--library" => {
                        if library_path.is_some() {
                            return Err("--library may be specified only once".to_owned());
                        }
                        library_path = Some(PathBuf::from(
                            args.next().ok_or("missing absolute DLL path after --library")?,
                        ));
                    }
                    _ => return Err(format!("unknown d3xx-probe option: {argument}")),
                }
            }
            let load = match library_path.as_ref() {
                Some(path) => forge_acqd::D3xxLibrary::load_absolute(path),
                None => forge_acqd::D3xxLibrary::load_system32(),
            };
            match load {
                Ok(library) => {
                    let devices = library
                        .enumerate()
                        .map_err(|error| format!("D3XX enumeration failed: {error}"))?;
                    let devices: Vec<_> = devices
                        .iter()
                        .map(|device| {
                            serde_json::json!({
                                "device_type": device.device_type,
                                "usb_id": format!("{:08x}", device.usb_id),
                                "location_id": device.location_id,
                                "serial_number": device.serial_number,
                                "description": device.description,
                                "opened": device.opened(),
                                "superspeed": device.superspeed()
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema": "forge.d3xx-probe.v1",
                            "status": "driver_loaded_hardware_unqualified",
                            "target_bridge_model": "FT601Q-B-T",
                            "target_device_type": 601,
                            "fifo_width_bits": 32,
                            "byte_enable_bits": 4,
                            "driver_loaded": true,
                            "library_path": library.source_path(),
                            "library_sha256_hex": hex(&library.library_sha256()),
                            "devices": devices,
                            "admission_contract_hash": forge_acqd::FT601_ADMISSION_CONTRACT_HASH_HEX,
                            "approved_admission_receipt_present": false,
                            "approved_configuration_readback_hash_present": false,
                            "approved_hardware_build_hash_present": false,
                            "configuration_readback_verified": false,
                            "hardware_transport_available": false
                        })
                    );
                }
                Err(error) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema": "forge.d3xx-probe.v1",
                            "status": "unavailable",
                            "target_bridge_model": "FT601Q-B-T",
                            "target_device_type": 601,
                            "fifo_width_bits": 32,
                            "byte_enable_bits": 4,
                            "driver_loaded": false,
                            "reason": error.to_string(),
                            "device_count": 0,
                            "admission_contract_hash": forge_acqd::FT601_ADMISSION_CONTRACT_HASH_HEX,
                            "approved_admission_receipt_present": false,
                            "approved_hardware_build_hash_present": false,
                            "configuration_readback_verified": false,
                            "hardware_transport_available": false
                        })
                    );
                }
            }
            Ok(())
        }
        #[cfg(all(windows, feature = "qualification-harness"))]
        Some("gui-kill-owner") => {
            let mut gui_pipe = None;
            let mut control_pipe = None;
            let mut root = None;
            let mut run_id = None;
            let mut supervisor_pid = None;
            let mut supervisor_creation_time = None;
            let mut executable_sha256 = None;
            let mut expected_attempts = None;
            while let Some(argument) = args.next() {
                let value = args
                    .next()
                    .ok_or_else(|| format!("missing value after {argument}"))?;
                match argument.as_str() {
                    "--gui-pipe" if gui_pipe.is_none() => gui_pipe = Some(value),
                    "--control-pipe" if control_pipe.is_none() => control_pipe = Some(value),
                    "--root" if root.is_none() => root = Some(PathBuf::from(value)),
                    "--run-id" if run_id.is_none() => run_id = Some(value),
                    "--supervisor-pid" if supervisor_pid.is_none() => {
                        supervisor_pid = Some(parse(&value, "supervisor PID")?)
                    }
                    "--supervisor-creation-time" if supervisor_creation_time.is_none() => {
                        supervisor_creation_time =
                            Some(parse(&value, "supervisor creation time")?)
                    }
                    "--executable-sha256" if executable_sha256.is_none() => {
                        executable_sha256 = Some(value)
                    }
                    "--expected-attempts" if expected_attempts.is_none() => {
                        expected_attempts = Some(parse(&value, "expected attempts")?)
                    }
                    _ => return Err(format!("unknown or duplicate gui-kill-owner option: {argument}")),
                }
            }
            forge_acqd::run_gui_kill_owner(
                &root.ok_or("--root is required")?,
                &gui_pipe.ok_or("--gui-pipe is required")?,
                &control_pipe.ok_or("--control-pipe is required")?,
                &run_id.ok_or("--run-id is required")?,
                supervisor_pid.ok_or("--supervisor-pid is required")?,
                supervisor_creation_time.ok_or("--supervisor-creation-time is required")?,
                &executable_sha256.ok_or("--executable-sha256 is required")?,
                expected_attempts.ok_or("--expected-attempts is required")?,
            )
            .map_err(|error| format!("GUI-kill owner failed: {error}"))
        }
        #[cfg(all(windows, feature = "qualification-harness"))]
        Some("gui-kill-client") => {
            let mut pipe = None;
            let mut root = None;
            let mut stage = None;
            let mut attempt = None;
            let mut request_id = None;
            while let Some(argument) = args.next() {
                let value = args
                    .next()
                    .ok_or_else(|| format!("missing value after {argument}"))?;
                match argument.as_str() {
                    "--pipe" if pipe.is_none() => pipe = Some(value),
                    "--root" if root.is_none() => root = Some(PathBuf::from(value)),
                    "--stage" if stage.is_none() => stage = Some(value),
                    "--attempt" if attempt.is_none() => attempt = Some(parse(&value, "attempt")?),
                    "--request-id" if request_id.is_none() => {
                        request_id = Some(parse(&value, "request ID")?)
                    }
                    _ => return Err(format!("unknown or duplicate gui-kill-client option: {argument}")),
                }
            }
            forge_acqd::run_gui_kill_client(
                &pipe.ok_or("--pipe is required")?,
                &root.ok_or("--root is required")?,
                &stage.ok_or("--stage is required")?,
                attempt.ok_or("--attempt is required")?,
                request_id.ok_or("--request-id is required")?,
            )
            .map_err(|error| format!("GUI-kill client failed: {error}"))
        }
        #[cfg(windows)]
        Some("software-replay-service") => {
            let options = parse_software_replay_service_args(args)?;
            let service = forge_acqd::software_replay_service::prepare_software_replay_service(
                options,
            )
            .map_err(|error| format!("software replay service setup failed: {error}"))?;
            println!(
                "{}",
                serde_json::to_string(service.reservation())
                    .map_err(|error| error.to_string())?
            );
            service
                .serve()
                .map(|_| ())
                .map_err(|error| format!("software replay service failed: {error}"))
        }
        #[cfg(all(windows, feature = "qualification-harness"))]
        Some("gui-kill-qualification") => {
            let mut root = None;
            let mut receipt = None;
            let mut build_artifact = None;
            let mut kill_count = 1_000_u32;
            let mut injected_failure = None;
            let mut inject_ack_read_failure = false;
            while let Some(argument) = args.next() {
                match argument.as_str() {
                    "--root" if root.is_none() => {
                        root = Some(PathBuf::from(args.next().ok_or("missing root after --root")?))
                    }
                    "--receipt" if receipt.is_none() => {
                        receipt = Some(PathBuf::from(
                            args.next().ok_or("missing receipt after --receipt")?,
                        ))
                    }
                    "--build-artifact" if build_artifact.is_none() => {
                        build_artifact = Some(PathBuf::from(
                            args.next().ok_or("missing build artifact after --build-artifact")?,
                        ))
                    }
                    "--kill-count" => {
                        kill_count = parse(
                            &args.next().ok_or("missing kill count after --kill-count")?,
                            "kill count",
                        )?
                    }
                    "--inject-child-timeout" if injected_failure.is_none() => {
                        injected_failure = Some(forge_acqd::GuiKillInjectedFailure::Timeout)
                    }
                    "--inject-child-exit" if injected_failure.is_none() => {
                        injected_failure = Some(forge_acqd::GuiKillInjectedFailure::Exit)
                    }
                    "--inject-ack-read-failure" if !inject_ack_read_failure => {
                        inject_ack_read_failure = true
                    }
                    _ => return Err(format!("unknown or duplicate gui-kill-qualification option: {argument}")),
                }
            }
            let receipt = forge_acqd::run_gui_kill_qualification(
                forge_acqd::GuiKillQualificationOptions {
                    root: root.ok_or("--root is required")?,
                    receipt_path: receipt.ok_or("--receipt is required")?,
                    executable_path: build_artifact.unwrap_or(std::env::current_exe()
                        .map_err(|error| format!("cannot locate forge-acqd executable: {error}"))?),
                    kill_count,
                    injected_failure,
                    inject_ack_read_failure,
                },
            )
            .map_err(|error| format!("GUI-kill qualification failed: {error}"))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some("protected-replay") => {
            let mut journal_path = None;
            let mut chunks = None;
            let mut payload_bytes = 92_usize;
            let mut durability_batch = 128_u64;
            while let Some(argument) = args.next() {
                let value = args
                    .next()
                    .ok_or_else(|| format!("missing value after {argument}"))?;
                match argument.as_str() {
                    "--journal" => journal_path = Some(PathBuf::from(value)),
                    "--chunks" => chunks = Some(parse(&value, "chunks")?),
                    "--payload-bytes" => payload_bytes = parse(&value, "payload bytes")?,
                    "--durability-batch" => {
                        durability_batch = parse(&value, "durability batch")?
                    }
                    _ => return Err(format!("unknown protected-replay option: {argument}")),
                }
            }
            let receipt = run_protected_replay(ProtectedReplayOptions {
                journal_path: journal_path.ok_or("--journal is required")?,
                chunks: chunks.ok_or("--chunks is required")?,
                sample_payload_bytes: payload_bytes,
                durability_batch_records: durability_batch,
            })
            .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string(&receipt).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some("journal-qualification") => {
            let mut journal_path = None;
            let mut receipt_path = None;
            let mut duration_seconds = None;
            let mut target_bytes_per_second = 190_080_000_u64;
            let mut durability_batch = 1_024_u64;
            let mut source_profile = JournalQualificationSourceProfile::ProtocolMax256;
            while let Some(argument) = args.next() {
                let value = args
                    .next()
                    .ok_or_else(|| format!("missing value after {argument}"))?;
                match argument.as_str() {
                    "--journal" => journal_path = Some(PathBuf::from(value)),
                    "--receipt" => receipt_path = Some(PathBuf::from(value)),
                    "--duration-seconds" => {
                        duration_seconds = Some(parse(&value, "duration seconds")?)
                    }
                    "--target-bytes-per-second" => {
                        target_bytes_per_second = parse(&value, "target bytes per second")?
                    }
                    "--source-profile" => {
                        source_profile = JournalQualificationSourceProfile::parse(&value)
                            .map_err(|error| error.to_string())?
                    }
                    "--durability-batch" => {
                        durability_batch = parse(&value, "durability batch")?
                    }
                    _ => return Err(format!("unknown journal-qualification option: {argument}")),
                }
            }
            let receipt = run_journal_qualification(JournalQualificationOptions {
                journal_path: journal_path.ok_or("--journal is required")?,
                receipt_path: receipt_path.ok_or("--receipt is required")?,
                duration: Duration::from_secs(
                    duration_seconds.ok_or("--duration-seconds is required")?,
                ),
                source_profile,
                target_canonical_bytes_per_second: target_bytes_per_second,
                durability_batch_records: durability_batch,
            })
            .map_err(|error| format!("journal qualification failed: {error}"))?;
            println!(
                "{}",
                serde_json::to_string(&receipt).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Some("analysis-ring-fixture") => {
            let mut output_path = None;
            while let Some(argument) = args.next() {
                let value = args
                    .next()
                    .ok_or_else(|| format!("missing value after {argument}"))?;
                match argument.as_str() {
                    "--output" if output_path.is_none() => output_path = Some(PathBuf::from(value)),
                    _ => {
                        return Err(format!(
                            "unknown or duplicate analysis-ring-fixture option: {argument}"
                        ))
                    }
                }
            }
            let output_path = output_path.ok_or("--output is required")?;
            let mut source = DeterministicReplaySource::new(DeterministicReplayConfig {
                run_id: [0x11; 16],
                pod_id: [0x22; 16],
                headstage_id: [0x33; 16],
                channel_layout_id: 1,
                channel_count: 4,
                samples_per_channel: 30,
                sample_rate_hz: 30_000,
                total_records: 2,
                seed: 0x4f52_4745,
            })
            .map_err(|error| error.to_string())?;
            let mut ring = AnalysisRing::new(4, 4_096, [0x11; 16], [0x44; 16], 7)
                .map_err(|error| error.to_string())?;
            for journal_sequence in 41..=42 {
                let record = source
                    .next_encoded_record()
                    .map_err(|error| error.to_string())?
                    .ok_or("fixture source ended early")?;
                ring.try_publish(&record, journal_sequence, 1_000 + journal_sequence)
                    .map_err(|error| error.to_string())?;
            }
            let snapshot = ring.snapshot();
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output_path)
                .map_err(|error| format!("cannot create fixture without overwrite: {error}"))?;
            output
                .write_all(&snapshot)
                .and_then(|()| output.sync_all())
                .map_err(|error| format!("cannot durably write fixture: {error}"))?;
            println!(
                "{}",
                serde_json::json!({
                    "schema": "forge.analysis-ring-fixture.v1",
                    "status": "snapshot_only",
                    "output": output_path,
                    "bytes": snapshot.len(),
                    "published_records": 2,
                    "hardware_transport_available": false,
                    "fixture_is_live_mapping": false,
                    "protected_live_mapping_primitive_available": cfg!(windows)
                })
            );
            Ok(())
        }
        Some("verify-journal-qualification") => {
            let mut receipt_path = None;
            while let Some(argument) = args.next() {
                let value = args
                    .next()
                    .ok_or_else(|| format!("missing value after {argument}"))?;
                match argument.as_str() {
                    "--receipt" => receipt_path = Some(PathBuf::from(value)),
                    _ => {
                        return Err(format!(
                            "unknown verify-journal-qualification option: {argument}"
                        ))
                    }
                }
            }
            let receipt = verify_journal_qualification_receipt(
                receipt_path.ok_or("--receipt is required")?,
            )
            .map_err(|error| format!("journal qualification verification failed: {error}"))?;
            println!(
                "{}",
                serde_json::json!({
                    "schema": "forge.journal-qualification-verification.v1",
                    "status": "verified",
                    "qualification_status": receipt.status,
                    "run_id_hex": receipt.evidence.run_id_hex,
                    "journal_sha256_hex": receipt.evidence.journal_sha256_hex,
                    "evidence_sha256_hex": receipt.evidence_sha256_hex,
                    "hardware_transport_available": false,
                    "nwb_dual_write_enabled": false
                })
            );
            Ok(())
        }
        Some("verify-nwb-generation") => {
            let mut receipt = None;
            let mut journal = None;
            let mut nwb = None;
            let mut manifest = None;
            let mut report = None;
            while let Some(argument) = args.next() {
                let value = args
                    .next()
                    .ok_or_else(|| format!("missing value after {argument}"))?;
                match argument.as_str() {
                    "--receipt" => receipt = Some(PathBuf::from(value)),
                    "--journal" => journal = Some(PathBuf::from(value)),
                    "--nwb-inprogress" => nwb = Some(PathBuf::from(value)),
                    "--manifest" => manifest = Some(PathBuf::from(value)),
                    "--report" => report = Some(PathBuf::from(value)),
                    _ => {
                        return Err(format!(
                            "unknown verify-nwb-generation option: {argument}"
                        ))
                    }
                }
            }
            let paths = NwbValidationBundlePaths::for_generation(
                receipt.ok_or("--receipt is required")?,
                journal.ok_or("--journal is required")?,
                nwb.ok_or("--nwb-inprogress is required")?,
                manifest.ok_or("--manifest is required")?,
                report.ok_or("--report is required")?,
            );
            let verified = verify_nwb_validation_bundle(&paths)
                .map_err(|error| format!("NWB generation verification failed: {error}"))?;
            println!(
                "{}",
                serde_json::json!({
                    "schema": "forge.nwb-generation-owner-verification.v1",
                    "status": "verified_unpublished",
                    "run_id_hex": hex(&verified.receipt.run_id),
                    "generation": verified.receipt.generation,
                    "checked_blocks": verified.receipt.checked_blocks,
                    "total_samples": verified.receipt.total_samples,
                    "validation_sequence": verified.receipt.validation_sequence,
                    "publication_authorized": verified.publication_authorized,
                    "hardware_transport_available": false
                })
            );
            Ok(())
        }
        #[cfg(feature = "qualification-harness")]
        Some("publish-nwb-generation") => {
            let (paths, publication_receipt, run_ledger) = parse_nwb_publication_paths(args)?;
            let published = publish_nwb_generation(&paths, &publication_receipt)
                .map_err(|error| format!("NWB generation publication failed: {error}"))?;
            let finalized_status = run_ledger
                .as_ref()
                .map(|path| finalize_nwb_publication(path, &publication_receipt))
                .transpose()
                .map_err(|error| format!("NWB publication Run-ledger bind failed: {error}"))?;
            let run_finalized = finalized_status.as_ref().is_some_and(|status| {
                status.latest_published_run_id_hex.as_deref()
                    == Some(hex(&published.receipt.run_id).as_str())
            });
            println!(
                "{}",
                serde_json::json!({
                    "schema": "forge.nwb-generation-publication.v1",
                    "status": "published_unledgered",
                    "run_id_hex": hex(&published.receipt.run_id),
                    "generation": published.receipt.generation,
                    "validation_sequence": published.receipt.validation_sequence,
                    "final_path": published.final_path,
                    "publication_receipt_path": published.publication_receipt_path,
                    "inprogress_retained": published.inprogress_retained,
                    "run_finalized": run_finalized,
                    "run_ledger_path": run_ledger,
                    "hardware_transport_available": false
                })
            );
            Ok(())
        }
        #[cfg(windows)]
        Some("service-owner") => {
            let launch = forge_acqd::windows_service_owner::parse_service_owner_args(
                args.map(std::ffi::OsString::from),
            )
            .map_err(|error| format!("invalid internal service-owner configuration: {error}"))?;
            forge_acqd::windows_service_owner::run_service_owner(launch)
                .map_err(|error| format!("internal service owner failed: {error}"))
        }
        #[cfg(windows)]
        Some("service-dispatch") => {
            let config = forge_acqd::windows_service_host::ServiceDispatchConfig::parse(
                args.map(std::ffi::OsString::from),
            )
            .map_err(|error| format!("invalid Windows service configuration: {error}"))?;
            forge_acqd::windows_service_host::start_service_dispatcher(config)
                .map_err(|error| format!("Windows service dispatcher failed: {error}"))
        }
        #[cfg(windows)]
        Some("service-install-plan") => {
            let install = parse_service_install_args(args)?;
            if install.confirmation.is_some() {
                return Err("--confirm is not accepted by the read-only install plan".to_owned());
            }
            let plan = forge_acqd::windows_service_install::ServiceInstallPlan::new_with_hardware_policy(
                std::env::current_exe().map_err(|error| error.to_string())?,
                install.data_root,
                &install.operator_sid,
                install.analysis_worker_sid.as_deref(),
                install.direct_pod_policy.as_ref(),
            )
            .map_err(|error| format!("invalid service install plan: {error}"))?;
            println!(
                "{}",
                serde_json::json!({
                    "schema": "forge.service-install-plan.v1",
                    "status": "validated_not_installed",
                    "plan": plan,
                    "required_confirmation": forge_acqd::windows_service_install::INSTALL_CONFIRMATION,
                    "deployment_qualified": false,
                    "direct_pod_internal_verification_configured": plan.direct_pod_policy_path.is_some(),
                    "hardware_transport_available": false
                })
            );
            Ok(())
        }
        #[cfg(windows)]
        Some("service-install") => {
            let install = parse_service_install_args(args)?;
            let plan = forge_acqd::windows_service_install::ServiceInstallPlan::new_with_hardware_policy(
                std::env::current_exe().map_err(|error| error.to_string())?,
                install.data_root,
                &install.operator_sid,
                install.analysis_worker_sid.as_deref(),
                install.direct_pod_policy.as_ref(),
            )
            .map_err(|error| format!("invalid service install plan: {error}"))?;
            let receipt = forge_acqd::windows_service_install::install_service(
                &plan,
                install.confirmation.as_deref().unwrap_or_default(),
            )
            .map_err(|error| format!("Windows service installation failed: {error}"))?;
            println!(
                "{}",
                serde_json::json!({
                    "schema": "forge.service-install-receipt.v1",
                    "status": "installed_not_started",
                    "receipt": receipt,
                    "deployment_qualified": false,
                    "direct_pod_internal_verification_configured": plan.direct_pod_policy_path.is_some(),
                    "hardware_transport_available": false
                })
            );
            Ok(())
        }
        Some("serve") => {
            let boundary = ipc_boundary();
            println!(
                "{}",
                serde_json::to_string(&boundary).map_err(|error| error.to_string())?
            );
            Err(boundary.reason.to_owned())
        }
        _ => Err(
            "hardware acquisition is unavailable; use --self-check, d3xx-probe [--library <absolute DLL>], software-replay-service, protected-replay, analysis-ring-fixture, journal-qualification, verify-journal-qualification, verify-nwb-generation, service-install-plan, or the SCM-only service-dispatch entry; NWB publication is unavailable in the default build"
                .to_owned(),
        ),
    }
}

#[cfg(windows)]
fn parse_software_replay_service_args(
    mut args: impl Iterator<Item = String>,
) -> Result<forge_acqd::software_replay_service::SoftwareReplayServiceOptions, String> {
    let mut requested_directory = None;
    let mut base_name = None;
    let mut run_id = None;
    let mut target_group_id = None;
    let mut frozen_config_hash = None;
    let mut pipe_name = None;
    let mut operator_sid = None;
    let mut selected_device_ids = Vec::new();
    let mut ready_receipt_path = None;
    while let Some(argument) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after {argument}"))?;
        match argument.as_str() {
            "--requested-directory" if requested_directory.is_none() => {
                requested_directory = Some(PathBuf::from(value))
            }
            "--base-name" if base_name.is_none() => base_name = Some(value),
            "--run-id" if run_id.is_none() => {
                run_id = Some(parse_hex_array::<16>(&value, "Run ID")?)
            }
            "--target-group-id" if target_group_id.is_none() => {
                target_group_id = Some(parse_hex_array::<16>(&value, "target group ID")?)
            }
            "--frozen-config-hash" if frozen_config_hash.is_none() => {
                frozen_config_hash = Some(parse_hex_array::<32>(&value, "frozen config hash")?)
            }
            "--pipe" if pipe_name.is_none() => pipe_name = Some(value),
            "--operator-sid" if operator_sid.is_none() => operator_sid = Some(value),
            "--selected-device" => selected_device_ids.push(value),
            "--ready-receipt" if ready_receipt_path.is_none() => {
                ready_receipt_path = Some(PathBuf::from(value))
            }
            _ => {
                return Err(format!(
                    "unknown or duplicate software replay service option: {argument}"
                ))
            }
        }
    }
    Ok(
        forge_acqd::software_replay_service::SoftwareReplayServiceOptions {
            requested_directory: requested_directory.ok_or("--requested-directory is required")?,
            base_name: base_name.ok_or("--base-name is required")?,
            run_id: run_id.ok_or("--run-id is required")?,
            target_group_id: target_group_id.ok_or("--target-group-id is required")?,
            frozen_config_hash: frozen_config_hash.ok_or("--frozen-config-hash is required")?,
            pipe_name: pipe_name.ok_or("--pipe is required")?,
            operator_sid: operator_sid.ok_or("--operator-sid is required")?,
            selected_device_ids,
            ready_receipt_path: ready_receipt_path.ok_or("--ready-receipt is required")?,
        },
    )
}

#[cfg(windows)]
struct ServiceInstallArgs {
    data_root: PathBuf,
    operator_sid: String,
    analysis_worker_sid: Option<String>,
    direct_pod_policy: Option<forge_acqd::ProtectedDirectPodPolicyReference>,
    confirmation: Option<String>,
}

#[cfg(windows)]
fn parse_service_install_args(
    mut args: impl Iterator<Item = String>,
) -> Result<ServiceInstallArgs, String> {
    let mut data_root = None;
    let mut operator_sid = None;
    let mut confirmation = None;
    let mut analysis_worker_sid = None;
    let mut direct_pod_policy_path = None;
    let mut direct_pod_policy_sha256 = None;
    let mut internal_approval_authority_sha256 = None;
    while let Some(argument) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after {argument}"))?;
        match argument.as_str() {
            "--data-root" if data_root.is_none() => data_root = Some(PathBuf::from(value)),
            "--operator-sid" if operator_sid.is_none() => operator_sid = Some(value),
            "--analysis-worker-sid" if analysis_worker_sid.is_none() => {
                analysis_worker_sid = Some(value)
            }
            "--direct-pod-policy" if direct_pod_policy_path.is_none() => {
                direct_pod_policy_path = Some(PathBuf::from(value))
            }
            "--direct-pod-policy-sha256" if direct_pod_policy_sha256.is_none() => {
                direct_pod_policy_sha256 = Some(value)
            }
            "--internal-approval-authority-sha256"
                if internal_approval_authority_sha256.is_none() =>
            {
                internal_approval_authority_sha256 = Some(value)
            }
            "--confirm" if confirmation.is_none() => confirmation = Some(value),
            _ => {
                return Err(format!(
                    "unknown or duplicate service install option: {argument}"
                ))
            }
        }
    }
    let direct_pod_policy = match (
        direct_pod_policy_path,
        direct_pod_policy_sha256,
        internal_approval_authority_sha256,
    ) {
        (None, None, None) => None,
        (Some(path), Some(policy_hash), Some(authority_hash)) => Some(
            forge_acqd::ProtectedDirectPodPolicyReference::from_hex(
                path,
                &policy_hash,
                &authority_hash,
            )
            .map_err(|error| format!("invalid direct-Pod internal verification policy: {error}"))?,
        ),
        _ => {
            return Err(
                "--direct-pod-policy, --direct-pod-policy-sha256, and --internal-approval-authority-sha256 are required together"
                    .to_owned(),
            )
        }
    };
    Ok(ServiceInstallArgs {
        data_root: data_root.ok_or("--data-root is required")?,
        operator_sid: operator_sid.ok_or("--operator-sid is required")?,
        analysis_worker_sid,
        direct_pod_policy,
        confirmation,
    })
}

#[cfg(feature = "qualification-harness")]
fn parse_nwb_publication_paths(
    mut args: impl Iterator<Item = String>,
) -> Result<(NwbValidationBundlePaths, PathBuf, Option<PathBuf>), String> {
    let mut receipt = None;
    let mut journal = None;
    let mut nwb = None;
    let mut manifest = None;
    let mut report = None;
    let mut publication_receipt = None;
    let mut run_ledger = None;
    while let Some(argument) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value after {argument}"))?;
        match argument.as_str() {
            "--receipt" => receipt = Some(PathBuf::from(value)),
            "--journal" => journal = Some(PathBuf::from(value)),
            "--nwb-inprogress" => nwb = Some(PathBuf::from(value)),
            "--manifest" => manifest = Some(PathBuf::from(value)),
            "--report" => report = Some(PathBuf::from(value)),
            "--publication-receipt" => publication_receipt = Some(PathBuf::from(value)),
            "--run-ledger" => run_ledger = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown publish-nwb-generation option: {argument}")),
        }
    }
    Ok((
        NwbValidationBundlePaths::for_generation(
            receipt.ok_or("--receipt is required")?,
            journal.ok_or("--journal is required")?,
            nwb.ok_or("--nwb-inprogress is required")?,
            manifest.ok_or("--manifest is required")?,
            report.ok_or("--report is required")?,
        ),
        publication_receipt.ok_or("--publication-receipt is required")?,
        run_ledger,
    ))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn parse_hex_array<const N: usize>(value: &str, name: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{name} must be exactly {} hexadecimal characters",
            N * 2
        ));
    }
    let mut decoded = [0_u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| format!("invalid {name}: {value}"))?;
    }
    Ok(decoded)
}

fn parse<T: std::str::FromStr>(value: &str, name: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid {name}: {value}"))
}
