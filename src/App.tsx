import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type PointerEvent as ReactPointerEvent,
} from "react";
import {
  Maximize2,
  Minimize2,
  Moon,
  PanelRightClose,
  PanelRightOpen,
  Pause,
  Play,
  Sun,
  Waves,
} from "lucide-react";
import type {
  AcquireIntent,
  AcquireLifecycleState,
  CapabilityEvidence,
  CapabilitySnapshot,
  CommandReceipt,
  DaemonSnapshot,
  DeviceIdentitySnapshot,
  DeviceKind,
  PodKey,
  PodSnapshot,
  PodTopologySnapshot,
  PreviewSignalKind,
} from "./adapters/acquireAdapter";
import { createAcquireRuntime } from "./adapters/acquireRuntime";
import type { RunDirectoryBrowser, RunDirectoryListing } from "./adapters/runDirectoryBrowser";
import { InfoHint } from "./components/InfoHint";
import { LiveTraceSurface, type ChannelDisplayStats } from "./components/LiveTraceSurface";
import { DeviceNameDialog } from "./components/DeviceNameDialog";
import { PodRack } from "./components/PodRack";
import type { PreflightCheck, RecordingSetupMode } from "./components/PreflightDialog";
import { RunControlPanel } from "./components/RunControlPanel";
import { RunIntegrityRail } from "./components/RunIntegrityRail";
import { SignalViewTabs, type SignalViewOption } from "./components/SignalViewTabs";
import type { PreviewNeuralModel } from "./core/previewNeuralModel";
import { deriveRunOutput } from "./core/runOutputState";

const LOW_STORAGE_THRESHOLD_BYTES = 20_000_000_000;

const PreflightDialog = lazy(async () => {
  const module = await import("./components/PreflightDialog");
  return { default: module.PreflightDialog };
});

function formatByteCount(bytes: number | null): string {
  if (bytes === null || !Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1_000) return `${Math.round(bytes)} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1_000)), units.length);
  const value = bytes / 1_000 ** exponent;
  return `${value >= 100 ? value.toFixed(0) : value >= 10 ? value.toFixed(1) : value.toFixed(2)} ${units[exponent - 1]}`;
}

const PHASE_COPY: Record<AcquireLifecycleState, { label: string; detail: string }> = {
  disconnected: {
    label: "STARTING",
    detail: "Waiting for the acquisition service to finish opening the recognized device source.",
  },
  connected_idle: {
    label: "READY",
    detail: "The recognized device source is ready. Preview remains separate from recording setup.",
  },
  preflighting: {
    label: "PREFLIGHTING",
    detail: "The request was accepted; waiting for an independent preflight snapshot.",
  },
  preflight_passed: {
    label: "PREFLIGHT PASS",
    detail: "Device identities, input descriptions, and the recording target are frozen. Arm has not been requested.",
  },
  arm_requested: {
    label: "ARM REQUESTED",
    detail: "The Arm command was accepted; the adapter has not confirmed Armed yet.",
  },
  armed: {
    label: "READY TO RECORD",
    detail: "The adapter snapshot confirms Armed. Recording has not started; Preview remains independent.",
  },
  start_requested: {
    label: "START REQUESTED",
    detail: "The Start command was accepted; waiting for a source-confirmed recording snapshot.",
  },
  recording: {
    label: "RECORDING",
    detail: "The writer is receiving an adapter-authored recording source. Preview is a bounded derivative and can stop independently.",
  },
  stop_requested: {
    label: "ENDING / SAVING",
    detail: "Stopping input and draining buffers. Preview remains independent.",
  },
  recording_stopped: {
    label: "SAVING · INPUT STOPPED",
    detail: "Input has stopped. Waiting for the durability barrier; Preview may continue.",
  },
  finalizing: {
    label: "SAVING · SEALING",
    detail: "Waiting for the durability barrier and seal receipt.",
  },
  finalized: {
    label: "RUN ENDED",
    detail: "The final result accepts only the adapter's NWB publication receipt.",
  },
  recovery_required: {
    label: "RECOVERY REQUIRED",
    detail: "The Run is not sealed and is not a complete recording. Only adapter-provided recovery or failure actions are allowed.",
  },
};

function capability(
  snapshot: CapabilitySnapshot,
  id: keyof CapabilitySnapshot["capabilities"],
): CapabilityEvidence {
  return snapshot.capabilities[id];
}

function lifecycleHasPreflight(lifecycle: AcquireLifecycleState): boolean {
  return !["disconnected", "connected_idle", "preflighting"].includes(lifecycle);
}

function lifecycleHasArm(lifecycle: AcquireLifecycleState): boolean {
  return [
    "armed",
    "start_requested",
    "recording",
    "stop_requested",
    "recording_stopped",
    "finalizing",
    "finalized",
    "recovery_required",
  ].includes(lifecycle);
}

function topologyPods(topology: PodTopologySnapshot): PodSnapshot[] {
  return [
    ...topology.directPods,
    ...topology.aggregators.flatMap((aggregator) =>
      aggregator.ports.flatMap((port) => port.pod === null ? [] : [port.pod])),
  ];
}

function AcquireApp({ previewModel }: { previewModel: PreviewNeuralModel }) {
  const runtime = useMemo(() => createAcquireRuntime(previewModel), [previewModel]);
  const runDirectoryBrowserRef = useRef<Promise<RunDirectoryBrowser> | null>(null);
  const adapter = runtime.adapter;
  const mountedRef = useRef(false);
  const autoConnectRequestedRef = useRef(false);
  const [capabilities, setCapabilities] = useState<CapabilitySnapshot | null>(null);
  const [snapshot, setSnapshot] = useState<DaemonSnapshot | null>(null);
  const [lastCommand, setLastCommand] = useState<CommandReceipt | null>(null);
  const [inFlightReceiptId, setInFlightReceiptId] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [preflightOpen, setPreflightOpen] = useState(false);
  const [selectedPodKey, setSelectedPodKey] = useState<PodKey | null>("MOCK-DIRECT-01");
  const [recordingSetupMode, setRecordingSetupMode] = useState<RecordingSetupMode>("single");
  const [singleRecordPodKey, setSingleRecordPodKey] = useState<PodKey | null>(null);
  const [multiRecordPodKeys, setMultiRecordPodKeys] = useState<ReadonlySet<PodKey>>(() => new Set());
  const [runLabel, setRunLabel] = useState("FORGE-RUN");
  const [requestedDirectory, setRequestedDirectory] = useState("F:\\ForgeRuns");
  const [directoryBrowserOpen, setDirectoryBrowserOpen] = useState(false);
  const [directoryBrowserListing, setDirectoryBrowserListing] = useState<RunDirectoryListing | null>(null);
  const [directoryBrowserBusy, setDirectoryBrowserBusy] = useState(false);
  const [directoryBrowserError, setDirectoryBrowserError] = useState<string | null>(null);
  const directoryBrowserRequestRef = useRef(0);
  const [plannedDurationHours, setPlannedDurationHours] = useState(24);
  const [renameTarget, setRenameTarget] = useState<{
    kind: DeviceKind;
    identity: DeviceIdentitySnapshot;
  } | null>(null);
  const [renameSaving, setRenameSaving] = useState(false);
  const [renameError, setRenameError] = useState<string | null>(null);
  const [selectedChannel, setSelectedChannel] = useState(0);
  const [channelStats, setChannelStats] = useState<ChannelDisplayStats>({
    rms: null,
    peak: null,
    eventCount: null,
    threshold: null,
    unitLabel: null,
    podEventCount: null,
    bankEventCount: null,
    renderedEventCount: null,
    previewOmittedEventCount: null,
  });
  const [previewKind, setPreviewKind] = useState<PreviewSignalKind>("wideband");
  const [gainUv, setGainUv] = useState(200);
  const [windowSeconds, setWindowSeconds] = useState(1);
  const [displayPaused, setDisplayPaused] = useState(false);
  const [traceTheme, setTraceTheme] = useState<"dark" | "light">("dark");
  const [podsCollapsed, setPodsCollapsed] = useState(false);
  const [podPanelWidth, setPodPanelWidth] = useState(220);
  const podResizeRef = useRef<{ pointerId: number; startX: number; startWidth: number } | null>(null);
  const [controlsCollapsed, setControlsCollapsed] = useState(true);
  const [signalFocusActive, setSignalFocusActive] = useState(false);
  const effectivePodsCollapsed = signalFocusActive || podsCollapsed;
  const effectiveControlsCollapsed = signalFocusActive || controlsCollapsed;
  const nwbOutputCapability = capabilities?.capabilities.nwb_materialization ?? null;
  const finalOutputReady = capabilities !== null
    && (capabilities.scope === "mock" || nwbOutputCapability?.status === "available");

  useEffect(() => {
    mountedRef.current = true;
    const unsubscribe = adapter.subscribeSnapshots(setSnapshot);
    void adapter.readCapabilities().then(setCapabilities);
    void adapter.readSnapshot().then(setSnapshot);
    return () => {
      mountedRef.current = false;
      unsubscribe();
      queueMicrotask(() => {
        if (!mountedRef.current) adapter.dispose();
      });
    };
  }, [adapter]);

  useEffect(() => {
    if (snapshot?.lastCommandReceiptId === inFlightReceiptId && inFlightReceiptId !== null) {
      setBusyAction(null);
      setInFlightReceiptId(null);
    }
  }, [inFlightReceiptId, snapshot?.lastCommandReceiptId]);

  useEffect(() => {
    if (snapshot?.previewState !== "live") setDisplayPaused(false);
  }, [snapshot?.previewState]);

  useEffect(() => {
    setSelectedChannel(0);
    setDisplayPaused(false);
  }, [previewKind, selectedPodKey]);

  const issue = useCallback(async (intent: AcquireIntent): Promise<CommandReceipt> => {
    setBusyAction(intent.type);
    const receipt = await adapter.execute(intent);
    setLastCommand(receipt);
    if (receipt.accepted) setInFlightReceiptId(receipt.receiptId);
    else setBusyAction(null);
    return receipt;
  }, [adapter]);

  useEffect(() => {
    if (!snapshot) return;
    if (snapshot.controlConnection === "connected") {
      autoConnectRequestedRef.current = false;
      return;
    }
    if (autoConnectRequestedRef.current || topologyPods(snapshot.topology).length === 0) return;
    autoConnectRequestedRef.current = true;
    void issue({ type: "connect" }).then((receipt) => {
      if (!receipt.accepted) autoConnectRequestedRef.current = false;
    });
  }, [issue, snapshot]);

  const selectablePods = useMemo(
    () => snapshot ? topologyPods(snapshot.topology).filter((pod) => pod.selectable) : [],
    [snapshot],
  );
  const runPlanLocked = snapshot !== null
    && !["disconnected", "connected_idle", "finalized"].includes(snapshot.lifecycle);
  const setupRecordPodKeys = useMemo<ReadonlySet<PodKey>>(() => {
    if (runPlanLocked && snapshot !== null) return new Set(snapshot.selectedPodKeys);
    if (recordingSetupMode === "multi") return multiRecordPodKeys;
    return singleRecordPodKey === null ? new Set() : new Set([singleRecordPodKey]);
  }, [multiRecordPodKeys, recordingSetupMode, runPlanLocked, singleRecordPodKey, snapshot]);
  const selectedRecordPods = useMemo(
    () => selectablePods.filter((pod) => setupRecordPodKeys.has(pod.key)),
    [selectablePods, setupRecordPodKeys],
  );
  const recordingSelectionValid = recordingSetupMode === "single"
    ? selectedRecordPods.length === 1
    : selectedRecordPods.length >= 2 && selectedRecordPods.length <= 8;
  const rackRecordPodKeys = useMemo<ReadonlySet<PodKey>>(
    () => runPlanLocked ? new Set(snapshot?.selectedPodKeys ?? []) : multiRecordPodKeys,
    [multiRecordPodKeys, runPlanLocked, snapshot?.selectedPodKeys],
  );

  useEffect(() => {
    if (!runPlanLocked || snapshot === null || snapshot.selectedPodKeys.length === 0) return;
    if (snapshot.selectedPodKeys.length === 1) {
      setRecordingSetupMode("single");
      setSingleRecordPodKey(snapshot.selectedPodKeys[0]);
    } else {
      setRecordingSetupMode("multi");
    }
  }, [runPlanLocked, snapshot]);

  const handleOpenSingleRecordingSetup = useCallback(() => {
    directoryBrowserRequestRef.current += 1;
    setDirectoryBrowserOpen(false);
    setDirectoryBrowserListing(null);
    setDirectoryBrowserBusy(false);
    setDirectoryBrowserError(null);
    if (runPlanLocked) {
      setPreflightOpen(true);
      return;
    }
    if (selectedPodKey === null || !selectablePods.some((pod) => pod.key === selectedPodKey)) return;
    setRecordingSetupMode("single");
    setSingleRecordPodKey(selectedPodKey);
    setPreflightOpen(true);
  }, [runPlanLocked, selectablePods, selectedPodKey]);

  const handleOpenMultiRecordingSetup = useCallback(() => {
    directoryBrowserRequestRef.current += 1;
    setDirectoryBrowserOpen(false);
    setDirectoryBrowserListing(null);
    setDirectoryBrowserBusy(false);
    setDirectoryBrowserError(null);
    if (runPlanLocked) {
      setPreflightOpen(true);
      return;
    }
    setRecordingSetupMode("multi");
    setPreflightOpen(true);
  }, [runPlanLocked]);

  const handleRequestedDirectoryChange = useCallback((value: string) => {
    setDirectoryBrowserError(null);
    setRequestedDirectory(value);
  }, []);

  const getRunDirectoryBrowser = useCallback(() => {
    runDirectoryBrowserRef.current ??= import("./adapters/runDirectoryBrowser")
      .then((module) => module.createRunDirectoryBrowser(true));
    return runDirectoryBrowserRef.current;
  }, []);

  const handleBrowseDirectory = useCallback(async (directory: string) => {
    const requestToken = directoryBrowserRequestRef.current + 1;
    directoryBrowserRequestRef.current = requestToken;
    setDirectoryBrowserBusy(true);
    setDirectoryBrowserError(null);
    try {
      const browser = await getRunDirectoryBrowser();
      const listing = await browser.browse(directory);
      if (directoryBrowserRequestRef.current !== requestToken) return;
      setDirectoryBrowserListing(listing);
    } catch (error) {
      if (directoryBrowserRequestRef.current !== requestToken) return;
      const module = await import("./adapters/runDirectoryBrowser");
      if (directoryBrowserRequestRef.current !== requestToken) return;
      setDirectoryBrowserError(module.directoryBrowserMessage(error));
    } finally {
      if (directoryBrowserRequestRef.current === requestToken) setDirectoryBrowserBusy(false);
    }
  }, [getRunDirectoryBrowser]);

  const handleOpenDirectoryBrowser = useCallback(() => {
    setDirectoryBrowserOpen(true);
    setDirectoryBrowserListing(null);
    setDirectoryBrowserError(null);
    void handleBrowseDirectory(requestedDirectory);
  }, [handleBrowseDirectory, requestedDirectory]);

  const handleCloseDirectoryBrowser = useCallback(() => {
    directoryBrowserRequestRef.current += 1;
    setDirectoryBrowserOpen(false);
    setDirectoryBrowserBusy(false);
    setDirectoryBrowserError(null);
  }, []);

  const handleUseDirectory = useCallback((directory: string) => {
    setRequestedDirectory(directory);
    handleCloseDirectoryBrowser();
  }, [handleCloseDirectoryBrowser]);

  const handleRunPreflight = useCallback(() => {
    if (!snapshot || !recordingSelectionValid || !finalOutputReady) return;
    void issue({
      type: "preflight",
      plan: {
        label: runLabel.trim(),
        plannedDurationSeconds: plannedDurationHours * 3_600,
        selectedDevices: selectedRecordPods.map((pod) => ({
          podKey: pod.key,
          deviceId: pod.identity.deviceId,
          identityEvidenceHash: pod.identity.identityEvidenceHash ?? "",
          inputEvidenceHash: pod.neuralInput?.evidenceHash ?? "",
        })),
        topologyEvidenceHash: snapshot.topology.evidenceHash,
        recordingTarget: {
          requestedDirectory,
          baseName: runLabel.trim(),
          allocationPolicy: "create_new_incrementing_suffix",
          overwritePolicy: "forbid",
        },
      },
    });
  }, [finalOutputReady, issue, plannedDurationHours, recordingSelectionValid, requestedDirectory, runLabel, selectedRecordPods, snapshot]);

  const handleRequestArm = useCallback(async () => {
    if (!finalOutputReady) return;
    const receipt = await issue({ type: "arm_recording" });
    if (receipt.accepted) setPreflightOpen(false);
  }, [finalOutputReady, issue]);

  const handleToggleRecordPod = useCallback((podKey: PodKey, selected: boolean) => {
    if (snapshot && !["disconnected", "connected_idle", "finalized"].includes(snapshot.lifecycle)) return;
    setMultiRecordPodKeys((current) => {
      const next = new Set(current);
      if (selected) next.add(podKey);
      else next.delete(podKey);
      return next;
    });
  }, [snapshot]);

  const handleStartPreview = useCallback(() => {
    if (!snapshot || selectedPodKey === null) return;
    setDisplayPaused(false);
    void issue({
      type: "start_preview",
      podKey: selectedPodKey,
      topologyEvidenceHash: snapshot.topology.evidenceHash,
    });
  }, [issue, selectedPodKey, snapshot]);

  const handleStartRecording = useCallback(() => {
    if (!snapshot) return;
    if (snapshot.lifecycle === "armed") {
      void issue({ type: "start_recording" });
      return;
    }
    if (["connected_idle", "finalized"].includes(snapshot.lifecycle)) {
      handleOpenSingleRecordingSetup();
    }
  }, [handleOpenSingleRecordingSetup, issue, snapshot]);

  const handleTogglePause = useCallback(async () => {
    if (!snapshot) return;
    const recording = snapshot.lifecycle === "recording";
    if (recording && (snapshot.scope === "mock" || snapshot.scope === "software")) {
      const resume = snapshot.recordingPaused;
      const receipt = await issue({ type: resume ? "resume_recording" : "pause_recording" });
      if (receipt.accepted) setDisplayPaused(!resume);
      return;
    }
    if (snapshot.previewState === "live") setDisplayPaused((paused) => !paused);
  }, [issue, snapshot]);

  const handleStop = useCallback(() => {
    if (!snapshot) return;
    if (snapshot.lifecycle === "recording") {
      void issue({ type: "stop_recording", reason: "operator" });
      return;
    }
    if (snapshot.previewState === "live") {
      void issue({ type: "stop_preview", reason: "operator" });
    }
  }, [issue, snapshot]);

  const handleRequestRename = useCallback((kind: DeviceKind, identity: DeviceIdentitySnapshot) => {
    setRenameError(null);
    setRenameTarget({ kind, identity });
  }, []);

  const handleSaveDeviceName = useCallback(async (displayName: string) => {
    if (renameTarget === null) return;
    setRenameSaving(true);
    setRenameError(null);
    const receipt = await adapter.renameDevice({
      kind: renameTarget.kind,
      deviceId: renameTarget.identity.deviceId,
      expectedIdentityEvidenceHash: renameTarget.identity.identityEvidenceHash ?? "",
      displayName,
      expectedRevision: renameTarget.identity.revision,
    });
    setRenameSaving(false);
    if (receipt.accepted) setRenameTarget(null);
    else setRenameError(`${receipt.reasonCode} · ${receipt.message}`);
  }, [adapter, renameTarget]);

  useEffect(() => {
    if (!snapshot || preflightOpen || renameTarget !== null) return undefined;
    const handleKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target?.matches("input, textarea, select, button, [contenteditable='true']")) return;
      const key = event.key.toLowerCase();
      if (key === "v" && snapshot.controlConnection === "connected" && snapshot.previewState === "stopped") {
        event.preventDefault();
        handleStartPreview();
      } else if (key === "n" && snapshot.controlConnection === "connected"
        && ["connected_idle", "finalized"].includes(snapshot.lifecycle)) {
        event.preventDefault();
        handleOpenSingleRecordingSetup();
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [handleOpenSingleRecordingSetup, handleStartPreview, preflightOpen, renameTarget, snapshot]);

  const toggleSignalFocus = useCallback(() => {
    setSignalFocusActive((active) => !active);
  }, []);

  if (!snapshot || !capabilities) {
    return (
      <div className="app-loading" role="status">
        <Waves size={24} aria-hidden="true" />
        <strong>Forge Acquire</strong>
        <span>Reading adapter capabilities and daemon snapshot…</span>
      </div>
    );
  }

  const connected = snapshot.controlConnection === "connected";
  const runOutput = deriveRunOutput(
    snapshot.lifecycle,
    snapshot.evidence,
    snapshot.runReceipt,
    snapshot.scope,
  );
  const phase = snapshot.recordingPaused
    ? {
        label: "RECORDING PAUSED",
        detail: "The mock recording Run and live display are paused. Resume continues the same Run; Stop closes and saves it.",
      }
    : displayPaused && snapshot.previewState === "live" && snapshot.lifecycle !== "recording"
      ? {
          label: "PREVIEW PAUSED",
          detail: "The live display is frozen. Resume continues Preview; Stop ends Preview.",
        }
    : ["finalized", "recovery_required"].includes(snapshot.lifecycle)
      ? { label: runOutput.phaseLabel, detail: runOutput.detail }
      : PHASE_COPY[snapshot.lifecycle];
  const controlSeparated = !connected && snapshot.runId !== null
    && !["finalized", "recovery_required"].includes(snapshot.lifecycle);
  const phaseDetail = controlSeparated
    ? `The control plane is disconnected while the recording data plane remains ${snapshot.lifecycle}. Closing the UI does not issue Stop or Abort.`
    : snapshot.lifecycle === "recovery_required"
      ? `${snapshot.evidence.acquisition.summary} ${snapshot.evidence.durability.summary}`
      : phase.detail;
  const previewActive = snapshot.previewState === "live" && connected;
  const pods = topologyPods(snapshot.topology);
  const selectedPod = pods.find((pod) => pod.key === selectedPodKey)
    ?? pods[0]
    ?? null;
  const selectedInput = selectedPod?.neuralInput ?? null;
  const visibleUnitLabel = selectedInput?.previewValueUnit === "adc_count" ? "ADC counts" : "µV";
  const previewTraceSource = selectedPod?.key ?? "No trace source";
  const previewTraceIdentity = `${previewTraceSource} · ${windowSeconds.toFixed(1)} s · ±${gainUv.toLocaleString()} ${visibleUnitLabel}`;
  const previewTraceTooltip = selectedInput?.scope === "mock"
    ? `${previewTraceIdentity}. Values come from the mock preview source and are not hardware-calibrated measurements.`
    : previewTraceIdentity;

  const preflightRunning = busyAction === "preflight" || snapshot.lifecycle === "preflighting";
  const setupTarget = snapshot.lifecycle === "finalized" ? null : snapshot.recordingTarget;
  const preflightPassed = snapshot.lifecycle !== "finalized"
    && finalOutputReady
    && lifecycleHasPreflight(snapshot.lifecycle);
  const recordingArmed = snapshot.lifecycle !== "finalized"
    && finalOutputReady
    && lifecycleHasArm(snapshot.lifecycle);
  const preflightChecks: PreflightCheck[] = [
    {
      id: "adapter-scope",
      label: "Adapter and evidence scope",
      status: "pass",
      detail: capabilities.scope === "software"
        ? `${capability(capabilities, "mock_acquisition").summary} FT601, Aggregator 10GbE, and physical Pods are outside this receipt.`
        : `${capability(capabilities, "mock_acquisition").summary} This view does not create a physical recording file.`,
      evidence: `${capabilities.adapterId} · ${capabilities.scope.toUpperCase()}`,
    },
    {
      id: "preview-session",
      label: "Preview source (optional)",
      status: "pass",
      detail: snapshot.previewState === "live"
        ? capabilities.scope === "software"
          ? "Preview is live. Recording may start from Preview, but Preview is not a recording prerequisite."
          : "Preview is live. Recording may start from Preview or directly from the selected Pod."
        : "Preview is stopped. Recording can still start directly from the selected Pod.",
      evidence: `previewState=${snapshot.previewState} · snapshot #${snapshot.snapshotSequence.toString()}`,
    },
    {
      id: "pod-plan",
      label: recordingSetupMode === "single" ? "Single-device identity" : "Multi-device identities",
      status: recordingSelectionValid ? "pass" : "blocked",
      detail: recordingSelectionValid
        ? `${selectedRecordPods.length} Pod${selectedRecordPods.length === 1 ? "" : "s"} will be recorded. The Run plan binds route keys, immutable device IDs, and identity receipts.`
        : recordingSetupMode === "single"
          ? "Single-device recording must freeze the current Preview Pod, and the snapshot must mark it selectable."
          : "Multi-device recording requires an explicit selection of 2–8 selectable Pods.",
      evidence: selectedRecordPods.map((pod) => `${pod.identity.deviceId}@${pod.identity.revision.toString()}`).join(" · ") || "no selected device",
    },
    {
      id: "recording-target",
      label: "New recording directory",
      status: setupTarget ? "pass" : "pending",
      detail: setupTarget
        ? `${setupTarget.resolvedRunDirectory} · ${setupTarget.directoryCreateDisposition} · overwrite forbidden`
        : lastCommand?.intent === "preflight" && !lastCommand.accepted
          ? `${lastCommand.reasonCode} · ${lastCommand.message}`
          : "Preflight asks the adapter to allocate a final directory with an incrementing suffix. The UI does not claim reservation success.",
      evidence: setupTarget?.evidenceHash ?? "no reservation receipt",
    },
    {
      id: "final-nwb-output",
      label: snapshot.scope === "mock" ? "Simulation output scope" : "Final file · NWB",
      status: snapshot.scope === "mock"
        ? "pass"
        : nwbOutputCapability?.status === "available"
          ? "pass"
          : nwbOutputCapability?.status ?? "unavailable",
      detail: snapshot.scope === "mock"
        ? "This run exercises only the simulation workflow and creates no recording file."
        : finalOutputReady
          ? "A formal recording must generate, validate, and publish NWB with create-new semantics. The Run receipt remains authoritative."
          : "The current adapter has no available NWB materializer, so Preflight blocks formal recording.",
      evidence: snapshot.scope === "mock"
        ? "MOCK_WORKFLOW_NO_FILE"
        : `${nwbOutputCapability?.reasonCode ?? "NO_NWB_CAPABILITY"} · ${nwbOutputCapability?.claimScope?.toUpperCase() ?? "SOFTWARE"}`,
    },
    {
      id: "daemon-preflight",
      label: "Recording admission snapshot",
      status: preflightPassed
        ? "pass"
        : preflightRunning
          ? "pending"
          : lastCommand?.intent === "preflight" && !lastCommand.accepted
            ? "blocked"
            : "pending",
      detail: preflightPassed
        ? `${capabilities.scope === "software" ? "Software daemon" : "Mock adapter"} snapshot entered ${snapshot.lifecycle}.`
        : "Waiting for the adapter report; a button press does not imply passage.",
      evidence: snapshot.evidenceHash,
    },
    {
      id: "input-contract",
      label: "Neural input contract",
      status: recordingSelectionValid && selectedRecordPods.every((pod) =>
        pod.identity.identityEvidenceHash !== null && pod.neuralInput?.evidenceHash !== null)
        ? "pass"
        : "blocked",
      detail: "Every recorded device must carry adapter-authored channel count, sample rate, layout, and input evidence. The UI never infers them from the hardware model.",
      evidence: selectedRecordPods.map((pod) => {
        const input = pod.neuralInput;
        return `${pod.identity.deviceId}:${input?.neuralChannelCount ?? "?"}ch@${input?.sampleRateHz ?? "?"}Hz`;
      }).join(" · ") || "no input receipt",
    },
  ];

  const durabilityFaultActive = snapshot.faults.some(
    (fault) => fault.latched && fault.code === "durability_failure",
  );
  const nonRecoverableFaultActive = snapshot.faults.some(
    (fault) => fault.latched && !fault.recoverable,
  );
  const busy = busyAction !== null;
  const recordingActive = snapshot.lifecycle === "recording";
  const pauseAffectsRecording = recordingActive
    && (snapshot.scope === "mock" || snapshot.scope === "software");
  const canPause = connected
    && (snapshot.previewState === "live" || pauseAffectsRecording);
  const stopMode = recordingActive
    ? "recording" as const
    : snapshot.previewState === "live"
      ? "preview" as const
      : null;
  const canStop = connected && stopMode !== null;
  const signalViewOptions: SignalViewOption[] = [
    {
      id: "wideband",
      label: "WIDEBAND",
      detail: "Sampled wideband extrema",
      status: capability(capabilities, "decimated_preview").status,
      scopeLabel: "MOCK",
    },
    {
      id: "lfp",
      label: "LFP",
      detail: "Synthetic reference component",
      status: capability(capabilities, "lfp_preview").status,
      scopeLabel: "MOCK TRUTH",
    },
    {
      id: "spike",
      label: "SPIKES",
      detail: "Synthetic events and waveforms",
      status: capability(capabilities, "spike_preview").status,
      scopeLabel: "MOCK ORACLE",
    },
  ];
  const previewModeCopy = previewKind === "wideband"
    ? { title: "Sampled wideband extrema", detail: "Current 8-channel bank. Each bucket inspects bounded representative points and known spike support points; it is not a complete bucket MIN–MAX." }
    : previewKind === "lfp"
      ? { title: "LFP reference extrema", detail: "Current 8-channel bank from the 8 Hz truth component of the same synthetic expression. It is neither native Intan LFP nor a validated production filter." }
      : { title: "Spike activity, raster, and waveforms", detail: "Events from the same synthetic oracle feed the 8-channel raster and selected-channel waveform window. All, Stats, and Last are display modes—not a validated production detector or sorter." };
  const recordingFileSize = snapshot.recordingTarget === null
    || snapshot.recordingTarget.directoryCreateDisposition === "simulated"
    ? "NO FILE"
    : formatByteCount(snapshot.load.recordingFileBytes);
  const storageFree = formatByteCount(snapshot.load.storageFreeBytes);
  const storageLow = snapshot.load.storageFreeBytes !== null
    && Number.isFinite(snapshot.load.storageFreeBytes)
    && snapshot.load.storageFreeBytes >= 0
    && snapshot.load.storageFreeBytes < LOW_STORAGE_THRESHOLD_BYTES;
  const storageLowPodKeys = new Set<PodKey>(
    storageLow && selectedPod !== null ? [selectedPod.key] : [],
  );
  const recordingPath = setupTarget?.resolvedRunDirectory ?? "Not configured";
  const clampPodPanelWidth = (width: number) => Math.min(360, Math.max(176, Math.round(width)));
  const handlePodResizeStart = (event: ReactPointerEvent<HTMLDivElement>) => {
    event.currentTarget.setPointerCapture(event.pointerId);
    podResizeRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startWidth: podPanelWidth,
    };
  };
  const handlePodResizeMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const resize = podResizeRef.current;
    if (resize === null || resize.pointerId !== event.pointerId) return;
    setPodPanelWidth(clampPodPanelWidth(resize.startWidth + event.clientX - resize.startX));
  };
  const handlePodResizeEnd = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (podResizeRef.current?.pointerId !== event.pointerId) return;
    podResizeRef.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };
  const workspaceStyle = {
    "--pod-column": `${effectivePodsCollapsed ? 72 : podPanelWidth}px`,
  } as CSSProperties;
  return (
    <div
      className="app-shell"
      data-signal-focus={signalFocusActive ? "true" : "false"}
    >
      <main className={[
        "bench-workspace",
        effectivePodsCollapsed ? "is-pods-collapsed" : "",
        effectiveControlsCollapsed ? "is-controls-collapsed" : "",
      ].filter(Boolean).join(" ")}
      data-pods-collapsed={effectivePodsCollapsed ? "true" : "false"}
      data-controls-collapsed={effectiveControlsCollapsed ? "true" : "false"}
      style={workspaceStyle}
      >
        <PodRack
          topology={snapshot.topology}
          selectedPodKey={selectedPod?.key ?? selectedPodKey}
          onSelect={setSelectedPodKey}
          recordPodKeys={rackRecordPodKeys}
          recordSelectionLocked={runPlanLocked}
          storageLowPodKeys={storageLowPodKeys}
          onRequestRename={handleRequestRename}
          synthetic={snapshot.synthetic}
          controlConnected={connected}
          collapsed={effectivePodsCollapsed}
          onToggleCollapsed={() => {
            if (signalFocusActive) {
              setSignalFocusActive(false);
              setPodsCollapsed(false);
            } else {
              setPodsCollapsed((collapsed) => !collapsed);
            }
          }}
        />

        {!effectivePodsCollapsed ? (
          <div
            className="pod-column-resizer"
            role="separator"
            aria-label="Resize device list"
            aria-orientation="vertical"
            aria-valuemin={176}
            aria-valuemax={360}
            aria-valuenow={podPanelWidth}
            tabIndex={0}
            onPointerDown={handlePodResizeStart}
            onPointerMove={handlePodResizeMove}
            onPointerUp={handlePodResizeEnd}
            onPointerCancel={handlePodResizeEnd}
            onKeyDown={(event) => {
              if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
              event.preventDefault();
              setPodPanelWidth((width) => clampPodPanelWidth(
                width + (event.key === "ArrowRight" ? 8 : -8),
              ));
            }}
          />
        ) : null}

        <>
          <header className="signal-toolbar workspace-signal-toolbar">
            <div className="signal-toolbar__primary">
              <div className="signal-title">
                <span className="instrument-kicker">DERIVED SIGNAL PREVIEW</span>
                <div className="signal-title__heading">
                  <div
                    className="signal-device-name"
                    data-tooltip={selectedPod?.label ?? "No previewable Pod"}
                  >
                    <h2 id="signal-workbench-title">{selectedPod?.label ?? "No previewable Pod"}</h2>
                  </div>
                  <InfoHint label="About this preview">
                    <strong>{previewModeCopy.title}</strong>
                    <span>{previewModeCopy.detail}</span>
                  </InfoHint>
                </div>
                <p>{previewModeCopy.title}</p>
                <SignalViewTabs
                  options={signalViewOptions}
                  selected={previewKind}
                  onSelect={setPreviewKind}
                />
              </div>
              <button
                className={`signal-focus-button icon-action${signalFocusActive ? " is-active" : ""}`}
                type="button"
                aria-label={signalFocusActive ? "Exit signal focus" : "Enter signal focus"}
                aria-pressed={signalFocusActive}
                data-tooltip={signalFocusActive ? "Restore panels" : "Focus signal"}
                onClick={toggleSignalFocus}
              >
                {signalFocusActive
                  ? <Minimize2 size={16} aria-hidden="true" />
                  : <Maximize2 size={16} aria-hidden="true" />}
                <span className="visually-hidden">{signalFocusActive ? "Restore panels" : "Focus signal"}</span>
              </button>
              <button
                className={`preview-pause icon-action${displayPaused ? " is-active" : ""}`}
                type="button"
                aria-label={displayPaused ? "Resume display" : "Freeze display"}
                data-tooltip={displayPaused ? "Resume display" : "Freeze display"}
                disabled={!previewActive}
                onClick={() => setDisplayPaused((paused) => !paused)}
              >
                {displayPaused ? <Play size={16} aria-hidden="true" /> : <Pause size={16} aria-hidden="true" />}
                <span className="visually-hidden">{displayPaused ? "Resume display" : "Freeze display"}</span>
              </button>
              <button
                className="panel-collapse-button acquisition-sidebar-toggle icon-action"
                type="button"
                aria-label={effectiveControlsCollapsed ? "Expand acquisition controls" : "Collapse acquisition controls"}
                aria-expanded={!effectiveControlsCollapsed}
                aria-controls="acquisition-controls"
                data-tooltip={effectiveControlsCollapsed ? "Expand acquisition controls" : "Collapse acquisition controls"}
                onClick={() => {
                  if (signalFocusActive) {
                    setSignalFocusActive(false);
                    setControlsCollapsed(false);
                  } else {
                    setControlsCollapsed((collapsed) => !collapsed);
                  }
                }}
              >
                {effectiveControlsCollapsed
                  ? <PanelRightOpen size={17} aria-hidden="true" />
                  : <PanelRightClose size={17} aria-hidden="true" />}
                <span className="visually-hidden">
                  {effectiveControlsCollapsed ? "Expand acquisition controls" : "Collapse acquisition controls"}
                </span>
              </button>
            </div>
          </header>

          <section
            className={[
              "signal-workbench",
              `signal-workbench--${previewKind}`,
              "signal-workbench--diagnostics-collapsed",
            ].filter(Boolean).join(" ")}
            aria-labelledby="signal-workbench-title"
            data-preview-mode={previewKind}
          >

          <div
            className="trace-stage"
            id="signal-preview-panel"
            role="tabpanel"
            aria-labelledby={`signal-tab-${previewKind}`}
            data-signal-kind={previewKind}
            data-trace-theme={traceTheme}
          >
            <div className="preview-display-controls" role="toolbar" aria-label="Preview display controls">
              {previewKind !== "spike" ? (
                <div className="preview-trace-metadata" role="group" aria-label="Trace metadata" data-tooltip={previewTraceTooltip}>
                  <span className="preview-trace-metadata__source">{previewTraceSource}</span>
                  <span className="preview-trace-metadata__metric">
                    <small>WINDOW</small>
                    <strong>{windowSeconds.toFixed(1)} s</strong>
                  </span>
                  <span className="preview-trace-metadata__metric preview-trace-metadata__metric--range">
                    <small>RANGE</small>
                    <strong>±{gainUv.toLocaleString()}</strong>
                    <em>{visibleUnitLabel}</em>
                  </span>
                </div>
              ) : (
                <div className="preview-spike-summary" role="status" aria-label="Spike event summary">
                  <span>
                    <small>POD EVENTS</small>
                    <strong>{channelStats.podEventCount ?? "—"}</strong>
                  </span>
                  <span>
                    <small>SELECTED 8-CH EVENTS</small>
                    <strong>{channelStats.bankEventCount ?? "—"}</strong>
                  </span>
                </div>
              )}
              <div className="preview-control-cluster">
                <span>{previewKind === "spike" ? "Waveform retention" : "History window"}</span>
                <div
                  className="segmented"
                  aria-label={previewKind === "spike"
                    ? "Retention for each selected-channel event waveform; does not change sampling or event generation."
                    : "Visible Preview history; does not change sampling or detector configuration."}
                  title={previewKind === "spike"
                    ? "Each waveform remains visible for 1, 2, or 5 seconds from its source sample time."
                    : "The 1, 2, and 5 second choices change only the visible history window."}
                >
                  {[1, 2, 5].map((seconds) => (
                    <button
                      key={seconds}
                      type="button"
                      className={windowSeconds === seconds ? "active" : ""}
                      aria-pressed={windowSeconds === seconds}
                      aria-label={previewKind === "spike"
                        ? `Retain each waveform for ${seconds} second${seconds === 1 ? "" : "s"}`
                        : `Show the past ${seconds} second${seconds === 1 ? "" : "s"}`}
                      onClick={() => setWindowSeconds(seconds)}
                    >
                      {seconds} s
                    </button>
                  ))}
                </div>
              </div>
              <div className="preview-control-cluster">
                  <span>Display range · {visibleUnitLabel}</span>
                <div
                  className="segmented"
                  aria-label={`Preview amplitude range in ${visibleUnitLabel}`}
                  title="Changes only the vertical display scale; device gain and recorded samples are unchanged."
                >
                  {[100, 200, 500].map((gain) => (
                    <button
                      key={gain}
                      type="button"
                      className={gainUv === gain ? "active" : ""}
                      aria-pressed={gainUv === gain}
                      aria-label={`Display range plus or minus ${gain} ${visibleUnitLabel}`}
                      onClick={() => setGainUv(gain)}
                    >
                      ±{gain}
                    </button>
                  ))}
                </div>
              </div>
              <button
                className="icon-action trace-theme-toggle"
                type="button"
                aria-label={`Switch signal display to ${traceTheme === "dark" ? "light" : "dark"} theme`}
                data-tooltip={`Switch signal display to ${traceTheme === "dark" ? "light" : "dark"} theme`}
                aria-pressed={traceTheme === "light"}
                onClick={() => setTraceTheme((theme) => theme === "dark" ? "light" : "dark")}
              >
                {traceTheme === "dark" ? <Sun size={15} aria-hidden="true" /> : <Moon size={15} aria-hidden="true" />}
              </button>
            </div>
            <div className="trace-stage__viewport">
              {selectedPod ? (
                <LiveTraceSurface
                  source={adapter.previewSource}
                  podKey={selectedPod.key}
                  signalKind={previewKind}
                  active={previewActive}
                  inputChannelCount={selectedInput?.neuralChannelCount ?? null}
                  selectedChannel={selectedChannel}
                  onSelectChannel={setSelectedChannel}
                  onStats={setChannelStats}
                  gainValue={gainUv}
                  windowSeconds={windowSeconds}
                  paused={displayPaused}
                  markers={[]}
                />
              ) : (
                <div className="trace-empty" role="img" aria-label="No preview data" />
              )}
            </div>
          </div>

          </section>
        </>

        <aside
          id="acquisition-controls"
          className={`control-stack${effectiveControlsCollapsed ? " control-stack--collapsed" : ""}`}
          data-collapsed={effectiveControlsCollapsed ? "true" : "false"}
        >
          {effectiveControlsCollapsed ? null : (
            <RunControlPanel
            connected={connected}
            busy={busy}
            phase={snapshot.lifecycle}
            phaseLabel={phase.label}
            phaseDetail={phaseDetail}
            runId={snapshot.runId}
            previewState={snapshot.previewState}
            recordingTarget={setupTarget}
            recording={recordingActive}
            runOutput={runOutput}
            recoveryRequired={snapshot.lifecycle === "recovery_required"}
            canStartPreview={connected && ["stopped", "fault"].includes(snapshot.previewState) && selectedPod !== null}
            canSetupSingleRecording={connected && selectedPod?.selectable === true && (setupTarget !== null
              || ["connected_idle", "finalized"].includes(snapshot.lifecycle))}
            canSetupMultiRecording={connected && (setupTarget !== null
              || ["connected_idle", "finalized"].includes(snapshot.lifecycle))}
            recordingSetupMode={recordingSetupMode}
            recordingDeviceCount={runPlanLocked && snapshot.selectedPodKeys.length > 0
              ? snapshot.selectedPodKeys.length
              : selectedRecordPods.length}
            previewDeviceName={selectedPod?.identity.displayName ?? selectedPod?.label ?? "No device selected"}
            canStart={connected
              && finalOutputReady
              && selectedPod?.selectable === true
              && ["connected_idle", "finalized", "armed"].includes(snapshot.lifecycle)}
            paused={snapshot.recordingPaused || displayPaused}
            canPause={canPause}
            canStop={canStop}
            stopMode={stopMode}
            pauseAffectsRecording={pauseAffectsRecording}
            canRecover={snapshot.scope === "mock"
              && connected
              && snapshot.lifecycle === "recovery_required"
              && !durabilityFaultActive
              && !nonRecoverableFaultActive}
            canAcknowledgeFailed={connected
              && snapshot.lifecycle === "recovery_required"
              && (nonRecoverableFaultActive || (snapshot.scope === "software" && !snapshot.stale))}
            onStartPreview={handleStartPreview}
            onSetupSingleRecording={handleOpenSingleRecordingSetup}
            onSetupMultiRecording={handleOpenMultiRecordingSetup}
            onStart={handleStartRecording}
            onTogglePause={() => void handleTogglePause()}
            onStop={handleStop}
            onRecover={() => void issue({ type: "recover_run" })}
            onAcknowledgeFailed={() => void issue({ type: "acknowledge_failed_run" })}
            runStatus={(
              <RunIntegrityRail
                lifecycle={snapshot.lifecycle}
                evidence={snapshot.evidence}
                runReceipt={snapshot.runReceipt}
                scope={snapshot.scope}
                recordingFileSize={recordingFileSize}
                storageFree={storageFree}
                storageFreeBytes={snapshot.load.storageFreeBytes}
                deviceName={selectedPod?.identity.displayName ?? "No device selected"}
                recordingPath={recordingPath}
                recordingPaused={snapshot.recordingPaused}
              />
            )}
            />
          )}
        </aside>
      </main>

      {preflightOpen ? <Suspense fallback={null}>
      <PreflightDialog
        open={preflightOpen}
        running={preflightRunning}
        passed={preflightPassed}
        armed={recordingArmed}
        recordingMode={recordingSetupMode}
        adapterScope={snapshot.scope}
        finalOutputReady={finalOutputReady}
        finalOutputLabel={snapshot.scope === "mock"
          ? "Simulation only · no file"
          : finalOutputReady ? "NWB 2.x · CREATE NEW" : "NWB output unavailable"}
        runLabel={runLabel}
        requestedDirectory={requestedDirectory}
        plannedDurationHours={plannedDurationHours}
        devices={selectablePods.map((pod) => ({
          key: pod.key,
          displayName: pod.identity.displayName,
          deviceId: pod.identity.deviceId,
          routeLabel: pod.connection.kind === "direct_pc"
            ? pod.connection.connectionId
            : `${pod.connection.aggregatorId} / PORT ${pod.connection.port}`,
        }))}
        selectedPodKeys={setupRecordPodKeys}
        recordingTarget={setupTarget}
        receiptId={lastCommand?.intent === "preflight" ? lastCommand.receiptId : snapshot.lastCommandReceiptId}
        checks={preflightChecks}
        directoryBrowserAvailable={"__TAURI_INTERNALS__" in globalThis}
        directoryBrowserOpen={directoryBrowserOpen}
        directoryBrowserListing={directoryBrowserListing}
        directoryBrowserBusy={directoryBrowserBusy}
        directoryBrowserError={directoryBrowserError}
        onRunLabelChange={setRunLabel}
        onRequestedDirectoryChange={handleRequestedDirectoryChange}
        onOpenDirectoryBrowser={handleOpenDirectoryBrowser}
        onBrowseDirectory={(directory) => void handleBrowseDirectory(directory)}
        onUseDirectory={handleUseDirectory}
        onCloseDirectoryBrowser={handleCloseDirectoryBrowser}
        onPlannedDurationHoursChange={(value) => setPlannedDurationHours(
          Number.isFinite(value) ? Math.min(24, Math.max(0.1, value)) : 0.1,
        )}
        onTogglePod={handleToggleRecordPod}
        onRunPreflight={handleRunPreflight}
        onRequestArm={() => void handleRequestArm()}
        onCancel={() => setPreflightOpen(false)}
      />
      </Suspense> : null}

      <DeviceNameDialog
        open={renameTarget !== null}
        deviceKind={renameTarget?.kind ?? null}
        identity={renameTarget?.identity ?? null}
        saving={renameSaving}
        errorMessage={renameError}
        onSave={(displayName) => void handleSaveDeviceName(displayName)}
        onCancel={() => {
          if (renameSaving) return;
          setRenameTarget(null);
          setRenameError(null);
        }}
      />
    </div>
  );
}

function App() {
  const [previewModel, setPreviewModel] = useState<PreviewNeuralModel | null>(null);

  useEffect(() => {
    let active = true;
    void import("./core/nwbDerivedDemo").then(({ NwbDerivedDemoModel }) => {
      if (active) setPreviewModel(new NwbDerivedDemoModel());
    });
    return () => {
      active = false;
    };
  }, []);

  if (previewModel === null) {
    return (
      <div className="app-loading" role="status">
        <Waves size={24} aria-hidden="true" />
        <strong>Forge Acquire</strong>
        <span>Loading compact NWB Preview data…</span>
      </div>
    );
  }
  return <AcquireApp previewModel={previewModel} />;
}

export default App;
