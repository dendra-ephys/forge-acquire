import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Cable,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  CircleStop,
  Clock3,
  Database,
  Gauge,
  Maximize2,
  Minimize2,
  PanelRightOpen,
  Pause,
  Play,
  RadioTower,
  Signal,
  Wrench,
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
  FaultCode,
  PodKey,
  PodSnapshot,
  PodTopologySnapshot,
  PreviewSignalKind,
} from "./adapters/acquireAdapter";
import { createAcquireRuntime } from "./adapters/acquireRuntime";
import type { RunDirectoryBrowser, RunDirectoryListing } from "./adapters/runDirectoryBrowser";
import { FaultRecoveryPanel, type FaultOption } from "./components/FaultRecoveryPanel";
import { HardwareStatusCard } from "./components/HardwareStatusCard";
import { LiveTraceSurface, type ChannelDisplayStats } from "./components/LiveTraceSurface";
import { DeviceNameDialog } from "./components/DeviceNameDialog";
import { PodRack } from "./components/PodRack";
import type { PreflightCheck, RecordingSetupMode } from "./components/PreflightDialog";
import { RunControlPanel } from "./components/RunControlPanel";
import { RunIntegrityRail } from "./components/RunIntegrityRail";
import { SignalViewTabs, type SignalViewOption } from "./components/SignalViewTabs";
import { deriveRunOutput } from "./core/runOutputState";

const PreflightDialog = lazy(async () => {
  const module = await import("./components/PreflightDialog");
  return { default: module.PreflightDialog };
});

const PHASE_COPY: Record<AcquireLifecycleState, { label: string; detail: string }> = {
  disconnected: {
    label: "DISCONNECTED",
    detail: "控制面未连接；没有 active Run receipt。",
  },
  connected_idle: {
    label: "CONNECTED / IDLE",
    detail: "Adapter snapshot 新鲜；可先启动 Preview，再设置记录范围并运行 Preflight。",
  },
  preflighting: {
    label: "PREFLIGHTING",
    detail: "请求已接受，正在等待独立 preflight snapshot。",
  },
  preflight_passed: {
    label: "PREFLIGHT PASS",
    detail: "设备身份、输入描述与记录目标已冻结；Recording Arm 尚未请求。",
  },
  arm_requested: {
    label: "ARM REQUESTED",
    detail: "Arm command 已接受；此刻仍不能称为 Armed。",
  },
  armed: {
    label: "READY TO RECORD",
    detail: "Adapter snapshot 已确认 Recording Arm；尚未开始记录，Preview 可独立启动或停止。",
  },
  start_requested: {
    label: "START REQUESTED",
    detail: "Start command 已接受；等待 source-confirmed recording snapshot。",
  },
  recording: {
    label: "RECORDING",
    detail: "Writer 正从 adapter-authored Recording source 接收输入；Preview 是独立的有界派生显示，可单独停止。",
  },
  stop_requested: {
    label: "ENDING / SAVING",
    detail: "正在停止输入并排空；Preview 保持独立。",
  },
  recording_stopped: {
    label: "SAVING · INPUT STOPPED",
    detail: "输入已停止；正在等待 durability barrier，Preview 可继续。",
  },
  finalizing: {
    label: "SAVING · SEALING",
    detail: "正在等待 durability barrier 与 seal receipt。",
  },
  finalized: {
    label: "RUN ENDED",
    detail: "最终结果只接受 adapter 的 NWB 发布回执。",
  },
  recovery_required: {
    label: "RECOVERY REQUIRED",
    detail: "Run 未封存，不能当作完整记录；只执行当前 adapter 明确提供的恢复或失败确认动作。",
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

function lifecycleHasStopped(lifecycle: AcquireLifecycleState): boolean {
  return ["recording_stopped", "finalizing", "finalized", "recovery_required"].includes(lifecycle);
}

function topologyPods(topology: PodTopologySnapshot): PodSnapshot[] {
  return [
    ...topology.directPods,
    ...topology.aggregators.flatMap((aggregator) =>
      aggregator.ports.flatMap((port) => port.pod === null ? [] : [port.pod])),
  ];
}

function App() {
  const runtime = useMemo(() => createAcquireRuntime(), []);
  const runDirectoryBrowserRef = useRef<Promise<RunDirectoryBrowser> | null>(null);
  const adapter = runtime.adapter;
  const mountedRef = useRef(false);
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
  const [selectedFaultId, setSelectedFaultId] = useState<FaultCode>("counter_gap");
  const [podsCollapsed, setPodsCollapsed] = useState(false);
  const [controlsCollapsed, setControlsCollapsed] = useState(false);
  const [diagnosticsCollapsed, setDiagnosticsCollapsed] = useState(true);
  const [signalFocusActive, setSignalFocusActive] = useState(false);
  const effectivePodsCollapsed = signalFocusActive || podsCollapsed;
  const effectiveControlsCollapsed = signalFocusActive || controlsCollapsed;
  const effectiveDiagnosticsCollapsed = signalFocusActive || diagnosticsCollapsed;
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
    void issue({
      type: "start_preview",
      podKey: selectedPodKey,
      topologyEvidenceHash: snapshot.topology.evidenceHash,
    });
  }, [issue, selectedPodKey, snapshot]);

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

  const handleInjectFault = useCallback(async () => {
    if (runtime.diagnostics === null) return;
    setBusyAction("inject_fault");
    if (selectedFaultId === "counter_gap") {
      await runtime.diagnostics.inject({ type: "counter_gap", missingSamples: 64 });
    } else if (selectedFaultId === "control_pipe_loss") {
      await runtime.diagnostics.inject({ type: "control_pipe_loss" });
    } else {
      await runtime.diagnostics.inject({ type: "durability_failure", reason: "Mock stable-media barrier timeout" });
    }
    setBusyAction(null);
  }, [runtime.diagnostics, selectedFaultId]);

  const handleClearRecoverable = useCallback(async () => {
    if (!snapshot || runtime.diagnostics === null) return;
    setBusyAction("clear_faults");
    const recoverable = snapshot.faults.filter((fault) => fault.latched && fault.recoverable);
    await Promise.all(recoverable.map((fault) => runtime.diagnostics!.clear(fault.code)));
    setBusyAction(null);
  }, [runtime.diagnostics, snapshot]);

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
        && snapshot.previewState === "live"
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
        <span>正在读取 adapter capability 与 daemon snapshot…</span>
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
  const phase = ["finalized", "recovery_required"].includes(snapshot.lifecycle)
    ? { label: runOutput.phaseLabel, detail: runOutput.detail }
    : PHASE_COPY[snapshot.lifecycle];
  const controlSeparated = !connected && snapshot.runId !== null
    && !["finalized", "recovery_required"].includes(snapshot.lifecycle);
  const phaseDetail = controlSeparated
    ? `控制面已断开；记录数据面仍保持 ${snapshot.lifecycle}，GUI 关闭或断开不会自动产生 Stop/Abort。`
    : snapshot.lifecycle === "recovery_required"
      ? `${snapshot.evidence.acquisition.summary} ${snapshot.evidence.durability.summary}`
      : phase.detail;
  const previewActive = snapshot.previewState === "live" && connected;
  const pods = topologyPods(snapshot.topology);
  const selectedPod = pods.find((pod) => pod.key === selectedPodKey)
    ?? pods[0]
    ?? null;
  const selectedInput = selectedPod?.neuralInput ?? null;
  const selectedUnitLabel = selectedInput?.previewValueUnit === "adc_count"
    ? "ADC counts"
    : selectedInput?.scope === "mock"
      ? "SYNTHETIC µV"
      : "µV";
  const selectedChannelCount = selectedInput?.neuralChannelCount ?? 0;
  const selectedBankStart = Math.floor(selectedChannel / 8) * 8;
  const selectedBankCount = Math.max(0, Math.min(8, selectedChannelCount - selectedBankStart));
  const selectedBankLabel = selectedBankCount > 0
    ? `CH ${String(selectedBankStart + 1).padStart(3, "0")}–${String(selectedBankStart + selectedBankCount).padStart(3, "0")}`
    : "NO INPUT";

  const faultOptions: FaultOption[] = [
    {
      id: "counter_gap",
      label: "Counter gap",
      description: "锁存 source / spike detector coverage FAILED，停止 Preview 并立即退出有效 Recording；不能生成有效保存回执。",
      enabled: runtime.diagnostics !== null && snapshot.lifecycle === "recording",
    },
    {
      id: "control_pipe_loss",
      label: "Control pipe loss",
      description: "仅丢失 GUI 控制连接；独立记录数据面继续且不生成 Stop。",
      enabled: runtime.diagnostics !== null && connected && snapshot.lifecycle !== "disconnected",
    },
    {
      id: "durability_failure",
      label: "Durability failure",
      description: "预设下一次结束并保存的 durability / seal 失败，进入 Recovery Required，不伪造 seal。",
      enabled: runtime.diagnostics !== null && snapshot.lifecycle === "recording",
    },
  ];
  const activeFaults = snapshot.faults.filter((fault) => fault.latched).map((fault) => ({
    id: fault.evidenceHash,
    severity: "error" as const,
    title: fault.code.replaceAll("_", " ").toUpperCase(),
    detail: fault.message,
    recoverable: fault.recoverable,
    recovery: fault.code === "counter_gap"
      ? "不能清除或生成有效 seal；确认失败并关闭当前 Run"
      : fault.code === "control_pipe_loss"
        ? "重新连接控制面；采集无需重启"
        : fault.code === "recording_pipeline_failure"
          ? "确认失败并关闭控制上下文；保留 partial journal，不补写 seal"
          : "清除测试 barrier fault，再用 Recover 重试保存",
  }));

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
      label: "适配器与证据范围",
      status: "pass",
      detail: capabilities.scope === "software"
        ? `${capability(capabilities, "mock_acquisition").summary} FT601、Aggregator 10GbE 与物理 Pod 不在本 receipt 范围内。`
        : `${capability(capabilities, "mock_acquisition").summary} 本页不创建真实记录文件。`,
      evidence: `${capabilities.adapterId} · ${capabilities.scope.toUpperCase()}`,
    },
    {
      id: "preview-session",
      label: "Preview 数据源",
      status: snapshot.previewState === "live" ? "pass" : "blocked",
      detail: snapshot.previewState === "live"
        ? capabilities.scope === "software"
          ? "有界 mock Preview 正在运行；它与写盘的独立 deterministic software stream 分开，不证明物理输入。"
          : "有界 mock Preview 正在运行；只验证控制面流程，不写文件。"
        : "先启动 Preview 并确认数据流，再创建记录",
      evidence: `previewState=${snapshot.previewState} · snapshot #${snapshot.snapshotSequence.toString()}`,
    },
    {
      id: "pod-plan",
      label: recordingSetupMode === "single" ? "单设备记录身份" : "多设备记录身份",
      status: recordingSelectionValid ? "pass" : "blocked",
      detail: recordingSelectionValid
        ? `${selectedRecordPods.length} 个 Pod 将写入；Run plan 绑定 route key、immutable device ID 与 identity receipt`
        : recordingSetupMode === "single"
          ? "单设备记录必须冻结当前 Preview Pod，且该 Pod 必须由 snapshot 标记为 selectable"
          : "多设备记录必须由操作者显式选择 2–8 个 selectable Pod",
      evidence: selectedRecordPods.map((pod) => `${pod.identity.deviceId}@${pod.identity.revision.toString()}`).join(" · ") || "no selected device",
    },
    {
      id: "recording-target",
      label: "新建记录目录",
      status: setupTarget ? "pass" : "pending",
      detail: setupTarget
        ? `${setupTarget.resolvedRunDirectory} · ${setupTarget.directoryCreateDisposition} · overwrite forbidden`
        : lastCommand?.intent === "preflight" && !lastCommand.accepted
          ? `${lastCommand.reasonCode} · ${lastCommand.message}`
          : "Preflight 将由 adapter 分配带递增序号的最终目录；UI 不声明 reservation 成功",
      evidence: setupTarget?.evidenceHash ?? "no reservation receipt",
    },
    {
      id: "final-nwb-output",
      label: snapshot.scope === "mock" ? "模拟输出范围" : "最终文件 · NWB",
      status: snapshot.scope === "mock"
        ? "pass"
        : nwbOutputCapability?.status === "available"
          ? "pass"
          : nwbOutputCapability?.status ?? "unavailable",
      detail: snapshot.scope === "mock"
        ? "本次只运行模拟工作流，不生成记录文件。"
        : finalOutputReady
          ? "正式记录必须生成、验证并以 create-new 方式发布 NWB；最终仍以 Run receipt 为准。"
          : "当前 adapter 没有可用的 NWB materializer，正式记录在 Preflight 阶段被阻止。",
      evidence: snapshot.scope === "mock"
        ? "MOCK_WORKFLOW_NO_FILE"
        : `${nwbOutputCapability?.reasonCode ?? "NO_NWB_CAPABILITY"} · ${nwbOutputCapability?.claimScope?.toUpperCase() ?? "SOFTWARE"}`,
    },
    {
      id: "daemon-preflight",
      label: "记录准入快照",
      status: preflightPassed
        ? "pass"
        : preflightRunning
          ? "pending"
          : lastCommand?.intent === "preflight" && !lastCommand.accepted
            ? "blocked"
            : "pending",
      detail: preflightPassed
        ? `${capabilities.scope === "software" ? "Software daemon" : "Mock adapter"} snapshot 已进入 ${snapshot.lifecycle}`
        : "等待 adapter 报告，不由按钮推测通过",
      evidence: snapshot.evidenceHash,
    },
    {
      id: "input-contract",
      label: "神经数据输入契约",
      status: recordingSelectionValid && selectedRecordPods.every((pod) =>
        pod.identity.identityEvidenceHash !== null && pod.neuralInput?.evidenceHash !== null)
        ? "pass"
        : "blocked",
      detail: "每个记录设备必须带 adapter-authored channel count、sample rate、layout 与 input evidence；UI 不从硬件型号推测",
      evidence: selectedRecordPods.map((pod) => {
        const input = pod.neuralInput;
        return `${pod.identity.deviceId}:${input?.neuralChannelCount ?? "?"}ch@${input?.sampleRateHz ?? "?"}Hz`;
      }).join(" · ") || "no input receipt",
    },
  ];

  const hardwareCapabilities = [
    capability(capabilities, "ft601_direct"),
    capability(capabilities, "aggregator_10gbe"),
    capability(capabilities, "rhs_acquisition"),
    capability(capabilities, "nwb_materialization"),
    capability(capabilities, "release_24h"),
  ];
  const durabilityFaultActive = snapshot.faults.some(
    (fault) => fault.latched && fault.code === "durability_failure",
  );
  const nonRecoverableFaultActive = snapshot.faults.some(
    (fault) => fault.latched && !fault.recoverable,
  );
  const busy = busyAction !== null;
  const canStopRecording = connected && snapshot.lifecycle === "recording";
  const loadIndicators = [
    { label: "SOURCE FIFO", value: snapshot.load.sourceBufferPercent },
    { label: "WRITER QUEUE", value: snapshot.load.writerQueuePercent },
    { label: "CONTROL LOAD", value: snapshot.load.controlLoadPercent },
  ];
  const signalViewOptions: SignalViewOption[] = [
    {
      id: "wideband",
      label: "WIDEBAND",
      detail: "宽带采样极值",
      status: capability(capabilities, "decimated_preview").status,
      scopeLabel: "MOCK",
    },
    {
      id: "lfp",
      label: "LFP",
      detail: "合成参考分量",
      status: capability(capabilities, "lfp_preview").status,
      scopeLabel: "MOCK TRUTH",
    },
    {
      id: "spike",
      label: "SPIKES",
      detail: "合成事件 + 波形",
      status: capability(capabilities, "spike_preview").status,
      scopeLabel: "MOCK ORACLE",
    },
  ];
  const previewModeCopy = previewKind === "wideband"
    ? { title: "宽带采样极值预览", detail: "当前 8 通道 bank；每桶只查有界代表点及已知 spike 支撑点，不冒充完整桶 MIN–MAX", stats: "SAMPLED RMS / PEAK" }
    : previewKind === "lfp"
      ? { title: "LFP 参考分量采样极值", detail: "当前 8 通道 bank；来自同一合成式中的 8 Hz 真值分量，不是 Intan 原生 LFP，也不是已验证生产滤波器", stats: "LFP RMS / PEAK" }
      : { title: "Spike 活动、Raster 与波形", detail: "同一合成流的事件 oracle → 8 通道 bank raster → 选中通道完整保留窗 waveform；可切换全部、统计与最新。不是已验证生产 detector/sorter", stats: "CH EVENTS / SOURCE" };
  const channelStatsValue = previewKind === "spike"
    ? channelStats.eventCount === null
      ? "—"
      : channelStats.threshold === null
        ? `${channelStats.eventCount} events · ORACLE`
        : `${channelStats.eventCount} / ${channelStats.threshold.toFixed(0)} ${channelStats.unitLabel ?? selectedUnitLabel}`
    : channelStats.rms === null
      ? "—"
      : `${channelStats.rms.toFixed(1)} / ${channelStats.peak?.toFixed(1) ?? "—"} ${channelStats.unitLabel ?? selectedUnitLabel}`;
  const lastCommandLabel = lastCommand?.intent === "stop_recording"
    ? "END & SAVE"
    : lastCommand?.intent.replaceAll("_", " ").toUpperCase();

  return (
    <div
      className="app-shell"
      data-signal-focus={signalFocusActive ? "true" : "false"}
    >
      <header className="bench-header">
        <div className="brand" aria-label="Forge Acquire">
          <div className="brand-mark"><Waves size={20} aria-hidden="true" /></div>
          <div><strong>Forge Acquire</strong><span>NEURAL CAPTURE CONTROL</span></div>
        </div>

        <div className="adapter-readout">
          <span className="adapter-readout__lamp" />
          <div>
            <span>ACTIVE ADAPTER</span>
            <strong>{snapshot.scope === "software" ? "SOFTWARE · RUST DATA PLANE" : "MOCK · BROWSER QA"}</strong>
          </div>
          <em>SYNTHETIC</em>
        </div>

        <div className="header-facts">
          <div><Clock3 size={14} aria-hidden="true" /><span>PLAN</span><strong>{plannedDurationHours.toFixed(1)} h</strong></div>
          <div><RadioTower size={14} aria-hidden="true" /><span>SNAPSHOT</span><strong>#{snapshot.snapshotSequence.toString()}</strong></div>
          <div><Database size={14} aria-hidden="true" /><span>RUN EPOCH</span><strong>{snapshot.runEpoch?.toString() ?? "—"}</strong></div>
        </div>

        <div className="gui-close-boundary">
          <Cable size={16} aria-hidden="true" />
          <div><strong>GUI ≠ DAEMON</strong><span>关闭窗口不会请求 Stop</span></div>
        </div>
      </header>

      <div className={`command-strip${lastCommand?.accepted === false ? " is-rejected" : ""}`} role={lastCommand?.accepted === false ? "alert" : "status"}>
        <span>CONTROL RECEIPT</span>
        {lastCommand ? (
          <>
            <strong>{lastCommandLabel} · {lastCommand.accepted ? "ACCEPTED" : "REJECTED"}</strong>
            <code>{lastCommand.receiptId}</code>
            <p>{lastCommand.message}；accepted 不等于状态已发生。</p>
          </>
        ) : (
          <p>尚无命令。所有事实由 capability / daemon snapshot / run receipt 提供。</p>
        )}
      </div>

      <main className={[
        "bench-workspace",
        effectivePodsCollapsed ? "is-pods-collapsed" : "",
        effectiveControlsCollapsed ? "is-controls-collapsed" : "",
      ].filter(Boolean).join(" ")}
      data-pods-collapsed={effectivePodsCollapsed ? "true" : "false"}
      data-controls-collapsed={effectiveControlsCollapsed ? "true" : "false"}
      >
        <PodRack
          topology={snapshot.topology}
          selectedPodKey={selectedPod?.key ?? selectedPodKey}
          onSelect={setSelectedPodKey}
          recordPodKeys={rackRecordPodKeys}
          recordSelectionLocked={runPlanLocked}
          onToggleRecord={handleToggleRecordPod}
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

        <section
          className={[
            "signal-workbench",
            `signal-workbench--${previewKind}`,
            effectiveDiagnosticsCollapsed ? "signal-workbench--diagnostics-collapsed" : "",
          ].filter(Boolean).join(" ")}
          aria-labelledby="signal-workbench-title"
          data-preview-mode={previewKind}
        >
          <header className="signal-toolbar">
            <div className="signal-toolbar__primary">
              <div className="signal-title">
                <span className="instrument-kicker">DERIVED SIGNAL PREVIEW</span>
                <h2 id="signal-workbench-title">{selectedPod?.label ?? "无有效 Pod snapshot"}</h2>
                <p title={previewModeCopy.detail}>{previewModeCopy.title} · {previewModeCopy.detail}</p>
                {selectedInput ? (
                  <p className="signal-input-contract">
                    INPUT RECEIPT · {selectedInput.profileLabel ?? selectedInput.profileId ?? "UNNAMED"}
                    {` · ${selectedInput.neuralChannelCount} neural · ${(selectedInput.sampleRateHz / 1_000).toFixed(0)} kS/s/ch · ${selectedUnitLabel}`}
                  </p>
                ) : null}
              </div>
              <div className="signal-state" role="status">
                <Activity size={14} aria-hidden="true" />
                <span>{previewActive ? "LIVE PREVIEW" : "WAITING"}</span>
              </div>
              {previewKind !== "spike" && selectedBankCount > 0 ? (
                <div className="toolbar-bank-nav" role="group" aria-label="Preview channel bank">
                  <button
                    type="button"
                    aria-label="Previous preview channel bank"
                    disabled={selectedBankStart === 0}
                    onClick={() => setSelectedChannel(Math.max(0, selectedBankStart - 8))}
                  >
                    <ChevronLeft size={16} aria-hidden="true" />
                  </button>
                  <div><span>CHANNEL BANK</span><strong>{selectedBankLabel}</strong></div>
                  <button
                    type="button"
                    aria-label="Next preview channel bank"
                    disabled={selectedBankStart + selectedBankCount >= selectedChannelCount}
                    onClick={() => setSelectedChannel(Math.min(selectedChannelCount - 1, selectedBankStart + 8))}
                  >
                    <ChevronRight size={16} aria-hidden="true" />
                  </button>
                </div>
              ) : null}
              <button
                className={`signal-focus-button${signalFocusActive ? " is-active" : ""}`}
                type="button"
                aria-label={signalFocusActive ? "退出信号聚焦" : "进入信号聚焦"}
                aria-pressed={signalFocusActive}
                title={signalFocusActive ? "恢复进入聚焦前的独立面板状态" : "收起非信号区域，让实际数据占据最大空间"}
                onClick={toggleSignalFocus}
              >
                {signalFocusActive
                  ? <Minimize2 size={16} aria-hidden="true" />
                  : <Maximize2 size={16} aria-hidden="true" />}
                <span>{signalFocusActive ? "恢复面板" : "信号聚焦"}</span>
              </button>
              <button
                className={`preview-pause${displayPaused ? " is-active" : ""}`}
                type="button"
                disabled={!previewActive}
                onClick={() => setDisplayPaused((paused) => !paused)}
              >
                {displayPaused ? <Play size={16} aria-hidden="true" /> : <Pause size={16} aria-hidden="true" />}
                {displayPaused ? "恢复显示" : "冻结显示"}
              </button>
            </div>
            <div className="signal-toolbar__controls">
              <SignalViewTabs
                options={signalViewOptions}
                selected={previewKind}
                onSelect={setPreviewKind}
              />
              <div className="preview-control-cluster">
                <span>{previewKind === "spike" ? "波形保留时间" : "屏幕历史窗"}</span>
                <div
                  className="segmented"
                  aria-label={previewKind === "spike"
                    ? "选中通道每条 event waveform 的保留时间；不改变采样率或事件生成"
                    : "预览屏幕历史时间范围；不改变采样率或检测配置"}
                  title={previewKind === "spike"
                    ? "每条 waveform 从其 source sample 时刻起保留相同的 1 / 2 / 5 秒；到期即隐去"
                    : "1 / 2 / 5 秒只改变屏幕回看范围，不改变 Headstage 采样率"}
                >
                  {[1, 2, 5].map((seconds) => (
                    <button
                      key={seconds}
                      type="button"
                      className={windowSeconds === seconds ? "active" : ""}
                      aria-pressed={windowSeconds === seconds}
                      aria-label={previewKind === "spike"
                        ? `每条 waveform 保留 ${seconds} 秒`
                        : `显示过去 ${seconds} 秒`}
                      onClick={() => setWindowSeconds(seconds)}
                    >
                      {seconds} s
                    </button>
                  ))}
                </div>
              </div>
              <div className="preview-control-cluster">
                <span>显示量程 · {selectedUnitLabel}</span>
                <div className="segmented" aria-label={`预览幅值范围，单位 ${selectedUnitLabel}`}>
                  {[100, 200, 500].map((gain) => (
                    <button
                      key={gain}
                      type="button"
                      className={gainUv === gain ? "active" : ""}
                      aria-pressed={gainUv === gain}
                      aria-label={`显示量程正负 ${gain} ${selectedUnitLabel}`}
                      onClick={() => setGainUv(gain)}
                    >
                      ±{gain}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </header>

          <div
            className="trace-stage"
            id="signal-preview-panel"
            role="tabpanel"
            aria-labelledby={`signal-tab-${previewKind}`}
            data-signal-kind={previewKind}
          >
            {selectedPod ? (
              <LiveTraceSurface
                source={adapter.previewSource}
                podKey={selectedPod.key}
                signalKind={previewKind}
                active={previewActive}
                sourceOpen={connected}
                sourceAvailable
                blockedReason="当前 adapter 没有可显示的有界预览。"
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
              <div className="trace-empty"><strong>Topology snapshot 中没有可预览 Pod</strong></div>
            )}
          </div>

          <div className="signal-readout-strip">
            <div><Signal size={15} aria-hidden="true" /><span>CHANNEL</span><strong>{previewActive ? `CH ${String(selectedChannel + 1).padStart(3, "0")}` : "—"}</strong></div>
            <div><Gauge size={15} aria-hidden="true" /><span>{previewModeCopy.stats}</span><strong>{channelStatsValue}</strong></div>
            {loadIndicators.map((indicator) => {
              const value = indicator.value === null ? null : Math.min(100, Math.max(0, indicator.value));
              return (
                <div className="load-indicator" key={indicator.label}>
                  <Activity size={15} aria-hidden="true" />
                  <span>{indicator.label}{snapshot.stale ? " · STALE" : ""}</span>
                  <strong>{value === null ? "—" : `${value.toFixed(0)}%`}</strong>
                  <i aria-hidden="true"><b style={{ width: `${value ?? 0}%` }} /></i>
                </div>
              );
            })}
            <div><Database size={15} aria-hidden="true" /><span>WEBVIEW RAW</span><strong>0 B</strong></div>
          </div>

          <section
            className={`diagnostic-region${effectiveDiagnosticsCollapsed ? " is-collapsed" : ""}${activeFaults.length > 0 ? " has-fault" : ""}`}
            data-collapsed={effectiveDiagnosticsCollapsed ? "true" : "false"}
            aria-labelledby="diagnostic-region-title"
          >
            <header className="diagnostic-region__header">
              <div className="diagnostic-region__title">
                <Wrench size={16} aria-hidden="true" />
                <div>
                  <span className="instrument-kicker">FAULT / DAEMON EVIDENCE</span>
                  <strong id="diagnostic-region-title">诊断与恢复</strong>
                </div>
              </div>
              <div className="diagnostic-region__actions">
                <span
                  className={`diagnostic-region__summary${activeFaults.length > 0 ? " has-fault" : ""}${snapshot.stale ? " is-stale" : ""}`}
                  role={activeFaults.length > 0 ? "alert" : "status"}
                >
                  {activeFaults.length > 0 ? <AlertTriangle size={14} aria-hidden="true" /> : <Activity size={14} aria-hidden="true" />}
                  {activeFaults.length > 0
                    ? `${activeFaults.length} LATCHED FAULT${activeFaults.length === 1 ? "" : "S"}`
                    : `SNAPSHOT #${snapshot.snapshotSequence.toString()} · ${snapshot.stale ? "STALE" : "FRESH"}`}
                </span>
                <button
                  className="panel-collapse-button"
                  type="button"
                  aria-label={effectiveDiagnosticsCollapsed ? "展开诊断与恢复" : "收起诊断与恢复"}
                  aria-expanded={!effectiveDiagnosticsCollapsed}
                  aria-controls="diagnostic-deck"
                  title={effectiveDiagnosticsCollapsed ? "展开故障注入、恢复与硬件证据" : "收起诊断区并把高度返还给信号画布"}
                  onClick={() => {
                    if (signalFocusActive) {
                      setSignalFocusActive(false);
                      setDiagnosticsCollapsed(false);
                    } else {
                      setDiagnosticsCollapsed((collapsed) => !collapsed);
                    }
                  }}
                >
                  {effectiveDiagnosticsCollapsed
                    ? <ChevronUp size={17} aria-hidden="true" />
                    : <ChevronDown size={17} aria-hidden="true" />}
                </button>
              </div>
            </header>
            {effectiveDiagnosticsCollapsed ? null : (
              <div className="diagnostic-deck" id="diagnostic-deck">
                <FaultRecoveryPanel
                  faults={activeFaults}
                  options={faultOptions}
                  selectedFaultId={selectedFaultId}
                  onSelectFault={(faultId) => setSelectedFaultId(faultId as FaultCode)}
                  onInject={() => void handleInjectFault()}
                  onClearResolved={() => void handleClearRecoverable()}
                  busy={busy}
                  injectionAvailable={runtime.diagnostics !== null}
                />
                <HardwareStatusCard
                  connection={snapshot.controlConnection}
                  stale={snapshot.stale}
                  snapshotSequence={snapshot.snapshotSequence}
                  observedAtMonotonicMs={snapshot.observedAtMonotonicMs}
                  evidenceHash={snapshot.evidenceHash}
                  capabilities={hardwareCapabilities}
                />
              </div>
            )}
          </section>
        </section>

        <aside
          className={`control-stack${effectiveControlsCollapsed ? " control-stack--collapsed" : ""}`}
          data-collapsed={effectiveControlsCollapsed ? "true" : "false"}
        >
          {effectiveControlsCollapsed ? (
            <section className="control-rail" aria-label="已收起的采集控制栏">
              <button
                className="panel-collapse-button panel-collapse-button--vertical control-rail__expand"
                type="button"
                aria-label="展开采集控制栏"
                aria-expanded={false}
                title="展开 Preview 与 Recording 控制"
                onClick={() => {
                  if (signalFocusActive) {
                    setSignalFocusActive(false);
                    setControlsCollapsed(false);
                  } else {
                    setControlsCollapsed(false);
                  }
                }}
              >
                <PanelRightOpen size={18} aria-hidden="true" />
                <span>CTRL</span>
              </button>
              <div className={`control-rail__phase${runOutput.state === "recording" ? " is-recording" : ""}${runOutput.urgent ? " has-fault" : ""}`} title={phase.label}>
                <Activity size={15} aria-hidden="true" />
                <span>RUN</span>
                <strong>{connected ? runOutput.compactLabel : "OFF"}</strong>
              </div>
              <div className={`control-rail__preview${previewActive ? " is-live" : ""}`} title={`Preview ${snapshot.previewState}`}>
                <Waves size={14} aria-hidden="true" />
                <span>VIEW</span>
                <strong>{snapshot.previewState === "live" ? "LIVE" : snapshot.previewState === "fault" ? "FAULT" : "OFF"}</strong>
              </div>
              <button
                className="instrument-button instrument-button--stop control-rail__stop"
                type="button"
                aria-label="结束并保存"
                disabled={!canStopRecording || busy}
                title={connected
                  ? "一次请求完成停止输入、排空、durability barrier 与 seal；Preview 继续"
                  : "控制连接丢失；GUI 无法发送结束并保存"}
                onClick={() => void issue({ type: "stop_recording", reason: "operator" })}
              >
                <CircleStop size={18} aria-hidden="true" />
                <span>End</span>
                <b>&amp; Save</b>
              </button>
              <span className="control-rail__stop-boundary">
                {!connected
                  ? "NO CTRL"
                  : runOutput.state === "recording"
                    ? "RECORDING"
                    : runOutput.state === "saving"
                      ? "NWB OUTPUT"
                      : runOutput.state === "nwb_saved"
                        ? "NWB SAVED"
                        : runOutput.state === "mock_complete"
                          ? "MOCK ONLY"
                          : runOutput.state === "raw_retained"
                            ? "NWB INCOMPLETE"
                            : runOutput.state === "failed"
                              ? "RUN FAILED"
                              : snapshot.previewState === "live" ? "PREVIEW" : "NO RECORDING"}
              </span>
              <span className={`control-rail__faults${activeFaults.length > 0 ? " has-fault" : ""}`}>
                {activeFaults.length > 0 ? `${activeFaults.length} FLT` : "0 FLT"}
              </span>
            </section>
          ) : <>
            <RunControlPanel
            connected={connected}
            busy={busy}
            phase={snapshot.lifecycle}
            phaseLabel={phase.label}
            phaseDetail={phaseDetail}
            runId={snapshot.runId}
            previewState={snapshot.previewState}
            recordingTarget={setupTarget}
            preflightPassed={lifecycleHasPreflight(snapshot.lifecycle)}
            recordingArmed={lifecycleHasArm(snapshot.lifecycle)}
            recording={snapshot.lifecycle === "recording"}
            recordingStopped={lifecycleHasStopped(snapshot.lifecycle)}
            runOutput={runOutput}
            finalized={snapshot.lifecycle === "finalized"}
            recoveryRequired={snapshot.lifecycle === "recovery_required"}
            canConnect={!connected
              && snapshot.controlConnection === "disconnected"
              && snapshot.runId === null}
            canDisconnect={connected && ["connected_idle", "finalized"].includes(snapshot.lifecycle)}
            canStartPreview={connected && ["stopped", "fault"].includes(snapshot.previewState) && selectedPod !== null}
            canStopPreview={connected && snapshot.previewState === "live"}
            canSetupSingleRecording={connected && selectedPod?.selectable === true && (setupTarget !== null
              || (snapshot.previewState === "live" && ["connected_idle", "finalized"].includes(snapshot.lifecycle)))}
            canSetupMultiRecording={connected && (setupTarget !== null
              || (snapshot.previewState === "live" && ["connected_idle", "finalized"].includes(snapshot.lifecycle)))}
            recordingSetupMode={recordingSetupMode}
            recordingDeviceCount={runPlanLocked && snapshot.selectedPodKeys.length > 0
              ? snapshot.selectedPodKeys.length
              : selectedRecordPods.length}
            previewDeviceName={selectedPod?.identity.displayName ?? selectedPod?.label ?? "未选择设备"}
            canStart={connected && finalOutputReady && snapshot.lifecycle === "armed"}
            canStopRecording={canStopRecording}
            canRecover={snapshot.scope === "mock"
              && connected
              && snapshot.lifecycle === "recovery_required"
              && !durabilityFaultActive
              && !nonRecoverableFaultActive}
            canAcknowledgeFailed={connected
              && snapshot.lifecycle === "recovery_required"
              && (nonRecoverableFaultActive || (snapshot.scope === "software" && !snapshot.stale))}
            onConnect={() => void issue({ type: "connect" })}
            onDisconnect={() => void issue({ type: "disconnect_control" })}
            onStartPreview={handleStartPreview}
            onStopPreview={() => void issue({ type: "stop_preview", reason: "operator" })}
            onSetupSingleRecording={handleOpenSingleRecordingSetup}
            onSetupMultiRecording={handleOpenMultiRecordingSetup}
            onStart={() => void issue({ type: "start_recording" })}
            onStopRecording={() => void issue({ type: "stop_recording", reason: "operator" })}
            onRecover={() => void issue({ type: "recover_run" })}
            onAcknowledgeFailed={() => void issue({ type: "acknowledge_failed_run" })}
            onCollapse={() => setControlsCollapsed(true)}
            />
          </>}
        </aside>
      </main>

      <RunIntegrityRail
        lifecycle={snapshot.lifecycle}
        evidence={snapshot.evidence}
        runReceipt={snapshot.runReceipt}
        scope={snapshot.scope}
      />

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
          ? "模拟流程 · 无文件"
          : finalOutputReady ? "NWB 2.x · CREATE NEW" : "NWB 输出未接入"}
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

export default App;
