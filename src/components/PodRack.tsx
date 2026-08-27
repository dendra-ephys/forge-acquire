import {
  Cable,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Pencil,
  RadioTower,
  Usb,
} from "lucide-react";
import { useState } from "react";
import type {
  AggregatorSnapshot,
  DeviceIdentitySnapshot,
  DeviceKind,
  PodKey,
  PodSnapshot,
  PodTopologySnapshot,
} from "../adapters/acquireAdapter";

export interface PodRackProps {
  topology: PodTopologySnapshot;
  selectedPodKey: PodKey | null;
  onSelect: (podKey: PodKey) => void;
  recordPodKeys: ReadonlySet<PodKey>;
  recordSelectionLocked: boolean;
  onToggleRecord: (podKey: PodKey, selected: boolean) => void;
  onRequestRename: (kind: DeviceKind, identity: DeviceIdentitySnapshot) => void;
  synthetic: boolean;
  controlConnected: boolean;
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

function stateIcon(pod: PodSnapshot, connected: boolean) {
  if (pod.state === "fault") return <CircleAlert size={15} aria-hidden="true" />;
  if (connected) return <CircleCheck size={15} aria-hidden="true" />;
  return <Cable size={15} aria-hidden="true" />;
}

function formatRate(sampleRateHz: number): string {
  return `${(sampleRateHz / 1_000).toFixed(0)} kS/s`;
}

function inputSummary(pod: PodSnapshot): string {
  const input = pod.neuralInput;
  if (input === null) return "输入描述 unavailable";
  return `${input.neuralChannelCount} neural · ${formatRate(input.sampleRateHz)}/ch`;
}

function podStateLabel(pod: PodSnapshot, connected: boolean): string {
  if (pod.state === "fault") return "FAULT";
  if (pod.state === "mock_recording") return "SYNTH REC";
  if (pod.state === "recording") return "RECORDING";
  return connected ? "MOCK READY" : "FIXTURE";
}

function podPathLabel(pod: PodSnapshot): string {
  if (pod.connection.kind === "direct_pc") {
    return `PC / USB3 / ${pod.connection.connectionId}`;
  }
  return `PC / 10GbE / ${pod.connection.aggregatorId} / PORT ${String(pod.connection.port).padStart(2, "0")} / USB3`;
}

function nameScopeLabel(identity: DeviceIdentitySnapshot): string {
  if (identity.persistence === "device_nonvolatile") {
    return identity.crossHostPersistenceQualified
      && identity.powerLossSafeWriteQualified
      && identity.nameReadBackVerified
      ? "DEVICE NVM ✓"
      : "DEVICE NVM · QUALIFICATION";
  }
  if (identity.persistence === "mock_session") return "MOCK NAME";
  if (identity.persistence === "host_local") return "THIS PC ONLY";
  return "NAME NOT PERSISTED";
}

function PodLeaf({
  pod,
  pathLabel,
  selected,
  recordSelected,
  recordSelectionLocked,
  connected,
  onSelect,
  onToggleRecord,
  onRequestRename,
}: {
  pod: PodSnapshot;
  pathLabel: string;
  selected: boolean;
  recordSelected: boolean;
  recordSelectionLocked: boolean;
  connected: boolean;
  onSelect: (podKey: PodKey) => void;
  onToggleRecord: (podKey: PodKey, selected: boolean) => void;
  onRequestRename: (kind: DeviceKind, identity: DeviceIdentitySnapshot) => void;
}) {
  const state = pod.state === "fault" ? "fault" : connected ? "online" : "warning";
  const displayName = pod.identity.displayName || pod.label;
  return (
    <li
      className={`pod-device-row${recordSelected ? " is-record-selected" : ""}`}
      data-pod-key={pod.key}
      data-record-selected={recordSelected ? "true" : "false"}
    >
      <button
        className={`pod-leaf pod-leaf--${state}${selected ? " is-selected" : ""}`}
        type="button"
        aria-label={`选择 ${displayName} 进行 Preview；设备 ID ${pod.identity.deviceId}；路径 ${pathLabel}`}
        aria-pressed={selected}
        onClick={() => onSelect(pod.key)}
      >
        <span className="pod-leaf__route" title={pathLabel}>PATH · {pathLabel}</span>
        <span className="pod-leaf__body">
          <strong title={displayName}>{displayName}</strong>
          <span className={`device-name-scope device-name-scope--${pod.identity.persistence}`}>
            {nameScopeLabel(pod.identity)}
          </span>
          <span>{inputSummary(pod)}</span>
          <span className="device-immutable-id" title={pod.identity.deviceId}>
            ID · {pod.identity.deviceId}
          </span>
          <span className="pod-leaf__detail">
            {pod.neuralInput?.profileLabel ?? "No headstage input receipt"}
          </span>
        </span>
        <span className={`pod-leaf__state pod-leaf__state--${state}`}>
          {stateIcon(pod, connected)}
          <span>{selected ? "PREVIEW" : podStateLabel(pod, connected)}</span>
          <span>· {pod.neuralInput?.scope.toUpperCase() ?? "NO INPUT"}</span>
        </span>
      </button>
      <div className="pod-device-actions" role="group" aria-label={`${displayName} 设备操作`}>
        <label
          className={`pod-record-toggle${recordSelected ? " is-selected" : ""}`}
          title={recordSelectionLocked
            ? "当前 Run 已冻结记录设备集合"
            : pod.selectable ? "将此 Pod 纳入多设备记录草案；不改变 Preview 设备" : pod.selectionReasonCode}
        >
          <input
            type="checkbox"
            checked={recordSelected}
            disabled={!pod.selectable || recordSelectionLocked}
            aria-label={recordSelectionLocked
              ? `${displayName} ${recordSelected ? "属于" : "不属于"}当前 Run`
              : `将 ${displayName} ${recordSelected ? "移出" : "加入"}多设备记录草案`}
            onChange={(event) => onToggleRecord(pod.key, event.currentTarget.checked)}
          />
          <span>{recordSelectionLocked ? "RUN" : "MULTI"}</span>
        </label>
        <button
          className="device-rename-button"
          type="button"
          disabled={!pod.identity.writable}
          aria-label={`重命名设备 ${displayName}`}
          title={pod.identity.writable ? `重命名 ${displayName}` : `不可重命名：${pod.identity.reasonCode}`}
          onClick={() => onRequestRename("pod", pod.identity)}
        >
          <Pencil size={15} aria-hidden="true" />
        </button>
      </div>
    </li>
  );
}

function aggregatorOccupiedPorts(aggregator: AggregatorSnapshot) {
  return aggregator.ports.filter((port) => port.pod !== null);
}

export function PodRack({
  topology,
  selectedPodKey,
  onSelect,
  recordPodKeys,
  recordSelectionLocked,
  onToggleRecord,
  onRequestRename,
  synthetic,
  controlConnected,
  collapsed,
  onToggleCollapsed,
}: PodRackProps) {
  const [expandedAggregators, setExpandedAggregators] = useState<ReadonlySet<string>>(
    () => new Set(topology.aggregators.map((aggregator) => aggregator.aggregatorId)),
  );
  const occupied = topology.directPods.length
    + topology.aggregators.reduce((sum, aggregator) => sum + aggregatorOccupiedPorts(aggregator).length, 0);
  const aggregatedCount = topology.aggregators.reduce(
    (sum, aggregator) => sum + aggregatorOccupiedPorts(aggregator).length,
    0,
  );

  const toggleAggregator = (aggregatorId: string) => {
    setExpandedAggregators((current) => {
      const next = new Set(current);
      if (next.has(aggregatorId)) next.delete(aggregatorId);
      else next.add(aggregatorId);
      return next;
    });
  };

  if (collapsed) {
    return (
      <section
        className="pod-rack pod-rack--collapsed"
        aria-label="设备列表已收起"
        data-collapsed="true"
      >
        <button
          className="panel-collapse-button panel-collapse-button--vertical"
          type="button"
          aria-label="展开设备列表"
          aria-expanded={false}
          title="展开设备列表"
          onClick={onToggleCollapsed}
        >
          <PanelLeftOpen size={18} aria-hidden="true" />
          <span>设备</span>
        </button>
        <div className="pod-rack-compact-count" aria-label={`${occupied} 个 Pod 已连接；${recordPodKeys.size} 个 Pod ${recordSelectionLocked ? "属于当前 Run" : "在多设备记录草案"}`}>
          <strong>{occupied}</strong>
          <span>/ {topology.maxPodsPerRun}</span>
          <span>{recordPodKeys.size} {recordSelectionLocked ? "RUN" : "MULTI"}</span>
        </div>
        <div className="pod-rack-compact-routes" aria-label={`${topology.directPods.length} direct and ${aggregatedCount} Aggregator Pods`}>
          <span><Usb size={15} aria-hidden="true" /><b>{topology.directPods.length}</b></span>
          <span><Network size={15} aria-hidden="true" /><b>{aggregatedCount}</b></span>
        </div>
        <span className={`pod-rack-compact-state${controlConnected ? " is-connected" : ""}`}>
          {controlConnected ? "LINK" : "OFF"}
        </span>
      </section>
    );
  }

  return (
    <section className="pod-rack" aria-labelledby="pod-rack-title" data-collapsed="false">
      <header className="instrument-section-heading">
        <div>
          <span className="instrument-kicker">DEVICES</span>
          <h2 id="pod-rack-title">设备列表</h2>
        </div>
        <div className="instrument-section-heading__actions">
          <span className="rack-record-count" aria-label={recordSelectionLocked
            ? `${recordPodKeys.size} Pods frozen in the current Run`
            : `${recordPodKeys.size} Pods explicitly selected for a multi-device draft`}>
            {recordPodKeys.size} {recordSelectionLocked ? "RUN" : "MULTI"}
          </span>
          <span className="rack-count" aria-label={`${occupied} of ${topology.maxPodsPerRun} Pods present in snapshot`}>
            {occupied}/{topology.maxPodsPerRun}
          </span>
          <button
            className="panel-collapse-button"
            type="button"
            aria-label="收起设备列表"
            aria-expanded={true}
            title="收起设备列表"
            onClick={onToggleCollapsed}
          >
            <PanelLeftClose size={17} aria-hidden="true" />
          </button>
        </div>
      </header>

      <div className="pod-topology" aria-label="设备连接列表">
        <section className="topology-branch" aria-labelledby="direct-pods-title">
          <header className="topology-root topology-root--direct">
            <Usb size={16} aria-hidden="true" />
            <span>
              <strong id="direct-pods-title">直接连接 PC</strong>
              <small>USB 3 device · {topology.directPods.length} Pods</small>
            </span>
            <em>DIRECT</em>
          </header>
          <ul className="topology-children topology-children--direct">
            {topology.directPods.map((pod) => (
              <PodLeaf
                key={pod.key}
                pod={pod}
                pathLabel={podPathLabel(pod)}
                selected={selectedPodKey === pod.key}
                recordSelected={recordPodKeys.has(pod.key)}
                recordSelectionLocked={recordSelectionLocked}
                connected={controlConnected}
                onSelect={onSelect}
                onToggleRecord={onToggleRecord}
                onRequestRename={onRequestRename}
              />
            ))}
          </ul>
        </section>

        {topology.aggregators.map((aggregator) => {
          const expanded = expandedAggregators.has(aggregator.aggregatorId);
          const occupiedPorts = aggregatorOccupiedPorts(aggregator);
          const childrenId = `aggregator-${aggregator.aggregatorId}-pods`;
          const aggregatorName = aggregator.identity.displayName || aggregator.label;
          return (
            <section className="topology-branch topology-branch--aggregator" key={aggregator.aggregatorId}>
              <div className="aggregator-device-row" data-device-id={aggregator.identity.deviceId}>
                <button
                  className="topology-root topology-root--aggregator"
                  type="button"
                  aria-expanded={expanded}
                  aria-controls={childrenId}
                  onClick={() => toggleAggregator(aggregator.aggregatorId)}
                >
                  <ChevronRight className="topology-root__chevron" size={15} aria-hidden="true" />
                  <Network size={16} aria-hidden="true" />
                  <span>
                    <strong title={aggregatorName}>{aggregatorName}</strong>
                    <small>{occupiedPorts.length} Pods · PATH · PC / 10GbE</small>
                    <small className="device-immutable-id" title={aggregator.identity.deviceId}>
                      ID · {aggregator.identity.deviceId}
                    </small>
                    <small className={`device-name-scope device-name-scope--${aggregator.identity.persistence}`}>
                      {nameScopeLabel(aggregator.identity)}
                    </small>
                  </span>
                  <em>SYNTHETIC PATH</em>
                  <b>HW {aggregator.hardwareStatus.toUpperCase()}</b>
                </button>
                <button
                  className="device-rename-button device-rename-button--aggregator"
                  type="button"
                  disabled={!aggregator.identity.writable}
                  aria-label={`重命名设备 ${aggregatorName}`}
                  title={aggregator.identity.writable
                    ? `重命名 ${aggregatorName}`
                    : `不可重命名：${aggregator.identity.reasonCode}`}
                  onClick={() => onRequestRename("aggregator", aggregator.identity)}
                >
                  <Pencil size={15} aria-hidden="true" />
                </button>
              </div>
              {expanded ? (
                <div id={childrenId}>
                  <ul className="topology-children topology-children--aggregator">
                    {occupiedPorts.map(({ pod }) => (
                      <PodLeaf
                        key={pod!.key}
                        pod={pod!}
                        pathLabel={podPathLabel(pod!)}
                        selected={selectedPodKey === pod!.key}
                        recordSelected={recordPodKeys.has(pod!.key)}
                        recordSelectionLocked={recordSelectionLocked}
                        connected={controlConnected}
                        onSelect={onSelect}
                        onToggleRecord={onToggleRecord}
                        onRequestRename={onRequestRename}
                      />
                    ))}
                  </ul>
                  <div className="topology-empty-ports">
                    {aggregator.maxPodPorts - occupiedPorts.length} empty Aggregator ports · {aggregator.hardwareReasonCode}
                  </div>
                </div>
              ) : null}
            </section>
          );
        })}
      </div>

      <footer className="rack-boundary-note">
        <RadioTower size={15} aria-hidden="true" />
        <span>
          {synthetic
            ? "设备与连接树由 mock snapshot 提供；Aggregator 子项不表示 10GbE 硬件已连接。"
            : "连接路径、父节点与 Pod 身份仅来自 daemon topology snapshot。"}
        </span>
      </footer>
    </section>
  );
}
