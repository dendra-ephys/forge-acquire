import {
  ChevronRight,
  CircleAlert,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Pencil,
  Usb,
} from "lucide-react";
import { useState } from "react";
import { InfoHint } from "./InfoHint";
import { ThemeToggle } from "./ThemeToggle";
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
  storageLowPodKeys: ReadonlySet<PodKey>;
  onRequestRename: (kind: DeviceKind, identity: DeviceIdentitySnapshot) => void;
  synthetic: boolean;
  controlConnected: boolean;
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

function formatRate(sampleRateHz: number): string {
  return `${(sampleRateHz / 1_000).toFixed(0)} kS/s`;
}

function inputSummary(pod: PodSnapshot): string {
  const input = pod.neuralInput;
  if (input === null) return "Input description unavailable";
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

function ForgeWaveMark() {
  return (
    <svg
      className="forge-wave-mark"
      viewBox="0 0 64 64"
      fill="none"
      stroke="currentColor"
      strokeWidth="4"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M6 34h8l5-16 8 31 7-23 6 13 5-9h13" />
    </svg>
  );
}

function PodLeaf({
  pod,
  pathLabel,
  selected,
  connected,
  storageLow,
  onSelect,
  onRequestRename,
}: {
  pod: PodSnapshot;
  pathLabel: string;
  selected: boolean;
  connected: boolean;
  storageLow: boolean;
  onSelect: (podKey: PodKey) => void;
  onRequestRename: (kind: DeviceKind, identity: DeviceIdentitySnapshot) => void;
}) {
  const state = pod.state === "fault" ? "fault" : connected ? "online" : "warning";
  const displayName = pod.identity.displayName || pod.label;
  return (
    <li
      className={`pod-device-row${storageLow ? " has-storage-warning" : ""}`}
      data-pod-key={pod.key}
      data-storage-low={storageLow ? "true" : "false"}
    >
      <button
        className={`pod-leaf pod-leaf--${state}${selected ? " is-selected" : ""}${storageLow ? " has-storage-warning" : ""}`}
        type="button"
        aria-label={`Preview ${displayName}; device ID ${pod.identity.deviceId}; path ${pathLabel}`}
        aria-pressed={selected}
        data-tooltip={`${inputSummary(pod)} · ${selected ? "Current Preview" : podStateLabel(pod, connected)} · ${pathLabel}`}
        onClick={() => onSelect(pod.key)}
      >
        <span className="pod-leaf__body">
          <strong title={displayName}>{displayName}</strong>
        </span>
        <span
          className={`pod-leaf__state pod-leaf__state--${state}`}
        >
          {pod.state === "fault" ? <CircleAlert size={14} aria-hidden="true" /> : <span aria-hidden="true" />}
          <span className="sr-only">{selected ? "Current Preview" : podStateLabel(pod, connected)}</span>
        </span>
      </button>
      <div className="pod-device-actions" role="group" aria-label={`${displayName} actions`}>
        <button
          className="device-rename-button"
          type="button"
          disabled={!pod.identity.writable}
          aria-label={`Rename ${displayName}`}
          data-tooltip={pod.identity.writable ? `Rename ${displayName}` : `Cannot rename: ${pod.identity.reasonCode}`}
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
  storageLowPodKeys,
  onRequestRename,
  synthetic,
  controlConnected,
  collapsed,
  onToggleCollapsed,
}: PodRackProps) {
  const [expandedAggregators, setExpandedAggregators] = useState<ReadonlySet<string>>(
    () => new Set(topology.aggregators.map((aggregator) => aggregator.aggregatorId)),
  );
  const [directExpanded, setDirectExpanded] = useState(true);
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
        aria-label="Device list collapsed"
        data-collapsed="true"
      >
        <div className="pod-rack-brand pod-rack-brand--collapsed" aria-label="Forge Acquire">
          <ForgeWaveMark />
        </div>
        <button
          className="panel-collapse-button panel-collapse-button--vertical"
          type="button"
          aria-label="Expand device list"
          aria-expanded={false}
          data-tooltip="Expand devices"
          onClick={onToggleCollapsed}
        >
          <PanelLeftOpen size={18} aria-hidden="true" />
          <span>Devices</span>
        </button>
        <div
          className="pod-rack-compact-count"
          aria-label={`${occupied} Pods connected; ${recordPodKeys.size} Pods ${recordSelectionLocked ? "in the current Run" : "in the multi-device draft"}`}
          data-tooltip={`${occupied} of ${topology.maxPodsPerRun} Pod slots are present. ${recordPodKeys.size} ${recordSelectionLocked ? "belong to the active Run" : "are selected in the recording draft"}.`}
        >
          <strong>{occupied}</strong>
          <span>of {topology.maxPodsPerRun}</span>
          <span className="pod-rack-compact-selection">{recordPodKeys.size} {recordSelectionLocked ? "RUN" : "REC"}</span>
        </div>
        <div className="pod-rack-compact-routes" aria-label={`${topology.directPods.length} direct and ${aggregatedCount} Aggregator Pods`}>
          <span data-tooltip={`${topology.directPods.length} Pods connected directly to this PC over USB 3`}><Usb size={15} aria-hidden="true" /><b>{topology.directPods.length}</b></span>
          <span data-tooltip={`${aggregatedCount} Pods routed through an Aggregator`}><Network size={15} aria-hidden="true" /><b>{aggregatedCount}</b></span>
        </div>
        <footer className="pod-rack-footer pod-rack-footer--collapsed" aria-label="Appearance">
          <ThemeToggle />
        </footer>
      </section>
    );
  }

  return (
    <section className="pod-rack" aria-labelledby="pod-rack-title" data-collapsed="false">
      <div className="pod-rack-brand" aria-label="Forge Acquire">
        <ForgeWaveMark />
        <strong>Forge Acquire</strong>
      </div>
      <header className="instrument-section-heading">
        <div className="instrument-section-heading__title">
          <span className="instrument-kicker">DEVICES</span>
          <div className="instrument-section-heading__title-row">
            <h2 id="pod-rack-title">Devices</h2>
            <InfoHint label="About device sources">
              <strong>Device sources</strong>
              <span>
                {synthetic
                  ? "Devices and routes come from a mock snapshot. Aggregator entries do not prove a live 10GbE connection."
                  : "Routes, parents, and Pod identities come only from the daemon topology snapshot."}
              </span>
            </InfoHint>
          </div>
        </div>
        <div className="instrument-section-heading__actions">
          <span
            className="rack-count"
            aria-label={`${occupied} of ${topology.maxPodsPerRun} Pods present in snapshot`}
            data-tooltip={`${occupied} Pods are present in the latest device snapshot. A Run can include at most ${topology.maxPodsPerRun} Pods.`}
          >
            {occupied}/{topology.maxPodsPerRun}
          </span>
          <button
            className="panel-collapse-button"
            type="button"
            aria-label="Collapse device list"
            aria-expanded={true}
            data-tooltip="Collapse devices"
            onClick={onToggleCollapsed}
          >
            <PanelLeftClose size={17} aria-hidden="true" />
          </button>
        </div>
      </header>

      <div className="pod-topology" aria-label="Device connections">
        <section className="topology-branch" aria-labelledby="direct-pods-title">
          <button
            className="topology-root topology-root--direct"
            type="button"
            aria-expanded={directExpanded}
            aria-controls="direct-pods"
            onClick={() => setDirectExpanded((current) => !current)}
          >
            <ChevronRight className="topology-root__chevron" size={15} aria-hidden="true" />
            <Usb size={16} aria-hidden="true" />
            <span>
              <strong id="direct-pods-title">Direct to PC</strong>
            </span>
            <small>{topology.directPods.length}</small>
          </button>
          {directExpanded ? (
            <ul id="direct-pods" className="topology-children topology-children--direct">
              {topology.directPods.map((pod) => (
                <PodLeaf
                  key={pod.key}
                  pod={pod}
                  pathLabel={podPathLabel(pod)}
                  selected={selectedPodKey === pod.key}
                  connected={controlConnected}
                  storageLow={storageLowPodKeys.has(pod.key)}
                  onSelect={onSelect}
                  onRequestRename={onRequestRename}
                />
              ))}
            </ul>
          ) : null}
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
                  </span>
                  <small>{occupiedPorts.length}</small>
                </button>
                <button
                  className="device-rename-button device-rename-button--aggregator"
                  type="button"
                  disabled={!aggregator.identity.writable}
                  aria-label={`Rename ${aggregatorName}`}
                  data-tooltip={aggregator.identity.writable
                    ? `Rename ${aggregatorName}`
                    : `Cannot rename: ${aggregator.identity.reasonCode}`}
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
                        connected={controlConnected}
                        storageLow={storageLowPodKeys.has(pod!.key)}
                        onSelect={onSelect}
                        onRequestRename={onRequestRename}
                      />
                    ))}
                  </ul>
                </div>
              ) : null}
            </section>
          );
        })}
      </div>

      <footer className="pod-rack-footer" aria-label="Appearance">
        <span>Appearance</span>
        <ThemeToggle />
      </footer>

    </section>
  );
}
