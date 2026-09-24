import {
  type CSSProperties,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import type { SpikePreviewFrame } from "../adapters/acquireAdapter";

const MAX_OVERVIEW_DOM_CHANNELS = 48;
const OVERVIEW_CARD_MIN_WIDTH = 176;
const OVERVIEW_GRID_ROW_HEIGHT = 86;
const OVERVIEW_OVERSCAN_ROWS = 2;

function clamp(value: number, minimum: number, maximum: number) {
  return Math.max(minimum, Math.min(maximum, value));
}

function channelLabel(channel: number): string {
  return `CH ${String(channel + 1).padStart(3, "0")}`;
}

export function waveformWindowInvariant(frame: SpikePreviewFrame): boolean {
  const window = frame.selectedChannelWaveforms;
  if (window.coverage !== "complete"
    || window.reasonCode !== null
    || window.observedEventCount !== window.returnedEventCount
    || window.returnedEventCount !== window.events.length
    || window.retentionSamples <= 0n) return false;
  const ids = new Set<string>();
  let previousCenter: bigint | null = null;
  const end = frame.sourceSampleEndExclusive;
  for (const event of window.events) {
    if (ids.has(event.eventId)
      || event.channel !== frame.selectedChannel
      || (previousCenter !== null && event.centerSample < previousCenter)
      || (end !== null && (event.centerSample >= end || end - event.centerSample >= window.retentionSamples))) {
      return false;
    }
    ids.add(event.eventId);
    previousCenter = event.centerSample;
  }
  return true;
}

export function waveformClusterGroups(frame: SpikePreviewFrame) {
  return [{
    id: "unsorted",
    label: "UNSORTED POOL",
    events: frame.selectedChannelWaveforms.events,
  }] as const;
}

export function boundedActivityWindow(totalChannels: number, scrollPercent: number) {
  const size = Math.min(MAX_OVERVIEW_DOM_CHANNELS, Math.max(0, totalChannels));
  const maximumStart = Math.max(0, totalChannels - size);
  const start = Math.round((maximumStart * clamp(scrollPercent, 0, 100)) / 100);
  return { start, size, maximumStart };
}

export function overviewColumnCount(viewportWidth: number): number {
  return Math.max(1, Math.min(8, Math.floor(Math.max(OVERVIEW_CARD_MIN_WIDTH, viewportWidth - 8) / OVERVIEW_CARD_MIN_WIDTH)));
}

export function virtualChannelWindow(
  totalChannels: number,
  scrollTop: number,
  viewportHeight: number,
  columns: number,
) {
  const safeColumns = Math.max(1, Math.floor(columns));
  const totalRows = Math.ceil(Math.max(0, totalChannels) / safeColumns);
  const firstVisibleRow = Math.floor(Math.max(0, scrollTop) / OVERVIEW_GRID_ROW_HEIGHT);
  const lastVisibleRowExclusive = Math.min(totalRows, Math.ceil(
    (Math.max(0, scrollTop) + Math.max(OVERVIEW_GRID_ROW_HEIGHT, viewportHeight))
      / OVERVIEW_GRID_ROW_HEIGHT,
  ));
  const visibleRows = Math.max(1, lastVisibleRowExclusive - firstVisibleRow);
  const capacityRows = Math.max(1, Math.floor(MAX_OVERVIEW_DOM_CHANNELS / safeColumns));
  const requestedRows = Math.min(
    capacityRows,
    visibleRows + OVERVIEW_OVERSCAN_ROWS * 2,
  );
  // When the viewport reaches the bottom, bias the bounded window downward so
  // the final Pod channel is present. A simple upper slice can otherwise spend
  // the 48-card budget on overscan above the viewport and omit the last rows.
  const minimumStartForViewport = Math.max(0, lastVisibleRowExclusive - requestedRows);
  const maximumStart = Math.max(0, totalRows - requestedRows);
  const startRow = Math.min(
    maximumStart,
    Math.max(minimumStartForViewport, firstVisibleRow - OVERVIEW_OVERSCAN_ROWS),
  );
  const availableRows = Math.max(0, totalRows - startRow);
  const renderedRows = Math.min(availableRows, requestedRows);
  const start = startRow * safeColumns;
  const size = Math.min(
    MAX_OVERVIEW_DOM_CHANNELS,
    Math.max(0, totalChannels - start),
    renderedRows * safeColumns,
  );
  return {
    start,
    size,
    rowHeight: OVERVIEW_GRID_ROW_HEIGHT,
    startRow,
    totalRows,
    columns: safeColumns,
  };
}

export function previewUnitLabel(
  frame: Pick<SpikePreviewFrame, "valueUnit" | "valueUnitScope" | "valueUnitReasonCode">,
): string {
  if (frame.valueUnit === "adc_count") return "ADC counts";
  if (frame.valueUnitReasonCode === "NWB_WAVEFORM_RECONSTRUCTION_UNITS") return "NWB µV";
  return frame.valueUnitScope === "mock" ? "SYNTHETIC µV" : "µV";
}

export interface SpikeScopeCanvasProps {
  frame: SpikePreviewFrame;
  expectedChannelCount: number | null;
  selectedChannel: number;
  detailOpen: boolean;
  onSelect: (channel: number) => void;
  onCloseDetail: () => void;
  gainValue: number;
  paused: boolean;
}

function waveformPoints(values: readonly number[], gainValue: number): string {
  const width = 240;
  const centerY = 15;
  const halfHeight = 13;
  return values.map((value, index) => {
    const x = (index / Math.max(1, values.length - 1)) * width;
    const y = centerY - clamp(value / Math.max(1, Math.abs(gainValue)), -1, 1) * halfHeight;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
}

export function SpikeScopeCanvas({
  frame,
  expectedChannelCount,
  selectedChannel,
  detailOpen,
  onSelect,
  onCloseDetail,
  gainValue,
  paused,
}: SpikeScopeCanvasProps) {
  const overviewRef = useRef<HTMLDivElement>(null);
  const canvasShellRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const summaryId = useId();
  const [overviewViewport, setOverviewViewport] = useState({ scrollTop: 0, height: 420, width: 900 });
  const [canvasSize, setCanvasSize] = useState({ width: 0, height: 0, dpr: 1 });
  const [announcement, setAnnouncement] = useState("");

  const waveformWindow = frame.selectedChannelWaveforms;
  const waveformInvariantValid = waveformWindowInvariant(frame);
  const waveformEvents = waveformWindow.events;
  const clusterGroups = waveformClusterGroups(frame);
  const unitLabel = previewUnitLabel(frame);
  const activeChannelCount = frame.channelActivity.filter((item) => item.observedEventCount > 0).length;
  const virtualWindow = virtualChannelWindow(
    frame.channelActivity.length,
    overviewViewport.scrollTop,
    overviewViewport.height,
    overviewColumnCount(overviewViewport.width),
  );
  const visibleActivity = frame.channelActivity.slice(
    virtualWindow.start,
    virtualWindow.start + virtualWindow.size,
  );
  const accounting = frame.accounting;
  const invariantValid = accounting.observedEventCount === accounting.rasterCandidateEventCount
    && accounting.rasterCandidateEventCount
      === accounting.sampledOutEventCount + accounting.returnedRasterEventCount
    && frame.coverage.source === "complete"
    && frame.coverage.analysis === "complete"
    && frame.coverage.sourceGapRanges.length === 0
    && frame.coverage.analysisGapRanges.length === 0;
  const channelMismatch = expectedChannelCount !== null
    && expectedChannelCount !== frame.inputChannelCount;

  useLayoutEffect(() => {
    const overview = overviewRef.current;
    if (!overview) return undefined;
    const measure = () => setOverviewViewport({
      scrollTop: overview.scrollTop,
      height: Math.max(OVERVIEW_GRID_ROW_HEIGHT, overview.clientHeight),
      width: Math.max(OVERVIEW_CARD_MIN_WIDTH, overview.clientWidth),
    });
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(overview);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const overview = overviewRef.current;
    if (!overview) return;
    const selectedRow = Math.floor(selectedChannel / virtualWindow.columns);
    const top = selectedRow * OVERVIEW_GRID_ROW_HEIGHT;
    const bottom = top + OVERVIEW_GRID_ROW_HEIGHT;
    if (top < overview.scrollTop) overview.scrollTop = top;
    else if (bottom > overview.scrollTop + overview.clientHeight) {
      overview.scrollTop = bottom - overview.clientHeight;
    }
  }, [selectedChannel, virtualWindow.columns]);

  useLayoutEffect(() => {
    const shell = canvasShellRef.current;
    if (!shell || !detailOpen) return undefined;
    const measure = () => {
      const bounds = shell.getBoundingClientRect();
      setCanvasSize({
        width: Math.max(0, bounds.width),
        height: Math.max(0, bounds.height),
        dpr: clamp(window.devicePixelRatio || 1, 1, 3),
      });
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(shell);
    return () => observer.disconnect();
  }, [detailOpen]);

  useLayoutEffect(() => {
    const canvas = canvasRef.current;
    const { width, height, dpr } = canvasSize;
    if (!canvas || !detailOpen || width <= 0 || height <= 0) return undefined;
    const render = window.requestAnimationFrame(() => {
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      const context = canvas.getContext("2d");
      if (!context) return;
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
      context.fillStyle = "#111";
      context.fillRect(0, 0, width, height);
      const left = 10;
      const right = width - 10;
      const top = 8;
      const bottom = height - 18;
      const centerY = top + (bottom - top) * 0.47;
      const yFor = (value: number) => centerY
        - (value / Math.max(1, Math.abs(gainValue))) * (bottom - top) * 0.44;

      context.strokeStyle = "#262626";
      for (let line = 1; line < 4; line += 1) {
        const y = top + ((bottom - top) * line) / 4;
        context.beginPath();
        context.moveTo(left, y);
        context.lineTo(right, y);
        context.stroke();
      }
      context.strokeStyle = "#3b3b3b";
      context.beginPath();
      context.moveTo(left, yFor(0));
      context.lineTo(right, yFor(0));
      context.stroke();

      if (waveformWindow.events.length > 0 && waveformInvariantValid) {
        waveformEvents.forEach((event) => {
          context.strokeStyle = "rgba(230,230,230,.48)";
          context.lineWidth = 1.1;
          context.beginPath();
          event.values.forEach((value, index) => {
            const x = left + (index / Math.max(1, event.values.length - 1)) * (right - left);
            if (index === 0) context.moveTo(x, yFor(value));
            else context.lineTo(x, yFor(value));
          });
          context.stroke();
        });
      } else {
        context.fillStyle = waveformInvariantValid ? "#888" : "#eee";
        context.font = "600 9px ui-monospace,Consolas,monospace";
        context.fillText(
          waveformInvariantValid ? "NO EVENTS IN WINDOW" : "WAVEFORM COVERAGE FAULT",
          left,
          top + 14,
        );
      }
      context.fillStyle = "#888";
      context.font = "500 8px ui-monospace,Consolas,monospace";
      context.fillText(`−${frame.windowSeconds.toFixed(1)} s`, left, height - 5);
      context.textAlign = "right";
      context.fillText("0 s", right, height - 5);
    });
    return () => window.cancelAnimationFrame(render);
  }, [canvasSize, detailOpen, frame, gainValue, waveformEvents, waveformInvariantValid, waveformWindow]);

  return (
    <div className="spike-preview-panel" data-paused={paused ? "true" : "false"}>
      <div
        id={summaryId}
        className="spike-event-summary-data sr-only"
        data-testid="spike-event-summary"
        data-pod-events={frame.podObservedEventCount}
        data-bank-events={accounting.observedEventCount}
        data-rendered={accounting.returnedRasterEventCount}
        data-preview-omitted={accounting.sampledOutEventCount}
        data-source-coverage={frame.coverage.source}
        data-analysis-coverage={frame.coverage.analysis}
        data-invariant-valid={invariantValid ? "true" : "false"}
      >
        Pod events {frame.podObservedEventCount}. Selected 8-channel events {accounting.observedEventCount}.
      </div>

      <div className={`spike-overview-layout${detailOpen ? " has-detail" : ""}`}>
        <section className="spike-channel-browser" aria-label="All-channel live Spike overview">
          <header className="spike-channel-browser__header">
            <span>WAVEFORM MATRIX</span>
            <strong>{frame.inputChannelCount} channels · {activeChannelCount} active</strong>
            <em>each tile is one channel · click for detail</em>
          </header>
          <div
            ref={overviewRef}
            className="spike-channel-overview"
            role="listbox"
            aria-label={`Live Spike overview for all ${frame.inputChannelCount} Pod channels`}
            data-testid="spike-overview"
            data-total-channels={frame.inputChannelCount}
            data-active-channels={activeChannelCount}
            data-rendered-channels={visibleActivity.length}
            data-window-start={virtualWindow.start}
            data-grid-columns={virtualWindow.columns}
            onScroll={(event) => setOverviewViewport({
              scrollTop: event.currentTarget.scrollTop,
              height: event.currentTarget.clientHeight,
              width: event.currentTarget.clientWidth,
            })}
          >
            <div className="spike-channel-overview__spacer" style={{ height: virtualWindow.totalRows * virtualWindow.rowHeight }} />
            <div
              className="spike-channel-overview__window"
              style={{
                transform: `translateY(${virtualWindow.startRow * virtualWindow.rowHeight}px)`,
                "--spike-grid-columns": virtualWindow.columns,
              } as CSSProperties}
            >
              {visibleActivity.map((activity) => (
                <button
                  type="button"
                  role="option"
                  key={activity.channel}
                  className={`spike-channel-card${activity.channel === selectedChannel ? " is-selected" : ""}`}
                  aria-label={`${channelLabel(activity.channel)} · ${activity.recentWaveforms.length} recent spike waveforms · ${activity.observedEventCount} events · open waveform detail`}
                  aria-selected={activity.channel === selectedChannel}
                  data-testid="spike-activity-channel"
                  data-channel={activity.channel}
                  onClick={() => {
                    onSelect(activity.channel);
                    setAnnouncement(`${channelLabel(activity.channel)} detail opened`);
                  }}
                >
                  <span className="spike-channel-card__header">
                    <strong>{channelLabel(activity.channel)}</strong>
                    <small>n={activity.observedEventCount}</small>
                  </span>
                  <span className="spike-channel-waveforms" aria-hidden="true">
                    {activity.recentWaveforms.length > 0 ? (
                      <svg viewBox="0 0 240 30" preserveAspectRatio="none" data-testid="spike-channel-waveform">
                        <line x1="0" y1="15" x2="240" y2="15" />
                        {activity.recentWaveforms.map((waveform, index) => (
                          <polyline
                            key={index}
                            points={waveformPoints(waveform, gainValue)}
                          />
                        ))}
                      </svg>
                    ) : <em>NO SPIKE IN WINDOW</em>}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </section>

        {detailOpen ? (
          <section
            className="spike-detail-panel"
            role="region"
            aria-label={`${channelLabel(selectedChannel)} waveform detail; ${waveformWindow.returnedEventCount} waveforms; ${frame.windowSeconds}s retention; ${unitLabel}.`}
            aria-describedby={summaryId}
          >
            <header className="spike-detail-header">
              <div><strong>{channelLabel(selectedChannel)}</strong><span>{waveformWindow.returnedEventCount} events · {unitLabel}</span></div>
              <button className="spike-detail-close" type="button" aria-label="Close channel detail" onClick={onCloseDetail}>×</button>
            </header>
            <div className="spike-detail-body">
              <section className="spike-detail-waveforms" aria-label="All retained waveforms">
                <header><strong>ALL WAVEFORMS</strong><span>{waveformWindow.returnedEventCount} retained</span></header>
                <div ref={canvasShellRef} className="spike-detail-canvas">
                  <canvas
                    ref={canvasRef}
                    aria-hidden="true"
                    data-testid="spike-raster-waveform"
                    data-bank-start={frame.channelStart}
                    data-bank-count={frame.channelCount}
                    data-frame-sequence={frame.sequence.toString()}
                    data-window-seconds={frame.windowSeconds}
                    data-waveform-mode="all"
                    data-waveforms-observed={waveformWindow.observedEventCount}
                    data-waveforms-rendered={waveformWindow.returnedEventCount}
                    data-waveforms-omitted={waveformWindow.observedEventCount - waveformWindow.returnedEventCount}
                    data-waveform-retention-samples={waveformWindow.retentionSamples.toString()}
                    data-waveform-coverage={waveformWindow.coverage}
                    data-source-sample-span={frame.sourceSampleStart === null || frame.sourceSampleEndExclusive === null
                      ? "unknown"
                      : (frame.sourceSampleEndExclusive - frame.sourceSampleStart).toString()}
                    data-amplitude-unit={frame.valueUnit}
                    data-unit-evidence-scope={frame.valueUnitScope}
                  />
                </div>
              </section>
              <section
                className="spike-cluster-panel"
                aria-label="Waveform clusters"
                data-testid="spike-waveform-clusters"
                data-sorting={frame.sorting}
              >
                <header><strong>WAVEFORM CLUSTERS</strong><span>NO SORTER LABELS</span></header>
                <div className="spike-cluster-grid">
                  {clusterGroups.map((group) => (
                    <article className="spike-cluster-card" key={group.id}>
                      <header><strong>{group.label}</strong><span>n={group.events.length}</span></header>
                      <svg viewBox="0 0 240 30" preserveAspectRatio="none" aria-hidden="true">
                        <line x1="0" y1="15" x2="240" y2="15" />
                        {group.events.map((event) => (
                          <polyline key={event.eventId} points={waveformPoints(event.values, gainValue)} />
                        ))}
                        {frame.selectedChannelWaveformStats ? (
                          <polyline
                            className="is-centroid"
                            points={waveformPoints(frame.selectedChannelWaveformStats.meanValues, gainValue)}
                          />
                        ) : null}
                      </svg>
                      <p>Events are displayed together until the sorter supplies cluster assignments.</p>
                    </article>
                  ))}
                </div>
              </section>
            </div>
          </section>
        ) : null}
      </div>

      <span className="sr-only" aria-live="polite">{announcement}</span>
      {channelMismatch ? <div className="spike-contract-error" role="alert">INPUT EVIDENCE MISMATCH</div> : null}
      {!invariantValid ? <div className="spike-contract-error" role="alert">COVERAGE FAULT</div> : null}
      {!waveformInvariantValid ? <div className="spike-contract-error" role="alert">WAVEFORM WINDOW FAULT</div> : null}
    </div>
  );
}
