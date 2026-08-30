import { ChevronLeft, ChevronRight } from "lucide-react";
import {
  useCallback,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ChangeEvent,
  type PointerEvent as ReactPointerEvent,
} from "react";
import type { SpikePreviewFrame } from "../adapters/acquireAdapter";

const CHANNEL_BANK_SIZE = 8;

export type SpikeWaveformDisplayMode = "all" | "statistics" | "latest";

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

export function waveformEventsForMode(
  frame: SpikePreviewFrame,
  mode: SpikeWaveformDisplayMode,
) {
  const events = frame.selectedChannelWaveforms.events;
  if (mode === "latest") return events.length === 0 ? [] : [events[events.length - 1]];
  return mode === "all" ? events : [];
}

export interface SpikeScopeCanvasProps {
  frame: SpikePreviewFrame;
  expectedChannelCount: number | null;
  selectedChannel: number;
  onSelect: (channel: number) => void;
  gainValue: number;
  paused: boolean;
}

interface CanvasSize {
  width: number;
  height: number;
  dpr: number;
}

function clamp(value: number, minimum: number, maximum: number) {
  return Math.max(minimum, Math.min(maximum, value));
}

function channelLabel(channel: number): string {
  return `CH ${String(channel + 1).padStart(3, "0")}`;
}

function bankLabel(start: number, count: number): string {
  return `${channelLabel(start)}–${channelLabel(start + Math.max(0, count - 1)).replace("CH ", "")}`;
}

export function previewUnitLabel(frame: Pick<
  SpikePreviewFrame,
  "valueUnit" | "valueUnitScope"
>): string {
  if (frame.valueUnit === "adc_count") return "ADC counts";
  return frame.valueUnitScope === "mock" ? "SYNTHETIC µV" : "µV";
}

function activityStyle(value: number, maximum: number): CSSProperties {
  const ratio = maximum <= 0 ? 0 : clamp(value / maximum, 0, 1);
  return {
    "--spike-activity-height": `${22 + ratio * 78}%`,
    "--spike-activity-opacity": (0.26 + ratio * 0.74).toFixed(3),
  } as CSSProperties;
}

export function SpikeScopeCanvas({
  frame,
  expectedChannelCount,
  selectedChannel,
  onSelect,
  gainValue,
  paused,
}: SpikeScopeCanvasProps) {
  const shellRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const summaryId = useId();
  const [size, setSize] = useState<CanvasSize>({ width: 0, height: 0, dpr: 1 });
  const [announcement, setAnnouncement] = useState("");
  const [waveformMode, setWaveformMode] = useState<SpikeWaveformDisplayMode>("all");
  const bankStart = frame.channelStart;
  const bankCount = frame.channelCount;
  const bankEnd = bankStart + Math.max(0, bankCount - 1);
  const bankIndex = Math.floor(bankStart / CHANNEL_BANK_SIZE);
  const bankTotal = Math.max(1, Math.ceil(frame.inputChannelCount / CHANNEL_BANK_SIZE));
  const unitLabel = previewUnitLabel(frame);
  const channelMismatch = expectedChannelCount !== null
    && expectedChannelCount !== frame.inputChannelCount;
  const maxActivity = Math.max(1, ...frame.channelActivity.map((item) => item.observedEventCount));
  const activeChannelCount = frame.channelActivity.filter((item) => item.observedEventCount > 0).length;
  const waveformWindow = frame.selectedChannelWaveforms;
  const waveformInvariantValid = waveformWindowInvariant(frame);
  const waveformEvents = waveformEventsForMode(frame, waveformMode);
  const waveformTraceCount = waveformMode === "statistics"
    ? frame.selectedChannelWaveformStats === null ? 0 : 1
    : waveformEvents.length;
  const bankOptions = useMemo(
    () => Array.from({ length: bankTotal }, (_, index) => {
      const start = index * CHANNEL_BANK_SIZE;
      return { start, count: Math.min(CHANNEL_BANK_SIZE, frame.inputChannelCount - start) };
    }),
    [bankTotal, frame.inputChannelCount],
  );

  const selectChannel = useCallback((channel: number, announce = true) => {
    const next = clamp(channel, 0, frame.inputChannelCount - 1);
    onSelect(next);
    if (announce) setAnnouncement(`${channelLabel(next)} selected`);
  }, [frame.inputChannelCount, onSelect]);

  const selectBank = useCallback((start: number) => {
    const nextStart = clamp(
      Math.floor(start / CHANNEL_BANK_SIZE) * CHANNEL_BANK_SIZE,
      0,
      Math.max(0, (bankTotal - 1) * CHANNEL_BANK_SIZE),
    );
    selectChannel(nextStart, false);
    const count = Math.min(CHANNEL_BANK_SIZE, frame.inputChannelCount - nextStart);
    setAnnouncement(`${bankLabel(nextStart, count)} selected`);
  }, [bankTotal, frame.inputChannelCount, selectChannel]);

  useLayoutEffect(() => {
    const shell = shellRef.current;
    if (!shell) return undefined;
    const measure = () => {
      const bounds = shell.getBoundingClientRect();
      setSize({
        width: Math.max(0, bounds.width),
        height: Math.max(0, bounds.height),
        dpr: clamp(window.devicePixelRatio || 1, 1, 3),
      });
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(shell);
    return () => observer.disconnect();
  }, []);

  useLayoutEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || size.width <= 0 || size.height <= 0) return undefined;
    const render = window.requestAnimationFrame(() => {
      canvas.width = Math.max(1, Math.round(size.width * size.dpr));
      canvas.height = Math.max(1, Math.round(size.height * size.dpr));
      const context = canvas.getContext("2d");
      if (!context) return;
      context.setTransform(size.dpr, 0, 0, size.dpr, 0, 0);
      context.fillStyle = "#09111a";
      context.fillRect(0, 0, size.width, size.height);

      const top = 25;
      const bottom = Math.max(top + 20, size.height - 20);
      const divider = clamp(size.width * 0.52, 250, Math.max(250, size.width - 180));
      const rasterLeft = 54;
      const rasterRight = divider - 9;
      const rasterWidth = Math.max(20, rasterRight - rasterLeft);
      const waveformLeft = divider + 11;
      const waveformRight = Math.max(waveformLeft + 20, size.width - 12);
      const waveformWidth = waveformRight - waveformLeft;

      context.font = "700 10px ui-monospace, Consolas, monospace";
      context.fillStyle = "#9eb3bd";
      context.fillText(`BANK RASTER · ${bankLabel(bankStart, bankCount)}`, 8, 16);
      context.fillText(`${channelLabel(selectedChannel)} WAVEFORMS · ${waveformMode.toUpperCase()}`, waveformLeft, 16);
      context.textAlign = "right";
      context.fillStyle = paused ? "#fdba74" : "#72cfdf";
      context.fillText(paused ? "DISPLAY PAUSED" : unitLabel, size.width - 10, 16);
      context.textAlign = "left";

      context.fillStyle = "#0c1722";
      context.fillRect(rasterLeft, top, rasterWidth, bottom - top);
      const rowHeight = (bottom - top) / Math.max(1, bankCount);
      for (let local = 0; local < bankCount; local += 1) {
        const channel = bankStart + local;
        const rowTop = top + local * rowHeight;
        if (channel === selectedChannel) {
          context.fillStyle = "rgba(34, 211, 238, 0.11)";
          context.fillRect(0, rowTop, divider, rowHeight);
          context.fillStyle = "#22d3ee";
          context.fillRect(0, rowTop, 3, rowHeight);
        }
        context.strokeStyle = "#20313f";
        context.beginPath();
        context.moveTo(rasterLeft, rowTop + rowHeight);
        context.lineTo(rasterRight, rowTop + rowHeight);
        context.stroke();
        context.font = "700 9px ui-monospace, Consolas, monospace";
        context.fillStyle = channel === selectedChannel ? "#e6fbff" : "#91a6b9";
        context.fillText(`CH${String(channel + 1).padStart(3, "0")}`, 8, rowTop + rowHeight * 0.68);
      }

      for (const event of frame.raster) {
        if (event.channel < bankStart || event.channel > bankEnd) continue;
        const local = event.channel - bankStart;
        const x = rasterLeft
          + clamp(event.eventOffsetMs / (frame.windowSeconds * 1_000), 0, 1) * rasterWidth;
        const rowTop = top + local * rowHeight;
        context.strokeStyle = event.channel === selectedChannel ? "#69dbe9" : "#8297a1";
        context.lineWidth = event.channel === selectedChannel ? 1.6 : 1;
        context.beginPath();
        context.moveTo(x, rowTop + rowHeight * 0.22);
        context.lineTo(x, rowTop + rowHeight * 0.78);
        context.stroke();
      }

      context.strokeStyle = "#2a3b44";
      context.beginPath();
      context.moveTo(divider, 4);
      context.lineTo(divider, size.height - 4);
      context.stroke();
      context.fillStyle = "#0c1722";
      context.fillRect(waveformLeft, top, waveformWidth, bottom - top);
      const waveformStats = frame.selectedChannelWaveformStats;
      if (waveformWindow.events.length > 0 && waveformInvariantValid) {
        const centerY = top + (bottom - top) * 0.46;
        const halfHeight = (bottom - top) * 0.45;
        const yFor = (value: number) => centerY
          - (value / Math.max(1, Math.abs(gainValue))) * halfHeight;
        context.strokeStyle = "#29404d";
        context.beginPath();
        context.moveTo(waveformLeft, yFor(0));
        context.lineTo(waveformRight, yFor(0));
        context.stroke();

        const threshold = waveformStats?.thresholdValue;
        if (threshold != null) {
          context.save();
          context.setLineDash([5, 4]);
          context.strokeStyle = "#d9a647";
          context.beginPath();
          context.moveTo(waveformLeft, yFor(threshold));
          context.lineTo(waveformRight, yFor(threshold));
          context.stroke();
          context.restore();
        }

        if (waveformMode === "statistics" && waveformStats) {
          const pointCount = Math.min(
            waveformStats.meanValues.length,
            waveformStats.p10Values.length,
            waveformStats.p90Values.length,
          );
          const xFor = (index: number) => waveformLeft
            + (index / Math.max(1, pointCount - 1)) * waveformWidth;
          context.beginPath();
          for (let index = 0; index < pointCount; index += 1) {
            const x = xFor(index);
            const y = yFor(waveformStats.p90Values[index]);
            if (index === 0) context.moveTo(x, y);
            else context.lineTo(x, y);
          }
          for (let index = pointCount - 1; index >= 0; index -= 1) {
            context.lineTo(xFor(index), yFor(waveformStats.p10Values[index]));
          }
          context.closePath();
          context.fillStyle = "rgba(74, 173, 203, 0.18)";
          context.fill();

          context.strokeStyle = "#68d6e6";
          context.lineWidth = 1.7;
          context.beginPath();
          waveformStats.meanValues.forEach((value, index) => {
            const x = xFor(index);
            const y = yFor(value);
            if (index === 0) context.moveTo(x, y);
            else context.lineTo(x, y);
          });
          context.stroke();
        } else {
          const endSample = frame.sourceSampleEndExclusive;
          waveformEvents.forEach((event, eventIndex) => {
            const ageRatio = endSample === null
              ? eventIndex / Math.max(1, waveformEvents.length - 1)
              : clamp(Number(endSample - event.centerSample) / Number(waveformWindow.retentionSamples), 0, 1);
            const newest = eventIndex === waveformEvents.length - 1;
            const opacity = waveformMode === "latest"
              ? 0.96
              : clamp(0.22 + (1 - ageRatio) * 0.58 + (newest ? 0.14 : 0), 0.22, 0.96);
            context.strokeStyle = `rgba(104, 214, 230, ${opacity.toFixed(3)})`;
            context.lineWidth = newest ? 1.9 : 1.05;
            context.beginPath();
            event.values.forEach((value, index) => {
              const x = waveformLeft
                + (index / Math.max(1, event.values.length - 1)) * waveformWidth;
              const y = yFor(value);
              if (index === 0) context.moveTo(x, y);
              else context.lineTo(x, y);
            });
            context.stroke();
          });
        }

        context.font = "600 9px ui-monospace, Consolas, monospace";
        if (threshold != null) {
          context.fillStyle = "#d9a647";
          context.fillText(`THR ${threshold.toFixed(0)}`, waveformLeft + 5, yFor(threshold) - 4);
        } else {
          context.fillStyle = "#8fa6b2";
          context.fillText("SYNTHETIC EVENT ORACLE · NO DETECTOR THRESHOLD", waveformLeft + 5, top + 12);
        }
        context.fillStyle = "#8fa6b2";
        context.fillText(
          waveformMode === "statistics"
            ? `STATISTICS n=${waveformWindow.returnedEventCount} · MEAN / P10–P90`
            : waveformMode === "latest"
              ? `LATEST 1 / ${waveformWindow.returnedEventCount} · UNSORTED`
              : `ALL ${waveformWindow.returnedEventCount} · TTL ${frame.windowSeconds.toFixed(1)} s · UNSORTED`,
          waveformLeft + 5,
          bottom - 5,
        );
      } else {
        context.font = "600 10px ui-monospace, Consolas, monospace";
        context.fillStyle = waveformInvariantValid ? "#7f929c" : "#f87171";
        context.fillText(
          waveformInvariantValid ? "NO EVENTS IN RETENTION WINDOW" : "WAVEFORM WINDOW COVERAGE FAULT",
          waveformLeft + 8,
          top + 24,
        );
      }

      context.font = "500 9px ui-monospace, Consolas, monospace";
      context.fillStyle = "#71869a";
      context.fillText(`−${frame.windowSeconds.toFixed(1)} s`, rasterLeft, size.height - 6);
      context.textAlign = "right";
      context.fillText("0 s", rasterRight, size.height - 6);
      context.textAlign = "left";
    });
    return () => window.cancelAnimationFrame(render);
  }, [
    bankCount,
    bankEnd,
    bankStart,
    frame,
    gainValue,
    paused,
    selectedChannel,
    size,
    unitLabel,
    waveformEvents,
    waveformInvariantValid,
    waveformMode,
    waveformWindow,
  ]);

  const selectFromRaster = useCallback((event: ReactPointerEvent<HTMLCanvasElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    const divider = clamp(bounds.width * 0.52, 250, Math.max(250, bounds.width - 180));
    const top = 25;
    const bottom = Math.max(top + 20, bounds.height - 20);
    const y = event.clientY - bounds.top;
    if (event.clientX - bounds.left >= divider || y < top || y >= bottom) return;
    const row = Math.floor((y - top) / ((bottom - top) / Math.max(1, bankCount)));
    selectChannel(bankStart + clamp(row, 0, bankCount - 1));
  }, [bankCount, bankStart, selectChannel]);

  const accounting = frame.accounting;
  const invariantValid = accounting.observedEventCount
    === accounting.rasterCandidateEventCount
    && accounting.rasterCandidateEventCount
      === accounting.sampledOutEventCount + accounting.returnedRasterEventCount
    && frame.coverage.source === "complete"
    && frame.coverage.analysis === "complete"
    && frame.coverage.sourceGapRanges.length === 0
    && frame.coverage.analysisGapRanges.length === 0;

  return (
    <div className="spike-preview-panel" data-paused={paused ? "true" : "false"}>
      <div
        id={summaryId}
        className={`spike-event-summary${invariantValid ? "" : " is-invalid"}`}
        data-testid="spike-event-summary"
        data-pod-events={frame.podObservedEventCount}
        data-bank-events={accounting.observedEventCount}
        data-rendered={accounting.returnedRasterEventCount}
        data-preview-omitted={accounting.sampledOutEventCount}
        data-source-coverage={frame.coverage.source}
        data-analysis-coverage={frame.coverage.analysis}
        data-invariant-valid={invariantValid ? "true" : "false"}
      >
        {[
          ["POD EVENTS", frame.podObservedEventCount, "合成 oracle 在全 Pod 所有通道、当前时间窗内的事件总数"],
          ["BANK EVENTS", accounting.observedEventCount, "POD EVENTS 中属于当前 8 通道 bank 的子集"],
          ["RASTER DRAWN", accounting.returnedRasterEventCount, "在 WebView 有界 raster 预算内实际绘制的事件"],
          ["DISPLAY OMITTED", accounting.sampledOutEventCount, "只从画面省略；源与分析覆盖必须仍为 COMPLETE"],
          ["SOURCE COVERAGE", frame.coverage.source.toUpperCase(), "当前 source sample range 是否完整；不能用事件丢失数替代"],
          ["DETECTOR COVERAGE", frame.coverage.analysis.toUpperCase(), "同一 source sample range 是否被 spike detector 完整处理；缺口必须给出 sample range 并进入故障"],
        ].map(([label, value, title]) => (
          <div key={String(label)} title={String(title)}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>

      <div className="spike-overview-block">
        <div className="spike-overview-label">
          <span>ALL {frame.inputChannelCount} CHANNELS · FULL POD ACTIVITY</span>
          <strong>{activeChannelCount} active · {unitLabel}</strong>
        </div>
        <div
          className="spike-activity-overview"
          role="group"
          aria-label={`全 Pod ${frame.inputChannelCount} 通道活动选择器。点击通道可切换 bank、raster 与 waveform。当前 bank ${bankLabel(bankStart, bankCount)}。`}
          data-testid="spike-overview"
          data-total-channels={frame.inputChannelCount}
          data-active-channels={activeChannelCount}
        >
          {frame.channelActivity.map((activity) => (
            <button
              type="button"
              key={activity.channel}
              className={[
                "spike-activity-cell",
                activity.channel >= bankStart && activity.channel <= bankEnd ? "is-bank" : "",
                activity.channel === selectedChannel ? "is-selected" : "",
                activity.observedEventCount === 0 ? "is-silent" : "",
              ].filter(Boolean).join(" ")}
              style={activityStyle(activity.observedEventCount, maxActivity)}
              aria-label={`${channelLabel(activity.channel)} · ${activity.observedEventCount} 个合成 oracle 事件 · 点击查看该通道`}
              aria-pressed={activity.channel === selectedChannel}
              tabIndex={activity.channel === selectedChannel ? 0 : -1}
              data-testid="spike-activity-channel"
              data-channel={activity.channel}
              title={`${channelLabel(activity.channel)} · ${activity.observedEventCount} oracle events · ${activity.rateHz.toFixed(1)} Hz · 点击切换显示通道`}
              onClick={() => selectChannel(activity.channel)}
            />
          ))}
        </div>
      </div>

      <div className="spike-navigation" role="toolbar" aria-label="Spike channel navigation">
        <div className="spike-navigation__group">
          <button
            type="button"
            aria-label="Previous channel bank"
            disabled={bankIndex <= 0}
            onClick={() => selectBank(bankStart - CHANNEL_BANK_SIZE)}
          >
            <ChevronLeft size={16} aria-hidden="true" />
          </button>
          <label>
            <span>CHANNEL BANK</span>
            <select
              aria-label="Channel bank"
              value={bankStart}
              onChange={(event: ChangeEvent<HTMLSelectElement>) => selectBank(Number(event.target.value))}
            >
              {bankOptions.map((bank) => (
                <option key={bank.start} value={bank.start}>{bankLabel(bank.start, bank.count)}</option>
              ))}
            </select>
          </label>
          <button
            type="button"
            aria-label="Next channel bank"
            disabled={bankIndex >= bankTotal - 1}
            onClick={() => selectBank(bankStart + CHANNEL_BANK_SIZE)}
          >
            <ChevronRight size={16} aria-hidden="true" />
          </button>
        </div>
        <div className="spike-navigation__group">
          <button
            type="button"
            aria-label="Previous channel"
            disabled={selectedChannel <= 0}
            onClick={() => selectChannel(selectedChannel - 1)}
          >
            <ChevronLeft size={16} aria-hidden="true" />
          </button>
          <label>
            <span>WAVEFORM CHANNEL</span>
            <select
              aria-label="Waveform channel"
              value={selectedChannel}
              onChange={(event: ChangeEvent<HTMLSelectElement>) => selectChannel(Number(event.target.value))}
            >
              {Array.from({ length: bankCount }, (_, local) => bankStart + local).map((channel) => (
                <option key={channel} value={channel}>{channelLabel(channel)}</option>
              ))}
            </select>
          </label>
          <button
            type="button"
            aria-label="Next channel"
            disabled={selectedChannel >= frame.inputChannelCount - 1}
            onClick={() => selectChannel(selectedChannel + 1)}
          >
            <ChevronRight size={16} aria-hidden="true" />
          </button>
        </div>
        <div
          className="spike-waveform-modes"
          role="radiogroup"
          aria-label="Waveform 显示模式"
        >
          {([
            ["all", "全部"],
            ["statistics", "统计"],
            ["latest", "最新"],
          ] as const).map(([mode, label]) => (
            <button
              key={mode}
              type="button"
              role="radio"
              aria-checked={waveformMode === mode}
              className={waveformMode === mode ? "is-active" : ""}
              onClick={() => {
                setWaveformMode(mode);
                setAnnouncement(`Waveform 显示模式：${label}`);
              }}
            >
              {label}
            </button>
          ))}
        </div>
        <span className="sr-only" aria-live="polite">{announcement}</span>
      </div>

      {channelMismatch ? (
        <div className="spike-contract-error" role="alert">
          INPUT EVIDENCE MISMATCH · Pod snapshot {expectedChannelCount} ch / preview frame {frame.inputChannelCount} ch
        </div>
      ) : null}
      {!invariantValid ? (
        <div className="spike-contract-error" role="alert">
          COVERAGE FAULT · source {frame.coverage.source} / detector {frame.coverage.analysis}
        </div>
      ) : null}
      {!waveformInvariantValid ? (
        <div className="spike-contract-error" role="alert">
          WAVEFORM WINDOW FAULT · {waveformWindow.reasonCode ?? "COUNT / ID / TTL INVARIANT"} ·
          observed {waveformWindow.observedEventCount} / returned {waveformWindow.returnedEventCount}
        </div>
      ) : null}

      <div ref={shellRef} className="spike-canvas-shell">
        <canvas
          ref={canvasRef}
          role="img"
          aria-label={`${channelLabel(selectedChannel)} ${waveformMode}; ${waveformWindow.returnedEventCount} waveforms; ${frame.windowSeconds}s TTL; ${unitLabel}; no raw stream.`}
          aria-describedby={summaryId}
          onPointerDown={selectFromRaster}
          data-testid="spike-raster-waveform"
          data-bank-start={bankStart}
          data-bank-count={bankCount}
          data-frame-sequence={frame.sequence.toString()}
          data-window-seconds={frame.windowSeconds}
          data-waveform-mode={waveformMode}
          data-waveforms-observed={waveformWindow.observedEventCount}
          data-waveforms-rendered={waveformTraceCount}
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
    </div>
  );
}
