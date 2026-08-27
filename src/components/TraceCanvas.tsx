import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import type {
  CSSProperties,
  KeyboardEvent as ReactKeyboardEvent,
  PointerEvent as ReactPointerEvent,
} from "react";
import type { Marker, TraceBlock } from "../core/types";

const MAX_VISIBLE_CHANNELS = 16;

interface CanvasSize {
  width: number;
  height: number;
  dpr: number;
}

interface TraceLayout {
  headerHeight: number;
  footerHeight: number;
  labelWidth: number;
  plotLeft: number;
  plotRight: number;
  plotTop: number;
  plotBottom: number;
  plotWidth: number;
  laneHeight: number;
}

export interface TraceTimeline {
  /** Host monotonic time at the left edge of the visible trace window. */
  startMonotonicMs: number;
  /** Host monotonic time at the right edge of the visible trace window. */
  endMonotonicMs: number;
}

export interface TraceCanvasProps {
  block: TraceBlock | null;
  /** Absolute, zero-based channel index. */
  selectedChannel: number | null;
  /** Receives an absolute, zero-based channel index. */
  onSelect: (channel: number) => void;
  /** Positive full-scale display value used for each lane. */
  gainValue: number;
  /** Evidence-aware unit label, for example `SYNTHETIC µV` or `ADC counts`. */
  amplitudeUnitLabel: string;
  /** Freezes this visualizer only; it never changes acquisition state. */
  paused?: boolean;
  markers?: readonly Marker[];
  /** Overrides the time range inferred from the TraceBlock. */
  timeline?: TraceTimeline;
  /** Pass an empty string to hide the synthetic-data badge. */
  syntheticLabel?: string;
  /** Pass an empty string to hide the display-only badge. */
  displayOnlyLabel?: string;
  pausedText?: string;
  emptyText?: string;
  ariaLabel?: string;
  className?: string;
  style?: CSSProperties;
  minHeight?: number;
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

function visibleChannelCount(block: TraceBlock | null): number {
  if (!block) return 0;
  return Math.min(
    MAX_VISIBLE_CHANNELS,
    Math.max(0, block.channelCount),
    block.valuesUv.length,
  );
}

function makeLayout(
  width: number,
  height: number,
  channelCount: number,
): TraceLayout {
  const headerHeight = height < 420 ? 30 : 36;
  const footerHeight = 24;
  const labelWidth = clamp(width * 0.105, 64, 92);
  const plotLeft = labelWidth;
  const plotRight = Math.max(plotLeft + 1, width - 12);
  const plotTop = headerHeight;
  const plotBottom = Math.max(plotTop + 1, height - footerHeight);

  return {
    headerHeight,
    footerHeight,
    labelWidth,
    plotLeft,
    plotRight,
    plotTop,
    plotBottom,
    plotWidth: Math.max(1, plotRight - plotLeft),
    laneHeight: Math.max(1, (plotBottom - plotTop) / Math.max(1, channelCount)),
  };
}

function roundedRect(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
  radius: number,
): void {
  const r = Math.min(radius, width / 2, height / 2);
  context.beginPath();
  context.moveTo(x + r, y);
  context.lineTo(x + width - r, y);
  context.quadraticCurveTo(x + width, y, x + width, y + r);
  context.lineTo(x + width, y + height - r);
  context.quadraticCurveTo(
    x + width,
    y + height,
    x + width - r,
    y + height,
  );
  context.lineTo(x + r, y + height);
  context.quadraticCurveTo(x, y + height, x, y + height - r);
  context.lineTo(x, y + r);
  context.quadraticCurveTo(x, y, x + r, y);
  context.closePath();
}

function drawBadge(
  context: CanvasRenderingContext2D,
  text: string,
  rightEdge: number,
  background: string,
  foreground: string,
): number {
  const horizontalPadding = 8;
  const width = Math.ceil(context.measureText(text).width) + horizontalPadding * 2;
  const height = 20;
  const x = rightEdge - width;
  const y = 8;

  roundedRect(context, x, y, width, height, 5);
  context.fillStyle = background;
  context.fill();
  context.fillStyle = foreground;
  context.fillText(text, x + horizontalPadding, y + 14);
  return x - 6;
}

function formatSeconds(seconds: number): string {
  if (seconds >= 10) return `${seconds.toFixed(0)} s`;
  if (seconds >= 1) return `${seconds.toFixed(1)} s`;
  return `${Math.round(seconds * 1_000)} ms`;
}

function drawWaveform(
  context: CanvasRenderingContext2D,
  samples: Float32Array,
  layout: TraceLayout,
  laneTop: number,
  laneHeight: number,
  gainUv: number,
  selected: boolean,
  encoding: TraceBlock["displayEncoding"] = "samples",
): void {
  if (samples.length === 0) return;

  const baseline = laneTop + laneHeight / 2;
  const amplitude = laneHeight * 0.38;
  const safeGain = Math.max(0.001, Math.abs(gainUv));
  const yFor = (sample: number): number => {
    const normalized = clamp(sample / safeGain, -1.24, 1.24);
    return baseline - normalized * amplitude;
  };

  context.save();
  context.beginPath();
  context.rect(
    layout.plotLeft,
    laneTop + 1,
    layout.plotWidth,
    Math.max(1, laneHeight - 2),
  );
  context.clip();
  context.strokeStyle = selected ? "#67e8f9" : "rgba(115, 190, 244, 0.82)";
  context.lineWidth = selected ? 1.55 : 1;
  context.lineJoin = "round";
  context.lineCap = "round";

  const pixelColumns = Math.max(1, Math.floor(layout.plotWidth));
  if (encoding === "min_max_pairs") {
    const pairCount = Math.floor(samples.length / 2);
    const columns = Math.min(pixelColumns, Math.max(1, pairCount));
    context.beginPath();
    for (let column = 0; column < columns; column += 1) {
      const startPair = Math.floor((column * pairCount) / columns);
      const endPair = Math.max(startPair + 1, Math.floor(((column + 1) * pairCount) / columns));
      let minimum = Number.POSITIVE_INFINITY;
      let maximum = Number.NEGATIVE_INFINITY;
      for (let pair = startPair; pair < endPair && pair < pairCount; pair += 1) {
        const low = samples[pair * 2];
        const high = samples[pair * 2 + 1];
        if (Number.isFinite(low)) minimum = Math.min(minimum, low);
        if (Number.isFinite(high)) maximum = Math.max(maximum, high);
      }
      if (!Number.isFinite(minimum) || !Number.isFinite(maximum)) continue;
      const x = layout.plotLeft + ((column + 0.5) / columns) * layout.plotWidth;
      context.moveTo(x, yFor(maximum));
      context.lineTo(x, yFor(minimum));
    }
    context.stroke();
  } else if (samples.length <= pixelColumns * 1.5) {
    context.beginPath();
    let started = false;
    for (let index = 0; index < samples.length; index += 1) {
      const sample = samples[index];
      if (!Number.isFinite(sample)) {
        started = false;
        continue;
      }
      const x =
        layout.plotLeft +
        (index / Math.max(1, samples.length - 1)) * layout.plotWidth;
      const y = yFor(sample);
      if (!started) {
        context.moveTo(x, y);
        started = true;
      } else {
        context.lineTo(x, y);
      }
    }
    context.stroke();
  } else {
    // Preserve brief spikes when many source points collapse into one CSS pixel.
    context.beginPath();
    for (let column = 0; column < pixelColumns; column += 1) {
      const start = Math.floor((column * samples.length) / pixelColumns);
      const end = Math.max(
        start + 1,
        Math.floor(((column + 1) * samples.length) / pixelColumns),
      );
      let minimum = Number.POSITIVE_INFINITY;
      let maximum = Number.NEGATIVE_INFINITY;
      for (let index = start; index < end && index < samples.length; index += 1) {
        const sample = samples[index];
        if (!Number.isFinite(sample)) continue;
        minimum = Math.min(minimum, sample);
        maximum = Math.max(maximum, sample);
      }
      if (!Number.isFinite(minimum) || !Number.isFinite(maximum)) continue;
      const x = layout.plotLeft + column + 0.5;
      context.moveTo(x, yFor(maximum));
      context.lineTo(x, yFor(minimum));
    }
    context.stroke();
  }

  context.restore();
}

function inferredTimeline(block: TraceBlock): TraceTimeline {
  const endMonotonicMs = block.generatedAtMonotonicMs;
  return {
    startMonotonicMs:
      endMonotonicMs - Math.max(0, block.sampleWindowSeconds) * 1_000,
    endMonotonicMs,
  };
}

export function TraceCanvas({
  block,
  selectedChannel,
  onSelect,
  gainValue,
  amplitudeUnitLabel,
  paused = false,
  markers = [],
  timeline,
  syntheticLabel = "SYNTHETIC SIGNAL",
  displayOnlyLabel = "DISPLAY ONLY",
  pausedText = "VIEW PAUSED",
  emptyText = "No display samples",
  ariaLabel = "Live neural traces",
  className,
  style,
  minHeight = 0,
}: TraceCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const lastLiveBlockRef = useRef<TraceBlock | null>(block);
  const [size, setSize] = useState<CanvasSize>({
    width: 0,
    height: 0,
    dpr: 1,
  });

  useEffect(() => {
    if (!paused) lastLiveBlockRef.current = block;
  }, [block, paused]);
  const displayedBlock = paused ? (lastLiveBlockRef.current ?? block) : block;
  const channelCount = visibleChannelCount(displayedBlock);

  useLayoutEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;

    const measure = () => {
      const bounds = container.getBoundingClientRect();
      const next: CanvasSize = {
        width: Math.max(0, bounds.width),
        height: Math.max(0, bounds.height),
        dpr: clamp(window.devicePixelRatio || 1, 1, 3),
      };
      setSize((current) => {
        if (
          Math.abs(current.width - next.width) < 0.25 &&
          Math.abs(current.height - next.height) < 0.25 &&
          current.dpr === next.dpr
        ) {
          return current;
        }
        return next;
      });
    };

    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(container);
    window.addEventListener("resize", measure);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, []);

  useLayoutEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || size.width <= 0 || size.height <= 0) return undefined;

    const frame = window.requestAnimationFrame(() => {
      const pixelWidth = Math.max(1, Math.round(size.width * size.dpr));
      const pixelHeight = Math.max(1, Math.round(size.height * size.dpr));
      if (canvas.width !== pixelWidth) canvas.width = pixelWidth;
      if (canvas.height !== pixelHeight) canvas.height = pixelHeight;

      const context = canvas.getContext("2d");
      if (!context) return;
      context.setTransform(size.dpr, 0, 0, size.dpr, 0, 0);
      context.clearRect(0, 0, size.width, size.height);
      context.fillStyle = "#09111a";
      context.fillRect(0, 0, size.width, size.height);

      const lanesToDraw = channelCount || MAX_VISIBLE_CHANNELS;
      const layout = makeLayout(size.width, size.height, lanesToDraw);

      context.font = "600 11px ui-sans-serif, system-ui, sans-serif";
      context.textBaseline = "alphabetic";
      context.fillStyle = "#9fb2c4";
      const header = displayedBlock
        ? `${displayedBlock.podId}  ·  CH ${String(
            displayedBlock.channelOffset + 1,
          ).padStart(3, "0")}–${String(
            displayedBlock.channelOffset + channelCount,
          ).padStart(3, "0")}  ·  ${formatSeconds(
            displayedBlock.sampleWindowSeconds,
          )}  ·  ±${Math.abs(gainValue).toLocaleString()} ${amplitudeUnitLabel}`
        : "Trace monitor";
      context.fillText(header, 12, 23);

      let badgeRight = size.width - 12;
      if (paused && pausedText) {
        badgeRight = drawBadge(
          context,
          pausedText,
          badgeRight,
          "rgba(249, 115, 22, 0.18)",
          "#fdba74",
        );
      }
      if (displayedBlock?.synthetic && syntheticLabel) {
        badgeRight = drawBadge(
          context,
          syntheticLabel,
          badgeRight,
          "rgba(168, 85, 247, 0.18)",
          "#d8b4fe",
        );
      }
      if (displayOnlyLabel) {
        drawBadge(
          context,
          displayOnlyLabel,
          badgeRight,
          "rgba(14, 165, 233, 0.16)",
          "#7dd3fc",
        );
      }

      context.fillStyle = "#0c1722";
      context.fillRect(
        0,
        layout.plotTop,
        size.width,
        layout.plotBottom - layout.plotTop,
      );

      // Ten time divisions and one baseline per channel keep the graph legible
      // without making the background compete with low-amplitude traces.
      context.lineWidth = 1;
      for (let division = 0; division <= 10; division += 1) {
        const x = layout.plotLeft + (division / 10) * layout.plotWidth;
        context.beginPath();
        context.strokeStyle =
          division === 0 || division === 10 ? "#293848" : "#172533";
        context.moveTo(x + 0.5, layout.plotTop);
        context.lineTo(x + 0.5, layout.plotBottom);
        context.stroke();
      }

      for (let row = 0; row < lanesToDraw; row += 1) {
        const laneTop = layout.plotTop + row * layout.laneHeight;
        const channel = displayedBlock
          ? displayedBlock.channelOffset + row
          : null;
        const selected = channel !== null && channel === selectedChannel;

        if (selected) {
          context.fillStyle = "rgba(34, 211, 238, 0.095)";
          context.fillRect(0, laneTop, size.width, layout.laneHeight);
          context.fillStyle = "#22d3ee";
          context.fillRect(0, laneTop, 3, layout.laneHeight);
        } else if (row % 2 === 1) {
          context.fillStyle = "rgba(255, 255, 255, 0.012)";
          context.fillRect(0, laneTop, size.width, layout.laneHeight);
        }

        context.beginPath();
        context.strokeStyle = "#1c2b39";
        context.moveTo(0, laneTop + layout.laneHeight + 0.5);
        context.lineTo(size.width, laneTop + layout.laneHeight + 0.5);
        context.stroke();

        context.beginPath();
        context.strokeStyle = selected ? "#28596a" : "#20313f";
        context.moveTo(layout.plotLeft, laneTop + layout.laneHeight / 2 + 0.5);
        context.lineTo(layout.plotRight, laneTop + layout.laneHeight / 2 + 0.5);
        context.stroke();

        if (displayedBlock && channel !== null && row < channelCount) {
          const fontSize = clamp(layout.laneHeight * 0.34, 9, 12);
          context.font = `${selected ? 700 : 600} ${fontSize}px ui-monospace, SFMono-Regular, Consolas, monospace`;
          context.fillStyle = selected ? "#e6fbff" : "#91a6b9";
          context.fillText(
            `CH ${String(channel + 1).padStart(3, "0")}`,
            10,
            laneTop + layout.laneHeight / 2 + fontSize * 0.36,
          );

          drawWaveform(
            context,
            displayedBlock.valuesUv[row],
            layout,
            laneTop,
            layout.laneHeight,
            gainValue,
            selected,
            displayedBlock.displayEncoding,
          );
        }
      }

      if (!displayedBlock || channelCount === 0) {
        context.font = "500 13px ui-sans-serif, system-ui, sans-serif";
        context.textAlign = "center";
        context.fillStyle = "#72869a";
        context.fillText(
          emptyText,
          layout.plotLeft + layout.plotWidth / 2,
          layout.plotTop + (layout.plotBottom - layout.plotTop) / 2,
        );
        context.textAlign = "left";
      }

      const activeTimeline = displayedBlock
        ? timeline && timeline.endMonotonicMs > timeline.startMonotonicMs
          ? timeline
          : inferredTimeline(displayedBlock)
        : null;

      if (activeTimeline) {
        const durationMs =
          activeTimeline.endMonotonicMs - activeTimeline.startMonotonicMs;
        const visibleMarkers = markers.filter(
          (marker) =>
            marker.hostMonotonicMs >= activeTimeline.startMonotonicMs &&
            marker.hostMonotonicMs <= activeTimeline.endMonotonicMs,
        );

        context.save();
        context.font = "600 10px ui-sans-serif, system-ui, sans-serif";
        for (let index = 0; index < visibleMarkers.length; index += 1) {
          const marker = visibleMarkers[index];
          const ratio =
            (marker.hostMonotonicMs - activeTimeline.startMonotonicMs) /
            durationMs;
          const x = layout.plotLeft + clamp(ratio, 0, 1) * layout.plotWidth;
          context.beginPath();
          context.strokeStyle = "rgba(251, 191, 36, 0.88)";
          context.lineWidth = 1;
          context.moveTo(x + 0.5, layout.plotTop);
          context.lineTo(x + 0.5, layout.plotBottom);
          context.stroke();

          context.fillStyle = "#fbbf24";
          context.beginPath();
          context.moveTo(x, layout.plotTop);
          context.lineTo(x - 4, layout.plotTop + 6);
          context.lineTo(x + 4, layout.plotTop + 6);
          context.closePath();
          context.fill();

          if (index < 6 && marker.label) {
            const label = marker.label.slice(0, 18);
            const textWidth = context.measureText(label).width;
            const labelX = clamp(x + 5, layout.plotLeft, layout.plotRight - textWidth);
            context.fillText(label, labelX, layout.plotTop + 14 + (index % 2) * 11);
          }
        }
        context.restore();

        context.font = "500 10px ui-monospace, SFMono-Regular, Consolas, monospace";
        context.fillStyle = "#71869a";
        context.fillText(
          `−${formatSeconds(durationMs / 1_000)}`,
          layout.plotLeft,
          size.height - 7,
        );
        context.textAlign = "center";
        context.fillText(
          `−${formatSeconds(durationMs / 2_000)}`,
          layout.plotLeft + layout.plotWidth / 2,
          size.height - 7,
        );
        context.textAlign = "right";
        context.fillText("0 s", layout.plotRight, size.height - 7);
        context.textAlign = "left";
      }
    });

    return () => window.cancelAnimationFrame(frame);
  }, [
    amplitudeUnitLabel,
    channelCount,
    displayOnlyLabel,
    displayedBlock,
    emptyText,
    gainValue,
    markers,
    paused,
    pausedText,
    selectedChannel,
    size,
    syntheticLabel,
    timeline,
  ]);

  const selectFromPointer = useCallback(
    (event: ReactPointerEvent<HTMLCanvasElement>) => {
      if (!displayedBlock || channelCount === 0) return;
      const canvas = event.currentTarget;
      canvas.focus();
      const bounds = canvas.getBoundingClientRect();
      if (bounds.width <= 0 || bounds.height <= 0) return;
      const layout = makeLayout(bounds.width, bounds.height, channelCount);
      const y = event.clientY - bounds.top;
      if (y < layout.plotTop || y >= layout.plotBottom) return;
      const row = Math.floor((y - layout.plotTop) / layout.laneHeight);
      if (row < 0 || row >= channelCount) return;
      onSelect(displayedBlock.channelOffset + row);
    },
    [channelCount, displayedBlock, onSelect],
  );

  const selectFromKeyboard = useCallback(
    (event: ReactKeyboardEvent<HTMLCanvasElement>) => {
      if (!displayedBlock || channelCount === 0) return;
      const first = displayedBlock.channelOffset;
      const last = first + channelCount - 1;
      const current = clamp(selectedChannel ?? first, first, last);
      let next: number | null = null;
      if (event.key === "ArrowUp") next = Math.max(first, current - 1);
      if (event.key === "ArrowDown") next = Math.min(last, current + 1);
      if (event.key === "Home") next = first;
      if (event.key === "End") next = last;
      if (next === null) return;
      event.preventDefault();
      onSelect(next);
    },
    [channelCount, displayedBlock, onSelect, selectedChannel],
  );

  const selectedDescription =
    selectedChannel === null
      ? "No channel selected"
      : `Channel ${selectedChannel + 1} selected`;
  const visibleDescription = displayedBlock && channelCount > 0
    ? `Channels ${displayedBlock.channelOffset + 1} through ${displayedBlock.channelOffset + channelCount} visible`
    : "No channel bank visible";

  return (
    <div
      ref={containerRef}
      className={["trace-canvas-shell", className].filter(Boolean).join(" ")}
      style={{
        width: "100%",
        height: "100%",
        minHeight,
        overflow: "hidden",
        borderRadius: 10,
        background: "#09111a",
        ...style,
      }}
      data-paused={paused ? "true" : "false"}
      data-synthetic={displayedBlock?.synthetic ? "true" : "false"}
      data-channel-start={displayedBlock?.channelOffset ?? "unknown"}
      data-channel-count={channelCount}
    >
      <canvas
        ref={canvasRef}
        role="application"
        aria-label={`${ariaLabel}. ${visibleDescription}. ${selectedDescription}`}
        tabIndex={0}
        onPointerDown={selectFromPointer}
        onKeyDown={selectFromKeyboard}
        style={{
          display: "block",
          width: "100%",
          height: "100%",
          cursor: channelCount > 0 ? "pointer" : "default",
          touchAction: "manipulation",
        }}
      />
    </div>
  );
}

export default TraceCanvas;
