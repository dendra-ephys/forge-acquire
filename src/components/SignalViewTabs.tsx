import type { KeyboardEvent } from "react";
import type {
  CapabilityStatus,
  PreviewSignalKind,
} from "../adapters/acquireAdapter";

export interface SignalViewOption {
  id: PreviewSignalKind;
  label: string;
  detail: string;
  status: CapabilityStatus;
  scopeLabel: string;
}

export interface SignalViewTabsProps {
  options: readonly SignalViewOption[];
  selected: PreviewSignalKind;
  onSelect: (kind: PreviewSignalKind) => void;
}

export function SignalViewTabs({ options, selected, onSelect }: SignalViewTabsProps) {
  const focusAndSelect = (kind: PreviewSignalKind) => {
    onSelect(kind);
    requestAnimationFrame(() => document.getElementById(`signal-tab-${kind}`)?.focus());
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLButtonElement>, current: PreviewSignalKind) => {
    const enabled = options.filter((option) => option.status === "available");
    const currentIndex = enabled.findIndex((option) => option.id === current);
    if (currentIndex < 0) return;
    let nextIndex: number | null = null;
    if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % enabled.length;
    if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + enabled.length) % enabled.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = enabled.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    focusAndSelect(enabled[nextIndex].id);
  };

  return (
    <div className="signal-view-tabs" role="tablist" aria-label="信号预览类型">
      {options.map((option) => {
        const active = selected === option.id;
        const available = option.status === "available";
        return (
          <button
            id={`signal-tab-${option.id}`}
            className={active ? "is-active" : ""}
            key={option.id}
            type="button"
            role="tab"
            aria-selected={active}
            aria-controls="signal-preview-panel"
            aria-disabled={!available}
            tabIndex={active ? 0 : -1}
            disabled={!available}
            onClick={() => onSelect(option.id)}
            onKeyDown={(event) => handleKeyDown(event, option.id)}
          >
            <strong>{option.label}</strong>
            <span>{option.detail}</span>
            <em>{available ? option.scopeLabel : option.status.replaceAll("_", " ")}</em>
          </button>
        );
      })}
    </div>
  );
}
