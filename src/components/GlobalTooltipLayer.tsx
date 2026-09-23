import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

interface TooltipPosition {
  left: number;
  top: number;
  placement: "top" | "bottom";
}

function positionTooltip(anchor: HTMLElement, tooltip: HTMLElement): TooltipPosition {
  const anchorBox = anchor.getBoundingClientRect();
  const tooltipBox = tooltip.getBoundingClientRect();
  const gap = 7;
  const edge = 8;
  const left = Math.min(
    window.innerWidth - tooltipBox.width - edge,
    Math.max(edge, anchorBox.left + (anchorBox.width - tooltipBox.width) / 2),
  );
  const preferTop = anchor.closest(".signal-toolbar") !== null;
  const fitsAbove = anchorBox.top - gap - tooltipBox.height >= edge;
  const fitsBelow = anchorBox.bottom + gap + tooltipBox.height <= window.innerHeight - edge;
  const placeBelow = !preferTop || !fitsAbove;

  return {
    left,
    top: placeBelow && fitsBelow
      ? anchorBox.bottom + gap
      : Math.max(edge, anchorBox.top - tooltipBox.height - gap),
    placement: placeBelow && fitsBelow ? "bottom" : "top",
  };
}

export function GlobalTooltipLayer() {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const [position, setPosition] = useState<TooltipPosition | null>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const text = anchor?.dataset.tooltip?.trim() ?? "";

  useEffect(() => {
    const tooltipTarget = (eventTarget: EventTarget | null) => eventTarget instanceof Element
      ? eventTarget.closest<HTMLElement>("[data-tooltip]")
      : null;
    const show = (event: Event) => {
      const target = tooltipTarget(event.target);
      if (target?.dataset.tooltip?.trim()) setAnchor(target);
    };
    const hide = (event: Event) => {
      const target = tooltipTarget(event.target);
      const next = "relatedTarget" in event ? tooltipTarget(event.relatedTarget as EventTarget | null) : null;
      if (target && target !== next) setAnchor((current) => current === target ? null : current);
    };
    const dismiss = (event: KeyboardEvent) => {
      if (event.key === "Escape") setAnchor(null);
    };

    document.addEventListener("pointerover", show, true);
    document.addEventListener("pointerout", hide, true);
    document.addEventListener("focusin", show, true);
    document.addEventListener("focusout", hide, true);
    document.addEventListener("keydown", dismiss, true);
    return () => {
      document.removeEventListener("pointerover", show, true);
      document.removeEventListener("pointerout", hide, true);
      document.removeEventListener("focusin", show, true);
      document.removeEventListener("focusout", hide, true);
      document.removeEventListener("keydown", dismiss, true);
    };
  }, []);

  useLayoutEffect(() => {
    if (!anchor || !tooltipRef.current || !text || !anchor.isConnected) {
      setPosition(null);
      return undefined;
    }
    const update = () => {
      if (tooltipRef.current && anchor.isConnected) {
        setPosition(positionTooltip(anchor, tooltipRef.current));
      }
    };
    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [anchor, text]);

  if (!anchor || !text) return null;

  return createPortal(
    <div
      className="global-tooltip"
      ref={tooltipRef}
      role="tooltip"
      data-placement={position?.placement ?? "bottom"}
      style={{
        left: position?.left ?? 0,
        top: position?.top ?? 0,
        visibility: position ? "visible" : "hidden",
      }}
    >
      {text}
    </div>,
    document.body,
  );
}
