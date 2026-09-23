import { Info } from "lucide-react";
import { type ReactNode, useCallback, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";

interface InfoHintProps {
  label: string;
  children: ReactNode;
  align?: "start" | "end";
  icon?: ReactNode;
}

export function InfoHint({ label, children, align = "start", icon }: InfoHintProps) {
  const tooltipId = useId();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLSpanElement>(null);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState<{ left: number; top: number; placement: "top" | "bottom" } | null>(null);

  const updatePosition = useCallback(() => {
    const trigger = triggerRef.current;
    const popover = popoverRef.current;
    if (!trigger || !popover) return;
    const triggerBox = trigger.getBoundingClientRect();
    const popoverBox = popover.getBoundingClientRect();
    const edge = 8;
    const gap = 7;
    const alignedLeft = align === "end" ? triggerBox.right - popoverBox.width : triggerBox.left;
    const left = Math.min(window.innerWidth - popoverBox.width - edge, Math.max(edge, alignedLeft));
    const fitsBelow = triggerBox.bottom + gap + popoverBox.height <= window.innerHeight - edge;
    setPosition({
      left,
      top: fitsBelow ? triggerBox.bottom + gap : Math.max(edge, triggerBox.top - popoverBox.height - gap),
      placement: fitsBelow ? "bottom" : "top",
    });
  }, [align]);

  useEffect(() => {
    if (!open) {
      setPosition(null);
      return undefined;
    }
    updatePosition();
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition, true);
    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition, true);
    };
  }, [open, updatePosition]);

  return (
    <span className={`info-hint info-hint--${align}`} onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}>
      <button
        className="info-hint__trigger"
        ref={triggerRef}
        type="button"
        aria-label={label}
        aria-describedby={tooltipId}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onKeyDown={(event) => {
          if (event.key === "Escape") setOpen(false);
        }}
      >
        {icon ?? <Info size={14} aria-hidden="true" />}
      </button>
      <span className="visually-hidden" id={tooltipId}>
        {children}
      </span>
      {open ? createPortal(
        <span
          className="info-hint__popover info-hint__popover--portal"
          ref={popoverRef}
          role="tooltip"
          data-placement={position?.placement ?? "bottom"}
          style={{
            left: position?.left ?? 0,
            top: position?.top ?? 0,
            visibility: position ? "visible" : "hidden",
          }}
        >
          {children}
        </span>,
        document.body,
      ) : null}
    </span>
  );
}
