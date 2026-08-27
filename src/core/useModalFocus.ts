import { useEffect, useRef } from "react";

const FOCUSABLE = [
  "button:not([disabled])",
  "input:not([disabled])",
  "textarea:not([disabled])",
  "select:not([disabled])",
  "a[href]",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

interface SiblingState {
  element: HTMLElement;
  hadInert: boolean;
  ariaHidden: string | null;
}

/** Focus trap, Escape route, background inerting, and focus restoration. */
export function useModalFocus(open: boolean, onClose: () => void) {
  const backdropRef = useRef<HTMLDivElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const closeRef = useRef(onClose);

  useEffect(() => {
    closeRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open) return undefined;
    const previouslyFocused = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const backdrop = backdropRef.current;
    const dialog = dialogRef.current;
    if (!backdrop || !dialog) return undefined;

    const siblings: SiblingState[] = [];
    for (const sibling of Array.from(backdrop.parentElement?.children ?? [])) {
      if (!(sibling instanceof HTMLElement) || sibling === backdrop) continue;
      siblings.push({
        element: sibling,
        hadInert: sibling.hasAttribute("inert"),
        ariaHidden: sibling.getAttribute("aria-hidden"),
      });
      sibling.setAttribute("inert", "");
      sibling.setAttribute("aria-hidden", "true");
    }

    const initial = dialog.querySelector<HTMLElement>("[data-modal-initial-focus]")
      ?? dialog.querySelector<HTMLElement>(FOCUSABLE)
      ?? dialog;
    const focusTimer = window.setTimeout(() => initial.focus(), 0);

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE))
        .filter((element) => element.getClientRects().length > 0);
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable.at(-1)!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      window.clearTimeout(focusTimer);
      document.removeEventListener("keydown", handleKeyDown);
      for (const sibling of siblings) {
        if (!sibling.hadInert) sibling.element.removeAttribute("inert");
        if (sibling.ariaHidden === null) sibling.element.removeAttribute("aria-hidden");
        else sibling.element.setAttribute("aria-hidden", sibling.ariaHidden);
      }
      if (previouslyFocused?.isConnected) previouslyFocused.focus();
    };
  }, [open]);

  return { backdropRef, dialogRef };
}
