import { useEffect, useId, useState } from "react";

import type { Marker } from "../core/types";
import { useModalFocus } from "../core/useModalFocus";

const defaultPresetLabels = ["Behavior", "Stimulation", "Sync event", "Note"];

export interface MarkerDialogProps {
  open: boolean;
  draft: Marker | null;
  presetLabels?: string[];
  onSave: (marker: Marker) => void;
  onCancel: () => void;
}

function formatCapturedTime(draft: Marker): string {
  if (draft.hardwareGlobalTime !== null) {
    return `Hardware global time ${draft.hardwareGlobalTime.toLocaleString("en-US")}`;
  }
  return `Host monotonic time ${draft.hostMonotonicMs.toFixed(3)} ms`;
}

export function MarkerDialog({
  open,
  draft,
  presetLabels = defaultPresetLabels,
  onSave,
  onCancel,
}: MarkerDialogProps) {
  const labelId = useId();
  const noteId = useId();
  const [label, setLabel] = useState("");
  const [note, setNote] = useState("");

  useEffect(() => {
    if (!open || draft === null) return;
    setLabel(draft.label);
    setNote(draft.note);
  }, [draft, open]);

  const { backdropRef, dialogRef } = useModalFocus(open, onCancel);

  if (!open) return null;

  const saveMarker = () => {
    if (draft === null || label.trim().length === 0) return;
    onSave({
      ...draft,
      label: label.trim(),
      note: note.trim(),
    });
  };

  return (
    <div
      ref={backdropRef}
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <section
        ref={dialogRef}
        tabIndex={-1}
        className="dialog marker-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="marker-title"
        aria-describedby="marker-capture-note"
      >
        <header className="dialog-header">
          <div>
            <h2 id="marker-title">Add marker details</h2>
            <p>The timestamp is locked. Add only human-readable context here.</p>
          </div>
          <button
            className="dialog-close"
            type="button"
            aria-label="Close marker editor"
            onClick={onCancel}
          >
            ×
          </button>
        </header>

        <form
          onSubmit={(event) => {
            event.preventDefault();
            saveMarker();
          }}
        >
          <div className="dialog-body">
            <div id="marker-capture-note" className="captured-time">
              <span>
                Time captured before the dialog opened
                <br />
                Labels and notes do not move the event
              </span>
              {draft !== null && <strong>{formatCapturedTime(draft)}</strong>}
            </div>

            {draft !== null && draft.nearestSampleCounter !== null && (
              <div className="captured-time">
                <span>Latest sample count</span>
                <strong>{draft.nearestSampleCounter.toLocaleString("zh-CN")}</strong>
              </div>
            )}

            {draft === null ? (
              <p role="alert">
                No marker draft was captured. Close this dialog and choose Add marker again.
              </p>
            ) : (
              <>
                <div className="field">
                  <label>Quick labels</label>
                  <div className="preset-row">
                    {presetLabels.map((preset) => (
                      <button
                        className={`preset-button${label === preset ? " selected" : ""}`}
                        type="button"
                        key={preset}
                        aria-pressed={label === preset}
                        onClick={() => setLabel(preset)}
                      >
                        {preset}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="field">
                  <label htmlFor={labelId}>Label</label>
                  <input
                    id={labelId}
                    type="text"
                    value={label}
                    maxLength={80}
                    data-modal-initial-focus
                    placeholder="Choose a preset or enter a short label"
                    onChange={(event) => setLabel(event.target.value)}
                  />
                </div>

                <div className="field">
                  <label htmlFor={noteId}>Note (optional)</label>
                  <textarea
                    id={noteId}
                    value={note}
                    maxLength={500}
                    rows={4}
                    placeholder="What happened at this moment?"
                    onChange={(event) => setNote(event.target.value)}
                  />
                </div>
              </>
            )}
          </div>

          <footer className="dialog-actions">
            <button className="button button-secondary" type="button" onClick={onCancel}>
              Cancel
            </button>
            <button
              className="button button-primary"
              type="submit"
              disabled={draft === null || label.trim().length === 0}
            >
              Save marker
            </button>
          </footer>
        </form>
      </section>
    </div>
  );
}
