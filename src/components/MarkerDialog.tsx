import { useEffect, useId, useState } from "react";

import type { Marker } from "../core/types";
import { useModalFocus } from "../core/useModalFocus";

const defaultPresetLabels = ["行为", "刺激", "同步事件", "备注"];

export interface MarkerDialogProps {
  open: boolean;
  draft: Marker | null;
  presetLabels?: string[];
  onSave: (marker: Marker) => void;
  onCancel: () => void;
}

function formatCapturedTime(draft: Marker): string {
  if (draft.hardwareGlobalTime !== null) {
    return `硬件全局时间 ${draft.hardwareGlobalTime.toLocaleString("zh-CN")}`;
  }
  return `主机单调时间 ${draft.hostMonotonicMs.toFixed(3)} ms`;
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
            <h2 id="marker-title">补充标记内容</h2>
            <p>时间已经锁定；这里只补充人类可读信息。</p>
          </div>
          <button
            className="dialog-close"
            type="button"
            aria-label="关闭标记编辑"
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
                时间已在对话框打开前捕获
                <br />
                输入标签和备注不会移动事件位置
              </span>
              {draft !== null && <strong>{formatCapturedTime(draft)}</strong>}
            </div>

            {draft !== null && draft.nearestSampleCounter !== null && (
              <div className="captured-time">
                <span>最近样本计数</span>
                <strong>{draft.nearestSampleCounter.toLocaleString("zh-CN")}</strong>
              </div>
            )}

            {draft === null ? (
              <p role="alert">
                没有已捕获的 Marker 草稿，请关闭后重新点击“添加标记”。
              </p>
            ) : (
              <>
                <div className="field">
                  <label>快速标签</label>
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
                  <label htmlFor={labelId}>标签</label>
                  <input
                    id={labelId}
                    type="text"
                    value={label}
                    maxLength={80}
                    data-modal-initial-focus
                    placeholder="选择预设或输入简短标签"
                    onChange={(event) => setLabel(event.target.value)}
                  />
                </div>

                <div className="field">
                  <label htmlFor={noteId}>备注（可选）</label>
                  <textarea
                    id={noteId}
                    value={note}
                    maxLength={500}
                    rows={4}
                    placeholder="补充当时发生了什么"
                    onChange={(event) => setNote(event.target.value)}
                  />
                </div>
              </>
            )}
          </div>

          <footer className="dialog-actions">
            <button className="button button-secondary" type="button" onClick={onCancel}>
              取消
            </button>
            <button
              className="button button-primary"
              type="submit"
              disabled={draft === null || label.trim().length === 0}
            >
              保存标记
            </button>
          </footer>
        </form>
      </section>
    </div>
  );
}
