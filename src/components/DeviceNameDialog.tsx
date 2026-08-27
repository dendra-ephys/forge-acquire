import { HardDrive, PencilLine, Save } from "lucide-react";
import { useEffect, useId, useState } from "react";
import type {
  DeviceIdentitySnapshot,
  DeviceKind,
  DeviceNamePersistence,
} from "../adapters/acquireAdapter";
import { useModalFocus } from "../core/useModalFocus";

export interface DeviceNameDialogProps {
  open: boolean;
  deviceKind: DeviceKind | null;
  identity: DeviceIdentitySnapshot | null;
  saving?: boolean;
  errorMessage?: string | null;
  onSave: (displayName: string) => void;
  onCancel: () => void;
}

const PERSISTENCE_COPY: Record<DeviceNamePersistence, { label: string; detail: string }> = {
  device_nonvolatile: {
    label: "DEVICE NVM",
    detail: "保存由设备确认后写入设备非易失存储，并随设备保留。",
  },
  mock_session: {
    label: "MOCK SESSION",
    detail: "仅 mock 会话，不代表跨电脑写入设备 NVM。",
  },
  host_local: {
    label: "HOST LOCAL",
    detail: "仅保存在当前主机，不改变设备非易失存储。",
  },
  none: {
    label: "NOT PERSISTED",
    detail: "当前 adapter 不提供名称持久化。",
  },
};

function displayCharacterCount(value: string): number {
  return Array.from(value).length;
}

function displayUtf8ByteCount(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function validateDisplayName(value: string, maxUtf8Bytes: number | null): string | null {
  const normalized = value.trim().normalize("NFC");
  const length = displayCharacterCount(normalized);
  if (length === 0) return "名称不能为空。";
  if (length > 48) return "名称不能超过 48 个字符。";
  if (maxUtf8Bytes !== null && displayUtf8ByteCount(normalized) > maxUtf8Bytes) {
    return `名称的 UTF-8 编码不能超过 ${maxUtf8Bytes} bytes。`;
  }
  if (/\p{Cc}/u.test(normalized)) return "名称不能包含控制字符。";
  return null;
}

export function DeviceNameDialog({
  open,
  deviceKind,
  identity,
  saving = false,
  errorMessage = null,
  onSave,
  onCancel,
}: DeviceNameDialogProps) {
  const [draftName, setDraftName] = useState("");
  const inputId = useId();
  const descriptionId = useId();
  const validationId = useId();
  const modalOpen = open && identity !== null && deviceKind !== null;
  const requestCancel = () => {
    if (!saving) onCancel();
  };
  const { backdropRef, dialogRef } = useModalFocus(modalOpen, requestCancel);

  useEffect(() => {
    if (!open || identity === null) return;
    setDraftName(identity.displayName);
  }, [identity?.deviceId, identity?.displayName, identity?.revision, open]);

  if (!modalOpen || identity === null || deviceKind === null) return null;

  const normalizedName = draftName.trim().normalize("NFC");
  const validationMessage = validateDisplayName(draftName, identity.maxNameUtf8Bytes);
  const persistence = PERSISTENCE_COPY[identity.persistence];
  const unchanged = normalizedName === identity.displayName.trim();
  const saveDisabled = saving || !identity.writable || identity.identityEvidenceHash === null
    || validationMessage !== null || unchanged;
  const kindLabel = deviceKind === "aggregator" ? "Aggregator" : "Pod";
  const statusLabel = String(identity.status).replaceAll("_", " ").toUpperCase();

  return (
    <div
      ref={backdropRef}
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) requestCancel();
      }}
    >
      <section
        ref={dialogRef}
        className="dialog device-name-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="device-name-dialog-title"
        aria-describedby={descriptionId}
        tabIndex={-1}
      >
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (!saveDisabled) onSave(normalizedName);
          }}
        >
          <header className="dialog-header">
            <div>
              <span className="instrument-kicker">DEVICE DISPLAY NAME</span>
              <h2 id="device-name-dialog-title">重命名 {kindLabel}</h2>
              <p id={descriptionId}>名称可以改变；不可变设备 ID 与连接路径不会改变。</p>
            </div>
            <button
              className="dialog-close"
              type="button"
              aria-label="关闭设备重命名"
              disabled={saving}
              data-modal-initial-focus={!identity.writable ? true : undefined}
              onClick={requestCancel}
            >
              ×
            </button>
          </header>

          <div className="dialog-body device-name-dialog__body">
            <div className="device-name-dialog__identity" aria-label="Immutable device identity">
              <HardDrive size={19} aria-hidden="true" />
              <div>
                <span>IMMUTABLE DEVICE ID</span>
                <code>{identity.deviceId}</code>
              </div>
              <div>
                <span>REVISION</span>
                <code>{identity.revision.toString()}</code>
              </div>
              <div>
                <span>STATUS</span>
                <strong>{statusLabel}</strong>
              </div>
            </div>

            <label className="device-name-field" htmlFor={inputId}>
              <span>设备显示名称</span>
              <span className="device-name-field__input">
                <PencilLine size={16} aria-hidden="true" />
                <input
                  id={inputId}
                  type="text"
                  value={draftName}
                  maxLength={48}
                  autoComplete="off"
                  spellCheck={false}
                  disabled={saving || !identity.writable}
                  aria-invalid={validationMessage !== null}
                  aria-describedby={validationMessage || errorMessage ? validationId : undefined}
                  data-modal-initial-focus={identity.writable ? true : undefined}
                  onChange={(event) => setDraftName(event.currentTarget.value)}
                />
                <b aria-label={`${displayCharacterCount(draftName.trim())} of 48 characters`}>
                  {displayCharacterCount(draftName.trim())}/48
                </b>
              </span>
            </label>

            <div className={`device-name-persistence device-name-persistence--${identity.persistence}`}>
              <div>
                <span>PERSISTENCE</span>
                <strong>{persistence.label}</strong>
              </div>
              <p>
                <span className="device-name-persistence__detail">{persistence.detail}</span>
                <span className="device-name-persistence__qualification">
                  {identity.crossHostPersistenceQualified
                    && identity.powerLossSafeWriteQualified
                    && identity.nameReadBackVerified
                    ? "跨电脑读取、掉电安全写入与回读收据均已证明。"
                    : "跨电脑读取或掉电安全写入尚未由硬件 qualification receipt 证明。"}
                </span>
              </p>
            </div>

            {!identity.writable || identity.identityEvidenceHash === null ? (
              <p className="device-name-dialog__blocked" role="note">
                此 identity 当前不可写：<code>{identity.identityEvidenceHash === null ? "NO_IDENTITY_RECEIPT" : identity.reasonCode}</code>
              </p>
            ) : null}

            {validationMessage || errorMessage ? (
              <p className="device-name-dialog__error" id={validationId} role="alert">
                {validationMessage ?? errorMessage}
              </p>
            ) : null}
          </div>

          <footer className="dialog-actions">
            <button
              className="instrument-button instrument-button--secondary"
              type="button"
              disabled={saving}
              onClick={requestCancel}
            >
              取消
            </button>
            <button
              className="instrument-button instrument-button--finalize device-name-dialog__save"
              type="submit"
              disabled={saveDisabled}
            >
              <Save size={16} aria-hidden="true" />
              {saving ? "正在保存…" : "保存名称"}
            </button>
          </footer>
        </form>
      </section>
    </div>
  );
}
