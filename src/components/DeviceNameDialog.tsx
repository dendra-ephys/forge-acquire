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
    detail: "The device confirms a write to nonvolatile storage, and the name remains with the device.",
  },
  mock_session: {
    label: "MOCK SESSION",
    detail: "Mock session only; this does not represent a cross-computer device NVM write.",
  },
  host_local: {
    label: "HOST LOCAL",
    detail: "Stored only on this host; device nonvolatile storage is unchanged.",
  },
  none: {
    label: "NOT PERSISTED",
    detail: "The current adapter does not provide name persistence.",
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
  if (length === 0) return "Name cannot be empty.";
  if (length > 48) return "Name cannot exceed 48 characters.";
  if (maxUtf8Bytes !== null && displayUtf8ByteCount(normalized) > maxUtf8Bytes) {
    return `The UTF-8 name cannot exceed ${maxUtf8Bytes} bytes.`;
  }
  if (/\p{Cc}/u.test(normalized)) return "Name cannot contain control characters.";
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
              <h2 id="device-name-dialog-title">Rename {kindLabel}</h2>
              <p id={descriptionId}>The display name can change. The immutable device ID and route cannot.</p>
            </div>
            <button
              className="dialog-close"
              type="button"
              aria-label="Close device rename"
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
              <span>Device display name</span>
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
                    ? "Cross-computer reads, power-safe writes, and readback receipts are qualified."
                    : "Cross-computer reads or power-safe writes are not yet proven by a hardware qualification receipt."}
                </span>
              </p>
            </div>

            {!identity.writable || identity.identityEvidenceHash === null ? (
              <p className="device-name-dialog__blocked" role="note">
                This identity is not writable: <code>{identity.identityEvidenceHash === null ? "NO_IDENTITY_RECEIPT" : identity.reasonCode}</code>
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
              Cancel
            </button>
            <button
              className="instrument-button instrument-button--finalize device-name-dialog__save"
              type="submit"
              disabled={saveDisabled}
            >
              <Save size={16} aria-hidden="true" />
              {saving ? "Saving…" : "Save name"}
            </button>
          </footer>
        </form>
      </section>
    </div>
  );
}
