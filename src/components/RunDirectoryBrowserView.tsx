import {
  ArrowUp,
  CornerDownRight,
  Folder,
  HardDrive,
  RefreshCw,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import type { RunDirectoryListing } from "../adapters/runDirectoryBrowser";
import "./RunDirectoryBrowserView.css";

interface RunDirectoryBrowserViewProps {
  initialDirectory: string;
  listing: RunDirectoryListing | null;
  loading: boolean;
  errorMessage: string | null;
  onBrowse: (directory: string) => void;
  onUseCurrent: (directory: string) => void;
  onCancel: () => void;
}

export function RunDirectoryBrowserView({
  initialDirectory,
  listing,
  loading,
  errorMessage,
  onBrowse,
  onUseCurrent,
  onCancel,
}: RunDirectoryBrowserViewProps) {
  const [draftPath, setDraftPath] = useState(listing?.currentDirectory ?? initialDirectory);
  const [activeIndex, setActiveIndex] = useState(0);
  const pathInputRef = useRef<HTMLInputElement>(null);
  const entryRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const directories = listing?.directories ?? [];
  const state = errorMessage !== null
    ? "error"
    : loading
      ? "loading"
      : directories.length === 0
        ? "empty"
        : "ready";

  useEffect(() => {
    pathInputRef.current?.focus();
    pathInputRef.current?.select();
  }, []);

  useEffect(() => {
    if (listing === null) return;
    setDraftPath(listing.currentDirectory);
    setActiveIndex(0);
  }, [listing]);

  const currentPathDescription = useMemo(() => {
    if (errorMessage !== null && listing !== null) {
      return `The requested folder was not opened. Current folder: ${listing.currentDirectory}`;
    }
    return listing?.currentDirectory ?? "No folder loaded";
  }, [errorMessage, listing]);

  const focusEntry = (index: number) => {
    const next = Math.min(Math.max(index, 0), directories.length - 1);
    if (next < 0) return;
    setActiveIndex(next);
    window.requestAnimationFrame(() => entryRefs.current[next]?.focus());
  };

  const handleEntryKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      focusEntry(index + 1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      focusEntry(index - 1);
    } else if (event.key === "Home") {
      event.preventDefault();
      focusEntry(0);
    } else if (event.key === "End") {
      event.preventDefault();
      focusEntry(directories.length - 1);
    }
  };

  return (
    <>
      <div
        className="run-directory-browser"
        data-testid="run-directory-browser"
        data-picker-state={state}
      >
        <section className="run-directory-current" aria-label="Current folder">
          <div>
            <span>CURRENT FOLDER</span>
            <strong
              data-testid="run-directory-current-path"
              data-current-path={listing?.currentDirectory ?? ""}
            >{currentPathDescription}</strong>
          </div>
          <button
            className="instrument-button instrument-button--secondary run-directory-parent"
            data-testid="run-directory-parent"
            type="button"
            disabled={loading || listing?.parentDirectory == null}
            title={listing?.parentDirectory == null ? "At the filesystem root" : "Open parent folder"}
            onClick={() => {
              if (listing?.parentDirectory) onBrowse(listing.parentDirectory);
            }}
          >
            <ArrowUp size={17} aria-hidden="true" />
            Parent
          </button>
        </section>

        {listing && listing.roots.length > 0 ? (
          <nav className="run-directory-roots" aria-label="Local drives">
            <span>Drives</span>
            <div>
              {listing.roots.map((root) => (
                <button
                  className={root.path === listing.currentDirectory ? "is-current" : ""}
                  type="button"
                  key={root.path}
                  disabled={loading}
                  aria-label={`Open drive ${root.label}`}
                  onClick={() => onBrowse(root.path)}
                >
                  <HardDrive size={15} aria-hidden="true" />
                  {root.label}
                </button>
              ))}
            </div>
          </nav>
        ) : null}

        <form
          className="run-directory-jump"
          onSubmit={(event) => {
            event.preventDefault();
            if (!loading && draftPath.trim().length > 0) onBrowse(draftPath.trim());
          }}
        >
          <label htmlFor="run-directory-path">Folder path</label>
          <div>
            <input
              ref={pathInputRef}
              id="run-directory-path"
              type="text"
              value={draftPath}
              disabled={loading}
              spellCheck={false}
              aria-invalid={errorMessage !== null}
              aria-describedby={errorMessage ? "run-directory-error" : undefined}
              onChange={(event) => setDraftPath(event.currentTarget.value)}
            />
            <button
              className="instrument-button instrument-button--secondary"
              type="submit"
              disabled={loading || draftPath.trim().length === 0}
            >
              <CornerDownRight size={17} aria-hidden="true" />
              Go
            </button>
          </div>
        </form>

        {errorMessage ? (
          <div
            className="run-directory-message run-directory-message--error"
            id="run-directory-error"
            data-testid="run-directory-error"
            role="alert"
          >
            <strong>Cannot read this folder</strong>
            <span>{errorMessage}</span>
          </div>
        ) : null}

        <section className="run-directory-children" aria-labelledby="run-directory-children-title">
          <header>
            <span id="run-directory-children-title">Folders</span>
            <small>{listing ? `${directories.length} items` : "Waiting"}</small>
          </header>
          <div
            className="run-directory-list"
            data-testid="run-directory-list"
            data-total-count={directories.length}
            role="listbox"
            aria-label="Immediate subfolders"
            aria-busy={loading}
          >
            {loading && listing === null ? (
              <div className="run-directory-message" role="status">
                <RefreshCw className="is-spinning" size={17} aria-hidden="true" />
                <span>Reading folder…</span>
              </div>
            ) : directories.length > 0 ? directories.map((directory, index) => (
              <button
                ref={(element) => { entryRefs.current[index] = element; }}
                className="run-directory-entry"
                data-testid="run-directory-entry"
                data-entry-name={directory.name}
                key={directory.path}
                type="button"
                role="option"
                aria-selected={index === activeIndex}
                tabIndex={index === activeIndex ? 0 : -1}
                disabled={loading}
                title={directory.path}
                onFocus={() => setActiveIndex(index)}
                onKeyDown={(event) => handleEntryKeyDown(event, index)}
                onClick={() => onBrowse(directory.path)}
              >
                <Folder size={17} aria-hidden="true" />
                <span>{directory.name}</span>
                <CornerDownRight size={16} aria-hidden="true" />
              </button>
            )) : (
              <div className="run-directory-message" role="status" tabIndex={-1}>
                <Folder size={17} aria-hidden="true" />
                <span>{errorMessage
                  ? "Correct the path above and try again."
                  : "This folder has no subfolders. You can still use the current folder."}</span>
              </div>
            )}
          </div>
          {listing?.truncated ? (
            <p className="run-directory-limit" role="status">
              Showing the first {listing.entryLimit} subfolders. Enter a full path above to go directly to another folder.
            </p>
          ) : null}
        </section>

        <p className="run-directory-boundary">This step selects a save location only; it does not create a Run or file.</p>
      </div>

      <footer className="dialog-actions run-directory-actions">
        <button
          className="instrument-button instrument-button--secondary"
          data-testid="run-directory-cancel"
          type="button"
          onClick={onCancel}
        >
          Back to setup
        </button>
        <button
          className="instrument-button instrument-button--arm"
          data-testid="run-directory-confirm"
          type="button"
          disabled={loading || listing === null}
          onClick={() => {
            if (listing) onUseCurrent(listing.currentDirectory);
          }}
        >
          <Folder size={17} aria-hidden="true" />
          Use current folder
        </button>
      </footer>
    </>
  );
}
