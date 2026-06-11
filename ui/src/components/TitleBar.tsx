import { invoke } from "@tauri-apps/api/core";
import iconUrl from "../assets/icon.png";
import "./TitleBar.css";

const TITLE = "Cove Windows Toolkit";
const VERSION = "v1.0.0";

function TitleBar() {
  // Drag the window from the bar background (not from the control buttons).
  const onMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    if ((e.target as HTMLElement).closest(".titlebar-btn")) return;
    invoke("win_start_drag");
  };

  const onDoubleClick = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest(".titlebar-btn")) return;
    invoke("win_toggle_maximize");
  };

  return (
    <div className="titlebar" onMouseDown={onMouseDown} onDoubleClick={onDoubleClick}>
      <img className="titlebar-icon" src={iconUrl} alt="" draggable={false} />

      <div className="titlebar-brand">
        <span className="titlebar-title">{TITLE}</span>
        <span className="titlebar-version">{VERSION}</span>
      </div>

      <div className="titlebar-controls">
        <button
          className="titlebar-btn"
          aria-label="Minimize"
          onClick={() => invoke("win_minimize")}
        >
          <svg width="10" height="10" viewBox="0 0 10 10">
            <line x1="0" y1="5" x2="10" y2="5" stroke="currentColor" strokeWidth="1" />
          </svg>
        </button>
        <button
          className="titlebar-btn"
          aria-label="Maximize"
          onClick={() => invoke("win_toggle_maximize")}
        >
          <svg width="10" height="10" viewBox="0 0 10 10">
            <rect x="0.5" y="0.5" width="9" height="9" fill="none" stroke="currentColor" strokeWidth="1" />
          </svg>
        </button>
        <button
          className="titlebar-btn titlebar-btn-close"
          aria-label="Close"
          onClick={() => invoke("win_close")}
        >
          <svg width="10" height="10" viewBox="0 0 10 10">
            <line x1="0" y1="0" x2="10" y2="10" stroke="currentColor" strokeWidth="1" />
            <line x1="0" y1="10" x2="10" y2="0" stroke="currentColor" strokeWidth="1" />
          </svg>
        </button>
      </div>
    </div>
  );
}

export default TitleBar;
