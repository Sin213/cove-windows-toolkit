import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./RuntimesPanel.css";

interface RuntimeEntry {
  name: string;
  version: string;
  runtime_type?: string;
  path?: string | null;
  installed: boolean;
  arch?: string;
  outdated: boolean;
  download_url?: string | null;
}

interface DirectXInfo {
  version: string;
  feature_level: string;
  download_url: string;
}

interface RuntimesData {
  dotnet: RuntimeEntry[];
  vcredist: RuntimeEntry[];
  directx: DirectXInfo;
  java: RuntimeEntry[];
}

export default function RuntimesPanel() {
  const [data, setData] = useState<RuntimesData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    invoke<RuntimesData>("get_installed_runtimes")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleCopy = () => {
    if (!data) return;
    const lines: string[] = [
      "=== Installed Runtimes ===",
      "",
      "-- .NET --",
      ...data.dotnet.map((r) =>
        r.installed
          ? `[OK] ${r.name} (${r.version})${r.path ? " - " + r.path : ""}`
          : `[--] ${r.name} - Not installed`
      ),
      "",
      "-- Visual C++ Redistributables --",
      ...data.vcredist.map((r) =>
        `[OK] ${r.name} (${r.version})`
      ),
      "",
      "-- DirectX --",
      `[OK] DirectX ${data.directx.version} (Feature Level ${data.directx.feature_level})`,
      "",
      "-- Java --",
      ...(data.java.length > 0
        ? data.java.map((r) => `[OK] ${r.name} (${r.version})${r.path ? " - " + r.path : ""}`)
        : ["[--] No Java installation detected"]),
    ];
    navigator.clipboard.writeText(lines.join("\n")).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  if (loading) return <div className="panel-loading">Detecting installed runtimes...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  return (
    <div className="runtimes-panel">
      {/* .NET */}
      <div className="runtimes-category">
        <div className="runtimes-category-title">.NET</div>
        <div className="runtimes-list">
          {data.dotnet.map((r) => (
            <RuntimeRow key={r.name} entry={r} />
          ))}
        </div>
      </div>

      {/* Visual C++ */}
      <div className="runtimes-category">
        <div className="runtimes-category-title">Visual C++ Redistributables</div>
        <div className="runtimes-list">
          {data.vcredist.map((r) => (
            <RuntimeRow key={r.name} entry={r} />
          ))}
        </div>
      </div>

      {/* DirectX */}
      <div className="runtimes-category">
        <div className="runtimes-category-title">DirectX</div>
        <div className="dx-row">
          <span className="runtime-status-icon installed">✔</span>
          <div className="runtime-info">
            <div className="runtime-name">DirectX {data.directx.version}</div>
          </div>
          <span className="runtime-version">Feature Level {data.directx.feature_level}</span>
        </div>
      </div>

      {/* Java */}
      <div className="runtimes-category">
        <div className="runtimes-category-title">Java</div>
        {data.java.length === 0 ? (
          <div className="java-empty">No Java installation detected</div>
        ) : (
          <div className="runtimes-list">
            {data.java.map((r) => (
              <RuntimeRow key={r.name} entry={r} />
            ))}
          </div>
        )}
      </div>

      <div className="runtimes-actions">
        <button className="copy-summary-btn" onClick={handleCopy}>
          {copied ? "Copied!" : "Copy Summary"}
        </button>
      </div>
    </div>
  );
}

function RuntimeRow({ entry }: { entry: RuntimeEntry }) {
  const statusClass = entry.installed
    ? entry.outdated
      ? "outdated"
      : "installed"
    : "missing";
  const icon = entry.installed ? (entry.outdated ? "⚠" : "✔") : "—";

  const handleDownload = () => {
    if (entry.download_url) {
      invoke("open_url", { url: entry.download_url });
    }
  };

  return (
    <div className="runtime-item">
      <span className={`runtime-status-icon ${statusClass}`}>{icon}</span>
      <div className="runtime-info">
        <div className="runtime-name">
          {entry.name}
          {entry.outdated && (
            <span className="runtime-outdated-badge">Outdated</span>
          )}
        </div>
        {entry.path && <div className="runtime-detail">{entry.path}</div>}
        {!entry.installed && <div className="runtime-detail">Not installed</div>}
      </div>
      {entry.arch && <span className="runtime-arch">{entry.arch}</span>}
      {entry.installed && entry.version && (
        <span className="runtime-version">{entry.version}</span>
      )}
      {entry.download_url && (
        <button className="runtime-dl-btn" onClick={handleDownload}>
          {entry.installed ? "Update" : "Download"}
        </button>
      )}
    </div>
  );
}
