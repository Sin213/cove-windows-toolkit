import { useEffect, useMemo, useState } from "react";
import { invoke } from "../lib/tauri";
import "./DriversPanel.css";

interface MatchingDriver {
  inf_name: string;
  provider?: string | null;
  driver_date?: string | null;
  driver_version?: string | null;
  rank?: number | null;
}

interface InstalledDriver {
  inf_name: string;
  original_inf_name?: string | null;
  provider?: string | null;
  class?: string | null;
  driver_date?: string | null;
  driver_version?: string | null;
  signer?: string | null;
  rank?: number | null;
}

interface DeviceIdentity {
  instance_id: string;
  hardware_ids: string[];
  compatible_ids: string[];
  class_guid?: string | null;
  class_name?: string | null;
  description?: string | null;
  manufacturer?: string | null;
  problem_code?: number | null;
  installed?: InstalledDriver | null;
  matching: MatchingDriver[];
}

interface MachineContext {
  arch: string;
  os_build: string;
  os_version: string;
}

interface DriverIdentityReport {
  complete: boolean;
  degraded: boolean;
  error?: string | null;
  machine: MachineContext;
  devices: DeviceIdentity[];
}

/** Windows CM_PROB codes surfaced in this slice's problem-code triage. */
const PROBLEM_LABELS: Record<number, string> = {
  28: "Driver not installed",
  10: "Device cannot start",
  22: "Device disabled",
  45: "Device not connected",
};

function problemLabel(code: number): string {
  return PROBLEM_LABELS[code] ?? `Problem code ${code}`;
}

type ProblemFilter = "all" | "problems" | "code28";

export default function DriversPanel() {
  const [report, setReport] = useState<DriverIdentityReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<ProblemFilter>("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    invoke<DriverIdentityReport>("get_driver_identity_inventory")
      .then(setReport)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const problemDevices = useMemo(
    () => (report?.devices ?? []).filter((d) => (d.problem_code ?? 0) !== 0),
    [report],
  );
  const code28 = useMemo(
    () => problemDevices.filter((d) => d.problem_code === 28),
    [problemDevices],
  );

  const visibleDevices = useMemo(() => {
    const devices = report?.devices ?? [];
    if (filter === "problems") return problemDevices;
    if (filter === "code28") return code28;
    return devices;
  }, [report, filter, problemDevices, code28]);

  if (loading) {
    return (
      <div className="drivers-loading" role="status">
        Enumerating device identity via pnputil...
      </div>
    );
  }

  if (error) {
    return (
      <div className="drivers-error" role="alert">
        <p>The driver identity scan could not run.</p>
        <p className="drivers-error-detail">{error}</p>
        <button type="button" className="drivers-retry-btn" onClick={load}>
          Retry scan
        </button>
      </div>
    );
  }

  if (!report) return null;

  const fidelity = report.complete
    ? "Full enumeration"
    : report.degraded
      ? "Degraded (older host)"
      : "Failed";

  return (
    <div className="drivers-panel">
      <div className="drivers-toolbar">
        <div className="drivers-fidelity">
          <span
            className={`drivers-fidelity-dot ${
              report.complete ? "ok" : report.degraded ? "warn" : "bad"
            }`}
            aria-hidden
          />
          {fidelity}
          <span className="drivers-machine">
            {report.machine.arch} · build {report.machine.os_build}
          </span>
        </div>
        <button type="button" className="drivers-rescan-btn" onClick={load}>
          Rescan
        </button>
      </div>

      <div className="drivers-summary">
        <button
          type="button"
          className={`drivers-stat ${filter === "all" ? "active" : ""}`}
          onClick={() => setFilter("all")}
        >
          <span className="drivers-stat-num">{report.devices.length}</span>
          <span className="drivers-stat-label">Devices</span>
        </button>
        <button
          type="button"
          className={`drivers-stat ${filter === "problems" ? "active" : ""}`}
          onClick={() => setFilter("problems")}
        >
          <span className="drivers-stat-num">{problemDevices.length}</span>
          <span className="drivers-stat-label">Problem</span>
        </button>
        <button
          type="button"
          className={`drivers-stat ${filter === "code28" ? "active" : ""}`}
          onClick={() => setFilter("code28")}
        >
          <span className="drivers-stat-num">{code28.length}</span>
          <span className="drivers-stat-label">No driver</span>
        </button>
      </div>

      {visibleDevices.length === 0 ? (
        <div className="drivers-empty">
          {filter === "all"
            ? "No connected devices were reported."
            : "No devices match this filter."}
        </div>
      ) : (
        <ul className="drivers-list">
          {visibleDevices.map((device) => {
            const isOpen = expanded === device.instance_id;
            const problem = (device.problem_code ?? 0) !== 0;
            return (
              <li key={device.instance_id} className="drivers-item">
                <button
                  type="button"
                  className="drivers-row"
                  aria-expanded={isOpen}
                  onClick={() =>
                    setExpanded(isOpen ? null : device.instance_id)
                  }
                >
                  <span
                    className={`drivers-status ${
                      problem ? "bad" : "ok"
                    }`}
                    title={
                      problem
                        ? problemLabel(device.problem_code as number)
                        : "Working"
                    }
                    aria-hidden
                  />
                  <span className="drivers-name">
                    {device.description ?? "Unknown device"}
                  </span>
                  <span className="drivers-class">
                    {device.class_name ?? "—"}
                  </span>
                  <span
                    className={`drivers-caret ${isOpen ? "open" : ""}`}
                    aria-hidden
                  >
                    ›
                  </span>
                </button>

                {isOpen && (
                  <dl className="drivers-detail">
                    <dt>Instance ID</dt>
                    <dd className="mono">{device.instance_id}</dd>

                    <dt>Hardware IDs ({device.hardware_ids.length})</dt>
                    <dd>
                      {device.hardware_ids.length === 0 ? (
                        <span className="dim">none reported</span>
                      ) : (
                        <ol className="id-list">
                          {device.hardware_ids.map((id) => (
                            <li key={id} className="mono">
                              {id}
                            </li>
                          ))}
                        </ol>
                      )}
                    </dd>

                    <dt>Compatible IDs ({device.compatible_ids.length})</dt>
                    <dd>
                      {device.compatible_ids.length === 0 ? (
                        <span className="dim">none reported</span>
                      ) : (
                        <ol className="id-list">
                          {device.compatible_ids.map((id) => (
                            <li key={id} className="mono">
                              {id}
                            </li>
                          ))}
                        </ol>
                      )}
                    </dd>

                    {device.installed && (
                      <>
                        <dt>Installed driver</dt>
                        <dd>
                          <span className="mono">{device.installed.inf_name}</span>
                          {device.installed.driver_version && (
                            <span className="dim">
                              {" "}
                              v{device.installed.driver_version}
                            </span>
                          )}
                          {device.installed.rank != null && (
                            <span className="dim">
                              {" "}
                              rank {device.installed.rank}
                            </span>
                          )}
                        </dd>
                      </>
                    )}

                    {device.matching.length > 0 && (
                      <>
                        <dt>
                          Matching drivers ({device.matching.length}, best first)
                        </dt>
                        <dd>
                          <ul className="matching-list">
                            {device.matching.map((m) => (
                              <li key={`${m.inf_name}-${m.rank ?? ""}`}>
                                <span className="mono">{m.inf_name}</span>
                                {m.provider && (
                                  <span className="dim"> — {m.provider}</span>
                                )}
                                {m.rank != null && (
                                  <span className="dim"> rank {m.rank}</span>
                                )}
                              </li>
                            ))}
                          </ul>
                        </dd>
                      </>
                    )}

                    {device.manufacturer && (
                      <>
                        <dt>Manufacturer</dt>
                        <dd>{device.manufacturer}</dd>
                      </>
                    )}

                    {problem && (
                      <>
                        <dt>Status</dt>
                        <dd className="drivers-problem-note">
                          {problemLabel(device.problem_code as number)}
                        </dd>
                      </>
                    )}
                  </dl>
                )}
              </li>
            );
          })}
        </ul>
      )}

      <p className="drivers-footnote">
        Read-only identity inventory via{" "}
        <span className="mono">pnputil /enum-devices</span>. IDs are shown in
        Windows' most-specific-first order; lower rank means a better driver
        match. This panel does not install or modify anything.
      </p>
    </div>
  );
}
