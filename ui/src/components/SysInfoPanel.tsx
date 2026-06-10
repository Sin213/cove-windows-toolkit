import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./SysInfoPanel.css";

interface OsInfo { name: string; version: string; build: string; arch: string; install_date: string; last_boot: string; }
interface CpuInfo { name: string; cores: number; threads: number; base_clock_mhz: number; max_clock_mhz: number; architecture: string; temperature_c: number | null; }
interface RamModule { capacity_bytes: number; speed_mhz: number; manufacturer: string; part_number: string; slot: string; }
interface RamInfo { total_bytes: number; available_bytes: number; speed_mhz: number; slots_used: number; slots_total: number; ram_type: string; modules: RamModule[]; }
interface MotherboardInfo { manufacturer: string; product: string; serial: string; bios_vendor: string; bios_version: string; bios_date: string; }
interface GpuInfo { name: string; driver_version: string; vram_bytes: number; status: string; }
interface MonitorInfo { name: string; resolution: string; }
interface PartitionInfo { letter: string; label: string; size_bytes: number; free_bytes: number; filesystem: string; }
interface DriveInfo { model: string; interface_type: string; media_type: string; size_bytes: number; partitions: PartitionInfo[]; status: string; }
interface AudioDevice { name: string; status: string; }
interface NetworkAdapter { name: string; adapter_type: string; mac: string; speed: string; ip: string; status: string; }
interface FullSystemInfo {
  os: OsInfo; cpu: CpuInfo; ram: RamInfo; motherboard: MotherboardInfo;
  graphics: GpuInfo[]; monitors: MonitorInfo[]; storage: DriveInfo[];
  audio: AudioDevice[]; network: NetworkAdapter[];
}

type Section = "summary" | "os" | "cpu" | "ram" | "motherboard" | "graphics" | "storage" | "audio" | "network";

const SECTIONS: { id: Section; label: string; icon: string }[] = [
  { id: "summary", label: "Summary", icon: "⌂" },
  { id: "os", label: "Operating System", icon: "🖥" },
  { id: "cpu", label: "CPU", icon: "▪" },
  { id: "ram", label: "RAM", icon: "▦" },
  { id: "motherboard", label: "Motherboard", icon: "▣" },
  { id: "graphics", label: "Graphics", icon: "🖵" },
  { id: "storage", label: "Storage", icon: "💾" },
  { id: "audio", label: "Audio", icon: "🔊" },
  { id: "network", label: "Network", icon: "⇄" },
];

function fmtBytes(b: number): string {
  if (b >= 1e12) return `${(b / 1e12).toFixed(1)} TB`;
  if (b >= 1e9) return `${(b / 1e9).toFixed(1)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(0)} MB`;
  return `${b} B`;
}

function fmtMhz(mhz: number): string {
  if (mhz >= 1000) return `${(mhz / 1000).toFixed(2)} GHz`;
  return `${mhz} MHz`;
}

function tempColor(c: number): string {
  if (c >= 85) return "var(--red)";
  if (c >= 70) return "var(--yellow)";
  return "var(--green)";
}

export default function SysInfoPanel() {
  const [info, setInfo] = useState<FullSystemInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState<Section>("summary");

  useEffect(() => {
    invoke<FullSystemInfo>("get_full_sysinfo")
      .then(setInfo)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="panel-loading">Gathering system information...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!info) return null;

  return (
    <div className="sysinfo-panel">
      <div className="sysinfo-nav">
        {SECTIONS.map((s) => (
          <button key={s.id} className={`sysinfo-nav-btn ${section === s.id ? "active" : ""}`} onClick={() => setSection(s.id)}>
            <span className="sysinfo-nav-icon">{s.icon}</span>
            <span>{s.label}</span>
          </button>
        ))}
      </div>
      <div className="sysinfo-content">
        {section === "summary" && <SummaryView info={info} />}
        {section === "os" && <OsView os={info.os} />}
        {section === "cpu" && <CpuView cpu={info.cpu} />}
        {section === "ram" && <RamView ram={info.ram} />}
        {section === "motherboard" && <MoboView mb={info.motherboard} />}
        {section === "graphics" && <GfxView gpus={info.graphics} monitors={info.monitors} />}
        {section === "storage" && <StorageView drives={info.storage} />}
        {section === "audio" && <AudioView devices={info.audio} />}
        {section === "network" && <NetView adapters={info.network} />}
      </div>
    </div>
  );
}

function Row({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="info-row">
      <span className="info-label">{label}</span>
      <span className="info-value" style={color ? { color } : undefined}>{value}</span>
    </div>
  );
}

function SectionCard({ title, icon, children }: { title: string; icon: string; children: React.ReactNode }) {
  return (
    <div className="sysinfo-card">
      <div className="card-title"><span className="card-icon">{icon}</span>{title}</div>
      {children}
    </div>
  );
}

function SummaryView({ info }: { info: FullSystemInfo }) {
  return (
    <div className="summary-grid">
      <SectionCard title="Operating System" icon="🖥">
        <div className="summary-value">{info.os.name} {info.os.arch}</div>
      </SectionCard>
      <SectionCard title="CPU" icon="▪">
        <div className="summary-value">
          {info.cpu.name}
          {info.cpu.temperature_c != null && (
            <span className="temp-badge" style={{ color: tempColor(info.cpu.temperature_c) }}>
              {info.cpu.temperature_c}°C
            </span>
          )}
        </div>
        <div className="summary-sub">{info.cpu.cores} Cores / {info.cpu.threads} Threads</div>
      </SectionCard>
      <SectionCard title="RAM" icon="▦">
        <div className="summary-value">{fmtBytes(info.ram.total_bytes)}</div>
        <div className="summary-sub">{info.ram.ram_type} {info.ram.speed_mhz} MHz - {info.ram.slots_used}/{info.ram.slots_total} slots</div>
      </SectionCard>
      <SectionCard title="Motherboard" icon="▣">
        <div className="summary-value">{info.motherboard.manufacturer} {info.motherboard.product}</div>
      </SectionCard>
      <SectionCard title="Graphics" icon="🖵">
        {info.graphics.map((g, i) => (
          <div key={i} className="summary-value">{g.name} ({fmtBytes(g.vram_bytes)} VRAM)</div>
        ))}
        {info.monitors.map((m, i) => (
          <div key={`m${i}`} className="summary-sub">{m.name} {m.resolution && `(${m.resolution})`}</div>
        ))}
      </SectionCard>
      <SectionCard title="Storage" icon="💾">
        {info.storage.map((d, i) => (
          <div key={i} className="summary-value">{fmtBytes(d.size_bytes)} {d.media_type} - {d.model}</div>
        ))}
      </SectionCard>
      <SectionCard title="Audio" icon="🔊">
        {info.audio.map((a, i) => (
          <div key={i} className="summary-value">{a.name}</div>
        ))}
      </SectionCard>
      <SectionCard title="Network" icon="⇄">
        {info.network.map((n, i) => (
          <div key={i} className="summary-value">
            {n.name}
            <span className={`net-status ${n.status === "Connected" ? "connected" : "disconnected"}`}>{n.status}</span>
          </div>
        ))}
      </SectionCard>
    </div>
  );
}

function OsView({ os }: { os: OsInfo }) {
  return (
    <div className="detail-section">
      <Row label="Name" value={os.name} />
      <Row label="Version" value={os.version} />
      <Row label="Build" value={os.build} />
      <Row label="Architecture" value={os.arch} />
      <Row label="Install Date" value={os.install_date} />
      <Row label="Last Boot" value={os.last_boot ? new Date(os.last_boot).toLocaleString() : ""} />
    </div>
  );
}

function CpuView({ cpu }: { cpu: CpuInfo }) {
  return (
    <div className="detail-section">
      <Row label="Processor" value={cpu.name} />
      <Row label="Cores" value={`${cpu.cores}`} />
      <Row label="Threads" value={`${cpu.threads}`} />
      <Row label="Base Clock" value={fmtMhz(cpu.base_clock_mhz)} />
      <Row label="Max Clock" value={fmtMhz(cpu.max_clock_mhz)} />
      <Row label="Architecture" value={cpu.architecture} />
      {cpu.temperature_c != null && (
        <Row label="Temperature" value={`${cpu.temperature_c}°C`} color={tempColor(cpu.temperature_c)} />
      )}
    </div>
  );
}

function RamView({ ram }: { ram: RamInfo }) {
  return (
    <div className="detail-section">
      <Row label="Total" value={fmtBytes(ram.total_bytes)} />
      <Row label="Available" value={fmtBytes(ram.available_bytes)} />
      <Row label="Type" value={ram.ram_type} />
      <Row label="Speed" value={`${ram.speed_mhz} MHz`} />
      <Row label="Slots" value={`${ram.slots_used} of ${ram.slots_total} used`} />
      {ram.modules.length > 0 && (
        <>
          <div className="subsection-title">Modules</div>
          {ram.modules.map((m, i) => (
            <div key={i} className="module-card">
              <Row label="Slot" value={m.slot} />
              <Row label="Capacity" value={fmtBytes(m.capacity_bytes)} />
              <Row label="Speed" value={`${m.speed_mhz} MHz`} />
              <Row label="Manufacturer" value={m.manufacturer} />
              <Row label="Part Number" value={m.part_number} />
            </div>
          ))}
        </>
      )}
    </div>
  );
}

function MoboView({ mb }: { mb: MotherboardInfo }) {
  return (
    <div className="detail-section">
      <Row label="Manufacturer" value={mb.manufacturer} />
      <Row label="Model" value={mb.product} />
      <Row label="Serial" value={mb.serial} />
      <div className="subsection-title">BIOS</div>
      <Row label="Vendor" value={mb.bios_vendor} />
      <Row label="Version" value={mb.bios_version} />
      <Row label="Date" value={mb.bios_date} />
    </div>
  );
}

function GfxView({ gpus, monitors }: { gpus: GpuInfo[]; monitors: MonitorInfo[] }) {
  return (
    <div className="detail-section">
      {gpus.map((g, i) => (
        <div key={i} className="module-card">
          <Row label="GPU" value={g.name} />
          <Row label="VRAM" value={fmtBytes(g.vram_bytes)} />
          <Row label="Driver" value={g.driver_version} />
          <Row label="Status" value={g.status} />
        </div>
      ))}
      {monitors.length > 0 && (
        <>
          <div className="subsection-title">Monitors</div>
          {monitors.map((m, i) => (
            <div key={i} className="module-card">
              <Row label="Name" value={m.name} />
              {m.resolution && <Row label="Resolution" value={m.resolution} />}
            </div>
          ))}
        </>
      )}
    </div>
  );
}

function StorageView({ drives }: { drives: DriveInfo[] }) {
  return (
    <div className="detail-section">
      {drives.map((d, i) => (
        <div key={i} className="module-card">
          <Row label="Model" value={d.model} />
          <Row label="Type" value={`${d.media_type} (${d.interface_type})`} />
          <Row label="Capacity" value={fmtBytes(d.size_bytes)} />
          <Row label="Status" value={d.status} />
          {d.partitions.length > 0 && (
            <div className="partitions">
              {d.partitions.map((p, j) => {
                const usedPct = p.size_bytes > 0 ? ((p.size_bytes - p.free_bytes) / p.size_bytes) * 100 : 0;
                return (
                  <div key={j} className="partition-row">
                    <span className="part-letter">{p.letter}</span>
                    <span className="part-label">{p.label || "-"}</span>
                    <div className="part-bar-wrap">
                      <div className="part-bar" style={{ width: `${usedPct}%`, background: usedPct > 90 ? "var(--red)" : "var(--accent)" }} />
                    </div>
                    <span className="part-size">{fmtBytes(p.free_bytes)} free / {fmtBytes(p.size_bytes)}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function AudioView({ devices }: { devices: AudioDevice[] }) {
  return (
    <div className="detail-section">
      {devices.map((a, i) => (
        <div key={i} className="module-card">
          <Row label="Device" value={a.name} />
          <Row label="Status" value={a.status} />
        </div>
      ))}
      {devices.length === 0 && <div className="empty-state">No audio devices detected.</div>}
    </div>
  );
}

function NetView({ adapters }: { adapters: NetworkAdapter[] }) {
  return (
    <div className="detail-section">
      {adapters.map((n, i) => (
        <div key={i} className="module-card">
          <Row label="Adapter" value={n.name} />
          <Row label="Type" value={n.adapter_type} />
          <Row label="MAC" value={n.mac} />
          <Row label="Speed" value={n.speed} />
          <Row label="IP" value={n.ip || "-"} />
          <Row label="Status" value={n.status} color={n.status === "Connected" ? "var(--green)" : "var(--text-muted)"} />
        </div>
      ))}
      {adapters.length === 0 && <div className="empty-state">No network adapters detected.</div>}
    </div>
  );
}
