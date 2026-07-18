import { useState } from "react";
import Icon from "./Icon";
import { openExternal } from "../lib/openExternal";
import "./ToolsPanel.css";

interface ToolEntry {
  id: string;
  name: string;
  category: string;
  description: string;
  url: string;
}

const TOOLS: ToolEntry[] = [
  {
    id: "occt",
    name: "OCCT",
    category: "Stability testing",
    url: "https://www.ocbase.com/download",
    description: "All-in-one hardware stability, stress-testing, benchmarking, and monitoring utility.",
  },
  {
    id: "prime95",
    name: "Prime95",
    category: "CPU stress test",
    url: "https://www.mersenne.org/download/",
    description: "CPU and memory stress-testing utility commonly used to identify processor and system instability.",
  },
  {
    id: "furmark",
    name: "FurMark",
    category: "GPU stress test",
    url: "https://geeks3d.com/furmark/",
    description: "Intensive GPU stress test and graphics-card benchmark.",
  },
  {
    id: "testmem5",
    name: "TestMem5",
    category: "RAM testing",
    url: "https://github.com/CoolCmd/TestMem5",
    description: "Configurable Windows RAM stress test for detecting memory errors and unstable timings.",
  },
  {
    id: "memtest86",
    name: "MemTest86",
    category: "RAM testing",
    url: "https://www.memtest86.com/",
    description: "Boot-level memory test that runs from USB, for when Windows is too unstable to test from the desktop.",
  },
  {
    id: "hwinfo",
    name: "HWiNFO",
    category: "Hardware monitoring",
    url: "https://www.hwinfo.com/download/",
    description: "In-depth sensor monitoring for temperatures, clocks, voltages, and fan speeds during stress testing.",
  },
  {
    id: "cpuz",
    name: "CPU-Z",
    category: "Hardware ID",
    url: "https://www.cpuid.com/softwares/cpu-z.html",
    description: "Quick identification of CPU, motherboard, and memory specs, timings, and SPD details.",
  },
  {
    id: "gpuz",
    name: "GPU-Z",
    category: "Hardware ID",
    url: "https://www.techpowerup.com/gpuz/",
    description: "Graphics-card details, BIOS version, VRAM, and live sensor readings at a glance.",
  },
  {
    id: "ddu",
    name: "Display Driver Uninstaller",
    category: "Driver cleanup",
    url: "https://www.wagnardsoft.com/",
    description: "Completely removes GPU drivers for a clean reinstall after crashes, artifacts, or driver conflicts.",
  },
  {
    id: "adwcleaner",
    name: "AdwCleaner",
    category: "Adware removal",
    url: "https://www.malwarebytes.com/adwcleaner",
    description: "Portable adware and PUP cleaner that removes unwanted toolbars, browser hijackers, and bundled junk software.",
  },
];

export default function ToolsPanel() {
  const [errors, setErrors] = useState<Record<string, string>>({});

  const handleVisit = async (tool: ToolEntry) => {
    setErrors((prev) => {
      const next = { ...prev };
      delete next[tool.id];
      return next;
    });
    const res = await openExternal(tool.url);
    if (!res.ok) {
      setErrors((prev) => ({ ...prev, [tool.id]: res.message }));
    }
  };

  return (
    <div className="tools-grid">
      {TOOLS.map((tool) => (
        <div key={tool.id} className="tool-card">
          <div className="tool-card-head">
            <Icon name="tools" size={16} />
            <span className="tool-category">{tool.category}</span>
          </div>
          <h3 className="tool-name">{tool.name}</h3>
          <p className="tool-desc">{tool.description}</p>
          <button
            type="button"
            className="tool-visit-btn"
            onClick={() => handleVisit(tool)}
            aria-label={`Visit the ${tool.name} website (opens in your browser)`}
          >
            Visit website
            <Icon name="external-link" size={13} />
          </button>
          {errors[tool.id] && (
            <div className="tool-error" role="alert">
              {errors[tool.id]}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
