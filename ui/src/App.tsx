import { useState } from "react";
import "./App.css";
import TitleBar from "./components/TitleBar";
import Sidebar from "./components/Sidebar";
import Dashboard from "./components/Dashboard";
import CategoryPanel from "./components/CategoryPanel";

export type View =
  | "dashboard"
  | "visual"
  | "privacy"
  | "services"
  | "startup"
  | "cleanup"
  | "power"
  | "health"
  | "eventlog"
  | "bsod"
  | "netdiag"
  | "updates"
  | "uninstall"
  | "sysinfo"
  | "temps"
  | "sfc"
  | "restore"
  | "history"
  | "performance"
  | "diff"
  | "security"
  | "runtimes"
  | "diskhealth";

function App() {
  const [view, setView] = useState<View>("dashboard");

  return (
    <>
      <TitleBar />
      <div className="app-body">
        <Sidebar current={view} onNavigate={setView} />
        <main className="main-content">
          {view === "dashboard" ? (
            <Dashboard onNavigate={setView} />
          ) : (
            <CategoryPanel view={view} onBack={() => setView("dashboard")} />
          )}
        </main>
      </div>
    </>
  );
}

export default App;
