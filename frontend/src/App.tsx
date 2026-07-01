import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Targets from "./pages/Targets";
import Certificates from "./pages/Certificates";
import CertificateDetail from "./pages/CertificateDetail";
import Endpoints from "./pages/Endpoints";
import EndpointDetail from "./pages/EndpointDetail";
import ScanJobs from "./pages/ScanJobs";
import Alerts from "./pages/Alerts";
import Settings from "./pages/Settings";

const nav = [
  ["/", "Dashboard"],
  ["/targets", "Targets"],
  ["/certificates", "Certificates"],
  ["/endpoints", "Endpoints"],
  ["/scans", "Scan Jobs"],
  ["/alerts", "Alerts"],
  ["/settings", "Settings"],
];

export default function App() {
  const [theme, setTheme] = useState(
    () => localStorage.getItem("theme")
      || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
  );
  const [showHelp, setShowHelp] = useState(false);
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">Cert<span>Watch</span></div>
        <nav>
          {nav.map(([to, label]) => (
            <NavLink key={to} to={to} end={to === "/"}>
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <button className="theme-toggle" onClick={() => setShowHelp((v) => !v)}>Help</button>
          {showHelp && <div className="notice">Need assistance? Contact Ryan Franzman.</div>}
          <button className="theme-toggle" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
            {theme === "dark" ? "☀ Light mode" : "🌙 Dark mode"}
          </button>
          <div className="notice">
            Authorized internal inventory only. Scan only networks and hosts you are
            authorized to assess.
          </div>
        </div>
      </aside>
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/targets" element={<Targets />} />
          <Route path="/certificates" element={<Certificates />} />
          <Route path="/certificates/:id" element={<CertificateDetail />} />
          <Route path="/endpoints" element={<Endpoints />} />
          <Route path="/endpoints/:id" element={<EndpointDetail />} />
          <Route path="/scans" element={<ScanJobs />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
