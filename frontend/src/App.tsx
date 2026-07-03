import { useEffect, useState } from "react";
import { NavLink, Route, Routes, useNavigate } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Targets from "./pages/Targets";
import Certificates from "./pages/Certificates";
import CertificateDetail from "./pages/CertificateDetail";
import Endpoints from "./pages/Endpoints";
import EndpointDetail from "./pages/EndpointDetail";
import ScanJobs from "./pages/ScanJobs";
import Alerts from "./pages/Alerts";
import Issuers from "./pages/Issuers";
import Settings from "./pages/Settings";
import Login from "./pages/Login";
import { AuthProvider, RequireAuth, useAuth } from "./auth";
import { logout } from "./api";

const nav = [
  ["/", "Dashboard"],
  ["/targets", "Targets"],
  ["/certificates", "Certificates"],
  ["/endpoints", "Endpoints"],
  ["/scans", "Scan Jobs"],
  ["/alerts", "Alerts"],
  ["/issuers", "Issuers"],
  ["/settings", "Settings"],
];

function UserChip() {
  const { user } = useAuth();
  const navigate = useNavigate();
  if (!user) return null;

  async function handleLogout() {
    try {
      await logout();
    } finally {
      navigate("/login", { replace: true });
    }
  }

  return (
    <div className="user-chip">
      <div className="user-chip-info">
        <div className="user-chip-email">{user.email}</div>
        <div className="user-chip-role">{user.role}</div>
      </div>
      <button className="theme-toggle" onClick={handleLogout}>Log out</button>
    </div>
  );
}

function AppShell() {
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
          <UserChip />
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
          <Route path="/issuers" element={<Issuers />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/*"
          element={
            <RequireAuth>
              <AppShell />
            </RequireAuth>
          }
        />
      </Routes>
    </AuthProvider>
  );
}
