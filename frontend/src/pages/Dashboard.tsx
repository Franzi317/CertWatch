import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Dashboard as Dash, Cert } from "../api";
import { StatCard, SeverityBadge, fmtDate } from "../ui";

export default function Dashboard() {
  const [d, setD] = useState<Dash | null>(null);
  const [soon, setSoon] = useState<Cert[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.get<Dash>("/dashboard").then(setD).catch((e) => setErr(e.message));
    api.get<{ items: Cert[] }>("/certificates?expiring_within=90&sort=not_after&limit=10")
      .then((r) => setSoon(r.items)).catch(() => {});
  }, []);

  return (
    <>
      <div className="topbar"><h1>Dashboard</h1></div>
      <div className="content">
        {err && <div className="panel" style={{ color: "var(--critical)" }}>Failed to load: {err}</div>}
        {d && (
          <>
            <div className="stat-grid">
              <StatCard label="Certificates" value={d.total_certificates} />
              <StatCard label="Endpoints scanned" value={d.total_endpoints} />
              <StatCard label="Expiring ≤ 90 days" value={d.expiring_90d} severity="info" />
              <StatCard label="Expiring ≤ 30 days" value={d.expiring_30d} severity="warning" />
              <StatCard label="Expiring ≤ 7 days" value={d.expiring_7d} severity="critical" />
              <StatCard label="Expired" value={d.expired} severity="critical" />
              <StatCard label="Failed scans" value={d.failed_scans} severity={d.failed_scans ? "warning" : "healthy"} />
              <StatCard label="Recently changed (7d)" value={d.recently_changed} />
              <StatCard label="Open alerts" value={d.open_alerts} severity={d.open_alerts ? "warning" : "healthy"} />
            </div>

            <div className="panel" style={{ marginTop: 20 }}>
              <div className="kv">
                <dt>Last successful scan</dt><dd>{fmtDate(d.last_successful_scan)}</dd>
                <dt>Next scheduled scan</dt><dd>{fmtDate(d.next_scheduled_scan)}</dd>
              </div>
            </div>

            <div className="panel">
              <h2>Expiration timeline — soonest 10</h2>
              {soon.length === 0 ? (
                <div className="empty">No certificates expiring within 90 days.</div>
              ) : (
                <table>
                  <thead><tr><th>Common Name</th><th>Issuer</th><th>Status</th><th>Expires</th></tr></thead>
                  <tbody>
                    {soon.map((c) => (
                      <tr key={c.id}>
                        <td><Link to={`/certificates/${c.id}`}>{c.common_name || c.fingerprint_sha256.slice(0, 24)}</Link></td>
                        <td>{c.issuer_cn || "—"}</td>
                        <td><SeverityBadge severity={c.severity} label={c.expiry_phrase} /></td>
                        <td>{fmtDate(c.not_after)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </>
        )}
      </div>
    </>
  );
}
