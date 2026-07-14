import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Dashboard as Dash, Cert } from "../api";
import { StatCard, SeverityBadge, BarList, fmtDate } from "../ui";

export default function Dashboard() {
  const [d, setD] = useState<Dash | null>(null);
  const [soon, setSoon] = useState<Cert[]>([]);
  const [expired, setExpired] = useState<Cert[]>([]);
  const [split, setSplit] = useState<{ internal: number; external: number } | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.get<Dash>("/dashboard").then(setD).catch((e) => setErr(e.message));
    api.get<{ items: Cert[] }>("/certificates?expiring_within=90&sort=not_after&limit=10")
      .then((r) => setSoon(r.items)).catch(() => {});
    api.get<{ items: Cert[] }>("/certificates?expired=true&sort=not_after&limit=10")
      .then((r) => setExpired(r.items)).catch(() => {});
    Promise.all([
      api.get<{ total: number }>("/certificates?internal=true&limit=1"),
      api.get<{ total: number }>("/certificates?internal=false&limit=1"),
    ]).then(([i, e]) => setSplit({ internal: i.total, external: e.total })).catch(() => {});
  }, []);

  const certTable = (rows: Cert[], empty: string) =>
    rows.length === 0 ? (
      <div className="empty">{empty}</div>
    ) : (
      <table>
        <thead><tr><th>Common Name</th><th>Issuer</th><th>Status</th><th>Expires</th></tr></thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.id}>
              <td><Link to={`/certificates/${c.id}`}>{c.common_name || c.fingerprint_sha256.slice(0, 24)}</Link></td>
              <td>{c.issuer_cn || "—"}</td>
              <td><SeverityBadge severity={c.severity} label={c.expiry_phrase} /></td>
              <td>{fmtDate(c.not_after)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );

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
              <StatCard label="CA certs expiring ≤90d" value={d.ca_expiring_90d} severity={d.ca_expiring_90d ? "warning" : "healthy"} />
              <StatCard label="Expiring ≤ 30 days" value={d.expiring_30d} severity="warning" />
              <StatCard label="Expiring ≤ 7 days" value={d.expiring_7d} severity="critical" />
              <StatCard label="Expired" value={d.expired} severity="critical" />
              <StatCard label="Failed scans" value={d.failed_scans} severity={d.failed_scans ? "warning" : "healthy"} />
              <StatCard label="Recently changed (7d)" value={d.recently_changed} />
              <StatCard label="Open alerts" value={d.open_alerts} severity={d.open_alerts ? "warning" : "healthy"} />
              <StatCard label="Open findings" value={d.open_findings} severity={d.open_findings ? "warning" : "healthy"} />
              <StatCard
                label="Critical findings"
                value={d.findings_by_severity?.critical ?? 0}
                severity={(d.findings_by_severity?.critical ?? 0) ? "critical" : "healthy"}
              />
              <StatCard label="Managed certificates" value={d.managed_certificates} severity="info" />
              <StatCard label="Unmanaged certificates" value={d.unmanaged_certificates} />
              <StatCard label="Orders in flight" value={d.orders_in_flight} severity={d.orders_in_flight ? "info" : "healthy"} />
              <StatCard
                label="Pending approval"
                value={d.orders_pending_approval}
                severity={d.orders_pending_approval ? "warning" : "healthy"}
              />
              <StatCard
                label="Renewal success (30d)"
                value={d.renewal_success_rate_30d == null ? "—" : `${Math.round(d.renewal_success_rate_30d * 100)}%`}
                severity={
                  d.renewal_success_rate_30d == null ? undefined
                    : d.renewal_success_rate_30d >= 0.9 ? "healthy"
                    : d.renewal_success_rate_30d >= 0.5 ? "warning" : "critical"
                }
              />
            </div>

            <div className="panel" style={{ marginTop: 20 }}>
              <div className="chart-grid">
                <div>
                  <h2>Expiration breakdown</h2>
                  <BarList segments={[
                    { label: "Expired", value: d.expired, color: "#7f1d1d" },
                    { label: "≤ 7 days", value: d.expiring_7d, color: "var(--critical)" },
                    { label: "8–30 days", value: Math.max(0, d.expiring_30d - d.expiring_7d), color: "var(--warning)" },
                    { label: "31–90 days", value: Math.max(0, d.expiring_90d - d.expiring_30d), color: "var(--info)" },
                    { label: "> 90 days", value: Math.max(0, d.total_certificates - d.expired - d.expiring_90d), color: "var(--healthy)" },
                  ]} />
                </div>
                <div>
                  <h2>Internal vs external</h2>
                  {split ? (
                    <BarList segments={[
                      { label: "Internal", value: split.internal, color: "#8b5cf6" },
                      { label: "External", value: split.external, color: "var(--info)" },
                    ]} />
                  ) : <div className="muted">Loading…</div>}
                </div>
              </div>
            </div>

            <div className="panel">
              <div className="kv">
                <dt>Last successful scan</dt><dd>{fmtDate(d.last_successful_scan)}</dd>
                <dt>Next scheduled scan</dt><dd>{fmtDate(d.next_scheduled_scan)}</dd>
              </div>
            </div>

            <div className="panel">
              <h2>Upcoming Expirations</h2>
              {certTable(soon, "No certificates expiring within 90 days.")}
            </div>

            <div className="panel">
              <h2>Expired</h2>
              {certTable(expired, "No expired certificates.")}
            </div>
          </>
        )}
      </div>
    </>
  );
}
