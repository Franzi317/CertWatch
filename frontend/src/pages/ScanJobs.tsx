import { useEffect, useState } from "react";
import { api, ScanJob } from "../api";
import { SeverityBadge, fmtDate, useToast } from "../ui";

const STATUS_SEV: Record<string, string> = {
  completed: "healthy", running: "info", pending: "info", cancelled: "unknown", failed: "critical",
};

export default function ScanJobs() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const { show, node } = useToast();

  const load = () => api.get<ScanJob[]>("/scans").then(setJobs).catch(() => {});
  useEffect(() => {
    load();
    // Poll while any job is active so progress updates without blocking the UI.
    const t = setInterval(load, 2000);
    return () => clearInterval(t);
  }, []);

  async function cancel(j: ScanJob) {
    await api.post(`/scans/${j.id}/cancel`); show("Cancellation requested."); load();
  }

  return (
    <>
      <div className="topbar"><h1>Scan Jobs</h1></div>
      <div className="content">
        <div className="panel">
          <table>
            <thead><tr><th>#</th><th>Target</th><th>Trigger</th><th>Status</th><th>Progress</th><th>Certs</th><th>Errors</th><th>Started</th><th>Finished</th><th></th></tr></thead>
            <tbody>
              {jobs.map((j) => {
                const pct = j.total_endpoints ? Math.round((j.scanned_endpoints / j.total_endpoints) * 100) : 0;
                return (
                  <tr key={j.id}>
                    <td>{j.id}</td>
                    <td>{j.target_name}</td>
                    <td>{j.trigger}</td>
                    <td><SeverityBadge severity={STATUS_SEV[j.status] || "unknown"} label={j.status} /></td>
                    <td>
                      <div className="row" style={{ gap: 8 }}>
                        <div className="progressbar"><div style={{ width: `${pct}%` }} /></div>
                        <span className="muted">{j.scanned_endpoints}/{j.total_endpoints}</span>
                      </div>
                    </td>
                    <td>{j.certs_found}</td>
                    <td>{j.errors}</td>
                    <td>{fmtDate(j.started_at)}</td>
                    <td>{fmtDate(j.finished_at)}</td>
                    <td>{["pending", "running"].includes(j.status) && <button className="ghost" onClick={() => cancel(j)}>Cancel</button>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {jobs.length === 0 && <div className="empty">No scan jobs yet.</div>}
        </div>
      </div>
      {node}
    </>
  );
}
