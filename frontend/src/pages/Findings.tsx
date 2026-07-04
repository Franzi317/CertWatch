import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Finding, FindingList } from "../api";
import { useAuth } from "../auth";
import { SeverityBadge, fmtDate, useToast } from "../ui";

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [disposition, setDisposition] = useState("");
  const [status, setStatus] = useState("active");
  const [busy, setBusy] = useState<number | null>(null);
  const { user } = useAuth();
  const { show, node } = useToast();
  const canWrite = user && (user.role === "operator" || user.role === "admin");

  function buildParams(): string {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (ruleId) params.set("rule_id", ruleId);
    if (disposition) params.set("disposition", disposition);
    params.set("status", status);
    return params.toString();
  }

  const load = () =>
    api.get<FindingList>(`/findings?${buildParams()}`)
      .then((r) => { setFindings(r.items); setTotal(r.total); })
      .catch((e) => show(e.message, true));

  useEffect(() => { load(); }, [severity, ruleId, disposition, status]);

  async function setFindingDisposition(f: Finding, next: string) {
    setBusy(f.id);
    try {
      await api.post(`/findings/${f.id}/disposition`, { disposition: next });
      show(`Finding ${f.id} marked ${next}.`);
      load();
    } catch (e: any) {
      show(`Update failed: ${e.message}`, true);
    } finally {
      setBusy(null);
    }
  }

  async function evaluate() {
    const r = await api.post<{ active: number }>("/findings/evaluate");
    load();
    show(`Evaluated: ${r.active} active.`);
  }

  return (
    <>
      <div className="topbar">
        <h1>Findings</h1>
        {canWrite && <button className="secondary" onClick={evaluate}>Re-evaluate</button>}
      </div>
      <div className="content">
        <div className="panel">
          <div className="row" style={{ marginBottom: 14, gap: 8, flexWrap: "wrap" }}>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All severities</option>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="critical">Critical</option>
            </select>
            <input
              placeholder="Rule ID…"
              value={ruleId}
              onChange={(e) => setRuleId(e.target.value)}
              style={{ width: 160 }}
            />
            <select value={disposition} onChange={(e) => setDisposition(e.target.value)}>
              <option value="">All dispositions</option>
              <option value="open">Open</option>
              <option value="accepted">Accepted</option>
              <option value="resolved">Resolved</option>
            </select>
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="active">Active</option>
              <option value="cleared">Cleared</option>
              <option value="">All</option>
            </select>
            <div className="spacer" />
            <a className="secondary" href={`/api/findings?${buildParams()}&format=csv`}>Download CSV</a>
            <span className="muted">{total} findings</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Severity</th><th>Rule</th><th>Title</th><th>Affected</th>
                <th>Disposition</th><th>Status</th><th></th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id}>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td>{f.rule_id}</td>
                  <td className="wrap">{f.title}</td>
                  <td>
                    {f.certificate_id ? (
                      <Link to={`/certificates/${f.certificate_id}`}>Certificate #{f.certificate_id}</Link>
                    ) : f.endpoint_id ? (
                      <Link to={`/endpoints/${f.endpoint_id}`}>Endpoint #{f.endpoint_id}</Link>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td><span className="tag">{f.disposition}</span></td>
                  <td><span className="tag">{f.status}</span></td>
                  <td>
                    {canWrite && (
                      <div className="row" style={{ gap: 4 }}>
                        {f.disposition !== "open" && (
                          <button className="ghost" disabled={busy === f.id} onClick={() => setFindingDisposition(f, "open")}>Open</button>
                        )}
                        {f.disposition !== "accepted" && (
                          <button className="ghost" disabled={busy === f.id} onClick={() => setFindingDisposition(f, "accepted")}>Accept</button>
                        )}
                        {f.disposition !== "resolved" && (
                          <button className="ghost" disabled={busy === f.id} onClick={() => setFindingDisposition(f, "resolved")}>Resolve</button>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {findings.length === 0 && <div className="empty">No findings.</div>}
        </div>
      </div>
      {node}
    </>
  );
}
