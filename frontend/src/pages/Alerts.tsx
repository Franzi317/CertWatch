import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Alert } from "../api";
import { SeverityBadge, fmtDate, useToast } from "../ui";

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [showResolved, setShowResolved] = useState(false);
  const { show, node } = useToast();

  const load = () => api.get<Alert[]>(`/alerts?include_resolved=${showResolved}`).then(setAlerts).catch(() => {});
  useEffect(() => { load(); }, [showResolved]);

  async function act(a: Alert, action: string, body?: any) {
    await api.post(`/alerts/${a.id}/${action}`, body); load(); show(`Alert ${action}.`);
  }
  async function evaluate() {
    const r = await api.post<any>("/alerts/evaluate"); load();
    show(`Evaluated: ${r.created} created, ${r.notified} notified, ${r.resolved} resolved.`);
  }

  return (
    <>
      <div className="topbar">
        <h1>Alerts</h1>
        <button className="secondary" onClick={evaluate}>Re-evaluate now</button>
      </div>
      <div className="content">
        <div className="panel">
          <div className="row" style={{ marginBottom: 14 }}>
            <label style={{ margin: 0 }}><input type="checkbox" checked={showResolved} onChange={(e) => setShowResolved(e.target.checked)} /> Include resolved</label>
            <div className="spacer" />
            <span className="muted">{alerts.length} alerts</span>
          </div>
          <table>
            <thead><tr><th>Severity</th><th>Rule</th><th>Endpoint</th><th>Message</th><th>Notified</th><th>State</th><th></th></tr></thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id}>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td>{a.rule_type}</td>
                  <td>{a.endpoint_id ? <Link to={`/endpoints/${a.endpoint_id}`}>{a.endpoint}</Link> : "—"}</td>
                  <td className="wrap">{a.message}</td>
                  <td>{a.notify_count}× {a.last_notified_at && <span className="muted">({fmtDate(a.last_notified_at)})</span>}</td>
                  <td>
                    {a.resolved && <span className="tag">resolved</span>}
                    {a.acknowledged && <span className="tag">acked</span>}
                    {a.muted && <span className="tag">muted</span>}
                    {!a.resolved && !a.acknowledged && !a.muted && <span className="tag">active</span>}
                  </td>
                  <td>
                    <div className="row" style={{ gap: 4 }}>
                      {!a.acknowledged && <button className="ghost" onClick={() => act(a, "ack")}>Ack</button>}
                      {!a.muted ? <button className="ghost" onClick={() => act(a, "mute", { mute_hours: 24 })}>Mute 24h</button>
                        : <button className="ghost" onClick={() => act(a, "unmute")}>Unmute</button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {alerts.length === 0 && <div className="empty">No alerts.</div>}
        </div>
      </div>
      {node}
    </>
  );
}
