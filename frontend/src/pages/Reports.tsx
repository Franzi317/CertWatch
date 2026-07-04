import { useEffect, useState } from "react";
import { api, Channel, ReportSchedule } from "../api";
import { useAuth } from "../auth";
import { Modal, fmtDate, useToast } from "../ui";

type ReportDraft = {
  id?: number; name: string; report_type: string; filter_params: any;
  format: string; recipients: string; channel_id: number | ""; cadence: string;
  schedule_time: string; schedule_day: number; enabled: boolean;
};
const BLANK: ReportDraft = {
  name: "", report_type: "certificates", filter_params: {}, format: "csv",
  recipients: "", channel_id: "", cadence: "daily", schedule_time: "08:00",
  schedule_day: 0, enabled: true,
};

function reportTypeLabel(t: string): string {
  return { certificates: "All certificates", expiring: "Expiring certificates", findings: "Findings", endpoints: "Endpoints" }[t] || t;
}

export default function Reports() {
  const [reports, setReports] = useState<ReportSchedule[]>([]);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [draft, setDraft] = useState<ReportDraft | null>(null);
  const [running, setRunning] = useState<number | null>(null);
  const { user } = useAuth();
  const { show, node } = useToast();
  const canWrite = !!user && (user.role === "operator" || user.role === "admin");
  const smtpChannels = channels.filter((c) => c.channel_type === "smtp");

  const load = () => {
    api.get<any>("/reports").then((r) => setReports(Array.isArray(r) ? r : r.items)).catch((e) => show(e.message, true));
    api.get<Channel[]>("/channels").then(setChannels).catch(() => {});
  };
  useEffect(() => { load(); }, []);

  async function save() {
    if (!draft) return;
    try {
      const body = {
        name: draft.name,
        report_type: draft.report_type,
        filter_params: draft.filter_params,
        format: draft.format,
        recipients: draft.recipients.split(",").map((x) => x.trim()).filter(Boolean),
        channel_id: draft.channel_id,
        cadence: draft.cadence,
        schedule_time: draft.schedule_time,
        schedule_day: draft.schedule_day,
        enabled: draft.enabled,
      };
      if (draft.id) await api.put(`/reports/${draft.id}`, body);
      else await api.post("/reports", body);
      setDraft(null); load(); show("Report schedule saved.");
    } catch (e: any) { show(e.message, true); }
  }
  async function remove(r: ReportSchedule) {
    if (!confirm(`Delete report "${r.name}"?`)) return;
    await api.del(`/reports/${r.id}`); load();
  }
  async function runNow(r: ReportSchedule) {
    setRunning(r.id);
    try {
      await api.post(`/reports/${r.id}/run`);
      show(`Report "${r.name}" queued to run.`);
    } catch (e: any) {
      show("Run failed: " + e.message, true);
    } finally {
      setRunning(null);
      load();
    }
  }
  function edit(r: ReportSchedule) {
    setDraft({
      id: r.id, name: r.name, report_type: r.report_type, filter_params: { ...r.filter_params },
      format: r.format, recipients: (r.recipients || []).join(","), channel_id: r.channel_id,
      cadence: r.cadence, schedule_time: r.schedule_time, schedule_day: r.schedule_day, enabled: r.enabled,
    });
  }
  const setFilter = (patch: any) => setDraft((d) => d && ({ ...d, filter_params: { ...d.filter_params, ...patch } }));

  return (
    <>
      <div className="topbar">
        <h1>Reports</h1>
        {canWrite && <button onClick={() => setDraft({ ...BLANK })}>+ New report</button>}
      </div>
      <div className="content">
        <div className="panel">
          <table>
            <thead>
              <tr>
                <th>Name</th><th>Type</th><th>Cadence</th><th>Channel</th>
                <th>Enabled</th><th>Last run</th><th></th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => {
                const ch = channels.find((c) => c.id === r.channel_id);
                return (
                  <tr key={r.id}>
                    <td>{r.name}</td>
                    <td>{reportTypeLabel(r.report_type)}</td>
                    <td>{r.cadence} @ {r.schedule_time}</td>
                    <td>{ch ? ch.name : `#${r.channel_id}`}</td>
                    <td>{r.enabled ? "yes" : "no"}</td>
                    <td>{r.last_run_at ? fmtDate(r.last_run_at) : <span className="muted">never</span>}</td>
                    <td>
                      {canWrite && (
                        <div className="row" style={{ gap: 4 }}>
                          <button className="ghost" disabled={running === r.id} onClick={() => runNow(r)}>
                            {running === r.id ? "Queuing…" : "Run now"}
                          </button>
                          <button className="ghost" onClick={() => edit(r)}>Edit</button>
                          <button className="ghost" style={{ color: "var(--critical)" }} onClick={() => remove(r)}>Delete</button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {reports.length === 0 && <div className="empty">No scheduled reports. Add one to get a recurring CSV emailed on a cadence.</div>}
        </div>
      </div>

      {draft && (
        <Modal title={draft.id ? "Edit report" : "New report"} onClose={() => setDraft(null)}>
          <div className="form-grid">
            <div className="field"><label>Name</label>
              <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} style={{ width: "100%" }} /></div>
            <div className="field"><label>Report type</label>
              <select value={draft.report_type} onChange={(e) => setDraft({ ...draft, report_type: e.target.value, filter_params: {} })} style={{ width: "100%" }}>
                <option value="certificates">All certificates</option>
                <option value="expiring">Expiring certificates</option>
                <option value="findings">Findings</option>
                <option value="endpoints">Endpoints</option>
              </select></div>
          </div>

          {draft.report_type === "expiring" && (
            <div className="field"><label>Expiring within (days)</label>
              <input type="number" value={draft.filter_params.expiring_within ?? 30}
                onChange={(e) => setFilter({ expiring_within: +e.target.value })} style={{ width: "100%" }} /></div>
          )}
          {draft.report_type === "findings" && (
            <div className="field"><label>Severity (optional)</label>
              <select value={draft.filter_params.severity || ""} onChange={(e) => setFilter({ severity: e.target.value || undefined })} style={{ width: "100%" }}>
                <option value="">All severities</option>
                <option value="info">Info</option>
                <option value="warning">Warning</option>
                <option value="critical">Critical</option>
              </select></div>
          )}

          <div className="form-grid">
            <div className="field"><label>Channel (SMTP)</label>
              <select value={draft.channel_id} onChange={(e) => setDraft({ ...draft, channel_id: +e.target.value })} style={{ width: "100%" }}>
                <option value="">Select a channel…</option>
                {smtpChannels.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select></div>
            <div className="field"><label>Recipients override (comma-separated, optional)</label>
              <input value={draft.recipients} onChange={(e) => setDraft({ ...draft, recipients: e.target.value })} style={{ width: "100%" }} /></div>
          </div>

          <div className="form-grid">
            <div className="field"><label>Cadence</label>
              <select value={draft.cadence} onChange={(e) => setDraft({ ...draft, cadence: e.target.value })} style={{ width: "100%" }}>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select></div>
            <div className="field"><label>Time (HH:MM, app timezone)</label>
              <input value={draft.schedule_time} onChange={(e) => setDraft({ ...draft, schedule_time: e.target.value })} style={{ width: "100%" }} /></div>
            {draft.cadence !== "daily" && (
              <div className="field"><label>{draft.cadence === "weekly" ? "Weekday (0=Mon..6=Sun)" : "Day of month (1-28)"}</label>
                <input type="number" value={draft.schedule_day} onChange={(e) => setDraft({ ...draft, schedule_day: +e.target.value })} style={{ width: "100%" }} /></div>
            )}
          </div>
          <div className="field"><label><input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} /> Enabled</label></div>

          <div className="row" style={{ marginTop: 12 }}>
            <div className="spacer" />
            <button className="secondary" onClick={() => setDraft(null)}>Cancel</button>
            <button onClick={save} disabled={!draft.channel_id}>Save</button>
          </div>
        </Modal>
      )}
      {node}
    </>
  );
}
