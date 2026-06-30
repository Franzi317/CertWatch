import { useEffect, useState } from "react";
import { api, Target } from "../api";
import { DataTable, Modal, useToast, fmtDate } from "../ui";

const COMMON_PORTS = [443, 8443, 9443, 636, 993, 995, 465, 587, 3389, 5986];
const BLANK: Partial<Target> = {
  name: "", description: "", target_type: "hostname", value: "", ports: [443],
  environment: "prod", owner: "", tags: [], scan_frequency_minutes: 1440, timeout: 5,
  concurrency: 50, enabled: true, alert_thresholds: [90, 60, 30, 14, 7, 1], use_sni: true,
};

export default function Targets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [editing, setEditing] = useState<Partial<Target> | null>(null);
  const [validation, setValidation] = useState<string>("");
  const { show, node } = useToast();

  const load = () => api.get<Target[]>("/targets").then(setTargets).catch((e) => show(e.message, true));
  useEffect(() => { load(); }, []);

  async function save() {
    if (!editing) return;
    try {
      const body = { ...editing };
      if (editing.id) await api.put(`/targets/${editing.id}`, body);
      else await api.post("/targets", body);
      setEditing(null);
      load();
      show("Target saved.");
    } catch (e: any) { show(e.message, true); }
  }

  async function validate() {
    if (!editing) return;
    try {
      const r = await api.post<any>("/targets/validate", editing);
      setValidation(`${r.host_count} host(s) × ${r.port_count} port(s) = ${r.endpoint_count} endpoint(s)`
        + (r.large_scan ? " ⚠ large scan" : ""));
    } catch (e: any) { setValidation("Invalid: " + e.message); }
  }

  async function scan(t: Target) {
    try { await api.post(`/targets/${t.id}/scan`); show(`Scan started for ${t.name}.`); }
    catch (e: any) { show(e.message, true); }
  }

  async function remove(t: Target) {
    if (!confirm(`Delete target "${t.name}"? This removes its endpoints and history.`)) return;
    await api.del(`/targets/${t.id}`); load(); show("Target deleted.");
  }

  async function toggle(t: Target) {
    await api.put(`/targets/${t.id}`, { ...t, enabled: !t.enabled }); load();
  }

  const set = (patch: Partial<Target>) => setEditing((e) => ({ ...e, ...patch }));

  return (
    <>
      <div className="topbar">
        <h1>Targets</h1>
        <button onClick={() => { setEditing({ ...BLANK }); setValidation(""); }}>+ New target</button>
      </div>
      <div className="content">
        <div className="panel">
          <DataTable
            rows={targets}
            searchKeys={["name", "value", "owner", "environment"]}
            columns={[
              { key: "name", header: "Name", render: (t) => <><b>{t.name}</b>{!t.enabled && <span className="tag" style={{ marginLeft: 6 }}>disabled</span>}</> },
              { key: "target_type", header: "Type" },
              { key: "value", header: "Value", render: (t) => <span className="mono">{t.value}</span> },
              { key: "ports", header: "Ports", render: (t) => t.ports.join(", ") },
              { key: "environment", header: "Env" },
              { key: "owner", header: "Owner" },
              { key: "endpoint_count", header: "Endpoints" },
              { key: "last_scanned_at", header: "Last scan", render: (t) => fmtDate(t.last_scanned_at) },
              {
                key: "actions", header: "", render: (t) => (
                  <div className="row" style={{ gap: 4 }}>
                    <button className="ghost" onClick={() => scan(t)}>Scan</button>
                    <button className="ghost" onClick={() => { setEditing(t); setValidation(""); }}>Edit</button>
                    <button className="ghost" onClick={() => toggle(t)}>{t.enabled ? "Disable" : "Enable"}</button>
                    <button className="ghost" style={{ color: "var(--critical)" }} onClick={() => remove(t)}>Delete</button>
                  </div>
                ),
              },
            ]}
            empty="No targets yet. Create one to start scanning."
          />
        </div>
      </div>

      {editing && (
        <Modal title={editing.id ? "Edit target" : "New target"} onClose={() => setEditing(null)}>
          <div className="form-grid">
            <div className="field"><label>Friendly name</label>
              <input value={editing.name || ""} onChange={(e) => set({ name: e.target.value })} style={{ width: "100%" }} /></div>
            <div className="field"><label>Type</label>
              <select value={editing.target_type} onChange={(e) => set({ target_type: e.target.value })} style={{ width: "100%" }}>
                <option value="hostname">Hostname / FQDN</option>
                <option value="ip">Single IP</option>
                <option value="cidr">CIDR block</option>
                <option value="range">IP range</option>
              </select></div>
            <div className="field" style={{ gridColumn: "1 / 3" }}><label>Value (e.g. host.example.com, 10.0.0.0/24, 10.0.0.10-50)</label>
              <input className="mono" value={editing.value || ""} onChange={(e) => set({ value: e.target.value })} style={{ width: "100%" }} /></div>
            <div className="field" style={{ gridColumn: "1 / 3" }}><label>Description</label>
              <input value={editing.description || ""} onChange={(e) => set({ description: e.target.value })} style={{ width: "100%" }} /></div>
            <div className="field" style={{ gridColumn: "1 / 3" }}><label>Ports</label>
              <div className="pill-row">
                {COMMON_PORTS.map((p) => {
                  const on = (editing.ports || []).includes(p);
                  return <button key={p} className={on ? "" : "secondary"} type="button"
                    onClick={() => set({ ports: on ? editing.ports!.filter((x) => x !== p) : [...(editing.ports || []), p] })}>{p}</button>;
                })}
              </div>
              <input className="mono" style={{ width: "100%", marginTop: 8 }} placeholder="comma-separated ports"
                value={(editing.ports || []).join(",")}
                onChange={(e) => set({ ports: e.target.value.split(",").map((x) => parseInt(x.trim())).filter((n) => !isNaN(n)) })} />
            </div>
            <div className="field"><label>Environment</label>
              <select value={editing.environment} onChange={(e) => set({ environment: e.target.value })} style={{ width: "100%" }}>
                {["prod", "non-prod", "dev", "lab"].map((x) => <option key={x}>{x}</option>)}
              </select></div>
            <div className="field"><label>Owner / team</label>
              <input value={editing.owner || ""} onChange={(e) => set({ owner: e.target.value })} style={{ width: "100%" }} /></div>
            <div className="field"><label>Tags (comma-separated)</label>
              <input value={(editing.tags || []).join(",")} onChange={(e) => set({ tags: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) })} style={{ width: "100%" }} /></div>
            <div className="field"><label>Scan frequency (minutes)</label>
              <input type="number" value={editing.scan_frequency_minutes} onChange={(e) => set({ scan_frequency_minutes: +e.target.value })} style={{ width: "100%" }} /></div>
            <div className="field"><label>Timeout (s)</label>
              <input type="number" step="0.5" value={editing.timeout} onChange={(e) => set({ timeout: +e.target.value })} style={{ width: "100%" }} /></div>
            <div className="field"><label>Concurrency</label>
              <input type="number" value={editing.concurrency} onChange={(e) => set({ concurrency: +e.target.value })} style={{ width: "100%" }} /></div>
            <div className="field" style={{ gridColumn: "1 / 3" }}><label>Alert thresholds (days before expiry, comma-separated)</label>
              <input value={(editing.alert_thresholds || []).join(",")} onChange={(e) => set({ alert_thresholds: e.target.value.split(",").map((x) => parseInt(x.trim())).filter((n) => !isNaN(n)) })} style={{ width: "100%" }} /></div>
            <div className="field"><label><input type="checkbox" checked={!!editing.use_sni} onChange={(e) => set({ use_sni: e.target.checked })} /> Use SNI for hostnames</label></div>
            <div className="field"><label><input type="checkbox" checked={!!editing.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled</label></div>
          </div>
          {validation && <p className="muted">{validation}</p>}
          <div className="row" style={{ marginTop: 12 }}>
            <button className="secondary" onClick={validate}>Validate / preview size</button>
            <div className="spacer" />
            <button className="secondary" onClick={() => setEditing(null)}>Cancel</button>
            <button onClick={save}>Save</button>
          </div>
        </Modal>
      )}
      {node}
    </>
  );
}
