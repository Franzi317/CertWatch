import { useEffect, useState } from "react";
import { api, Channel } from "../api";
import { Modal, useToast } from "../ui";

type ChannelDraft = {
  id?: number; name: string; channel_type: string; enabled: boolean; re_alert_hours: number; config: any;
};
const SMTP_BLANK: ChannelDraft = {
  name: "SMTP email", channel_type: "smtp", enabled: true, re_alert_hours: 24,
  config: { host: "", port: 587, use_starttls: true, use_tls: false, username: "", password: "", from_address: "certwatch@example.com", recipients: [] },
};
const HOOK_BLANK: ChannelDraft = {
  name: "Teams webhook", channel_type: "teams", enabled: true, re_alert_hours: 24,
  config: { url: "", format: "teams" },
};

export default function Settings() {
  const [channels, setChannels] = useState<Channel[]>([]);
  const [draft, setDraft] = useState<ChannelDraft | null>(null);
  const [sys, setSys] = useState<Record<string, any>>({});
  const { show, node } = useToast();

  const load = () => {
    api.get<Channel[]>("/channels").then(setChannels).catch(() => {});
    api.get<Record<string, any>>("/settings").then(setSys).catch(() => {});
  };
  useEffect(() => { load(); }, []);

  async function saveChannel() {
    if (!draft) return;
    try {
      if (draft.id) await api.put(`/channels/${draft.id}`, draft);
      else await api.post("/channels", draft);
      setDraft(null); load(); show("Channel saved.");
    } catch (e: any) { show(e.message, true); }
  }
  async function test(c: Channel) {
    try { await api.post(`/channels/${c.id}/test`); show("Test notification sent."); }
    catch (e: any) { show("Test failed: " + e.message, true); }
  }
  async function removeChannel(c: Channel) {
    if (!confirm(`Delete channel "${c.name}"?`)) return;
    await api.del(`/channels/${c.id}`); load();
  }
  async function saveSys() {
    await api.put("/settings", sys); show("Settings saved."); load();
  }
  function editChannel(c: Channel) {
    // Secrets are never returned; start blank and only send if changed.
    setDraft({ id: c.id, name: c.name, channel_type: c.channel_type, enabled: c.enabled, re_alert_hours: c.re_alert_hours, config: { ...c.config_summary } });
  }
  const setCfg = (patch: any) => setDraft((d) => d && ({ ...d, config: { ...d.config, ...patch } }));

  return (
    <>
      <div className="topbar"><h1>Settings</h1></div>
      <div className="content">
        <div className="panel">
          <div className="row">
            <h2 style={{ margin: 0 }}>Notification channels</h2>
            <div className="spacer" />
            <button className="secondary" onClick={() => setDraft({ ...SMTP_BLANK })}>+ SMTP</button>
            <button className="secondary" onClick={() => setDraft({ ...HOOK_BLANK })}>+ Teams / Webhook</button>
          </div>
          <table style={{ marginTop: 12 }}>
            <thead><tr><th>Name</th><th>Type</th><th>Enabled</th><th>Re-alert</th><th>Config</th><th></th></tr></thead>
            <tbody>
              {channels.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{c.channel_type}</td>
                  <td>{c.enabled ? "yes" : "no"}</td>
                  <td>{c.re_alert_hours}h</td>
                  <td className="mono muted">{JSON.stringify(c.config_summary)}</td>
                  <td><div className="row" style={{ gap: 4 }}>
                    <button className="ghost" onClick={() => test(c)}>Test</button>
                    <button className="ghost" onClick={() => editChannel(c)}>Edit</button>
                    <button className="ghost" style={{ color: "var(--critical)" }} onClick={() => removeChannel(c)}>Delete</button>
                  </div></td>
                </tr>
              ))}
            </tbody>
          </table>
          {channels.length === 0 && <div className="empty">No channels configured. Add SMTP or a webhook to receive alerts.</div>}
        </div>

        <div className="panel">
          <h2>Scan & alert defaults</h2>
          <div className="form-grid">
            <div className="field"><label>App base URL (used in alert links)</label>
              <input value={sys.app_base_url || ""} onChange={(e) => setSys({ ...sys, app_base_url: e.target.value })} style={{ width: "100%" }} /></div>
            <div className="field"><label>Scan-failure alert threshold (consecutive failures)</label>
              <input type="number" value={sys.scan_failure_threshold ?? 3} onChange={(e) => setSys({ ...sys, scan_failure_threshold: +e.target.value })} style={{ width: "100%" }} /></div>
            <div className="field"><label><input type="checkbox" checked={!!sys.alert_on_self_signed} onChange={(e) => setSys({ ...sys, alert_on_self_signed: e.target.checked })} /> Alert on self-signed certificates</label></div>
          </div>
          <button onClick={saveSys}>Save settings</button>
        </div>
      </div>

      {draft && (
        <Modal title={draft.id ? "Edit channel" : "New channel"} onClose={() => setDraft(null)}>
          <div className="form-grid">
            <div className="field"><label>Name</label><input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} style={{ width: "100%" }} /></div>
            <div className="field"><label>Re-alert interval (hours)</label><input type="number" value={draft.re_alert_hours} onChange={(e) => setDraft({ ...draft, re_alert_hours: +e.target.value })} style={{ width: "100%" }} /></div>
          </div>

          {draft.channel_type === "smtp" ? (
            <div className="form-grid">
              <div className="field"><label>SMTP host</label><input value={draft.config.host || ""} onChange={(e) => setCfg({ host: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>Port</label><input type="number" value={draft.config.port || 587} onChange={(e) => setCfg({ port: +e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label><input type="checkbox" checked={!!draft.config.use_starttls} onChange={(e) => setCfg({ use_starttls: e.target.checked })} /> STARTTLS</label></div>
              <div className="field"><label><input type="checkbox" checked={!!draft.config.use_tls} onChange={(e) => setCfg({ use_tls: e.target.checked })} /> Implicit TLS (SMTPS)</label></div>
              <div className="field"><label>Username</label><input value={draft.config.username || ""} onChange={(e) => setCfg({ username: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>Password {draft.id && <span className="muted">(blank = unchanged)</span>}</label><input type="password" value={draft.config.password || ""} onChange={(e) => setCfg({ password: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>From address</label><input value={draft.config.from_address || ""} onChange={(e) => setCfg({ from_address: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>Recipients (comma-separated)</label><input value={(draft.config.recipients || []).join(",")} onChange={(e) => setCfg({ recipients: e.target.value.split(",").map((x: string) => x.trim()).filter(Boolean) })} style={{ width: "100%" }} /></div>
            </div>
          ) : (
            <div className="form-grid">
              <div className="field"><label>Type</label>
                <select value={draft.channel_type} onChange={(e) => setDraft({ ...draft, channel_type: e.target.value })} style={{ width: "100%" }}>
                  <option value="teams">Microsoft Teams (MessageCard)</option>
                  <option value="webhook">Generic JSON webhook</option>
                </select></div>
              <div className="field"><label>Format</label>
                <select value={draft.config.format || "teams"} onChange={(e) => setCfg({ format: e.target.value })} style={{ width: "100%" }}>
                  <option value="teams">Teams MessageCard</option>
                  <option value="generic">Generic JSON</option>
                </select></div>
              <div className="field" style={{ gridColumn: "1 / 3" }}><label>Webhook URL {draft.id && <span className="muted">(blank = unchanged)</span>}</label>
                <input type="password" value={draft.config.url || ""} onChange={(e) => setCfg({ url: e.target.value })} style={{ width: "100%" }} /></div>
            </div>
          )}
          <div className="field"><label><input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} /> Enabled</label></div>
          <div className="row" style={{ marginTop: 12 }}>
            <div className="spacer" />
            <button className="secondary" onClick={() => setDraft(null)}>Cancel</button>
            <button onClick={saveChannel}>Save</button>
          </div>
        </Modal>
      )}
      {node}
    </>
  );
}
