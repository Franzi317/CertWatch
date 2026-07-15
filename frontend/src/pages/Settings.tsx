import { useEffect, useState } from "react";
import { api, Channel, WatchedDomain } from "../api";
import { Modal, fmtDate, useToast } from "../ui";

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
const SLACK_BLANK: ChannelDraft = {
  name: "Slack", channel_type: "slack", enabled: true, re_alert_hours: 24,
  config: { url: "", format: "slack", min_severity: "" },
};
const PAGERDUTY_BLANK: ChannelDraft = {
  name: "PagerDuty", channel_type: "pagerduty", enabled: true, re_alert_hours: 24,
  config: { routing_key: "", events_url: "", min_severity: "critical" },
};

export default function Settings() {
  const [channels, setChannels] = useState<Channel[]>([]);
  const [draft, setDraft] = useState<ChannelDraft | null>(null);
  const [sys, setSys] = useState<Record<string, any>>({});
  const [domains, setDomains] = useState<WatchedDomain[]>([]);
  const [newDomain, setNewDomain] = useState("");
  const [checking, setChecking] = useState<number | null>(null);
  const { show, node } = useToast();

  const load = () => {
    api.get<Channel[]>("/channels").then(setChannels).catch(() => {});
    api.get<Record<string, any>>("/settings").then(setSys).catch(() => {});
    api.get<{ items: WatchedDomain[] }>("/watched-domains").then((r) => setDomains(r.items)).catch(() => {});
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
  async function addDomain() {
    const domain = newDomain.trim();
    if (!domain) return;
    try {
      await api.post("/watched-domains", { domain });
      setNewDomain(""); load(); show("Domain added.");
    } catch (e: any) { show(e.message, true); }
  }
  async function removeDomain(d: WatchedDomain) {
    if (!confirm(`Stop watching "${d.domain}"?`)) return;
    try { await api.del(`/watched-domains/${d.id}`); load(); }
    catch (e: any) { show(e.message, true); }
  }
  async function checkDomain(d: WatchedDomain) {
    setChecking(d.id);
    try {
      await api.post(`/watched-domains/${d.id}/check`);
      show(`Check queued for ${d.domain}.`);
      load();
    } catch (e: any) {
      show("Check failed: " + e.message, true);
    } finally {
      setChecking(null);
    }
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
            <button className="secondary" onClick={() => setDraft({ ...SLACK_BLANK })}>+ Slack</button>
            <button className="secondary" onClick={() => setDraft({ ...PAGERDUTY_BLANK })}>+ PagerDuty</button>
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

        <div className="panel">
          <div className="row">
            <h2 style={{ margin: 0 }}>Watched domains (CT monitoring)</h2>
            <div className="spacer" />
            <input
              placeholder="example.com"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") addDomain(); }}
              style={{ width: 220 }}
            />
            <button className="secondary" onClick={addDomain}>+ Add domain</button>
          </div>
          <table style={{ marginTop: 12 }}>
            <thead><tr><th>Domain</th><th>Enabled</th><th>Last checked</th><th>Last crt.sh ID</th><th></th></tr></thead>
            <tbody>
              {domains.map((d) => (
                <tr key={d.id}>
                  <td>{d.domain}</td>
                  <td>{d.enabled ? "yes" : "no"}</td>
                  <td>{d.last_checked_at ? fmtDate(d.last_checked_at) : <span className="muted">never</span>}</td>
                  <td className="mono">{d.last_crtsh_id ?? "—"}</td>
                  <td><div className="row" style={{ gap: 4 }}>
                    <button className="ghost" disabled={checking === d.id} onClick={() => checkDomain(d)}>
                      {checking === d.id ? "Checking…" : "Check now"}
                    </button>
                    <button className="ghost" style={{ color: "var(--critical)" }} onClick={() => removeDomain(d)}>Delete</button>
                  </div></td>
                </tr>
              ))}
            </tbody>
          </table>
          {domains.length === 0 && <div className="empty">No watched domains. Add one to discover certificates via Certificate Transparency logs.</div>}
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
          ) : draft.channel_type === "slack" ? (
            <div className="form-grid">
              <div className="field" style={{ gridColumn: "1 / 3" }}>
                <label>Incoming webhook URL {draft.config.url_set ? <span className="muted">(configured — leave blank to keep)</span> : draft.id && <span className="muted">(blank = unchanged)</span>}</label>
                <input type="password" value={draft.config.url || ""} onChange={(e) => setCfg({ url: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>Minimum severity</label>
                <select value={draft.config.min_severity || ""} onChange={(e) => setCfg({ min_severity: e.target.value })} style={{ width: "100%" }}>
                  <option value="">All severities</option>
                  <option value="info">Info and above</option>
                  <option value="warning">Warning and above</option>
                  <option value="critical">Critical only</option>
                </select></div>
            </div>
          ) : draft.channel_type === "pagerduty" ? (
            <div className="form-grid">
              <div className="field" style={{ gridColumn: "1 / 3" }}>
                <label>Routing / integration key {draft.config.routing_key_set ? <span className="muted">(configured — leave blank to keep)</span> : draft.id && <span className="muted">(blank = unchanged)</span>}</label>
                <input type="password" value={draft.config.routing_key || ""} onChange={(e) => setCfg({ routing_key: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>Events API URL <span className="muted">(optional — defaults to events.pagerduty.com)</span></label>
                <input value={draft.config.events_url || ""} onChange={(e) => setCfg({ events_url: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>Minimum severity</label>
                <select value={draft.config.min_severity || "critical"} onChange={(e) => setCfg({ min_severity: e.target.value })} style={{ width: "100%" }}>
                  <option value="">All severities</option>
                  <option value="info">Info and above</option>
                  <option value="warning">Warning and above</option>
                  <option value="critical">Critical only</option>
                </select></div>
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
