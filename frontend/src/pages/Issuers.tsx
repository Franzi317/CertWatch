import { useEffect, useState } from "react";
import { api, Issuer } from "../api";
import { Modal, fmtDate, useToast } from "../ui";

type IssuerDraft = {
  id?: number; name: string; issuer_type: string; enabled: boolean; config: any;
};
const ADCS_BLANK: IssuerDraft = {
  name: "AD CS", issuer_type: "adcs", enabled: true,
  config: { server_url: "", ca_config: "", template: "", username: "", password: "" },
};
const ACME_BLANK: IssuerDraft = {
  name: "ACME CA", issuer_type: "acme", enabled: true,
  config: { directory_url: "", contact_email: "" },
};

export default function Issuers() {
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [draft, setDraft] = useState<IssuerDraft | null>(null);
  const [testing, setTesting] = useState<number | null>(null);
  const { show, node } = useToast();

  const load = () => { api.get<Issuer[]>("/issuers").then(setIssuers).catch(() => {}); };
  useEffect(() => { load(); }, []);

  async function save() {
    if (!draft) return;
    try {
      if (draft.id) await api.put(`/issuers/${draft.id}`, draft);
      else await api.post("/issuers", draft);
      setDraft(null); load(); show("Issuer saved.");
    } catch (e: any) { show(e.message, true); }
  }
  async function test(i: Issuer) {
    setTesting(i.id);
    try {
      const res = await api.post<{ ok: boolean; detail: string }>(`/issuers/${i.id}/test`);
      show(res.ok ? `Test succeeded: ${res.detail}` : `Test failed: ${res.detail}`, !res.ok);
    } catch (e: any) {
      show("Test failed: " + e.message, true);
    } finally {
      setTesting(null);
      load();
    }
  }
  async function remove(i: Issuer) {
    if (!confirm(`Delete issuer "${i.name}"?`)) return;
    await api.del(`/issuers/${i.id}`); load();
  }
  function edit(i: Issuer) {
    // Secrets are never returned; start blank and only send if changed.
    setDraft({ id: i.id, name: i.name, issuer_type: i.issuer_type, enabled: i.enabled, config: { ...i.config } });
  }
  const setCfg = (patch: any) => setDraft((d) => d && ({ ...d, config: { ...d.config, ...patch } }));

  return (
    <>
      <div className="topbar"><h1>Issuers</h1></div>
      <div className="content">
        <div className="panel">
          <div className="row">
            <h2 style={{ margin: 0 }}>CA integrations</h2>
            <div className="spacer" />
            <button className="secondary" onClick={() => setDraft({ ...ADCS_BLANK, config: { ...ADCS_BLANK.config } })}>+ AD CS</button>
            <button className="secondary" onClick={() => setDraft({ ...ACME_BLANK, config: { ...ACME_BLANK.config } })}>+ ACME</button>
          </div>
          <table style={{ marginTop: 12 }}>
            <thead><tr><th>Name</th><th>Type</th><th>Enabled</th><th>Last test</th><th></th></tr></thead>
            <tbody>
              {issuers.map((i) => (
                <tr key={i.id}>
                  <td>{i.name}</td>
                  <td>{i.issuer_type === "adcs" ? "AD CS" : "ACME"}</td>
                  <td>{i.enabled ? "yes" : "no"}</td>
                  <td>
                    {i.last_test_at ? (
                      <>
                        <span className={`badge ${i.last_test_ok ? "sev-healthy" : "sev-critical"}`}>
                          {i.last_test_ok ? "ok" : "failed"}
                        </span>
                        <span className="muted" style={{ marginLeft: 6 }}>{fmtDate(i.last_test_at)}</span>
                      </>
                    ) : <span className="muted">never tested</span>}
                  </td>
                  <td><div className="row" style={{ gap: 4 }}>
                    <button className="ghost" disabled={testing === i.id} onClick={() => test(i)}>
                      {testing === i.id ? "Testing…" : "Test"}
                    </button>
                    <button className="ghost" onClick={() => edit(i)}>Edit</button>
                    <button className="ghost" style={{ color: "var(--critical)" }} onClick={() => remove(i)}>Delete</button>
                  </div></td>
                </tr>
              ))}
            </tbody>
          </table>
          {issuers.length === 0 && <div className="empty">No issuers configured. Add AD CS or an ACME CA to enable certificate issuance.</div>}
        </div>
      </div>

      {draft && (
        <Modal title={draft.id ? "Edit issuer" : "New issuer"} onClose={() => setDraft(null)}>
          <div className="form-grid">
            <div className="field"><label>Name</label>
              <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} style={{ width: "100%" }} /></div>
            {!draft.id && (
              <div className="field"><label>Type</label>
                <select
                  value={draft.issuer_type}
                  onChange={(e) => setDraft({
                    ...draft,
                    issuer_type: e.target.value,
                    config: e.target.value === "adcs" ? { ...ADCS_BLANK.config } : { ...ACME_BLANK.config },
                  })}
                  style={{ width: "100%" }}
                >
                  <option value="adcs">AD CS (certsrv)</option>
                  <option value="acme">ACME (http-01)</option>
                </select></div>
            )}
          </div>

          {draft.issuer_type === "adcs" ? (
            <div className="form-grid">
              <div className="field"><label>Server URL</label>
                <input value={draft.config.server_url || ""} onChange={(e) => setCfg({ server_url: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>CA config (CAName\hostname)</label>
                <input value={draft.config.ca_config || ""} onChange={(e) => setCfg({ ca_config: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>Template</label>
                <input value={draft.config.template || ""} onChange={(e) => setCfg({ template: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>Username</label>
                <input value={draft.config.username || ""} onChange={(e) => setCfg({ username: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>Password {draft.id && <span className="muted">(leave blank to keep existing)</span>}</label>
                <input type="password" value={draft.config.password || ""} onChange={(e) => setCfg({ password: e.target.value })} style={{ width: "100%" }} /></div>
            </div>
          ) : (
            <div className="form-grid">
              <div className="field"><label>Directory URL</label>
                <input value={draft.config.directory_url || ""} onChange={(e) => setCfg({ directory_url: e.target.value })} style={{ width: "100%" }} /></div>
              <div className="field"><label>Contact email</label>
                <input value={draft.config.contact_email || ""} onChange={(e) => setCfg({ contact_email: e.target.value })} style={{ width: "100%" }} /></div>
            </div>
          )}
          <div className="field"><label><input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} /> Enabled</label></div>
          <div className="row" style={{ marginTop: 12 }}>
            <div className="spacer" />
            <button className="secondary" onClick={() => setDraft(null)}>Cancel</button>
            <button onClick={save}>Save</button>
          </div>
        </Modal>
      )}
      {node}
    </>
  );
}
