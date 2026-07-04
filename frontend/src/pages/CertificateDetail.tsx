import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, Cert, Issuer, ManagedCertificate, RenewalPolicy } from "../api";
import { Modal, SeverityBadge, fmtDate, useToast } from "../ui";

export default function CertificateDetail() {
  const { id } = useParams();
  const [c, setC] = useState<Cert | null>(null);
  const [managedMatch, setManagedMatch] = useState<ManagedCertificate | null | undefined>(undefined);
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [policies, setPolicies] = useState<RenewalPolicy[]>([]);
  const [showManage, setShowManage] = useState(false);
  const [draft, setDraft] = useState({ issuer_id: 0, renewal_policy_id: 0 });
  const { show, node } = useToast();

  useEffect(() => { api.get<Cert>(`/certificates/${id}`).then(setC).catch(() => {}); }, [id]);
  useEffect(() => {
    if (!id) return;
    // Best-effort: a certificate is "already managed" if some ManagedCertificate
    // currently points at it. Not a dedicated backend check, just a list scan.
    api.get<ManagedCertificate[]>("/managed-certificates")
      .then((rows) => setManagedMatch(rows.find((m) => m.current_certificate_id === Number(id)) || null))
      .catch(() => setManagedMatch(null));
  }, [id]);

  function openManageForm() {
    Promise.all([
      api.get<Issuer[]>("/issuers"),
      api.get<RenewalPolicy[]>("/renewal-policies"),
    ]).then(([is, ps]) => {
      setIssuers(is);
      setPolicies(ps);
      setDraft({ issuer_id: is[0]?.id || 0, renewal_policy_id: ps[0]?.id || 0 });
      setShowManage(true);
    }).catch((e) => show(e.message, true));
  }

  async function submitManage() {
    if (!draft.issuer_id || !draft.renewal_policy_id) {
      show("Pick an issuer and a renewal policy.", true);
      return;
    }
    try {
      const m = await api.post<ManagedCertificate>(`/certificates/${id}/manage`, draft);
      setManagedMatch(m);
      setShowManage(false);
      show("Certificate is now lifecycle-managed.");
    } catch (e: any) { show(e.message, true); }
  }

  if (!c) return <div className="content">Loading…</div>;

  return (
    <>
      <div className="topbar">
        <h1>{c.common_name || "Certificate"}</h1>
        <div className="row" style={{ gap: 12 }}>
          <SeverityBadge severity={c.severity} label={c.expiry_phrase} />
          {managedMatch === null && (
            <button onClick={openManageForm}>Manage this certificate</button>
          )}
          {managedMatch && (
            <Link to="/managed-certificates" className="badge sev-info">Lifecycle-managed ({managedMatch.state})</Link>
          )}
        </div>
      </div>
      <div className="content">
        <div className="panel">
          <h2>Certificate metadata</h2>
          <dl className="kv">
            <dt>Common Name</dt><dd>{c.common_name || "—"}</dd>
            <dt>Subject</dt><dd className="mono">{c.subject}</dd>
            <dt>Subject Alt Names</dt><dd>{c.sans.length ? c.sans.join(", ") : "—"}</dd>
            <dt>Issuer</dt><dd className="mono">{c.issuer}</dd>
            <dt>Serial</dt><dd className="mono">{c.serial_number}</dd>
            <dt>SHA-256 fingerprint</dt><dd className="mono">{c.fingerprint_sha256}</dd>
            <dt>Signature algorithm</dt><dd>{c.signature_algorithm}</dd>
            <dt>Public key</dt><dd>{c.public_key_algorithm}{c.public_key_size ? ` (${c.public_key_size} bit)` : ""}</dd>
            <dt>Not before</dt><dd>{fmtDate(c.not_before)}</dd>
            <dt>Not after</dt><dd>{fmtDate(c.not_after)} ({c.expiry_phrase})</dd>
            <dt>Chain length</dt><dd>{c.chain_length}</dd>
            <dt>Flags</dt><dd>
              {c.self_signed && <span className="tag">self-signed</span>}
              {c.is_wildcard && <span className="tag">wildcard</span>}
              {c.is_ca && <span className="tag">CA</span>}
              {!c.self_signed && !c.is_wildcard && !c.is_ca && "—"}
            </dd>
            <dt>First seen</dt><dd>{fmtDate(c.first_seen)}</dd>
            <dt>Last seen</dt><dd>{fmtDate(c.last_seen)}</dd>
          </dl>
        </div>

        <div className="panel">
          <h2>Bound endpoints ({c.endpoints?.length || 0})</h2>
          <table>
            <thead><tr><th>Endpoint</th><th>Target</th><th>SNI</th><th>Status</th></tr></thead>
            <tbody>
              {(c.endpoints || []).map((e) => (
                <tr key={e.id}>
                  <td><Link to={`/endpoints/${e.id}`}>{e.host || e.ip}:{e.port}</Link></td>
                  <td>{e.target_name}</td>
                  <td className="mono">{e.sni || "—"}</td>
                  <td><SeverityBadge severity={e.severity} label={e.last_status_phrase} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <h2>Observation history</h2>
          <table>
            <thead><tr><th>When</th><th>Status</th><th>Change</th><th>SNI</th></tr></thead>
            <tbody>
              {(c.observations || []).map((o) => (
                <tr key={o.id}>
                  <td>{fmtDate(o.observed_at)}</td>
                  <td>{o.status_phrase}</td>
                  <td>{o.change_status || "—"}</td>
                  <td className="mono">{o.sni_used || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {c.pem && (
          <div className="panel">
            <h2>PEM</h2>
            <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 11 }}>{c.pem}</pre>
          </div>
        )}
      </div>

      {showManage && (
        <Modal title="Manage this certificate" onClose={() => setShowManage(false)}>
          <div className="form-grid">
            <div className="field"><label>Issuer</label>
              <select
                value={draft.issuer_id}
                onChange={(e) => setDraft({ ...draft, issuer_id: Number(e.target.value) })}
                style={{ width: "100%" }}
              >
                {issuers.length === 0 && <option value={0}>No issuers configured</option>}
                {issuers.map((i) => <option key={i.id} value={i.id}>{i.name}</option>)}
              </select>
            </div>
            <div className="field"><label>Renewal policy</label>
              <select
                value={draft.renewal_policy_id}
                onChange={(e) => setDraft({ ...draft, renewal_policy_id: Number(e.target.value) })}
                style={{ width: "100%" }}
              >
                {policies.length === 0 && <option value={0}>No renewal policies configured</option>}
                {policies.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
          </div>
          <div className="row" style={{ marginTop: 12 }}>
            <div className="spacer" />
            <button className="secondary" onClick={() => setShowManage(false)}>Cancel</button>
            <button onClick={submitManage} disabled={issuers.length === 0 || policies.length === 0}>Manage</button>
          </div>
        </Modal>
      )}
      {node}
    </>
  );
}
