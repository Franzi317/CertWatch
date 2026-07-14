import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { CaCertificate, listCaCertificates } from "../api";
import { DataTable, SeverityBadge, fmtDate } from "../ui";

export default function CaCertificates() {
  const [rows, setRows] = useState<CaCertificate[]>([]);

  useEffect(() => {
    listCaCertificates().then((r) => setRows(r.items)).catch(() => {});
  }, []);

  return (
    <>
      <div className="topbar"><h1>CA Certificates</h1></div>
      <div className="content">
        <div className="panel">
          <div className="row" style={{ marginBottom: 14 }}>
            <span className="muted">
              {rows.length} CA certificate{rows.length === 1 ? "" : "s"} observed in scanned
              chains (sorted by soonest expiry)
            </span>
          </div>
          <DataTable
            rows={rows}
            searchKeys={["common_name", "issuer_cn", "fingerprint_sha256"]}
            columns={[
              { key: "common_name", header: "Subject / CN", wrap: true, render: (c) => <Link to={`/certificates/${c.id}`}>{c.common_name || <span className="mono">{c.fingerprint_sha256.slice(0, 24)}…</span>}</Link> },
              { key: "issuer_cn", header: "Issuer", wrap: true },
              { key: "role", header: "Role", value: (c) => (c.is_root ? "Root" : "Intermediate"), render: (c) => <span className="tag">{c.is_root ? "Root" : "Intermediate"}</span> },
              { key: "severity", header: "Status", value: (c) => c.days_until_expiry ?? 99999, render: (c) => <SeverityBadge severity={c.severity} label={c.expiry_phrase} /> },
              { key: "not_after", header: "Expires", value: (c) => c.not_after || "", render: (c) => fmtDate(c.not_after) },
              { key: "dependent_count", header: "Dependents" },
            ]}
            empty="No CA certificates observed yet. Requires Python 3.13+ full-chain capture during scans."
          />
        </div>
      </div>
    </>
  );
}
