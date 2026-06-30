import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Cert } from "../api";
import { DataTable, SeverityBadge, fmtDate } from "../ui";

const VIEWS: Record<string, string> = {
  all: "",
  expiring90: "expiring_within=90",
  expiring30: "expiring_within=30",
  expired: "expired=true",
  selfsigned: "self_signed=true",
};

export default function Certificates() {
  const [view, setView] = useState("all");
  const [rows, setRows] = useState<Cert[]>([]);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    const qs = VIEWS[view];
    api.get<{ total: number; items: Cert[] }>(`/certificates?limit=1000${qs ? "&" + qs : ""}`)
      .then((r) => { setRows(r.items); setTotal(r.total); }).catch(() => {});
  }, [view]);

  return (
    <>
      <div className="topbar"><h1>Certificates</h1></div>
      <div className="content">
        <div className="panel">
          <div className="row" style={{ marginBottom: 14 }}>
            {Object.keys(VIEWS).map((v) => (
              <button key={v} className={view === v ? "" : "secondary"} onClick={() => setView(v)}>
                {{ all: "All", expiring90: "Expiring ≤90d", expiring30: "Expiring ≤30d", expired: "Expired", selfsigned: "Self-signed" }[v]}
              </button>
            ))}
            <div className="spacer" />
            <span className="muted">{total} unique certificates (deduplicated by fingerprint)</span>
          </div>
          <DataTable
            rows={rows}
            searchKeys={["common_name", "issuer_cn", "fingerprint_sha256"]}
            columns={[
              { key: "common_name", header: "Common Name", wrap: true, render: (c) => <Link to={`/certificates/${c.id}`}>{c.common_name || <span className="mono">{c.fingerprint_sha256.slice(0, 24)}…</span>}</Link> },
              { key: "issuer_cn", header: "Issuer", wrap: true },
              { key: "severity", header: "Status", value: (c) => c.days_until_expiry ?? 99999, render: (c) => <SeverityBadge severity={c.severity} label={c.expiry_phrase} /> },
              { key: "not_after", header: "Expires", value: (c) => c.not_after || "", render: (c) => fmtDate(c.not_after) },
              { key: "public_key_algorithm", header: "Key", render: (c) => `${c.public_key_algorithm}${c.public_key_size ? " " + c.public_key_size : ""}` },
              { key: "flags", header: "Flags", render: (c) => <>{c.self_signed && <span className="tag">self-signed</span>}{c.is_wildcard && <span className="tag">wildcard</span>}{c.is_ca && <span className="tag">CA</span>}</> },
              { key: "endpoint_count", header: "Endpoints" },
            ]}
            empty="No certificates match this view."
          />
        </div>
      </div>
    </>
  );
}
