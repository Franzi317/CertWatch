import { ReactNode, useMemo, useState } from "react";

export function SeverityBadge({ severity, label }: { severity: string; label?: string }) {
  return <span className={`badge sev-${severity}`}>{label || severity}</span>;
}

export function StatCard({ label, value, severity }: { label: string; value: ReactNode; severity?: string }) {
  return (
    <div className={`stat-card ${severity ? "sev-" + severity : ""}`}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </div>
  );
}

export interface Seg { label: string; value: number; color: string; }

// One horizontal bar per category. Bar widths are scaled to the largest value so
// small categories stay visible; the exact count sits at the right.
export function BarList({ segments }: { segments: Seg[] }) {
  const max = Math.max(1, ...segments.map((s) => s.value));
  return (
    <div className="barlist">
      {segments.map((s) => (
        <div key={s.label} className="barlist-row">
          <span className="barlist-label">{s.label}</span>
          <div className="barlist-track">
            <div className="barlist-fill" title={`${s.label}: ${s.value}`}
              style={{ width: `${(s.value / max) * 100}%`, minWidth: s.value > 0 ? 3 : 0, background: s.color }} />
          </div>
          <span className="barlist-value">{s.value}</span>
        </div>
      ))}
    </div>
  );
}

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  );
}

export function fmtDate(s: string | null | undefined): string {
  if (!s) return "—";
  const d = new Date(s);
  return d.toLocaleString();
}

export function fmtDay(s: string | null | undefined): string {
  if (!s) return "—";
  return new Date(s).toLocaleDateString();
}

// Generic sortable, searchable, paginated table.
export interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => ReactNode;
  value?: (row: T) => string | number;
  wrap?: boolean;
}

export function DataTable<T extends Record<string, any>>({
  rows,
  columns,
  searchKeys,
  pageSize = 25,
  empty = "No records.",
}: {
  rows: T[];
  columns: Column<T>[];
  searchKeys?: (keyof T)[];
  pageSize?: number;
  empty?: string;
}) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const [page, setPage] = useState(0);

  const filtered = useMemo(() => {
    let r = rows;
    if (q && searchKeys) {
      const lc = q.toLowerCase();
      r = r.filter((row) =>
        searchKeys.some((k) => String(row[k] ?? "").toLowerCase().includes(lc))
      );
    }
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      r = [...r].sort((a, b) => {
        const va = col?.value ? col.value(a) : a[sort.key];
        const vb = col?.value ? col.value(b) : b[sort.key];
        if (va == null) return 1;
        if (vb == null) return -1;
        return (va < vb ? -1 : va > vb ? 1 : 0) * sort.dir;
      });
    }
    return r;
  }, [rows, q, sort, columns, searchKeys]);

  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const cur = Math.min(page, pages - 1);
  const slice = filtered.slice(cur * pageSize, cur * pageSize + pageSize);

  function toggleSort(key: string) {
    setSort((s) => (s?.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: 1 }));
  }

  return (
    <div>
      {searchKeys && (
        <div className="row" style={{ marginBottom: 12 }}>
          <input
            className="searchbar"
            placeholder="Filter…"
            value={q}
            onChange={(e) => { setQ(e.target.value); setPage(0); }}
          />
          <span className="muted">{filtered.length} of {rows.length}</span>
        </div>
      )}
      {slice.length === 0 ? (
        <div className="empty">{empty}</div>
      ) : (
        <table>
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key} className={c.wrap ? "wrap" : ""} onClick={() => toggleSort(c.key)}>
                  {c.header}{sort?.key === c.key ? (sort.dir === 1 ? " ▲" : " ▼") : ""}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {slice.map((row, i) => (
              <tr key={i}>
                {columns.map((c) => (
                  <td key={c.key} className={c.wrap ? "wrap" : ""}>
                    {c.render ? c.render(row) : String(row[c.key] ?? "—")}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {pages > 1 && (
        <div className="pagination">
          <button className="secondary" disabled={cur === 0} onClick={() => setPage(cur - 1)}>Prev</button>
          <span>Page {cur + 1} of {pages}</span>
          <button className="secondary" disabled={cur >= pages - 1} onClick={() => setPage(cur + 1)}>Next</button>
        </div>
      )}
    </div>
  );
}

export function useToast() {
  const [toast, setToast] = useState<{ msg: string; error?: boolean } | null>(null);
  const show = (msg: string, error = false) => {
    setToast({ msg, error });
    setTimeout(() => setToast(null), 4000);
  };
  const node = toast ? <div className={`toast ${toast.error ? "error" : ""}`}>{toast.msg}</div> : null;
  return { show, node };
}
