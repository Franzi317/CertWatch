"""CSV export helper for list endpoints (Phase 2, Task 1)."""
from __future__ import annotations

import csv
import io


def rows_to_csv(fieldnames: list[str], rows: list[dict]) -> str:
    """Project each row dict down to `fieldnames` and render as CSV text.

    Extra keys in a row are ignored; missing keys become an empty cell.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in fieldnames})
    return buf.getvalue()
