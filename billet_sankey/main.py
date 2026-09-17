from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


REQUIRED_COLUMNS = ("Unit", "Office", "Workrole")


def read_rows(csv_path: Path) -> list[tuple[str, str, str]]:
    """Read CSV rows and return (Unit, Office, Workrole) tuples.

    Empty or incomplete rows are skipped; basic header validation is performed.
    """
    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise SystemExit(f"{csv_path}: missing header row")

        missing = [column for column in REQUIRED_COLUMNS if column not in reader.fieldnames]
        if missing:
            raise SystemExit(
                f"{csv_path}: missing required columns: {', '.join(missing)}"
            )

        rows: list[tuple[str, str, str]] = []
        skipped = 0
        for line_number, row in enumerate(reader, start=2):
            unit = (row.get("Unit") or "").strip()
            office = (row.get("Office") or "").strip()
            workrole = (row.get("Workrole") or "").strip()

            if not office or not workrole:
                skipped += 1
                continue

            rows.append((unit, office, workrole))

        if not rows:
            raise SystemExit(f"{csv_path}: no usable rows found")

        if skipped:
            print(f"Skipped {skipped} incomplete row(s).", file=sys.stderr)

        return rows


def office_sort_key(code: str) -> tuple[str, int, str]:
    """Sort key for office / prefix codes like C1, C12, X432.

    Orders primarily by leading letter, then by numeric part when present,
    with shorter prefixes (e.g. "C") appearing before longer ones ("C1", "C12").
    """
    if not code:
        return ("", 0, code)
    m = re.match(r"^([A-Za-z])(\d+)$", code)
    if m:
        letter, digits = m.groups()
        return (letter, int(digits), code)
    # Fallback: treat first character as letter and length as depth.
    letter = code[0] if code[0].isalpha() else ""
    return (letter, len(code), code)


def build_sankey(rows: list[tuple[str, str, str]]) -> dict:
    """Build a tree-like visualization using Plotly treemap.

    Hierarchy:
      root "Office"
        → office prefixes (C, C1, C13, ...)
          → leaf nodes for Workrole at that exact Office (Workrole|Office).

    Unit is ignored in this view; we only show Office → Workrole.
    """
    # Compute counts per prefix and per leaf.
    prefix_counts: defaultdict[str, int] = defaultdict(int)
    leaf_counts: defaultdict[tuple[str, str], int] = defaultdict(int)

    for _unit, office, workrole in rows:
        # Count leaf occurrences (Office, Workrole).
        leaf_counts[(office, workrole)] += 1

        # Count flows through each prefix of this Office.
        for depth in range(1, len(office) + 1):
            prefix = office[:depth]
            prefix_counts[prefix] += 1

    # Build node list: root, prefixes, then leaves.
    labels: list[str] = []
    ids: list[str] = []
    parents: list[str] = []
    values: list[int] = []

    # Root node
    root_label = "Office"
    root_id = "root"
    labels.append(root_label)
    ids.append(root_id)
    parents.append("")
    values.append(sum(leaf_counts.values()))

    # Office prefixes
    # Ensure deterministic ordering: shorter prefixes first, then lexicographic by office_sort_key.
    sorted_prefixes = sorted(prefix_counts.keys(), key=office_sort_key)
    for prefix in sorted_prefixes:
        if not prefix:
            continue
        labels.append(prefix)
        ids.append(f"prefix:{prefix}")
        # Parent is either root (for first char) or previous prefix.
        if len(prefix) == 1:
            parents.append(root_id)
        else:
            parents.append(f"prefix:{prefix[:-1]}")
        values.append(prefix_counts[prefix])

    # Leaves: group all workroles that exist at the same Office path into one leaf.
    # Each leaf label lists consolidated counts per workrole, e.g. "3 x TDNA, 2 x EA".
    office_to_roles: dict[str, list[tuple[str, int]]] = {}
    for (office, workrole), count in sorted(leaf_counts.items(), key=lambda item: (office_sort_key(item[0][0]), item[0][1])):
        office_to_roles.setdefault(office, []).append((workrole, count))

    for office, roles in sorted(office_to_roles.items(), key=lambda item: office_sort_key(item[0])):
        # Build a combined label, sorted by count (descending), then workrole.
        parts = [
            f"{count} x {workrole}"
            for workrole, count in sorted(roles, key=lambda rc: (-rc[1], rc[0]))
        ]
        leaf_label = "<br>".join(parts)
        labels.append(leaf_label)
        ids.append(f"leaf:{office}")
        parents.append(f"prefix:{office}")
        values.append(sum(count for _workrole, count in roles))

    fig = {
        "data": [
            {
                "type": "treemap",
                "labels": labels,
                "ids": ids,
                "parents": parents,
                "values": values,
                "branchvalues": "total",
                "tiling": {
                    "pad": 4,
                },
                "marker": {
                    "line": {"width": 0.5, "color": "rgba(80, 80, 80, 0.6)"},
                },
                "hovertemplate": "%{label}<br>Count: %{value}<extra></extra>",
            }
        ],
        "layout": {
            "template": "plotly_white",
            "title": {
                "text": "Office → Workrole Tree",
                "x": 0.5,
            },
            "font": {"size": 12},
            "margin": {"l": 20, "r": 20, "t": 60, "b": 20},
            "width": 1400,
            "height": 900,
        },
        "summary": {
            "rows": len(rows),
            "nodes": len(labels),
            "max_office_len": max(len(office) for _, office, _ in rows),
        },
    }

    return fig


def render_html(fig: dict) -> str:
    data_json = json.dumps(fig["data"]).replace("</", "<\/")
    layout_json = json.dumps(fig["layout"]).replace("</", "<\/")
    summary = fig["summary"]

    return f"""<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>Office → Workrole Tree</title>
    <script src=\"https://cdn.plot.ly/plotly-2.35.2.min.js\"></script>
    <style>
      html, body {{ height: 100%; margin: 0; }}
      body {{ font-family: system-ui, sans-serif; }}
      #meta {{ padding: 12px 20px 0; color: #444; font-size: 14px; }}
      #chart {{ width: 100vw; height: calc(100vh - 56px); }}
    </style>
  </head>
  <body>
    <div id=\"meta\">
      Rows: {summary['rows']} · Nodes: {summary['nodes']} · Max office depth: {summary['max_office_len']}
    </div>
    <div id=\"chart\"></div>
    <script>
      const data = {data_json};
      const layout = {layout_json};
      Plotly.newPlot('chart', data, layout, {{responsive: true, displaylogo: false}});
    </script>
  </body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an Office → Workrole tree from a CSV with Unit, Office, and Workrole columns.",
    )
    parser.add_argument("csv_path", type=Path, help="Input CSV file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("sankey.html"),
        help="Output HTML file (default: sankey.html)",
    )
    args = parser.parse_args()

    rows = read_rows(args.csv_path)
    fig = build_sankey(rows)
    args.output.write_text(render_html(fig), encoding="utf-8")

    print(f"Wrote {args.output} from {len(rows)} row(s).", file=sys.stderr)


if __name__ == "__main__":
    main()
