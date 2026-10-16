"""Report generation: Markdown + self-contained HTML."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Template

from reconx.core import console
from reconx.core.config import OUTPUT_DIR
from reconx.core.report import ScanReport

MD_TEMPLATE = """# ReconX Report - {{ target }}

- **Operator:** {{ operator }}
- **Mulai:** {{ started_at }}
- **Selesai:** {{ finished_at }}
- **Durasi:** {{ "%.0f"|format(duration) }} detik
- **Mode kecepatan:** {{ speed }}

## Ringkasan Temuan

| Kategori | Jumlah |
| --- | ---: |
{% for label, count in summary.items() -%}
| {{ label }} | {{ count }} |
{% endfor %}

## Tool yang Dijalankan

{% for line in tool_log -%}
- {{ line }}
{% endfor %}

{% if subdomains %}
## Subdomain ({{ subdomains|length }})

{% for item in subdomains -%}
- {{ item }}
{% endfor %}
{% endif %}

{% if live_hosts %}
## Live Hosts ({{ live_hosts|length }})

{% for item in live_hosts -%}
- {{ item }}
{% endfor %}
{% endif %}

{% if nuclei_findings %}
## Nuclei Findings ({{ nuclei_findings|length }})

{% for item in nuclei_findings -%}
- `{{ item }}`
{% endfor %}
{% endif %}

{% if nmap_findings %}
## Nmap Open Ports ({{ nmap_findings|length }})

{% for item in nmap_findings -%}
- `{{ item }}`
{% endfor %}
{% endif %}

{% if xray_findings %}
## Xray Findings ({{ xray_findings|length }})

{% for item in xray_findings -%}
- `{{ item }}`
{% endfor %}
{% endif %}

{% if dns_records %}
## DNS Records ({{ dns_records|length }})

{% for item in dns_records -%}
- `{{ item }}`
{% endfor %}
{% endif %}

{% if zone_transfer %}
## Zone Transfer (TEMUAN SERIUS)

{% for item in zone_transfer -%}
- {{ item }}
{% endfor %}
{% endif %}

{% if content_findings %}
## Content Discovery ({{ content_findings|length }})

{% for item in content_findings -%}
- `{{ item }}`
{% endfor %}
{% endif %}

{% if parameter_findings %}
## Parameter Tersembunyi ({{ parameter_findings|length }})

{% for item in parameter_findings -%}
- {{ item }}
{% endfor %}
{% endif %}

{% if sqli_findings %}
## SQL Injection ({{ sqli_findings|length }})

{% for item in sqli_findings -%}
- {{ item }}
{% endfor %}
{% endif %}

{% if xss_findings %}
## XSS ({{ xss_findings|length }})

{% for item in xss_findings -%}
- {{ item }}
{% endfor %}
{% endif %}

{% if cloud_findings %}
## Cloud Storage ({{ cloud_findings|length }})

{% for item in cloud_findings -%}
- {{ item }}
{% endfor %}
{% endif %}

{% if takeover_candidates %}
## Subdomain Takeover Candidates

{% for item in takeover_candidates -%}
- {{ item }}
{% endfor %}
{% endif %}

{% if sensitive_hits %}
## Potensi Data Sensitif

{% for item in sensitive_hits -%}
- {{ item }}
{% endfor %}
{% endif %}

{% if parameterized_urls %}
## URL Berparameter ({{ parameterized_urls|length }})

{% for item in parameterized_urls[:200] -%}
- {{ item }}
{% endfor %}
{% endif %}

{% if dorking_results %}
## Dork Queries

{% for item in dorking_results -%}
- `{{ item }}`
{% endfor %}
{% endif %}

{% if errors %}
## Catatan / Kendala

{% for item in errors -%}
- {{ item }}
{% endfor %}
{% endif %}

---
_Dibuat otomatis oleh ReconX. Hanya untuk pengujian yang diizinkan._
"""

HTML_TEMPLATE = """<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>ReconX Report - {{ target }}</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background:#0d1117; color:#c9d1d9;
         margin:0; padding:2rem; line-height:1.55; }
  h1,h2 { color:#58a6ff; border-bottom:1px solid #21262d; padding-bottom:.3rem; }
  .meta { color:#8b949e; margin-bottom:2rem; }
  table { border-collapse:collapse; margin:1rem 0; }
  th,td { border:1px solid #21262d; padding:.4rem .9rem; text-align:left; }
  th { background:#161b22; }
  ul { padding-left:1.2rem; }
  code { background:#161b22; padding:.1rem .35rem; border-radius:4px; color:#ffa657; }
  .badge { display:inline-block; background:#1f6feb; color:#fff; border-radius:10px;
           padding:.05rem .55rem; font-size:.8rem; margin-left:.4rem; }
  footer { margin-top:3rem; color:#8b949e; font-size:.85rem; }
</style>
</head>
<body>
<h1>ReconX Report</h1>
<div class="meta">
  <div><strong>Target:</strong> {{ target }}</div>
  <div><strong>Operator:</strong> {{ operator }}</div>
  <div><strong>Mulai:</strong> {{ started_at }}</div>
  <div><strong>Selesai:</strong> {{ finished_at }} ({{ "%.0f"|format(duration) }} detik)</div>
</div>

<h2>Ringkasan Temuan</h2>
<table>
  <tr><th>Kategori</th><th>Jumlah</th></tr>
  {% for label, count in summary.items() -%}
  <tr><td>{{ label }}</td><td>{{ count }}</td></tr>
  {% endfor %}
</table>

{% if nuclei_findings %}
<h2>Nuclei Findings<span class="badge">{{ nuclei_findings|length }}</span></h2>
<ul>{% for item in nuclei_findings %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
{% endif %}

{% if nmap_findings %}
<h2>Nmap Open Ports<span class="badge">{{ nmap_findings|length }}</span></h2>
<ul>{% for item in nmap_findings %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
{% endif %}

{% if xray_findings %}
<h2>Xray Findings<span class="badge">{{ xray_findings|length }}</span></h2>
<ul>{% for item in xray_findings %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
{% endif %}

{% if zone_transfer %}
<h2>Zone Transfer<span class="badge">CRITICAL</span></h2>
<ul>{% for item in zone_transfer %}<li>{{ item }}</li>{% endfor %}</ul>
{% endif %}

{% if content_findings %}
<h2>Content Discovery<span class="badge">{{ content_findings|length }}</span></h2>
<ul>{% for item in content_findings %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
{% endif %}

{% if parameter_findings %}
<h2>Parameter Tersembunyi<span class="badge">{{ parameter_findings|length }}</span></h2>
<ul>{% for item in parameter_findings %}<li>{{ item }}</li>{% endfor %}</ul>
{% endif %}

{% if sqli_findings %}
<h2>SQL Injection<span class="badge">{{ sqli_findings|length }}</span></h2>
<ul>{% for item in sqli_findings %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
{% endif %}

{% if xss_findings %}
<h2>XSS<span class="badge">{{ xss_findings|length }}</span></h2>
<ul>{% for item in xss_findings %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
{% endif %}

{% if cloud_findings %}
<h2>Cloud Storage<span class="badge">{{ cloud_findings|length }}</span></h2>
<ul>{% for item in cloud_findings %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
{% endif %}

{% if takeover_candidates %}
<h2>Takeover Candidates</h2>
<ul>{% for item in takeover_candidates %}<li>{{ item }}</li>{% endfor %}</ul>
{% endif %}

{% if sensitive_hits %}
<h2>Potensi Data Sensitif</h2>
<ul>{% for item in sensitive_hits %}<li>{{ item }}</li>{% endfor %}</ul>
{% endif %}

{% if subdomains %}
<h2>Subdomain<span class="badge">{{ subdomains|length }}</span></h2>
<ul>{% for item in subdomains %}<li>{{ item }}</li>{% endfor %}</ul>
{% endif %}

{% if live_hosts %}
<h2>Live Hosts<span class="badge">{{ live_hosts|length }}</span></h2>
<ul>{% for item in live_hosts %}<li>{{ item }}</li>{% endfor %}</ul>
{% endif %}

{% if parameterized_urls %}
<h2>URL Berparameter<span class="badge">{{ parameterized_urls|length }}</span></h2>
<ul>{% for item in parameterized_urls[:300] %}<li>{{ item }}</li>{% endfor %}</ul>
{% endif %}

<footer>Dibuat otomatis oleh ReconX pada {{ finished_at }}. Hanya untuk pengujian yang diizinkan.</footer>
</body>
</html>
"""


def _context(report: ScanReport) -> dict:
    return {
        "target": report.target,
        "operator": report.operator,
        "started_at": report.started_at,
        "finished_at": report.finished_at or datetime.now().isoformat(),
        "duration": report.duration_seconds,
        "speed": report.speed,
        "summary": report.summary_counts(),
        "tool_log": report.tool_log,
        "errors": report.errors,
        "subdomains": report.subdomains,
        "live_hosts": report.live_hosts,
        "nuclei_findings": report.nuclei_findings,
        "nmap_findings": report.nmap_findings,
        "xray_findings": report.xray_findings,
        "dns_records": report.dns_records,
        "zone_transfer": report.zone_transfer,
        "content_findings": report.content_findings,
        "parameter_findings": report.parameter_findings,
        "sqli_findings": report.sqli_findings,
        "xss_findings": report.xss_findings,
        "cloud_findings": report.cloud_findings,
        "takeover_candidates": report.takeover_candidates,
        "sensitive_hits": report.sensitive_hits,
        "parameterized_urls": report.parameterized_urls,
        "dorking_results": report.dorking_results,
    }


def generate(report: ScanReport, directory: Path | None = None) -> dict[str, Path]:
    """Render Markdown and HTML reports; return their paths."""
    directory = directory or OUTPUT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    ctx = _context(report)

    md_path = directory / f"{report.target}-{stamp}.md"
    html_path = directory / f"{report.target}-{stamp}.html"

    md_path.write_text(Template(MD_TEMPLATE).render(**ctx), encoding="utf-8")
    html_path.write_text(Template(HTML_TEMPLATE).render(**ctx), encoding="utf-8")

    console.ok(f"Laporan Markdown : {md_path}")
    console.ok(f"Laporan HTML     : {html_path}")
    return {"markdown": md_path, "html": html_path}
