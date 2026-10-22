#!/usr/bin/env python3
"""Render captured ANSI output as a terminal-style SVG screenshot.

Usage: render_ansi_svg.py INPUT.ansi OUTPUT.svg TITLE COMMAND
"""
import html
import re
import sys

COLORS = {
    "90": "#6b7280",
    "91": "#f87171",
    "92": "#34d399",
    "93": "#fbbf24",
    "94": "#60a5fa",
    "95": "#e879f9",
    "96": "#67e8f9",
    "97": "#e2e8f0",
}
DEFAULT = "#c9d6e8"
SGR = re.compile(r"\x1b\[([0-9;]*)m")


def esc(text):
    return html.escape(text, quote=False)


def runs(line, color=DEFAULT):
    """Split one line into (color, text) runs, following the SGR codes.

    The active color is carried across lines, like a terminal does, so a
    sequence emitted at the end of one line colors the next one.
    """
    out = []
    pos = 0
    for match in SGR.finditer(line):
        if match.start() > pos:
            out.append((color, line[pos:match.start()]))
        params = match.group(1)
        color = DEFAULT if params in ("", "0") else COLORS.get(params.split(";")[-1], DEFAULT)
        pos = match.end()
    if pos < len(line):
        out.append((color, line[pos:]))
    return out, color


def render(content, outfile, title, command):
    lines = content.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    height = 110 + len(lines) * 21 + 22
    body = []
    y = 110
    color = DEFAULT
    for line in lines:
        spans, color = runs(line, color)
        markup = "".join(
            f'<tspan fill="{run_color}">{esc(text)}</tspan>' for run_color, text in spans
        )
        body.append(f'    <text x="32" y="{y}" xml:space="preserve">{markup}</text>')
        y += 21
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 {height}" width="1000" height="{height}" role="img" aria-label="{esc(title)}">
  <title>{esc(title)}</title>
  <defs>
    <linearGradient id="term" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#0d1728"/>
      <stop offset="1" stop-color="#091120"/>
    </linearGradient>
    <linearGradient id="bar" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#122037"/>
      <stop offset="1" stop-color="#0f1b2e"/>
    </linearGradient>
    <style>
      .mono {{ font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace; }}
    </style>
  </defs>
  <rect width="1000" height="{height}" rx="16" fill="url(#term)" stroke="#22344f"/>
  <path d="M0 16 A16 16 0 0 1 16 0 H984 A16 16 0 0 1 1000 16 V44 H0 Z" fill="url(#bar)"/>
  <line x1="0" y1="44.5" x2="1000" y2="44.5" stroke="#1e2e47"/>
  <circle cx="24" cy="22" r="6" fill="#f87171"/>
  <circle cx="44" cy="22" r="6" fill="#fbbf24"/>
  <circle cx="64" cy="22" r="6" fill="#34d399"/>
  <text x="500" y="27" class="mono" font-size="12" text-anchor="middle" fill="#7488a3">{esc(title)}</text>
  <text x="32" y="72" class="mono" font-size="14" xml:space="preserve"><tspan fill="#34d399">$ </tspan><tspan fill="#e2e8f0">{esc(command)}</tspan></text>
  <line x1="0" y1="86" x2="1000" y2="86" stroke="#1b2a41"/>
  <g class="mono" font-size="14">
{chr(10).join(body)}
  </g>
</svg>
'''
    with open(outfile, "w", encoding="utf-8") as handle:
        handle.write(svg)
    print(f"wrote {outfile} ({height}px)")


def main():
    if len(sys.argv) != 5:
        sys.exit("usage: render_ansi_svg.py INPUT.ansi OUTPUT.svg TITLE COMMAND")
    infile, outfile, title, command = sys.argv[1:]
    with open(infile, encoding="utf-8") as handle:
        render(handle.read(), outfile, title, command)


if __name__ == "__main__":
    main()
