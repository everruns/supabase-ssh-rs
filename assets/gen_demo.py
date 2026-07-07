#!/usr/bin/env python3
"""Generate an animated terminal-demo SVG from real captured command output.

Reads /tmp/demo-capture.txt (marker-delimited real output from the bashkit
sandbox) and renders a self-contained, GitHub-friendly animated SVG that
streams each command + its output line-by-line, then loops.

No external dependencies; animation is pure CSS @keyframes (opacity reveal),
which renders inline on GitHub.
"""
import html
import re

import sys
CAPTURE = sys.argv[1] if len(sys.argv) > 1 else "capture.txt"
OUT = sys.argv[2] if len(sys.argv) > 2 else "demo.svg"

# ---- palette (Catppuccin-ish, dark) ----
BG = "#181825"
BAR = "#11111b"
FG = "#cdd6f4"      # default output text
DIM = "#6c7086"     # ssh + args dimming
GREEN = "#a6e3a1"   # prompt $
BLUE = "#89b4fa"    # command name / paths
YELLOW = "#f9e2af"  # headings in output
DOT_R, DOT_G, DOT_Y = "#f38ba8", "#a6e3a1", "#f9e2af"

FONT = ("ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, "
        "'Liberation Mono', monospace")
FS = 15
LH = 22
PAD_X = 22
PAD_TOP = 54     # room for title bar
PAD_BOT = 20
BAR_H = 34
CHAR_W = 9.0     # approx advance for the font at FS=15


def parse():
    with open(CAPTURE) as f:
        raw = f.read()
    blocks = re.findall(r"<<<CMD>>>(.*?)\n(.*?)<<<END>>>", raw, re.S)
    return [(cmd, out.rstrip("\n").split("\n") if out.strip() else [])
            for cmd, out in blocks]


def esc(s):
    return html.escape(s, quote=False)


def build_lines(blocks):
    """Return a flat list of (kind, text) lines forming the session."""
    lines = []
    for i, (cmd, out) in enumerate(blocks):
        lines.append(("cmd", cmd))
        for o in out:
            kind = "head" if o.startswith("#") else "out"
            lines.append((kind, o))
        if i != len(blocks) - 1:
            lines.append(("gap", ""))
    lines.append(("gap", ""))
    lines.append(("prompt", ""))   # trailing idle prompt with blinking cursor
    return lines


def tspans_for_cmd(cmd):
    """Prompt + `ssh supabase.sh` + command, with light syntax coloring."""
    parts = []
    parts.append(f'<tspan fill="{GREEN}">$ </tspan>')
    parts.append(f'<tspan fill="{DIM}">ssh </tspan>')
    parts.append(f'<tspan fill="{BLUE}">supabase.sh</tspan>')
    parts.append(f'<tspan fill="{FG}"> {esc(cmd)}</tspan>')
    return "".join(parts)


def tspan_for_out(kind, text):
    if kind == "head":
        return f'<tspan fill="{YELLOW}">{esc(text)}</tspan>'
    # colorize file paths in output blue
    if text.startswith("/supabase/"):
        return f'<tspan fill="{BLUE}">{esc(text)}</tspan>'
    return f'<tspan fill="{FG}">{esc(text)}</tspan>'


def main():
    blocks = parse()
    lines = build_lines(blocks)

    n = len(lines)
    max_cols = max((len(t) for _, t in lines), default=40)
    # account for the "$ ssh supabase.sh " prefix width on command lines
    prefix = len("$ ssh supabase.sh ")
    max_cols = max(max_cols, prefix + max(
        (len(t) for k, t in lines if k == "cmd"), default=0))

    width = int(PAD_X * 2 + max_cols * CHAR_W)
    width = max(width, 660)
    height = int(PAD_TOP + PAD_BOT + n * LH)

    # timing: stream reveal, then hold, then loop
    per_line = 0.55      # seconds between line reveals
    hold = 3.0           # seconds to hold full screen
    total = n * per_line + hold
    hold_pct = 94.0      # keep lines visible until near the end

    css = [
        f".t{{font-family:{FONT};font-size:{FS}px;"
        "white-space:pre;dominant-baseline:middle;}",
        ".l{opacity:0;}",
    ]
    for i in range(n):
        reveal_at = (i * per_line) / total * 100.0
        on_at = min(reveal_at + 0.4, hold_pct - 0.1)
        css.append(
            f"@keyframes r{i}{{0%,{reveal_at:.2f}%{{opacity:0}}"
            f"{on_at:.2f}%,{hold_pct:.2f}%{{opacity:1}}100%{{opacity:0}}}}"
        )
        css.append(
            f".l{i}{{animation:r{i} {total:.2f}s infinite;"
            "animation-timing-function:linear;}"
        )
    # blinking cursor
    css.append("@keyframes blink{0%,49%{opacity:1}50%,100%{opacity:0}}")
    css.append(f".cur{{animation:blink 1s steps(1) infinite;fill:{FG};}}")

    body = []
    y0 = PAD_TOP + LH / 2
    for i, (kind, text) in enumerate(lines):
        y = y0 + i * LH
        if kind == "cmd":
            content = tspans_for_cmd(text)
        elif kind == "prompt":
            content = f'<tspan fill="{GREEN}">$ </tspan>'
        elif kind == "gap":
            content = ""
        else:
            content = tspan_for_out(kind, text)
        body.append(
            f'<text class="t l l{i}" x="{PAD_X}" y="{y:.1f}">{content}</text>'
        )

    # blinking cursor after the trailing "$ " prompt on the final line
    cur_y = y0 + (n - 1) * LH
    cur_x = PAD_X + 2 * CHAR_W
    body.append(
        f'<rect class="cur l l{n-1}" x="{cur_x:.1f}" y="{cur_y-8:.1f}" '
        f'width="9" height="16" rx="1"/>'
    )

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="Terminal demo: browsing Supabase docs over SSH with bashkit">
<style>{''.join(css)}</style>
<rect x="0" y="0" width="{width}" height="{height}" rx="10" fill="{BG}"/>
<rect x="0" y="0" width="{width}" height="{BAR_H}" rx="10" fill="{BAR}"/>
<rect x="0" y="{BAR_H-10}" width="{width}" height="10" fill="{BAR}"/>
<circle cx="20" cy="17" r="6" fill="{DOT_R}"/>
<circle cx="40" cy="17" r="6" fill="{DOT_G}"/>
<circle cx="60" cy="17" r="6" fill="{DOT_Y}"/>
<text x="{width/2}" y="17" text-anchor="middle" dominant-baseline="middle" font-family="{FONT}" font-size="12" fill="{DIM}">agent@local — ssh supabase.sh</text>
{chr(10).join(body)}
</svg>
'''
    with open(OUT, "w") as f:
        f.write(svg)
    print(f"wrote {OUT}  ({width}x{height}, {n} lines, {total:.1f}s loop)")


if __name__ == "__main__":
    main()
