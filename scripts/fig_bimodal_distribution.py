"""
fig_bimodal_distribution.py — Publication-quality figures for the IEEE DESSERT 2026 paper
"Measuring Excessive Data Exposure in Agentic AI Workflow Automation".

Design targets IEEE two-column format:
  - single-column width (~3.5 in), serif (Times) to match body text
  - greyscale-safe (prints correctly in B&W)
  - no chart title (caption sits below the figure in the paper)
  - vector PDF (primary) + 600-DPI PNG (preview / Word embedding)

All numbers are the locked v3.4 values from exposure_findings_unified.

Outputs (both formats per figure):
  results/charts/fig_ede_distribution.pdf / .png   (Fig 2, bimodal histogram)

Run:  python fig_bimodal_distribution.py
"""

from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# ── Paths ──────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = PROJECT_ROOT / "results" / "charts"
COPY_DIR = Path("/mnt/user-data/outputs")     # preview copy when run in Claude env
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Publication style (IEEE single column) ──────────────────────────────────
matplotlib.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 8,
    "axes.linewidth": 0.6,
    "axes.unicode_minus": False,
    "xtick.major.width": 0.6,
    "ytick.major.width": 0.6,
    "xtick.major.size": 3,
    "ytick.major.size": 3,
    "pdf.fonttype": 42,   # embed TrueType (editable text, no type-3 warnings)
    "ps.fonttype": 42,
})

BAR_FILL = "#5A5A5A"     # mid grey, prints cleanly in B&W
BAR_EDGE = "#1A1A1A"     # near-black outline
GRID_GREY = "#D9D9D9"


# ════════════════════════════════════════════════════════════════════════════
# FIGURE 2 — Bimodal distribution of per-node EDE ratios
# (Table VI, v3.4 locked numbers)
# ════════════════════════════════════════════════════════════════════════════
def make_ede_distribution():
    # Order matters: this is the EDE ratio axis, left (minimal) to right (max).
    # Short range labels avoid overlap at single-column width.
    bands = ["0", "0–0.25", "0.25–0.5", "0.5–0.75", "0.75–1.0", "1.0"]
    counts = [9897, 0, 1877, 19822, 10832, 0]

    fig, ax = plt.subplots(figsize=(3.5, 2.7))

    x = range(len(bands))
    bars = ax.bar(x, counts, width=0.74,
                  color=BAR_FILL, edgecolor=BAR_EDGE, linewidth=0.7, zorder=3)

    # Honest value label above every bar, including the empty bands (shown as 0)
    ymax = max(counts)
    for xi, c in zip(x, counts):
        ax.text(xi, c + ymax * 0.015, f"{c:,}",
                ha="center", va="bottom", fontsize=7, color="#1A1A1A", zorder=4)

    # Axes
    ax.set_xticks(list(x))
    ax.set_xticklabels(bands, fontsize=6.5, rotation=20, ha="right")
    ax.set_xlabel("Per-node EDE ratio", fontsize=8)
    ax.set_ylabel("Node instances", fontsize=8)
    ax.set_ylim(0, ymax * 1.12)

    # Thousands separator on y axis
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{int(v):,}"))

    # Light horizontal gridlines only, behind bars
    ax.yaxis.grid(True, color=GRID_GREY, linewidth=0.5, zorder=0)
    ax.set_axisbelow(True)

    # Strip top/right spines for a clean look
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout(pad=0.4)
    return fig


# ════════════════════════════════════════════════════════════════════════════
def save(fig, stem):
    pdf = OUT_DIR / f"{stem}.pdf"
    png = OUT_DIR / f"{stem}.png"
    fig.savefig(str(pdf), bbox_inches="tight", facecolor="white")
    fig.savefig(str(png), dpi=600, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  saved {pdf.name} + {png.name}")
    # preview copy when running in the Claude environment
    try:
        COPY_DIR.mkdir(parents=True, exist_ok=True)
        import shutil
        shutil.copy2(str(pdf), str(COPY_DIR / pdf.name))
        shutil.copy2(str(png), str(COPY_DIR / png.name))
    except Exception:
        pass


def main():
    print("Building paper figures (v3.4 numbers)...")
    save(make_ede_distribution(), "fig_ede_distribution")
    print("done.")


if __name__ == "__main__":
    main()
