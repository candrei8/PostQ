"""Chart generation for PDF reports — produces base64 PNG images."""

from __future__ import annotations

import base64
import io
import logging
from typing import Any

from quant_scan.core.models import ScanResult

logger = logging.getLogger(__name__)


def _fig_to_base64(fig: Any) -> str:
    """Convert a matplotlib figure to base64 PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor(), edgecolor="none")
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode("ascii")
    buf.close()
    import matplotlib.pyplot as plt

    plt.close(fig)
    return b64


def generate_severity_pie(result: ScanResult, colors: dict[str, str] | None = None) -> str:
    """Generate a severity distribution pie chart as base64 PNG."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        default_colors = {
            "critical": "#e74c3c",
            "high": "#e67e22",
            "medium": "#f39c12",
            "low": "#3498db",
            "info": "#95a5a6",
        }
        colors = colors or default_colors

        data = result.summary.by_severity
        if not data:
            return ""

        labels = []
        sizes = []
        chart_colors = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = data.get(sev, 0)
            if count > 0:
                labels.append(f"{sev.upper()} ({count})")
                sizes.append(count)
                chart_colors.append(default_colors.get(sev, "#cccccc"))

        if not sizes:
            return ""

        fig, ax = plt.subplots(figsize=(6, 4), facecolor="#1a1a2e")
        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            colors=chart_colors,
            autopct="%1.0f%%",
            startangle=140,
            textprops={"color": "white", "fontsize": 9},
        )
        for t in autotexts:
            t.set_color("white")
            t.set_fontweight("bold")
        ax.set_title("Severity Distribution", color="white", fontsize=13, fontweight="bold")

        return _fig_to_base64(fig)

    except ImportError:
        logger.debug("matplotlib not available for chart generation")
        return ""


def generate_risk_bar(result: ScanResult) -> str:
    """Generate a quantum risk distribution bar chart as base64 PNG."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        data = result.summary.by_quantum_risk
        if not data:
            return ""

        risk_colors = {
            "vulnerable": "#e74c3c",
            "weakened": "#f39c12",
            "safe": "#2ecc71",
            "unknown": "#95a5a6",
        }

        labels = []
        values = []
        colors = []
        for risk in ["vulnerable", "weakened", "safe", "unknown"]:
            count = data.get(risk, 0)
            if count > 0:
                labels.append(risk.upper())
                values.append(count)
                colors.append(risk_colors.get(risk, "#cccccc"))

        if not values:
            return ""

        fig, ax = plt.subplots(figsize=(6, 3.5), facecolor="#1a1a2e")
        ax.set_facecolor("#16213e")
        bars = ax.bar(labels, values, color=colors, edgecolor="none", width=0.6)
        ax.set_title("Quantum Risk Distribution", color="white", fontsize=13, fontweight="bold")
        ax.tick_params(colors="white")
        ax.spines["bottom"].set_color("#444")
        ax.spines["left"].set_color("#444")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.set_ylabel("Findings", color="white")

        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                str(val),
                ha="center",
                color="white",
                fontweight="bold",
            )

        return _fig_to_base64(fig)

    except ImportError:
        logger.debug("matplotlib not available for chart generation")
        return ""


def generate_score_gauge(score: float, grade: str) -> str:
    """Generate a score gauge chart as base64 PNG."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        fig, ax = plt.subplots(figsize=(4, 3), subplot_kw={"projection": "polar"}, facecolor="#1a1a2e")
        ax.set_facecolor("#1a1a2e")

        # Gauge from 0 to 100
        theta = np.linspace(np.pi, 0, 100)
        np.ones(100)

        # Color gradient: red -> yellow -> green
        colors_arr = []
        for i in range(100):
            if i < 40:
                colors_arr.append("#e74c3c")
            elif i < 60:
                colors_arr.append("#f39c12")
            elif i < 75:
                colors_arr.append("#f1c40f")
            elif i < 90:
                colors_arr.append("#2ecc71")
            else:
                colors_arr.append("#27ae60")

        for i in range(99):
            ax.bar(theta[i], 1, width=(theta[i] - theta[i + 1]), bottom=0.6, color=colors_arr[i], alpha=0.3)

        # Filled portion
        score_idx = min(int(score), 99)
        for i in range(score_idx):
            ax.bar(theta[i], 1, width=(theta[i] - theta[i + 1]), bottom=0.6, color=colors_arr[i], alpha=0.9)

        # Score text
        ax.text(np.pi / 2, 0.3, f"{score:.0f}", ha="center", va="center", fontsize=28, fontweight="bold", color="white")
        ax.text(
            np.pi / 2,
            -0.1,
            grade,
            ha="center",
            va="center",
            fontsize=16,
            fontweight="bold",
            color=colors_arr[score_idx],
        )

        ax.set_ylim(0, 1.7)
        ax.set_yticklabels([])
        ax.set_xticklabels([])
        ax.spines["polar"].set_visible(False)
        ax.grid(False)

        return _fig_to_base64(fig)

    except ImportError:
        logger.debug("matplotlib not available for chart generation")
        return ""
