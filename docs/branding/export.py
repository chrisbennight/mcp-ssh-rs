"""Export outlined brand artwork from the checked-in mark and licensed fonts.

Development only: python -m pip install fonttools==4.65.0
Run from any directory: python docs/branding/export.py
"""

from pathlib import Path
import xml.etree.ElementTree as ET

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "crates/ssh-server/static"
OUT = Path(__file__).with_name("assets")
FONT = instantiateVariableFont(TTFont(STATIC / "fonts/Manrope.ttf"), {"wght": 700})
GLYPHS = FONT.getGlyphSet()
CMAP = FONT.getBestCmap()
UNITS = FONT["head"].unitsPerEm
NS = "{http://www.w3.org/2000/svg}"


def text(value, x, y, size, color):
    paths = []
    scale = size / UNITS
    for char in value:
        glyph = GLYPHS[CMAP[ord(char)]]
        pen = SVGPathPen(GLYPHS)
        glyph.draw(pen)
        paths.append(f'<path transform="translate({x:.3f} {y}) scale({scale:.6f} {-scale:.6f})" d="{pen.getCommands()}"/>')
        x += glyph.width * scale
    return f'<g fill="{color}" aria-label="{value}">' + "".join(paths) + "</g>"


def mark(ink, accent):
    source = ET.parse(STATIC / "brand.svg").getroot()
    parts = []
    for child in source:
        if child.tag in {NS + "path", NS + "circle"}:
            child.set("stroke", ink if child.attrib.pop("class") == "ink" else accent)
            parts.append(ET.tostring(child, encoding="unicode"))
    return '<g fill="none">' + "".join(parts) + "</g>"


def svg(name, width, height, body, title="mcp-ssh-rs"):
    (OUT / name).write_text(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title"><title id="title">{title}</title>{body}</svg>\n'
    )


def main():
    OUT.mkdir(exist_ok=True)
    for mode, bg, ink, accent in [
        ("light", "#f7f5f0", "#23201b", "#b66a45"),
        ("dark", "#23201b", "#f7f5f0", "#df9b76"),
    ]:
        symbol = mark(ink, accent)
        svg(f"symbol-{mode}.svg", 64, 64, symbol)
        wordmark = f'<g transform="translate(8 8)">{symbol}</g>' + text("mcp-ssh-rs", 88, 54, 38, ink)
        svg(f"wordmark-{mode}.svg", 330, 80, wordmark)
        header = f'<rect width="960" height="240" rx="16" fill="{bg}"/>'
        header += f'<g transform="translate(40 44) scale(1.6)">{symbol}</g>'
        header += text("mcp-ssh-rs", 172, 113, 64, ink)
        header += text("SSH commands and file transfers for MCP clients", 44, 180, 25, ink)
        svg(f"header-{mode}.svg", 960, 240, header)
    svg("symbol-mono.svg", 64, 64, mark("#23201b", "#23201b"))
    social = '<rect width="1280" height="640" fill="#f7f5f0"/>'
    social += '<path d="M80 535H1200" stroke="#b66a45" stroke-width="3"/>'
    social += '<g transform="translate(75 125) scale(2.8)">' + mark("#23201b", "#b66a45") + '</g>'
    social += text("mcp-ssh-rs", 300, 260, 104, "#23201b")
    social += text("SSH commands and file transfers", 85, 380, 47, "#23201b")
    svg("social-preview.svg", 1280, 640, social)


if __name__ == "__main__":
    main()
