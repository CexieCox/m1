"""Generate Low-Level Flowchart and Pipeline Architecture for Module 1 (LoaderFilter).

Produces:
- Module_1_Low_Level_Algorithm_Flowchart.drawio (draw.io mxGraph XML)
- Module_1_Low_Level_Algorithm_Flowchart.html (Interactive SVG with zoom/pan & high-res render)
- Module_1_Low_Level_Algorithm_Flowchart.png (Headless Chrome render)
- Slices for each Step (step1.png, step2.png, step3.png, step4.png, step5.png, export.png)
"""

from __future__ import annotations

import html
import json
import os
import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

BASE_DIR = Path(__file__).resolve().parent.parent

# Styles for draw.io
STYLE_CONTAINER = "rounded=1;whiteSpace=wrap;html=1;fillColor=#F8FAFC;strokeColor=#94A3B8;strokeWidth=1.5;dashed=1;dashPattern=6 4;arcSize=2;"
STYLE_ELLIPSE = "ellipse;whiteSpace=wrap;html=1;fontFamily=Arial;fontSize=12;fontStyle=1;fontColor=#0F172A;fillColor=#FFFFFF;strokeColor=#334155;strokeWidth=1.8;"
STYLE_RECT = "rounded=0;whiteSpace=wrap;html=1;fontFamily=Arial;fontSize=11;fontColor=#0F172A;fillColor=#FFFFFF;strokeColor=#334155;strokeWidth=1.8;align=center;spacing=4;"
STYLE_DIAMOND = "rhombus;whiteSpace=wrap;html=1;fontFamily=Arial;fontSize=11;fontStyle=1;fontColor=#0F172A;fillColor=#FFFFFF;strokeColor=#334155;strokeWidth=1.8;align=center;spacing=2;"
STYLE_PARALLELOGRAM = "shape=parallelogram;perimeter=parallelogramPerimeter;whiteSpace=wrap;html=1;fixedSize=1;size=14;fontFamily=Arial;fontSize=11;fontColor=#0F172A;fillColor=#FFFFFF;strokeColor=#334155;strokeWidth=1.8;align=center;spacing=3;"
STYLE_NOTE = "shape=note;whiteSpace=wrap;html=1;backgroundOutline=1;darkOpacity=0.08;size=14;fontFamily=Arial;fontSize=11;fontStyle=1;fontColor=#0F172A;fillColor=#FFFFFF;strokeColor=#334155;strokeWidth=1.8;align=center;spacing=3;"
STYLE_BLOCK_ARROW = "shape=singleArrow;direction=west;whiteSpace=wrap;html=1;fontFamily=Arial;fontSize=11;fontStyle=1;fontColor=#991B1B;fillColor=#FEF2F2;strokeColor=#DC2626;strokeWidth=1.8;align=center;spacingLeft=15;"
STYLE_ARCH_NOTE = "text;html=1;align=left;verticalAlign=top;whiteSpace=wrap;fontFamily=Arial;fontSize=10;fontColor=#334155;spacingLeft=8;"

# Edge styles for draw.io
STYLE_EDGE_GREY = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=block;endFill=1;strokeColor=#334155;strokeWidth=1.6;fontFamily=Arial;fontSize=10;"
STYLE_EDGE_GREEN = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=block;endFill=1;strokeColor=#16A34A;strokeWidth=1.8;fontColor=#16A34A;fontFamily=Arial;fontSize=11;fontStyle=1;"
STYLE_EDGE_RED = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=block;endFill=1;strokeColor=#DC2626;strokeWidth=1.8;fontColor=#DC2626;fontFamily=Arial;fontSize=11;fontStyle=1;"
STYLE_EDGE_BLUE = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=block;endFill=1;strokeColor=#2563EB;strokeWidth=1.8;fontColor=#2563EB;fontFamily=Arial;fontSize=11;fontStyle=1;"
STYLE_EDGE_DASH_BLUE = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=block;endFill=1;strokeColor=#0284C7;strokeWidth=1.8;dashed=1;dashPattern=6 4;fontColor=#0284C7;fontFamily=Arial;fontSize=11;fontStyle=1;"

class FlowchartBuilder:
    def __init__(self, width: int = 1740, height: int = 5300):
        self.width = width
        self.height = height
        self.nodes = []
        self.edges = []
        self.arch_notes = []

    def add_container(self, node_id: str, x: int, y: int, w: int, h: int, title: str, subtitle: str = ""):
        self.nodes.append({
            "id": node_id, "type": "container",
            "x": x, "y": y, "w": w, "h": h,
            "title": title, "subtitle": subtitle,
            "label": f"<b>{title}</b>" + (f"<br><i>{subtitle}</i>" if subtitle else ""),
            "drawio_style": STYLE_CONTAINER
        })

    def add_ellipse(self, node_id: str, x: int, y: int, w: int, h: int, text: str):
        self.nodes.append({
            "id": node_id, "type": "ellipse",
            "x": x, "y": y, "w": w, "h": h,
            "text": text, "label": text,
            "drawio_style": STYLE_ELLIPSE
        })

    def add_rect(self, node_id: str, x: int, y: int, w: int, h: int, text: str, subtext: str = ""):
        label = f"<b>{text}</b>" + (f"<br>{subtext}" if subtext else "")
        self.nodes.append({
            "id": node_id, "type": "rect",
            "x": x, "y": y, "w": w, "h": h,
            "text": text, "subtext": subtext, "label": label,
            "drawio_style": STYLE_RECT
        })

    def add_diamond(self, node_id: str, x: int, y: int, w: int, h: int, text: str, subtext: str = ""):
        label = f"<b>{text}</b>" + (f"<br>{subtext}" if subtext else "")
        self.nodes.append({
            "id": node_id, "type": "diamond",
            "x": x, "y": y, "w": w, "h": h,
            "text": text, "subtext": subtext, "label": label,
            "drawio_style": STYLE_DIAMOND
        })

    def add_parallelogram(self, node_id: str, x: int, y: int, w: int, h: int, text: str, subtext: str = ""):
        label = f"<b>{text}</b>" + (f"<br>{subtext}" if subtext else "")
        self.nodes.append({
            "id": node_id, "type": "parallelogram",
            "x": x, "y": y, "w": w, "h": h,
            "text": text, "subtext": subtext, "label": label,
            "drawio_style": STYLE_PARALLELOGRAM
        })

    def add_note(self, node_id: str, x: int, y: int, w: int, h: int, text: str, subtext: str = ""):
        label = f"<b>{text}</b>" + (f"<br>{subtext}" if subtext else "")
        self.nodes.append({
            "id": node_id, "type": "note",
            "x": x, "y": y, "w": w, "h": h,
            "text": text, "subtext": subtext, "label": label,
            "drawio_style": STYLE_NOTE
        })

    def add_block_arrow(self, node_id: str, x: int, y: int, w: int, h: int, text: str, subtext: str = ""):
        label = f"<b>{text}</b>" + (f"<br>{subtext}" if subtext else "")
        self.nodes.append({
            "id": node_id, "type": "block_arrow",
            "x": x, "y": y, "w": w, "h": h,
            "text": text, "subtext": subtext, "label": label,
            "drawio_style": STYLE_BLOCK_ARROW
        })

    def add_arch_note(self, note_id: str, x: int, y: int, w: int, h: int, title: str, lines: list[str]):
        body = "<br>".join(lines)
        label = f"<b>{title}</b><br>{body}"
        self.arch_notes.append({
            "id": note_id, "x": x, "y": y, "w": w, "h": h,
            "title": title, "lines": lines, "label": label
        })
        self.nodes.append({
            "id": note_id, "type": "arch_note",
            "x": x, "y": y, "w": w, "h": h,
            "title": title, "lines": lines, "label": label,
            "drawio_style": STYLE_ARCH_NOTE
        })

    def add_edge(self, edge_id: str, source: str, target: str, color_type: str = "grey", label: str = "", points: list[tuple[int, int]] | None = None):
        style_map = {
            "grey": STYLE_EDGE_GREY,
            "green": STYLE_EDGE_GREEN,
            "red": STYLE_EDGE_RED,
            "blue": STYLE_EDGE_BLUE,
            "dash_blue": STYLE_EDGE_DASH_BLUE
        }
        self.edges.append({
            "id": edge_id, "source": source, "target": target,
            "color_type": color_type, "label": label,
            "points": points or [],
            "drawio_style": style_map.get(color_type, STYLE_EDGE_GREY)
        })

    def to_drawio_xml(self) -> str:
        root = ET.Element("mxfile", host="app.diagrams.net")
        diagram = ET.SubElement(root, "diagram", id="module1_flowchart", name="Module 1 Low-Level Flowchart")
        model = ET.SubElement(
            diagram, "mxGraphModel",
            dx=str(self.width), dy=str(self.height), grid="1", gridSize="10",
            guides="1", tooltips="1", connect="1", arrows="1", fold="1",
            page="0", pageScale="1", pageWidth=str(self.width), pageHeight=str(self.height),
            math="0", shadow="0"
        )
        graph_root = ET.SubElement(model, "root")
        ET.SubElement(graph_root, "mxCell", id="0")
        ET.SubElement(graph_root, "mxCell", id="1", parent="0")

        # First add containers so they render in background
        for node in [n for n in self.nodes if n["type"] == "container"]:
            cell = ET.SubElement(graph_root, "mxCell")
            cell.set("id", node["id"])
            cell.set("value", "")
            cell.set("style", node["drawio_style"])
            cell.set("parent", "1")
            cell.set("vertex", "1")
            geo = ET.SubElement(cell, "mxGeometry")
            geo.set("x", str(node["x"]))
            geo.set("y", str(node["y"]))
            geo.set("width", str(node["w"]))
            geo.set("height", str(node["h"]))
            geo.set("as", "geometry")

            # Header text for container
            head_cell = ET.SubElement(graph_root, "mxCell")
            head_cell.set("id", f"{node['id']}_head")
            head_cell.set("value", node["label"])
            head_cell.set("style", "text;html=1;align=left;verticalAlign=top;fontFamily=Arial;fontSize=13;fontColor=#0F172A;spacingLeft=10;spacingTop=6;")
            head_cell.set("parent", "1")
            head_cell.set("vertex", "1")
            geo2 = ET.SubElement(head_cell, "mxGeometry")
            geo2.set("x", str(node["x"]))
            geo2.set("y", str(node["y"]))
            geo2.set("width", str(node["w"]))
            geo2.set("height", "35")
            geo2.set("as", "geometry")

        # Then add nodes
        for node in [n for n in self.nodes if n["type"] != "container"]:
            cell = ET.SubElement(graph_root, "mxCell")
            cell.set("id", node["id"])
            cell.set("value", node.get("label", ""))
            cell.set("style", node.get("drawio_style", ""))
            cell.set("parent", "1")
            cell.set("vertex", "1")
            geo = ET.SubElement(cell, "mxGeometry")
            geo.set("x", str(node["x"]))
            geo.set("y", str(node["y"]))
            geo.set("width", str(node["w"]))
            geo.set("height", str(node["h"]))
            geo.set("as", "geometry")

        # Then add edges
        for edge in self.edges:
            cell = ET.SubElement(graph_root, "mxCell")
            cell.set("id", edge["id"])
            cell.set("value", edge.get("label", ""))
            cell.set("style", edge.get("drawio_style", ""))
            cell.set("parent", "1")
            cell.set("edge", "1")
            if "source" in edge:
                cell.set("source", edge["source"])
            if "target" in edge:
                cell.set("target", edge["target"])
            geo = ET.SubElement(cell, "mxGeometry")
            geo.set("relative", "1")
            geo.set("as", "geometry")
            if edge["points"]:
                points_elem = ET.SubElement(geo, "Array", **{"as": "points"})
                for pt in edge["points"]:
                    pt_elem = ET.SubElement(points_elem, "mxPoint")
                    pt_elem.set("x", str(pt[0]))
                    pt_elem.set("y", str(pt[1]))

        return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")

    def to_svg(self) -> str:
        svg_parts = []
        svg_parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.width} {self.height}" width="{self.width}" height="{self.height}" style="background-color: #FFFFFF; font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, Helvetica, Arial, sans-serif;">')

        # Defs: Arrow markers and drop shadows
        svg_parts.append('''
        <defs>
            <marker id="arrow-grey" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#334155" />
            </marker>
            <marker id="arrow-green" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#16A34A" />
            </marker>
            <marker id="arrow-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#DC2626" />
            </marker>
            <marker id="arrow-blue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#2563EB" />
            </marker>
            <filter id="shadow" x="-5%" y="-5%" width="110%" height="110%">
                <feDropShadow dx="0" dy="1" stdDeviation="2" flood-color="#000000" flood-opacity="0.06"/>
            </filter>
        </defs>
        ''')

        # 1. Render Containers
        for node in [n for n in self.nodes if n["type"] == "container"]:
            x, y, w, h = node["x"], node["y"], node["w"], node["h"]
            svg_parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="#F8FAFC" stroke="#94A3B8" stroke-width="1.6" stroke-dasharray="6,4" />')
            svg_parts.append(f'<text x="{x+16}" y="{y+24}" font-size="14" font-weight="700" fill="#0F172A">{html.escape(node["title"])}</text>')
            if node.get("subtitle"):
                svg_parts.append(f'<text x="{x+16}" y="{y+42}" font-size="11" font-style="italic" fill="#64748B">{html.escape(node["subtitle"])}</text>')

        # 2. Render Arch Notes
        for an in self.arch_notes:
            x, y, w, h = an["x"], an["y"], an["w"], an["h"]
            svg_parts.append(f'<line x1="{x}" y1="{y}" x2="{x}" y2="{y+h}" stroke="#1E293B" stroke-width="3" />')
            svg_parts.append(f'<text x="{x+8}" y="{y+12}" font-size="10.5" font-weight="700" fill="#0F172A">{html.escape(an["title"])}</text>')
            curr_y = y + 26
            for line in an["lines"]:
                svg_parts.append(f'<text x="{x+8}" y="{curr_y}" font-size="9.5" fill="#334155">{html.escape(line)}</text>')
                curr_y += 14

        # 3. Render Edges
        color_map = {
            "grey": ("#334155", "arrow-grey", "1.6", "none"),
            "green": ("#16A34A", "arrow-green", "1.8", "none"),
            "red": ("#DC2626", "arrow-red", "1.8", "none"),
            "blue": ("#2563EB", "arrow-blue", "1.8", "none"),
            "dash_blue": ("#0284C7", "arrow-blue", "1.8", "6,4")
        }
        for edge in self.edges:
            pts = edge["points"]
            if not pts or len(pts) < 2:
                continue
            c_color, marker_id, swidth, dash = color_map.get(edge["color_type"], color_map["grey"])
            path_d = f"M {pts[0][0]} {pts[0][1]}"
            for p in pts[1:]:
                path_d += f" L {p[0]} {p[1]}"
            dash_attr = f' stroke-dasharray="{dash}"' if dash != "none" else ""
            svg_parts.append(f'<path d="{path_d}" fill="none" stroke="{c_color}" stroke-width="{swidth}"{dash_attr} marker-end="url(#{marker_id})" />')

            # Render Edge Label
            if edge.get("label"):
                # Position label along the edge (at midpoint of first segment or specific bend)
                if len(pts) >= 2:
                    p1, p2 = pts[0], pts[1]
                    lx = (p1[0] + p2[0]) / 2
                    ly = (p1[1] + p2[1]) / 2 - 5
                    bg_w = len(edge["label"]) * 7 + 8
                    svg_parts.append(f'<rect x="{lx - bg_w/2}" y="{ly - 10}" width="{bg_w}" height="14" fill="#FFFFFF" rx="2" opacity="0.9" />')
                    svg_parts.append(f'<text x="{lx}" y="{ly}" font-size="10" font-weight="700" fill="{c_color}" text-anchor="middle">{html.escape(edge["label"])}</text>')

        # 4. Render Nodes
        for node in [n for n in self.nodes if n["type"] not in ("container", "arch_note")]:
            x, y, w, h = node["x"], node["y"], node["w"], node["h"]
            ntype = node["type"]

            if ntype == "ellipse":
                cx, cy = x + w / 2, y + h / 2
                rx, ry = w / 2, h / 2
                svg_parts.append(f'<ellipse cx="{cx}" cy="{cy}" rx="{rx}" ry="{ry}" fill="#FFFFFF" stroke="#334155" stroke-width="1.8" filter="url(#shadow)" />')
                svg_parts.append(f'<text x="{cx}" y="{cy+4}" font-size="12" font-weight="700" fill="#0F172A" text-anchor="middle">{html.escape(node["text"])}</text>')

            elif ntype == "rect":
                svg_parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#FFFFFF" stroke="#334155" stroke-width="1.8" filter="url(#shadow)" />')
                lines = [node["text"]] + ([node["subtext"]] if node.get("subtext") else [])
                start_y = y + (h - len(lines) * 15) / 2 + 11
                for i, line in enumerate(lines):
                    fw = "700" if i == 0 else "400"
                    fs = "11" if i == 0 else "10"
                    fc = "#0F172A" if i == 0 else "#475569"
                    svg_parts.append(f'<text x="{x + w/2}" y="{start_y + i*15}" font-size="{fs}" font-weight="{fw}" fill="{fc}" text-anchor="middle">{html.escape(line)}</text>')

            elif ntype == "diamond":
                cx, cy = x + w / 2, y + h / 2
                points = f"{cx},{y} {x+w},{cy} {cx},{y+h} {x},{cy}"
                svg_parts.append(f'<polygon points="{points}" fill="#FFFFFF" stroke="#334155" stroke-width="1.8" filter="url(#shadow)" />')
                lines = [node["text"]] + ([node["subtext"]] if node.get("subtext") else [])
                start_y = cy - (len(lines) - 1) * 7.5 + 4
                for i, line in enumerate(lines):
                    fw = "700" if i == 0 else "400"
                    fs = "10.5" if i == 0 else "9.5"
                    fc = "#0F172A" if i == 0 else "#475569"
                    svg_parts.append(f'<text x="{cx}" y="{start_y + i*14}" font-size="{fs}" font-weight="{fw}" fill="{fc}" text-anchor="middle">{html.escape(line)}</text>')

            elif ntype == "parallelogram":
                skew = 14
                points = f"{x+skew},{y} {x+w},{y} {x+w-skew},{y+h} {x},{y+h}"
                svg_parts.append(f'<polygon points="{points}" fill="#FFFFFF" stroke="#334155" stroke-width="1.8" filter="url(#shadow)" />')
                lines = [node["text"]] + ([node["subtext"]] if node.get("subtext") else [])
                start_y = y + (h - len(lines) * 15) / 2 + 11
                for i, line in enumerate(lines):
                    fw = "700" if i == 0 else "400"
                    fs = "11" if i == 0 else "10"
                    fc = "#0F172A" if i == 0 else "#475569"
                    svg_parts.append(f'<text x="{x + w/2}" y="{start_y + i*15}" font-size="{fs}" font-weight="{fw}" fill="{fc}" text-anchor="middle">{html.escape(line)}</text>')

            elif ntype == "note":
                fold = 14
                path_d = f"M {x} {y} L {x+w-fold} {y} L {x+w} {y+fold} L {x+w} {y+h} L {x} {y+h} Z"
                fold_d = f"M {x+w-fold} {y} L {x+w-fold} {y+fold} L {x+w} {y+fold} Z"
                svg_parts.append(f'<path d="{path_d}" fill="#FFFFFF" stroke="#334155" stroke-width="1.8" filter="url(#shadow)" />')
                svg_parts.append(f'<path d="{fold_d}" fill="#E2E8F0" stroke="#334155" stroke-width="1.5" />')
                lines = [node["text"]] + ([node["subtext"]] if node.get("subtext") else [])
                start_y = y + (h - len(lines) * 15) / 2 + 11
                for i, line in enumerate(lines):
                    fw = "700" if i == 0 else "400"
                    fs = "11" if i == 0 else "10"
                    fc = "#0F172A" if i == 0 else "#475569"
                    svg_parts.append(f'<text x="{x + (w-fold/2)/2}" y="{start_y + i*15}" font-size="{fs}" font-weight="{fw}" fill="{fc}" text-anchor="middle">{html.escape(line)}</text>')

            elif ntype == "block_arrow":
                head_w = 16
                arrow_d = f"M {x+head_w} {y} L {x+w} {y} L {x+w} {y+h} L {x+head_w} {y+h} L {x+head_w} {y+h+6} L {x} {y+h/2} L {x+head_w} {y-6} Z"
                svg_parts.append(f'<path d="{arrow_d}" fill="#FEF2F2" stroke="#DC2626" stroke-width="1.8" filter="url(#shadow)" />')
                lines = [node["text"]] + ([node["subtext"]] if node.get("subtext") else [])
                start_y = y + (h - len(lines) * 14) / 2 + 10
                for i, line in enumerate(lines):
                    fw = "700" if i == 0 else "400"
                    fs = "10.5" if i == 0 else "9.5"
                    fc = "#991B1B" if i == 0 else "#B91C1C"
                    svg_parts.append(f'<text x="{x + head_w + (w-head_w)/2}" y="{start_y + i*14}" font-size="{fs}" font-weight="{fw}" fill="{fc}" text-anchor="middle">{html.escape(line)}</text>')

        svg_parts.append('</svg>')
        return "\n".join(svg_parts)


def build_module1_diagram() -> FlowchartBuilder:
    builder = FlowchartBuilder(width=1740, height=5300)

    # =========================================================================
    # 0. TOP HEADER & LEGEND BOX
    # =========================================================================
    # Title & Subtitle
    # Legend Box in Top Right (X: 1140, Y: 15, W: 540, H: 95)
    builder.nodes.append({
        "id": "legend_box", "type": "container",
        "x": 1140, "y": 15, "w": 550, "h": 95,
        "title": "FLOWCHART SYMBOLS & CONVENTIONS",
        "subtitle": "TemporalKG Flowchart Specification Standard v2.0",
        "label": "<b>FLOWCHART SYMBOLS & CONVENTIONS</b><br>TemporalKG Specification",
        "drawio_style": "rounded=1;whiteSpace=wrap;html=1;fillColor=#F1F5F9;strokeColor=#64748B;strokeWidth=1.5;dashed=1;dashPattern=6 4;arcSize=3;"
    })
    # Legend inner text items
    builder.nodes.append({
        "id": "legend_text_left", "type": "arch_note",
        "x": 1155, "y": 50, "w": 260, "h": 50,
        "title": "SHAPES",
        "lines": [
            "Ellipse: Start / End",
            "Rect: Process / Op | Diamond: Decision",
            "Parallelogram: Input Data | Folded: Artifact"
        ],
        "drawio_style": STYLE_ARCH_NOTE
    })
    builder.nodes.append({
        "id": "legend_text_right", "type": "arch_note",
        "x": 1425, "y": 50, "w": 250, "h": 50,
        "title": "ORTHOGONAL FLOW ARROWS",
        "lines": [
            "Solid (Grey): Normal sequence",
            "Green: Valid / Pass (Yes)",
            "Red: Error / Fail (No) | Blue: Loop / Dep"
        ],
        "drawio_style": STYLE_ARCH_NOTE
    })

    # Header title node
    builder.nodes.append({
        "id": "main_title", "type": "rect",
        "x": 30, "y": 20, "w": 1080, "h": 85,
        "text": "MODULE 1: LOADER LOG FILTERING (LOADERFILTER)",
        "subtext": "LOW-LEVEL ALGORITHMIC FLOWCHART & PIPELINE ARCHITECTURE · TEMPORALKG CANONICAL SPECIFICATION",
        "drawio_style": "rounded=1;whiteSpace=wrap;html=1;fillColor=#0F172A;strokeColor=#0F172A;fontFamily=Arial;fontSize=18;fontStyle=1;fontColor=#FFFFFF;align=left;spacingLeft=25;"
    })

    # =========================================================================
    # 1. LEFT COLUMN: PIPELINE DATA FLOW ARCHITECTURE (X: 30, Y: 120, W: 460, H: 5120)
    # =========================================================================
    builder.add_container(
        "col_left", x=30, y=120, w=460, h=5120,
        title="MODULE 1 / PIPELINE DATA FLOW ARCHITECTURE",
        subtitle="5 Core Pipeline Steps · 1 QA Verification Suite · 1 Downstream Handoff"
    )

    # Pipeline Arch Notes & Steps
    # Top Inputs
    builder.add_parallelogram(
        "p_in1", x=60, y=180, w=400, h=55,
        text="WinMET Sandbox Traces (Volumes 1-5)",
        subtext="Raw CAPE JSON Execution Reports"
    )
    builder.add_parallelogram(
        "p_in2", x=60, y=250, w=400, h=55,
        text="Metadata Labels & Seed Taxonomy",
        subtext="AVClass + CAPE Detections + Consensus + taxonomy.json"
    )

    # Step 1
    builder.add_arch_note(
        "p_an1", x=60, y=325, w=400, h=50,
        title="DETERMINISTIC LOCATOR CONTRACT",
        lines=[
            "Strict pruning of symlinks, junctions, reparse points (0x400).",
            "Physical deduplication via (st_dev, st_ino) keys.",
            "SHA256 resolution: filename pattern -> ijson prefetch."
        ]
    )
    builder.add_rect(
        "p_s1", x=80, y=390, w=360, h=65,
        text="Step 1: Discover Sources",
        subtext="Path enumeration, link pruning, physical dedup, SHA prefetch"
    )
    builder.add_note(
        "p_out1", x=100, y=475, w=320, h=55,
        text="Discovered Sources Inventory",
        subtext="Deduped locators + Prefetched SHA-256"
    )

    # Step 2
    builder.add_arch_note(
        "p_an2", x=60, y=555, w=400, h=65,
        title="THREE-TIER SCREENING MODEL",
        lines=[
            "Tiers: Candidate -> Observed -> Payload Execution.",
            "Partitions: same_seed_family, one_seed_missing, diff_review.",
            "Only seed family members qualify for candidate status."
        ]
    )
    builder.add_rect(
        "p_s2", x=80, y=635, w=360, h=65,
        text="Step 2: Build Candidate Inventory",
        subtext="Label store matching, conflict reconciliation, 3-tier partitioning"
    )
    builder.add_note(
        "p_out2", x=100, y=720, w=320, h=55,
        text="Candidate Inventory Entries",
        subtext="seed_candidate | candidate | mismatch | not_candidate"
    )

    # Step 3
    builder.add_arch_note(
        "p_an3", x=60, y=800, w=400, h=65,
        title="BOUNDED RESOURCE STREAMING",
        lines=[
            "Parse limits: max file bytes, max call bytes, max JSON depth.",
            "Multi-worker pool with timeout isolation.",
            "Extract process tree, API calls, dropped files, memory dumps."
        ]
    )
    builder.add_rect(
        "p_s3", x=80, y=880, w=360, h=65,
        text="Step 3: Multi-Worker Evidence Scan",
        subtext="Streaming parse with ijson, process trees, API call facts"
    )
    builder.add_note(
        "p_out3", x=100, y=965, w=320, h=55,
        text="Extracted Evidence Store",
        subtext="evidence/by_report/{report_id}/ (facts, processes, artifacts)"
    )

    # Step 4
    builder.add_arch_note(
        "p_an4", x=60, y=1045, w=400, h=80,
        title="CONSERVATIVE BINDING CONTRACT",
        lines=[
            "observed = supported_family(target) AND trustworthy_binding(target->proc)",
            "           AND runtime_execution(proc) AND NOT conflicts.",
            "Binding trust: machine (cmdline/hash) + registry rules + review.",
            "payload_execution = observed AND child stage execution observed."
        ]
    )
    builder.add_rect(
        "p_s4", x=80, y=1140, w=360, h=65,
        text="Step 4: Conservative Decision & Manifest",
        subtext="Evaluate conservative-v1 policy, link bindings, CSV manifests"
    )
    builder.add_note(
        "p_out4", x=100, y=1225, w=320, h=55,
        text="Decision Manifests & JSONL",
        subtext="observed.csv | candidates.csv | all_reports.jsonl"
    )

    # Step 5
    builder.add_arch_note(
        "p_an5", x=60, y=1305, w=400, h=65,
        title="INDEPENDENT AUDIT TRAIL",
        lines=[
            "15 independent QC checks (QC-01..QC-15).",
            "Atomic SQLite state snapshot.",
            "CSV injection protection + UTF-8 BOM encoding."
        ]
    )
    builder.add_rect(
        "p_s5", x=80, y=1385, w=360, h=65,
        text="Step 5: Quality Assurance Verification",
        subtext="Execute QC-01 to QC-15 verification checks"
    )
    builder.add_note(
        "p_out5", x=100, y=1470, w=320, h=55,
        text="QA Report & Integrity Markers",
        subtext="qa_report.json + .loaderfilter-output.json"
    )

    # Step 6 / Export
    builder.add_arch_note(
        "p_an6", x=60, y=1550, w=400, h=50,
        title="DOWNSTREAM DATASET EXPORT",
        lines=[
            "Byte-for-byte verified copy of candidate JSON reports.",
            "Immutable source run: write to isolated destination directory."
        ]
    )
    builder.add_rect(
        "p_s6", x=80, y=1615, w=360, h=65,
        text="Candidate Report Export (tools/export_run.py)",
        subtext="Verified copy, SHA256 integrity check, manifest.jsonl"
    )
    builder.add_note(
        "p_out6", x=100, y=1700, w=320, h=55,
        text="Loader-Candidate Reports",
        subtext="export.json + manifest.jsonl + checksums.json + reports/"
    )

    # Downstream Handoff
    builder.add_block_arrow(
        "p_handoff", x=80, y=1790, w=360, h=60,
        text="Module 2: TransitionBuilder",
        subtext="Handoff Loader-Candidate Dataset to Stage Transitions & KG"
    )

    # Edges in Left Column
    builder.add_edge("pe_in1", "p_in1", "p_s1", "grey", points=[(260, 235), (260, 390)])
    builder.add_edge("pe_in2", "p_in2", "p_s2", "grey", points=[(460, 277), (475, 277), (475, 667), (440, 667)])
    builder.add_edge("pe_1", "p_s1", "p_out1", "grey", points=[(260, 455), (260, 475)])
    builder.add_edge("pe_2", "p_out1", "p_s2", "grey", points=[(260, 530), (260, 635)])
    builder.add_edge("pe_3", "p_s2", "p_out2", "grey", points=[(260, 700), (260, 720)])
    builder.add_edge("pe_4", "p_out2", "p_s3", "grey", points=[(260, 775), (260, 880)])
    builder.add_edge("pe_5", "p_s3", "p_out3", "grey", points=[(260, 945), (260, 965)])
    builder.add_edge("pe_6", "p_out3", "p_s4", "grey", points=[(260, 1020), (260, 1140)])
    builder.add_edge("pe_7", "p_s4", "p_out4", "grey", points=[(260, 1205), (260, 1225)])
    builder.add_edge("pe_8", "p_out4", "p_s5", "grey", points=[(260, 1280), (260, 1385)])
    builder.add_edge("pe_9", "p_s5", "p_out5", "grey", points=[(260, 1450), (260, 1470)])
    builder.add_edge("pe_10", "p_out5", "p_s6", "grey", points=[(260, 1525), (260, 1615)])
    builder.add_edge("pe_11", "p_s6", "p_out6", "grey", points=[(260, 1680), (260, 1700)])
    builder.add_edge("pe_12", "p_out6", "p_handoff", "grey", points=[(260, 1755), (260, 1790)])


    # =========================================================================
    # 2. RIGHT COLUMN: DETAILED STEP FLOWCHARTS (X: 520, W: 1180)
    # =========================================================================

    # -------------------------------------------------------------------------
    # STEP 1 / DISCOVER REPORT SOURCES (step1_discover_sources.py)
    # Container Y: 120, H: 810
    # -------------------------------------------------------------------------
    builder.add_container(
        "box_s1", x=520, y=120, w=1180, h=810,
        title="STEP 1 / DISCOVER REPORT SOURCES",
        subtitle="step1_discover_sources.py · Deterministic Link-Safe Enumeration & SHA-256 Prefetch"
    )
    # Inter-column link arrow
    builder.add_edge("link_s1", "p_s1", "box_s1", "dash_blue", label="Detail", points=[(440, 420), (520, 160)])

    # Arch Notes on Left of Step 1 (X: 540, W: 280)
    builder.add_arch_note(
        "s1_an1", x=540, y=165, w=280, h=85,
        title="INPUT ROOTS & GLOB PATTERNS",
        lines=[
            "Supports multiple roots (WinMET Vols 1-5).",
            "Translates include/exclude globs to regex.",
            "Prunes output directories to prevent recursion."
        ]
    )
    builder.add_arch_note(
        "s1_an2", x=540, y=270, w=280, h=85,
        title="FILESYSTEM SAFETY GUARDS",
        lines=[
            "Prunes symlinks, junctions, reparse points (0x400).",
            "Guards against circular traversal & lock hanging.",
            "Validates regular files via stat.S_ISREG."
        ]
    )
    builder.add_arch_note(
        "s1_an3", x=540, y=375, w=280, h=85,
        title="PHYSICAL DEDUPLICATION",
        lines=[
            "Maps (st_dev, st_ino) -> primary DiscoveredFile.",
            "Duplicate physical files -> secondary locators.",
            "source_id = sha256(root_id + '\\0' + relpath)."
        ]
    )
    builder.add_arch_note(
        "s1_an4", x=540, y=480, w=280, h=85,
        title="IDENTITY PREFETCH STREAMING",
        lines=[
            "If mode requires target sha256 (auto/report),",
            "stream-parse target.file.sha256 via ijson.",
            "Bounded by max_file_bytes; avoids full DOM RAM."
        ]
    )

    # Step 1 Flowchart Nodes (X center: 1160)
    builder.add_ellipse("s1_start", x=1080, y=160, w=160, h=38, text="Start")
    builder.add_parallelogram(
        "s1_in", x=980, y=215, w=360, h=48,
        text="Input: --config, --limit, input specs",
        subtext="config.inputs roots, include/exclude patterns"
    )
    builder.add_rect(
        "s1_init", x=980, y=280, w=360, h=44,
        text="Initialize RunLogger & PatternSets",
        subtext="Compile regexes; resolve excluded directories"
    )
    builder.add_diamond(
        "s1_d_roots", x=1010, y=340, w=300, h=52,
        text="More input roots in config?",
        subtext=""
    )
    builder.add_diamond(
        "s1_d_walk", x=1010, y=410, w=300, h=52,
        text="More directory entries in _walk?",
        subtext=""
    )
    builder.add_diamond(
        "s1_d_link", x=1020, y=480, w=280, h=50,
        text="Is symlink, junction, or reparse point?",
        subtext="FILE_ATTRIBUTE_REPARSE_POINT 0x400"
    )
    builder.add_rect(
        "s1_prune_link", x=1350, y=483, w=200, h=44,
        text="Increment skipped_links",
        subtext="Prune traversal handle"
    )
    builder.add_diamond(
        "s1_d_match", x=1020, y=550, w=280, h=50,
        text="Matches include & not excluded?",
        subtext="Regex check on relative & basename"
    )
    builder.add_diamond(
        "s1_d_phys", x=1010, y=620, w=300, h=52,
        text="(st_dev, st_ino) already indexed?",
        subtext="Physical file identity check"
    )
    builder.add_rect(
        "s1_sec_loc", x=1350, y=624, w=200, h=44,
        text="Append secondary locator",
        subtext="duplicate_physical_paths += 1"
    )
    builder.add_rect(
        "s1_create_file", x=980, y=690, w=360, h=44,
        text="Compute source_id & DiscoveredFile",
        subtext="sha256(root_id + '\\0' + relpath); record size, mtime"
    )
    builder.add_diamond(
        "s1_d_prefetch", x=1020, y=750, w=280, h=50,
        text="Needs target SHA256 prefetch?",
        subtext="mode == auto/report and missing from filename"
    )
    builder.add_rect(
        "s1_prefetch_stream", x=1350, y=753, w=200, h=44,
        text="Peek target.file.sha256",
        subtext="Stream via ijson up to max_bytes"
    )
    builder.add_note(
        "s1_out", x=980, y=820, w=360, h=48,
        text="Discovered Sources Inventory",
        subtext="DiscoveredFile records + target_shas mapping"
    )
    builder.add_ellipse("s1_end", x=1080, y=880, w=160, h=36, text="End")

    # Step 1 Edges
    builder.add_edge("s1_e1", "s1_start", "s1_in", "grey", points=[(1160, 198), (1160, 215)])
    builder.add_edge("s1_e2", "s1_in", "s1_init", "grey", points=[(1160, 263), (1160, 280)])
    builder.add_edge("s1_e3", "s1_init", "s1_d_roots", "grey", points=[(1160, 324), (1160, 340)])
    builder.add_edge("s1_e4", "s1_d_roots", "s1_d_walk", "green", label="Yes", points=[(1160, 392), (1160, 410)])
    builder.add_edge("s1_e5", "s1_d_walk", "s1_d_link", "green", label="Next file", points=[(1160, 462), (1160, 480)])
    builder.add_edge("s1_e6", "s1_d_link", "s1_prune_link", "red", label="Yes (Link)", points=[(1300, 505), (1350, 505)])
    builder.add_edge("s1_e7", "s1_prune_link", "s1_d_walk", "blue", label="Loop", points=[(1550, 505), (1570, 505), (1570, 436), (1310, 436)])
    builder.add_edge("s1_e8", "s1_d_link", "s1_d_match", "green", label="No (Regular)", points=[(1160, 530), (1160, 550)])
    builder.add_edge("s1_e9", "s1_d_match", "s1_d_phys", "green", label="Matches", points=[(1160, 600), (1160, 620)])
    builder.add_edge("s1_e10", "s1_d_phys", "s1_sec_loc", "red", label="Yes (Duplicate)", points=[(1310, 646), (1350, 646)])
    builder.add_edge("s1_e11", "s1_sec_loc", "s1_d_walk", "blue", label="Loop", points=[(1550, 646), (1580, 646), (1580, 436), (1310, 436)])
    builder.add_edge("s1_e12", "s1_d_phys", "s1_create_file", "green", label="No (New)", points=[(1160, 672), (1160, 690)])
    builder.add_edge("s1_e13", "s1_create_file", "s1_d_prefetch", "grey", points=[(1160, 734), (1160, 750)])
    builder.add_edge("s1_e14", "s1_d_prefetch", "s1_prefetch_stream", "green", label="Yes", points=[(1300, 775), (1350, 775)])
    builder.add_edge("s1_e15", "s1_prefetch_stream", "s1_out", "grey", points=[(1450, 797), (1450, 844), (1340, 844)])
    builder.add_edge("s1_e16", "s1_d_prefetch", "s1_out", "grey", label="No", points=[(1160, 800), (1160, 820)])
    builder.add_edge("s1_e17", "s1_out", "s1_end", "grey", points=[(1160, 868), (1160, 880)])
    builder.add_edge("s1_e18", "s1_d_roots", "s1_out", "red", label="No (Done)", points=[(1010, 366), (920, 366), (920, 844), (980, 844)])


    # -------------------------------------------------------------------------
    # STEP 2 / BUILD CANDIDATE INVENTORY (step2_build_inventory.py)
    # Container Y: 960, H: 810
    # -------------------------------------------------------------------------
    builder.add_container(
        "box_s2", x=520, y=960, w=1180, h=810,
        title="STEP 2 / BUILD CANDIDATE INVENTORY",
        subtitle="step2_build_inventory.py · Multi-Label Reconciliation & 3-Tier Candidate Screening"
    )
    builder.add_edge("link_s2", "p_s2", "box_s2", "dash_blue", label="Detail", points=[(440, 667), (520, 1000)])

    # Arch Notes on Left of Step 2 (X: 540, W: 280)
    builder.add_arch_note(
        "s2_an1", x=540, y=1005, w=280, h=85,
        title="SEED TAXONOMY CONTRACT",
        lines=[
            "Explicit seed family list: smokeloader, guloader, sload,...",
            "Normalizes aliases to canonical identifiers.",
            "Casefold canonical resolution contract."
        ]
    )
    builder.add_arch_note(
        "s2_an2", x=540, y=1110, w=280, h=85,
        title="TRIPLE LABEL RECONCILIATION",
        lines=[
            "AVClass + CAPE Detections + Consensus mapping.",
            "Per-kind state: present | absent | missing | conflict.",
            "Pair state: same_canonical | one_present | diff | unresolved."
        ]
    )
    builder.add_arch_note(
        "s2_an3", x=540, y=1215, w=280, h=85,
        title="THREE-TIER PARTITIONING",
        lines=[
            "Partition 1: same_seed_family (high confidence agreement).",
            "Partition 2: one_seed_other_missing (unilateral signal).",
            "Partition 3: different_nonmissing_labels_review (conflict)."
        ]
    )
    builder.add_arch_note(
        "s2_an4", x=540, y=1320, w=280, h=85,
        title="CANDIDATE ADMISSION PREDICATE",
        lines=[
            "is_candidate = True iff label in seed taxonomy families",
            "or consensus indicates loader candidate.",
            "Non-loaders categorized as not_candidate."
        ]
    )

    # Step 2 Flowchart Nodes
    builder.add_ellipse("s2_start", x=1080, y=1000, w=160, h=38, text="Start")
    builder.add_parallelogram(
        "s2_in", x=980, y=1055, w=360, h=48,
        text="Input: Discovered files, taxonomy.json",
        subtext="Label files: AVClass, CAPE, Consensus tables"
    )
    builder.add_rect(
        "s2_init", x=980, y=1120, w=360, h=44,
        text="Initialize LabelStore & Load Taxonomy",
        subtext="Ingest labels; record SHA256 file fingerprints"
    )
    builder.add_diamond(
        "s2_d_files", x=1010, y=1180, w=300, h=52,
        text="More discovered files to evaluate?",
        subtext=""
    )
    builder.add_rect(
        "s2_resolve_sha", x=980, y=1250, w=360, h=44,
        text="Resolve SHA-256 for File Locator",
        subtext="Check filename -> target_shas -> source_id fallback"
    )
    builder.add_rect(
        "s2_lookup_labels", x=980, y=1310, w=360, h=44,
        text="Lookup LabelStore & Classify States",
        subtext="Determine kind states: present | absent | missing | conflict"
    )
    builder.add_rect(
        "s2_pair_state", x=980, y=1370, w=360, h=44,
        text="Compute label_pair_state Contract",
        subtext="same_canonical_family | one_present | different_nonmissing"
    )
    builder.add_diamond(
        "s2_d_seed", x=1010, y=1430, w=300, h=52,
        text="Any label maps to seed loader family?",
        subtext="Taxonomy seed loader membership test"
    )
    builder.add_rect(
        "s2_cand_yes", x=1350, y=1434, w=210, h=44,
        text="is_candidate = True",
        subtext="is_seed_candidate = True; partition counter"
    )
    builder.add_diamond(
        "s2_d_consensus", x=1010, y=1500, w=300, h=52,
        text="Consensus or review indicates candidate?",
        subtext="Secondary loader identification check"
    )
    builder.add_rect(
        "s2_cand_rev", x=1350, y=1504, w=210, h=44,
        text="is_candidate = True (Review)",
        subtext="Flagged for human / rule review"
    )
    builder.add_rect(
        "s2_cand_no", x=980, y=1570, w=360, h=44,
        text="is_candidate = False",
        subtext="Classify entry as not_candidate"
    )
    builder.add_note(
        "s2_out", x=980, y=1630, w=360, h=48,
        text="Candidate Inventory Entries",
        subtext="InventoryResult (seed_candidates, candidates, non_candidates)"
    )
    builder.add_ellipse("s2_end", x=1080, y=1695, w=160, h=36, text="End")

    # Step 2 Edges
    builder.add_edge("s2_e1", "s2_start", "s2_in", "grey", points=[(1160, 1038), (1160, 1055)])
    builder.add_edge("s2_e2", "s2_in", "s2_init", "grey", points=[(1160, 1103), (1160, 1120)])
    builder.add_edge("s2_e3", "s2_init", "s2_d_files", "grey", points=[(1160, 1164), (1160, 1180)])
    builder.add_edge("s2_e4", "s2_d_files", "s2_resolve_sha", "green", label="Next file", points=[(1160, 1232), (1160, 1250)])
    builder.add_edge("s2_e5", "s2_resolve_sha", "s2_lookup_labels", "grey", points=[(1160, 1294), (1160, 1310)])
    builder.add_edge("s2_e6", "s2_lookup_labels", "s2_pair_state", "grey", points=[(1160, 1354), (1160, 1370)])
    builder.add_edge("s2_e7", "s2_pair_state", "s2_d_seed", "grey", points=[(1160, 1414), (1160, 1430)])
    builder.add_edge("s2_e8", "s2_d_seed", "s2_cand_yes", "green", label="Yes (Seed)", points=[(1310, 1456), (1350, 1456)])
    builder.add_edge("s2_e9", "s2_cand_yes", "s2_d_files", "blue", label="Next", points=[(1560, 1456), (1580, 1456), (1580, 1206), (1310, 1206)])
    builder.add_edge("s2_e10", "s2_d_seed", "s2_d_consensus", "red", label="No", points=[(1160, 1482), (1160, 1500)])
    builder.add_edge("s2_e11", "s2_d_consensus", "s2_cand_rev", "green", label="Yes", points=[(1310, 1526), (1350, 1526)])
    builder.add_edge("s2_e12", "s2_cand_rev", "s2_d_files", "blue", label="Next", points=[(1560, 1526), (1580, 1526), (1580, 1206), (1310, 1206)])
    builder.add_edge("s2_e13", "s2_d_consensus", "s2_cand_no", "red", label="No", points=[(1160, 1552), (1160, 1570)])
    builder.add_edge("s2_e14", "s2_cand_no", "s2_d_files", "blue", label="Next", points=[(980, 1592), (940, 1592), (940, 1206), (1010, 1206)])
    builder.add_edge("s2_e15", "s2_d_files", "s2_out", "red", label="No (Done)", points=[(1010, 1206), (910, 1206), (910, 1654), (980, 1654)])
    builder.add_edge("s2_e16", "s2_out", "s2_end", "grey", points=[(1160, 1678), (1160, 1695)])


    # -------------------------------------------------------------------------
    # STEP 3 / STREAM-PARSE & EXTRACT EVIDENCE (step3_scan_evidence.py)
    # Container Y: 1800, H: 830
    # -------------------------------------------------------------------------
    builder.add_container(
        "box_s3", x=520, y=1800, w=1180, h=830,
        title="STEP 3 / STREAM-PARSE & EXTRACT EVIDENCE",
        subtitle="step3_scan_evidence.py · Multi-Worker Streaming CAPE Parser & Fact Abstraction"
    )
    builder.add_edge("link_s3", "p_s3", "box_s3", "dash_blue", label="Detail", points=[(440, 912), (520, 1840)])

    # Arch Notes on Left of Step 3 (X: 540, W: 280)
    builder.add_arch_note(
        "s3_an1", x=540, y=1845, w=280, h=85,
        title="SELECTIVE CANDIDATE SCOPE",
        lines=[
            "Default analysis scope: candidates only.",
            "Optional scope: all (full corpus audit).",
            "Avoids parsing gigabytes of irrelevant traces."
        ]
    )
    builder.add_arch_note(
        "s3_an2", x=540, y=1950, w=280, h=85,
        title="BOUNDED STREAMING (ijson)",
        lines=[
            "Direct streaming over CAPE JSON tokens.",
            "Never loads full JSON tree into RAM.",
            "max_json_depth guard prevents deep stack overflows."
        ]
    )
    builder.add_arch_note(
        "s3_an3", x=540, y=2055, w=280, h=85,
        title="MULTI-WORKER TIMEOUT GUARDS",
        lines=[
            "ParseScheduler spawns isolated worker pool.",
            "Enforces max_file_bytes (200MB) & timeout_seconds.",
            "Worker kills hanging JSON parser gracefully."
        ]
    )
    builder.add_arch_note(
        "s3_an4", x=540, y=2160, w=280, h=85,
        title="EVIDENCE ABSTRACTION CONTRACT",
        lines=[
            "Process tree: PID, PPID, cmdline, call_count.",
            "API events: process_create, remote_thread, alloc.",
            "Synthesizes Fact records with deterministic evidence_id."
        ]
    )

    # Step 3 Flowchart Nodes
    builder.add_ellipse("s3_start", x=1080, y=1840, w=160, h=38, text="Start")
    builder.add_parallelogram(
        "s3_in", x=980, y=1895, w=360, h=48,
        text="Input: InventoryEntry list, config.resources",
        subtext="Workers count, timeout_seconds, limits"
    )
    builder.add_rect(
        "s3_filter_tasks", x=980, y=1960, w=360, h=44,
        text="Filter Entries by Scope & Build Tasks",
        subtext="Filter scope == candidates; construct worker payload"
    )
    builder.add_rect(
        "s3_sched_init", x=980, y=2020, w=360, h=44,
        text="Initialize ParseScheduler(workers=N)",
        subtext="Dispatch worker pool; open task communication pipe"
    )
    builder.add_diamond(
        "s3_d_tasks", x=1010, y=2080, w=300, h=52,
        text="More parsing tasks in worker queue?",
        subtext=""
    )
    builder.add_diamond(
        "s3_d_size", x=1010, y=2150, w=300, h=52,
        text="File size <= max_file_bytes?",
        subtext="Resource exhaustion guard (default: 200MB)"
    )
    builder.add_rect(
        "s3_err_size", x=1350, y=2154, w=210, h=44,
        text="Record Error: file_too_large",
        subtext="Increment error count; skip file"
    )
    builder.add_diamond(
        "s3_d_timeout", x=1010, y=2220, w=300, h=52,
        text="Parse completes within timeout?",
        subtext="Process execution timeout guard (e.g. 180s)"
    )
    builder.add_rect(
        "s3_err_timeout", x=1350, y=2224, w=210, h=44,
        text="Record Error: timeout_exceeded",
        subtext="Kill worker process; record error"
    )
    builder.add_rect(
        "s3_extract_facts", x=980, y=2290, w=360, h=44,
        text="Extract Processes, API Calls & Dropped Files",
        subtext="ijson stream parse; synthesize deterministic Fact records"
    )
    builder.add_rect(
        "s3_write_evidence", x=980, y=2350, w=360, h=44,
        text="Write ReportEvidence Artifacts",
        subtext="Save to run_dir/evidence/by_report/{report_id}/"
    )
    builder.add_rect(
        "s3_store_sqlite", x=980, y=2410, w=360, h=44,
        text="Update StateStore SQLite & Completed Count",
        subtext="Upsert report status; commit transaction"
    )
    builder.add_note(
        "s3_out", x=980, y=2470, w=360, h=48,
        text="Extracted Evidence Store",
        subtext="evidence/by_report/{id}/ (facts, processes, artifacts)"
    )
    builder.add_ellipse("s3_end", x=1080, y=2535, w=160, h=36, text="End")

    # Step 3 Edges
    builder.add_edge("s3_e1", "s3_start", "s3_in", "grey", points=[(1160, 1878), (1160, 1895)])
    builder.add_edge("s3_e2", "s3_in", "s3_filter_tasks", "grey", points=[(1160, 1943), (1160, 1960)])
    builder.add_edge("s3_e3", "s3_filter_tasks", "s3_sched_init", "grey", points=[(1160, 2004), (1160, 2020)])
    builder.add_edge("s3_e4", "s3_sched_init", "s3_d_tasks", "grey", points=[(1160, 2064), (1160, 2080)])
    builder.add_edge("s3_e5", "s3_d_tasks", "s3_d_size", "green", label="Next task", points=[(1160, 2132), (1160, 2150)])
    builder.add_edge("s3_e6", "s3_d_size", "s3_err_size", "red", label="No", points=[(1310, 2176), (1350, 2176)])
    builder.add_edge("s3_e7", "s3_err_size", "s3_d_tasks", "blue", label="Next", points=[(1560, 2176), (1580, 2176), (1580, 2106), (1310, 2106)])
    builder.add_edge("s3_e8", "s3_d_size", "s3_d_timeout", "green", label="Yes", points=[(1160, 2202), (1160, 2220)])
    builder.add_edge("s3_e9", "s3_d_timeout", "s3_err_timeout", "red", label="Timeout", points=[(1310, 2246), (1350, 2246)])
    builder.add_edge("s3_e10", "s3_err_timeout", "s3_d_tasks", "blue", label="Next", points=[(1560, 2246), (1580, 2246), (1580, 2106), (1310, 2106)])
    builder.add_edge("s3_e11", "s3_d_timeout", "s3_extract_facts", "green", label="Success", points=[(1160, 2272), (1160, 2290)])
    builder.add_edge("s3_e12", "s3_extract_facts", "s3_write_evidence", "grey", points=[(1160, 2334), (1160, 2350)])
    builder.add_edge("s3_e13", "s3_write_evidence", "s3_store_sqlite", "grey", points=[(1160, 2394), (1160, 2410)])
    builder.add_edge("s3_e14", "s3_store_sqlite", "s3_d_tasks", "blue", label="Next task", points=[(980, 2432), (930, 2432), (930, 2106), (1010, 2106)])
    builder.add_edge("s3_e15", "s3_d_tasks", "s3_out", "red", label="No (Done)", points=[(1010, 2106), (900, 2106), (900, 2494), (980, 2494)])
    builder.add_edge("s3_e16", "s3_out", "s3_end", "grey", points=[(1160, 2518), (1160, 2535)])


    # -------------------------------------------------------------------------
    # STEP 4 / CONSERVATIVE POLICY DECISION & MANIFEST (step4_decide_and_manifest.py)
    # Container Y: 2660, H: 870
    # -------------------------------------------------------------------------
    builder.add_container(
        "box_s4", x=520, y=2660, w=1180, h=870,
        title="STEP 4 / CONSERVATIVE POLICY DECISION & MANIFEST",
        subtitle="step4_decide_and_manifest.py · conservative-v1 Evaluation, Binding Graph & Manifests"
    )
    builder.add_edge("link_s4", "p_s4", "box_s4", "dash_blue", label="Detail", points=[(440, 1172), (520, 2700)])

    # Arch Notes on Left of Step 4 (X: 540, W: 280)
    builder.add_arch_note(
        "s4_an1", x=540, y=2705, w=280, h=85,
        title="CONSERVATIVE-V1 PREDICATE",
        lines=[
            "observed = supported_family(target)",
            "           AND trustworthy_binding(target->process)",
            "           AND runtime_execution(process)",
            "           AND NOT invalidating_conflicts."
        ]
    )
    builder.add_arch_note(
        "s4_an2", x=540, y=2810, w=280, h=85,
        title="BINDING TRUST HIERARCHY",
        lines=[
            "Machine bindings: cmdline hash, injection target.",
            "Registry rules: curated technical patterns.",
            "Human audit: verified analysts' reviews.",
            "Unbound execution -> stays false; flagged review."
        ]
    )
    builder.add_arch_note(
        "s4_an3", x=540, y=2915, w=280, h=85,
        title="RUNTIME EXECUTION PROOF",
        lines=[
            "Target process must have call_count > 0.",
            "Verified via successful process_create or",
            "remote_thread targeting candidate process PID.",
            "No execution call -> not evaluated."
        ]
    )
    builder.add_arch_note(
        "s4_an4", x=540, y=3020, w=280, h=85,
        title="PAYLOAD EXECUTION TIER",
        lines=[
            "payload_execution = observed",
            "AND secondary execution of non-target payload",
            "(dropped exe, procdump, hollowed child process).",
            "Distinguishes initial loader from actual payload."
        ]
    )
    builder.add_arch_note(
        "s4_an5", x=540, y=3125, w=280, h=85,
        title="SECURE MANIFEST GENERATION",
        lines=[
            "UTF-8 BOM encoding for Excel compatibility.",
            "Sanitizes leading formula chars (=, +, -, @).",
            "Streams all_reports.jsonl with full decision trace."
        ]
    )

    # Step 4 Flowchart Nodes
    builder.add_ellipse("s4_start", x=1080, y=2700, w=160, h=38, text="Start")
    builder.add_parallelogram(
        "s4_in", x=980, y=2755, w=360, h=48,
        text="Input: StateStore SQLite, run_id, review files",
        subtext="manifest_dir, all_reports.jsonl output path"
    )
    builder.add_diamond(
        "s4_d_reports", x=1010, y=2820, w=300, h=52,
        text="More reports in StateStore to evaluate?",
        subtext=""
    )
    builder.add_rect(
        "s4_bindings", x=980, y=2890, w=360, h=44,
        text="Generate Machine, Registry & Review Bindings",
        subtext="Determine trustworthy_process_indices"
    )
    builder.add_rect(
        "s4_runtime_exec", x=980, y=2950, w=360, h=44,
        text="Evaluate runtime_execution(process_index)",
        subtext="Inspect process_create & remote_thread success events"
    )
    builder.add_diamond(
        "s4_d_exec", x=1010, y=3010, w=300, h=52,
        text="Execution confirmed with trusted binding?",
        subtext=""
    )
    builder.add_diamond(
        "s4_d_obs", x=1010, y=3080, w=300, h=52,
        text="Target SHA matches & Family supported?",
        subtext="Zero invalidating conflicts"
    )
    builder.add_rect(
        "s4_set_obs", x=1350, y=3084, w=210, h=44,
        text="observed = True",
        subtext="execution_status = loader_execution_observed"
    )
    builder.add_diamond(
        "s4_d_payload", x=1010, y=3150, w=300, h=52,
        text="observed == True & Child stage executed?",
        subtext="Procdump, dropped executable, injected child"
    )
    builder.add_rect(
        "s4_set_payload", x=1350, y=3154, w=210, h=44,
        text="payload_execution = True",
        subtext="Second-stage payload execution verified"
    )
    builder.add_rect(
        "s4_classify_dec", x=980, y=3220, w=360, h=44,
        text="Assign machine_decision & Quality Flags",
        subtext="loader_run_observed | needs_review | unresolved"
    )
    builder.add_rect(
        "s4_write_manifests", x=980, y=3280, w=360, h=44,
        text="Generate CSV Manifests & all_reports.jsonl",
        subtext="UTF-8 BOM; CSV anti-formula injection; write 6 CSVs"
    )
    builder.add_note(
        "s4_out", x=980, y=3340, w=360, h=48,
        text="Decision Manifests & JSONL",
        subtext="observed.csv, candidates.csv, payload_execution.csv, jsonl"
    )
    builder.add_ellipse("s4_end", x=1080, y=3405, w=160, h=36, text="End")

    # Step 4 Edges
    builder.add_edge("s4_e1", "s4_start", "s4_in", "grey", points=[(1160, 2738), (1160, 2755)])
    builder.add_edge("s4_e2", "s4_in", "s4_d_reports", "grey", points=[(1160, 2803), (1160, 2820)])
    builder.add_edge("s4_e3", "s4_d_reports", "s4_bindings", "green", label="Next report", points=[(1160, 2872), (1160, 2890)])
    builder.add_edge("s4_e4", "s4_bindings", "s4_runtime_exec", "grey", points=[(1160, 2934), (1160, 2950)])
    builder.add_edge("s4_e5", "s4_runtime_exec", "s4_d_exec", "grey", points=[(1160, 2994), (1160, 3010)])
    builder.add_edge("s4_e6", "s4_d_exec", "s4_d_obs", "green", label="Yes", points=[(1160, 3062), (1160, 3080)])
    builder.add_edge("s4_e7", "s4_d_obs", "s4_set_obs", "green", label="Yes (Satisfied)", points=[(1310, 3106), (1350, 3106)])
    builder.add_edge("s4_e8", "s4_d_obs", "s4_d_payload", "red", label="No", points=[(1160, 3132), (1160, 3150)])
    builder.add_edge("s4_e9", "s4_set_obs", "s4_d_payload", "grey", points=[(1450, 3128), (1450, 3176), (1310, 3176)])
    builder.add_edge("s4_e10", "s4_d_payload", "s4_set_payload", "green", label="Yes", points=[(1310, 3176), (1350, 3176)])
    builder.add_edge("s4_e11", "s4_d_payload", "s4_classify_dec", "red", label="No", points=[(1160, 3202), (1160, 3220)])
    builder.add_edge("s4_e12", "s4_set_payload", "s4_classify_dec", "grey", points=[(1450, 3198), (1450, 3242), (1340, 3242)])
    builder.add_edge("s4_e13", "s4_d_exec", "s4_classify_dec", "red", label="No exec", points=[(1010, 3036), (950, 3036), (950, 3242), (980, 3242)])
    builder.add_edge("s4_e14", "s4_classify_dec", "s4_d_reports", "blue", label="Next report", points=[(980, 3242), (920, 3242), (920, 2846), (1010, 2846)])
    builder.add_edge("s4_e15", "s4_d_reports", "s4_write_manifests", "red", label="Done", points=[(1310, 2846), (1580, 2846), (1580, 3302), (1340, 3302)])
    builder.add_edge("s4_e16", "s4_write_manifests", "s4_out", "grey", points=[(1160, 3324), (1160, 3340)])
    builder.add_edge("s4_e17", "s4_out", "s4_end", "grey", points=[(1160, 3388), (1160, 3405)])


    # -------------------------------------------------------------------------
    # STEP 5 / RUN QUALITY ASSURANCE (step5_run_qa.py)
    # Container Y: 3560, H: 810
    # -------------------------------------------------------------------------
    builder.add_container(
        "box_s5", x=520, y=3560, w=1180, h=810,
        title="STEP 5 / RUN QUALITY ASSURANCE",
        subtitle="step5_run_qa.py · QC-01 to QC-15 Verification Suite & Data Integrity Audit"
    )
    builder.add_edge("link_s5", "p_s5", "box_s5", "dash_blue", label="Detail", points=[(440, 1417), (520, 3600)])

    # Arch Notes on Left of Step 5 (X: 540, W: 280)
    builder.add_arch_note(
        "s5_an1", x=540, y=3605, w=280, h=85,
        title="ISOLATED CHECK EXECUTION",
        lines=[
            "Each check runs in isolated try-except block.",
            "Check exception -> recorded as 'error' not abort.",
            "Ensures full QA audit visibility even on broken runs."
        ]
    )
    builder.add_arch_note(
        "s5_an2", x=540, y=3710, w=280, h=105,
        title="15 QUALITY CONTROL CHECKS",
        lines=[
            "QC-01..03: Config, taxonomy, label fingerprints.",
            "QC-04..06: Source ID uniqueness, derivation, 1:1 map.",
            "QC-07..08: Evidence checksums & non-empty schema.",
            "QC-09..11: Decision coverage, CSV BOM, row parity.",
            "QC-12..13: Hierarchy (observed <= cand <= all) & unres.",
            "QC-14..15: Run markers & State/Logs audit trail."
        ]
    )
    builder.add_arch_note(
        "s5_an3", x=540, y=3835, w=280, h=85,
        title="ATOMIC OUTCOME CONTRACT",
        lines=[
            "Overall status is 'pass' iff 0 failures.",
            "Emits qa/qa_report.json with full check details.",
            "Writes .loaderfilter-output.json completion marker."
        ]
    )

    # Step 5 Flowchart Nodes
    builder.add_ellipse("s5_start", x=1080, y=3600, w=160, h=38, text="Start")
    builder.add_parallelogram(
        "s5_in", x=980, y=3655, w=360, h=48,
        text="Input: RunLayout, StateStore, Config, run_id",
        subtext="Load state.sqlite, manifests, config snapshots"
    )
    builder.add_rect(
        "s5_init_log", x=980, y=3720, w=360, h=44,
        text="Initialize CheckLog & Load Database Entities",
        subtext="Query sources, reports, report_meta, artifacts"
    )
    builder.add_rect(
        "s5_qc_cfg", x=980, y=3780, w=360, h=44,
        text="Execute QC-01 to QC-03: Config & Fingerprints",
        subtext="Verify semantic config hash, taxonomy SHA, label files"
    )
    builder.add_rect(
        "s5_qc_src", x=980, y=3840, w=360, h=44,
        text="Execute QC-04 to QC-06: Identity & Locators",
        subtext="Check unique source_ids, derivation, 1:1 report hash"
    )
    builder.add_rect(
        "s5_qc_evi", x=980, y=3900, w=360, h=44,
        text="Execute QC-07 to QC-08: Evidence Integrity",
        subtext="Verify evidence files on disk & schema compliance"
    )
    builder.add_rect(
        "s5_qc_man", x=980, y=3960, w=360, h=44,
        text="Execute QC-09 to QC-11: Manifests & Formats",
        subtext="Check decision coverage, UTF-8 BOM, row count parity"
    )
    builder.add_rect(
        "s5_qc_hier", x=980, y=4020, w=360, h=44,
        text="Execute QC-12 to QC-15: Hierarchy & Run Markers",
        subtext="observed <= candidate <= all_sources; output markers"
    )
    builder.add_diamond(
        "s5_d_pass", x=1010, y=4080, w=300, h=52,
        text="All 15 QC checks passed?",
        subtext="failures_count == 0"
    )
    builder.add_block_arrow(
        "s5_fail", x=1350, y=4084, w=210, h=44,
        text="Return EXIT_INTEGRITY (1)",
        subtext="QA Failed; Log check failures"
    )
    builder.add_rect(
        "s5_write_qa", x=980, y=4150, w=360, h=44,
        text="Write qa/qa_report.json & Marker",
        subtext="Create .loaderfilter-output.json; commit SQLite run status"
    )
    builder.add_note(
        "s5_out", x=980, y=4210, w=360, h=48,
        text="QA Verification Artifacts",
        subtext="qa_report.json + .loaderfilter-output.json"
    )
    builder.add_ellipse("s5_end", x=1080, y=4275, w=160, h=36, text="End")

    # Step 5 Edges
    builder.add_edge("s5_e1", "s5_start", "s5_in", "grey", points=[(1160, 3638), (1160, 3655)])
    builder.add_edge("s5_e2", "s5_in", "s5_init_log", "grey", points=[(1160, 3703), (1160, 3720)])
    builder.add_edge("s5_e3", "s5_init_log", "s5_qc_cfg", "grey", points=[(1160, 3764), (1160, 3780)])
    builder.add_edge("s5_e4", "s5_qc_cfg", "s5_qc_src", "grey", points=[(1160, 3824), (1160, 3840)])
    builder.add_edge("s5_e5", "s5_qc_src", "s5_qc_evi", "grey", points=[(1160, 3884), (1160, 3900)])
    builder.add_edge("s5_e6", "s5_qc_evi", "s5_qc_man", "grey", points=[(1160, 3944), (1160, 3960)])
    builder.add_edge("s5_e7", "s5_qc_man", "s5_qc_hier", "grey", points=[(1160, 4004), (1160, 4020)])
    builder.add_edge("s5_e8", "s5_qc_hier", "s5_d_pass", "grey", points=[(1160, 4064), (1160, 4080)])
    builder.add_edge("s5_e9", "s5_d_pass", "s5_fail", "red", label="Fail", points=[(1310, 4106), (1350, 4106)])
    builder.add_edge("s5_e10", "s5_d_pass", "s5_write_qa", "green", label="Pass", points=[(1160, 4132), (1160, 4150)])
    builder.add_edge("s5_e11", "s5_write_qa", "s5_out", "grey", points=[(1160, 4194), (1160, 4210)])
    builder.add_edge("s5_e12", "s5_out", "s5_end", "grey", points=[(1160, 4258), (1160, 4275)])


    # -------------------------------------------------------------------------
    # STEP 6 / EXPORT CANDIDATE DATASET (tools/export_run.py)
    # Container Y: 4400, H: 800
    # -------------------------------------------------------------------------
    builder.add_container(
        "box_s6", x=520, y=4400, w=1180, h=800,
        title="STEP 6 / EXPORT CANDIDATE DATASET",
        subtitle="tools/export_run.py · Byte-for-Byte Verified Handoff to Module 2"
    )
    builder.add_edge("link_s6", "p_s6", "box_s6", "dash_blue", label="Detail", points=[(440, 1647), (520, 4440)])

    # Arch Notes on Left of Step 6 (X: 540, W: 280)
    builder.add_arch_note(
        "s6_an1", x=540, y=4445, w=280, h=85,
        title="IMMUTABLE SOURCE RUN",
        lines=[
            "Exports NEVER modify the source run directory.",
            "All output written to a fresh destination layout.",
            "Generates export.json metadata & checksums.json."
        ]
    )
    builder.add_arch_note(
        "s6_an2", x=540, y=4550, w=280, h=85,
        title="BYTE-FOR-BYTE COPY & VERIFY",
        lines=[
            "Copies raw reports through .tmp files.",
            "Calculates SHA-256 of copied bytes.",
            "Verifies matches recorded manifest SHA-256.",
            "Atomically renames to final destination path."
        ]
    )
    builder.add_arch_note(
        "s6_an3", x=540, y=4655, w=280, h=85,
        title="SELECTION & BUCKETING",
        lines=[
            "Selections: candidates | seed-candidates | observed.",
            "Buckets: loader_strict | payload | mixed.",
            "Optional --group-by-year partition."
        ]
    )

    # Step 6 Flowchart Nodes
    builder.add_ellipse("s6_start", x=1080, y=4440, w=160, h=38, text="Start")
    builder.add_parallelogram(
        "s6_in", x=980, y=4495, w=360, h=48,
        text="Input: --run-dir, --dest, --selection, --format",
        subtext="Export options: format=reports, group_by_year=True"
    )
    builder.add_diamond(
        "s6_d_qa", x=1010, y=4560, w=300, h=52,
        text="Run QA Status == success?",
        subtext="Check .loaderfilter-output.json marker"
    )
    builder.add_block_arrow(
        "s6_abort_qa", x=1350, y=4564, w=210, h=44,
        text="Raise UsageError",
        subtext="Cannot export from unverified run"
    )
    builder.add_rect(
        "s6_filter_sources", x=980, y=4630, w=360, h=44,
        text="Filter Sources by Selection Scope",
        subtext="e.g. selection == candidates -> filter is_candidate == True"
    )
    builder.add_diamond(
        "s6_d_reports", x=1010, y=4690, w=300, h=52,
        text="More selected reports to export?",
        subtext=""
    )
    builder.add_rect(
        "s6_copy_tmp", x=980, y=4760, w=360, h=44,
        text="Copy Raw JSON to dest/.tmp",
        subtext="Compute SHA-256 digest of copied bytes"
    )
    builder.add_diamond(
        "s6_d_sha", x=1010, y=4820, w=300, h=52,
        text="Copied SHA-256 == Expected SHA-256?",
        subtext="Byte integrity verification guard"
    )
    builder.add_block_arrow(
        "s6_abort_sha", x=1350, y=4824, w=210, h=44,
        text="Raise IntegrityError",
        subtext="Source bytes altered on disk!"
    )
    builder.add_rect(
        "s6_rename_atomic", x=980, y=4890, w=360, h=44,
        text="Atomic Rename .tmp -> dest/reports/",
        subtext="Record in manifest.jsonl with metadata"
    )
    builder.add_rect(
        "s6_write_export_meta", x=980, y=4950, w=360, h=44,
        text="Write export.json & checksums.json",
        subtext="Save manifest.jsonl and overall export counts"
    )
    builder.add_note(
        "s6_out", x=980, y=5010, w=360, h=48,
        text="Loader-Candidate Reports",
        subtext="export.json + manifest.jsonl + checksums.json + reports/"
    )
    builder.add_block_arrow(
        "s6_exit", x=980, y=5075, w=360, h=50,
        text="Handoff to Module 2 (TransitionBuilder)",
        subtext="Input dataset for Stage Transitions & Knowledge Graph"
    )
    builder.add_ellipse("s6_end", x=1080, y=5145, w=160, h=36, text="End")

    # Step 6 Edges
    builder.add_edge("s6_e1", "s6_start", "s6_in", "grey", points=[(1160, 4478), (1160, 4495)])
    builder.add_edge("s6_e2", "s6_in", "s6_d_qa", "grey", points=[(1160, 4543), (1160, 4560)])
    builder.add_edge("s6_e3", "s6_d_qa", "s6_abort_qa", "red", label="No", points=[(1310, 4586), (1350, 4586)])
    builder.add_edge("s6_e4", "s6_d_qa", "s6_filter_sources", "green", label="Yes", points=[(1160, 4612), (1160, 4630)])
    builder.add_edge("s6_e5", "s6_filter_sources", "s6_d_reports", "grey", points=[(1160, 4674), (1160, 4690)])
    builder.add_edge("s6_e6", "s6_d_reports", "s6_copy_tmp", "green", label="Next report", points=[(1160, 4742), (1160, 4760)])
    builder.add_edge("s6_e7", "s6_copy_tmp", "s6_d_sha", "grey", points=[(1160, 4804), (1160, 4820)])
    builder.add_edge("s6_e8", "s6_d_sha", "s6_abort_sha", "red", label="Mismatch", points=[(1310, 4846), (1350, 4846)])
    builder.add_edge("s6_e9", "s6_d_sha", "s6_rename_atomic", "green", label="Matches", points=[(1160, 4872), (1160, 4890)])
    builder.add_edge("s6_e10", "s6_rename_atomic", "s6_d_reports", "blue", label="Next", points=[(980, 4912), (930, 4912), (930, 4716), (1010, 4716)])
    builder.add_edge("s6_e11", "s6_d_reports", "s6_write_export_meta", "red", label="Done", points=[(1310, 4716), (1580, 4716), (1580, 4972), (1340, 4972)])
    builder.add_edge("s6_e12", "s6_write_export_meta", "s6_out", "grey", points=[(1160, 4994), (1160, 5010)])
    builder.add_edge("s6_e13", "s6_out", "s6_exit", "grey", points=[(1160, 5058), (1160, 5075)])
    builder.add_edge("s6_e14", "s6_exit", "s6_end", "grey", points=[(1160, 5125), (1160, 5145)])

    return builder


def main():
    print("[INFO] Building Module 1 flowchart models...")
    builder = build_module1_diagram()

    # 1. Output Draw.io XML
    drawio_path = BASE_DIR / "Module_1_Low_Level_Algorithm_Flowchart.drawio"
    drawio_xml = builder.to_drawio_xml()
    drawio_path.write_text(drawio_xml, encoding="utf-8")
    print(f"[SUCCESS] Generated Draw.io file: {drawio_path} ({len(drawio_xml)} bytes)")

    # 2. Output SVG Vector Graphic
    svg_path = BASE_DIR / "Module_1_Low_Level_Algorithm_Flowchart.svg"
    svg_content = builder.to_svg()
    svg_path.write_text(svg_content, encoding="utf-8")
    print(f"[SUCCESS] Generated SVG file: {svg_path} ({len(svg_content)} bytes)")

    # 3. Output HTML Viewer
    html_path = BASE_DIR / "Module_1_Low_Level_Algorithm_Flowchart.html"
    html_page = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Module 1 Low-Level Flowchart — TemporalKG Specification</title>
    <style>
        body {{
            margin: 0;
            padding: 20px;
            background: #F1F5F9;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        .header {{
            max-width: 1740px;
            width: 100%;
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 20px;
            color: #0F172A;
        }}
        .header .badge {{
            background: #0284C7;
            color: #FFFFFF;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        .container {{
            background: #FFFFFF;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            border-radius: 8px;
            overflow: auto;
            max-width: 100%;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Module 1: Loader Log Filtering — Low-Level Algorithmic Flowchart</h1>
        <span class="badge">Canonical TemporalKG Contract</span>
    </div>
    <div class="container">
        {svg_content}
    </div>
</body>
</html>"""
    html_path.write_text(html_page, encoding="utf-8")
    print(f"[SUCCESS] Generated HTML Viewer: {html_path}")

    # 4. Render High-Resolution PNG via Chrome Headless
    chrome_exe = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    png_path = BASE_DIR / "Module_1_Low_Level_Algorithm_Flowchart.png"
    if os.path.exists(chrome_exe):
        print("[INFO] Rendering high-resolution PNG using Chrome headless...")
        cmd = [
            chrome_exe,
            "--headless=new",
            "--disable-gpu",
            "--force-device-scale-factor=1.5",
            f"--window-size={builder.width},{builder.height + 100}",
            f"--screenshot={png_path.resolve()}",
            str(html_path.resolve())
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if png_path.is_file():
            print(f"[SUCCESS] Rendered PNG: {png_path} ({png_path.stat().st_size} bytes)")
        else:
            print(f"[WARN] Chrome finished with code {res.returncode}, PNG not created. Stderr: {res.stderr}")
    else:
        print("[WARN] Chrome executable not found, skipping PNG rasterization.")


if __name__ == "__main__":
    main()
