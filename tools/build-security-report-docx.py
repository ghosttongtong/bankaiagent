#!/usr/bin/env python3
"""Build docs/37-安全自评报告.docx from docs/37-安全自评报告.md (三线表、黑白、页脚页码)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
MD_PATH = ROOT / "docs" / "37-安全自评报告.md"
OUT_PATH = ROOT / "docs" / "37-安全自评报告.docx"

FONT_NAME = "宋体"
FONT_SIZE = Pt(12)  # 小四
BLACK = RGBColor(0, 0, 0)


def set_run_font(run, bold=False):
    run.font.name = FONT_NAME
    run._element.rPr.rFonts.set(qn("w:eastAsia"), FONT_NAME)
    run.font.size = FONT_SIZE
    run.font.color.rgb = BLACK
    run.bold = bold


def add_formatted_paragraph(doc, text: str, style=None, align=None, bold_all=False):
    p = doc.add_paragraph(style=style)
    if align is not None:
        p.paragraph_format.alignment = align
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
    p.paragraph_format.space_after = Pt(6)
    parts = re.split(r"(\*\*[^*]+\*\*)", text)
    for part in parts:
        if not part:
            continue
        m = re.match(r"\*\*(.+)\*\*", part)
        run = p.add_run(m.group(1) if m else part)
        set_run_font(run, bold=bold_all or bool(m))
    return p


def parse_table_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    cells = [c.strip() for c in line.split("|")]
    return cells


def is_separator_row(cells: list[str]) -> bool:
    return all(re.match(r"^:?-+:?$", c.replace(" ", "")) or c == "" for c in cells)


def set_cell_border(cell, top="nil", bottom="nil", left="nil", right="nil"):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcBorders = OxmlElement("w:tcBorders")
    for edge, val in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
        el = OxmlElement(f"w:{edge}")
        if val == "single":
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), "8")
            el.set(qn("w:color"), "000000")
        else:
            el.set(qn("w:val"), "nil")
        tcBorders.append(el)
    tcPr.append(tcBorders)


def apply_three_line_table(table, header_rows: int = 1):
    tbl = table._tbl
    tblPr = tbl.tblPr
    if tblPr is None:
        tblPr = OxmlElement("w:tblPr")
        tbl.insert(0, tblPr)
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{edge}")
        if edge == "top":
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), "12")
            el.set(qn("w:color"), "000000")
        elif edge == "bottom":
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), "12")
            el.set(qn("w:color"), "000000")
        else:
            el.set(qn("w:val"), "nil")
        borders.append(el)
    tblPr.append(borders)

    for ri, row in enumerate(table.rows):
        for cell in row.cells:
            if ri == 0:
                set_cell_border(cell, top="single", bottom="nil", left="nil", right="nil")
            elif ri == header_rows - 1:
                set_cell_border(cell, top="nil", bottom="single", left="nil", right="nil")
            else:
                set_cell_border(cell, top="nil", bottom="nil", left="nil", right="nil")


def add_table(doc, rows: list[list[str]]):
    if not rows:
        return
    header = rows[0]
    ncols = len(header)
    table = doc.add_table(rows=len(rows), cols=ncols)
    table.autofit = True
    for ri, row_cells in enumerate(rows):
        for ci in range(ncols):
            text = row_cells[ci] if ci < len(row_cells) else ""
            cell = table.rows[ri].cells[ci]
            cell.text = ""
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.SINGLE
            run = p.add_run(text)
            set_run_font(run, bold=(ri == 0))
    apply_three_line_table(table, header_rows=1)
    doc.add_paragraph()  # spacing after table


def add_page_number_footer(section):
    footer = section.footer
    p = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(0)
    run = p.add_run("— ")
    set_run_font(run)
    run = p.add_run()
    fld_char_begin = OxmlElement("w:fldChar")
    fld_char_begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = " PAGE "
    fld_char_sep = OxmlElement("w:fldChar")
    fld_char_sep.set(qn("w:fldCharType"), "separate")
    fld_char_end = OxmlElement("w:fldChar")
    fld_char_end.set(qn("w:fldCharType"), "end")
    run._r.append(fld_char_begin)
    run._r.append(instr)
    run._r.append(fld_char_sep)
    run._r.append(fld_char_end)
    run2 = p.add_run(" —")
    set_run_font(run2)


def configure_document(doc: Document):
    section = doc.sections[0]
    section.top_margin = Cm(2.54)
    section.bottom_margin = Cm(2.54)
    section.left_margin = Cm(3.17)
    section.right_margin = Cm(3.17)
    add_page_number_footer(section)
    style = doc.styles["Normal"]
    style.font.name = FONT_NAME
    style._element.rPr.rFonts.set(qn("w:eastAsia"), FONT_NAME)
    style.font.size = FONT_SIZE
    style.font.color.rgb = BLACK


def build_from_md(md_text: str, base_dir: Path) -> Document:
    doc = Document()
    configure_document(doc)
    lines = md_text.splitlines()
    i = 0
    table_buffer: list[list[str]] = []

    def flush_table():
        nonlocal table_buffer
        if table_buffer:
            add_table(doc, table_buffer)
            table_buffer = []

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("|") and "|" in stripped[1:]:
            cells = parse_table_row(stripped)
            if is_separator_row(cells):
                i += 1
                continue
            table_buffer.append(cells)
            i += 1
            continue
        else:
            flush_table()

        if not stripped:
            i += 1
            continue

        if stripped.startswith("# ") and not stripped.startswith("## "):
            flush_table()
            t = stripped[2:].strip()
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(12)
            run = p.add_run(t)
            set_run_font(run, bold=True)
            run.font.size = Pt(16)
            i += 1
            continue

        if stripped.startswith("## "):
            flush_table()
            t = stripped[3:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(12)
            run = p.add_run(t)
            set_run_font(run, bold=True)
            run.font.size = Pt(14)
            i += 1
            continue

        if stripped.startswith("### "):
            flush_table()
            t = stripped[4:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(6)
            run = p.add_run(t)
            set_run_font(run, bold=True)
            i += 1
            continue

        if stripped.startswith("**表") and stripped.endswith("**"):
            flush_table()
            caption = stripped.strip("*")
            add_formatted_paragraph(doc, caption, align=WD_ALIGN_PARAGRAPH.CENTER, bold_all=True)
            i += 1
            continue

        if re.match(r"^\d+\.\s", stripped):
            flush_table()
            add_formatted_paragraph(doc, stripped)
            i += 1
            continue

        if stripped.startswith(">"):
            flush_table()
            add_formatted_paragraph(doc, stripped.lstrip("> ").strip())
            i += 1
            continue

        if stripped.startswith("![") and "](" in stripped:
            flush_table()
            m = re.match(r"!\[(.*?)\]\((.*?)\)", stripped)
            if m:
                alt, src = m.group(1), m.group(2)
                img_path = base_dir / src
                if img_path.is_file():
                    p = doc.add_paragraph()
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    run = p.add_run()
                    run.add_picture(str(img_path), width=Cm(12))
                else:
                    add_formatted_paragraph(doc, f"[图片缺失: {src}]")
            i += 1
            continue

        flush_table()
        add_formatted_paragraph(doc, stripped)
        i += 1

    flush_table()
    return doc


def main() -> int:
    md_path = MD_PATH
    out_path = OUT_PATH
    if len(sys.argv) >= 2:
        md_path = Path(sys.argv[1])
    if len(sys.argv) >= 3:
        out_path = Path(sys.argv[2])
    if not md_path.is_file():
        print(f"Missing: {md_path}", file=sys.stderr)
        return 1
    text = md_path.read_text(encoding="utf-8")
    doc = build_from_md(text, md_path.parent)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(out_path)
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
