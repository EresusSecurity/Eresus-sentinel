#!/usr/bin/env python3
"""Generate the Eresus Sentinel Turkish whitepaper PDF — comprehensive edition."""

from fpdf import FPDF
import os


class SentinelPDF(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font("DejaVu", "I", 8)
            self.set_text_color(120, 120, 120)
            self.cell(0, 8, "Eresus Sentinel — Teknik Makale — 2026", align="L")
            self.cell(0, 8, f"Sayfa {self.page_no()}", align="R", new_x="LMARGIN", new_y="NEXT")
            self.set_draw_color(180, 180, 180)
            self.line(10, 16, 200, 16)
            self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("DejaVu", "I", 7)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, "\u00a9 2026 Eresus Security. T\u00fcm haklar\u0131 sakl\u0131d\u0131r.", align="C")

    def chapter_title(self, title):
        self.set_font("DejaVu", "B", 14)
        self.set_text_color(20, 60, 120)
        self.ln(6)
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(20, 60, 120)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def section_title(self, title):
        self.set_font("DejaVu", "B", 11)
        self.set_text_color(40, 40, 40)
        self.ln(4)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def subsection_title(self, title):
        self.set_font("DejaVu", "B", 10)
        self.set_text_color(60, 60, 60)
        self.ln(2)
        self.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def body(self, text):
        self.set_font("DejaVu", "", 10)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 5.5, text)
        self.ln(2)

    def bullet(self, text):
        self.set_font("DejaVu", "", 10)
        self.set_text_color(30, 30, 30)
        x = self.get_x()
        self.cell(6, 5.5, "  \u2022  ", new_x="RIGHT", new_y="TOP")
        self.multi_cell(self.w - self.r_margin - self.get_x(), 5.5, text)
        self.set_x(x)

    def numbered(self, num, text):
        self.set_font("DejaVu", "", 10)
        self.set_text_color(30, 30, 30)
        x = self.get_x()
        self.cell(8, 5.5, f"  {num}.  ", new_x="RIGHT", new_y="TOP")
        self.multi_cell(self.w - self.r_margin - self.get_x(), 5.5, text)
        self.set_x(x)

    def bold_text(self, text):
        self.set_font("DejaVu", "B", 10)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 5.5, text)
        self.ln(1)

    def table_row(self, cols, widths, bold=False, fill=False):
        self.set_font("DejaVu", "B" if bold else "", 8)
        if fill:
            self.set_fill_color(235, 240, 250)
        h = 6
        for i, col in enumerate(cols):
            self.cell(widths[i], h, col, border=1, fill=fill)
        self.ln(h)

    def code_block(self, text):
        self.set_font("DejaVu", "", 8)
        self.set_fill_color(240, 240, 240)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 4.5, text, fill=True)
        self.set_text_color(30, 30, 30)
        self.ln(2)

    def note_box(self, text):
        self.set_fill_color(255, 248, 220)
        self.set_draw_color(200, 180, 100)
        self.set_font("DejaVu", "I", 9)
        self.set_text_color(80, 60, 0)
        x = self.get_x()
        y = self.get_y()
        self.multi_cell(0, 5, text, fill=True, border=1)
        self.set_text_color(30, 30, 30)
        self.ln(3)


def build_pdf():
    # Find a Unicode font
    font_path = None
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/opt/homebrew/share/fonts/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    ]
    # Try to find DejaVu via fc-match
    import subprocess
    try:
        result = subprocess.run(["fc-match", "-f", "%{file}", "DejaVu Sans"], capture_output=True, text=True)
        if result.returncode == 0 and os.path.exists(result.stdout.strip()):
            font_path = result.stdout.strip()
    except FileNotFoundError:
        pass

    if not font_path:
        for c in candidates:
            if os.path.exists(c):
                font_path = c
                break

    if not font_path:
        # Download DejaVu
        print("DejaVu font bulunamadı, indiriliyor...")
        import urllib.request, zipfile, io
        url = "https://github.com/dejavu-fonts/dejavu-fonts/releases/download/version_2_37/dejavu-fonts-ttf-2.37.zip"
        try:
            data = urllib.request.urlopen(url, timeout=30).read()
            zf = zipfile.ZipFile(io.BytesIO(data))
            for name in zf.namelist():
                if name.endswith("DejaVuSans.ttf"):
                    font_dir = os.path.join(os.path.dirname(__file__), ".fonts")
                    os.makedirs(font_dir, exist_ok=True)
                    font_path = os.path.join(font_dir, "DejaVuSans.ttf")
                    with open(font_path, "wb") as f:
                        f.write(zf.read(name))
                    # Also extract bold
                    for bn in zf.namelist():
                        if bn.endswith("DejaVuSans-Bold.ttf"):
                            with open(os.path.join(font_dir, "DejaVuSans-Bold.ttf"), "wb") as f:
                                f.write(zf.read(bn))
                        if bn.endswith("DejaVuSans-Oblique.ttf"):
                            with open(os.path.join(font_dir, "DejaVuSans-Oblique.ttf"), "wb") as f:
                                f.write(zf.read(bn))
                        if bn.endswith("DejaVuSans-BoldOblique.ttf"):
                            with open(os.path.join(font_dir, "DejaVuSans-BoldOblique.ttf"), "wb") as f:
                                f.write(zf.read(bn))
                    break
        except Exception as e:
            print(f"Font indirilemedi: {e}")
            print("Varsayılan Helvetica kullanılacak (Türkçe karakterler eksik olabilir)")

    pdf = SentinelPDF()
    pdf.set_auto_page_break(auto=True, margin=20)

    if font_path:
        font_dir = os.path.dirname(font_path)
        pdf.add_font("DejaVu", "", font_path)
        bold_path = os.path.join(font_dir, "DejaVuSans-Bold.ttf")
        if os.path.exists(bold_path):
            pdf.add_font("DejaVu", "B", bold_path)
        else:
            pdf.add_font("DejaVu", "B", font_path)
        italic_path = os.path.join(font_dir, "DejaVuSans-Oblique.ttf")
        if os.path.exists(italic_path):
            pdf.add_font("DejaVu", "I", italic_path)
        else:
            pdf.add_font("DejaVu", "I", font_path)
        bi_path = os.path.join(font_dir, "DejaVuSans-BoldOblique.ttf")
        if os.path.exists(bi_path):
            pdf.add_font("DejaVu", "BI", bi_path)
        else:
            pdf.add_font("DejaVu", "BI", font_path)
    else:
        pdf.add_font("DejaVu", "", "Helvetica")
        pdf.add_font("DejaVu", "B", "Helvetica")
        pdf.add_font("DejaVu", "I", "Helvetica")

    from _paper_part1 import write_part1
    from _paper_part2 import write_part2
    from _paper_part3 import write_part3
    from _paper_part4 import write_part4

    write_part1(pdf)
    write_part2(pdf)
    write_part3(pdf)
    write_part4(pdf)

    # ===== OUTPUT =====
    output_path = os.path.join(os.path.dirname(__file__), "..", "docs", "paper", "Eresus-Sentinel-Aldatma-Savunma-Stratejisi.pdf")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)
    print(f"PDF oluşturuldu: {os.path.abspath(output_path)}")
    return output_path


if __name__ == "__main__":
    build_pdf()
