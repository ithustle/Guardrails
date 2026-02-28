use crate::models::{AnalysisReport, Finding, Severity, Verdict};
use printpdf::*;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

const PAGE_WIDTH: f32 = 210.0;
const PAGE_HEIGHT: f32 = 297.0;
const MARGIN_LEFT: f32 = 25.0;
const MARGIN_RIGHT: f32 = 25.0;
const MARGIN_TOP: f32 = 25.0;
const LINE_HEIGHT: f32 = 5.0;
const SECTION_GAP: f32 = 8.0;

pub fn generate_pdf(report: &AnalysisReport, output_path: &Path) -> Result<String, String> {
    let (doc, page1, layer1) = PdfDocument::new(
        "Guardrails - APK Policy Analysis Report",
        Mm(PAGE_WIDTH),
        Mm(PAGE_HEIGHT),
        "Layer 1",
    );

    let font = doc.add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| format!("Failed to load font: {}", e))?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| format!("Failed to load bold font: {}", e))?;
    let font_mono = doc.add_builtin_font(BuiltinFont::Courier)
        .map_err(|e| format!("Failed to load mono font: {}", e))?;

    let mut writer = PdfWriter {
        doc: &doc,
        current_page: page1,
        current_layer: layer1,
        y: PAGE_HEIGHT - MARGIN_TOP,
        font: font.clone(),
        font_bold: font_bold.clone(),
        font_mono: font_mono.clone(),
    };

    // Title
    writer.write_line_bold("GUARDRAILS — APK Policy Analysis Report", 14.0);
    writer.advance(3.0);
    writer.write_line(&format!("Date: {}", &report.created_at[..10.min(report.created_at.len())]), 10.0);
    writer.write_line(&format!("APK: {}", report.apk_filename), 10.0);
    writer.write_line(&format!("Package: {}", report.package_name), 10.0);
    let version_str = format!(
        "Version: {} ({})",
        report.version_name.as_deref().unwrap_or("N/A"),
        report.version_code.map(|v| v.to_string()).unwrap_or_else(|| "N/A".to_string())
    );
    writer.write_line(&version_str, 10.0);

    writer.draw_separator();

    // Verdict
    let verdict_text = match &report.verdict {
        Verdict::Pass => "VERDICT: PASS",
        Verdict::Fail => "VERDICT: FAIL",
        Verdict::Review => "VERDICT: REVIEW REQUIRED",
    };
    writer.write_line_bold(verdict_text, 14.0);
    writer.advance(3.0);
    writer.write_wrapped(&report.summary, 10.0);

    writer.draw_separator();

    // 1. Metadata
    writer.write_line_bold("1. METADATA", 12.0);
    writer.advance(2.0);
    writer.write_line(&format!("   Package: {}", report.metadata.package_name), 9.0);
    writer.write_line(
        &format!(
            "   Min SDK: {} | Target SDK: {}",
            report.metadata.min_sdk.map(|v| v.to_string()).unwrap_or_else(|| "N/A".to_string()),
            report.metadata.target_sdk.map(|v| v.to_string()).unwrap_or_else(|| "N/A".to_string()),
        ),
        9.0,
    );
    writer.write_line(
        &format!("   Target SDK Status: {}", report.metadata.target_sdk_status),
        9.0,
    );

    writer.advance(SECTION_GAP);

    // 2. Permissions
    writer.write_line_bold("2. PERMISSIONS", 12.0);
    writer.advance(2.0);
    if report.permissions.is_empty() {
        writer.write_line("   No flagged permissions found.", 9.0);
    } else {
        for finding in &report.permissions {
            writer.check_page_break();
            write_finding(&mut writer, finding);
        }
    }

    writer.advance(SECTION_GAP);

    // 3. Third-Party SDKs
    writer.check_page_break();
    writer.write_line_bold("3. THIRD-PARTY SDKs", 12.0);
    writer.advance(2.0);
    if report.sdks.is_empty() {
        writer.write_line("   No flagged SDKs found.", 9.0);
    } else {
        for finding in &report.sdks {
            writer.check_page_break();
            write_finding(&mut writer, finding);
        }
    }

    writer.advance(SECTION_GAP);

    // 4. Code Patterns
    writer.check_page_break();
    writer.write_line_bold("4. CODE PATTERNS", 12.0);
    writer.advance(2.0);
    if report.patterns.is_empty() {
        writer.write_line("   No flagged code patterns found.", 9.0);
    } else {
        for finding in &report.patterns {
            writer.check_page_break();
            write_finding(&mut writer, finding);
        }
    }

    writer.advance(SECTION_GAP);

    // 5. Embedded Assets
    writer.check_page_break();
    writer.write_line_bold("5. EMBEDDED ASSETS", 12.0);
    writer.advance(2.0);
    if report.assets.is_empty() {
        writer.write_line("   No suspicious embedded assets found.", 9.0);
    } else {
        for finding in &report.assets {
            writer.check_page_break();
            write_finding(&mut writer, finding);
        }
    }

    writer.advance(SECTION_GAP);

    // 6. VirusTotal Scan
    writer.check_page_break();
    writer.write_line_bold("6. VIRUSTOTAL SCAN", 12.0);
    writer.advance(2.0);
    match &report.virustotal {
        Some(vt) => {
            writer.write_line(
                &format!("   Result: {}/{} engines flagged", vt.detections, vt.total_engines),
                9.0,
            );
            writer.write_line(&format!("   Status: {}", vt.status), 9.0);
        }
        None => {
            writer.write_line("   Scan not performed. Configure VirusTotal API key in settings.", 9.0);
        }
    }

    writer.draw_separator();

    // Conclusion
    writer.check_page_break();
    writer.write_line_bold("CONCLUSION", 12.0);
    writer.advance(3.0);

    match &report.verdict {
        Verdict::Pass => {
            writer.write_wrapped(
                "This APK passed all checks. No critical policy violations were detected.",
                10.0,
            );
        }
        Verdict::Fail => {
            let critical_count = report.permissions.iter()
                .chain(report.sdks.iter())
                .chain(report.patterns.iter())
                .chain(report.assets.iter())
                .filter(|f| f.severity == Severity::Critical)
                .count();
            writer.write_wrapped(
                &format!(
                    "This APK has {} critical issue(s) that would likely result in Google Play rejection or account suspension. The issues listed above must be resolved before this application can be published. Critical items are mandatory fixes. Warning items are recommended.",
                    critical_count
                ),
                10.0,
            );
        }
        Verdict::Review => {
            writer.write_wrapped(
                "This APK has warnings that require manual review before publishing. While no critical violations were found, the flagged items should be addressed or justified.",
                10.0,
            );
        }
    }

    writer.draw_separator();
    writer.write_line("Generated by Guardrails v1.0", 8.0);

    // Save PDF
    let file = File::create(output_path)
        .map_err(|e| format!("Failed to create PDF file: {}", e))?;
    doc.save(&mut BufWriter::new(file))
        .map_err(|e| format!("Failed to save PDF: {}", e))?;

    Ok(output_path.to_string_lossy().to_string())
}

fn write_finding(writer: &mut PdfWriter, finding: &Finding) {
    let prefix = match finding.severity {
        Severity::Critical => "   CRITICAL: ",
        Severity::Warning => "   WARNING: ",
        Severity::Info => "   INFO: ",
    };
    writer.write_line_bold(&format!("{}{}", prefix, finding.title), 9.0);
    writer.write_wrapped(&format!("     -> {}", finding.description), 8.0);
    writer.advance(2.0);
}

struct PdfWriter<'a> {
    doc: &'a PdfDocumentReference,
    current_page: PdfPageIndex,
    current_layer: PdfLayerIndex,
    y: f32,
    font: IndirectFontRef,
    font_bold: IndirectFontRef,
    #[allow(dead_code)]
    font_mono: IndirectFontRef,
}

impl<'a> PdfWriter<'a> {
    fn get_layer(&self) -> PdfLayerReference {
        self.doc.get_page(self.current_page).get_layer(self.current_layer)
    }

    fn write_line(&mut self, text: &str, font_size: f32) {
        let layer = self.get_layer();
        layer.use_text(text, font_size, Mm(MARGIN_LEFT), Mm(self.y), &self.font);
        self.y -= LINE_HEIGHT;
    }

    fn write_line_bold(&mut self, text: &str, font_size: f32) {
        let layer = self.get_layer();
        layer.use_text(text, font_size, Mm(MARGIN_LEFT), Mm(self.y), &self.font_bold);
        self.y -= LINE_HEIGHT;
    }

    fn write_wrapped(&mut self, text: &str, font_size: f32) {
        // Simple word-wrap at ~80 chars per line
        let max_chars = ((PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT) / (font_size * 0.25)) as usize;
        let max_chars = max_chars.max(40);

        let words: Vec<&str> = text.split_whitespace().collect();
        let mut line = String::new();

        for word in words {
            if line.len() + word.len() + 1 > max_chars {
                self.write_line(&line, font_size);
                self.check_page_break();
                line = format!("     {}", word);
            } else {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(word);
            }
        }
        if !line.is_empty() {
            self.write_line(&line, font_size);
        }
    }

    fn advance(&mut self, mm: f32) {
        self.y -= mm;
    }

    fn draw_separator(&mut self) {
        self.advance(3.0);
        let layer = self.get_layer();
        let points = vec![
            (Point::new(Mm(MARGIN_LEFT), Mm(self.y)), false),
            (Point::new(Mm(PAGE_WIDTH - MARGIN_RIGHT), Mm(self.y)), false),
        ];
        let line = Line {
            points,
            is_closed: false,
        };
        layer.set_outline_color(Color::Greyscale(Greyscale::new(0.7, None)));
        layer.set_outline_thickness(0.5);
        layer.add_line(line);
        self.advance(5.0);
    }

    fn check_page_break(&mut self) {
        if self.y < 30.0 {
            let (page, layer) = self.doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Layer 1");
            self.current_page = page;
            self.current_layer = layer;
            self.y = PAGE_HEIGHT - MARGIN_TOP;
        }
    }
}
