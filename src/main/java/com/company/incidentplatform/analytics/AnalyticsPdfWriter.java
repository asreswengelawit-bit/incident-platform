package com.company.incidentplatform.analytics;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Small dependency-free PDF report renderer; report contents omit reporter identity. */
final class AnalyticsPdfWriter {

    private AnalyticsPdfWriter() {
    }

    static byte[] write(AnalyticsIncident incident) {
        List<String> lines = new ArrayList<>(List.of(
                "Incident report",
                "Reference: " + incident.id(),
                "Title: " + safe(incident.title()),
                "Category: " + safe(incident.category()),
                "Status: " + incident.status(),
                "Severity: " + incident.severity(),
                "Reported: " + incident.reportedAt(),
                "Occurred: " + incident.occurredAt(),
                "Resolved: " + incident.resolvedAt(),
                "Department: " + safe(incident.anonymous() ? null : incident.department()),
                "Affected system: " + safe(incident.affectedSystem()),
                "Escalated: " + incident.escalated(),
                "Description:"));
        lines.addAll(wrap(safe(incident.description()), 88));

        StringBuilder content = new StringBuilder("BT\n/F1 10 Tf\n50 790 Td\n13 TL\n");
        for (int i = 0; i < lines.size(); i++) {
            if (i > 0) {
                content.append("T*\n");
            }
            content.append('(').append(pdfString(lines.get(i))).append(") Tj\n");
        }
        content.append("ET\n");
        byte[] stream = content.toString().getBytes(StandardCharsets.US_ASCII);

        List<byte[]> objects = List.of(
                ascii("<< /Type /Catalog /Pages 2 0 R >>"),
                ascii("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
                ascii("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"),
                ascii("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
                concat(ascii("<< /Length " + stream.length + " >>\nstream\n"), stream, ascii("endstream")));

        StringBuilder pdf = new StringBuilder("%PDF-1.4\n");
        List<Integer> offsets = new ArrayList<>();
        for (int i = 0; i < objects.size(); i++) {
            offsets.add(pdf.length());
            pdf.append(i + 1).append(" 0 obj\n")
                    .append(new String(objects.get(i), StandardCharsets.US_ASCII))
                    .append("\nendobj\n");
        }
        int xref = pdf.length();
        pdf.append("xref\n0 ").append(objects.size() + 1).append("\n")
                .append("0000000000 65535 f \n");
        for (int offset : offsets) {
            pdf.append(String.format(Locale.ROOT, "%010d 00000 n \n", offset));
        }
        pdf.append("trailer\n<< /Size ").append(objects.size() + 1)
                .append(" /Root 1 0 R >>\nstartxref\n").append(xref).append("\n%%EOF\n");
        return pdf.toString().getBytes(StandardCharsets.US_ASCII);
    }

    private static List<String> wrap(String text, int width) {
        List<String> lines = new ArrayList<>();
        if (text.isBlank()) {
            lines.add("");
            return lines;
        }
        for (String line : text.split("\\R", -1)) {
            String remaining = line;
            while (remaining.length() > width) {
                int breakAt = remaining.lastIndexOf(' ', width);
                if (breakAt <= 0) {
                    breakAt = width;
                }
                lines.add(remaining.substring(0, breakAt));
                remaining = remaining.substring(Math.min(breakAt + 1, remaining.length()));
            }
            lines.add(remaining);
        }
        return lines;
    }

    private static String safe(String value) {
        return value == null ? "" : value.replaceAll("[^\\x20-\\x7E]", "?");
    }

    private static String pdfString(String value) {
        return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)");
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[] first, byte[] second, byte[] third) {
        byte[] result = new byte[first.length + second.length + third.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        System.arraycopy(third, 0, result, first.length + second.length, third.length);
        return result;
    }
}
