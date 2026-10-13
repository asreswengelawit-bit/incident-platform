package com.company.incidentplatform.evidence;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

/**
 * Content sniffing for 7.6.
 *
 * <p>7.6 requires evidence to be rejected "by content-sniffed type, not just
 * file extension", and the reason it says so is that the extension is chosen by
 * whoever uploaded the file. Renaming {@code invoice.pdf.exe} to {@code
 * invoice.pdf} is the oldest trick in the book, and an allow-list consulted on
 * the extension is a control that documents intent rather than enforcing it.
 * The declared {@code Content-Type} header is no better -- it is also supplied by
 * the caller.
 *
 * <p>So the decision is made on the bytes, and this class exists to answer one
 * question about them: what are these, really?
 *
 * <h2>Design constraints</h2>
 *
 * <ul>
 *   <li><b>Never throws, never guesses.</b> Anything unrecognised comes back as
 *       {@link #UNKNOWN}, which the policy treats as not allow-listed. A sniffer
 *       that falls back to {@code application/octet-stream}-is-fine-inverts the
 *       control.</li>
 *   <li><b>No decompression, ever.</b> The ZIP branch reads entry <em>names</em>
 *       from the central directory and nothing else, so a decompression bomb
 *       costs the same as an empty file. Nothing here is a zip-slip risk either,
 *       because no entry is ever written out.</li>
 *   <li><b>Rejection reasons are specific.</b> {@code application/x-msdownload}
 *       in the audit trail is worth a great deal more to whoever investigates a
 *       report than {@code unknown}, so executables and scripts are named as
 *       such instead of falling through.</li>
 * </ul>
 *
 * <p>What this class is <em>not</em> is a malware scanner. It identifies a
 * container format; whether the payload inside it is malicious is
 * {@link EvidenceScanner}'s question, and the two are deliberately separate so
 * that a better scanner can be dropped in without touching the allow-list.
 */
/**
 * A component because {@link EvidenceService} takes one by constructor injection and
 * this class is stateless: the signature tables it consults are static, so one shared
 * instance is correct and there is nothing to configure.
 */
@Component
public final class ContentTypeSniffer {

    /** Returned when the bytes match nothing known. Never allow-listed. */
    public static final SniffedType UNKNOWN = new SniffedType("application/octet-stream", "unknown");

    /**
     * Bytes inspected for identification. Every signature checked below is within
     * the first 32 bytes except the ZIP end-of-central-directory scan, which is
     * bounded separately and reads only from the tail.
     */
    private static final int HEADER_BYTES = 64;

    /** Bound on the tail search for the ZIP end-of-central-directory record. */
    private static final int EOCD_SEARCH_WINDOW = 66_000;

    /** ZIP central-directory file header. */
    private static final int ZIP_CENTRAL_HEADER = 0x0201_4b50;
    private static final int ZIP_EOCD = 0x0605_4b50;
    private static final int ZIP_EOCD_LENGTH = 22;
    private static final int ZIP_CENTRAL_HEADER_LENGTH = 46;
    /** ZIP64 sentinel. Detected so it can be refused rather than misread. */
    private static final int ZIP64_SENTINEL = 0xFFFF;

    private ContentTypeSniffer() {
    }

    /**
     * The result of sniffing: a MIME type and a human-readable description.
     *
     * <p>{@code mimeType} is a plain string rather than a {@code MediaType} so
     * that a type the application does not model -- {@code
     * application/x-msdownload} -- is still reportable. Refusing to describe a
     * malicious file because no enum constant matched it would be perverse.
     */
    public record SniffedType(String mimeType, String description) {
    }

    /**
     * Identifies {@code bytes}. {@code bytes} must be the head of the file, up to
     * {@code length} bytes; the ZIP branch additionally needs the tail, so callers
     * that can hold the whole file should pass all of it.
     *
     * @param length how many bytes of {@code bytes} are meaningful
     */
    public static SniffedType sniff(byte[] bytes, int length) {
        if (bytes == null || length <= 0) {
            return UNKNOWN;
        }
        int end = Math.min(length, bytes.length);
        if (end < 4) {
            return UNKNOWN;
        }

        // Executables and scripts first: these are the payload types 7.6 most
        // needs named, and checking them before the container formats keeps the
        // rejection reason precise.
        SniffedType executable = detectExecutable(bytes, end);
        if (executable != null) {
            return executable;
        }

        SniffedType container = detectContainer(bytes, end);
        if (container != null) {
            return container;
        }

        SniffedType textual = detectText(bytes, end);
        if (textual != null) {
            return textual;
        }

        return UNKNOWN;
    }

    private static SniffedType detectExecutable(byte[] b, int end) {
        if (startsWith(b, end, 0x4D, 0x5A)) { // "MZ"
            return new SniffedType("application/x-msdownload", "Windows PE executable");
        }
        if (startsWith(b, end, 0x7F, 0x45, 0x4C, 0x46)) { // 0x7F "ELF"
            return new SniffedType("application/x-elf", "ELF executable");
        }
        if (startsWith(b, end, 0xCA, 0xFE, 0xBA, 0xBE) || startsWith(b, end, 0xCA, 0xFE, 0xBA, 0xBF)) {
            return new SniffedType("application/java-vm", "Java class or Mach-O fat binary");
        }
        if (startsWith(b, end, 0xFE, 0xED, 0xFA, 0xCE) || startsWith(b, end, 0xFE, 0xED, 0xFA, 0xCF)) {
            return new SniffedType("application/x-mach-binary", "Mach-O executable");
        }
        if (startsWith(b, end, 0x23, 0x21)) { // "#!"
            return new SniffedType("text/x-script", "script with interpreter shebang");
        }
        // A .bat/.cmd file is plain text, so it can only be caught by content --
        // which is exactly the point of sniffing rather than trusting the name.
        if (looksLikeWindowsBatch(b, end)) {
            return new SniffedType("text/x-msdos-batch", "Windows batch script");
        }
        if (looksLikePowershell(b, end)) {
            return new SniffedType("text/x-powershell", "PowerShell script");
        }
        if (looksLikeVbScript(b, end)) {
            return new SniffedType("text/x-vbscript", "VBScript file");
        }
        return null;
    }

    private static SniffedType detectContainer(byte[] b, int end) {
        if (startsWith(b, end, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)) {
            return new SniffedType("image/png", "PNG image");
        }
        if (startsWith(b, end, 0xFF, 0xD8, 0xFF)) {
            return new SniffedType("image/jpeg", "JPEG image");
        }
        if (asciiEquals(b, end, 0, "GIF87a") || asciiEquals(b, end, 0, "GIF89a")) {
            return new SniffedType("image/gif", "GIF image");
        }
        if (asciiEquals(b, end, 0, "BM")) {
            return new SniffedType("image/bmp", "BMP image");
        }
        // RIFF....WEBP -- the four size bytes between the two tags are skipped.
        if (asciiEquals(b, end, 0, "RIFF") && asciiEquals(b, end, 8, "WEBP")) {
            return new SniffedType("image/webp", "WebP image");
        }
        if (asciiEquals(b, end, 0, "II*\u0000") || asciiEquals(b, end, 0, "MM\u0000*")) {
            return new SniffedType("image/tiff", "TIFF image");
        }
        if (asciiEquals(b, end, 0, "%PDF-")) {
            return new SniffedType("application/pdf", "PDF document");
        }
        if (asciiEquals(b, end, 0, "{\\rtf")) {
            return new SniffedType("application/rtf", "RTF document");
        }
        if (startsWith(b, end, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)) {
            // OLE2 compound file: legacy .doc/.xls/.ppt, and Outlook .msg. The
            // CFB directory is not parsed to tell them apart -- the distinction
            // does not change any decision here, and the scanner looks inside.
            return new SniffedType("application/x-ole-storage",
                    "OLE2 compound document (legacy Office or Outlook .msg)");
        }
        if (isZip(b, end)) {
            return identifyZip(b, end);
        }
        return null;
    }

    /**
     * Distinguishes an allow-listed OOXML document from an arbitrary archive.
     *
     * <p>A ZIP is not on the allow-list, but {@code .docx}/{@code .xlsx} are, and
     * both are ZIPs. The distinction is made by reading the entry names out of
     * the central directory -- not by searching the raw bytes for the string
     * {@code "word/document.xml"}, which any file could contain as data and
     * which would therefore let a crafted ZIP be accepted as a Word document.
     *
     * <p>Macro-enabled Office formats are named explicitly so the scanner can
     * quarantine them: 7.6 asks for macros to be disabled before storage, and
     * with no Office runtime to strip them the only honest outcome is refusal.
     */
    private static SniffedType identifyZip(byte[] b, int end) {
        List<String> entries = readCentralDirectoryEntryNames(b, end);
        if (entries.isEmpty()) {
            return new SniffedType("application/zip", "ZIP archive (no readable central directory)");
        }
        boolean word = containsEntry(entries, "word/document.xml");
        boolean sheet = containsEntry(entries, "xl/workbook.xml");
        boolean slides = containsEntry(entries, "ppt/presentation.xml");
        boolean macros = entries.stream().anyMatch(ContentTypeSniffer::isMacroBearing);

        if (macros) {
            return new SniffedType("application/vnd.ms-office.macroEnabled",
                    "macro-enabled Office document");
        }
        if (word) {
            return new SniffedType(
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "Word document (.docx)");
        }
        if (sheet) {
            return new SniffedType(
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "Excel workbook (.xlsx)");
        }
        if (slides) {
            return new SniffedType(
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    "PowerPoint presentation (.pptx)");
        }
        return new SniffedType("application/zip", "ZIP archive");
    }

    private static boolean isMacroBearing(String entry) {
        String lower = entry.toLowerCase(Locale.ROOT);
        return lower.endsWith("vbaproject.bin") || lower.endsWith("vbadata.xml");
    }

    private static boolean containsEntry(List<String> entries, String exactMatch) {
        return entries.stream().anyMatch(entry -> entry.equalsIgnoreCase(exactMatch));
    }

    /**
     * Reads entry names from the ZIP central directory, names only.
     *
     * <p>The end-of-central-directory record sits at the very end of the file
     * (before any archive comment), so the search starts {@value #EOCD_SEARCH_WINDOW}
     * bytes back. A file that has been truncated, concatenated, or crafted to
     * point the central directory outside its own bytes yields an empty list,
     * which the caller reports as an unreadable archive rather than guessing.
     */
    private static List<String> readCentralDirectoryEntryNames(byte[] b, int end) {
        List<String> names = new ArrayList<>();
        int eocd = findEocd(b, end);
        if (eocd < 0) {
            return names;
        }
        ByteBuffer eocdBuffer = ByteBuffer.wrap(b, eocd, ZIP_EOCD_LENGTH).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        int totalEntries = eocdBuffer.getShort(10) & 0xFFFF;
        long directorySize = eocdBuffer.getInt(12) & 0xFFFFFFFFL;
        long directoryOffset = eocdBuffer.getInt(16) & 0xFFFFFFFFL;

        // ZIP64 or an implausible count: refused rather than parsed. An
        // allow-list is not the place to be clever about malformed containers.
        if (totalEntries == ZIP64_SENTINEL || directoryOffset == 0xFFFFFFFFL || directorySize == 0xFFFFFFFFL) {
            return names;
        }
        if (directoryOffset + directorySize > end || totalEntries > 5_000) {
            return names;
        }

        int position = (int) directoryOffset;
        for (int i = 0; i < totalEntries; i++) {
            if (position + ZIP_CENTRAL_HEADER_LENGTH > end) {
                break;
            }
            ByteBuffer header = ByteBuffer.wrap(b, position, ZIP_CENTRAL_HEADER_LENGTH)
                    .order(java.nio.ByteOrder.LITTLE_ENDIAN);
            if (header.getInt(0) != ZIP_CENTRAL_HEADER) {
                break;
            }
            int nameLength = header.getShort(28) & 0xFFFF;
            int extraLength = header.getShort(30) & 0xFFFF;
            int commentLength = header.getShort(32) & 0xFFFF;
            int nameStart = position + ZIP_CENTRAL_HEADER_LENGTH;
            if (nameStart + nameLength > end) {
                break;
            }
            names.add(new String(b, nameStart, nameLength, StandardCharsets.UTF_8));
            position = nameStart + nameLength + extraLength + commentLength;
        }
        return names;
    }

    private static int findEocd(byte[] b, int end) {
        int lowest = Math.max(0, end - EOCD_SEARCH_WINDOW);
        for (int i = end - ZIP_EOCD_LENGTH; i >= lowest; i--) {
            if ((b[i] & 0xFF) == 0x50
                    && (b[i + 1] & 0xFF) == 0x4b
                    && (b[i + 2] & 0xFF) == 0x05
                    && (b[i + 3] & 0xFF) == 0x06) {
                return i;
            }
        }
        return -1;
    }

    private static boolean isZip(byte[] b, int end) {
        return startsWith(b, end, 0x50, 0x4B, 0x03, 0x04)   // local file header
                || startsWith(b, end, 0x50, 0x4B, 0x05, 0x06) // empty archive
                || startsWith(b, end, 0x50, 0x4B, 0x07, 0x08); // spanned archive
    }

    /**
     * Text detection, and the boundary of what the allow-list will ever accept as
     * a "log file".
     *
     * <p>A file is text only if it decodes as strict UTF-8 and contains no NUL and
     * no unexpected C0 control characters. That rejects UTF-16 logs (whose ASCII
     * bytes are NUL-interleaved), which is deliberate: a UTF-16 file is not what a
     * user means by "a log", and allowing it would double the number of ways a
     * file can be interpreted -- a plain, boring way to be wrong.
     */
    private static SniffedType detectText(byte[] b, int end) {
        int length = Math.min(end, 8_192);
        byte[] sample = new byte[length];
        System.arraycopy(b, 0, sample, 0, length);

        for (byte value : sample) {
            int unsigned = value & 0xFF;
            if (unsigned == 0) {
                return null;
            }
            if (unsigned < 0x20 && unsigned != '\t' && unsigned != '\r' && unsigned != '\n' && unsigned != 0x0C) {
                return null;
            }
        }

        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            CharBuffer decoded = decoder.decode(ByteBuffer.wrap(sample));
            if (isRfc5322Message(decoded)) {
                return new SniffedType("message/rfc822", "email message (.eml)");
            }
            return new SniffedType("text/plain", "plain text");
        } catch (CharacterCodingException notText) {
            return null;
        }
    }

    /**
     * FR-1.2 names {@code .eml} explicitly, so it is worth recognising properly
     * rather than lumping in with logs: an email is the most common phishing
     * evidence type and the one most likely to be a sanitiser's evidence too.
     *
     * <p>The test is that the first line is a header field, a header/body
     * separator appears within the sample, and at least one of the headers an RFC
     * 5322 message is required or conventionally expected to carry is present.
     * Requiring more than "starts with a colon-terminated word" is what keeps an
     * arbitrary {@code key: value} log file from being recorded as an email.
     */
    private static boolean isRfc5322Message(CharBuffer text) {
        int limit = text.limit();
        int newline = indexOf(text, '\n', 0);
        if (newline < 0 || newline > 512) {
            return false;
        }
        int colon = indexOf(text, ':', 0);
        if (colon < 0 || colon > newline || colon == 0) {
            return false;
        }
        for (int i = 0; i < colon; i++) {
            char c = text.get(i);
            boolean legal = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-'
                    || (i > 0 && c >= '0' && c <= '9');
            if (!legal) {
                return false;
            }
        }

        boolean blankLine = false;
        boolean from = false;
        boolean date = false;
        int lineStart = 0;
        while (lineStart < limit) {
            int lineEnd = indexOf(text, '\n', lineStart);
            if (lineEnd < 0) {
                lineEnd = limit;
            }
            String line = text.subSequence(lineStart, lineEnd).toString().trim();
            if (line.isEmpty()) {
                blankLine = true;
                break;
            }
            if (line.length() < 2 || line.charAt(1) != ':') {
                return false;
            }
            String field = line.substring(0, line.indexOf(':')).trim().toLowerCase(Locale.ROOT);
            if (field.equals("from") || field.equals("return-path") || field.equals("sender")) {
                from = true;
            }
            if (field.equals("date") || field.equals("received") || field.equals("message-id")) {
                date = true;
            }
            lineStart = lineEnd + 1;
        }
        return blankLine && from && date;
    }

    private static boolean looksLikeWindowsBatch(byte[] b, int end) {
        String head = asciiHead(b, end, 512).toUpperCase(Locale.ROOT);
        return head.contains("ECHO OFF")
                || head.contains("@ECHO OFF")
                || (head.contains("SET ") && head.contains("%~DP0"));
    }

    private static boolean looksLikePowershell(byte[] b, int end) {
        String head = asciiHead(b, end, 512);
        String lower = head.toLowerCase(Locale.ROOT);
        return lower.contains("invoke-expression")
                || lower.contains("iex(")
                || lower.contains("downloadstring")
                || lower.contains("new-object net.webclient")
                || lower.contains("system.net.webrequest")
                || lower.contains("frombase64string")
                || lower.contains("start-process")
                || lower.contains("set-executionpolicy");
    }

    private static boolean looksLikeVbScript(byte[] b, int end) {
        String head = asciiHead(b, end, 512).toLowerCase(Locale.ROOT);
        return head.contains("createobject(\"wscript.shell\")")
                || head.contains("createobject(\"scripting.filesystemobject\")")
                || head.contains("shell.application")
                || head.contains("adodb.stream");
    }

    private static String asciiHead(byte[] b, int end, int length) {
        int size = Math.min(Math.min(end, length), b.length);
        StringBuilder out = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            int unsigned = b[i] & 0xFF;
            out.append(unsigned < 0x80 ? (char) unsigned : ' ');
        }
        return out.toString();
    }

    private static int indexOf(CharBuffer buffer, char target, int from) {
        int limit = buffer.limit();
        for (int i = Math.max(0, from); i < limit; i++) {
            if (buffer.get(i) == target) {
                return i;
            }
        }
        return -1;
    }

    private static boolean startsWith(byte[] b, int end, int... signature) {
        if (end < signature.length) {
            return false;
        }
        for (int i = 0; i < signature.length; i++) {
            if ((b[i] & 0xFF) != (signature[i] & 0xFF)) {
                return false;
            }
        }
        return true;
    }

    /** Compares bytes to a literal, mapping each char to its low byte. */
    private static boolean asciiEquals(byte[] b, int end, int offset, String literal) {
        if (end < offset + literal.length()) {
            return false;
        }
        for (int i = 0; i < literal.length(); i++) {
            if ((b[offset + i] & 0xFF) != (literal.charAt(i) & 0xFF)) {
                return false;
            }
        }
        return true;
    }
}
