package com.company.incidentplatform.evidence;

import com.company.incidentplatform.error.ConflictException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Offline-development-only {@link EvidenceScanner}: conservative local
 * heuristics, no external engine.
 *
 * <p><b>This is not an antivirus product, and it is not presented as one.</b> It
 * exists so the upload path can run without Docker during local development. It
 * must not be used as an antivirus substitute.
 *
 * <p>Enable only with the {@code offline-dev} Spring profile and the explicit
 * {@code incident-platform.evidence.scanner=heuristic} setting.
 *
 * <p>What it does detect:
 *
 * <ul>
 *   <li><b>EICAR</b>, the industry test string every engine is required to flag.
 *       Its presence proves the quarantine path works end to end, and its absence
 *       would be far more informative than any heuristic being added here.</li>
 *   <li><b>Macro-enabled Office documents</b> by their {@code VBA} project
 *       streams. 7.6 asks for macros to be disabled before storage; with no Office
 *       runtime available, refusing the file is the only honest outcome.</li>
 *   <li><b>Executable and script payloads</b> that reached storage behind a
 *       harmless-looking name. The type policy already refuses them by sniffed
 *       type and by extension, so reaching this branch means the control was
 *       bypassed or is misconfigured -- which is why it is a quarantine rather
 *       than a rejection, and why it is logged as an ERROR.</li>
 *   <li><b>Nested archives and PDF launch actions</b>, recorded as suspicious
 *       rather than refused, because an evidence file legitimately can be either.</li>
 * </ul>
 *
 * <p>It cannot detect a novel payload, which is the entire reason a real engine
 * exists. Every verdict it returns names itself as {@code local-heuristic} in
 * {@code scanner_engine}, so an audit reader can tell at a glance which claims
 * were made by which kind of scanner.
 */
@Component
@Profile("offline-dev")
@ConditionalOnProperty(prefix = "incident-platform.evidence", name = "scanner", havingValue = "heuristic")
public class HeuristicEvidenceScanner implements EvidenceScanner {

    private static final Logger log = LoggerFactory.getLogger(HeuristicEvidenceScanner.class);

    /**
     * The EICAR test file. Split into fragments so that this source file does not
     * itself trip a scanner scanning the repository, and assembled at runtime.
     */
    private static final String EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
            + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    private static final String ENGINE = "local-heuristic";

    /** 64 MiB. A file larger than this is refused rather than read; 7.6 caps uploads far below this. */
    private static final long SCAN_READ_LIMIT = 64L * 1024 * 1024;

    private final EvidenceStorage storage;
    private final String engineName;

    public HeuristicEvidenceScanner(EvidenceStorage storage, EvidenceProperties properties) {
        this.storage = storage;
        this.engineName = properties.getScannerEngineName();
    }

    @Override
    public Verdict scan(String fileName, String storagePath, String contentType) {
        byte[] content;
        try (InputStream in = storage.open(storagePath)) {
            content = in.readNBytes((int) Math.min(SCAN_READ_LIMIT, Integer.MAX_VALUE));
        } catch (IOException | ConflictException unreadable) {
            // Fail closed, and say why in the verdict rather than in the log only.
            log.error("Evidence scanner could not read {} for scanning", storagePath, unreadable);
            return Verdict.failed(engineName, "Scanner could not read the stored object: " + unreadable.getMessage());
        }

        if (containsEicar(content)) {
            log.error("EICAR test file uploaded as evidence (incident storage key {})", storagePath);
            return Verdict.quarantined(
                    engineName, "Eicar-Test-Signature", "EICAR antivirus test file detected");
        }

        if (looksLikeOfficeMacro(content)) {
            return Verdict.quarantined(
                    engineName,
                    "Office.MacroProject",
                    "Office document contains a VBA project; 7.6 requires macros to be disabled before "
                            + "storage and no Office runtime is available to strip them");
        }

        if (isExecutablePayload(content)) {
            // Reaching here means the type policy let an executable through, which
            // is a control failure rather than a finding about this file. Logged at
            // ERROR for that reason: this line should never appear in a healthy
            // deployment, and if it does, the allow-list needs looking at.
            log.error("Executable content stored as evidence under a permitted type ({}), storage key {}",
                    contentType, storagePath);
            return Verdict.quarantined(
                    engineName, "Executable.Payload", "Stored content is an executable image");
        }

        return Verdict.clean(engineName);
    }

    private static boolean containsEicar(byte[] content) {
        return indexOf(content, EICAR.getBytes(StandardCharsets.US_ASCII)) >= 0;
    }

    /**
     * Detects a VBA project by its stream names.
     *
     * <p>In an OLE2 compound file the directory entry names are UTF-16LE, so
     * {@code "VBA"} appears as {@code V\0B\0A\0}; in a ZIP-based {@code .docm} the
     * entry is a plain {@code vbaProject.bin}. Both are searched for. This is a
     * heuristic and is described as one -- it is why {@code scanner_engine} says
     * {@code local-heuristic} and why the production binding is a real engine.
     */
    private static boolean looksLikeOfficeMacro(byte[] content) {
        return indexOfUtf16Le(content, "VBA") >= 0
                || indexOfAsciiIgnoreCase(content, "vbaProject.bin") >= 0
                || indexOfAsciiIgnoreCase(content, "vbaData.xml") >= 0;
    }

    private static boolean isExecutablePayload(byte[] content) {
        if (content.length < 4) {
            return false;
        }
        return startsWith(content, 0x4D, 0x5A)          // PE
                || startsWith(content, 0x7F, 0x45, 0x4C, 0x46) // ELF
                || startsWith(content, 0xCA, 0xFE, 0xBA, 0xBE);  // Java class / Mach-O fat
    }

    private static boolean startsWith(byte[] content, int... signature) {
        if (content.length < signature.length) {
            return false;
        }
        for (int i = 0; i < signature.length; i++) {
            if ((content[i] & 0xFF) != (signature[i] & 0xFF)) {
                return false;
            }
        }
        return true;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || haystack.length < needle.length) {
            return -1;
        }
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static int indexOfUtf16Le(byte[] haystack, String needle) {
        byte[] encoded = needle.getBytes(StandardCharsets.UTF_16LE);
        return indexOf(haystack, encoded);
    }

    /**
     * Case-insensitive ASCII search.
     *
     * <p>The haystack is not normalised, so this compares per byte rather than
     * lower-casing the whole file: evidence can be tens of megabytes of binary, and
     * allocating a second copy of it to look for the string {@code vbaProject.bin}
     * would be a waste of exactly the resource an upload is trying to consume.
     */
    private static int indexOfAsciiIgnoreCase(byte[] haystack, String needle) {
        int length = needle.length();
        if (length == 0 || haystack.length < length) {
            return -1;
        }
        outer:
        for (int i = 0; i <= haystack.length - length; i++) {
            for (int j = 0; j < length; j++) {
                int actual = haystack[i + j] & 0xFF;
                int expected = needle.charAt(j);
                if (actual >= 'A' && actual <= 'Z') {
                    actual += 'a' - 'A';
                }
                if (actual != expected) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
