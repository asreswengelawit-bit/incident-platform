package com.company.incidentplatform.evidence;

import com.company.incidentplatform.incident.IncidentCategoryEntity;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * 7.6 / FR-1.2 -- the allow-list decision, made on the sniffed type.
 *
 * <p>Three inputs, in this order:
 *
 * <ol>
 *   <li>{@link #NEVER_ALLOWED} -- types that are refused whatever the
 *       configuration says,</li>
 *   <li>the category's rows in {@code incident_category_allowed_type}
 *       (FR-1.2: "allowed types configurable by Admin"), falling back to the
 *       platform default set when the category has none,</li>
 *   <li>the file's <em>extension</em>, as a secondary signal only.</li>
 * </ol>
 *
 * <p>Item 3 is last and narrow on purpose. The extension cannot make a file
 * acceptable -- only an extension implying an executable or a script can make it
 * <em>in</em>acceptable, as defence in depth behind the sniffed-type decision.
 * The reverse relationship does not exist, because "the name looks fine" is the
 * exact reasoning 7.6 rules out.
 */
@Component
public class EvidenceTypePolicy {

    private static final Logger log = LoggerFactory.getLogger(EvidenceTypePolicy.class);

    /**
     * Refused regardless of configuration.
     *
     * <p>An allow-list is a control, and a control that an Administrator can
     * configure into uselessness has to be told so. These are types whose whole
     * purpose is to be executed by whatever opens them, which is not a property a
     * file uploaded as <em>evidence</em> can need: the evidence value is in the
     * content being visible to a human, and none of these render usefully for
     * that. An attempt to add one of these to a category's allow-list is refused
     * and logged, rather than obeyed, and the refusal is reported in the
     * {@link Decision} so it reaches the 7.11 audit row too.
     */
    private static final Set<String> NEVER_ALLOWED = Set.of(
            "application/x-msdownload",
            "application/x-elf",
            "application/x-mach-binary",
            "application/java-vm",
            "text/x-script",
            "text/x-msdos-batch",
            "text/x-powershell",
            "text/x-vbscript",
            "application/vnd.ms-office.macroEnabled",
            "application/zip",
            "application/octet-stream");

    /**
     * Extensions implying one of the never-allowed types.
     *
     * <p>Secondary control only. A {@code .exe} whose bytes are a PNG is refused
     * on the strength of the name even though the content is harmless; that is
     * intentional, because the cost of the false positive is a renamed file and
     * the cost of the false negative is a payload that some future handler opens.
     */
    private static final Set<String> NEVER_ALLOWED_EXTENSIONS = Set.of(
            "exe", "dll", "com", "scr", "pif", "cpl", "msi", "msp", "sys", "ocx",
            "jar", "class", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf",
            "wsh", "hta", "bat", "cmd", "lnk", "iso", "img", "chm", "reg", "scf",
            "application", "gadget", "inf", "ins", "isp", "job", "mst", "sct", "shb",
            "vb", "vxd", "ws", "wsc");

    private final EvidenceAllowedTypeRepository allowedTypes;
    private final EvidenceProperties properties;

    public EvidenceTypePolicy(
            EvidenceAllowedTypeRepository allowedTypes, EvidenceProperties properties) {
        this.allowedTypes = allowedTypes;
        this.properties = properties;
    }

    /**
     * The verdict, carrying the reason it was reached.
     *
     * <p>The reason is not decoration. 7.11 requires the audit row to be
     * reconstructable, and "evidence rejected" without "because it is an
     * executable" is an entry an administrator can act on in neither direction.
     */
    public record Decision(boolean allowed, String reason) {

        static Decision allow(String reason) {
            return new Decision(true, reason);
        }

        static Decision refuse(String reason) {
            return new Decision(false, reason);
        }
    }

    @Transactional(readOnly = true)
    public Decision decide(IncidentCategoryEntity category, String sniffedMimeType, String fileName) {
        String mimeType = normalise(sniffedMimeType);

        if (NEVER_ALLOWED.contains(mimeType)) {
            return Decision.refuse(
                    "sniffed type " + mimeType + " is never accepted as evidence (7.6)");
        }

        String extension = extensionOf(fileName);
        if (extension != null && NEVER_ALLOWED_EXTENSIONS.contains(extension)) {
            // Name-based refusal of an otherwise-inert payload. Logged as a
            // warning because a legitimate reporter renaming a file produces this
            // too, and a repeated pattern across many reports is itself a signal.
            log.warn("Evidence file name carries a non-evidence extension ({}), refused for category {}",
                    extension, category == null ? "<none>" : category.getName());
            return Decision.refuse(
                    "file extension ." + extension + " is not accepted for evidence (7.6)");
        }

        Set<String> configured = configuredTypesFor(category);
        if (configured.contains(mimeType)) {
            return Decision.allow("sniffed type " + mimeType + " is allow-listed for this category");
        }
        return Decision.refuse("sniffed type " + mimeType + " is not allow-listed for this category");
    }

    /**
     * The effective allow-list for a category.
     *
     * <p>A category with no configured rows falls back to the platform defaults.
     * The alternative -- treating an empty allow-list as "accept nothing" -- was
     * rejected because the seeded categories in {@code V11} have no rows, and it
     * would have made evidence upload fail closed for every category in a fresh
     * deployment with no visible cause. A category that must genuinely accept
     * nothing is expressed by deactivating it, which has a name and a workflow.
     */
    private Set<String> configuredTypesFor(IncidentCategoryEntity category) {
        if (category != null) {
            List<EvidenceAllowedTypeEntity> rows = allowedTypes.findByIdCategoryId(category.getId());
            if (!rows.isEmpty()) {
                Set<String> types = new LinkedHashSet<>();
                for (EvidenceAllowedTypeEntity row : rows) {
                    types.add(normalise(row.getMimeType()));
                }
                return types;
            }
        }
        return new LinkedHashSet<>(properties.getDefaultAllowedMimeTypes());
    }

    private static String normalise(String mimeType) {
        if (mimeType == null) {
            return "";
        }
        // Parameters ("; charset=utf-8") are not part of the identity of a type
        // and a sniffed type never carries them, but a configured row might.
        int parameters = mimeType.indexOf(';');
        String base = parameters >= 0 ? mimeType.substring(0, parameters) : mimeType;
        return base.trim().toLowerCase(Locale.ROOT);
    }

    private static String extensionOf(String fileName) {
        if (fileName == null) {
            return null;
        }
        int dot = fileName.lastIndexOf('.');
        if (dot < 0 || dot == fileName.length() - 1) {
            return null;
        }
        return fileName.substring(dot + 1).toLowerCase(Locale.ROOT);
    }
}
