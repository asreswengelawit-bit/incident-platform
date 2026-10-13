package com.company.incidentplatform.evidence;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Platform configuration for the evidence path ({@code incident-platform.evidence}).
 *
 * <p>Bound as a class rather than read through scattered {@code @Value} injections
 * because these values are the ones an operator has to reason about together: the
 * storage root, the size ceilings, and the allow-list are a single security
 * posture, and seeing them in one place is the difference between configuring
 * them deliberately and configuring them accidentally.
 *
 * <p>The defaults are development-safe rather than production-relaxed. In
 * particular {@code storageRoot} is a path <em>outside</em> any web root, and the
 * startup check in {@link FileSystemEvidenceStorage} refuses to come up if it
 * resolves to somewhere a static resource handler could serve.
 */
@ConfigurationProperties(prefix = "incident-platform.evidence")
public class EvidenceProperties {

    /**
     * Private directory the bytes are written to.
     *
     * <p>7.6: "Files stored outside the web root, served only via authenticated,
     * authorization-checked download endpoints -- never as direct/static links."
     */
    private String storageRoot;

    /**
     * Platform-wide default allow-list, used for any category with no rows in
     * {@code incident_category_allowed_type}.
     *
     * <p>Sourced from the sniffed type only. Order is irrelevant.
     */
    private List<String> defaultAllowedMimeTypes;

    /**
     * Hard ceiling per file, applied before the per-category limit.
     *
     * <p>Must not exceed {@code spring.servlet.multipart.max-file-size}, which is
     * what actually stops a large body being buffered; this is the second gate,
     * for the case where the multipart ceiling is raised globally for another
     * endpoint and evidence should stay tighter.
     */
    private long maxFileSizeBytes;

    /**
     * Name of the scanner engine recorded in {@code incident_evidence} when the
     * active {@link EvidenceScanner} gives no better name. 7.6 and the {@code V5}
     * check constraint both require provenance for a CLEAN verdict, so this
     * cannot be blank.
     */
    private String scannerEngineName;

    /**
     * Constructor-bound, so every parameter carries its own {@link DefaultValue}.
     *
     * <p>This class has exactly one constructor and it takes arguments, which is what
     * makes Spring Boot bind it by constructor rather than by setter. Under that
     * binding the defaults live in the annotations, not in field initialisers: a bare
     * {@code @DefaultValue} supplies no default, and binding then fails outright with
     * "Parameter of type java.lang.String must have a non-empty default value". That
     * failure happens while the bean is being created, so it takes down every
     * application context that enables the evidence path.
     */
    public EvidenceProperties(
            @DefaultValue("./var/evidence") String storageRoot,
            @DefaultValue({
                    "image/png",
                    "image/jpeg",
                    "image/gif",
                    "image/bmp",
                    "image/webp",
                    "application/pdf",
                    "message/rfc822",
                    "application/x-ole-storage",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "application/rtf",
                    "text/plain"}) List<String> defaultAllowedMimeTypes,
            @DefaultValue("26214400") long maxFileSizeBytes,
            @DefaultValue("local-heuristic") String scannerEngineName) {
        this.storageRoot = storageRoot;
        this.defaultAllowedMimeTypes = List.copyOf(defaultAllowedMimeTypes);
        this.maxFileSizeBytes = maxFileSizeBytes;
        this.scannerEngineName = scannerEngineName;
    }

    public String getStorageRoot() {
        return storageRoot;
    }

    public List<String> getDefaultAllowedMimeTypes() {
        return defaultAllowedMimeTypes;
    }

    public long getMaxFileSizeBytes() {
        return maxFileSizeBytes;
    }

    public String getScannerEngineName() {
        return scannerEngineName;
    }
}
