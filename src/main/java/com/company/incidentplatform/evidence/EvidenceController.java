package com.company.incidentplatform.evidence;

import com.company.incidentplatform.security.PlatformUser;
import com.company.incidentplatform.web.CurrentUser;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

/**
 * Section 9: the evidence endpoints.
 *
 * <pre>
 *   POST /api/v1/incidents/{id}/evidence                    Reporter (own), Analyst+
 *   GET  /api/v1/incidents/{id}/evidence                    whoever may read the incident
 *   GET  /api/v1/incidents/{id}/evidence/{evidenceId}       whoever may read the incident
 * </pre>
 *
 * <p>There is no delete endpoint and no update endpoint, and their absence is the
 * specification rather than an omission: 7.6 restricts object deletion to the 7.14
 * retention/legal-hold process, and FR-1.4's evidentiary-integrity rule means an
 * attached file is never edited or replaced.
 *
 * <p>Authorization happens in {@link EvidenceService}, not here, for the same
 * reason it does on every other controller: one place decides, so it cannot be
 * forgotten on the endpoint someone adds later.
 */
@RestController
@RequestMapping("/api/v1/incidents/{incidentId}/evidence")
public class EvidenceController {

    private final EvidenceService evidenceService;

    public EvidenceController(EvidenceService evidenceService) {
        this.evidenceService = evidenceService;
    }

    /**
     * FR-1.2: attach a file.
     *
     * <p>201 even when the file is quarantined: the upload genuinely was accepted
     * and the object exists as an indicator. The response body carries
     * {@code scanStatus} and {@code quarantineReason} so the client can say so, and
     * {@code downloadable=false} means the UI cannot offer a download link that
     * would 409.
     */
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    EvidenceViews.EvidenceView upload(
            @PathVariable UUID incidentId,
            @RequestPart("file") MultipartFile file,
            @RequestParam(value = "chainOfCustodyNote", required = false) String chainOfCustodyNote,
            @CurrentUser PlatformUser caller) {

        return evidenceService.upload(incidentId, file, chainOfCustodyNote, caller);
    }

    @GetMapping
    List<EvidenceViews.EvidenceView> list(
            @PathVariable UUID incidentId,
            @CurrentUser PlatformUser caller) {

        return evidenceService.list(incidentId, caller);
    }

    /**
     * 7.6's download path: the browser asks the API, the API decides, and the
     * object store is never reachable from a client.
     *
     * <p>{@link StreamingResponseBody} rather than returning a {@code Resource}:
     * the service's verification has already completed by the time the response
     * headers are written, and streaming keeps a 25 MB file out of the heap on the
     * way out as well as on the way in.
     */
    @GetMapping("/{evidenceId}")
    ResponseEntity<StreamingResponseBody> download(
            @PathVariable UUID incidentId,
            @PathVariable UUID evidenceId,
            @CurrentUser PlatformUser caller) {

        EvidenceViews.EvidenceContent content = evidenceService.download(incidentId, evidenceId, caller);
        return ResponseEntity.ok()
                .contentType(mediaTypeOf(content.detectedContentType()))
                .contentLength(content.sizeBytes())
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment()
                                .filename(content.fileName())
                                .build()
                                .toString())
                // 7.5: the response must not be reinterpreted as something the
                // sniffer did not say it is. A stored HTML or SVG file served with
                // its own type would execute in the origin of the API.
                .header("X-Content-Type-Options", "nosniff")
                .header(HttpHeaders.CACHE_CONTROL, "no-store, private")
                .body(streamOf(content));
    }

    /**
     * The detached content type.
     *
     * <p>Always the <em>sniffed</em> type, never the client's declared one: echoing
     * a client-supplied {@code Content-Type} into a response is how a stored file
     * becomes stored XSS against the API's own origin.
     */
    private static MediaType mediaTypeOf(String detectedContentType) {
        if (detectedContentType == null || detectedContentType.isBlank()) {
            return MediaType.APPLICATION_OCTET_STREAM;
        }
        try {
            return MediaType.parseMediaType(detectedContentType);
        } catch (org.springframework.http.InvalidMediaTypeException unparseable) {
            return MediaType.APPLICATION_OCTET_STREAM;
        }
    }

    private static StreamingResponseBody streamOf(EvidenceViews.EvidenceContent content) {
        return (OutputStream out) -> {
            try (InputStream in = content.content()) {
                in.transferTo(out);
                out.flush();
            }
        };
    }
}
