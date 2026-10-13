package com.company.incidentplatform.audit;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.UUID;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Per-request facts that 7.11 requires in every audit entry: a request id, the
 * endpoint, the method, and the client address.
 *
 * <p>The request id is a {@link UUID} because {@code audit_log.request_id} is a
 * {@code uuid} column -- a correlation id is only useful if it can be a real key
 * rather than an arbitrary string that needs a functional index.
 *
 * <p>Reads from {@link RequestContextHolder} rather than taking a servlet
 * dependency, so the same code can be exercised in a unit test with no web layer
 * at all. Every accessor degrades to empty when there is no active request,
 * because audit writing must not become the thing that fails during a scheduled
 * job or a startup listener.
 */
public final class RequestContext {

    public static final String REQUEST_ID_ATTRIBUTE = "incident_platform.request_id";
    private static final String TRUSTED_PROXY_HEADER = "X-Forwarded-For";

    /**
     * Whether {@code X-Forwarded-For} may be believed, set once at startup from
     * {@code incident-platform.trust-forwarded-for}.
     *
     * <p>Held here rather than passed at each of the dozen call sites that need a
     * client address. Passed as a parameter, it was hard-coded to {@code false}
     * everywhere outside the security filter chain -- which meant a deployment
     * correctly configured behind a trusted proxy recorded the proxy's address
     * against its denied-authorization events, and 7.12's anomaly detection would
     * have seen every one of them as the same client. The property is
     * deployment-wide, so the right shape is one value read once.
     */
    private static volatile boolean trustForwardedFor;

    private RequestContext() {
    }

    /** Called once during startup; see {@code PlatformSecurityProperties}. */
    public static void trustForwardedFor(boolean trusted) {
        trustForwardedFor = trusted;
    }

    public static Optional<UUID> requestId() {
        return attribute(REQUEST_ID_ATTRIBUTE, UUID.class);
    }

    public static String endpoint() {
        HttpServletRequest request = currentRequest();
        if (request == null) {
            return null;
        }
        // The pattern, not the concrete path. /api/v1/incidents/<uuid> records as
        // the template so the column stays useful for grouping instead of
        // fragmenting into one value per incident.
        String pattern = (String) request.getAttribute(
                org.springframework.web.servlet.HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        return pattern != null ? pattern : request.getRequestURI();
    }

    public static String method() {
        HttpServletRequest request = currentRequest();
        return request == null ? null : request.getMethod();
    }

    /**
     * The client address, honouring {@code X-Forwarded-For} only when a trusted
     * proxy is configured.
     *
     * <p>7.5 is explicit that forwarded headers are client-controlled unless the
     * proxy is trusted, and an unvalidated {@code X-Forwarded-For} would let an
     * attacker forge the source address recorded against a denied-authorization
     * event -- destroying exactly the evidence 7.12 needs. When no trusted proxy
     * is declared, the socket address is used and the header ignored.
     */
    public static String remoteAddress() {
        return remoteAddress(trustForwardedFor);
    }

    public static String remoteAddress(boolean trustForwardedFor) {
        HttpServletRequest request = currentRequest();
        if (request == null) {
            return null;
        }
        if (trustForwardedFor) {
            String forwarded = request.getHeader(TRUSTED_PROXY_HEADER);
            if (forwarded != null && !forwarded.isBlank()) {
                // Left-most entry is the original client.
                int comma = forwarded.indexOf(',');
                String first = comma > 0 ? forwarded.substring(0, comma) : forwarded;
                if (!first.isBlank()) {
                    return first.trim();
                }
            }
        }
        return request.getRemoteAddr();
    }

    public static UUID newRequestId() {
        return UUID.randomUUID();
    }

    private static HttpServletRequest currentRequest() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servletAttributes) {
            return servletAttributes.getRequest();
        }
        return null;
    }

    private static <T> Optional<T> attribute(String name, Class<T> type) {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return Optional.empty();
        }
        Object value = attributes.getAttribute(name, RequestAttributes.SCOPE_REQUEST);
        return type.isInstance(value) ? Optional.of(type.cast(value)) : Optional.empty();
    }
}
