package com.company.incidentplatform.audit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Assigns a request id and echoes it back.
 *
 * <p>7.11 requires the audit entry to carry a request id, and 7.12 needs
 * correlation between an anomaly alert and the request that caused it. The id is
 * also returned to the caller in a response header, so a user can quote it in a
 * support request and an operator can find the exact audit rows.
 *
 * <p>An inbound {@code X-Request-Id} is honoured only if it parses as a UUID.
 * Accepting arbitrary caller-supplied strings would let a client either forge a
 * correlation id that collides with a real one, or inject unbounded text into
 * every log line and audit row it appears in.
 *
 * <p>Ordered ahead of the Spring Security filter chain so the id exists even for
 * a request rejected during authentication.
 */
@Component
@Order(1)
public class RequestIdFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Request-Id";
    private static final String MDC_KEY = "requestId";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        UUID requestId = parseInbound(request.getHeader(HEADER));
        if (requestId == null) {
            requestId = UUID.randomUUID();
        }

        request.setAttribute(RequestContext.REQUEST_ID_ATTRIBUTE, requestId);
        response.setHeader(HEADER, requestId.toString());
        MDC.put(MDC_KEY, requestId.toString());
        try {
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }

    private static UUID parseInbound(String header) {
        if (header == null || header.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(header.trim());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
