package com.company.incidentplatform.web;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.audit.RequestContext;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.config.PlatformSecurityProperties;
import com.company.incidentplatform.error.ConflictException;
import com.company.incidentplatform.error.EvidenceRejectedException;
import com.company.incidentplatform.error.LastAdministratorException;
import com.company.incidentplatform.error.ResourceNotFoundException;
import com.company.incidentplatform.incident.InvalidStatusTransitionException;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformUser;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/**
 * Section 7.5 -- one place where an exception becomes an HTTP response.
 *
 * <p>Three rules, all of them 7.5 rather than taste:
 *
 * <ul>
 *   <li><b>No internal detail reaches the client.</b> The body is a stable error
 *       code; the message, the exception, the stack trace and any SQL live in the
 *       log, correlated by the request id the filter already returned in
 *       {@code X-Request-Id}. A validation failure is the one place a caller is
 *       told something about their own input, and even then only the field name
 *       and the constraint's own message -- never the rejected value, which
 *       would echo a password or a token back into a log the caller can read.</li>
 *   <li><b>Denials are audited here too.</b> {@code SecurityConfig}'s access
 *       handler only sees failures raised inside the filter chain. An
 *       {@link AuthorizationDeniedException} thrown by the 7.2 object-level guard
 *       inside a controller propagates to the dispatcher instead, so without this
 *       class a BOLA denial -- the exact event 7.11 requires recorded and 7.12
 *       alerts on -- would return a 403 and leave no trace.</li>
 *   <li><b>The response code is not the decision.</b> Nothing here decides who may
 *       do what; it only decides how a refusal is reported. Authorization lives in
 *       the guard and the state machine, where it is testable without a servlet.</li>
 * </ul>
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    private final AuditService audit;
    private final PlatformSecurityProperties props;

    public ApiExceptionHandler(AuditService audit, PlatformSecurityProperties props) {
        this.audit = audit;
        this.props = props;
    }

    /**
     * 7.2 object- and function-level denials raised inside a controller.
     *
     * <p>Audited as a denial with the specific rule that refused, which is what
     * turns "a Reporter walked a range of incident ids and got 403 each time"
     * into a detectable BOLA-probing pattern rather than 200 identical status
     * codes.
     */
    @ExceptionHandler(AuthorizationDeniedException.class)
    ResponseEntity<Map<String, Object>> onAuthorizationDenied(AuthorizationDeniedException ex) {
        audit.recordDenied(
                currentUserOrNull(),
                ex.decision().deniedReason() == null
                        ? DeniedReason.INSUFFICIENT_ROLE
                        : ex.decision().deniedReason(),
                ex.resourceType(),
                ex.resourceId(),
                "access",
                RequestContext.endpoint(),
                RequestContext.method(),
                requestId(),
                RequestContext.remoteAddress(props.trustForwardedFor()),
                ex.decision().checkType(),
                ex.decision().rule());
        return respond(HttpStatus.FORBIDDEN, "forbidden");
    }

    /** A @PreAuthorize denial (7.2 function level at the method boundary). */
    @ExceptionHandler(AccessDeniedException.class)
    ResponseEntity<Map<String, Object>> onSpringAccessDenied(AccessDeniedException ex) {
        audit.recordDenied(
                currentUserOrNull(),
                DeniedReason.INSUFFICIENT_ROLE,
                "endpoint",
                null,
                "access",
                RequestContext.endpoint(),
                RequestContext.method(),
                requestId(),
                RequestContext.remoteAddress(props.trustForwardedFor()),
                AuthorizationCheckType.FUNCTION_LEVEL,
                "security.method_access_denied");
        return respond(HttpStatus.FORBIDDEN, "forbidden");
    }

    /**
     * 8.2: an unlisted (current, next) pair. 422 rather than 400, because the
     * request is well-formed and the refusal is about the incident's position in
     * the lifecycle -- and 8.2 requires it to be recorded as a denied action.
     */
    @ExceptionHandler(InvalidStatusTransitionException.class)
    ResponseEntity<Map<String, Object>> onInvalidTransition(InvalidStatusTransitionException ex) {
        // The refused pair goes into the rule string. A column of
        // "transition_not_permitted" rows tells a reviewer that something was
        // refused; knowing it was CLOSED -> INVESTIGATING tells them whether the
        // workflow is being misused or someone is probing it.
        String rule = ex.getFromStatus() == null
                ? "state_machine.transition_not_permitted"
                : "state_machine.transition_not_permitted:" + ex.getFromStatus() + "_TO_" + ex.getToStatus();

        audit.recordDenied(
                currentUserOrNull(),
                DeniedReason.TRANSITION_NOT_PERMITTED,
                "incident",
                null,
                "status_change",
                RequestContext.endpoint(),
                RequestContext.method(),
                requestId(),
                RequestContext.remoteAddress(props.trustForwardedFor()),
                AuthorizationCheckType.OBJECT_LEVEL,
                rule);
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "transition_not_permitted");
    }

    /**
     * 7.10: an optimistic-lock failure or an assignment race. The message here is
     * the one place a caller is told what went wrong, because 7.10 explicitly
     * requires the conflict surface "a clear 'this incident changed, please
     * refresh' response" -- a generic body would leave the Analyst unable to tell
     * a lost edit from a rejected one.
     */
    @ExceptionHandler({ConflictException.class, OptimisticLockingFailureException.class})
    ResponseEntity<Map<String, Object>> onConflict(Exception ex) {
        if (ex instanceof OptimisticLockingFailureException) {
            log.info("Optimistic lock conflict on {} {} requestId={}",
                    RequestContext.method(), RequestContext.endpoint(), requestId());
        }
        return respond(HttpStatus.CONFLICT, "conflict", "This record changed while you were editing it. "
                + "Reload it and reapply your change.");
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    ResponseEntity<Map<String, Object>> onNotFound(ResourceNotFoundException ex) {
        log.info("Not found: {} requestId={} method={}",
                ex.getMessage(), requestId(), RequestContext.method());
        return respond(HttpStatus.NOT_FOUND, "not_found");
    }

    /**
     * FR-6.1: the last-administrator invariant. 409, like a version conflict, but a
     * different answer -- see {@link LastAdministratorException} for why the two must
     * not share a body, and {@code AdminUserService} for the serialisation that makes
     * the invariant hold under concurrency.
     *
     * <p>Logged at warn rather than info: unlike a lost optimistic-lock race, this is
     * not a routine outcome of two people working at once. It means an admin tried to
     * remove the last administrator, which is worth noticing whether or not the
     * refusal was correct.
     */
    @ExceptionHandler(LastAdministratorException.class)
    ResponseEntity<Map<String, Object>> onLastAdministrator(LastAdministratorException ex) {
        PlatformUser actor = currentUserOrNull();
        log.warn("Last-administrator invariant refused an admin change: {} requestId={} method={} actor={}",
                ex.getAttemptedAction(), requestId(), RequestContext.method(),
                actor == null ? "unknown" : actor.id());
        return respond(HttpStatus.CONFLICT, "last_administrator", ex.getMessage());
    }

    /**
     * Bean-validation failures on a request body. Field names and constraint
     * messages only: the rejected value is not echoed, so a caller that put a
     * secret in a field cannot have it reflected into a response or a proxy log.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<Map<String, Object>> onValidationFailure(MethodArgumentNotValidException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            fields.putIfAbsent(error.getField(), error.getDefaultMessage());
        }
        return respond(HttpStatus.BAD_REQUEST, "validation_failed", null, fields);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<Map<String, Object>> onUnreadableBody(HttpMessageNotReadableException ex) {
        // The parser's message names the offending JSON path and sometimes the
        // offending token, so it is logged, not returned.
        log.debug("Unparseable request body on {} {} requestId={}",
                RequestContext.method(), RequestContext.endpoint(), requestId(), ex);
        return respond(HttpStatus.BAD_REQUEST, "malformed_request");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<Map<String, Object>> onIllegalArgument(IllegalArgumentException ex) {
        // Messages from our own validation (unknown category, out-of-range impact
        // rank, an unconfigured matrix cell) are about the caller's request and
        // are safe to reflect; anything thrown by a library is not, so the
        // exception type decides rather than the message alone.
        boolean ownValidation = ex.getClass().equals(IllegalArgumentException.class);
        if (!ownValidation) {
            log.warn("IllegalArgumentException from {} on {} requestId={}",
                    ex.getClass().getName(), RequestContext.endpoint(), requestId(), ex);
            return respond(HttpStatus.BAD_REQUEST, "invalid_request");
        }
        return respond(HttpStatus.BAD_REQUEST, "invalid_request", ex.getMessage());
    }

    /**
     * 7.6: an evidence upload or download was refused by policy.
     *
     * <p>{@link EvidenceRejectedException} is thrown from nine sites across the
     * evidence module, and each {@code Kind} documents the status it is supposed to
     * produce. Without a handler here they all reached the catch-all below and
     * returned {@code 500 internal_error} -- which is wrong in a way that mattered:
     *
     * <ul>
     *   <li>a quarantined or unscanned file returned 500, telling the caller the
     *       <em>platform</em> failed when in fact 7.6 held the file and recorded it
     *       as an IOC, so the reviewer chased the wrong control;</li>
     *   <li>an unsupported type returned 500 rather than 415, so a client could not
     *       distinguish "wrong file" from "try again" -- the exact distinction the
     *       Kind javadoc exists to preserve;</li>
     *   <li>an oversized file returned 500 rather than 413, contradicting the
     *       {@link MaxUploadSizeExceededException} branch below, which already
     *       returns 413 for the same FR-1.2 limit reached at the container level.
     *       Two paths, one limit, two different status codes.</li>
     * </ul>
     *
     * <p>The messages are returned because {@link EvidenceRejectedException}
     * documents that they are composed in-application from the policy's own
     * reasoning -- no file content, sniffed bytes, or storage path reaches them.
     * The integrity case is deliberately terse for the same reason: it is a
     * chain-of-custody event (already audited at its throw site before the
     * exception was raised), and the client needs to know only that nothing was
     * served.
     */
    @ExceptionHandler(EvidenceRejectedException.class)
    ResponseEntity<Map<String, Object>> onEvidenceRejected(EvidenceRejectedException ex) {
        return switch (ex.getKind()) {
            case UNSUPPORTED_TYPE -> {
                log.info("Evidence upload rejected: type not permitted, requestId={}", requestId());
                yield respond(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type", ex.getMessage());
            }
            case TOO_LARGE -> {
                log.info("Evidence upload rejected: exceeds per-category limit, requestId={}", requestId());
                yield respond(HttpStatus.PAYLOAD_TOO_LARGE, "payload_too_large", ex.getMessage());
            }
            case NOT_DOWNLOADABLE -> {
                log.info("Evidence download refused: not downloadable (quarantined, unscanned or "
                        + "retention-removed), requestId={}", requestId());
                yield respond(HttpStatus.CONFLICT, "evidence_not_downloadable", ex.getMessage());
            }
            case INTEGRITY_FAILURE -> {
                // 7.6 hash mismatch is already an audited record written at the
                // throw site, before this handler runs. Do not audit it a second
                // time here -- one event, one row (7.11).
                log.error("Evidence integrity failure refused a download, requestId={}", requestId());
                yield respond(HttpStatus.CONFLICT, "evidence_integrity_failure", ex.getMessage());
            }
        };
    }

    /** 7.6: a per-category upload limit refused the body before it was stored. */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    ResponseEntity<Map<String, Object>> onUploadTooLarge(MaxUploadSizeExceededException ex) {
        return respond(HttpStatus.PAYLOAD_TOO_LARGE, "payload_too_large",
                "The file exceeds the configured size limit for this category (FR-1.2).");
    }

    /**
     * A database constraint refused the write. Surfaced as a 409 with no detail:
     * a constraint name is a schema map, and the client has no legitimate need for
     * it. The message goes to the log, where it belongs.
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    ResponseEntity<Map<String, Object>> onDataIntegrity(DataIntegrityViolationException ex) {
        log.warn("Data integrity violation on {} {} requestId={}",
                RequestContext.method(), RequestContext.endpoint(), requestId(), ex);
        return respond(HttpStatus.CONFLICT, "conflict");
    }

    /**
     * Anything unanticipated. Logged in full with the request id, returned as a
     * bare 500 -- which is the honest code here: the client is not at fault and
     * the platform is not returning a usable answer.
     */
    @ExceptionHandler(Exception.class)
    ResponseEntity<Map<String, Object>> onUnexpected(Exception ex) {
        log.error("Unhandled exception on {} {} requestId={}",
                RequestContext.method(), RequestContext.endpoint(), requestId(), ex);
        return respond(HttpStatus.INTERNAL_SERVER_ERROR, "internal_error");
    }

    private ResponseEntity<Map<String, Object>> respond(HttpStatus status, String code) {
        return respond(status, code, null, null);
    }

    private ResponseEntity<Map<String, Object>> respond(HttpStatus status, String code, String message) {
        return respond(status, code, message, null);
    }

    private ResponseEntity<Map<String, Object>> respond(
            HttpStatus status, String code, String message, Map<String, String> fieldErrors) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        if (message != null) {
            body.put("message", message);
        }
        if (fieldErrors != null) {
            body.put("fieldErrors", fieldErrors);
        }
        return ResponseEntity.status(status).body(body);
    }

    private static UUID requestId() {
        return RequestContext.requestId().orElse(null);
    }

    private static PlatformUser currentUserOrNull() {
        var authentication = org.springframework.security.core.context.SecurityContextHolder
                .getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof PlatformUser user)) {
            return null;
        }
        return user;
    }
}
