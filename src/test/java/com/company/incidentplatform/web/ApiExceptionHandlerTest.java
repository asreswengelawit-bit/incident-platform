package com.company.incidentplatform.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.company.incidentplatform.audit.AuditService;
import com.company.incidentplatform.config.PlatformSecurityProperties;
import com.company.incidentplatform.error.ConflictException;
import com.company.incidentplatform.error.EvidenceRejectedException;
import com.company.incidentplatform.error.LastAdministratorException;
import com.company.incidentplatform.error.ResourceNotFoundException;
import com.company.incidentplatform.incident.InvalidStatusTransitionException;
import com.company.incidentplatform.incident.IncidentStatus;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * Section 7.5 -- the error contract.
 *
 * <p>{@link ApiExceptionHandler} is the only place an exception becomes an HTTP
 * response, so these tests are about two properties: the status a refusal gets,
 * and what the body is allowed to contain.
 *
 * <p><strong>The property that matters most</strong> is that a refusal is
 * distinguishable from a failure. {@code 500 internal_error} means "the platform
 * broke"; every other code here means "the platform worked and is telling you no".
 * Conflating the two sends the reader of the log, the on-call, and the client to
 * entirely the wrong place -- and for the evidence path that is the difference
 * between "7.6 quarantined this file and recorded it as an IOC, as designed" and
 * "the evidence subsystem is broken".
 */
@DisplayName("7.5 ApiExceptionHandler error contract")
class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler =
            new ApiExceptionHandler(mock(AuditService.class), mock(PlatformSecurityProperties.class));

    @SuppressWarnings("unchecked")
    private static Map<String, Object> body(ResponseEntity<Map<String, Object>> response) {
        assertThat(response.getBody()).as("every error response carries a body").isNotNull();
        return response.getBody();
    }

    @Nested
    @DisplayName("7.6 each evidence refusal gets its own status, not a 500")
    class EvidenceRefusals {

        @ParameterizedTest(name = "{0} -> {1} {2}")
        @CsvSource({
                "UNSUPPORTED_TYPE,    415, unsupported_media_type",
                "TOO_LARGE,           413, payload_too_large",
                "NOT_DOWNLOADABLE,    409, evidence_not_downloadable",
                "INTEGRITY_FAILURE,   409, evidence_integrity_failure"
        })
        @DisplayName("the four Kinds map to the statuses their javadoc documents")
        void kindsMapToDocumentedStatuses(
                EvidenceRejectedException.Kind kind, int expectedStatus, String expectedCode) {
            ResponseEntity<Map<String, Object>> response = handler.onEvidenceRejected(
                    new EvidenceRejectedException(kind, "refused"));

            assertThat(response.getStatusCode().value()).isEqualTo(expectedStatus);
            assertThat(body(response)).containsEntry("error", expectedCode);
        }

        @Test
        @DisplayName("no evidence refusal is reported as an internal error")
        void noEvidenceRefusalIsA500() {
            for (EvidenceRejectedException.Kind kind : EvidenceRejectedException.Kind.values()) {
                ResponseEntity<Map<String, Object>> response =
                        handler.onEvidenceRejected(new EvidenceRejectedException(kind, "refused"));

                assertThat(response.getStatusCode().is5xxServerError())
                        .as("Kind %s is a caller-facing refusal, not a platform failure. A 500 here "
                                + "tells the on-call the evidence subsystem is down when 7.6 merely "
                                + "did its job.", kind)
                        .isFalse();
            }
        }

        @Test
        @DisplayName("the upload limit reports 413 on both paths that can hit it")
        void sizeLimitIsConsistentAcrossPaths() {
            // FR-1.2's limit can be reached two ways: the application-level check in
            // EvidenceService, and the container's own multipart limit. Both mean the
            // same thing to the client, so both have to answer 413 -- a client cannot
            // act on "too large" if one path says 413 and the other says 500.
            ResponseEntity<Map<String, Object>> applicationPath = handler.onEvidenceRejected(
                    new EvidenceRejectedException(
                            EvidenceRejectedException.Kind.TOO_LARGE, "too large"));
            ResponseEntity<Map<String, Object>> containerPath =
                    handler.onUploadTooLarge(new org.springframework.web.multipart.MaxUploadSizeExceededException(0L));

            assertThat(applicationPath.getStatusCode())
                    .as("FR-1.2's size limit must not produce two different answers")
                    .isEqualTo(containerPath.getStatusCode());
            assertThat(body(applicationPath)).containsEntry("error", body(containerPath).get("error"));
        }

        @Test
        @DisplayName("a refused upload still explains itself to the caller")
        void refusalCarriesAnActionableMessage() {
            ResponseEntity<Map<String, Object>> response = handler.onEvidenceRejected(
                    new EvidenceRejectedException(
                            EvidenceRejectedException.Kind.UNSUPPORTED_TYPE,
                            "Content type application/x-msdownload is not accepted for this category."));

            assertThat(body(response))
                    .as("EvidenceRejectedException documents its messages as composed in-application "
                            + "from policy reasoning, so returning them reveals nothing internal and "
                            + "tells the reporter what to change")
                    .containsEntry("message",
                            "Content type application/x-msdownload is not accepted for this category.");
        }

        @Test
        @DisplayName("an integrity failure reveals nothing beyond the fact")
        void integrityFailureIsTerse() {
            ResponseEntity<Map<String, Object>> response = handler.onEvidenceRejected(
                    new EvidenceRejectedException(
                            EvidenceRejectedException.Kind.INTEGRITY_FAILURE,
                            "Evidence failed its integrity check and was not served."));

            Map<String, Object> payload = body(response);
            assertThat(payload).containsEntry("error", "evidence_integrity_failure");
            assertThat(payload.get("message").toString())
                    .as("A chain-of-custody failure (Section 4 Integrity) must not disclose the "
                            + "expected or actual hash, the storage path, or anything a client could "
                            + "replay")
                    .doesNotContain("sha256", "/", "hash")
                    .isEqualTo("Evidence failed its integrity check and was not served.");
        }
    }

    @Nested
    @DisplayName("7.5 refusals and failures stay distinguishable")
    class RefusalVersusFailure {

        @Test
        @DisplayName("an unlisted status transition is 422, not 400")
        void invalidTransitionIsUnprocessable() {
            ResponseEntity<Map<String, Object>> response = handler.onInvalidTransition(
                    new InvalidStatusTransitionException(
                            IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING, "not permitted"));

            assertThat(response.getStatusCode())
                    .as("8.2 rejects an unlisted pair, and the request itself was well-formed -- 400 "
                            + "would blame the caller's syntax for a lifecycle refusal")
                    .isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
            assertThat(body(response)).containsEntry("error", "transition_not_permitted");
        }

        @Test
        @DisplayName("a lost optimistic-lock race is 409 with guidance")
        void conflictExplainsTheLostUpdate() {
            ResponseEntity<Map<String, Object>> response =
                    handler.onConflict(new ConflictException("version mismatch"));

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
            assertThat(body(response))
                    .as("7.10 explicitly requires a clear 'this incident changed, please refresh' "
                            + "response; a bare code leaves the Analyst unable to tell a lost edit "
                            + "from a rejected one")
                    .containsEntry("message",
                            "This record changed while you were editing it. Reload it and reapply "
                                    + "your change.");
        }

        @Test
        @DisplayName("a missing resource is 404 with no detail")
        void notFoundLeaksNothing() {
            ResponseEntity<Map<String, Object>> response =
                    handler.onNotFound(new ResourceNotFoundException("incident",
                            java.util.UUID.randomUUID()));

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
            assertThat(body(response))
                    .as("7.5: no internal detail in the body")
                    .doesNotContainKey("message");
        }

        @Test
        @DisplayName("a database constraint violation is 409 with no constraint name")
        void dataIntegrityDoesNotExposeSchema() {
            ResponseEntity<Map<String, Object>> response = handler.onDataIntegrity(
                    new DataIntegrityViolationException(
                            "violates foreign key constraint \"fk_incident_assignee\""));

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
            assertThat(body(response).toString())
                    .as("A constraint name is a schema map, and the client has no legitimate need "
                            + "for it")
                    .doesNotContain("fk_incident_assignee", "foreign key");
        }

        @Test
        @DisplayName("only a genuinely unhandled exception is a 500")
        void unhandledIsTheOnlyServerError() {
            assertThat(handler.onUnexpected(new IllegalStateException("connection pool exhausted"))
                    .getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(body(handler.onUnexpected(new IllegalStateException("boom"))))
                    .as("7.5: a stack trace or message from an unexpected failure goes to the log, "
                            + "never to the client")
                    .containsOnlyKeys("error");
        }
    }

    @Nested
    @DisplayName("FR-6.1 the last-administrator refusal is not a version conflict")
    class LastAdministratorRefusal {

        @Test
        @DisplayName("it is 409 with its own code and a message naming the recovery step")
        void hasItsOwnCodeAndMessage() {
            ResponseEntity<Map<String, Object>> response = handler.onLastAdministrator(
                    new LastAdministratorException("revoke can_manage_users from SECURITY_ADMIN"));

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
            assertThat(body(response))
                    .containsEntry("error", "last_administrator")
                    .satisfies(payload -> assertThat(payload.get("message").toString())
                            .contains("Grant can_manage_users to another administrator first"));
        }

        @Test
        @DisplayName("its body is distinguishable from the version-conflict body")
        void notConfusableWithAVersionConflict() {
            // The whole point of a separate code and message: a client that retries on
            // the generic conflict body will retry forever and never recover, because
            // the identical request fails identically every time. A client that can
            // tell the two apart knows to grant the capability to somebody else first.
            Map<String, Object> invariant = body(
                    handler.onLastAdministrator(new LastAdministratorException("disable this account")));
            Map<String, Object> versionConflict = body(
                    handler.onConflict(new ConflictException("version mismatch")));

            assertThat(invariant.get("error"))
                    .as("a client branching on the error code must not see the generic conflict code")
                    .isNotEqualTo(versionConflict.get("error"));
            assertThat(invariant.get("message").toString())
                    .as("nor may it be handed 'reload it and reapply your change', which cannot help here")
                    .isNotEqualTo(versionConflict.get("message"))
                    .doesNotContain("Reload it and reapply");
        }

        @Test
        @DisplayName("it is not a ConflictException, so the generic handler cannot catch it")
        void keptOutOfTheConflictHierarchy() {
            // Extending ConflictException would be the tidier-looking choice and would
            // leave the misleading body one annotation reordering away. The types are
            // kept apart deliberately; this guards against a later "simplification".
            assertThat(ConflictException.class.isAssignableFrom(LastAdministratorException.class))
                    .as("the generic 409 path returns a body that tells the caller to reload and "
                            + "reapply, which is exactly wrong for a refusal that never becomes valid")
                    .isFalse();
        }

        @Test
        @DisplayName("it is a refusal, not a platform failure")
        void neverA500() {
            assertThat(handler.onLastAdministrator(new LastAdministratorException("disable this account"))
                            .getStatusCode().is5xxServerError())
                    .as("a 500 here would tell on-call the admin subsystem is broken, when the "
                            + "invariant simply did its job")
                    .isFalse();
        }
    }

    @Nested
    @DisplayName("7.5 client errors do not echo what was submitted")
    class NoEchoOfSubmittedValues {

        @Test
        @DisplayName("an unparseable body does not reflect the offending token")
        void malformedBodyIsNotEchoed() {
            ResponseEntity<Map<String, Object>> response = handler.onUnreadableBody(
                    new org.springframework.http.converter.HttpMessageNotReadableException(
                            "JSON parse error: unexpected token 'secret-value-here'"));

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(body(response).toString())
                    .as("The parser's message names the offending JSON path and sometimes the token")
                    .doesNotContain("secret-value-here");
        }

        @Test
        @DisplayName("a library-thrown IllegalArgumentException subclass is not reflected verbatim")
        void libraryExceptionsAreNotReflected() {
            ResponseEntity<Map<String, Object>> response =
                    handler.onIllegalArgument(new LibraryDerivedArgumentException(
                            "connection string jdbc:postgresql://db:5432/prod rejected"));

            assertThat(body(response).toString())
                    .as("The exception TYPE decides, not the message: anything that is not exactly "
                            + "IllegalArgumentException is treated as internal detail, because a "
                            + "library subclass can carry a connection string or a file path")
                    .doesNotContain("jdbc:postgresql", "5432");
            assertThat(body(response)).doesNotContainKey("message");
        }

        /** A subclass, not IllegalArgumentException itself: that is the realistic library case. */
        private static final class LibraryDerivedArgumentException extends IllegalArgumentException {
            LibraryDerivedArgumentException(String message) {
                super(message);
            }
        }

        @Test
        @DisplayName("our own validation message is reflected, because it is about the caller's request")
        void ownValidationIsReflected() {
            ResponseEntity<Map<String, Object>> response =
                    handler.onIllegalArgument(new IllegalArgumentException(
                            "Invalid sort field 'password'. Allowed sort fields: reportedAt"));

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(body(response)).containsEntry("error", "invalid_request");
        }
    }
}
