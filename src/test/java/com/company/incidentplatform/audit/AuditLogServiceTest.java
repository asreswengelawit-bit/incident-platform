package com.company.incidentplatform.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.company.incidentplatform.TestFixtures;
import com.company.incidentplatform.authorization.AuthorizationDeniedException;
import com.company.incidentplatform.incident.PagedResponse;
import com.company.incidentplatform.security.AuthorizationCheckType;
import com.company.incidentplatform.security.DeniedReason;
import com.company.incidentplatform.security.PlatformUser;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Section 7.11 / 7.2 function level / FR-1.6 -- the audit-log read path.
 *
 * <p>Three things are under test and they are the three ways this endpoint could
 * quietly fail its purpose:
 *
 * <ol>
 *   <li><b>BFLA</b> -- a valid token without {@code can_view_audit_log} must be
 *       refused, and refused as a denial so 7.11 records the attempt. Refusing with
 *       a bare 500 would lose exactly the event 7.12 alerts on.</li>
 *   <li><b>Unaudited oversight</b> -- the read must itself be recorded. A log only
 *       Admin and Auditor can read, read without a trace, gives an attacker the
 *       most sensitive table in the system with no evidence anyone looked.</li>
 *   <li><b>FR-1.6</b> -- an audit row for creating an anonymous report carries the
 *       reporter's {@code actor_id}, so returning it unredacted would answer "who
 *       reported this anonymously?" with no identity-access entry. That is the
 *       failure the requirement's separately-audited clause is written against.</li>
 * </ol>
 *
 * <p>The repository is mocked, so these tests assert the service's decisions and
 * not the SQL. The SQL's filter binding and the {@code verify_audit_log_chain}
 * round-trip are covered by {@code AuditServiceIntegrationTest}, which runs against
 * a real PostgreSQL.
 */
class AuditLogServiceTest {

    private static final UUID ADMIN = UUID.fromString("00000000-0000-0000-0000-0000000000f6");
    private static final UUID AUDITOR = UUID.fromString("00000000-0000-0000-0000-0000000000a7");
    private static final UUID ANALYST = UUID.fromString("00000000-0000-0000-0000-0000000000b2");
    private static final UUID WHISTLEBLOWER = UUID.fromString("00000000-0000-0000-0000-0000000000a1");
    private static final UUID INCIDENT = UUID.fromString("00000000-0000-0000-0000-0000000000c1");
    private static final UUID REQUEST_ID = UUID.fromString("00000000-0000-0000-0000-0000000000e1");

    private AuditLogQueryRepository repository;
    private AuditService auditService;
    private AuditLogService service;

    @BeforeEach
    void setUp() {
        repository = mock(AuditLogQueryRepository.class);
        auditService = mock(AuditService.class);
        service = new AuditLogService(repository, auditService);
        installRequestContext();
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    /**
     * Puts a request in scope so the audit records built by the service carry a real
     * endpoint, method, request id, and client address.
     *
     * <p>Worth doing rather than matching those arguments loosely: {@code
     * RequestContext} degrades to null outside a web call by design, so a test that
     * stubbed them away would pass even if the service stopped recording the endpoint
     * altogether. 7.11 requires the endpoint on every entry, and the denial check
     * {@code ck_audit_log_denial_endpoint} depends on it.
     */
    private void installRequestContext() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/audit-logs");
        request.setRequestURI("/api/v1/audit-logs");
        request.setRemoteAddr("10.0.0.9");
        // The pattern, not the concrete URI -- which is what makes the column groupable.
        request.setAttribute(
                org.springframework.web.servlet.HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE,
                "/api/v1/audit-logs");
        request.setAttribute(RequestContext.REQUEST_ID_ATTRIBUTE, REQUEST_ID);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    private static AuditLogQuery noFilters() {
        return new AuditLogQuery(null, null, null, null, null, null, null, null);
    }

    private static AuditLogEntry entry(UUID id, UUID actorId, String entityType, UUID entityId) {
        return new AuditLogEntry(
                id, Instant.parse("2026-03-01T10:00:00Z"), actorId, "REPORTER", "kc-" + actorId,
                entityType, entityId, "incident.create", "ALLOWED", null, null,
                "/api/v1/incidents", "POST", UUID.randomUUID(),
                "FUNCTION_LEVEL", "capability.can_create_incident", "10.0.0.1",
                null, "{\"anonymous\":true}", false, "aa", "bb");
    }

    private void givenPage(List<AuditLogEntry> entries) {
        when(repository.find(any(), any(), any(), anyInt(), anyInt()))
                .thenReturn(new AuditLogQueryRepository.Page(entries, entries.size()));
        when(repository.protectedReporterIds(any())).thenReturn(Set.of());
    }

    private static int anyInt() {
        return org.mockito.ArgumentMatchers.anyInt();
    }

    @Nested
    @DisplayName("7.2 function level: only can_view_audit_log holders reach the table")
    class FunctionLevel {

        @Test
        @DisplayName("an Admin with the capability is served")
        void allowsAdmin() {
            givenPage(List.of(entry(UUID.randomUUID(), ANALYST, "incident", INCIDENT)));

            PagedResponse<AuditLogViews.AuditEntryView> page =
                    service.query(noFilters(), 0, 25, null, null, TestFixtures.admin(ADMIN));

            assertThat(page.content()).hasSize(1);
        }

        @Test
        @DisplayName("an Auditor with the capability is served -- 7.3's independent reviewer")
        void allowsAuditor() {
            givenPage(List.of(entry(UUID.randomUUID(), ANALYST, "incident", INCIDENT)));

            PagedResponse<AuditLogViews.AuditEntryView> page =
                    service.query(noFilters(), 0, 25, null, null, TestFixtures.auditor(AUDITOR));

            assertThat(page.content()).hasSize(1);
        }

        @Test
        @DisplayName("an Analyst is denied, and the refusal is a 7.11 function-level denial")
        void deniesAnalyst() {
            assertThatThrownBy(() ->
                    service.query(noFilters(), 0, 25, null, null, TestFixtures.analyst(ANALYST, "SECURITY")))
                    .isInstanceOf(AuthorizationDeniedException.class)
                    .satisfies(thrown -> {
                        AuthorizationDeniedException denied = (AuthorizationDeniedException) thrown;
                        assertThat(denied.decision().checkType())
                                .isEqualTo(AuthorizationCheckType.FUNCTION_LEVEL);
                        assertThat(denied.decision().deniedReason())
                                .isEqualTo(DeniedReason.INSUFFICIENT_ROLE);
                        assertThat(denied.decision().rule())
                                .isEqualTo("capability.can_view_audit_log");
                    });
        }

        @Test
        @DisplayName("a service account is denied -- ingestion must not become a read channel")
        void deniesServiceAccount() {
            // V12 gives SERVICE_ACCOUNT can_create_incident but no read capability,
            // precisely so ingestion cannot be used to read the audit trail back.
            assertThatThrownBy(() -> service.query(noFilters(), 0, 25, null, null,
                    TestFixtures.serviceAccount(ANALYST)))
                    .isInstanceOf(AuthorizationDeniedException.class);
        }

        @Test
        @DisplayName("a reporter is denied")
        void deniesReporter() {
            assertThatThrownBy(() -> service.query(noFilters(), 0, 25, null, null,
                    TestFixtures.reporter(ANALYST, "FINANCE")))
                    .isInstanceOf(AuthorizationDeniedException.class);
        }

        @Test
        @DisplayName("a denial happens before the table is touched")
        void deniesBeforeQuerying() {
            // Otherwise the refusal's timing and any error would leak whether the
            // log exists and how large it is.
            givenPage(List.of(entry(UUID.randomUUID(), ANALYST, "incident", INCIDENT)));

            service.query(noFilters(), 0, 25, null, null, TestFixtures.admin(ADMIN));

            assertThatThrownBy(() ->
                    service.query(noFilters(), 0, 25, null, null, TestFixtures.analyst(ANALYST, "SECURITY")))
                    .isInstanceOf(AuthorizationDeniedException.class);

            // Exactly one query: the Admin's. The denied call never reached it.
            verify(repository, times(1)).find(any(), any(), any(), anyInt(), anyInt());
        }
    }

    @Nested
    @DisplayName("7.11: the read is itself audited")
    class ReadIsAudited {

        @Test
        @DisplayName("a successful query writes an audit_log.query entry naming the filters")
        void auditsTheRead() {
            UUID actor = ANALYST;
            givenPage(List.of(entry(UUID.randomUUID(), actor, "incident", INCIDENT)));
            AuditLogQuery query =
                    new AuditLogQuery("ALLOWED", "incident.create", "incident", INCIDENT, null, null, null, null);
            PlatformUser admin = TestFixtures.admin(ADMIN);

            service.query(query, 0, 25, "timestamp", "DESC", admin);

            ArgumentCaptor<String> afterValue = ArgumentCaptor.forClass(String.class);
            verify(auditService).recordChange(
                    eq(admin), eq("audit_log"), eq(null),
                    eq(AuditLogService.ACTION_AUDIT_QUERY),
                    // The pattern, not the concrete URI, so entries group by endpoint.
                    eq("/api/v1/audit-logs"),
                    eq("GET"), eq(REQUEST_ID), eq("10.0.0.9"),
                    eq(AuthorizationCheckType.FUNCTION_LEVEL),
                    eq("capability.can_view_audit_log"),
                    eq(null), afterValue.capture(), eq(false));

            // The filters are what distinguish a targeted single-actor review from a
            // sweep of the whole trail -- the difference 7.12's scraping alert needs.
            assertThat(afterValue.getValue())
                    .contains("\"action\":\"incident.create\"")
                    .contains("\"entity_type\":\"incident\"")
                    .contains("\"sort_direction\":\"DESC\"")
                    .contains("\"returned\":1");
        }

        @Test
        @DisplayName("a filter value cannot break out of the JSON it is recorded in")
        void escapesFilterValuesInAudit() {
            // The query itself is parameterized, but the filters are echoed into a
            // jsonb column -- so an unescaped quote would inject a key into the
            // audit row. A second injection surface, in the one place least likely
            // to be reviewed as code.
            givenPage(List.of(entry(UUID.randomUUID(), ANALYST, "incident", INCIDENT)));
            AuditLogQuery hostile = new AuditLogQuery(
                    null, "x\",\"injected\":\"yes", null, null, null, null, null, null);

            service.query(hostile, 0, 25, null, null, TestFixtures.admin(ADMIN));

            ArgumentCaptor<String> afterValue = ArgumentCaptor.forClass(String.class);
            verify(auditService).recordChange(
                    any(), anyString(), any(), anyString(), any(), anyString(), any(), any(),
                    any(), anyString(), any(), afterValue.capture(), anyBoolean());

            assertThat(afterValue.getValue())
                    .contains("\\\"injected\\\":\\\"yes")
                    .doesNotContain("\"injected\":\"yes");
        }

        @Test
        @DisplayName("a read is audited even when nothing matched")
        void auditsEmptyResult() {
            // An empty page is still a read. 7.12 needs "someone swept the log and
            // found nothing" to be visible; skipping the entry on zero rows would
            // make the quietest queries the only unrecorded ones.
            givenPage(List.of());

            service.query(noFilters(), 0, 25, null, null, TestFixtures.admin(ADMIN));

            verify(auditService).recordChange(
                    any(), eq("audit_log"), eq(null), eq(AuditLogService.ACTION_AUDIT_QUERY),
                    any(), any(), any(), any(), any(), anyString(), any(), anyString(), anyBoolean());
        }

        @Test
        @DisplayName("a denied read does not also write an allowed-query entry")
        void denialIsNotDoubleRecorded() {
            assertThatThrownBy(() ->
                    service.query(noFilters(), 0, 25, null, null, TestFixtures.analyst(ANALYST, "SECURITY")))
                    .isInstanceOf(AuthorizationDeniedException.class);

            // The denial entry is written by the AccessDeniedHandler, not here. If
            // this also wrote a query record the log would claim the caller saw a
            // page of entries they were never given.
            verify(auditService, never()).recordChange(
                    any(), anyString(), any(), anyString(), any(), anyString(), any(), any(),
                    any(), anyString(), any(), anyString(), anyBoolean());
        }
    }

    @Nested
    @DisplayName("FR-1.6: an anonymous reporter's identity is withheld by default")
    class AnonymousReporterRedaction {

        @Test
        @DisplayName("the reporter's actor_id is suppressed and marked, not silently dropped")
        void suppressesAnonymousReporterActor() {
            givenPage(List.of(entry(UUID.randomUUID(), WHISTLEBLOWER, "incident", INCIDENT)));
            when(repository.protectedReporterIds(any())).thenReturn(Set.of(WHISTLEBLOWER));

            PagedResponse<AuditLogViews.AuditEntryView> page =
                    service.query(noFilters(), 0, 25, null, null, TestFixtures.auditor(AUDITOR));

            AuditLogViews.AuditEntryView view = page.content().get(0);
            assertThat(view.actorId()).isNull();
            assertThat(view.actorIdWithheld()).isTrue();
            // Marked rather than blank, so a reviewer can tell a withheld value from
            // a system event that genuinely had no actor.
            assertThat(view.actorIdLabel()).isEqualTo(AuditLogViews.WITHHELD_ACTOR_LABEL);
        }

        @Test
        @DisplayName("no FR-1.6 entry is written when nothing was disclosed")
        void writesNoIdentityEntryWhenWithheld() {
            // A withheld value is not a denial -- the caller received a redacted view
            // like everyone else. Recording it as identity access would both overstate
            // access that never happened and pollute 7.12's signal.
            givenPage(List.of(entry(UUID.randomUUID(), WHISTLEBLOWER, "incident", INCIDENT)));
            when(repository.protectedReporterIds(any())).thenReturn(Set.of(WHISTLEBLOWER));

            service.query(noFilters(), 0, 25, null, null, TestFixtures.auditor(AUDITOR));

            verify(auditService, never()).recordChange(
                    any(), eq("incident"), any(), eq(AuditLogService.ACTION_IDENTITY_VIEWED),
                    any(), any(), any(), any(), any(), anyString(), any(), anyString(), anyBoolean());
        }

        @Test
        @DisplayName("a non-reporter actor on the same incident is NOT suppressed")
        void doesNotSuppressOtherActors() {
            // Over-redacting here would gut the audit trail exactly where it matters:
            // the Analyst who triaged an anonymous report is not the protected
            // identity, and hiding them destroys the record of who handled it.
            UUID analyst = ANALYST;
            givenPage(List.of(entry(UUID.randomUUID(), analyst, "incident", INCIDENT)));
            when(repository.protectedReporterIds(any())).thenReturn(Set.of(WHISTLEBLOWER));

            AuditLogViews.AuditEntryView view = service
                    .query(noFilters(), 0, 25, null, null, TestFixtures.auditor(AUDITOR))
                    .content().get(0);

            assertThat(view.actorId()).isEqualTo(analyst);
            assertThat(view.actorIdWithheld()).isFalse();
        }

        @Test
        @DisplayName("a caller holding can_view_reporter_identity sees the id, and it is audited")
        void disclosesToGrantedCaller() {
            givenPage(List.of(entry(UUID.randomUUID(), WHISTLEBLOWER, "incident", INCIDENT)));
            when(repository.protectedReporterIds(any())).thenReturn(Set.of(WHISTLEBLOWER));
            when(repository.anonymousIncidentIdsReportedBy(WHISTLEBLOWER))
                    .thenReturn(Set.of(INCIDENT));
            PlatformUser granted = TestFixtures.adminWithAuditLogAndReporterIdentity(ADMIN);

            AuditLogViews.AuditEntryView view = service
                    .query(noFilters(), 0, 25, null, null, granted).content().get(0);

            assertThat(view.actorId()).isEqualTo(WHISTLEBLOWER);
            assertThat(view.actorIdWithheld()).isFalse();

            // The separately-audited action FR-1.6 requires, attributed to the
            // incident whose identity was exposed.
            ArgumentCaptor<String> afterValue = ArgumentCaptor.forClass(String.class);
            verify(auditService).recordChange(
                    eq(granted), eq("incident"), eq(INCIDENT),
                    eq(AuditLogService.ACTION_IDENTITY_VIEWED), any(), eq("GET"), any(), any(),
                    eq(AuthorizationCheckType.PROPERTY_LEVEL),
                    eq("capability.can_view_reporter_identity"),
                    eq(null), afterValue.capture(), eq(false));
            assertThat(afterValue.getValue()).contains("FR-1.6").contains(WHISTLEBLOWER.toString());
        }

        @Test
        @DisplayName("the identity entry is grouped per incident, not per row")
        void groupsIdentityEntriesPerIncident() {
            // A reviewer paging one reporter's history would otherwise emit a burst
            // of near-identical entries that buries the signal 7.12 reads.
            givenPage(List.of(
                    entry(UUID.randomUUID(), WHISTLEBLOWER, "incident", INCIDENT),
                    entry(UUID.randomUUID(), WHISTLEBLOWER, "incident", INCIDENT),
                    entry(UUID.randomUUID(), WHISTLEBLOWER, "incident", INCIDENT)));
            when(repository.protectedReporterIds(any())).thenReturn(Set.of(WHISTLEBLOWER));
            when(repository.anonymousIncidentIdsReportedBy(WHISTLEBLOWER))
                    .thenReturn(Set.of(INCIDENT));

            service.query(noFilters(), 0, 25, null, null,
                    TestFixtures.adminWithAuditLogAndReporterIdentity(ADMIN));

            verify(auditService, times(1)).recordChange(
                    any(), eq("incident"), eq(INCIDENT),
                    eq(AuditLogService.ACTION_IDENTITY_VIEWED), any(), any(), any(), any(),
                    any(), anyString(), any(), anyString(), anyBoolean());
        }

        @Test
        @DisplayName("the disclosure count is recorded in the query entry too")
        void reportsDisclosuresOnTheQueryEntry() {
            // So an auditor can see from the read record alone that protected
            // identities were surfaced, without joining to the FR-1.6 entry.
            givenPage(List.of(entry(UUID.randomUUID(), WHISTLEBLOWER, "incident", INCIDENT)));
            when(repository.protectedReporterIds(any())).thenReturn(Set.of(WHISTLEBLOWER));
            when(repository.anonymousIncidentIdsReportedBy(WHISTLEBLOWER)).thenReturn(Set.of(INCIDENT));

            service.query(noFilters(), 0, 25, null, null,
                    TestFixtures.adminWithAuditLogAndReporterIdentity(ADMIN));

            ArgumentCaptor<String> afterValue = ArgumentCaptor.forClass(String.class);
            verify(auditService).recordChange(
                    any(), eq("audit_log"), eq(null), eq(AuditLogService.ACTION_AUDIT_QUERY),
                    any(), any(), any(), any(), any(), anyString(), any(), afterValue.capture(), anyBoolean());

            assertThat(afterValue.getValue()).contains("\"anonymous_identities_disclosed\":1");
        }

        @Test
        @DisplayName("an Admin without the explicit grant gets no identity -- V12's default")
        void defaultDeploymentDisclosesNothing() {
            // V12 deliberately withdraws can_view_reporter_identity from SECURITY_ADMIN
            // and Section 2's decision is that an Admin grants it to themself as an
            // audited act. So a fresh deployment discloses no anonymous reporter
            // through this endpoint at all, for any role.
            givenPage(List.of(entry(UUID.randomUUID(), WHISTLEBLOWER, "incident", INCIDENT)));
            when(repository.protectedReporterIds(any())).thenReturn(Set.of(WHISTLEBLOWER));

            AuditLogViews.AuditEntryView view = service
                    .query(noFilters(), 0, 25, null, null, TestFixtures.admin(ADMIN))
                    .content().get(0);

            assertThat(view.actorId()).isNull();
            assertThat(view.actorIdWithheld()).isTrue();
        }

        @Test
        @DisplayName("the protected-id query is skipped entirely for a page with no actors")
        void skipsProtectedIdLookupForEmptyPage() {
            givenPage(List.of());

            service.query(noFilters(), 0, 25, null, null, TestFixtures.auditor(AUDITOR));

            verify(repository, never()).protectedReporterIds(any());
        }
    }

    @Nested
    @DisplayName("9.1 pagination bounds reach the query")
    class Pagination {

        @Test
        @DisplayName("an oversized page size is clamped before it reaches the repository")
        void clampsPageSize() {
            givenPage(List.of());

            service.query(noFilters(), 0, 100_000, null, null, TestFixtures.admin(ADMIN));

            verify(repository).find(any(), eq("timestamp"),
                    eq(AuditLogQuery.SortDirection.DESC), eq(0), eq(AuditLogQuery.MAX_PAGE_SIZE));
        }

        @Test
        @DisplayName("a negative page becomes 0 rather than a negative OFFSET")
        void clampsNegativePage() {
            givenPage(List.of());

            service.query(noFilters(), -3, 25, null, null, TestFixtures.admin(ADMIN));

            verify(repository).find(any(), any(), any(), eq(0), eq(25));
        }

        @Test
        @DisplayName("an unlisted sort field is refused and never reaches the repository")
        void rejectsUnlistedSort() {
            givenPage(List.of());

            assertThatThrownBy(() -> service.query(
                    noFilters(), 0, 25, "actor_role", null, TestFixtures.admin(ADMIN)))
                    .isInstanceOf(IllegalArgumentException.class);

            verify(repository, never()).find(any(), any(), any(), anyInt(), anyInt());
        }

        @Test
        @DisplayName("the response reports the total and page count from the same predicate")
        void reportsTotals() {
            when(repository.find(any(), any(), any(), anyInt(), anyInt()))
                    .thenReturn(new AuditLogQueryRepository.Page(
                            List.of(entry(UUID.randomUUID(), ANALYST, "incident", INCIDENT)), 57));
            when(repository.protectedReporterIds(any())).thenReturn(Set.of());

            PagedResponse<AuditLogViews.AuditEntryView> page =
                    service.query(noFilters(), 1, 25, null, null, TestFixtures.admin(ADMIN));

            assertThat(page.totalElements()).isEqualTo(57);
            assertThat(page.totalPages()).isEqualTo(3);
            assertThat(page.last()).isFalse();
            assertThat(page.page()).isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("7.11 chain verification")
    class ChainVerification {

        private final Instant from = Instant.parse("2026-03-01T00:00:00Z");
        private final Instant to = Instant.parse("2026-03-08T00:00:00Z");

        @Test
        @DisplayName("zero problems means the chain is intact, and the check is recorded")
        void reportsIntact() {
            when(repository.verifyChain(from, to)).thenReturn(List.of());

            AuditLogViews.ChainVerificationView result =
                    service.verifyChain(from, to, TestFixtures.auditor(AUDITOR));

            assertThat(result.intact()).isTrue();
            assertThat(result.problemsFound()).isZero();
            // The check itself is a compliance event: who verified, over what
            // window, and the outcome.
            verify(auditService).recordChange(
                    any(), eq("audit_log"), eq(null), eq(AuditLogService.ACTION_CHAIN_VERIFY),
                    any(), any(), any(), any(), eq(AuthorizationCheckType.FUNCTION_LEVEL),
                    eq("capability.can_view_audit_log"), eq(null), anyString(), eq(false));
        }

        @Test
        @DisplayName("problems are returned individually, not collapsed to a boolean")
        void reportsProblems() {
            // 7.11 needs tamper detection to be actionable: an administrator has to
            // be able to see WHICH entries failed and how.
            when(repository.verifyChain(from, to)).thenReturn(List.of(
                    new AuditLogQueryRepository.ChainProblem(UUID.randomUUID(), from, "previous_hash mismatch"),
                    new AuditLogQueryRepository.ChainProblem(UUID.randomUUID(), from.plusSeconds(60), "chain gap")));

            AuditLogViews.ChainVerificationView result =
                    service.verifyChain(from, to, TestFixtures.auditor(AUDITOR));

            assertThat(result.intact()).isFalse();
            assertThat(result.problemsFound()).isEqualTo(2);
            assertThat(result.problems()).extracting(AuditLogQueryRepository.ChainProblem::problem)
                    .containsExactly("previous_hash mismatch", "chain gap");
        }

        @Test
        @DisplayName("the failure count is recorded so a pass and a fail are distinguishable")
        void recordsOutcome() {
            when(repository.verifyChain(from, to))
                    .thenReturn(List.of(new AuditLogQueryRepository.ChainProblem(
                            UUID.randomUUID(), from, "previous_hash mismatch")));

            service.verifyChain(from, to, TestFixtures.auditor(AUDITOR));

            ArgumentCaptor<String> afterValue = ArgumentCaptor.forClass(String.class);
            verify(auditService).recordChange(
                    any(), any(), any(), any(), any(), any(), any(), any(), any(), anyString(),
                    any(), afterValue.capture(), anyBoolean());

            assertThat(afterValue.getValue())
                    .contains("\"problems_found\":1")
                    .contains("\"intact\":false");
        }

        @Test
        @DisplayName("a caller without the capability cannot verify the chain")
        void deniesWithoutCapability() {
            assertThatThrownBy(() ->
                    service.verifyChain(from, to, TestFixtures.analyst(ANALYST, "SECURITY")))
                    .isInstanceOf(AuthorizationDeniedException.class);

            verify(repository, never()).verifyChain(any(), any());
        }

        @Test
        @DisplayName("a reversed window is refused")
        void rejectsReversedWindow() {
            assertThatThrownBy(() ->
                    service.verifyChain(to, from, TestFixtures.auditor(AUDITOR)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("strictly after");
        }

        @Test
        @DisplayName("an unbounded all-time window is refused -- it is a full-table hash")
        void rejectsUnboundedWindow() {
            // The function recomputes a digest per row, so "all history" driven by a
            // request parameter is a denial of service with a URL.
            assertThatThrownBy(() -> service.verifyChain(
                    Instant.parse("2000-01-01T00:00:00Z"), Instant.parse("2026-01-01T00:00:00Z"),
                    TestFixtures.auditor(AUDITOR)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not exceed");
        }

        @Test
        @DisplayName("an absent window defaults to a bounded recent range rather than all time")
        void defaultsToBoundedWindow() {
            when(repository.verifyChain(any(), any())).thenReturn(List.of());

            AuditLogViews.ChainVerificationView result = service.verifyChain(null, null, TestFixtures.auditor(AUDITOR));

            ArgumentCaptor<Instant> effectiveTo = ArgumentCaptor.forClass(Instant.class);
            verify(repository).verifyChain(any(), effectiveTo.capture());
            assertThat(java.time.Duration.between(result.from(), result.to()).toDays())
                    .isEqualTo(30);
        }
    }
}
