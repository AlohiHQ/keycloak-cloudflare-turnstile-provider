package com.zymlabs.keycloak.cloudflare.turnstileprovider;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for CloudflareTurnstileService.
 *
 * Note: These tests verify the service structure, token validation, and error handling.
 * Full HTTP response testing (success/failure JSON parsing, network errors, etc.) would
 * require either integration tests with actual Cloudflare API or refactoring the service
 * to accept an injectable HttpClient for mocking.
 *
 * Current tests focus on:
 * - Service construction and configuration
 * - Pre-HTTP validation (null/empty/whitespace tokens)
 * - RemoteIP parameter handling
 * - Resource cleanup (close method)
 * - Result object structure
 */
@DisplayName("Cloudflare Turnstile Service Tests")
class CloudflareTurnstileServiceTest {

    // ===== SERVICE CONSTRUCTION TESTS =====

    @Test
    @DisplayName("Should create service with default timeouts")
    void testServiceCreationDefaultTimeouts() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret");
        assertThat(service).isNotNull();
        service.close();
    }

    @Test
    @DisplayName("Should create service with custom timeouts")
    void testServiceCreationCustomTimeouts() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret", 10000, 10000);
        assertThat(service).isNotNull();
        service.close();
    }

    @Test
    @DisplayName("Should create service with zero timeouts")
    void testServiceCreationZeroTimeouts() {
        // Zero timeout means infinite wait - valid but not recommended
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret", 0, 0);
        assertThat(service).isNotNull();
        service.close();
    }

    @Test
    @DisplayName("Should create service with very small timeouts")
    void testServiceCreationSmallTimeouts() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret", 1, 1);
        assertThat(service).isNotNull();
        service.close();
    }

    @Test
    @DisplayName("Should create service with very large timeouts")
    void testServiceCreationLargeTimeouts() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret", 600000, 600000);
        assertThat(service).isNotNull();
        service.close();
    }

    // ===== TOKEN VALIDATION TESTS =====

    @Test
    @DisplayName("Should handle null token")
    void testNullToken() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret");
        CloudflareTurnstileService.TurnstileVerificationResult result = service.verify(null, "1.2.3.4", null);

        assertThat(result).isNotNull();
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes()).isEqualTo("missing-input-response");
        assertThat(result.getChallengeTs()).isNull();
        assertThat(result.getHostname()).isNull();
        assertThat(result.getRawResponse()).isNull();

        service.close();
    }

    @Test
    @DisplayName("Should handle empty token")
    void testEmptyToken() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret");
        CloudflareTurnstileService.TurnstileVerificationResult result = service.verify("", "1.2.3.4", null);

        assertThat(result).isNotNull();
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes()).isEqualTo("missing-input-response");

        service.close();
    }

    @Test
    @DisplayName("Should handle whitespace-only token")
    void testWhitespaceToken() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret");
        CloudflareTurnstileService.TurnstileVerificationResult result = service.verify("   ", "1.2.3.4", null);

        assertThat(result).isNotNull();
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes()).isEqualTo("missing-input-response");

        service.close();
    }

    @Test
    @DisplayName("Should handle token with only tabs and newlines")
    void testWhitespaceVariationsToken() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret");
        CloudflareTurnstileService.TurnstileVerificationResult result = service.verify("\t\n\r", "1.2.3.4", null);

        assertThat(result).isNotNull();
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes()).isEqualTo("missing-input-response");

        service.close();
    }

    // ===== REMOTE IP PARAMETER TESTS =====

    @Test
    @DisplayName("Should handle null remoteIp")
    void testNullRemoteIp() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret");
        // Null token to avoid HTTP call, we're just testing parameter handling
        CloudflareTurnstileService.TurnstileVerificationResult result = service.verify(null, null, null);

        assertThat(result).isNotNull();
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes()).isEqualTo("missing-input-response");

        service.close();
    }

    @Test
    @DisplayName("Should handle empty remoteIp")
    void testEmptyRemoteIp() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret");
        // Null token to avoid HTTP call, we're just testing parameter handling
        CloudflareTurnstileService.TurnstileVerificationResult result = service.verify(null, "", null);

        assertThat(result).isNotNull();
        assertThat(result.isSuccess()).isFalse();

        service.close();
    }

    @Test
    @DisplayName("Should handle whitespace remoteIp")
    void testWhitespaceRemoteIp() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret");
        // Null token to avoid HTTP call, we're just testing parameter handling
        CloudflareTurnstileService.TurnstileVerificationResult result = service.verify(null, "   ", null);

        assertThat(result).isNotNull();
        assertThat(result.isSuccess()).isFalse();

        service.close();
    }

    // ===== RESOURCE CLEANUP TESTS =====

    @Test
    @DisplayName("Close should be idempotent")
    void testCloseIdempotency() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret");

        // Should not throw when called multiple times
        service.close();
        service.close();
        service.close();
    }

    @Test
    @DisplayName("Verify can be called multiple times before close")
    void testMultipleVerifyCalls() {
        CloudflareTurnstileService service = new CloudflareTurnstileService("test-secret");

        // Multiple calls with null token (avoids HTTP calls)
        CloudflareTurnstileService.TurnstileVerificationResult result1 = service.verify(null, "1.2.3.4", null);
        CloudflareTurnstileService.TurnstileVerificationResult result2 = service.verify("", "1.2.3.4", null);
        CloudflareTurnstileService.TurnstileVerificationResult result3 = service.verify("   ", "1.2.3.4", null);

        assertThat(result1.isSuccess()).isFalse();
        assertThat(result2.isSuccess()).isFalse();
        assertThat(result3.isSuccess()).isFalse();

        service.close();
    }

    // ===== VERIFICATION RESULT TESTS =====

    @Test
    @DisplayName("TurnstileVerificationResult should have correct getters for success")
    void testVerificationResultSuccess() {
        CloudflareTurnstileService.TurnstileVerificationResult result =
                new CloudflareTurnstileService.TurnstileVerificationResult(
                        true,
                        null,
                        "2024-01-01T00:00:00Z",
                        "example.com",
                        "{\"success\":true}"
                );

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getErrorCodes()).isNull();
        assertThat(result.getChallengeTs()).isEqualTo("2024-01-01T00:00:00Z");
        assertThat(result.getHostname()).isEqualTo("example.com");
        assertThat(result.getRawResponse()).isEqualTo("{\"success\":true}");
    }

    @Test
    @DisplayName("TurnstileVerificationResult should have correct getters for failure")
    void testVerificationResultFailure() {
        CloudflareTurnstileService.TurnstileVerificationResult result =
                new CloudflareTurnstileService.TurnstileVerificationResult(
                        false,
                        "timeout-or-duplicate",
                        null,
                        null,
                        "{\"success\":false,\"error-codes\":[\"timeout-or-duplicate\"]}"
                );

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes()).isEqualTo("timeout-or-duplicate");
        assertThat(result.getChallengeTs()).isNull();
        assertThat(result.getHostname()).isNull();
        assertThat(result.getRawResponse()).contains("timeout-or-duplicate");
    }

    @Test
    @DisplayName("TurnstileVerificationResult should handle multiple error codes")
    void testVerificationResultMultipleErrors() {
        CloudflareTurnstileService.TurnstileVerificationResult result =
                new CloudflareTurnstileService.TurnstileVerificationResult(
                        false,
                        "timeout-or-duplicate,invalid-input-response",
                        null,
                        null,
                        "{\"success\":false,\"error-codes\":[\"timeout-or-duplicate\",\"invalid-input-response\"]}"
                );

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes()).contains("timeout-or-duplicate");
        assertThat(result.getErrorCodes()).contains("invalid-input-response");
        assertThat(result.getErrorCodes()).contains(",");
    }

    @Test
    @DisplayName("TurnstileVerificationResult should handle network error format")
    void testVerificationResultNetworkError() {
        CloudflareTurnstileService.TurnstileVerificationResult result =
                new CloudflareTurnstileService.TurnstileVerificationResult(
                        false,
                        "network-error",
                        null,
                        null,
                        "Error: Connection timeout"
                );

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes()).isEqualTo("network-error");
        assertThat(result.getRawResponse()).contains("Error:");
    }

    @Test
    @DisplayName("verify should throw, not report a failed check, when Cloudflare can't be reached")
    void verifyThrowsWhenCloudflareIsUnreachable() {
        // Nothing can connect within a millisecond: an outage as far as the service can tell
        try (CloudflareTurnstileService service = new CloudflareTurnstileService("secret", 1, 1)) {
            assertThatThrownBy(() -> service.verify("token", "1.2.3.4", null))
                    .isInstanceOf(CloudflareTurnstileService.UnavailableException.class);
        }
    }

    @Test
    @DisplayName("TurnstileVerificationResult toString should include all fields")
    void testVerificationResultToString() {
        CloudflareTurnstileService.TurnstileVerificationResult result =
                new CloudflareTurnstileService.TurnstileVerificationResult(
                        false,
                        "timeout-or-duplicate",
                        "2024-01-01T00:00:00Z",
                        "example.com",
                        "{\"success\":false}"
                );

        String str = result.toString();
        assertThat(str)
                .contains("success=false")
                .contains("timeout-or-duplicate")
                .contains("example.com");
    }

    @Test
    @DisplayName("TurnstileVerificationResult toString should handle null values")
    void testVerificationResultToStringNulls() {
        CloudflareTurnstileService.TurnstileVerificationResult result =
                new CloudflareTurnstileService.TurnstileVerificationResult(
                        true,
                        null,
                        null,
                        null,
                        null
                );

        String str = result.toString();
        assertThat(str).contains("success=true");
        // Should not throw NPE with null fields
    }

    // ===== SESSION BINDING (CDATA) TESTS =====

    private static final String ACCEPTED = "{\"success\":true,\"hostname\":\"id.example.com\",\"cdata\":\"%s\"}";

    /** Cloudflare's answer, read as if it had just come back from siteverify. */
    private static CloudflareTurnstileService.TurnstileVerificationResult read(String body, String expectedCdata) {
        try (CloudflareTurnstileService service = new CloudflareTurnstileService("secret")) {
            return service.readResponse(body, expectedCdata, "1.2.3.4");
        } catch (java.io.IOException e) {
            throw new AssertionError("test response should parse", e);
        }
    }

    @Test
    @DisplayName("A token solved by this session's widget is accepted")
    void cdataMatchingTheSessionIsAccepted() {
        var result = read(String.format(ACCEPTED, "session-A"), "session-A");

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getErrorCodes()).isNull();
        assertThat(result.getCdata()).isEqualTo("session-A");
    }

    @Test
    @DisplayName("A token Cloudflare accepted but solved for another session is refused")
    void cdataFromAnotherSessionIsRefused() {
        var result = read(String.format(ACCEPTED, "session-B"), "session-A");

        // Cloudflare said yes; it is this check alone that turns it down
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes()).isEqualTo(CloudflareTurnstileService.CDATA_MISMATCH);
    }

    @Test
    @DisplayName("A token carrying no cdata is refused when this session expects one")
    void missingCdataIsRefusedWhenOneIsExpected() {
        // What a theme that drops data-cdata produces, and an empty value is the same answer
        assertThat(read("{\"success\":true}", "session-A").isSuccess()).isFalse();
        assertThat(read(String.format(ACCEPTED, ""), "session-A").isSuccess()).isFalse();
    }

    @Test
    @DisplayName("A cdata we never asked for is left alone")
    void cdataIsNotCheckedWhenNoneWasExpected() {
        // cData is Cloudflare's field, not ours: a flow that minted nothing has no business refusing
        // someone else's value, and whoever reuses tokens would simply send none.
        var result = read(String.format(ACCEPTED, "someone-elses-value"), null);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getErrorCodes()).isNull();
        assertThat(result.getCdata()).isEqualTo("someone-elses-value");
    }

    @Test
    @DisplayName("A cdata mismatch is reported alongside Cloudflare's own error codes")
    void cdataMismatchJoinsCloudflaresErrorCodes() {
        var result = read("{\"success\":false,\"error-codes\":[\"timeout-or-duplicate\"],\"cdata\":\"session-B\"}",
                "session-A");

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes())
                .isEqualTo("timeout-or-duplicate," + CloudflareTurnstileService.CDATA_MISMATCH);
    }

    @Test
    @DisplayName("A failed check stays failed when its cdata matches")
    void matchingCdataDoesNotRescueAFailedCheck() {
        var result = read("{\"success\":false,\"error-codes\":[\"invalid-input-response\"],\"cdata\":\"session-A\"}",
                "session-A");

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes()).isEqualTo("invalid-input-response");
    }

    @Test
    @DisplayName("Cloudflare's testing keys are not held to the session binding")
    void testingKeysAreNotBound() {
        // Verbatim from siteverify with the testing secret key 1x0000000000000000000000000000000AA:
        // a canned answer that echoes no cdata, whatever the widget was rendered with. Refusing it
        // would lock out every realm on the testing keys, which is what the e2e suite and the docs
        // screenshots run on, and what Cloudflare's own Testing page tells people to develop against.
        var result = read("{\"challenge_ts\":\"2026-11-20T14:59:26.689Z\",\"error-codes\":[],"
                + "\"hostname\":\"example.com\",\"metadata\":{\"result_with_testing_key\":true},"
                + "\"success\":true}", "session-A");

        assertThat(result.isSuccess()).isTrue();
        // Cloudflare sends an empty array here, which this parser reads as an empty string, not null
        assertThat(result.getErrorCodes()).isNullOrEmpty();
    }

    @Test
    @DisplayName("A real key's answer is still bound when it carries other metadata")
    void metadataAloneDoesNotSkipTheBindingCheck() {
        // Only the testing-key flag skips the check: an Enterprise answer carries a metadata object too
        var result = read("{\"success\":true,\"metadata\":{\"ephemeral_id\":\"x:9f78e0ed\"}}", "session-A");

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrorCodes()).isEqualTo(CloudflareTurnstileService.CDATA_MISMATCH);
        assertThat(result.getEphemeralId()).isEqualTo("x:9f78e0ed");
    }
}
