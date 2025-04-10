package io.jenkins.plugins.wiz;

import static org.junit.jupiter.api.Assertions.*;

import net.sf.json.JSONObject;
import org.junit.jupiter.api.Test;

class WizScannerResultTest {

    @Test
    void testParseJsonContent() {
        String jsonStr = "{" + "\"scanOriginResource\": {\"name\": \"test-resource\"},"
                + "\"createdAt\": \"2024-01-01T12:00:00Z\","
                + "\"status\": {\"verdict\": \"PASSED_BY_POLICY\"},"
                + "\"result\": {"
                + "\"analytics\": {"
                + "\"vulnerabilities\": {"
                + "\"criticalCount\": 1,"
                + "\"highCount\": 2,"
                + "\"mediumCount\": 3,"
                + "\"lowCount\": 4,"
                + "\"infoCount\": 5,"
                + "\"totalCount\": 15"
                + "},"
                + "\"secrets\": {"
                + "\"criticalCount\": 1,"
                + "\"highCount\": 1,"
                + "\"mediumCount\": 1,"
                + "\"lowCount\": 1,"
                + "\"infoCount\": 1,"
                + "\"totalCount\": 5"
                + "}"
                + "},"
                + "\"scanStatistics\": {"
                + "\"criticalMatches\": 1,"
                + "\"highMatches\": 2,"
                + "\"mediumMatches\": 3,"
                + "\"lowMatches\": 4,"
                + "\"infoMatches\": 5,"
                + "\"totalMatches\": 15,"
                + "\"filesFound\": 10,"
                + "\"filesParsed\": 8,"
                + "\"queriesLoaded\": 5,"
                + "\"queriesExecuted\": 4,"
                + "\"queriesExecutionFailed\": 1"
                + "}"
                + "},"
                + "\"reportUrl\": \"https://test.wiz.io/report/123\""
                + "}";

        JSONObject root = JSONObject.fromObject(jsonStr);
        WizScannerResult result = WizScannerResult.parseJsonContent(root);

        assertNotNull(result, "Result should not be null");
        assertEquals("test-resource", result.getScannedResource());
        assertEquals("January 1, 2024 at 12:00 PM", result.getScanTime());
        assertEquals(WizScannerResult.ScanStatus.PASSED, result.getStatus());
        assertEquals("https://test.wiz.io/report/123", result.getReportUrl());

        // Check vulnerabilities
        assertTrue(result.getVulnerabilities().isPresent());
        WizScannerResult.Vulnerabilities vulns = result.getVulnerabilities().get();
        assertEquals(1, vulns.getCriticalCount());
        assertEquals(2, vulns.getHighCount());
        assertEquals(15, vulns.getTotalCount());

        // Check secrets
        assertTrue(result.getSecrets().isPresent());
        WizScannerResult.Secrets secrets = result.getSecrets().get();
        assertEquals(1, secrets.getCriticalCount());
        assertEquals(5, secrets.getTotalCount());

        // Check scan statistics
        assertTrue(result.getScanStatistics().isPresent());
        WizScannerResult.ScanStatistics stats = result.getScanStatistics().get();
        assertEquals(1, stats.getCriticalMatches());
    }

    @Test
    void testParseJsonContentWithInvalidData() {
        String jsonStr = "{" + "\"scanOriginResource\": {\"name\": \"test-resource\"},"
                + "\"status\": {\"verdict\": \"INVALID_STATUS\"}"
                + "}";

        JSONObject root = JSONObject.fromObject(jsonStr);
        WizScannerResult result = WizScannerResult.parseJsonContent(root);

        assertNotNull(result, "Result should not be null");
        assertEquals(WizScannerResult.ScanStatus.UNKNOWN, result.getStatus());
        assertTrue(result.getVulnerabilities().isPresent());
        assertEquals(0, result.getVulnerabilities().get().getTotalCount());
    }
}
