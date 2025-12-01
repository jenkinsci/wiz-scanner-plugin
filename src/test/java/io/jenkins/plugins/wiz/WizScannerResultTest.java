package io.jenkins.plugins.wiz;

import static org.junit.Assert.*;

import net.sf.json.JSONObject;
import org.junit.Test;

public class WizScannerResultTest {

    @Test
    public void testParseJsonContentWithV0_IAC() {
        String jsonStr = "{" + "\"scanOriginResource\": {\"name\": \"test-resource\"},"
                + "\"createdAt\": \"2024-01-01T12:00:00Z\","
                + "\"status\": {\"verdict\": \"PASSED_BY_POLICY\"},"
                + "\"result\": {"
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
        assertNotNull("Result should not be null", result);
        assertEquals("test-resource", result.getScannedResource());
        assertEquals("January 1, 2024 at 12:00 PM", result.getScanTime());
        assertEquals(WizScannerResult.ScanStatus.PASSED, result.getStatus());
        assertEquals("https://test.wiz.io/report/123", result.getReportUrl());
        assertTrue(result.getAnalytics().isPresent());
        assertEquals(1, result.getAnalytics().get().size());
        assertNotNull(result.getAnalytics().get().get("Misconfigurations"));
        assertEquals(1, result.getAnalytics().get().get("Misconfigurations").getCriticalCount());
    }

    @Test
    public void testParseJsonContent() {
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

        assertNotNull("Result should not be null", result);
        assertEquals("test-resource", result.getScannedResource());
        assertEquals("January 1, 2024 at 12:00 PM", result.getScanTime());
        assertEquals(WizScannerResult.ScanStatus.PASSED, result.getStatus());
        assertEquals("https://test.wiz.io/report/123", result.getReportUrl());

        // Check vulnerabilities
        assertTrue(result.getAnalytics().isPresent());

        var vulns = result.getAnalytics().map(map -> map.get("Vulnerabilities"));
        assertTrue(vulns.isPresent());
        assertEquals(1, vulns.get().getCriticalCount());
        assertEquals(2, vulns.get().getHighCount());
        assertEquals(15, vulns.get().getTotalCount());

        // Check secrets
        var secrets = result.getAnalytics().map(map -> map.get("Secrets"));
        assertTrue(secrets.isPresent());
        assertEquals(1, secrets.get().getCriticalCount());
        assertEquals(5, secrets.get().getTotalCount());

        // Check scan statistics
        var misconfig = result.getAnalytics().map(map -> map.get("Misconfigurations"));
        assertTrue(misconfig.isPresent());
        assertEquals(1, misconfig.get().getCriticalCount());
    }

    @Test
    public void testParseJsonContentWithInvalidData() {
        String jsonStr = "{" + "\"scanOriginResource\": {\"name\": \"test-resource\"},"
                + "\"status\": {\"verdict\": \"INVALID_STATUS\"}"
                + "}";

        JSONObject root = JSONObject.fromObject(jsonStr);
        WizScannerResult result = WizScannerResult.parseJsonContent(root);

        assertNotNull("Result should not be null", result);
        assertEquals(WizScannerResult.ScanStatus.UNKNOWN, result.getStatus());

        var vulns = result.getAnalytics().map(map -> map.get("vulnerabilities"));
        assertFalse(vulns.isPresent());
    }
}
