package io.jenkins.plugins.wiz;

import hudson.FilePath;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.commons.lang3.StringUtils;

/**
 * Represents the results of a Wiz security scan.
 * This class handles parsing and storing scan results from JSON format.
 */
public class WizScannerResult {
    private static final Logger LOGGER = Logger.getLogger(WizScannerResult.class.getName());
    private static final DateTimeFormatter OUTPUT_FORMATTER =
            DateTimeFormatter.ofPattern("MMMM d, yyyy 'at' h:mm a", Locale.ENGLISH);
    private static final DateTimeFormatter INPUT_FORMATTER = DateTimeFormatter.ISO_DATE_TIME;

    private String scannedResource;
    private String scanTime;
    private ScanStatus status;
    private String reportUrl;

    private Map<String, ScannerAnalytics> analytics;

    public Optional<Map<String, ScannerAnalytics>> getAnalytics() {
        return Optional.ofNullable(analytics);
    }

    public void setAnalytics(Map<String, ScannerAnalytics> analytics) {
        this.analytics = analytics;
    }

    public enum ScanStatus {
        PASSED("PASSED_BY_POLICY", "Passed"),
        FAILED("FAILED_BY_POLICY", "Failed"),
        IN_PROGRESS("IN_PROGRESS", "InProgress"),
        WARNED("WARN_BY_POLICY", "Warned"),
        UNKNOWN("UNKNOWN", "Unknown");

        private final String apiValue;
        private final String displayValue;

        ScanStatus(String apiValue, String displayValue) {
            this.apiValue = apiValue;
            this.displayValue = displayValue;
        }

        @Override
        public String toString() {
            return displayValue;
        }

        public static ScanStatus fromString(String value) {
            for (ScanStatus status : values()) {
                if (status.apiValue.equals(value)) {
                    return status;
                }
            }
            return UNKNOWN;
        }

        public boolean matches(String displayStatus) {
            return this.displayValue.equals(displayStatus);
        }
    }

    private enum FindingTypes {
        MISCONFIGURATION("scanStatistics", "Misconfigurations"),
        HOST_CONFIGURATION("hostConfiguration", "Host Configurations"),
        VULNERABILITY("vulnerabilities", "Vulnerabilities"),
        SECRET("secrets", "Secrets"),
        MALWARE("malware", "Malware"),
        SAST("sast", "SAST");

        private final String apiValue;
        private final String uiValue;

        FindingTypes(String apiValue, String uiValue) {
            this.apiValue = apiValue;
            this.uiValue = uiValue;
        }
    }

    public static class ScannerAnalytics {
        private int infoCount;
        private int lowCount;
        private int mediumCount;
        private int highCount;
        private int criticalCount;
        private int totalCount;

        // Enhanced getters with validation
        public int getInfoCount() {
            return Math.max(0, infoCount);
        }

        public int getLowCount() {
            return Math.max(0, lowCount);
        }

        public int getMediumCount() {
            return Math.max(0, mediumCount);
        }

        public int getHighCount() {
            return Math.max(0, highCount);
        }

        public int getCriticalCount() {
            return Math.max(0, criticalCount);
        }

        public int getTotalCount() {
            return Math.max(0, totalCount);
        }

        // Setters with validation
        public void setInfoCount(int count) {
            this.infoCount = Math.max(0, count);
        }

        public void setLowCount(int count) {
            this.lowCount = Math.max(0, count);
        }

        public void setMediumCount(int count) {
            this.mediumCount = Math.max(0, count);
        }

        public void setHighCount(int count) {
            this.highCount = Math.max(0, count);
        }

        public void setCriticalCount(int count) {
            this.criticalCount = Math.max(0, count);
        }

        public void setTotalCount(int count) {
            this.totalCount = Math.max(0, count);
        }

        // Add validation method
        public boolean isValid() {
            return totalCount >= (infoCount + lowCount + mediumCount + highCount + criticalCount);
        }

        static Map<String, ScannerAnalytics> parseScannerAnalytics(JSONObject root) {
            Map<String, ScannerAnalytics> analytics = null;
            if (root != null && root.has("result")) {
                JSONObject result = root.getJSONObject("result");
                if (result.has("analytics")) {
                    JSONObject analyticsObj = result.getJSONObject("analytics");
                    analytics = new HashMap<>();
                    for (FindingTypes key : FindingTypes.values()) {
                        try {
                            var scannerAnalyticsJson = analyticsObj.optJSONObject(key.apiValue);
                            if (scannerAnalyticsJson == null) {
                                continue;
                            }
                            if (scannerAnalyticsJson.isNullObject()) {
                                continue;
                            }

                            ScannerAnalytics scannerAnalytics = new ScannerAnalytics();
                            scannerAnalytics.setInfoCount(scannerAnalyticsJson.optInt("infoCount", 0));
                            scannerAnalytics.setLowCount(scannerAnalyticsJson.optInt("lowCount", 0));
                            scannerAnalytics.setMediumCount(scannerAnalyticsJson.optInt("mediumCount", 0));
                            scannerAnalytics.setHighCount(scannerAnalyticsJson.optInt("highCount", 0));
                            scannerAnalytics.setCriticalCount(scannerAnalyticsJson.optInt("criticalCount", 0));
                            scannerAnalytics.setTotalCount(scannerAnalyticsJson.optInt("totalCount", 0));
                            analytics.put(key.uiValue, scannerAnalytics);
                        } catch (Exception e) {
                            LOGGER.log(Level.WARNING, "Error parsing " + key, e);
                        }
                    }
                }
            }
            return analytics;
        }
    }

    // Enhanced getters and setters with validation
    public String getScannedResource() {
        return StringUtils.defaultString(scannedResource);
    }

    public void setScannedResource(String resource) {
        this.scannedResource = StringUtils.trimToNull(resource);
    }

    public String getScanTime() {
        return StringUtils.defaultString(scanTime);
    }

    public void setScanTime(String time) {
        this.scanTime = StringUtils.trimToNull(time);
    }

    public ScanStatus getStatus() {
        return Objects.requireNonNullElse(status, ScanStatus.UNKNOWN);
    }

    public void setStatus(ScanStatus status) {
        this.status = status;
    }

    public String getReportUrl() {
        return StringUtils.defaultString(reportUrl);
    }

    public void setReportUrl(String url) {
        this.reportUrl = StringUtils.trimToNull(url);
    }

    /**
     * Creates a WizScannerResult from a JSON file
     * @param jsonFile The JSON file to parse
     * @return The parsed WizScannerResult or null if parsing fails
     */
    public static WizScannerResult fromJsonFile(FilePath jsonFile) throws IOException {
        try {
            if (jsonFile == null || !jsonFile.exists()) {
                throw new IOException("JSON file does not exist");
            }

            String content = jsonFile.readToString();
            if (StringUtils.isBlank(content)) {
                throw new IOException("JSON file is empty");
            }

            JSONObject root = (JSONObject) JSONSerializer.toJSON(content);
            return parseJsonContent(root);

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to parse scan results", e);
            return null;
        }
    }

    /**
     * Parses a WizScannerResult from a JSON object
     * @param root The JSON object to parse
     * @return The parsed WizScannerResult or null if parsing fails
     */
    public static WizScannerResult parseJsonContent(JSONObject root) {
        WizScannerResult details = new WizScannerResult();

        try {
            details.setScannedResource(getJsonString(root, "scanOriginResource.name"));
            details.setScanTime(formatDateTime(getJsonString(root, "createdAt")));
            details.setStatus(parseStatus(getJsonString(root, "status.verdict")));
            Map<String, ScannerAnalytics> analytics = ScannerAnalytics.parseScannerAnalytics(root);

            // Support v0 cli IAC scan:
            ScannerAnalytics misconfigurationAnalytics = parseMisconfigurationStatistics(root);
            if (misconfigurationAnalytics != null) {
                if (analytics == null) {
                    analytics = Map.of(FindingTypes.MISCONFIGURATION.uiValue, misconfigurationAnalytics);
                } else {
                    analytics.put(FindingTypes.MISCONFIGURATION.uiValue, misconfigurationAnalytics);
                }
            }

            details.setAnalytics(analytics);

            details.setReportUrl(getJsonString(root, "reportUrl"));

            validateResult(details);
            return details;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error parsing JSON content", e);
            return null;
        }
    }

    private static void validateResult(WizScannerResult details) {
        details.getAnalytics()
                .ifPresent(map -> map.forEach((key, value) -> {
                    if (!value.isValid()) {
                        LOGGER.log(Level.WARNING, "Analytics data for " + key + " contains inconsistencies");
                    }
                }));
    }

    private static String getJsonString(JSONObject root, String path) {
        if (root == null || StringUtils.isBlank(path)) {
            return "";
        }
        try {
            JSONObject current = root;
            String[] keys = path.split("\\.");

            for (int i = 0; i < keys.length - 1; i++) {
                if (!current.has(keys[i])) {
                    return "";
                }
                current = current.getJSONObject(keys[i]);
                if (current == null) {
                    return "";
                }
            }

            return current.optString(keys[keys.length - 1], "");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error getting JSON string for path: " + path, e);
            return "";
        }
    }

    private static String formatDateTime(String dateTimeString) {
        if (StringUtils.isBlank(dateTimeString)) {
            return "";
        }
        try {
            LocalDateTime dateTime = LocalDateTime.parse(dateTimeString, INPUT_FORMATTER);
            return dateTime.format(OUTPUT_FORMATTER);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error formatting datetime: " + dateTimeString, e);
            return dateTimeString;
        }
    }

    private static ScanStatus parseStatus(String statusString) {
        if (StringUtils.isBlank(statusString)) {
            return ScanStatus.UNKNOWN;
        }
        return ScanStatus.fromString(statusString);
    }

    private static ScannerAnalytics parseMisconfigurationStatistics(JSONObject root) {
        ScannerAnalytics stats = null;
        try {
            if (root != null && root.has("result")) {
                JSONObject result = root.getJSONObject("result");
                if (result.has("scanStatistics")) {
                    ScannerAnalytics misconfigurationStatistics = new ScannerAnalytics();
                    JSONObject scanStats = result.getJSONObject("scanStatistics");
                    misconfigurationStatistics.setInfoCount(scanStats.optInt("infoMatches", 0));
                    misconfigurationStatistics.setLowCount(scanStats.optInt("lowMatches", 0));
                    misconfigurationStatistics.setMediumCount(scanStats.optInt("mediumMatches", 0));
                    misconfigurationStatistics.setHighCount(scanStats.optInt("highMatches", 0));
                    misconfigurationStatistics.setCriticalCount(scanStats.optInt("criticalMatches", 0));
                    misconfigurationStatistics.setTotalCount(scanStats.optInt("totalMatches", 0));
                    stats = misconfigurationStatistics;
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error parsing scan statistics", e);
        }
        return stats;
    }

    @Override
    public String toString() {
        return String.format(
                "WizScannerResult{resource='%s', status=%s, findings=%s}",
                getScannedResource(),
                getStatus(),
                getAnalytics()
                        .map(analytics -> analytics.entrySet().stream()
                                .map((entry) ->
                                        entry.getKey() + "=" + entry.getValue().getTotalCount())
                                .collect(Collectors.joining(", ")))
                        .orElse("none"));
    }
}
