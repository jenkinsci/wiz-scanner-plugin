package io.jenkins.plugins.wiz;

import hudson.FilePath;
import hudson.model.Run;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.RunAction2;

/**
 * Represents a Wiz Scanner action that can be attached to a build.
 * This action stores and displays the results of a Wiz security scan.
 */
public class WizScannerAction implements RunAction2 {
    private static final Logger LOGGER = Logger.getLogger(WizScannerAction.class.getName());
    private static final String DEFAULT_ICON = "symbol-wiz plugin-wiz-scanner";
    private static final String BASE_URL_NAME = "wiz-results";
    private static final String DEFAULT_DISPLAY_NAME = "Wiz Scanner";

    private transient Run<?, ?> run;
    private final WizScannerResult scanDetails;
    private final String name;
    private final String artifactSuffix;

    /**
     * Creates a new WizScannerAction
     *
     * @param build          The build this action is associated with
     * @param workspace      The workspace containing scan results
     * @param artifactSuffix Suffix for multiple scans in the same build
     * @param artifactName   Name of the results artifact
     * @throws IllegalArgumentException if required parameters are null
     */
    public WizScannerAction(Run<?, ?> build, FilePath workspace, String artifactSuffix, String artifactName) {
        WizInputValidator.validateScanAction(build, workspace, artifactName);

        this.name = artifactSuffix;
        this.artifactSuffix = artifactSuffix;
        this.run = build;

        WizScannerResult loadedDetails = null;
        try {
            FilePath resultsFile = workspace.child(artifactName);
            loadedDetails = loadScanDetails(resultsFile);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to load scan details", e);
        }
        this.scanDetails = loadedDetails;
    }

    /**
     * Loads scan details from a JSON file
     * @param jsonFile The JSON file containing scan results
     * @return The parsed WizScannerResult
     * @throws IOException if the file cannot be read
     */
    private WizScannerResult loadScanDetails(FilePath jsonFile) throws IOException, InterruptedException {
        if (!jsonFile.exists()) {
            throw new IOException("Results file does not exist: " + jsonFile.getRemote());
        }

        WizScannerResult result = WizScannerResult.fromJsonFile(jsonFile);
        if (result == null) {
            throw new IOException("Failed to parse scan results from: " + jsonFile.getRemote());
        }
        return result;
    }

    // RunAction2 implementation
    @Override
    public void onAttached(Run<?, ?> run) {
        this.run = run;
    }

    @Override
    public void onLoad(Run<?, ?> run) {
        this.run = run;
    }

    // Action interface implementation
    @Override
    public String getIconFileName() {
        return DEFAULT_ICON;
    }

    @Override
    public String getDisplayName() {
        return artifactSuffix == null ? DEFAULT_DISPLAY_NAME : DEFAULT_DISPLAY_NAME + " " + artifactSuffix;
    }

    @Override
    public String getUrlName() {
        return artifactSuffix == null ? BASE_URL_NAME : BASE_URL_NAME + "-" + artifactSuffix;
    }

    // Getters
    public Run<?, ?> getRun() {
        return run;
    }

    public String getName() {
        return name;
    }

    @SuppressWarnings("unused")
    public WizScannerResult getScanDetails() {
        return scanDetails;
    }
}
