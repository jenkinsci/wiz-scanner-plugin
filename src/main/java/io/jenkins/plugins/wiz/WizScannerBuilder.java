package io.jenkins.plugins.wiz;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.interceptor.RequirePOST;

public class WizScannerBuilder extends Builder implements SimpleBuildStep {
    private static final Logger LOGGER = Logger.getLogger(WizScannerBuilder.class.getName());
    private static final String DEFAULT_ARTIFACT_NAME = "wizscan.json";
    private static final String ARTIFACT_PREFIX = "wizscan-";
    private static final String ARTIFACT_SUFFIX = ".json";
    private static final String WIZ_ENV_KEY = "WIZ_ENV";

    public static final int OK_CODE = 0;
    private static volatile int buildId; // Made volatile for thread safety
    private static volatile int count;

    private final String userInput;

    @DataBoundConstructor
    public WizScannerBuilder(String userInput) {
        this.userInput = StringUtils.trimToEmpty(userInput);
    }

    @SuppressWarnings("unused")
    public String getUserInput() {
        return userInput;
    }

    private static synchronized int getNextCount() {
        return ++count;
    }

    private static synchronized void resetCount() {
        count = 1;
    }

    /**
     * Determines the artifact name based on build context
     */
    private static class ArtifactInfo {
        final String name;
        final String suffix;

        ArtifactInfo(String name, String suffix) {
            this.name = name;
            this.suffix = suffix;
        }
    }

    /**
     * Credential holder for Wiz CLI authentication. To be filled with either
     * client ID and secret key or retrieved from Jenkins credentials store.
     */
    private static class WizCredentials {
        final String clientId;
        final Secret secretKey;

        WizCredentials(String clientId, Secret secretKey) {
            this.clientId = clientId;
            this.secretKey = secretKey;
        }

        public String getClientId() {
            return clientId;
        }

        public Secret getSecretKey() {
            return secretKey;
        }
    }

    private ArtifactInfo determineArtifactName(int currentBuildId) {
        if (currentBuildId != buildId) {
            buildId = currentBuildId;
            resetCount();
            return new ArtifactInfo(DEFAULT_ARTIFACT_NAME, null);
        }
        String suffix = String.valueOf(getNextCount());
        return new ArtifactInfo(ARTIFACT_PREFIX + suffix + ARTIFACT_SUFFIX, suffix);
    }

    @Override
    public void perform(
            @NonNull Run<?, ?> build,
            @NonNull FilePath workspace,
            @NonNull EnvVars env,
            @NonNull Launcher launcher,
            @NonNull TaskListener listener)
            throws InterruptedException, IOException {
        try {
            LOGGER.log(Level.FINE, "Starting Wiz Scanner build step for build {0}", build.getDisplayName());

            // Get configuration
            DescriptorImpl descriptor = getDescriptor();
            EnvVars envVars = build.getEnvironment(listener);

            WizCredentials wizCredentials;
            if (StringUtils.isNotBlank(descriptor.getWizCredentialsId())) {
                StandardUsernamePasswordCredentials credentials = CredentialsProvider.findCredentialById(
                        descriptor.getWizCredentialsId(), StandardUsernamePasswordCredentials.class, build);

                wizCredentials = new WizCredentials(credentials.getUsername(), credentials.getPassword());

                WizInputValidator.validateConfiguration(
                        wizCredentials.getClientId(), wizCredentials.getSecretKey(), descriptor.getWizCliURL());
            } else {
                // Validate configuration
                WizInputValidator.validateConfiguration(
                        descriptor.getWizClientId(), descriptor.getWizSecretKey(), descriptor.getWizCliURL());

                wizCredentials = new WizCredentials(descriptor.getWizClientId(), descriptor.getWizSecretKey());
            }

            // Set environment variables
            setupEnvironment(envVars, descriptor.getWizEnv());

            // Determine artifact names
            ArtifactInfo artifactInfo = determineArtifactName(build.hashCode());

            // Execute scan
            int exitCode = WizCliRunner.execute(
                    workspace,
                    envVars,
                    launcher,
                    listener,
                    descriptor.getWizCliURL(),
                    wizCredentials.getClientId(),
                    wizCredentials.getSecretKey(),
                    userInput,
                    artifactInfo.name);

            // Process results
            processResults(build, exitCode, workspace, listener, artifactInfo);

        } catch (AbortException e) {
            throw e;
        } catch (Exception e) {
            throw new AbortException("Wiz scan failed: " + e.getMessage());
        }
    }

    private void setupEnvironment(EnvVars envVars, String wizEnv) {
        if (StringUtils.isNotBlank(wizEnv)) {
            envVars.put(WIZ_ENV_KEY, wizEnv);
            LOGGER.log(Level.FINE, "Set WIZ_ENV to {0}", wizEnv);
        }
    }

    private void processResults(
            Run<?, ?> build, int exitCode, FilePath workspace, TaskListener listener, ArtifactInfo artifactInfo)
            throws IOException {

        FilePath resultFile = workspace.child(artifactInfo.name);
        try {
            if (resultFile.exists() && resultFile.length() > 0) {
                build.addAction(new WizScannerAction(build, workspace, artifactInfo.suffix, artifactInfo.name));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while checking results file", e);
        }

        try {
            WizCliUtils.cleanupArtifacts(build, workspace, listener, artifactInfo.name);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error during artifact cleanup", e);
        }

        if (exitCode != OK_CODE) {
            throw new AbortException("Wiz scanning failed with exit code: " + exitCode);
        }

        LOGGER.log(Level.FINE, "Wiz scan completed successfully");
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    @Symbol("wizcli")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        private String wizCredentialsId;
        private String wizClientId;
        private Secret wizSecretKey;
        private String wizCliURL;
        private String wizEnv;

        public DescriptorImpl() {
            load();
        }

        @RequirePOST
        @SuppressFBWarnings(value = "SECURITY")
        public FormValidation doCheckUserInput(@QueryParameter String value) {
            if (StringUtils.isBlank(value)) {
                return FormValidation.error(Messages.WizScannerBuilder_DescriptorImpl_errors_missingName());
            }
            return FormValidation.ok();
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public @NonNull String getDisplayName() {
            return Messages.WizScannerBuilder_DescriptorImpl_DisplayName();
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            wizCredentialsId = formData.getString("wizCredentialsId");
            wizClientId = formData.getString("wizClientId");
            wizSecretKey = Secret.fromString(formData.getString("wizSecretKey"));
            wizCliURL = formData.getString("wizCliURL");
            wizEnv = formData.getString("wizEnv");
            save();
            return super.configure(req, formData);
        }

        // Getters
        public String getWizClientId() {
            return wizClientId;
        }

        public Secret getWizSecretKey() {
            return wizSecretKey;
        }

        public String getWizCliURL() {
            return wizCliURL;
        }

        public String getWizEnv() {
            return wizEnv;
        }

        public String getWizCredentialsId() {
            return wizCredentialsId;
        }
    }
}
