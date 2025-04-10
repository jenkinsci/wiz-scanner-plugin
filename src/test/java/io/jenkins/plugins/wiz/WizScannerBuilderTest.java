package io.jenkins.plugins.wiz;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.FreeStyleProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.ArgumentListBuilder;
import hudson.util.FormValidation;
import hudson.util.Secret;
import hudson.util.StreamTaskListener;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class WizScannerBuilderTest {

    private JenkinsRule j;

    private TaskListener listener;
    private Launcher mockLauncher;
    private WizScannerBuilder builder;
    private FilePath workspace;
    private EnvVars env;
    private ByteArrayOutputStream logOutput;
    private static final String TEST_COMMAND = "docker scan alpine:latest";

    @BeforeEach
    void setUp(JenkinsRule rule) throws Exception {
        j = rule;
        workspace = j.jenkins.getRootPath();
        builder = new WizScannerBuilder(TEST_COMMAND);
        logOutput = new ByteArrayOutputStream();
        listener = new StreamTaskListener(logOutput, Charset.defaultCharset());

        env = new EnvVars();
        env.put("PATH", "/usr/local/bin:/usr/bin:/bin");
        env.put("WIZ_ENV", "test");

        mockLauncher = mock(Launcher.class);
        Launcher.ProcStarter procStarter = mock(Launcher.ProcStarter.class);
        when(mockLauncher.launch()).thenReturn(procStarter);
        when(procStarter.cmds(any(ArgumentListBuilder.class))).thenReturn(procStarter);
        when(procStarter.envs(anyMap())).thenReturn(procStarter);
        when(procStarter.pwd(any(FilePath.class))).thenReturn(procStarter);
        when(procStarter.stdout(any(OutputStream.class))).thenReturn(procStarter);
        when(procStarter.stderr(any(OutputStream.class))).thenReturn(procStarter);
        when(procStarter.quiet(anyBoolean())).thenReturn(procStarter);
        when(procStarter.join()).thenReturn(0);
    }

    @Test
    void testConfigRoundtrip() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject();
        project.getBuildersList().add(builder);

        project = j.configRoundtrip(project);

        // Get the builder from the configured project
        WizScannerBuilder after = project.getBuildersList().get(WizScannerBuilder.class);

        // Verify configuration is preserved
        j.assertEqualDataBoundBeans(builder, after);
    }

    @Test
    void testPerformFailureInvalidConfig() throws Exception {
        // Setup with invalid config
        WizScannerBuilder.DescriptorImpl descriptor =
                j.jenkins.getDescriptorByType(WizScannerBuilder.DescriptorImpl.class);
        FreeStyleProject project = j.createFreeStyleProject();
        Run<?, ?> run = project.scheduleBuild2(0).get();

        descriptor.configure(
                null,
                net.sf.json.JSONObject.fromObject("{" + "'wizClientId': '',"
                        + "'wizSecretKey': '',"
                        + "'wizCliURL': '',"
                        + "'wizEnv': ''"
                        + "}"));

        AbortException e =
                assertThrows(AbortException.class, () -> builder.perform(run, workspace, env, mockLauncher, listener));
        assertEquals("Wiz Client ID is required", e.getMessage());
    }

    @Test
    void testFormValidation() {
        WizScannerBuilder.DescriptorImpl descriptor = new WizScannerBuilder.DescriptorImpl();

        // Test empty input
        assertEquals(
                Messages.WizScannerBuilder_DescriptorImpl_errors_missingName(),
                descriptor.doCheckUserInput("").getMessage(),
                "Error message for empty input");

        // Test valid input
        assertEquals(FormValidation.Kind.OK, descriptor.doCheckUserInput(TEST_COMMAND).kind, "OK for valid input");
    }

    @Test
    void testDescriptorBasics() {
        WizScannerBuilder.DescriptorImpl descriptor = new WizScannerBuilder.DescriptorImpl();

        // Test display name
        assertNotNull(descriptor.getDisplayName(), "Display name should not be null");

        // Test applicability
        assertTrue(descriptor.isApplicable(FreeStyleProject.class), "Should be applicable to FreeStyleProject");
    }

    @Test
    void testDescriptorConfigurationSaveAndLoad() throws Exception {
        WizScannerBuilder.DescriptorImpl sut = j.jenkins.getDescriptorByType(WizScannerBuilder.DescriptorImpl.class);

        String expectedClientId = "test-client-id";
        String expectedSecretKey = "test-secret-key";
        String expectedCliUrl = "https://test.wiz.io/cli";
        String expectedEnv = "test-env";

        JSONObject formData = new JSONObject();
        formData.put("wizClientId", expectedClientId);
        formData.put("wizSecretKey", expectedSecretKey);
        formData.put("wizCliURL", expectedCliUrl);
        formData.put("wizEnv", expectedEnv);

        sut.configure(null, formData);

        assertEquals(expectedClientId, sut.getWizClientId(), "Client ID not saved correctly");
        assertEquals(expectedSecretKey, Secret.toString(sut.getWizSecretKey()), "Secret key not saved correctly");
        assertEquals(expectedCliUrl, sut.getWizCliURL(), "CLI URL not saved correctly");
        assertEquals(expectedEnv, sut.getWizEnv(), "Environment not saved correctly");

        sut = new WizScannerBuilder.DescriptorImpl();

        assertEquals(expectedClientId, sut.getWizClientId(), "Client ID not loaded correctly");
        assertEquals(expectedSecretKey, Secret.toString(sut.getWizSecretKey()), "Secret key not loaded correctly");
        assertEquals(expectedCliUrl, sut.getWizCliURL(), "CLI URL not loaded correctly");
        assertEquals(expectedEnv, sut.getWizEnv(), "Environment not loaded correctly");
    }
}
