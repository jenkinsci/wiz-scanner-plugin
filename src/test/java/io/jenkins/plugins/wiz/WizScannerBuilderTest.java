package io.jenkins.plugins.wiz;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
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
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class WizScannerBuilderTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private TaskListener listener;
    private Launcher mockLauncher;
    private WizScannerBuilder builder;
    private FilePath workspace;
    private EnvVars env;
    private ByteArrayOutputStream logOutput;
    private static final String TEST_COMMAND = "docker scan alpine:latest";

    @Before
    public void setUp() throws Exception {
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
    public void testConfigRoundtrip() throws Exception {
        FreeStyleProject project = j.createFreeStyleProject();
        project.getBuildersList().add(builder);

        project = j.configRoundtrip(project);

        // Get the builder from the configured project
        WizScannerBuilder after = project.getBuildersList().get(WizScannerBuilder.class);

        // Verify configuration is preserved
        j.assertEqualDataBoundBeans(builder, after);
    }

    @Test
    public void testPerformFailureInvalidConfig() throws Exception {
        // Setup with invalid config
        WizScannerBuilder.DescriptorImpl descriptor =
                j.jenkins.getDescriptorByType(WizScannerBuilder.DescriptorImpl.class);
        FreeStyleProject project = j.createFreeStyleProject();
        Run<?, ?> run = project.scheduleBuild2(0).get();

        descriptor.configure(
                null,
                net.sf.json.JSONObject.fromObject("{" + "'wizCredentialsId': '',"
                        + "'wizClientId': '',"
                        + "'wizSecretKey': '',"
                        + "'wizCliURL': '',"
                        + "'wizEnv': ''"
                        + "}"));

        try {
            builder.perform(run, workspace, env, mockLauncher, listener);
            fail("Expected AbortException to be thrown");
        } catch (AbortException e) {
            assertEquals("Wiz Client ID is required", e.getMessage());
        }
    }

    @Test
    public void testFormValidation() {
        WizScannerBuilder.DescriptorImpl descriptor = new WizScannerBuilder.DescriptorImpl();

        // Test empty input
        assertEquals(
                "Error message for empty input",
                Messages.WizScannerBuilder_DescriptorImpl_errors_missingName(),
                descriptor.doCheckUserInput("").getMessage());

        // Test valid input
        assertEquals("OK for valid input", FormValidation.Kind.OK, descriptor.doCheckUserInput(TEST_COMMAND).kind);
    }

    @Test
    public void testDescriptorBasics() {
        WizScannerBuilder.DescriptorImpl descriptor = new WizScannerBuilder.DescriptorImpl();

        // Test display name
        assertNotNull("Display name should not be null", descriptor.getDisplayName());

        // Test applicability
        assertTrue("Should be applicable to FreeStyleProject", descriptor.isApplicable(FreeStyleProject.class));
    }

    @Test
    public void testDescriptorConfigurationSaveAndLoad() throws Exception {
        WizScannerBuilder.DescriptorImpl sut = j.jenkins.getDescriptorByType(WizScannerBuilder.DescriptorImpl.class);

        String expectedCredentialsId = "test-credentials-id";
        String expectedClientId = "test-client-id";
        String expectedSecretKey = "test-secret-key";
        String expectedCliUrl = "https://test.wiz.io/cli";
        String expectedEnv = "test-env";

        JSONObject formData = new JSONObject();
        formData.put("wizCredentialsId", expectedCredentialsId);
        formData.put("wizClientId", expectedClientId);
        formData.put("wizSecretKey", expectedSecretKey);
        formData.put("wizCliURL", expectedCliUrl);
        formData.put("wizEnv", expectedEnv);

        sut.configure(null, formData);

        assertEquals("Client ID not saved correctly", expectedClientId, sut.getWizClientId());
        assertEquals("Secret key not saved correctly", expectedSecretKey, Secret.toString(sut.getWizSecretKey()));
        assertEquals("CLI URL not saved correctly", expectedCliUrl, sut.getWizCliURL());
        assertEquals("Environment not saved correctly", expectedEnv, sut.getWizEnv());

        sut = new WizScannerBuilder.DescriptorImpl();

        assertEquals("Client ID not loaded correctly", expectedClientId, sut.getWizClientId());
        assertEquals("Secret key not loaded correctly", expectedSecretKey, Secret.toString(sut.getWizSecretKey()));
        assertEquals("CLI URL not loaded correctly", expectedCliUrl, sut.getWizCliURL());
        assertEquals("Environment not loaded correctly", expectedEnv, sut.getWizEnv());
    }

    @Test
    public void testCredentialsAreProperlySetFromStore() throws Exception {
        WizScannerBuilder.DescriptorImpl descriptor =
                j.jenkins.getDescriptorByType(WizScannerBuilder.DescriptorImpl.class);
        FreeStyleProject project = j.createFreeStyleProject();

        UsernamePasswordCredentialsImpl credentials = new UsernamePasswordCredentialsImpl(
                CredentialsScope.GLOBAL, "wizsecret", "Wiz Credentials", "someusername", "changeit");

        UsernamePasswordCredentialsImpl credentialsSpy = spy(credentials);

        CredentialsProvider.lookupStores(j.jenkins).iterator().next().addCredentials(Domain.global(), credentialsSpy);

        Run<?, ?> run = project.scheduleBuild2(0).get();

        descriptor.configure(
                null,
                net.sf.json.JSONObject.fromObject("{" + "'wizCredentialsId': '" + credentials.getId() + "',"
                        + "'wizClientId': '',"
                        + "'wizSecretKey': '',"
                        + "'wizCliURL': 'https://downloads.wiz.io/wizcli/0/dummy',"
                        + "'wizEnv': ''"
                        + "}"));

        try {
            builder.perform(run, workspace, env, mockLauncher, listener);
            fail("Expected AbortException to be thrown");
        } catch (AbortException e) {
            assertEquals(
                    "Error executing Wiz CLI: Failed to setup Wiz CLI: Download failed with HTTP code: 403",
                    e.getMessage());
        }

        verify(credentialsSpy).getUsername();
        verify(credentialsSpy).getPassword();
    }
}
