package io.jenkins.plugins.wiz;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class WizCliVersionDetectionTest {

    private final String url;
    private final WizCliVersion expectedVersion;

    public WizCliVersionDetectionTest(String url, WizCliVersion expectedVersion) {
        this.url = url;
        this.expectedVersion = expectedVersion;
    }

    @Parameters(name = "{index}: {0} -> {1}")
    public static Collection<Object[]> testCases() {
        return Arrays.asList(new Object[][] {
            // V1 URLs with v1/wizcli pattern
            {"https://downloads.wiz.io/v1/wizcli/latest/wizcli-linux-amd64", WizCliVersion.V1},
            {"https://downloads.wiz.io/v1/wizcli/1.0.0/wizcli-linux-arm64", WizCliVersion.V1},
            {"https://downloads.wiz.io/v1/wizcli/1.2.3/wizcli-darwin-amd64", WizCliVersion.V1},
            {"https://downloads.wiz.io/v1/wizcli/0.9.0/wizcli-windows-amd64.exe", WizCliVersion.V1},

            // V1 URLs with wizcli/1.x.x pattern
            {"https://downloads.wiz.io/wizcli/1.0.0/wizcli-linux-amd64", WizCliVersion.V1},
            {"https://downloads.wiz.io/wizcli/1.0.2/wizcli-linux-amd64", WizCliVersion.V1},
            {"https://downloads.wiz.io/wizcli/1.2.3/wizcli-darwin-amd64", WizCliVersion.V1},
            {"https://downloads.wiz.io/wizcli/1.99.99/wizcli-windows-amd64.exe", WizCliVersion.V1},

            // V0 URLs with wizcli/0.x.x pattern
            {"https://downloads.wiz.io/wizcli/0.0.1/wizcli-linux-amd64", WizCliVersion.V0},
            {"https://downloads.wiz.io/wizcli/0.0.2/wizcli-linux-amd64", WizCliVersion.V0},
            {"https://downloads.wiz.io/wizcli/0.1.0/wizcli-windows-amd64.exe", WizCliVersion.V0},
            {"https://downloads.wiz.io/wizcli/0.99.99/wizcli-darwin-amd64", WizCliVersion.V0},

            // V0 URLs with wizcli/latest pattern (without v1 prefix)
            {"https://downloads.wiz.io/wizcli/latest/wizcli-linux-amd64", WizCliVersion.V0},
            {"https://downloads.wiz.io/wizcli/latest/wizcli-darwin-amd64", WizCliVersion.V0},
            {"https://downloads.wiz.io/wizcli/latest/wizcli-windows-amd64.exe", WizCliVersion.V0}
        });
    }

    @Test
    public void testVersionDetection() {
        try {
            ParsedWizCliUrl parsedUrl = WizInputValidator.parseWizCliUrl(url);
            assertEquals("Version detection failed for URL: " + url, expectedVersion, parsedUrl.getVersion());
            assertEquals("URL should match input", url, parsedUrl.getUrl());
            assertEquals("toString() should return URL", url, parsedUrl.toString());
        } catch (Exception e) {
            fail("Failed to parse valid URL: " + url + ", error: " + e.getMessage());
        }
    }
}