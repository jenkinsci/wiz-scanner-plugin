package io.jenkins.plugins.wiz;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class WizInputValidatorTest {

    private final Map.Entry<WizCliVersion, String> test;

    public WizInputValidatorTest(Map.Entry<WizCliVersion, String> command) {
        this.test = command;
    }

    @Parameters(name = "{index}: {0}")
    public static Collection<Map.Entry<WizCliVersion, String>> validCommands() {
        return Arrays.asList(
                // V0 commands
                Map.entry(WizCliVersion.V0, "dir scan --path /path/to/directory"),
                Map.entry(WizCliVersion.V0, "docker scan --image nginx:latest"),
                Map.entry(WizCliVersion.V0, "docker scan --image alpine:3.14"),
                Map.entry(WizCliVersion.V0, "docker scan --image /tmp/image.tar.gz"),
                Map.entry(WizCliVersion.V0, "iac scan --path /terraform/config"),
                Map.entry(WizCliVersion.V0, "dir scan --path /app --no-publish --policy policy1"),
                Map.entry(WizCliVersion.V0, "docker scan --image myapp:v1.0 --driver=extract --no-telemetry"),
                Map.entry(WizCliVersion.V0, "dir scan --path /app --policy policy1 --policy policy2 --no-color --format json"),
                Map.entry(WizCliVersion.V0, "docker scan --image test:latest --output /tmp/results.json,json"),
                Map.entry(WizCliVersion.V0, "iac scan --path ./src --format sarif"),

                Map.entry(WizCliVersion.V1, "scan dir /path/to/directory"),
                Map.entry(WizCliVersion.V1, "scan container-image nginx:latest"),
                Map.entry(WizCliVersion.V1, "scan container-image alpine:3.14"),
                Map.entry(WizCliVersion.V1, "scan container-image /tmp/image.tar.gz"),
                Map.entry(WizCliVersion.V1, "scan vm vm-12345"),
                Map.entry(WizCliVersion.V1, "scan vm-image --region=us-east-1 --subscription-id=abc123 image-id"),
                Map.entry(WizCliVersion.V1, "scan dir /app --disabled-scanners=Malware,Secret --no-publish"),
                Map.entry(WizCliVersion.V1, "scan container-image myapp:v1.0 --driver=extract --no-telemetry"),
                Map.entry(WizCliVersion.V1, "scan dir /app --policies=policy1,policy2 --no-color --stdout=json"),
                Map.entry(WizCliVersion.V1, "scan dir ./src --json-output-file=/tmp/results.json")
        );

    }

    @Test
    public void testValidateCommand() {
        try {
            var version = test.getKey();
            var command = this.test.getValue();
            if (version == WizCliVersion.V0) {
                // V1 supports V0 commands
                WizInputValidator.validateCommand(command, WizCliVersion.V1);
            } else {
                // V0 does not support V1 commands:
                assertThrows(IllegalArgumentException.class, () ->
                        WizInputValidator.validateCommand(command, WizCliVersion.V0));
            }
            WizInputValidator.validateCommand(command, version);
        } catch (Exception e) {
            fail("Expected command to pass validation but got exception: " + e.getMessage());
        }
    }
}