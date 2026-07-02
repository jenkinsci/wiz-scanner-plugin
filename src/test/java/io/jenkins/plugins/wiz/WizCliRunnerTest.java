package io.jenkins.plugins.wiz;

import static org.junit.Assert.*;

import hudson.FilePath;
import hudson.util.ArgumentListBuilder;
import java.lang.reflect.Method;
import java.util.List;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class WizCliRunnerTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void testBuildScanArgumentsAddsJsonOutputFileForV1() throws Exception {
        ArgumentListBuilder args = buildScanArguments(
                "scan container-image my-nginx:9", new WizCliSetup(false, WizCliVersion.V1), "wizscan.json");

        List<String> argList = args.toList();

        assertTrue(argList.contains("--json-output-file"));
        assertEquals("wizscan.json", argList.get(argList.indexOf("--json-output-file") + 1));
        assertTrue(argList.contains("--stdout"));
        assertEquals("json", argList.get(argList.indexOf("--stdout") + 1));
    }

    @Test
    public void testBuildScanArgumentsDoesNotDuplicateJsonOutputFileForV1() throws Exception {
        ArgumentListBuilder args = buildScanArguments(
                "scan container-image my-nginx:9 --json-output-file custom.json --stdout json",
                new WizCliSetup(false, WizCliVersion.V1),
                "wizscan.json");

        List<String> argList = args.toList();

        assertEquals(1, countOccurrences(argList, "--json-output-file"));
        assertEquals("custom.json", argList.get(argList.indexOf("--json-output-file") + 1));
        assertEquals(1, countOccurrences(argList, "--stdout"));
    }

    @Test
    public void testCopyOutputToArtifactDoesNotOverwriteExistingJsonFile() throws Exception {
        FilePath workspace = new FilePath(temporaryFolder.newFolder("workspace"));
        FilePath outputFile = workspace.child("wizcli_output");
        FilePath artifact = workspace.child("wizscan.json");

        outputFile.write("banner and mixed stdout", "UTF-8");
        artifact.write("{\"source\":\"json-output-file\"}", "UTF-8");

        copyOutputToArtifact(outputFile, workspace, "wizscan.json");

        assertEquals("{\"source\":\"json-output-file\"}", artifact.readToString());
    }

    @Test
    public void testCopyOutputToArtifactFallsBackToStdoutWhenJsonFileMissing() throws Exception {
        FilePath workspace = new FilePath(temporaryFolder.newFolder("workspace"));
        FilePath outputFile = workspace.child("wizcli_output");
        FilePath artifact = workspace.child("wizscan.json");

        outputFile.write("{\"source\":\"stdout\"}", "UTF-8");

        copyOutputToArtifact(outputFile, workspace, "wizscan.json");

        assertEquals("{\"source\":\"stdout\"}", artifact.readToString());
    }

    private static ArgumentListBuilder buildScanArguments(String userInput, WizCliSetup cliSetup, String artifactName)
            throws Exception {
        Method method = WizCliRunner.class.getDeclaredMethod(
                "buildScanArguments", String.class, WizCliSetup.class, String.class);
        method.setAccessible(true);
        return (ArgumentListBuilder) method.invoke(null, userInput, cliSetup, artifactName);
    }

    private static void copyOutputToArtifact(FilePath outputFile, FilePath workspace, String artifactName)
            throws Exception {
        Method method = WizCliRunner.class.getDeclaredMethod(
                "copyOutputToArtifact", FilePath.class, FilePath.class, String.class);
        method.setAccessible(true);
        method.invoke(null, outputFile, workspace, artifactName);
    }

    private static int countOccurrences(List<String> items, String needle) {
        int count = 0;
        for (String item : items) {
            if (needle.equals(item)) {
                count++;
            }
        }
        return count;
    }
}
