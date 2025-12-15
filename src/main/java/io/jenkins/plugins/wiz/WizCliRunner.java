package io.jenkins.plugins.wiz;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Launcher.ProcStarter;
import hudson.model.TaskListener;
import hudson.util.ArgumentListBuilder;
import hudson.util.Secret;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Main executor class for Wiz CLI operations. Handles command building, execution,
 * and output processing in a structured way.
 */
public class WizCliRunner {
    private static final Logger LOGGER = Logger.getLogger(WizCliRunner.class.getName());
    private static final String OUTPUT_FILENAME = "wizcli_output";
    private static final String ERROR_FILENAME = "wizcli_err_output";

    /**
     * Execute a complete Wiz CLI workflow including setup, authentication, and scanning.
     */
    public static int execute(
            FilePath workspace,
            EnvVars env,
            Launcher launcher,
            TaskListener listener,
            String wizCliURL,
            String wizClientId,
            Secret wizSecretKey,
            String userInput,
            String artifactName)
            throws IOException, InterruptedException {

        WizCliSetup cliSetup = null;
        try {
            // Download and setup CLI
            cliSetup = WizCliDownloader.setupWizCli(workspace, wizCliURL, listener);

            // Authenticate
            WizCliAuthenticator.authenticate(launcher, workspace, env, wizClientId, wizSecretKey, listener, cliSetup);

            // Execute scan
            return executeScan(workspace, env, launcher, listener, userInput, artifactName, cliSetup);

        } catch (Exception e) {
            throw new AbortException("Error executing Wiz CLI: " + e.getMessage());
        } finally {
            if (cliSetup != null) {
                try {
                    int logoutResult = WizCliAuthenticator.logout(launcher, workspace, env, listener, cliSetup);

                    if (logoutResult != 0) {
                        LOGGER.warning("Failed to logout from Wiz CLI. Exit code: " + logoutResult);
                    }
                } catch (Exception e) {
                    // Log but don't fail the build if logout fails
                    LOGGER.log(Level.WARNING, "Error during Wiz CLI logout", e);
                    listener.error("Warning: Failed to logout from Wiz CLI: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Executes the actual scan command after setup and authentication are complete.
     */
    private static int executeScan(
            FilePath workspace,
            EnvVars env,
            Launcher launcher,
            TaskListener listener,
            String userInput,
            String artifactName,
            WizCliSetup cliSetup)
            throws IOException, InterruptedException {

        listener.getLogger().println("Executing Wiz scan...");

        // Validate command before execution
        try {
            WizInputValidator.validateCommand(userInput, cliSetup.getVersion());
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.SEVERE, "Command validation failed", e);
            listener.getLogger().println("Error: Invalid command: " + e.getMessage());
            return -1;
        }

        FilePath outputFile = workspace.child(OUTPUT_FILENAME);
        FilePath errorFile = workspace.child(ERROR_FILENAME);

        ArgumentListBuilder scanArgs = buildScanArguments(userInput, cliSetup);
        listener.getLogger().println("Executing command: " + scanArgs);

        int exitCode = executeScanProcess(launcher, workspace, env, scanArgs, outputFile, errorFile);

        if (exitCode != 0 && errorFile.exists()) {
            listener.error("Scan failed with error output:");
            listener.getLogger().println(errorFile.readToString());
        }

        copyOutputToArtifact(outputFile, workspace, artifactName);

        return exitCode;
    }

    /**
     * Builds the scan command arguments, properly handling quoted strings and ensuring JSON output.
     */
    private static ArgumentListBuilder buildScanArguments(String userInput, WizCliSetup cliSetup) {
        ArgumentListBuilder args = new ArgumentListBuilder();
        args.add(cliSetup.getCliCommand());

        // Split and add user input, respecting quotes
        if (userInput != null && !userInput.trim().isEmpty()) {
            Pattern pattern = Pattern.compile("[^\\s\"']+|\"([^\"]*)\"|'([^']*)'");
            Matcher matcher = pattern.matcher(userInput.trim());

            while (matcher.find()) {
                String arg = matcher.group();
                // Remove surrounding quotes if present
                if ((arg.startsWith("\"") && arg.endsWith("\"")) || (arg.startsWith("'") && arg.endsWith("'"))) {
                    arg = arg.substring(1, arg.length() - 1);
                }
                args.add(arg);
            }
        }

        // Ensure JSON output format if not specified
        assert userInput != null;
        if (cliSetup.getVersion() == WizCliVersion.V0) {
            if (!userInput.contains("-f") && !userInput.contains("--format")) {
                args.add("-f", "json");
            }
        } else {
            if (!userInput.contains("--stdout")) {
                args.add("--stdout", "json");
            }
        }

        return args;
    }

    /**
     * Executes the scan process with proper stream handling and cleanup.
     */
    private static int executeScanProcess(
            Launcher launcher,
            FilePath workspace,
            EnvVars env,
            ArgumentListBuilder args,
            FilePath outputFile,
            FilePath errorFile)
            throws IOException, InterruptedException {

        ProcStarter proc = launcher.launch()
                .cmds(args)
                .pwd(workspace)
                .envs(env)
                .stdout(outputFile.write())
                .stderr(errorFile.write());

        return proc.join();
    }

    /**
     * Copies the scan output to an artifact file in the workspace.
     */
    private static void copyOutputToArtifact(FilePath outputFile, FilePath workspace, String artifactName)
            throws IOException, InterruptedException {
        FilePath target = workspace.child(artifactName);
        outputFile.copyTo(target);
    }
}
