package io.jenkins.plugins.wiz;

import hudson.AbortException;
import hudson.FilePath;
import hudson.model.Run;
import hudson.util.Secret;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;

/**
 * Validator for Wiz CLI inputs and commands.
 */
public class WizInputValidator {
    private static final Pattern URL_PATTERN =
            Pattern.compile("https://downloads\\.wiz\\.io/(v1/)?wizcli/([^/]+)/([^/]+)");

    private static final Set<String> V0_ALLOWED_ROOT_COMMANDS =
            new HashSet<>(Arrays.asList("auth", "dir", "docker", "iac"));
    private static final Set<String> V1_ALLOWED_ROOT_COMMANDS =
            new HashSet<>(Arrays.asList("auth", "dir", "docker", "iac", "scan"));

    private static final Map<String, Set<String>> V0_ALLOWED_SUBCOMMANDS = new HashMap<>();
    private static final Map<String, Set<String>> V1_ALLOWED_SUBCOMMANDS = new HashMap<>();

    static {
        V0_ALLOWED_SUBCOMMANDS.put("dir", new HashSet<>(List.of("scan")));
        V0_ALLOWED_SUBCOMMANDS.put("docker", new HashSet<>(List.of("scan")));
        V0_ALLOWED_SUBCOMMANDS.put("iac", new HashSet<>(List.of("scan")));

        V1_ALLOWED_SUBCOMMANDS.putAll(V0_ALLOWED_SUBCOMMANDS);
        V1_ALLOWED_SUBCOMMANDS.put("scan", new HashSet<>(List.of("dir", "container-image", "vm", "vm-image")));
    }

    /**
     * Validates the global configuration parameters
     */
    public static void validateConfiguration(String wizClientId, Secret wizSecretKey, String wizCliURL)
            throws AbortException {
        if (StringUtils.isBlank(wizClientId)) {
            throw new AbortException("Wiz Client ID is required");
        }
        if (wizSecretKey == null || StringUtils.isBlank(Secret.toString(wizSecretKey))) {
            throw new AbortException("Wiz Secret Key is required");
        }
        if (StringUtils.isBlank(wizCliURL)) {
            throw new AbortException("Wiz CLI URL is required");
        }
    }

    /**
     * Validates scan action parameters
     */
    public static void validateScanAction(Run<?, ?> build, FilePath workspace, String artifactName)
            throws IllegalArgumentException {
        if (build == null) throw new IllegalArgumentException("Build cannot be null");
        if (workspace == null) throw new IllegalArgumentException("Workspace cannot be null");
        if (artifactName == null) throw new IllegalArgumentException("Artifact name cannot be null");
    }

    /**
     * Parses and validates the Wiz CLI download URL, detecting the CLI version.
     *
     * @param url the Wiz CLI download URL
     * @return a ParsedWizCliUrl object containing the URL and detected version
     * @throws AbortException if the URL format is invalid
     */
    public static ParsedWizCliUrl parseWizCliUrl(String url) throws AbortException {
        if (!URL_PATTERN.matcher(url).matches()) {
            throw new AbortException(
                    "Invalid Wiz CLI URL format. Expected: "
                            + "https://downloads.wiz.io/wizcli/{version}/{binary_name} or https://downloads.wiz.io/v1/wizcli/{version}/{binary_name}");
        }

        WizCliVersion version;
        if (url.contains("v1/wizcli/") || url.matches(".*wizcli/1\\..*")) {
            version = WizCliVersion.V1;
        } else {
            version = WizCliVersion.V0;
        }

        return new ParsedWizCliUrl(url, version);
    }

    /**
     * Detects the CLI version from the URL.
     *
     * <p>Version detection rules:
     * <ul>
     *   <li>V1: URLs containing "v1/wizcli/" or "wizcli/1."</li>
     *   <li>V0: All other valid Wiz CLI URLs</li>
     * </ul>
     *
     * @param url the Wiz CLI download URL
     * @return the detected CLI version
     */
    private static WizCliVersion detectVersionFromUrl(String url) {

        // Check for v1/wizcli pattern (e.g., https://downloads.wiz.io/v1/wizcli/latest/...)
        if (url.contains("v1/wizcli/")) {
            return WizCliVersion.V1;
        }

        // Check for wizcli/1.x.x pattern (e.g., https://downloads.wiz.io/wizcli/1.0.2/...)
        if (url.matches(".*wizcli/1\\..*")) {
            return WizCliVersion.V1;
        }

        // Default to V0 for all other cases (including wizcli/0.x.x and wizcli/latest)
        return WizCliVersion.V0;
    }

    /**
     * Validates the command structure and arguments.
     */
    public static void validateCommand(String userInput, WizCliVersion version) throws IllegalArgumentException {
        if (StringUtils.isBlank(userInput)) {
            throw new IllegalArgumentException("No command provided");
        }

        List<String> arguments = parseArgumentsRespectingQuotes(userInput);
        if (arguments.isEmpty()) {
            throw new IllegalArgumentException("No valid arguments provided");
        }

        String rootCommand = arguments.get(0);
        var allowedRootCommands = version == WizCliVersion.V0 ? V0_ALLOWED_ROOT_COMMANDS : V1_ALLOWED_ROOT_COMMANDS;
        var allowedSubCommands = version == WizCliVersion.V0 ? V0_ALLOWED_SUBCOMMANDS : V1_ALLOWED_SUBCOMMANDS;
        if (!allowedRootCommands.contains(rootCommand)) {
            throw new IllegalArgumentException(
                    "Invalid command. Allowed commands are: " + String.join(", ", allowedRootCommands));
        }

        if (allowedSubCommands.containsKey(rootCommand) && arguments.size() > 1) {
            String subcommand = arguments.get(1);
            Set<String> allowedSubcommands = allowedSubCommands.get(rootCommand);

            if (!allowedSubcommands.contains(subcommand)) {
                throw new IllegalArgumentException("Invalid subcommand for " + rootCommand
                        + ". Allowed subcommands are: " + String.join(", ", allowedSubcommands));
            }
        }

        // Validate each argument
        for (String arg : arguments) {
            validateArgument(arg);
        }
    }

    private static List<String> parseArgumentsRespectingQuotes(String input) {
        List<String> arguments = new ArrayList<>();
        Matcher matcher = Pattern.compile("[^\\s\"']+|\"([^\"]*)\"|'([^']*)'").matcher(input);

        while (matcher.find()) {
            String arg = matcher.group();
            if (arg.startsWith("\"") && arg.endsWith("\"") || arg.startsWith("'") && arg.endsWith("'")) {
                arg = arg.substring(1, arg.length() - 1);
            }
            arguments.add(arg);
        }

        return arguments;
    }

    private static void validateArgument(String arg) {
        if (StringUtils.isBlank(arg)) {
            throw new IllegalArgumentException("Empty argument provided");
        }

        // Check for potential command injection characters
        if (arg.contains(";")
                || arg.contains("|")
                || arg.contains("&")
                || arg.contains(">")
                || arg.contains("<")
                || arg.contains("`")) {
            throw new IllegalArgumentException("Invalid characters in argument: " + arg);
        }
    }
}
