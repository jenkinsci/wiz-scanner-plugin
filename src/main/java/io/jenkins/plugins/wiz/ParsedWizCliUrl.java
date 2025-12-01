package io.jenkins.plugins.wiz;

/**
 * Represents a validated and parsed Wiz CLI download URL with version information.
 */
public class ParsedWizCliUrl {
    private final String url;
    private final WizCliVersion version;

    /**
     * Creates a new ParsedWizCliUrl instance.
     *
     * @param url the validated URL string
     * @param version the detected CLI version
     */
    public ParsedWizCliUrl(String url, WizCliVersion version) {
        this.url = url;
        this.version = version;
    }

    /**
     * Gets the CLI version detected from the URL.
     *
     * @return the CLI version
     */
    public WizCliVersion getVersion() {
        return version;
    }

    /**
     * Gets the URL as a string.
     *
     * @return the URL string
     */
    public String getUrl() {
        return url;
    }

    /**
     * Returns the URL string representation.
     *
     * @return the URL string
     */
    @Override
    public String toString() {
        return url;
    }
}
