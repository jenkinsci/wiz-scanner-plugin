package io.jenkins.plugins.wiz;

import hudson.AbortException;
import hudson.FilePath;
import hudson.ProxyConfiguration;
import hudson.model.TaskListener;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import jenkins.security.MasterToSlaveCallable;
import org.apache.commons.lang3.SystemUtils;

/**
 * Handles downloading and verifying the Wiz CLI binary.
 */
public class WizCliDownloader {
    private static final Logger LOGGER = Logger.getLogger(WizCliDownloader.class.getName());
    private static final int DOWNLOAD_TIMEOUT = 60000; // 60 seconds
    private static final int CONNECT_TIMEOUT = 10000; // 10 seconds
    private static final String PUBLIC_KEY_RESOURCE = "/io/jenkins/plugins/wiz/public_key.asc";

    /**
     * Sets up the Wiz CLI by downloading and verifying the binary.
     */
    public static WizCliSetup setupWizCli(FilePath workspace, String wizCliURL, TaskListener listener)
            throws IOException {
        try {
            ParsedWizCliUrl parsedUrl = WizInputValidator.parseWizCliUrl(wizCliURL);

            // Detect OS and architecture on the agent
            String[] osDetails = workspace.act(new MasterToSlaveCallable<String[], IOException>() {
                @Override
                public String[] call() {
                    boolean isWindows = SystemUtils.IS_OS_WINDOWS;
                    return new String[] {
                        String.valueOf(isWindows),
                    };
                }
            });

            boolean isWindows = Boolean.parseBoolean(osDetails[0]);

            String cliFileName = isWindows ? WizCliSetup.WIZCLI_WINDOWS_PATH : WizCliSetup.WIZCLI_UNIX_PATH;
            FilePath cliPath = workspace.child(cliFileName);

            downloadAndVerifyWizCli(parsedUrl.getUrl(), cliPath, workspace, listener);

            if (!isWindows) {
                cliPath.chmod(0755);
            }

            return new WizCliSetup(isWindows, parsedUrl.getVersion());

        } catch (AbortException e) {
            listener.error("Invalid Wiz CLI URL format: " + e.getMessage());
            throw e;
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private static void downloadAndVerifyWizCli(
            String wizCliURL, FilePath cliPath, FilePath workspace, TaskListener listener) throws IOException {
        try {
            // Download CLI
            listener.getLogger().println("Downloading Wiz CLI from: " + wizCliURL);
            downloadFile(wizCliURL, cliPath);
            listener.getLogger().println("Download completed successfully");

            // Construct verification file URLs
            String sha256URL = wizCliURL + "-sha256";
            String signatureURL = sha256URL + ".sig";

            // Create FilePath objects for verification files
            FilePath sha256File = workspace.child("wizcli-sha256");
            FilePath signatureFile = workspace.child("wizcli-sha256.sig");
            FilePath publicKeyFile = workspace.child("public_key.asc");

            try {
                // Download verification files
                downloadFile(sha256URL, sha256File);
                downloadFile(signatureURL, signatureFile);

                // Extract public key from resources
                extractPublicKey(publicKeyFile);

                // Verify signature and checksum
                verifySignatureAndChecksum(listener, cliPath, sha256File, signatureFile, publicKeyFile, workspace);

            } finally {
                // Clean up verification files
                cleanupVerificationFiles(workspace, listener);
            }
        } catch (Exception e) {
            listener.error("Failed to download or verify Wiz CLI: " + e.getMessage());
            throw new AbortException("Failed to setup Wiz CLI: " + e.getMessage());
        }
    }

    private static void extractPublicKey(FilePath publicKeyFile) throws IOException {
        try (InputStream keyStream = WizCliDownloader.class.getResourceAsStream(PUBLIC_KEY_RESOURCE)) {
            if (keyStream == null) {
                throw new IOException("Could not find public key resource");
            }

            // Read the public key from resources
            String publicKey = new String(keyStream.readAllBytes(), StandardCharsets.UTF_8);

            // Write to workspace
            publicKeyFile.write(publicKey, StandardCharsets.UTF_8.name());

            LOGGER.log(Level.FINE, "Public key extracted successfully");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to extract public key", e);
            throw new IOException("Failed to extract public key from resources", e);
        }
    }

    private static void downloadFile(String fileURL, FilePath targetPath) throws IOException {
        URL url = new URL(fileURL);
        HttpURLConnection conn = null;
        InputStream inputStream = null;
        OutputStream outputStream = null;

        try {
            ProxyConfiguration proxyConfig = Jenkins.get().getProxy();
            try {
                conn = (HttpURLConnection)
                        (proxyConfig != null
                                ? url.openConnection(proxyConfig.createProxy(url.getHost()))
                                : url.openConnection());
            } catch (IllegalArgumentException e) {
                throw new IOException("Invalid proxy configuration", e);
            }

            conn.setConnectTimeout(CONNECT_TIMEOUT);
            conn.setReadTimeout(DOWNLOAD_TIMEOUT);

            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("Download failed with HTTP code: " + responseCode);
            }

            FilePath parent = targetPath.getParent();
            if (parent == null) {
                throw new IOException("Invalid target path: parent directory is null");
            }

            try {
                parent.mkdirs();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Directory creation was interrupted", e);
            }

            inputStream = conn.getInputStream();
            try {
                outputStream = targetPath.write();
                byte[] buffer = new byte[8192]; // 8KB buffer
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("File download was interrupted", e);
            }
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Error closing input stream", e);
                }
            }
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Error closing output stream", e);
                }
            }
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static void verifySignatureAndChecksum(
            TaskListener listener,
            FilePath cliPath,
            FilePath sha256File,
            FilePath signaturePath,
            FilePath publicKeyPath,
            FilePath workspace)
            throws IOException {
        try {
            boolean verified = workspace.act(new VerifySignatureCallable(sha256File, signaturePath, publicKeyPath));

            if (!verified) {
                throw new IOException("GPG signature verification failed");
            }

            // Continue with checksum verification
            verifyChecksum(cliPath, sha256File);
            listener.getLogger().println("Successfully verified Wiz CLI signature and checksum");
        } catch (Exception e) {
            throw new IOException("GPG signature verification failed: " + e.getMessage(), e);
        }
    }

    private static void verifyChecksum(FilePath cliPath, FilePath sha256File) throws IOException, InterruptedException {
        String expectedHash = sha256File.readToString().trim();
        String actualHash = calculateSHA256(cliPath);

        if (!expectedHash.equals(actualHash)) {
            throw new IOException(
                    "SHA256 checksum verification failed. Expected: " + expectedHash + ", Actual: " + actualHash);
        }
    }

    private static String calculateSHA256(FilePath filePath) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192]; // 8KB buffer size
            int bytesRead;

            try (InputStream inputStream = filePath.read()) {
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            byte[] hash = digest.digest();
            StringBuilder hexString = new StringBuilder();

            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (Exception e) {
            throw new IOException("Failed to calculate SHA256: " + e.getMessage(), e);
        }
    }

    private static void cleanupVerificationFiles(FilePath workspace, TaskListener listener) {
        FilePath[] filesToClean = {
            workspace.child("wizcli-sha256"), workspace.child("wizcli-sha256.sig"), workspace.child("public_key.asc")
        };

        for (FilePath file : filesToClean) {
            try {
                if (file.exists()) {
                    file.delete();
                    LOGGER.log(Level.FINE, "Deleted verification file: {0}", file.getRemote());
                }
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to delete verification file: " + file.getRemote(), e);
                listener.getLogger().println("Warning: Failed to delete " + file.getRemote());
            }
        }
    }

    private static class VerifySignatureCallable extends MasterToSlaveCallable<Boolean, IOException> {
        private final FilePath sha256File;
        private final FilePath signaturePath;
        private final FilePath publicKeyPath;

        public VerifySignatureCallable(FilePath sha256File, FilePath signaturePath, FilePath publicKeyPath) {
            this.sha256File = sha256File;
            this.signaturePath = signaturePath;
            this.publicKeyPath = publicKeyPath;
        }

        @Override
        public Boolean call() throws IOException {
            try {
                PGPVerifier verifier = new PGPVerifier();
                return verifier.verifySignatureFromFiles(
                        sha256File.getRemote(), signaturePath.getRemote(), publicKeyPath.getRemote());
            } catch (PGPVerifier.PGPVerificationException e) {
                throw new IOException("PGP verification failed", e);
            }
        }
    }
}
