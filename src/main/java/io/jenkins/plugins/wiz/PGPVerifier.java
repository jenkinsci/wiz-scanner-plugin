package io.jenkins.plugins.wiz;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

/**
 * Provides PGP signature verification functionality using the BouncyCastle library.
 * This class handles verification of PGP signatures against provided public keys and signed data.
 * Thread safety: This class is thread-safe as it maintains no state between operations.
 */
public class PGPVerifier {
    private static final Logger LOGGER = Logger.getLogger(PGPVerifier.class.getName());

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Verifies a PGP signature using file paths.
     *
     * @param dataPath Path to the file containing the signed data
     * @param signaturePath Path to the signature file
     * @param publicKeyPath Path to the public key file
     * @return true if signature is valid, false otherwise
     * @throws PGPVerificationException if verification fails due to invalid input or processing errors
     */
    public boolean verifySignatureFromFiles(String dataPath, String signaturePath, String publicKeyPath)
            throws PGPVerificationException {
        try {
            LOGGER.log(Level.FINE, "Starting signature verification for file: {0}", dataPath);

            // Read all required files
            byte[] signedData = readFileWithValidation(dataPath, "data");
            byte[] signature = readFileWithValidation(signaturePath, "signature");
            byte[] publicKey = readFileWithValidation(publicKeyPath, "public key");

            return verifySignature(signedData, signature, publicKey);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to read verification files: {0}", e.getMessage());
            throw new PGPVerificationException("Failed to read verification files", e);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Signature verification failed: {0}", e.getMessage());
            throw new PGPVerificationException("Signature verification failed", e);
        }
    }

    /**
     * Verifies a PGP signature using byte arrays.
     */
    private boolean verifySignature(byte[] signedData, byte[] signature, byte[] publicKey)
            throws PGPVerificationException {
        try {
            validateInput(signedData, signature, publicKey);

            PGPPublicKey pgpPublicKey = readPublicKey(new ByteArrayInputStream(publicKey));
            PGPSignature pgpSignature = readSignature(signature);

            LOGGER.log(Level.FINE, "Verifying signature with key ID: {0}", Long.toHexString(pgpPublicKey.getKeyID()));

            pgpSignature.init(new BcPGPContentVerifierBuilderProvider(), pgpPublicKey);
            pgpSignature.update(signedData);

            boolean result = pgpSignature.verify();
            LOGGER.log(Level.FINE, "Signature verification result: {0}", result);

            return result;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Signature verification failed: {0}", e.getMessage());
            throw new PGPVerificationException("Signature verification failed", e);
        }
    }

    /**
     * Reads and validates a PGP public key.
     */
    private PGPPublicKey readPublicKey(InputStream input) throws PGPVerificationException {
        try (ArmoredInputStream armoredInput = new ArmoredInputStream(input)) {
            PGPPublicKeyRingCollection pgpRings = readKeyRingCollection(armoredInput);
            return findSigningKey(pgpRings);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to read public key: {0}", e.getMessage());
            throw new PGPVerificationException("Failed to read public key", e);
        }
    }

    /**
     * Creates a PGPPublicKeyRingCollection from an input stream.
     */
    private PGPPublicKeyRingCollection readKeyRingCollection(ArmoredInputStream input)
            throws IOException, PGPException {
        return new PGPPublicKeyRingCollection(input, new BcKeyFingerprintCalculator());
    }

    /**
     * Finds a suitable signing key from the key ring collection.
     */
    private PGPPublicKey findSigningKey(PGPPublicKeyRingCollection pgpRings) throws PGPVerificationException {
        for (PGPPublicKeyRing keyRing : pgpRings) {
            PGPPublicKey signingKey = findSigningKeyInRing(keyRing);
            if (signingKey != null) {
                return signingKey;
            }
        }
        throw new PGPVerificationException("No suitable signing key found in provided key ring");
    }

    /**
     * Searches for a signing key within a specific key ring.
     */
    private PGPPublicKey findSigningKeyInRing(PGPPublicKeyRing keyRing) {
        PGPPublicKey masterKey = keyRing.getPublicKey();
        LOGGER.log(Level.FINE, "Processing keyring with master key: {0}", Long.toHexString(masterKey.getKeyID()));

        Iterator<PGPPublicKey> keys = keyRing.getPublicKeys();
        while (keys.hasNext()) {
            PGPPublicKey key = keys.next();
            if (isValidSigningKey(key)) {
                return key;
            }
        }
        return null;
    }

    /**
     * Checks if a key is valid for signing by examining its signatures and flags.
     */
    private boolean isValidSigningKey(PGPPublicKey key) {
        LOGGER.log(Level.FINE, "Examining key: {0}", Long.toHexString(key.getKeyID()));

        Iterator<?> sigs = key.getSignatures();
        while (sigs.hasNext()) {
            if (hasValidSigningFlag(sigs.next(), key)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a signature indicates the key is valid for signing.
     */
    private boolean hasValidSigningFlag(Object sig, PGPPublicKey key) {
        if (!(sig instanceof PGPSignature signature)) {
            return false;
        }

        PGPSignatureSubpacketVector hashedSigs = signature.getHashedSubPackets();

        if (hashedSigs == null) {
            return false;
        }

        int keyFlags = hashedSigs.getKeyFlags();
        LOGGER.log(Level.FINE, "Key flags: {0}", keyFlags);

        if (!key.isMasterKey() && (keyFlags & PGPKeyFlags.CAN_SIGN) != 0) {
            LOGGER.log(Level.FINE, "Found suitable signing key");
            return true;
        }

        return false;
    }

    /**
     * Reads and parses a PGP signature.
     */
    private PGPSignature readSignature(byte[] signatureContent) throws PGPVerificationException {
        LOGGER.log(Level.FINE, "Reading signature data of size: {0} bytes", signatureContent.length);

        try (InputStream sigStream = new ByteArrayInputStream(signatureContent)) {
            // First attempt: Try reading as binary signature
            PGPSignature signature = readBinarySignature(sigStream);
            if (signature != null) {
                return signature;
            }

            // Second attempt: Try reading as ASCII armored
            sigStream.reset();
            signature = readArmoredSignature(sigStream);
            if (signature != null) {
                return signature;
            }

            // Final attempt: Try with BCPGInputStream
            sigStream.reset();
            signature = readRawSignature(sigStream);
            if (signature != null) {
                return signature;
            }

            throw new PGPVerificationException("Failed to read signature in any supported format");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error reading signature data: {0}", e.getMessage());
            throw new PGPVerificationException("Error reading signature data", e);
        }
    }

    /**
     * Attempts to read a binary PGP signature.
     */
    private PGPSignature readBinarySignature(InputStream sigStream) {
        try {
            JcaPGPObjectFactory pgpFactory = new JcaPGPObjectFactory(sigStream);
            Object obj = pgpFactory.nextObject();

            if (obj instanceof PGPSignatureList sigs) {
                if (!sigs.isEmpty()) {
                    LOGGER.log(Level.FINE, "Successfully read binary signature list");
                    return sigs.get(0);
                }
            } else if (obj instanceof PGPSignature) {
                LOGGER.log(Level.FINE, "Successfully read binary signature");
                return (PGPSignature) obj;
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Failed to read binary signature: {0}", e.getMessage());
        }
        return null;
    }

    /**
     * Attempts to read an ASCII armored PGP signature.
     */
    private PGPSignature readArmoredSignature(InputStream sigStream) {
        try {
            InputStream decoderStream = PGPUtil.getDecoderStream(sigStream);
            JcaPGPObjectFactory pgpFactory = new JcaPGPObjectFactory(decoderStream);
            Object obj = pgpFactory.nextObject();

            if (obj instanceof PGPSignatureList sigs) {
                if (!sigs.isEmpty()) {
                    LOGGER.log(Level.FINE, "Successfully read ASCII armored signature list");
                    return sigs.get(0);
                }
            } else if (obj instanceof PGPSignature) {
                LOGGER.log(Level.FINE, "Successfully read ASCII armored signature");
                return (PGPSignature) obj;
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Failed to read ASCII armored signature: {0}", e.getMessage());
        }
        return null;
    }

    /**
     * Attempts to read a raw PGP signature using BCPGInputStream.
     */
    private PGPSignature readRawSignature(InputStream sigStream) {
        try {
            BCPGInputStream bcpgIn = new BCPGInputStream(sigStream);
            PGPSignature signature = new PGPSignature(bcpgIn);
            LOGGER.log(Level.FINE, "Successfully read raw signature");
            return signature;
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Failed to read raw signature: {0}", e.getMessage());
            return null;
        }
    }

    /**
     * Validates input data for signature verification.
     */
    private void validateInput(byte[] signedData, byte[] signature, byte[] publicKey) throws PGPVerificationException {
        if (signedData == null || signedData.length == 0) {
            LOGGER.log(Level.SEVERE, "Signed data validation failed: data is null or empty");
            throw new PGPVerificationException("Signed data is null or empty");
        }
        if (signature == null || signature.length == 0) {
            LOGGER.log(Level.SEVERE, "Signature validation failed: signature is null or empty");
            throw new PGPVerificationException("Signature is null or empty");
        }
        if (publicKey == null || publicKey.length == 0) {
            LOGGER.log(Level.SEVERE, "Public key validation failed: key is null or empty");
            throw new PGPVerificationException("Public key is null or empty");
        }
    }

    /**
     * Reads a file with validation checks.
     */
    private byte[] readFileWithValidation(String path, String fileType) throws IOException {
        if (path == null || path.trim().isEmpty()) {
            LOGGER.log(Level.SEVERE, "Invalid {0} file path: null or empty", fileType);
            throw new IOException(fileType + " path is null or empty");
        }

        try {
            byte[] content = Files.readAllBytes(Paths.get(path));
            if (content.length == 0) {
                LOGGER.log(Level.SEVERE, "Empty {0} file: {1}", new Object[] {fileType, path});
                throw new IOException(fileType + " file is empty");
            }
            LOGGER.log(Level.FINE, "Successfully read {0} file: {1}, size: {2} bytes", new Object[] {
                fileType, path, content.length
            });
            return content;
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to read {0} file {1}: {2}", new Object[] {fileType, path, e.getMessage()});
            throw new IOException("Failed to read " + fileType + " file: " + path, e);
        }
    }

    /**
     * Custom exception for PGP verification errors.
     */
    public static class PGPVerificationException extends Exception {
        public PGPVerificationException(String message) {
            super(message);
        }

        public PGPVerificationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
