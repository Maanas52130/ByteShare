package org.example.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyAgreement;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class KeyExchangeUtils {
    private static final String X25519 = "X25519";
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final int HASH_LEN = 32; // SHA-256 length in bytes

    // Load BouncyCastle provider at class load time
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** Generate X25519 key pair */
    public static KeyPair generateX25519KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(X25519, "BC");
        kpg.initialize(new NamedParameterSpec(X25519));
        return kpg.generateKeyPair();
    }

    public static String publicKeyToBase64(PublicKey pub) {
        return Base64.getEncoder().encodeToString(pub.getEncoded());
    }

    public static String privateKeyToBase64(PrivateKey priv) {
        return Base64.getEncoder().encodeToString(priv.getEncoded());
    }

    public static PublicKey publicKeyFromBase64(String b64) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(b64);
        KeyFactory kf = KeyFactory.getInstance(X25519, "BC");
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        return kf.generatePublic(spec);
    }

    public static PrivateKey privateKeyFromBase64(String b64) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(b64);
        KeyFactory kf = KeyFactory.getInstance(X25519, "BC");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
        return kf.generatePrivate(spec);
    }

    /** Derive raw shared secret bytes from private key and peer public key */
    public static byte[] deriveSharedSecret(PrivateKey ourPriv, PublicKey theirPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance(X25519, "BC");
        ka.init(ourPriv);
        ka.doPhase(theirPub, true);
        return ka.generateSecret(); // 32 bytes for X25519
    }

    // HMAC-SHA256 helper
    private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(new SecretKeySpec(key, HMAC_SHA256));
        return mac.doFinal(data);
    }

    /** HKDF-Extract(salt, ikm) -> prk */
    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws Exception {
        if (salt == null || salt.length == 0) salt = new byte[HASH_LEN];
        return hmacSha256(salt, ikm);
    }

    /** HKDF-Expand(prk, info, length) -> okm */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws Exception {
        if (length < 0) throw new IllegalArgumentException("length must be non-negative");
        int n = (int) Math.ceil((double) length / HASH_LEN);
        if (n > 255) throw new IllegalArgumentException("Cannot expand to more than 255 blocks");
        byte[] okm = new byte[length];
        byte[] t = new byte[0];
        int copied = 0;
        for (int i = 1; i <= n; i++) {
            int dataLen = t.length + (info == null ? 0 : info.length) + 1;
            byte[] data = new byte[dataLen];
            System.arraycopy(t, 0, data, 0, t.length);
            if (info != null) System.arraycopy(info, 0, data, t.length, info.length);
            data[data.length - 1] = (byte) i;
            t = hmacSha256(prk, data);
            int toCopy = Math.min(HASH_LEN, length - copied);
            System.arraycopy(t, 0, okm, copied, toCopy);
            copied += toCopy;
        }
        return okm;
    }

    /** Derive KEK from shared secret using HKDF-SHA256 */
    public static byte[] deriveKekFromSharedSecret(PrivateKey ourPriv, PublicKey peerPub, int kekLenBytes) throws Exception {
        byte[] shared = deriveSharedSecret(ourPriv, peerPub);
        byte[] prk = hkdfExtract(null, shared);
        byte[] info = "ByteShare X25519 HKDF v1".getBytes(StandardCharsets.UTF_8);
        byte[] okm = hkdfExpand(prk, info, kekLenBytes);
        // Zero sensitive arrays best-effort
        java.util.Arrays.fill(shared, (byte) 0);
        java.util.Arrays.fill(prk, (byte) 0);
        return okm;
    }

    /** Wrap AES key with KEK derived from X25519 */
    public static byte[] wrapAesKeyWithX25519(PrivateKey senderPriv, PublicKey receiverPub, byte[] aesKeyBytes) throws Exception {
        byte[] kek = deriveKekFromSharedSecret(senderPriv, receiverPub, 32);
        try {
            return CryptoUtils.encryptBytesWithAesGcm(aesKeyBytes, kek);
        } finally {
            java.util.Arrays.fill(kek, (byte) 0);
        }
    }

    /** Unwrap AES key with KEK derived from X25519 */
    public static byte[] unwrapAesKeyWithX25519(PrivateKey receiverPriv, PublicKey senderEphemeralPub, byte[] wrappedBytes) throws Exception {
        byte[] kek = deriveKekFromSharedSecret(receiverPriv, senderEphemeralPub, 32);
        try {
            return CryptoUtils.decryptBytesWithAesGcm(wrappedBytes, kek);
        } finally {
            java.util.Arrays.fill(kek, (byte) 0);
        }
    }

    // File I/O helpers

    public static void saveStringToFile(String data, Path path) throws Exception {
        Files.createDirectories(path.getParent());
        Files.write(path, data.getBytes(StandardCharsets.UTF_8));
    }

    public static String readStringFromFile(Path path) throws Exception {
        return Files.readString(path, StandardCharsets.UTF_8);
    }
}
