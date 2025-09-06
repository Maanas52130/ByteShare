package org.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * AES-GCM streaming utilities.
 * - encryptStream / decryptStream handle arbitrarily large files (IV prepended)
 * - encryptBytesWithAesGcm / decryptBytesWithAesGcm used for wrapping small secrets
 */
public class CryptoUtils {
    private static final String AES = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int AES_KEY_BITS = 256;
    private static final int IV_LEN = 12; // 96-bit IV for GCM
    private static final int TAG_BITS = 128;
    private static final int BUFFER = 64 * 1024; // 64 KiB

    // Single RNG instance: prefer getInstanceStrong, but safely fall back if necessary.
    private static final SecureRandom RNG;
    static {
        SecureRandom tmp;
        try {
            tmp = SecureRandom.getInstanceStrong();
        } catch (Exception e) {
            tmp = new SecureRandom();
        }
        RNG = tmp;
    }

    public static SecretKey generateAesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(AES);
        kg.init(AES_KEY_BITS, RNG);
        return kg.generateKey();
    }

    /**
     * Encrypt input stream to output stream using AES-GCM.
     * Writes IV (IV_LEN bytes) as the first bytes to the output stream.
     * Streams the ciphertext; low memory use.
     */
    public static void encryptStream(InputStream in, OutputStream out, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_LEN];
        RNG.nextBytes(iv);

        // write IV first
        out.write(iv);

        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        try (CipherOutputStream cos = new CipherOutputStream(out, cipher)) {
            byte[] buffer = new byte[BUFFER];
            int r;
            while ((r = in.read(buffer)) != -1) {
                cos.write(buffer, 0, r);
            }
            cos.flush();
        }
    }

    /**
     * Decrypt input stream (which must start with IV_LEN bytes of IV) to output stream.
     */
    public static void decryptStream(InputStream in, OutputStream out, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_LEN];
        int read = 0;
        while (read < IV_LEN) {
            int r = in.read(iv, read, IV_LEN - read);
            if (r == -1) throw new IllegalStateException("Unexpected end of stream while reading IV");
            read += r;
        }

        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        try (CipherInputStream cis = new CipherInputStream(in, cipher)) {
            byte[] buffer = new byte[BUFFER];
            int r;
            while ((r = cis.read(buffer)) != -1) {
                out.write(buffer, 0, r);
            }
            out.flush();
        }
    }

    /**
     * AES-GCM encrypt a small byte array (plaintext) with provided KEK bytes.
     * Returns IV || ciphertext bytes.
     */
    public static byte[] encryptBytesWithAesGcm(byte[] plaintext, byte[] kek) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(kek, AES);
        byte[] iv = new byte[IV_LEN];
        RNG.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
        byte[] ct = cipher.doFinal(plaintext);

        byte[] out = new byte[IV_LEN + ct.length];
        System.arraycopy(iv, 0, out, 0, IV_LEN);
        System.arraycopy(ct, 0, out, IV_LEN, ct.length);
        return out;
    }

    /**
     * Decrypt bytes produced by encryptBytesWithAesGcm (IV||ciphertext).
     */
    public static byte[] decryptBytesWithAesGcm(byte[] ivAndCiphertext, byte[] kek) throws Exception {
        if (ivAndCiphertext.length < IV_LEN) throw new IllegalArgumentException("Invalid input");
        byte[] iv = new byte[IV_LEN];
        System.arraycopy(ivAndCiphertext, 0, iv, 0, IV_LEN);
        byte[] ct = new byte[ivAndCiphertext.length - IV_LEN];
        System.arraycopy(ivAndCiphertext, IV_LEN, ct, 0, ct.length);

        SecretKeySpec keySpec = new SecretKeySpec(kek, AES);
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
        return cipher.doFinal(ct);
    }

    public static SecretKey secretKeyFromBytes(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, AES);
    }
}
