package org.example.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.NamedParameterSpec;

public class KeyManager {
    private static final Path BASE = Paths.get(System.getProperty("user.home"), ".byteshare");
    private static final Path PUB = BASE.resolve("receiver_pub.key");
    private static final Path PRIV = BASE.resolve("receiver_priv.key");

    static {
        // Register Bouncy Castle as a provider if not already registered
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static KeyPair loadOrCreateKeyPair() throws Exception {
        if (java.nio.file.Files.exists(PUB) && java.nio.file.Files.exists(PRIV)) {
            String pubB64 = KeyExchangeUtils.readStringFromFile(PUB);
            String privB64 = KeyExchangeUtils.readStringFromFile(PRIV);
            return new KeyPair(
                    KeyExchangeUtils.publicKeyFromBase64(pubB64),
                    KeyExchangeUtils.privateKeyFromBase64(privB64)
            );
        } else {
            // Use BouncyCastle provider explicitly
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "BC");
            kpg.initialize(new NamedParameterSpec("X25519"), SecureRandom.getInstanceStrong());
            KeyPair kp = kpg.generateKeyPair();

            String pubB64 = KeyExchangeUtils.publicKeyToBase64(kp.getPublic());
            String privB64 = KeyExchangeUtils.privateKeyToBase64(kp.getPrivate());

            KeyExchangeUtils.saveStringToFile(pubB64, PUB);
            KeyExchangeUtils.saveStringToFile(privB64, PRIV);

            return kp;
        }
    }
}
