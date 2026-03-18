import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * CryptoUtils:
 * - RSA key generation
 * - RSA encrypt/decrypt (Base64 for sending over sockets)
 * - RSA signature + verify (this is how we "use PRK" safely)
 * - AES encrypt/decrypt for Phase 2 (E(KA, ...) and E(KB, ...))
 */
public class CryptoUtils {


    // 1) RSA KEY GENERATION

    public static KeyPair genRSA() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    // Convert a public key to Base64 string (so we can send it over sockets)
    public static String pubToB64(PublicKey k) {
        return Base64.getEncoder().encodeToString(k.getEncoded());
    }

    // Convert Base64 string back into a PublicKey
    public static PublicKey pubFromB64(String b64) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    }


    // 2) RSA ENCRYPT / DECRYPT

    // Encrypt a short message using RSA (works for <=245 bytes with 2048-bit key and PKCS1 padding)
    public static String rsaEncB64(String msg, Key key) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] ct = c.doFinal(msg.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct);
    }

    // Decrypt RSA ciphertext (Base64 string)
    public static String rsaDecB64(String b64, Key key) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] pt = c.doFinal(Base64.getDecoder().decode(b64));
        return new String(pt, StandardCharsets.UTF_8);
    }


    // 3) RSA SIGNATURE (PRK usage)

    // This is the correct way to use PRK to prove the KDC created the key (authenticity).
    public static String signToB64(String message, PrivateKey prk) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(prk);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    public static boolean verifyFromB64(String message, String sigB64, PublicKey puk) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(puk);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return sig.verify(Base64.getDecoder().decode(sigB64));
    }


    // 4) AES (SYMMETRIC) for Phase 2

    // Keep it simple: AES/ECB. Not secure, but lab says protocol is vulnerable anyway.
    // We only need it so we can do E(KA, ...) and E(KB, ...) to send KAB.
    public static String aesEncB64(String msg, String key16chars) throws Exception {
        SecretKeySpec ks = new SecretKeySpec(key16chars.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, ks);
        byte[] ct = c.doFinal(msg.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct);
    }

    public static String aesDecB64(String b64, String key16chars) throws Exception {
        SecretKeySpec ks = new SecretKeySpec(key16chars.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, ks);
        byte[] pt = c.doFinal(Base64.getDecoder().decode(b64));
        return new String(pt, StandardCharsets.UTF_8);
    }


    // 5) Simple random values

    public static String randNonce() {
        return "N" + System.nanoTime();
    }

    // 16 chars = 16 bytes = 128-bit AES key (simple for the lab)
    public static String randAESKey16() {
        String base = Long.toHexString(Double.doubleToLongBits(Math.random()))
                + Long.toHexString(System.nanoTime());
        if (base.length() < 16) base = (base + "0000000000000000");
        return base.substring(0, 16);
    }
}