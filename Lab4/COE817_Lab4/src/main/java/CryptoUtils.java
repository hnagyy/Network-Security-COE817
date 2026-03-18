import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtils {
    
    public static KeyPair getKDCKeyPair() throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");

        sr.setSeed("COE817_KDC_KEY".getBytes());

        kpg.initialize(2048, sr);

        return kpg.generateKeyPair();
    }

    public static KeyPair generateRSAKeyPair() throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        return kpg.generateKeyPair();
    }

    public static SecretKey generateAESKey() throws Exception {

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);

        return kg.generateKey();
    }

    public static String encryptAES(String text, SecretKey key) throws Exception {

        if(key == null){
            throw new RuntimeException("AES key is null. Key distribution not completed.");
        }

        Cipher cipher = Cipher.getInstance("AES");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encrypted = cipher.doFinal(text.getBytes());

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decryptAES(String text, SecretKey key) throws Exception {

        Cipher cipher = Cipher.getInstance("AES");

        cipher.init(Cipher.DECRYPT_MODE,key);

        byte[] decoded = Base64.getDecoder().decode(text);

        return new String(cipher.doFinal(decoded));
    }

    public static byte[] rsaEncrypt(byte[] data, PublicKey key) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.ENCRYPT_MODE,key);

        return cipher.doFinal(data);
    }

    public static byte[] rsaDecrypt(byte[] data, PrivateKey key) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.DECRYPT_MODE,key);

        return cipher.doFinal(data);
    }

    public static byte[] sign(byte[] data, PrivateKey key) throws Exception {

        Signature s = Signature.getInstance("SHA256withRSA");

        s.initSign(key);

        s.update(data);

        return s.sign();
    }

    public static boolean verify(byte[] data, byte[] sig, PublicKey key) throws Exception {

        Signature s = Signature.getInstance("SHA256withRSA");

        s.initVerify(key);

        s.update(data);

        return s.verify(sig);
    }

    public static String publicKeyToBase64(PublicKey key){

        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey publicKeyFromBase64(String key) throws Exception{

        byte[] bytes = Base64.getDecoder().decode(key);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);

        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static long generateNonce(){

        return new SecureRandom().nextLong();
    }

    public static SecretKey secretKeyFromBytes(byte[] bytes){

        return new SecretKeySpec(bytes,"AES");
    }
}