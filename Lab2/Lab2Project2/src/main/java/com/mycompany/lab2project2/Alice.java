package com.mycompany.lab2project2;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import java.util.Random;
import javax.crypto.Cipher;

public class Alice {

    static KeyPair aliceKeyPair;
    static final String ALICE_ID = "Alice";

    public static void main(String[] args) throws Exception {

        aliceKeyPair = generateRSAKeyPair();

        Socket socket = new Socket("localhost", 6000);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        // Receive Bob public key
        PublicKey bobPublicKey = getPublicKey(in.readLine());

        // Send Alice public key
        out.println(Base64.getEncoder().encodeToString(aliceKeyPair.getPublic().getEncoded()));

        // -------- Message 1 --------
        String aliceNonce = Integer.toString(new Random().nextInt(100000));
        out.println(ALICE_ID + "|" + aliceNonce);

        // -------- Message 2 --------
        String msg2 = in.readLine();
        System.out.println("Received message 2: " + msg2);

        String[] m2 = msg2.split("\\|");
        String bobNonce = m2[0];
        String decryptedNA = decryptRSA(m2[1], aliceKeyPair.getPrivate());
        System.out.println("Decrypted message 2: " + decryptedNA);

        // ✅ VERIFY NONCE
        if (decryptedNA.equals(aliceNonce)) {
            System.out.println("Bob authenticated successfully: nonce NA matches.");
        } else {
            System.out.println("Authentication FAILED: nonce NA does not match!");
            socket.close();
            return;
        }

        // -------- Message 3 --------
        out.println(encryptRSA(bobNonce, bobPublicKey));

        socket.close();
    }

    static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    static String encryptRSA(String data, PublicKey key) throws Exception {
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(c.doFinal(data.getBytes()));
    }

    static String decryptRSA(String data, PrivateKey key) throws Exception {
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE, key);
        return new String(c.doFinal(Base64.getDecoder().decode(data)));
    }

    static PublicKey getPublicKey(String key) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(key);
        return KeyFactory.getInstance("RSA")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(bytes));
    }
}
