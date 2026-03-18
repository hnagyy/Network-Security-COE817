package com.mycompany.lab2project2;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import java.util.Random;
import javax.crypto.Cipher;

public class Bob {

    static KeyPair bobKeyPair;
    static final String BOB_ID = "Bob";

    public static void main(String[] args) throws Exception {

        bobKeyPair = generateRSAKeyPair();

        ServerSocket server = new ServerSocket(6000);
        System.out.println("Bob waiting...");
        Socket socket = server.accept();

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        // Send Bob public key
        out.println(Base64.getEncoder().encodeToString(bobKeyPair.getPublic().getEncoded()));

        // Receive Alice public key
        PublicKey alicePublicKey = getPublicKey(in.readLine());

        // -------- Message 1 --------
        String msg1 = in.readLine();
        System.out.println("Received message 1: " + msg1);

        String[] m1 = msg1.split("\\|");
        String aliceNonce = m1[1];

        // -------- Message 2 --------
        String bobNonce = Integer.toString(new Random().nextInt(100000));
        String encNA = encryptRSA(aliceNonce, alicePublicKey);
        out.println(bobNonce + "|" + encNA);

        // -------- Message 3 --------
        String msg3 = in.readLine();
        System.out.println("Received message 3: " + msg3);

        String decryptedNB = decryptRSA(msg3, bobKeyPair.getPrivate());
        System.out.println("Decrypted message 3: " + decryptedNB);

        // ✅ VERIFY NONCE
        if (decryptedNB.equals(bobNonce)) {
            System.out.println("Authentication successful: nonce NB matches.");
        } else {
            System.out.println("Authentication FAILED: nonce NB does not match!");
        }

        socket.close();
        server.close();
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
