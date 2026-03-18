package com.mycompany.lab2;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.util.Base64;
import java.util.Random;

public class Alice {

    static final String SHARED_SECRET_KEY = "1234567890123456";
    static final String ALICE_ID = "Alice";

    public static void main(String[] args) throws Exception {

        Socket socket = new Socket("localhost", 5000);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        // Message 1: Alice → Bob
        String aliceNonce = Integer.toString(new Random().nextInt(100000));
        out.println(ALICE_ID + "|" + aliceNonce);

        // Message 2: Bob → Alice
        String message2 = in.readLine();
        System.out.println("Received message 2: " + message2);

        String[] parts = message2.split("\\|");
        String bobNonce = parts[0];
        String decryptedMessage2 = decryptAES(parts[1]);
        System.out.println("Decrypted message 2: " + decryptedMessage2);

        // Message 3: Alice → Bob
        out.println(encryptAES(ALICE_ID + "|" + bobNonce));

        socket.close();
    }

    static String encryptAES(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(SHARED_SECRET_KEY.getBytes(), "AES"));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes()));
    }

    static String decryptAES(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(SHARED_SECRET_KEY.getBytes(), "AES"));
        return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
    }
}
