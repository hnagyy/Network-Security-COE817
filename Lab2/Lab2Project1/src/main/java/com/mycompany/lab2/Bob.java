package com.mycompany.lab2;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Random;

public class Bob {

    static final String SHARED_SECRET_KEY = "1234567890123456";
    static final String BOB_ID = "Bob";

    public static void main(String[] args) throws Exception {

        ServerSocket serverSocket = new ServerSocket(5000);
        System.out.println("Bob waiting...");
        Socket socket = serverSocket.accept();

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        // Message 1: Alice → Bob
        String message1 = in.readLine();
        System.out.println("Received message 1: " + message1);

        String[] parts = message1.split("\\|");
        String aliceNonce = parts[1];

        // Message 2: Bob → Alice
        String bobNonce = Integer.toString(new Random().nextInt(100000));
        String encryptedPayload = encryptAES(BOB_ID + "|" + aliceNonce);
        out.println(bobNonce + "|" + encryptedPayload);

        // Message 3: Alice → Bob
        String message3 = in.readLine();
        System.out.println("Received message 3: " + message3);

        String decryptedMessage3 = decryptAES(message3);
        System.out.println("Decrypted message 3: " + decryptedMessage3);

        socket.close();
        serverSocket.close();
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
