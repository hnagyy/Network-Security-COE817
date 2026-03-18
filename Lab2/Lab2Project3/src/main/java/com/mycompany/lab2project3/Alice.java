package com.mycompany.lab2project3;

import java.security.*;
import java.util.Base64;

public class Alice {

    static final String ALICE_ID = "Alice";

    public static void main(String[] args) throws Exception {

        // Alice generates RSA key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair aliceKeys = kpg.generateKeyPair();

        // ---------- Message 1 ----------
        long timestamp = System.currentTimeMillis();
        System.out.println("Message 1 (Alice to Bob):");
        System.out.println(ALICE_ID + "|" + timestamp);

        // ---------- Message 2 ----------
        System.out.println("\nMessage 2 (Bob to Alice):");
        System.out.println("ACK");

        // ---------- Message 3 ----------
        String message = "Hello Bob";
        String signedData = message + "|" + timestamp;

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(aliceKeys.getPrivate());
        signer.update(signedData.getBytes());
        byte[] signature = signer.sign();

        System.out.println("\nMessage 3 (Alice to Bob):");
        System.out.println(message + "|" + timestamp + "|" +
                Base64.getEncoder().encodeToString(signature));

        // Bob verifies
        Bob.verify(
                message,
                timestamp,
                signature,
                aliceKeys.getPublic()
        );
    }
}
