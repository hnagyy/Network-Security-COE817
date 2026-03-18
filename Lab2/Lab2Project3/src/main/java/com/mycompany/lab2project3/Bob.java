package com.mycompany.lab2project3;

import java.security.*;

public class Bob {

    static final long ALLOWED_WINDOW_MS = 5000; // 5 seconds

    public static void verify(
            String message,
            long timestamp,
            byte[] signature,
            PublicKey alicePublicKey
    ) throws Exception {

        System.out.println("\nBob processing Message 3...");

        // Verify signature
        String signedData = message + "|" + timestamp;

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(alicePublicKey);
        verifier.update(signedData.getBytes());
        boolean signatureValid = verifier.verify(signature);

        // Verify timestamp freshness
        long currentTime = System.currentTimeMillis();
        boolean timestampFresh =
                Math.abs(currentTime - timestamp) <= ALLOWED_WINDOW_MS;

        System.out.println("Decrypted / Verified Message 3:");
        System.out.println("Signature valid: " + signatureValid);
        System.out.println("Timestamp fresh: " + timestampFresh);
    }
}
