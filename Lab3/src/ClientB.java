import java.io.*;
import java.net.*;
import java.security.*;

/**
 * ClientB:
 * - Generates RSA key pair (PUB/PRB)
 * - PHASE 1: receives KB securely + verifies signature
 * - PHASE 2: receives KAB encrypted under KB
 */
public class ClientB {

    private static final String IDB = "B";

    public static void main(String[] args) {
        try {

            // 0) Generate RSA keys for B

            KeyPair kpB = CryptoUtils.genRSA();
            PublicKey PUB = kpB.getPublic();
            PrivateKey PRB = kpB.getPrivate();

            System.out.println("___________________________________\n");
            System.out.println("            CLIENT B");
            System.out.println("___________________________________\n");
            System.out.println("[DEMO] PUB (B public):  " + PUB);
            System.out.println("[DEMO] PRB (B private): " + PRB);
            System.out.println();

            Socket s = new Socket("localhost", 5000);
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
            PrintWriter out = new PrintWriter(new OutputStreamWriter(s.getOutputStream()), true);


            // 1) Setup: Send B's public key, receive KDC public key

            out.println("SETUP_PUB|" + CryptoUtils.pubToB64(PUB));
            String setup = in.readLine(); // SETUP_PUK|<b64>
            PublicKey PUK = CryptoUtils.pubFromB64(setup.split("\\|", 2)[1]);


            // 2) Start protocol: send IDB

            out.println("IDB|" + IDB);


            // 3) PHASE 1

            // KDC -> B : E(PUB, [NK2||IDK])
            String p1_1 = in.readLine(); // P1_1|<b64>
            String dec1 = CryptoUtils.rsaDecB64(p1_1.split("\\|", 2)[1], PRB);
            String NK2 = dec1.split("\\|\\|")[0];
            String IDK = dec1.split("\\|\\|")[1];

            // B -> KDC : E(PUK, [NB||NK2])
            String NB = CryptoUtils.randNonce();
            String enc2 = CryptoUtils.rsaEncB64(NB + "||" + NK2, PUK);
            out.println("P1_2|" + enc2);

            // KDC -> B : E(PUB, NK2)
            String p1_3 = in.readLine(); // P1_3|<b64>
            String NK2_check = CryptoUtils.rsaDecB64(p1_3.split("\\|", 2)[1], PRB);

            // KDC -> B : E(PUB, KB) and SIG(PRK, KB)
            String p1_4b = in.readLine();      // P1_4B|<encKB>
            String p1_4b_sig = in.readLine();  // P1_4B_SIG|<sig>

            String encKB = p1_4b.split("\\|", 2)[1];
            String sigKB = p1_4b_sig.split("\\|", 2)[1];

            String KB = CryptoUtils.rsaDecB64(encKB, PRB);
            boolean sigOK = CryptoUtils.verifyFromB64(KB, sigKB, PUK);


            // DEMO OUTPUT for Phase 1

            System.out.println("--------- PHASE 1 (B) ---------");
            System.out.println("IDB: " + IDB);
            System.out.println("IDK: " + IDK);
            System.out.println("NK2 received: " + NK2);
            System.out.println("NK2 check   : " + NK2_check);
            System.out.println("[DEMO] Decrypted KB: " + KB);
            System.out.println("[DEMO] Signature valid? " + sigOK);
            System.out.println();


            // 4) PHASE 2: B receives session key message

            // KDC -> B : E(KB, [KAB, IDA])
            String p2 = in.readLine(); // P2_B|<b64>
            String decP2 = CryptoUtils.aesDecB64(p2.split("\\|", 2)[1], KB);
            String KAB = decP2.split(",")[0];
            String IDA = decP2.split(",")[1];


            // DEMO OUTPUT for Phase 2

            System.out.println("--------- PHASE 2 (B) ---------");
            System.out.println("IDA from message: " + IDA);
            System.out.println("[DEMO] Decrypted KAB: " + KAB);
            System.out.println();

            out.println("DONE_B|Client B got KAB");

            s.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}