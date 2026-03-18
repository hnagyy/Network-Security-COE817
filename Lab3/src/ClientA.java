import java.io.*;
import java.net.*;
import java.security.*;

/**
 * ClientA:
 * - Generates RSA key pair (PUA/PRA)
 * - Talks to KDC using sockets
 * - PHASE 1: receives KA securely + verifies signature
 * - PHASE 2: receives KAB encrypted under KA
 */
public class ClientA {

    private static final String IDA = "A";

    public static void main(String[] args) {
        try {
        
            // 0) Generate RSA keys for A
           
            KeyPair kpA = CryptoUtils.genRSA();
            PublicKey PUA = kpA.getPublic();
            PrivateKey PRA = kpA.getPrivate();

            System.out.println("___________________________________\n");
            System.out.println("            CLIENT A");
            System.out.println("___________________________________\n");
            System.out.println("[DEMO] PUA (A public):  " + PUA);
            System.out.println("[DEMO] PRA (A private): " + PRA);
            System.out.println();

            Socket s = new Socket("localhost", 5000);
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
            PrintWriter out = new PrintWriter(new OutputStreamWriter(s.getOutputStream()), true);

            
            // 1) Setup: Send A's public key, receive KDC public key
            
            out.println("SETUP_PUB|" + CryptoUtils.pubToB64(PUA));
            String setup = in.readLine(); // SETUP_PUK|<b64>
            PublicKey PUK = CryptoUtils.pubFromB64(setup.split("\\|", 2)[1]);

           
            // 2) Start protocol: send IDA

            out.println("IDA|" + IDA);


            // 3) PHASE 1

            // KDC -> A : E(PUA, [NK1||IDK])
            String p1_1 = in.readLine(); // P1_1|<b64>
            String dec1 = CryptoUtils.rsaDecB64(p1_1.split("\\|", 2)[1], PRA);
            String NK1 = dec1.split("\\|\\|")[0];
            String IDK = dec1.split("\\|\\|")[1];

            // A -> KDC : E(PUK, [NA||NK1])
            String NA = CryptoUtils.randNonce();
            String enc2 = CryptoUtils.rsaEncB64(NA + "||" + NK1, PUK);
            out.println("P1_2|" + enc2);

            // KDC -> A : E(PUA, NK1)
            String p1_3 = in.readLine(); // P1_3|<b64>
            String NK1_check = CryptoUtils.rsaDecB64(p1_3.split("\\|", 2)[1], PRA);

            // KDC -> A : E(PUA, KA) and SIG(PRK, KA)
            String p1_4a = in.readLine();      // P1_4A|<encKA>
            String p1_4a_sig = in.readLine();  // P1_4A_SIG|<sig>

            String encKA = p1_4a.split("\\|", 2)[1];
            String sigKA = p1_4a_sig.split("\\|", 2)[1];

            // Decrypt KA using PRA
            String KA = CryptoUtils.rsaDecB64(encKA, PRA);

            // Verify signature using KDC public key (PUK)
            boolean sigOK = CryptoUtils.verifyFromB64(KA, sigKA, PUK);

            
            // DEMO OUTPUT for Phase 1

            System.out.println("--------- PHASE 1 (A) ---------");
            System.out.println("IDA: " + IDA);
            System.out.println("IDK: " + IDK);
            System.out.println("NK1 received: " + NK1);
            System.out.println("NK1 check   : " + NK1_check);
            System.out.println("[DEMO] Decrypted KA: " + KA);
            System.out.println("[DEMO] Signature valid? " + sigOK);
            System.out.println();


            // 4) PHASE 2 request

            // A triggers session key distribution by sending IDA, IDB
            out.println("P2_REQ|" + IDA + "|B");

            // KDC -> A : E(KA, [KAB, IDB])
            String p2 = in.readLine(); // P2_A|<b64>
            String decP2 = CryptoUtils.aesDecB64(p2.split("\\|", 2)[1], KA);
            String KAB = decP2.split(",")[0];
            String IDB = decP2.split(",")[1];


            // DEMO OUTPUT for Phase 2

            System.out.println("--------- PHASE 2 (A) ---------");
            System.out.println("IDB from message: " + IDB);
            System.out.println("[DEMO] Decrypted KAB: " + KAB);
            System.out.println();

            out.println("DONE_A|Client A got KAB");

            s.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}