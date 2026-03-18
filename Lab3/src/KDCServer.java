import java.io.*;
import java.net.*;
import java.security.*;

/**
 * KDCServer:
 * - Acts as the "KDC" from the lab diagram.
 * - Runs a server socket and talks to two clients: A and B.
 *
 * PHASE 1 (RSA):
 *  - KDC generates master keys KA and KB (symmetric)
 *  - Sends KA to A (encrypted with PUA), sends KB to B (encrypted with PUB)
 *  - Also sends a signature from PRK so A/B can verify it came from KDC
 *
 * PHASE 2 (Symmetric):
 *  - KDC generates session key KAB
 *  - Sends KAB to A encrypted with KA
 *  - Sends KAB to B encrypted with KB
 */
public class KDCServer {

    private static final String IDK = "KDC";
    private static final int PORT = 5000;

    public static void main(String[] args) {
        try {

            // 0) KDC generates its RSA keys (PUK/PRK)

            KeyPair kdcKP = CryptoUtils.genRSA();
            PublicKey PUK = kdcKP.getPublic();
            PrivateKey PRK = kdcKP.getPrivate();

            System.out.println("___________________________________\n");
            System.out.println("         KDC SERVER START");
            System.out.println("___________________________________");
            System.out.println("IDK: " + IDK);
            System.out.println("[DEMO] KDC Public Key (PUK):  " + PUK);
            System.out.println("[DEMO] KDC Private Key (PRK): " + PRK);
            System.out.println();


            // 1) Start server socket and accept two clients (A then B)

            ServerSocket ss = new ServerSocket(PORT);
            System.out.println("Listening on port " + PORT + " ...");
            System.out.println("Run ClientA first, then ClientB.");
            System.out.println();

            Socket sockA = ss.accept();
            Conn A = setupExchangeKeys(sockA, "A", PUK);
            System.out.println("Setup complete with Client A");

            Socket sockB = ss.accept();
            Conn B = setupExchangeKeys(sockB, "B", PUK);
            System.out.println("Setup complete with Client B");

            System.out.println();


            // 2) Protocol begins (IDs)

            // A -> KDC : IDA
            String msgIDA = A.in.readLine(); // "IDA|A"
            // B -> KDC : IDB
            String msgIDB = B.in.readLine(); // "IDB|B"

            String IDA = msgIDA.split("\\|")[1];
            String IDB = msgIDB.split("\\|")[1];

            System.out.println("[KDC] Received IDA: " + IDA);
            System.out.println("[KDC] Received IDB: " + IDB);
            System.out.println();


            // 3) PHASE 1: generate nonces and master keys

            String NK1 = CryptoUtils.randNonce();
            String NK2 = CryptoUtils.randNonce();
            String KA = CryptoUtils.randAESKey16();
            String KB = CryptoUtils.randAESKey16();

            System.out.println("___________________________________\n");
            System.out.println("           PHASE 1 (RSA)");
            System.out.println("___________________________________\n");
            System.out.println("[KDC] Generated NK1: " + NK1);
            System.out.println("[KDC] Generated NK2: " + NK2);
            System.out.println("[KDC] Generated KA : " + KA + "  (master key for A<->KDC)");
            System.out.println("[KDC] Generated KB : " + KB + "  (master key for B<->KDC)");
            System.out.println();

            // Diagram step: KDC -> A : E(PUA, [NK1||IDK])
            String step1A = NK1 + "||" + IDK;
            String enc_step1A = CryptoUtils.rsaEncB64(step1A, A.PUclient);
            A.out.println("P1_1|" + enc_step1A);

            // Diagram step: KDC -> B : E(PUB, [NK2||IDK])
            String step1B = NK2 + "||" + IDK;
            String enc_step1B = CryptoUtils.rsaEncB64(step1B, B.PUclient);
            B.out.println("P1_1|" + enc_step1B);

            // Diagram step: A -> KDC : E(PUK, [NA||NK1])
            String fromA = A.in.readLine();           // "P1_2|<b64>"
            String encA2 = fromA.split("\\|", 2)[1];
            String decA2 = CryptoUtils.rsaDecB64(encA2, PRK); // decrypt using PRK
            String NA = decA2.split("\\|\\|")[0];
            String NK1_back = decA2.split("\\|\\|")[1];

            // Diagram step: B -> KDC : E(PUK, [NB||NK2])
            String fromB = B.in.readLine();           // "P1_2|<b64>"
            String encB2 = fromB.split("\\|", 2)[1];
            String decB2 = CryptoUtils.rsaDecB64(encB2, PRK);
            String NB = decB2.split("\\|\\|")[0];
            String NK2_back = decB2.split("\\|\\|")[1];

            // Diagram step: KDC -> A : E(PUA, NK1)
            A.out.println("P1_3|" + CryptoUtils.rsaEncB64(NK1, A.PUclient));

            // Diagram step: KDC -> B : E(PUB, NK2)
            B.out.println("P1_3|" + CryptoUtils.rsaEncB64(NK2, B.PUclient));

            // Diagram intent: use PRK to prove KA/KB came from KDC
            // Instead of nested RSA encryption (doesn't fit RSA size limit),
            // we do:
            //   KDC -> A : E(PUA, KA) and SIG(PRK, KA)
            //   KDC -> B : E(PUB, KB) and SIG(PRK, KB)

            String encKA = CryptoUtils.rsaEncB64(KA, A.PUclient);
            String sigKA = CryptoUtils.signToB64(KA, PRK);
            A.out.println("P1_4A|" + encKA);
            A.out.println("P1_4A_SIG|" + sigKA);

            String encKB = CryptoUtils.rsaEncB64(KB, B.PUclient);
            String sigKB = CryptoUtils.signToB64(KB, PRK);
            B.out.println("P1_4B|" + encKB);
            B.out.println("P1_4B_SIG|" + sigKB);

            // Helpful debug/demo print
            System.out.println("[KDC] NA from A: " + NA + " and NK1_back: " + NK1_back);
            System.out.println("[KDC] NB from B: " + NB + " and NK2_back: " + NK2_back);
            System.out.println();


            // 4) PHASE 2: generate session key KAB and distribute via KA/KB

            System.out.println("___________________________________\n");
            System.out.println("          PHASE 2 (AES)");
            System.out.println("___________________________________\n");

            // A -> KDC : request "IDA, IDB"
            // (we let A send the request to trigger phase 2)
            String phase2req = A.in.readLine(); // "P2_REQ|IDA|IDB"
            System.out.println("[KDC] Received Phase2 request: " + phase2req);

            String KAB = CryptoUtils.randAESKey16();
            System.out.println("[KDC] Generated session key KAB: " + KAB);
            System.out.println();

            // KDC -> A : E(KA, [KAB, IDB])
            String payloadA = KAB + "," + IDB;
            String encA = CryptoUtils.aesEncB64(payloadA, KA);
            A.out.println("P2_A|" + encA);

            // KDC -> B : E(KB, [KAB, IDA])
            String payloadB = KAB + "," + IDA;
            String encB = CryptoUtils.aesEncB64(payloadB, KB);
            B.out.println("P2_B|" + encB);

            // Receive final “done” messages for clean shutdown
            System.out.println(A.in.readLine()); // DONE_A|...
            System.out.println(B.in.readLine()); // DONE_B|...

            System.out.println("\n[KDC] Demo finished successfully ✅");

            sockA.close();
            sockB.close();
            ss.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Setup exchange:
     * The lab diagram assumes public keys are already known.
     * In code, we must exchange them somehow.
     *
     * Client -> KDC: SETUP_PUB|<clientPublicKeyB64>
     * KDC    -> Client: SETUP_PUK|<kdcPublicKeyB64>
     */
    private static class Conn {
        BufferedReader in;
        PrintWriter out;
        PublicKey PUclient;
        String name;
        Conn(BufferedReader in, PrintWriter out, PublicKey pk, String name) {
            this.in = in; this.out = out; this.PUclient = pk; this.name = name;
        }
    }

    private static Conn setupExchangeKeys(Socket sock, String who, PublicKey PUK) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        PrintWriter out = new PrintWriter(new OutputStreamWriter(sock.getOutputStream()), true);

        String line = in.readLine(); // SETUP_PUB|<b64>
        String b64 = line.split("\\|", 2)[1];
        PublicKey clientPub = CryptoUtils.pubFromB64(b64);

        // Send KDC public key back
        out.println("SETUP_PUK|" + CryptoUtils.pubToB64(PUK));

        return new Conn(in, out, clientPub, who);
    }
}