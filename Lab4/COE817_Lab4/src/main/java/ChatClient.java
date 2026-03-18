import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

public class ChatClient {

    String id;

    KeyPair keys;

    SecretKey groupKey;

    PublicKey kdcPublic;

    ObjectOutputStream out;

    ObjectInputStream in;

    Set<Long> usedNonces = new HashSet<>();

    public ChatClient(String id) throws Exception{

        this.id = id;

        keys = CryptoUtils.generateRSAKeyPair();

        // simulate known KDC public key
        kdcPublic = CryptoUtils.getKDCKeyPair().getPublic();
    }

    void start() throws Exception{

        Socket socket = new Socket("localhost",5000);

        out = new ObjectOutputStream(socket.getOutputStream());

        in = new ObjectInputStream(socket.getInputStream());

        sendID();

        new Thread(this::receive).start();

        sendLoop();
    }

    void sendID() throws Exception{

        Packet p = new Packet();

        p.type="ID";

        p.senderId=id;

        p.publicKeyBase64 = CryptoUtils.publicKeyToBase64(keys.getPublic());

        out.writeObject(p);

        out.flush();
    }

    void receive(){

        try{

            while(true){

                Packet p = (Packet)in.readObject();

                switch(p.type){

                    case "CHALLENGE":

                        handleChallenge(p);

                        break;

                    case "KEY":

                        handleKey(p);

                        break;

                    case "CHAT":

                        handleChat(p);

                        break;
                }
            }

        }catch(Exception e){}
    }

    void handleChallenge(Packet p) throws Exception{

        byte[] enc = Base64.getDecoder().decode(p.encryptedData);

        byte[] dec = CryptoUtils.rsaDecrypt(enc,keys.getPrivate());

        String[] parts = new String(dec).split("\\|");

        long nk = Long.parseLong(parts[0]);

        long na = CryptoUtils.generateNonce();

        String resp = na+"|"+nk;

        byte[] encResp = CryptoUtils.rsaEncrypt(resp.getBytes(), kdcPublic);

        Packet r = new Packet();

        r.type="CHALLENGE_RESPONSE";

        r.senderId=id;

        r.encryptedData = Base64.getEncoder().encodeToString(encResp);

        out.writeObject(r);

        out.flush();
    }

    void handleKey(Packet p) throws Exception{

        byte[] enc = Base64.getDecoder().decode(p.encryptedGroupKeyBase64);

        byte[] key = CryptoUtils.rsaDecrypt(enc,keys.getPrivate());

        groupKey = CryptoUtils.secretKeyFromBytes(key);

       System.out.println("Key received from KDC");
    }

    void handleChat(Packet p) throws Exception{

        // decrypt message
        String text = CryptoUtils.decryptAES(p.encryptedPayloadBase64, groupKey);

        String[] parts = text.split("\\|");

        String sender = parts[0];
        long nonce = Long.parseLong(parts[1]);
        String msg = parts[2];

        // replay protection
        if(usedNonces.contains(nonce)){

            System.out.println("Replay attack detected. Message rejected.");
            return;
        }

        usedNonces.add(nonce);

        // verify signature
        PublicKey senderKey =
            CryptoUtils.publicKeyFromBase64(p.publicKeyBase64);

        boolean verified = CryptoUtils.verify(
            text.getBytes(),
            Base64.getDecoder().decode(p.signatureBase64),
            senderKey
        );

        if(!verified){

            System.out.println("Signature verification FAILED.");
            return;
        }

        System.out.println("---------------------------------");
        System.out.println("Message received from " + sender);
        System.out.println("Decrypted message: " + msg);
        System.out.println("Signature verification successful.");
        System.out.println("---------------------------------");
    }

    void sendLoop() throws Exception{

        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        // wait until group key arrives
        while(groupKey == null){
            Thread.sleep(200);
        }

        System.out.println("Secure chat ready. Type messages.");

        while(true){

            String msg = br.readLine();

            long nonce = CryptoUtils.generateNonce();

            String payload = id + "|" + nonce + "|" + msg;

            String enc = CryptoUtils.encryptAES(payload, groupKey);

            // sign plaintext
            byte[] sig = CryptoUtils.sign(payload.getBytes(), keys.getPrivate());

            Packet p = new Packet();

            p.type = "CHAT";
            p.senderId = id;

            p.encryptedPayloadBase64 = enc;
            p.signatureBase64 = Base64.getEncoder().encodeToString(sig);
            p.publicKeyBase64 = CryptoUtils.publicKeyToBase64(keys.getPublic());

            out.writeObject(p);
            out.flush();
        }
    }
}