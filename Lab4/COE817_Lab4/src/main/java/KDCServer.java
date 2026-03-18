import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;

public class KDCServer {

    Map<String,ClientHandler> clients = new ConcurrentHashMap<>();

    Map<String,String> publicKeys = new ConcurrentHashMap<>();

    KeyPair kdcKeys;

    SecretKey groupKey;

    public KDCServer() throws Exception{

        kdcKeys = CryptoUtils.getKDCKeyPair();

        groupKey = CryptoUtils.generateAESKey();
    }

    public static void main(String[] args) throws Exception{

        new KDCServer().start();
    }

    void start() throws Exception{

        ServerSocket server = new ServerSocket(5000);

        System.out.println("KDC running");

        while(true){

            Socket s = server.accept();

            new Thread(new ClientHandler(s,this)).start();
        }
    }

    void distributeKey() throws Exception{

        byte[] key = groupKey.getEncoded();

        for(String id:clients.keySet()){

            PublicKey pk = CryptoUtils.publicKeyFromBase64(publicKeys.get(id));

            byte[] enc = CryptoUtils.rsaEncrypt(key,pk);

            Packet p = new Packet();

            p.type="KEY";

            p.encryptedGroupKeyBase64 = Base64.getEncoder().encodeToString(enc);

            clients.get(id).send(p);
        }
    }

    void forward(Packet p,String sender){

        for(String id:clients.keySet()){

            if(!id.equals(sender)){

                System.out.println("Forwarding message from " + sender + " to " + id);

                clients.get(id).send(p);
            }
        }
    }

    class ClientHandler implements Runnable{

        Socket socket;

        ObjectInputStream in;

        ObjectOutputStream out;

        String id;

        KDCServer server;

        ClientHandler(Socket s,KDCServer k) throws Exception{

            socket=s;

            server=k;

            out = new ObjectOutputStream(socket.getOutputStream());

            in = new ObjectInputStream(socket.getInputStream());
        }

        public void run(){

            try{

                while(true){

                    Packet p = (Packet)in.readObject();

                    switch(p.type){

                        case "ID":

                            handleID(p);

                            break;

                        case "CHALLENGE_RESPONSE":

                            handleAuth(p);

                            break;

                        case "CHAT":

                            System.out.println("------------------------------------------------");
                            System.out.println("KDC received encrypted message from client " + p.senderId);
                            System.out.println("Encrypted payload: " + p.encryptedPayloadBase64);
                            System.out.println("Forwarding message to other clients...");
                            System.out.println("------------------------------------------------");

                            server.forward(p, p.senderId);

                            break;
                    }
                }

            }catch(Exception e){}
        }

        void handleID(Packet p) throws Exception{

            id=p.senderId;

            server.publicKeys.put(id,p.publicKeyBase64);

            long nonce = CryptoUtils.generateNonce();

            String challenge = nonce+"|KDC";

            PublicKey pk = CryptoUtils.publicKeyFromBase64(p.publicKeyBase64);

            byte[] enc = CryptoUtils.rsaEncrypt(challenge.getBytes(),pk);

            Packet reply = new Packet();

            reply.type="CHALLENGE";

            reply.encryptedData = Base64.getEncoder().encodeToString(enc);

            send(reply);
        }

        void handleAuth(Packet p) throws Exception{

            byte[] enc = Base64.getDecoder().decode(p.encryptedData);

            byte[] dec = CryptoUtils.rsaDecrypt(enc,server.kdcKeys.getPrivate());

            System.out.println("Authenticated "+p.senderId);

            server.clients.put(p.senderId,this);

            if(server.clients.size()==3){

                server.distributeKey();
            }
        }

        void send(Packet p){

            try{

                out.writeObject(p);

                out.flush();

            }catch(Exception e){}
        }
    }
}