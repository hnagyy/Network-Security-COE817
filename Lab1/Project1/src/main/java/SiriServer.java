import java.io.*;
import java.net.*;
import java.util.Map;

public class SiriServer {
    private static final int PORT = 5000;

    private static final Map<String, String> QA = Map.of(
        "who created you", "I was created by Apple.",
        "what does siri mean", "Siri can mean victory and beautiful.",
        "are you a robot", "I am a virtual assistant.",
        "what is your name", "My name is Siri (text edition).",
        "what can you do", "I can answer simple questions using a chat server."
    );

    public static void main(String[] args) {
        System.out.println("SiriServer starting on localhost:" + PORT);

        try (ServerSocket server = new ServerSocket(PORT, 50, InetAddress.getByName("localhost"));
             Socket client = server.accept();
             BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
             PrintWriter out = new PrintWriter(client.getOutputStream(), true)) {

            System.out.println("Client connected: " + client.getInetAddress());

            sendEncrypted(out, "Hi! Ask me a question. Type 'bye' to exit.");

            String encQ;
            while ((encQ = in.readLine()) != null) {
                System.out.println("\n[From Client] Encrypted: " + encQ);

                String q = VigenereCipher.decrypt(encQ);
                System.out.println("[From Client] Decrypted: " + q);

                if (q.trim().equalsIgnoreCase("bye")) {
                    sendEncrypted(out, "Bye! Have a nice day.");
                    break;
                }

                String answer = QA.getOrDefault(norm(q),
                        "Sorry, I do not know that yet. Try asking: 'Who created you?'");

                sendEncrypted(out, answer);
            }

            System.out.println("\nClient disconnected. Server shutting down.");

        } catch (IOException e) {
            System.out.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void sendEncrypted(PrintWriter out, String plain) {
        String enc = VigenereCipher.encrypt(plain);
        out.println(enc);
        System.out.println("[To Client] Decrypted: " + plain);
        System.out.println("[To Client] Encrypted: " + enc);
    }

    private static String norm(String s) {
        s = s.trim().toLowerCase();
        while (!s.isEmpty() && ".!?".indexOf(s.charAt(s.length() - 1)) >= 0) {
            s = s.substring(0, s.length() - 1).trim();
        }
        return s;
    }
}
