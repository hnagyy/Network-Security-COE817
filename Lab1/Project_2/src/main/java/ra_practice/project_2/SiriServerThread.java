package ra_practice.project_2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class SiriServerThread extends Thread {

    private final Socket socket;

    public SiriServerThread(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        ) {
            // Send welcome message (encrypted)
            String welcome = "Hi! Ask me a question. Type 'bye' to exit.";
            out.println(VigenereCipher.encrypt(welcome));

            String encryptedLine;

            while ((encryptedLine = in.readLine()) != null) {

                System.out.println("\n[From Client " + socket.getPort() + "] Encrypted: " + encryptedLine);

                String decrypted = VigenereCipher.decrypt(encryptedLine);
                System.out.println("[From Client " + socket.getPort() + "] Decrypted: " + decrypted);

                if (decrypted.trim().equalsIgnoreCase("bye")) {
                    String bye = "Bye!";
                    String byeEnc = VigenereCipher.encrypt(bye);
                    System.out.println("[To Client " + socket.getPort() + "] Encrypted: " + byeEnc);
                    out.println(byeEnc);
                    break;
                }

                String answer = getAnswer(decrypted);

                System.out.println("[To Client " + socket.getPort() + "] Decrypted: " + answer);
                String encryptedAnswer = VigenereCipher.encrypt(answer);
                System.out.println("[To Client " + socket.getPort() + "] Encrypted: " + encryptedAnswer);

                out.println(encryptedAnswer);
            }

        } catch (IOException e) {
            System.out.println("[ServerThread] Client disconnected: " + socket);
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    private String getAnswer(String question) {
        String q = question.trim().toLowerCase();

        if (q.contains("who created you")) return "I was created by Apple.";
        if (q.contains("what does siri mean")) return "victory and beautiful";
        if (q.contains("are you a robot")) return "I am a virtual assistant.";

        return "Sorry, I don't know that one.";
    }
}
