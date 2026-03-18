import java.io.*;
import java.net.*;
import java.util.Scanner;

public class SiriClient {
    private static final String HOST = "localhost";
    private static final int PORT = 5000;

    public static void main(String[] args) {
        System.out.println("SiriClient connecting to " + HOST + ":" + PORT);

        try (Socket socket = new Socket(HOST, PORT);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             Scanner sc = new Scanner(System.in)) {

            receiveAndShow(in);  // greeting

            while (true) {
                System.out.print("\nYou: ");
                String msg = sc.nextLine();

                sendEncrypted(out, msg);

                if (msg.trim().equalsIgnoreCase("bye")) break;

                if (!receiveAndShow(in)) break;
            }

        } catch (IOException e) {
            System.out.println("Client error: " + e.getMessage());
        }
    }

    private static void sendEncrypted(PrintWriter out, String plain) {
        String enc = VigenereCipher.encrypt(plain);
        out.println(enc);
        System.out.println("[To Server] Decrypted: " + plain);
        System.out.println("[To Server] Encrypted: " + enc);
    }

    private static boolean receiveAndShow(BufferedReader in) throws IOException {
        String enc = in.readLine();
        if (enc == null) {
            System.out.println("\nServer closed the connection.");
            return false;
        }
        System.out.println("[From Server] Encrypted: " + enc);
        System.out.println("[From Server] Decrypted: " + VigenereCipher.decrypt(enc));
        return true;
    }
}
