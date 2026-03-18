package ra_practice.project_2;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class SiriMultiServer {

    public static void main(String[] args) {
        int port = 5000; // MUST match the port in SiriClient

        System.out.println("SiriMultiServer starting on port " + port);

        try (ServerSocket serverSocket = new ServerSocket(port)) {

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[Server] New client connected: " + clientSocket);

                // Create a new thread for each client
                SiriServerThread t = new SiriServerThread(clientSocket);
                t.start();
            }

        } catch (IOException e) {
            System.out.println("[Server] Error: " + e.getMessage());
        }
    }
}
