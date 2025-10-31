package com.securitynet.casio;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import com.securitynet.casio.service.ApplicationHandler;

public class CasioApplication {
    public static void main(String[] args) {
        System.out.println("=====================");
        System.out.println("Starting Casio Server");
        System.out.println("=====================\n");

        // Address configuration
        String address = "localhost";
        int port = 9002;

        if (args.length >= 1) {
            address = args[0];
        }
        if (args.length >= 2) {
            port = Integer.parseInt(args[1]);
            if (port < 1024 || port > 65535) {
                System.err.println("Port must be between 1024 and 65535");
                System.exit(1);
            }
        }

        // Start the server
        try (ServerSocket socket = new ServerSocket(port)) {
            System.out.println("Casio Server started on " + address + ":" + port);
            while (true) {
                Socket clientSocket = socket.accept();
                ApplicationHandler handler = new ApplicationHandler(clientSocket);
                new Thread(handler).start();
            }
        } catch (IOException e) {
            System.err.println("Error starting Casio Server: " + e.getMessage());
        }
    }
}