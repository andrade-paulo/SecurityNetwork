package com.securitynet;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import com.securitynet.model.NameTable;
import com.securitynet.service.ApplicationHandler;

public class DNS {
    private static NameTable nameTable;

    public static void main(String[] args) {
        System.out.println("===================");
        System.out.println("Starting DNS Server");
        System.out.println("===================\n");

        // Address configuration
        String address = "localhost";
        int port = 8000;

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

        // Initialize the name table
        nameTable = new NameTable();

        // Start the server
        try (ServerSocket socket = new ServerSocket(port)) {
            System.out.println("DNS Server started on " + address + ":" + port);
            while (true) {
                Socket clientSocket = socket.accept();
                ApplicationHandler handler = new ApplicationHandler(clientSocket, nameTable);
                new Thread(handler).start();
            }
        } catch (IOException e) {
            System.err.println("Error starting DNS Server: " + e.getMessage());
        }
    }
}