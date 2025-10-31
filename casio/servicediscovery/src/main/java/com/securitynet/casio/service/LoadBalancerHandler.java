package com.securitynet.casio.service;

import com.securitynet.casio.model.ServiceInstance;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;


public class LoadBalancerHandler implements Runnable {

    private final Socket clientSocket;
    private final RegistryService registryService;
    private Socket applicationServerSocket;

    public LoadBalancerHandler(Socket clientSocket, RegistryService registryService) {
        this.clientSocket = clientSocket;
        this.registryService = registryService;
    }

    @Override
    public void run() {
        String clientAddress = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        
        try {
            ServiceInstance targetInstance = registryService.getNextInstance();

            if (targetInstance == null) {
                System.err.println("Nenhum servidor de aplicação disponível para o cliente: " + clientAddress);

                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                out.println("ERROR: No application servers available. Please try again later.");

                clientSocket.close();
                return;
            }

            System.out.println("Cliente " + clientAddress + " sendo roteado para -> " + targetInstance.getInstanceId());

            this.applicationServerSocket = new Socket(targetInstance.getHost(), targetInstance.getPort());

            // Two threads for bidirectional streaming
            Thread clientToServer = new Thread(() -> 
                forwardStream(clientSocket, applicationServerSocket), "ClientToServer");
                
            Thread serverToClient = new Thread(() -> 
                forwardStream(applicationServerSocket, clientSocket), "ServerToClient");

            clientToServer.start();
            serverToClient.start();

            // Wait for the Client->Server thread to finish
            clientToServer.join();
            
            serverToClient.interrupt();
        } catch (IOException e) {
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            closeSocket(clientSocket);
            closeSocket(applicationServerSocket);
        }
    }


    private void forwardStream(Socket inSocket, Socket outSocket) {
        try (InputStream in = inSocket.getInputStream();
             OutputStream out = outSocket.getOutputStream()) {
             
            byte[] buffer = new byte[4096];
            
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
                out.flush();
            }
        } catch (IOException e) {
        } finally {
            closeSocket(inSocket);
            closeSocket(outSocket);
        }
    }
    
    private void closeSocket(Socket socket) {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            // --- IGNORE ---
        }
    }
}