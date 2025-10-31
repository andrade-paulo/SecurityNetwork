package com.securitynet;

import com.securitynet.model.Message;
import com.securitynet.security.AES;
import com.securitynet.security.Util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class Browser {
    private static final String DNS_ADDRESS = "localhost";
    private static final int DNS_PORT = 8053;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        while (true) {
            System.out.print("\nService search (EXIT to quit): ");
            
            String serviceName = scanner.nextLine();
            
            if (serviceName.equalsIgnoreCase("EXIT")) {
                System.out.println("Exiting browser.");
                break;
            }

            // The system will search for the input in the DNS first to get the address
            // If found, it will connect to the App Server
            String serviceAddress = connectToDNS(serviceName);
            if (serviceAddress != null && !serviceAddress.equals("NOT_FOUND")) {
                connectToAppServer(serviceAddress, scanner);
            } else {
                System.out.println("Service not found. Please try another service.");
            }
        }
    }


    private static String connectToDNS(String userInput) {
        String address = null;
        
        System.out.println("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-");
        try (Socket socket = new Socket(DNS_ADDRESS, DNS_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            System.out.println("Consulting DNS (" + DNS_ADDRESS + ":" + DNS_PORT + ")...");

            // Security handshake
            Object[] crypto = performHandshake(out, in);
            if (crypto == null) return null; // Handshake failed
            
            SecretKey aesKey = (SecretKey) crypto[0];
            AES aesCipher = (AES) crypto[1];

            // Send GET request
            Message message = new Message("GET", userInput);
            sendEncryptedMessage(message, out, aesKey, aesCipher);

            // Receive GET response
            String serverResponse = receiveEncryptedMessage(in, aesCipher);

            address = serverResponse.substring(7); // Remove "VALUE: "
            
            if (!address.equals("NOT_FOUND")) {
                System.out.println("Address found: " + address);
            } else {
                System.out.println("Service not found in DNS.");
            }

            Message responseMessage = new Message("EXIT", "");
            sendEncryptedMessage(responseMessage, out, aesKey, aesCipher);

        } catch (Exception e) {
            System.err.println("DNS connection error: " + e.getMessage());
        }
        System.out.println("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
        
        return address;
    }


    private static void connectToAppServer(String address, Scanner scanner) {
        String[] parts = address.split(":");
        String host = parts[0];
        int port = Integer.parseInt(parts[1]);

        try (Socket socket = new Socket(host, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            System.out.println("Conectando ao App Server (" + host + ":" + port + ")...");
            
            // Security handshake
            Object[] crypto = performHandshake(out, in);
            if (crypto == null) return;
            
            SecretKey aesKey = (SecretKey) crypto[0];
            AES aesCipher = (AES) crypto[1];

            // Receive welcome message
            String welcomeMessage = receiveEncryptedMessage(in, aesCipher);
            String[] welcomeParts = welcomeMessage.split(";");
            String welcomeText = welcomeParts[1];
            System.out.print(welcomeText);

            // Loop
            while (true) {
                System.out.print("\n:");
                String userInput = scanner.nextLine();
                String[] msgParts = userInput.split(" ", 2);
                String instruction = msgParts[0].toUpperCase();
                String metadata = (msgParts.length > 1) ? msgParts[1] : "";
                
                // Generic message usage
                Message message = new Message(instruction, metadata); 

                if (instruction.equals("EXIT")) {
                    sendEncryptedMessage(new Message("EXIT", ""), out, aesKey, aesCipher);
                    System.out.println("Server response: " + receiveEncryptedMessage(in, aesCipher));
                    break;
                }

                sendEncryptedMessage(message, out, aesKey, aesCipher);

                String serverResponse = receiveEncryptedMessage(in, aesCipher);
                System.out.println("Server response: " + serverResponse);
            }

        } catch (Exception e) {
            System.err.println("Erro na conexão com o App Server: " + e.getMessage());
        }
    }


    private static Object[] performHandshake(PrintWriter out, BufferedReader in) {
        try {
            // Receives RSA public key
            String rsaPublicKeyBase64 = in.readLine();
            byte[] rsaPublicKeyBytes = Base64.getDecoder().decode(rsaPublicKeyBase64);

            // Reconstructs the PublicKey object
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(rsaPublicKeyBytes);
            PublicKey serverRsaPublicKey = kf.generatePublic(keySpec);

            // Generates a random AES key for the session
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            SecretKey aesKey = kg.generateKey();
            AES aesCipher = new AES(aesKey);

            // Crypts the AES key with the server's RSA public key
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverRsaPublicKey);
            byte[] encryptedAesKeyBytes = rsaCipher.doFinal(aesKey.getEncoded());

            // Sends the encrypted AES key (in Base64) to the server
            out.println(Base64.getEncoder().encodeToString(encryptedAesKeyBytes));

            System.out.println("Handshake complete. Secure channel established.\n");
            return new Object[]{ aesKey, aesCipher };
        } catch (IllegalArgumentException e) {
            System.err.println("Falha no Handshake: Servidor indisponível ou resposta inválida.");
            return null;
        } catch (Exception e) {
            System.err.println("Falha no Handshake: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }


    private static void sendEncryptedMessage(Message message, PrintWriter out, SecretKey aesKey, AES aesCipher) throws Exception {
        byte[] hmacBytes = Util.calculateHmacSha256(aesKey.getEncoded(), message.getContent().getBytes());
        message.setHmac(Util.bytes2Hex(hmacBytes));

        String messageString = message.toString();

        String encryptedMessage = aesCipher.encrypt(messageString);

        out.println(encryptedMessage);
    }


    private static String receiveEncryptedMessage(BufferedReader in, AES aesCipher) throws IOException {
        String encryptedResponse = in.readLine();
        if (encryptedResponse == null) {
            throw new IOException("Server disconnected.");
        }
        
        return aesCipher.decrypt(encryptedResponse);
    }
}