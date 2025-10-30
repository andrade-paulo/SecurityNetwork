package com.securitynet;

import com.securitynet.model.DNSMessage;
import com.securitynet.security.AES;
import com.securitynet.security.Util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;

// Imports de Criptografia
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class Browser {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 8000;

    private static SecretKey aesKey; // Chave AES da sessão
    private static AES aesCipher;    // Cifrador AES da sessão

    public static void main(String[] args) {
        
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             Scanner scanner = new Scanner(System.in)) {

            System.out.println("Connected to DNS server. Performing handshake...");

            // ==========================================================
            // FASE 1: HANDSHAKE (Troca de Chave)
            // ==========================================================

            // 1. Recebe a chave pública RSA do servidor (Base64)
            String rsaPublicKeyBase64 = in.readLine();
            byte[] rsaPublicKeyBytes = Base64.getDecoder().decode(rsaPublicKeyBase64);

            // 2. Reconstrói a Chave Pública RSA
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(rsaPublicKeyBytes);
            PublicKey serverRsaPublicKey = kf.generatePublic(keySpec);

            // 3. Gera uma chave AES secreta
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256); // Tamanho de chave robusto (requer JCE ilimitado)
            aesKey = kg.generateKey();
            aesCipher = new AES(aesKey); // Inicializa nosso cifrador

            // 4. Cifra a chave AES com a chave pública RSA do servidor
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverRsaPublicKey);
            byte[] encryptedAesKeyBytes = rsaCipher.doFinal(aesKey.getEncoded());

            // 5. Envia a chave AES cifrada (em Base64) para o servidor
            out.println(Base64.getEncoder().encodeToString(encryptedAesKeyBytes));

            System.out.println("Handshake complete. Secure channel established.");
            
            // ==========================================================
            // FASE 2: LOOP DE MENSAGENS (Comunicação Cifrada)
            // ==========================================================
            String userInput;

            while (true) {
                String[] validCommands = {"ADD", "GET", "REMOVE", "UPDATE", "EXIT"};

                System.out.println("\nEnter command (ADD <name> <ip>, GET <name>, REMOVE <name>, UPDATE <name> <ip>, EXIT):");
                userInput = scanner.nextLine();

                String[] parts = userInput.split(" ", 2);
                String instruction = parts[0].toUpperCase();
                String metadata = (parts.length > 1) ? parts[1] : "";
                
                DNSMessage message = new DNSMessage(instruction, metadata);

                if (instruction.equals("EXIT")) {
                    sendEncryptedMessage(message, out);
                    String serverResponse = receiveEncryptedMessage(in);
                    System.out.println("Server response: " + serverResponse);
                    break;
                }

                if (!java.util.Arrays.asList(validCommands).contains(instruction)) {
                    System.out.println("Invalid command.");
                    continue;
                }

                if ((instruction.equals("ADD") || instruction.equals("UPDATE")) && metadata.split(" ").length < 2) {
                    System.out.println(metadata.split(" ").length);
                    System.out.println("Invalid " + instruction + " format. Use: " + instruction + " <name> <ip>");
                    continue;
                } else if ((instruction.equals("GET") || instruction.equals("REMOVE")) && metadata.split(" ").length < 1) {
                    System.out.println("Invalid " + instruction + " format. Use: " + instruction + " <name>");
                    continue;
                }

                // Envia a mensagem (cifrada + HMAC)
                sendEncryptedMessage(message, out);

                // Recebe a resposta (cifrada)
                String serverResponse = receiveEncryptedMessage(in);
                System.out.println("Server response: " + serverResponse);
            }

        } catch (IOException e) {
            System.err.println("Client IO error: " + e.getMessage());
        } catch (Exception e) {
            // Captura exceções de criptografia
            System.err.println("Client crypto error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Método auxiliar para gerar HMAC, definir na mensagem, criptografar e enviar.
     */
    private static void sendEncryptedMessage(DNSMessage message, PrintWriter out) throws Exception {
        // 1. Gera HMAC usando a chave AES da sessão
        byte[] hmacBytes = Util.calculateHmacSha256(aesKey.getEncoded(), message.getContent().getBytes());
        message.setHmac(Util.bytes2Hex(hmacBytes));

        // 2. Converte a mensagem inteira (com HMAC) para String
        String messageString = message.toString();

        // 3. Criptografa a mensagem (usando AES/CBC + IV)
        String encryptedMessage = aesCipher.encrypt(messageString);

        // 4. Envia
        out.println(encryptedMessage);
    }

    /**
     * Método auxiliar para receber, descriptografar e retornar a resposta.
     */
    private static String receiveEncryptedMessage(BufferedReader in) throws IOException {
        String encryptedResponse = in.readLine();
        if (encryptedResponse == null) {
            throw new IOException("Server disconnected.");
        }
        
        // Descriptografa a resposta (usando AES/CBC + IV)
        return aesCipher.decrypt(encryptedResponse);
    }
}