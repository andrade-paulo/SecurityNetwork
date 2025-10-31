package com.securitynet.casio.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.securitynet.casio.model.entities.Message;
import com.securitynet.casio.security.AES;
import com.securitynet.casio.security.Util;

public class ApplicationHandler implements Runnable {
    private Socket socket;
    private boolean connection = true;
    private String socketAddress;

    private Calculator calculator;

    private KeyPair rsaKeyPair;
    private SecretKey clientAesKey;
    private byte[] clientAesKeyBytes;
    private AES aesCipher; 

    public ApplicationHandler(Socket socket) {
        this.socket = socket;
        this.socketAddress = socket.getInetAddress().getHostAddress() + ":" + socket.getPort();
        
        this.calculator = new Calculator();

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048); 
            this.rsaKeyPair = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Erro ao inicializar RSA: " + e.getMessage());
            this.connection = false; 
        }

        System.out.println("New connection from " + this.socketAddress);
    }

    @Override
    public void run() {
        try (PrintWriter out = new PrintWriter(socket.getOutputStream(), true); 
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            
            if (!connection) return; 

            // Security Handshake
            out.println(Base64.getEncoder().encodeToString(this.rsaKeyPair.getPublic().getEncoded()));

            String encryptedAesKeyBase64 = in.readLine();
            if (encryptedAesKeyBase64 == null) {
                connection = false;
                return; 
            }

            byte[] encryptedAesKeyBytes = Base64.getDecoder().decode(encryptedAesKeyBase64);
            
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, this.rsaKeyPair.getPrivate());
            byte[] decryptedAesKeyBytes = rsaCipher.doFinal(encryptedAesKeyBytes);

            this.clientAesKey = new SecretKeySpec(decryptedAesKeyBytes, 0, decryptedAesKeyBytes.length, "AES");
            this.clientAesKeyBytes = this.clientAesKey.getEncoded();
            this.aesCipher = new AES(this.clientAesKey);
            
            System.out.println("Handshake com " + this.socketAddress + " concluído. Chave AES estabelecida.");

            // Send wellcome message
            String welcomeMessage = "Welcome to Casio Secure Calculator Service!\n" +
                                    "You can perform operations: ADD, SUBTRACT, MULTIPLY, DIVIDE.\n" +
                                    "Example: ADD 9+8\n" +
                                    "Send 'EXIT' to close the connection.\n";

            Message welcomeMsgObj = new Message("WELCOME", welcomeMessage);

            String encryptedWelcomeMsg = aesCipher.encrypt(welcomeMsgObj.toString());
            out.println(encryptedWelcomeMsg);

            // Main communication loop
            String inputLine;

            while (connection && (inputLine = in.readLine()) != null) {
                String decryptedInputLine = aesCipher.decrypt(inputLine);
                if (decryptedInputLine == null) {
                    out.println(aesCipher.encrypt("ERROR: Invalid message decryption."));
                    continue;
                }

                Message message = new Message(decryptedInputLine);

                // Valida o HMAC usando os bytes da chave AES do cliente
                if (!validateHmac(this.clientAesKeyBytes, message.getHmac(), message.getContent().getBytes())) { 
                    out.println(aesCipher.encrypt("PERMISSION DENIED: Invalid HMAC."));
                    continue;
                }
                
                String instruction = message.getInstruction();
                String response = ""; 

                if (instruction.equals("ADD")) {
                    response = add(message);
                } else if (instruction.equals("SUBTRACT")) {
                    response = subtract(message);
                } else if (instruction.equals("MULTIPLY")) {
                    response = multiply(message);
                } else if (instruction.equals("DIVIDE")) {
                    response = divide(message);
                } else if (instruction.equals("EXIT")) {
                    response = "Connection closing.";
                    connection = false;
                } else {
                    response = "ERROR: Unknown instruction.";
                }

                out.println(aesCipher.encrypt(response));
            }
        } 
        
        catch (IOException e) {
            //
        } catch (Exception e) {
            System.err.println("Erro de criptografia na conexão " + this.socketAddress + ": " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                //
            }
            System.out.println("Connection closed for " + this.socketAddress + "\n");
        }
    }


    private boolean validateHmac(byte[] key, String hmac, byte[] data) {
        try {
            byte[] hmacBytes = Util.calculateHmacSha256(key, data);
            String calculatedHmac = Util.bytes2Hex(hmacBytes);

            return calculatedHmac.equals(hmac);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    private String add(Message message) {
        String[] parts = message.getMetadata().split("\\+");
        
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);
        
        int result = calculator.add(a, b);

        return "RESULT: " + result;
    }

    private String subtract(Message message) {
        String[] parts = message.getMetadata().split("\\-");
        
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);
        
        int result = calculator.subtract(a, b);

        return "RESULT: " + result;
    }

    private String multiply(Message message) {
        String[] parts = message.getMetadata().split("\\*");
        
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);
        
        int result = calculator.multiply(a, b);

        return "RESULT: " + result;
    }

    private String divide(Message message) {
        String[] parts = message.getMetadata().split("\\/");
        
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);
        
        try {
            double result = calculator.divide(a, b);
            return "RESULT: " + result;
        } catch (IllegalArgumentException e) {
            return "ERROR: " + e.getMessage();
        }
    }
}
