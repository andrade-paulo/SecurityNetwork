package com.securitynet.service;

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
import com.securitynet.model.NameTable;
import com.securitynet.model.entities.DNSMessage;
import com.securitynet.security.AES;
import com.securitynet.security.Util;

public class ApplicationHandler implements Runnable {
    private Socket socket;
    private boolean connection = true;
    private NameTable nameTable;
    private String socketAddress;

    private KeyPair rsaKeyPair;
    private SecretKey clientAesKey;
    private byte[] clientAesKeyBytes;
    private AES aesCipher; 
    
    public ApplicationHandler(Socket socket, NameTable nameTable) {
        this.socket = socket;
        this.nameTable = nameTable;
        this.socketAddress = socket.getInetAddress().getHostAddress() + ":" + socket.getPort();
        
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

            // Main communication loop
            String inputLine;
            while (connection && (inputLine = in.readLine()) != null) {
                
                String decryptedInputLine = aesCipher.decrypt(inputLine);
                if (decryptedInputLine == null) {
                    out.println(aesCipher.encrypt("ERROR: Invalid message decryption."));
                    continue;
                }

                DNSMessage message = new DNSMessage(decryptedInputLine);

                // Valida o HMAC usando os bytes da chave AES do cliente
                if (!validateHmac(this.clientAesKeyBytes, message.getHmac(), message.getContent().getBytes())) { 
                    out.println(aesCipher.encrypt("PERMISSION DENIED: Invalid HMAC."));
                    continue;
                }
                
                String instruction = message.getInstruction();
                String response = ""; 

                if (instruction.equals("ADD")) {
                    response = add(message);
                } else if (instruction.equals("GET")) {
                    response = get(message);
                } else if (instruction.equals("REMOVE")) {
                    response = remove(message);
                } else if (instruction.equals("UPDATE")) {
                    response = update(message);
                } else if (instruction.equals("EXIT")) {
                    response = "Connection closing.";
                    connection = false;
                } else {
                    response = "ERROR: Unknown instruction.";
                }

                out.println(aesCipher.encrypt(response));
            }

        } catch (IOException e) {
            System.err.println("Error handling connection from " + this.socketAddress + ": " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Erro de criptografia na conexão " + this.socketAddress + ": " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                //
            }
            System.out.println("Connection closed for " + this.socketAddress);
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


    private String add(DNSMessage message) {
        String[] parts = message.getMetadata().split(" ", 2);
        if (parts.length < 2) {
            return "ERROR: Invalid ADD format. Use: ADD <name> <value>";
        }

        String name = parts[0];
        String value = parts[1];

        try {
            nameTable.addName(name, value, this.clientAesKeyBytes); 
            return "SUCCESS: Name added.";
        } catch (IllegalArgumentException e) {
            return "ERROR: " + e.getMessage();
        }
    }

    private String get(DNSMessage message) {
        String name = message.getMetadata();

        try {
            String value = nameTable.getName(name);
            if (value != null) {
                return "VALUE: " + value;
            } else {
                return "ERROR: Name not found.";
            }
        } catch (IllegalArgumentException e) {
            return "ERROR: " + e.getMessage();
        }
    }

    private String remove(DNSMessage message) {
        String name = message.getMetadata();

        try {
            nameTable.removeName(name, this.clientAesKeyBytes);
            return "SUCCESS: Name removed.";
        } catch (IllegalArgumentException e) {
            return "ERROR: " + e.getMessage();
        } catch (SecurityException e) {
            return e.getMessage();
        }
    }

    private String update(DNSMessage message) {
        String[] parts = message.getMetadata().split(" ", 2);
        if (parts.length < 2) {
            return "ERROR: Invalid UPDATE format. Use: UPDATE <name> <new_value>";
        }

        String name = parts[0];
        String newValue = parts[1];

        try {
            nameTable.updateName(name, newValue, this.clientAesKeyBytes);
            return "SUCCESS: Name updated.";
        } catch (IllegalArgumentException e) {
            return "ERROR: " + e.getMessage();
        } catch (SecurityException e) {
            return e.getMessage();
        }
    }
}