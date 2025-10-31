package com.securitynet.casio.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.securitynet.casio.model.Message;
import com.securitynet.casio.model.DAO.SecurityKeyDAO; // NOVO IMPORT
import com.securitynet.casio.security.AES;

public class DNSRegistryService {
    
    public static void registerWithDNS(String dnsHost, int dnsPort, String serviceName, String serviceAddress) {
        System.out.println("[DNSRegistry] Tentando registrar " + serviceName + " -> " + serviceAddress + " no DNS em " + dnsHost + ":" + dnsPort);

        // Try to load existing AES key from file
        SecurityKeyDAO dao = SecurityKeyDAO.loadKeysFromFile();
        String dnsKeyBase64 = (dao != null) ? dao.getDnsKey() : null;
        
        SecretKey aesKey = null;
        byte[] aesKeyBytes = null;
        AES aesCipher = null;

        try (Socket socket = new Socket(dnsHost, dnsPort);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            System.out.println("[DNSRegistry] Nenhuma chave AES encontrada. Executando handshake...");

            // Receive server RSA key
            String serverRsaKeyBase64 = in.readLine();
            if (serverRsaKeyBase64 == null) {
                throw new IOException("Servidor DNS não enviou chave RSA.");
            }

            if (dnsKeyBase64 != null) {  // If there is an existing key, reuse it
                System.out.println("[DNSRegistry] Carregando chave AES existente do arquivo.");
                aesKeyBytes = Base64.getDecoder().decode(dnsKeyBase64);
                aesKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
            } else {  // If no existing key, generate a new one
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                aesKey = keyGen.generateKey();
                aesKeyBytes = aesKey.getEncoded();
            }

            // Send AES key (new or existing) encrypted with RSA
            byte[] serverRsaKeyBytes = Base64.getDecoder().decode(serverRsaKeyBase64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(serverRsaKeyBytes);
            PublicKey serverRsaPublicKey = KeyFactory.getInstance("RSA").generatePublic(spec);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverRsaPublicKey);
            byte[] encryptedAesKeyBytes = rsaCipher.doFinal(aesKeyBytes);
            String encryptedAesKeyBase64 = Base64.getEncoder().encodeToString(encryptedAesKeyBytes);

            out.println(encryptedAesKeyBase64);

            System.out.println("[DNSRegistry] Handshake com DNS concluído. Chave AES estabelecida.");
            aesCipher = new AES(aesKey);

            // Save the AES key if it was newly generated
            if (dao == null) dao = new SecurityKeyDAO();
            dao.setDnsKey(Base64.getEncoder().encodeToString(aesKeyBytes));
            dao.saveKeysToFile();
            System.out.println("[DNSRegistry] Chave AES salva para uso futuro.");

            // Try to update or add the service record
            String response = sendDnsMessage(aesCipher, out, in, "UPDATE", serviceName + " " + serviceAddress, aesKeyBytes);

            if (response != null && response.startsWith("ERROR: Name does not exist")) {
                System.out.println("[DNSRegistry] Nome não existe. Tentando adicionar...");
                response = sendDnsMessage(aesCipher, out, in, "ADD", serviceName + " " + serviceAddress, aesKeyBytes);
            }

            System.out.println("[DNSRegistry] Resposta do Servidor DNS: " + response);

            // Closes the connection
            sendDnsMessage(aesCipher, out, in, "EXIT", "", aesKeyBytes);
        } catch (Exception e) {
            if (dnsKeyBase64 != null && 
                (e instanceof javax.crypto.BadPaddingException || 
                 e instanceof javax.crypto.IllegalBlockSizeException ||
                 e instanceof java.security.InvalidKeyException)) 
            {
                System.err.println("[DNSRegistry] Falha criptográfica (" + e.getClass().getSimpleName() + "). A chave AES salva pode estar inválida.");
                // Limpa a chave e salva
                if (dao != null) {
                    dao.setDnsKey(null);
                    dao.saveKeysToFile();
                    System.err.println("[DNSRegistry] Chave AES inválida removida. Tente novamente para executar um novo handshake.");
                }
            } else {
                 System.err.println("[DNSRegistry] Falha ao registrar no DNS: " + e.getMessage());
            }
            // e.printStackTrace();
        }
    }

    private static String sendDnsMessage(AES aesCipher, PrintWriter out, BufferedReader in, 
                                         String instruction, String metadata, byte[] aesKeyBytes) throws Exception {
        
        Message message = new Message(instruction, metadata);
        String messageWithHmac = message.buildMessageWithHmac(aesKeyBytes);
        String encryptedMessage = aesCipher.encrypt(messageWithHmac);

        out.println(encryptedMessage);

        if (instruction.equals("EXIT")) {
            return "Connection closed";
        }
        
        String encryptedResponse = in.readLine();
        if (encryptedResponse == null) {
            throw new IOException("Servidor DNS desconectou inesperadamente.");
        }

        String decryptedResponse = aesCipher.decrypt(encryptedResponse);
        if (decryptedResponse == null) {
            throw new javax.crypto.BadPaddingException("Falha ao descriptografar a resposta do DNS. A chave pode estar inválida.");
        }
        return decryptedResponse;
    }
}