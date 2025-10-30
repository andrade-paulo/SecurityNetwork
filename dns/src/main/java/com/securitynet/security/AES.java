package com.securitynet.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AES {
    
    private SecretKey key;
    private final String CIPHER_INSTANCE = "AES/CBC/PKCS5Padding";
    private final int IV_LENGTH = 16; // AES IV é sempre 16 bytes

    // 1. Construtor modificado para aceitar a chave
    public AES(SecretKey key) {
        this.key = key;
        // Não gera mais a chave aqui
    }

    // Método generateKey() removido (ou mantido se for usado em outro lugar, 
    // mas não no construtor)

    // 2. Encrypt modificado para usar CBC e IV
    public String encrypt(String openText) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
            
            // Gera um IV aleatório
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            byte[] encryptedMessageBytes = cipher.doFinal(openText.getBytes());
            
            // Concatena IV + Ciphertext para envio
            byte[] ivAndCiphertext = new byte[IV_LENGTH + encryptedMessageBytes.length];
            System.arraycopy(iv, 0, ivAndCiphertext, 0, IV_LENGTH);
            System.arraycopy(encryptedMessageBytes, 0, ivAndCiphertext, IV_LENGTH, encryptedMessageBytes.length);

            // Codifica o [IV + Ciphertext] em Base64
            String encryptedMessage = Base64.getEncoder().encodeToString(ivAndCiphertext);

            System.out.println(">> Mensagem cifrada (com IV): " + encryptedMessage);
            return encryptedMessage;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    // 3. Decrypt modificado para extrair o IV e usar CBC
    public String decrypt(String encryptedTextBase64) {
        try {
            byte[] ivAndCiphertext = Base64.getDecoder().decode(encryptedTextBase64);
            
            // Extrai o IV (primeiros 16 bytes)
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(ivAndCiphertext, 0, iv, 0, IV_LENGTH);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Extrai o Ciphertext (o resto)
            int ciphertextLength = ivAndCiphertext.length - IV_LENGTH;
            byte[] ciphertext = new byte[ciphertextLength];
            System.arraycopy(ivAndCiphertext, IV_LENGTH, ciphertext, 0, ciphertextLength);

            Cipher decryptor = Cipher.getInstance(CIPHER_INSTANCE);
            decryptor.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] decryptedMessageBytes = decryptor.doFinal(ciphertext);
            return new String(decryptedMessageBytes);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }
}