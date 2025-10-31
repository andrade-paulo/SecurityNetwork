package com.securitynet.casio.security;

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
    private final int IV_LENGTH = 16;

    public AES(SecretKey key) {
        this.key = key;
    }

    public String encrypt(String openText) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
            
            // Generate random Initialization Vector (IV)
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            byte[] encryptedMessageBytes = cipher.doFinal(openText.getBytes());
            
            // Concat IV e Ciphertext
            byte[] ivAndCiphertext = new byte[IV_LENGTH + encryptedMessageBytes.length];
            System.arraycopy(iv, 0, ivAndCiphertext, 0, IV_LENGTH);
            System.arraycopy(encryptedMessageBytes, 0, ivAndCiphertext, IV_LENGTH, encryptedMessageBytes.length);

            // Encrypted message in Base64
            String encryptedMessage = Base64.getEncoder().encodeToString(ivAndCiphertext);

            System.out.println(">> Mensagem cifrada (com IV): " + encryptedMessage);
            return encryptedMessage;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }


    public String decrypt(String encryptedTextBase64) {
        try {
            byte[] ivAndCiphertext = Base64.getDecoder().decode(encryptedTextBase64);
            
            // Extract IV
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(ivAndCiphertext, 0, iv, 0, IV_LENGTH);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Extract Ciphertext
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