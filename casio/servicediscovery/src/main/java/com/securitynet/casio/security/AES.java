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
            
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            byte[] encryptedMessageBytes = cipher.doFinal(openText.getBytes());
            
            byte[] ivAndCiphertext = new byte[IV_LENGTH + encryptedMessageBytes.length];
            System.arraycopy(iv, 0, ivAndCiphertext, 0, IV_LENGTH);
            System.arraycopy(encryptedMessageBytes, 0, ivAndCiphertext, IV_LENGTH, encryptedMessageBytes.length);

            String encryptedMessage = Base64.getEncoder().encodeToString(ivAndCiphertext);
            return encryptedMessage;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.println("Erro ao criptografar (AES Client): " + e.getMessage());
            return null;
        }
    }

    public String decrypt(String encryptedTextBase64) {
        try {
            byte[] ivAndCiphertext = Base64.getDecoder().decode(encryptedTextBase64);
            
            if (ivAndCiphertext.length <= IV_LENGTH) {
                throw new IllegalBlockSizeException("Input data too short to contain IV and ciphertext. Length: " + ivAndCiphertext.length);
            }
            
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(ivAndCiphertext, 0, iv, 0, IV_LENGTH);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            int ciphertextLength = ivAndCiphertext.length - IV_LENGTH;
            byte[] ciphertext = new byte[ciphertextLength];
            System.arraycopy(ivAndCiphertext, IV_LENGTH, ciphertext, 0, ciphertextLength);

            Cipher decryptor = Cipher.getInstance(CIPHER_INSTANCE);
            decryptor.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] decryptedMessageBytes = decryptor.doFinal(ciphertext);
            return new String(decryptedMessageBytes);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.println("Erro ao descriptografar (AES Client): " + e.getMessage());
            return null;
        } catch (IllegalArgumentException e) {
            System.err.println("Erro ao descriptografar (AES Client): Resposta não era Base64 (provavelmente texto plano). " + e.getMessage());
            return null;
        }
    }
}