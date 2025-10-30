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

    /**
     * Construtor que aceita a chave AES da sessão.
     */
    public AES(SecretKey key) {
        this.key = key;
    }

    /**
     * Cifra uma mensagem de texto simples.
     * Usa AES/CBC, gera um IV aleatório e o anexa ao início (prepend) do ciphertext.
     */
    public String encrypt(String openText) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
            
            // 1. Gera um IV aleatório
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            // 2. Cifra a mensagem
            byte[] encryptedMessageBytes = cipher.doFinal(openText.getBytes());
            
            // 3. Concatena IV + Ciphertext
            byte[] ivAndCiphertext = new byte[IV_LENGTH + encryptedMessageBytes.length];
            System.arraycopy(iv, 0, ivAndCiphertext, 0, IV_LENGTH);
            System.arraycopy(encryptedMessageBytes, 0, ivAndCiphertext, IV_LENGTH, encryptedMessageBytes.length);

            // 4. Codifica em Base64 para transmissão
            return Base64.getEncoder().encodeToString(ivAndCiphertext);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.println("Erro ao criptografar: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Decifra uma mensagem (Base64) que contém [IV + Ciphertext].
     */
    public String decrypt(String encryptedTextBase64) {
        try {
            byte[] ivAndCiphertext = Base64.getDecoder().decode(encryptedTextBase64);
            
            // 1. Extrai o IV (primeiros 16 bytes)
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(ivAndCiphertext, 0, iv, 0, IV_LENGTH);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // 2. Extrai o Ciphertext (o resto)
            int ciphertextLength = ivAndCiphertext.length - IV_LENGTH;
            byte[] ciphertext = new byte[ciphertextLength];
            System.arraycopy(ivAndCiphertext, IV_LENGTH, ciphertext, 0, ciphertextLength);

            // 3. Decifra
            Cipher decryptor = Cipher.getInstance(CIPHER_INSTANCE);
            decryptor.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] decryptedMessageBytes = decryptor.doFinal(ciphertext);
            return new String(decryptedMessageBytes);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.println("Erro ao descriptografar: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}