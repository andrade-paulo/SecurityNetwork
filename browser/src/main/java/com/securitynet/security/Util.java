package com.securitynet.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import io.github.cdimascio.dotenv.Dotenv;

public class Util {
    private static Dotenv dotenv = Dotenv.configure().directory("src/main/resources/").filename(".env").load();

    public static byte[] calculateHmacSha256(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(keySpec);

        return mac.doFinal(data);
    }

    public static String bytes2Hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();

        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        
        return result.toString();
    }

    public static byte[] get_common_client_key() {
        String key_string = dotenv.get("COMMON_CLIENT_KEY");
        return key_string.getBytes();
    }
}
