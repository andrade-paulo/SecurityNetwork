package com.securitynet.casio.model.DAO;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class SecurityKeyDAO implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final String KEY_FILE_PATH = "Data/security_keys.dat";

    private String dnsKey;
    private String appServerKey;

    public SecurityKeyDAO() {
        this.dnsKey = null;
        this.appServerKey = null;
    }

    public String getDnsKey() {
        return dnsKey;
    }

    public void setDnsKey(String dnsKey) {
        this.dnsKey = dnsKey;
    }

    public String getAppServerKey() {
        return appServerKey;
    }

    public void setAppServerKey(String appServerKey) {
        this.appServerKey = appServerKey;
    }

    // Write in a binary file
    public void saveKeysToFile() {
        try {
            File keyFile = new File(KEY_FILE_PATH);
            File dataDir = keyFile.getParentFile();
            if (!dataDir.exists()) {
                if (dataDir.mkdirs()) {
                    System.out.println("[SecurityKeyDAO] Criado diretório: " + dataDir.getAbsolutePath());
                } else {
                    System.err.println("[SecurityKeyDAO] Falha ao criar diretório: " + dataDir.getAbsolutePath());
                }
            }

            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(keyFile))) {
                oos.writeObject(this);
            }
        } catch (IOException e) {
            System.err.println("[SecurityKeyDAO] Falha ao salvar chaves: " + e.getMessage());
            // e.printStackTrace();
        }
    }

    public static SecurityKeyDAO loadKeysFromFile() {
        // Check if file exists
        File keyFile = new File(KEY_FILE_PATH);
        if (!keyFile.exists()) {
            System.out.println("[SecurityKeyDAO] Arquivo de chaves não encontrado.");
            return null;
        }
        
        try (java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.io.FileInputStream(keyFile))) {
            return (SecurityKeyDAO) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("[SecurityKeyDAO] Falha ao carregar chaves: " + e.getMessage());
            // e.printStackTrace();
            return null;
        }
    }
}