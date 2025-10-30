package com.securitynet.model;

import java.util.Arrays; // Importe para comparar os arrays de bytes
import java.util.HashMap;

import com.securitynet.model.entities.NameTableEntry;

public class NameTable {
    // Agora o HashMap armazena a entrada completa
    private HashMap<String, NameTableEntry> nameMap;

    public NameTable() {
        this.nameMap = new HashMap<>();
    }

    /**
     * Adiciona um nome, associando-o ao valor (IP) e à chave do proprietário.
     */
    public void addName(String name, String value, byte[] ownerKey) {
        if (name == null || value == null || ownerKey == null) {
            throw new IllegalArgumentException("Name, value, and owner key cannot be null");
        }

        if (nameMap.containsKey(name)) {
            throw new IllegalArgumentException("Name already exists in the table");
        }

        NameTableEntry entry = new NameTableEntry(value, ownerKey);
        nameMap.put(name, entry);
    }

    /**
     * Obtém o valor (IP) de um nome. (Esta lógica não muda)
     */
    public String getName(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Name cannot be null");
        }
        
        NameTableEntry entry = nameMap.get(name);
        return (entry != null) ? entry.getValue() : null;
    }

    /**
     * Remove um nome, mas SOMENTE se a chave fornecida corresponder à chave do proprietário.
     */
    public void removeName(String name, byte[] requestingKey) {
        if (name == null || requestingKey == null) {
            throw new IllegalArgumentException("Name and requesting key cannot be null");
        }

        NameTableEntry entry = nameMap.get(name);

        if (entry == null) {
            throw new IllegalArgumentException("Name does not exist in the table");
        }

        // AQUI ESTÁ A LÓGICA DE PERMISSÃO
        if (!Arrays.equals(entry.getOwnerKey(), requestingKey)) {
            // Lança uma exceção de segurança se as chaves não baterem
            throw new SecurityException("PERMISSION DENIED: You are not the owner of this entry.");
        }

        // Se passou na verificação, remove
        nameMap.remove(name);
    }

    public void updateName(String name, String newValue, byte[] requestingKey) {
        if (name == null || newValue == null || requestingKey == null) {
            throw new IllegalArgumentException("Name, new value, and requesting key cannot be null");
        }

        NameTableEntry entry = nameMap.get(name);

        if (entry == null) {
            throw new IllegalArgumentException("Name does not exist in the table");
        }

        // Verifica a permissão
        if (!Arrays.equals(entry.getOwnerKey(), requestingKey)) {
            throw new SecurityException("PERMISSION DENIED: You are not the owner of this entry.");
        }

        // Atualiza o valor
        entry.setValue(newValue);
    }

    public boolean containsName(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Name cannot be null");
        }

        return nameMap.containsKey(name);
    }

    public int size() {
        return nameMap.size();
    }
}