package com.securitynet.model.entities;

public class NameTableEntry {
    private String value;
    private byte[] ownerKey; // A chave AES (bytes) do cliente que criou

    public NameTableEntry(String value, byte[] ownerKey) {
        this.value = value;
        this.ownerKey = ownerKey;
    }

    public String getValue() {
        return value;
    }

    public byte[] getOwnerKey() {
        return ownerKey;
    }

    public void setValue(String newValue) {
        this.value = newValue;
    }
}