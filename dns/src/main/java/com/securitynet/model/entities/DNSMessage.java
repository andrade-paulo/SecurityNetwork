package com.securitynet.model.entities;

public class DNSMessage {
    private String instruction;
    private String metadata;
    private String hmac;

    public DNSMessage(String instruction, String metadata) {
        this.instruction = instruction;
        this.metadata = metadata;
        this.hmac = "";
    }

    public DNSMessage(String rawMessage) {
        String parts[] = rawMessage.split(";", 3);
        this.instruction = parts[0];
        this.metadata = parts.length > 1 ? parts[1] : "";
        this.hmac = parts.length > 2 ? parts[2] : "";
    }

    public String getInstruction() {
        return instruction;
    }

    public String getMetadata() {
        return metadata;
    }

    public String getContent() {
        return this.instruction + ";" + this.metadata;
    }

    public String getHmac() {
        return hmac;
    }

    @Override
    public String toString() {
        return instruction + ";" + metadata + ";" + hmac;
    }
}
