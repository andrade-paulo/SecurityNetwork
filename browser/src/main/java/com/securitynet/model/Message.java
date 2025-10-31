package com.securitynet.model;

public class Message {
    private String instruction;
    private String metadata;
    private String hmac;

    public Message(String instruction, String metadata) {
        this.instruction = instruction;
        this.metadata = metadata;
        this.hmac = "";
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

    public void setHmac(String hmac) {
        this.hmac = hmac;
    }

    @Override
    public String toString() {
        return instruction + ";" + metadata + ";" + hmac;
    }
}