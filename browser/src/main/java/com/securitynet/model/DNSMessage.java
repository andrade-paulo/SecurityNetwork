package com.securitynet.model;

public class DNSMessage {
    private String instruction;
    private String metadata;
    private String hmac;

    /**
     * Construtor modificado. Não gera mais o HMAC.
     * O HMAC será definido externamente usando setHmac().
     */
    public DNSMessage(String instruction, String metadata) {
        this.instruction = instruction;
        this.metadata = metadata;
        this.hmac = ""; // Inicializa vazio
    }

    public String getInstruction() {
        return instruction;
    }

    public String getMetadata() {
        return metadata;
    }

    /**
     * Retorna o conteúdo que deve ser usado para gerar o HMAC.
     */
    public String getContent() {
        return this.instruction + ";" + this.metadata;
    }

    public String getHmac() {
        return hmac;
    }

    /**
     * Novo método para definir o HMAC gerado externamente.
     */
    public void setHmac(String hmac) {
        this.hmac = hmac;
    }

    /**
     * Retorna a mensagem completa formatada para envio.
     */
    @Override
    public String toString() {
        return instruction + ";" + metadata + ";" + hmac;
    }
}