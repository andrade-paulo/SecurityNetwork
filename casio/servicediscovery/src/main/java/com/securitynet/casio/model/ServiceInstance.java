package com.securitynet.casio.model;

import java.util.Objects;

public class ServiceInstance {
    private final String host;
    private final int port;
    private boolean alive;
    private final String instanceId;

    public ServiceInstance(String host, int port) {
        this.host = host;
        this.port = port;
        this.alive = false;
        this.instanceId = host + ":" + port;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public boolean isAlive() {
        return alive;
    }

    public void setAlive(boolean alive) {
        this.alive = alive;
    }

    public String getInstanceId() {
        return instanceId;
    }

    @Override
    public String toString() {
        return "ServiceInstance{" +
                "instanceId='" + instanceId + '\'' +
                ", alive=" + alive +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServiceInstance that = (ServiceInstance) o;
        return instanceId.equals(that.instanceId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(instanceId);
    }
}