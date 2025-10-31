package com.securitynet.casio.service;

import com.securitynet.casio.model.ServiceInstance;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.List;

public class HealthCheckService implements Runnable {

    private final RegistryService registryService;
    private final int HEALTH_CHECK_INTERVAL = 10000;
    private final int CONNECTION_TIMEOUT = 2000;

    public HealthCheckService(RegistryService registryService) {
        this.registryService = registryService;
    }

    @Override
    public void run() {
        System.out.println("[HealthCheck] Serviço de Health Check iniciado.");
        while (true) {
            try {
                List<ServiceInstance> instances = registryService.getAllInstances();
                
                for (ServiceInstance instance : instances) {
                    checkInstance(instance);
                }

                Thread.sleep(HEALTH_CHECK_INTERVAL);
            } catch (InterruptedException e) {
                System.err.println("[HealthCheck] Serviço interrompido.");
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void checkInstance(ServiceInstance instance) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(instance.getHost(), instance.getPort()), CONNECTION_TIMEOUT);
            // Conexão bem-sucedida
            if (!instance.isAlive()) {
                instance.setAlive(true);
                System.out.println("[HealthCheck] Instância UP: " + instance.getInstanceId());
            }
        } catch (IOException e) {
            // Falha na conexão (timeout, recusada, etc.)
            if (instance.isAlive()) {
                instance.setAlive(false);
                System.err.println("[HealthCheck] Instância DOWN: " + instance.getInstanceId());
            }
        }
    }
}