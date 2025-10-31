package com.securitynet.casio;

import com.securitynet.casio.model.ServiceInstance;
import com.securitynet.casio.service.DNSRegistryService;
import com.securitynet.casio.service.HealthCheckService;
import com.securitynet.casio.service.LoadBalancerHandler;
import com.securitynet.casio.service.RegistryService;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ServiceDiscovery {
    private static final int LOAD_BALANCER_PORT = 9000;
    
    // DNS configuration
    private static final String DNS_HOST = "localhost";
    private static final int DNS_PORT = 8053;
    private static final String SERVICE_NAME = "casio.com";


    public static void main(String[] args) {
        System.out.println("=====================================");
        System.out.println("Starting Casio Service Discovery (LB)");
        System.out.println("=====================================\n");

        RegistryService registry = RegistryService.getInstance();

        // Still hardcoding some service instances
        registry.register(new ServiceInstance("localhost", 9001));
        registry.register(new ServiceInstance("localhost", 9002));
        
        // Health Check Thread
        HealthCheckService healthChecker = new HealthCheckService(registry);
        new Thread(healthChecker, "HealthCheckThread").start();

        // Register with DNS
        String selfAddress = "localhost:" + LOAD_BALANCER_PORT;
        DNSRegistryService.registerWithDNS(DNS_HOST, DNS_PORT, SERVICE_NAME, selfAddress);

        // Main Load Balancer Server Loop
        try (ServerSocket serverSocket = new ServerSocket(LOAD_BALANCER_PORT)) {
            System.out.println("\nService Discovery (LB) escutando na porta " + LOAD_BALANCER_PORT);
            
            while (true) {
                Socket clientSocket = serverSocket.accept();
                LoadBalancerHandler handler = new LoadBalancerHandler(clientSocket, registry);
                new Thread(handler).start();
            }

        } catch (IOException e) {
            System.err.println("Erro ao iniciar o Service Discovery: " + e.getMessage());
        }
    }
}