package com.securitynet.casio.service;

import com.securitynet.casio.model.ServiceInstance;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class RegistryService {
    // CopyOnWriteArrayList is thread-safe for concurrent access
    private final List<ServiceInstance> instances = new CopyOnWriteArrayList<>();
    
    // AtomicInteger is used to ensure thread-safe round-robin selection
    private final AtomicInteger counter = new AtomicInteger(0);

    private static final RegistryService instance = new RegistryService();

    private RegistryService() {}

    public static RegistryService getInstance() {
        return instance;
    }

    public void register(ServiceInstance serviceInstance) {
        if (!instances.contains(serviceInstance)) {
            instances.add(serviceInstance);
            System.out.println("[RegistryService] Nova instância registrada: " + serviceInstance.getInstanceId());
        }
    }

    public void unregister(ServiceInstance serviceInstance) {
        instances.remove(serviceInstance);
        System.out.println("[RegistryService] Instância removida: " + serviceInstance.getInstanceId());
    }

    public List<ServiceInstance> getAllInstances() {
        return instances;
    }

    public ServiceInstance getNextInstance() {
        List<ServiceInstance> aliveInstances = instances.stream()
                .filter(ServiceInstance::isAlive)
                .collect(Collectors.toList());

        if (aliveInstances.isEmpty()) {
            return null; // No alive instances available
        }

        // Round-Robin Logic
        int index = counter.getAndIncrement() % aliveInstances.size();
        return aliveInstances.get(index);
    }
}