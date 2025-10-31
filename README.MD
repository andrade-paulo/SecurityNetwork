# SecurityNet
This is a project that simulates a whole local network with different services and a generic client. The main goal of this project is to study network security concepts and practices by implementing various security measures and protocols within the simulated environment.

# Technologies Used
- **Programming Language**: Java 17
- **Encryption Algorithms**: RSA for asymmetric encryption, AES for symmetric encryption, and HMAC for message authentication.
- **Networking**: Socket programming for communication between the client and services.

# Architecture 

## Components
Every communication is performed through sockets.
- **Mini-DNS**: A simple DNS server that resolves domain names to IP addresses within the simulated network.
- **Casio Calculation Service**: A service that performs basic arithmetic calculations, simulating a calculator application.
- **Browser**: A generic client application that can make requests to different services within the network.

## Network Concept
[IMAGE HERE]

## DNS Architecture Diagram
[IMAGE HERE]

## Casio Architecture Diagram
[IMAGE HERE]

# Security Measures Implemented
- **Confidentiality**: An RSA handshake is performed at the beginning of each session to securely exchange the symmetric keys used for encryption.
- **Confidentiality**: All communications between the client and services are encrypted using symmetric encryption (AES) to ensure data confidentiality.
- **Authentication & Integrity**: HMAC (Hash-based Message Authentication Code) is used to verify the authenticity and integrity of the messages.

## Security Handshake
[IMAGE HERE]

