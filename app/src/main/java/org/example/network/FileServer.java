package org.example.network;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.example.crypto.CryptoUtils;
import org.example.crypto.KeyExchangeUtils;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.Base64;

public class FileServer {

    private static final int DISCOVERY_PORT = 60000;
    private final int fileServerPort;

    private HttpServer server;
    private DiscoveryServer discoveryServer;
    private final List<File> files;
    private final String pin;

    private SecretKey sessionAesKey;
    private final AtomicReference<PublicKey> registeredReceiverPub = new AtomicReference<>();

    public FileServer(List<File> files) throws IOException {
        this.files = files;
        this.fileServerPort = findFreePort();
        this.pin = generatePin();
    }

    public void start() throws IOException {
        try {
            this.sessionAesKey = CryptoUtils.generateAesKey();
        } catch (Exception e) {
            throw new IOException("Unable to create session AES key: " + e.getMessage(), e);
        }

        server = HttpServer.create(new InetSocketAddress(fileServerPort), 0);
        server.createContext("/", new RootHandler());
        server.createContext("/files", new FileListHandler());
        server.createContext("/download", new FileDownloadHandler());
        server.createContext("/web", new WebHandler());
        server.createContext("/pin", new PinHandler());
        server.createContext("/register", new RegisterHandler());
        server.createContext("/wrappedKey", new WrappedKeyHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("[FileServer] Running at: " + getAccessUrl());

        discoveryServer = new DiscoveryServer(fileServerPort);
        discoveryServer.start();
    }

    public void stop() {
        if (server != null) server.stop(0);
        if (discoveryServer != null) discoveryServer.stopServer();
    }

    public String getPin() { return pin; }

    public String getAccessUrl() throws UnknownHostException {
        return "http://" + InetAddress.getLocalHost().getHostAddress() + ":" + fileServerPort;
    }

    private class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String html = """
                <!DOCTYPE html><html><head><meta charset="UTF-8"><title>ByteShare</title></head><body>
                <h2>Enter PIN to Access Files</h2>
                <form action="/web" method="get">
                    <label for="pin">PIN:</label>
                    <input type="password" id="pin" name="pin" required>
                    <button type="submit">Submit</button>
                </form></body></html>
            """;
            byte[] data = html.getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, data.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(data); }
        }
    }

    private class FileListHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String providedPin = getQueryParam(exchange.getRequestURI().getQuery(), "pin");
            if (providedPin == null || !providedPin.equals(pin)) {
                exchange.sendResponseHeaders(403, 0);
                try (OutputStream os = exchange.getResponseBody()) { os.write("Invalid PIN".getBytes()); }
                return;
            }
            StringBuilder sb = new StringBuilder();
            for (File file : files) sb.append(file.getName()).append("\n");
            byte[] response = sb.toString().getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(response); }
        }
    }

    private class WebHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String providedPin = getQueryParam(exchange.getRequestURI().getQuery(), "pin");
            if (providedPin == null || !providedPin.equals(pin)) {
                String errorHtml = "<html><body><h3>Invalid PIN!</h3><a href=\"/\">Go Back</a></body></html>";
                byte[] errorData = errorHtml.getBytes();
                exchange.getResponseHeaders().add("Content-Type", "text/html");
                exchange.sendResponseHeaders(403, errorData.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(errorData); }
                return;
            }
            StringBuilder sb = new StringBuilder("<html><head><title>ByteShare Files</title></head><body><h2>Available Files</h2><ul>");
            for (File file : files) {
                sb.append("<li><a href='/download?file=").append(URLEncoder.encode(file.getName(), "UTF-8"))
                  .append("&pin=").append(pin).append("'>").append(file.getName()).append("</a></li>");
            }
            sb.append("</ul></body></html>");
            byte[] response = sb.toString().getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(response); }
        }
    }

    private class FileDownloadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            if (query == null) { exchange.sendResponseHeaders(400, -1); return; }

            String requestedFileName = getQueryParam(query, "file");
            String providedPin = getQueryParam(query, "pin");
            if (providedPin == null || !providedPin.equals(pin)) {
                exchange.sendResponseHeaders(403, 0);
                try (OutputStream os = exchange.getResponseBody()) { os.write("Invalid PIN".getBytes()); }
                return;
            }

            File file = files.stream().filter(f -> f.getName().equals(requestedFileName)).findFirst().orElse(null);
            if (file == null) { exchange.sendResponseHeaders(404, -1); return; }

            exchange.getResponseHeaders().add("Content-Disposition", "attachment; filename=\"" + file.getName() + "\"");
            exchange.sendResponseHeaders(200, 0);

            try (OutputStream os = exchange.getResponseBody();
                 InputStream fis = Files.newInputStream(file.toPath())) {
                CryptoUtils.encryptStream(fis, os, sessionAesKey);
            } catch (Exception e) { e.printStackTrace(); }
        }
    }

    private class PinHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] response = pin.getBytes();
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(response); }
        }
    }

    private class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { exchange.sendResponseHeaders(405, -1); return; }
            String providedPin = getQueryParam(exchange.getRequestURI().getQuery(), "pin");
            if (providedPin == null || !providedPin.equals(pin)) {
                exchange.sendResponseHeaders(403, 0);
                try (OutputStream os = exchange.getResponseBody()) { os.write("Invalid PIN".getBytes()); }
                return;
            }
            String body;
            try (InputStream is = exchange.getRequestBody()) { body = new String(is.readAllBytes()); }
            if (body == null || body.isBlank()) {
                exchange.sendResponseHeaders(400, 0);
                try (OutputStream os = exchange.getResponseBody()) { os.write("Missing public key".getBytes()); }
                return;
            }
            try {
                PublicKey pub = KeyExchangeUtils.publicKeyFromBase64(body.trim());
                registeredReceiverPub.set(pub);
                String ok = "OK";
                exchange.sendResponseHeaders(200, ok.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(ok.getBytes()); }
                System.out.println("[FileServer] Registered receiver public key for session.");
            } catch (Exception ex) {
                ex.printStackTrace();
                String err = "Invalid public key";
                exchange.sendResponseHeaders(400, err.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(err.getBytes()); }
            }
        }
    }

    private class WrappedKeyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String providedPin = getQueryParam(exchange.getRequestURI().getQuery(), "pin");
            if (providedPin == null || !providedPin.equals(pin)) {
                exchange.sendResponseHeaders(403, 0);
                try (OutputStream os = exchange.getResponseBody()) { os.write("Invalid PIN".getBytes()); }
                return;
            }
            PublicKey receiverPub = registeredReceiverPub.get();
            if (receiverPub == null) {
                String err = "Receiver public key not registered";
                exchange.sendResponseHeaders(400, err.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(err.getBytes()); }
                return;
            }

            try {
                KeyPair ephemeral = KeyExchangeUtils.generateX25519KeyPair();
                byte[] aesKeyBytes = sessionAesKey.getEncoded();
                byte[] wrapped = KeyExchangeUtils.wrapAesKeyWithX25519(ephemeral.getPrivate(), receiverPub, aesKeyBytes);

                String ephemeralB64 = KeyExchangeUtils.publicKeyToBase64(ephemeral.getPublic());
                String wrappedB64 = Base64.getEncoder().encodeToString(wrapped);

                String resp = ephemeralB64 + "\n" + wrappedB64;
                byte[] out = resp.getBytes();
                exchange.getResponseHeaders().add("Content-Type", "text/plain");
                exchange.sendResponseHeaders(200, out.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(out); }
                System.out.println("[FileServer] Provided wrapped AES key (ephemeral pub returned).");
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, 0);
            }
        }
    }
    

    private static class DiscoveryServer extends Thread {
        private volatile boolean running = true;
        private DatagramSocket socket;
        private final int fileServerPort;

        public DiscoveryServer(int fileServerPort) { this.fileServerPort = fileServerPort; }

        @Override
        public void run() {
            try {
                socket = new DatagramSocket(DISCOVERY_PORT, InetAddress.getByName("0.0.0.0"));
                System.out.println("[DiscoveryServer] Listening for discovery on port " + DISCOVERY_PORT);

                byte[] buffer = new byte[512];
                while (running) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);

                    String message = new String(packet.getData(), 0, packet.getLength()).trim();
                    if (message.equals("DISCOVER_BYTESHARE")) {
                        String reply = "BYTESHARE::" + InetAddress.getLocalHost().getHostAddress() + ":" + fileServerPort;
                        byte[] replyData = reply.getBytes();
                        DatagramPacket response = new DatagramPacket(replyData, replyData.length,
                                packet.getAddress(), packet.getPort());
                        socket.send(response);
                        System.out.println("[DiscoveryServer] Responded to " + packet.getAddress());
                    }
                }
            } catch (IOException e) {
                if (running) e.printStackTrace();
            }
        }

        public void stopServer() {
            running = false;
            if (socket != null && !socket.isClosed()) socket.close();
        }
    }

    private static String getQueryParam(String query, String key) {
        if (query == null) return null;
        for (String param : query.split("&")) {
            if (param.startsWith(key + "=")) {
                try { return URLDecoder.decode(param.substring(key.length() + 1), "UTF-8"); }
                catch (Exception ignored) {}
            }
        }
        return null;
    }

    private int findFreePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        }
    }

    private String generatePin() {
        Random random = new Random();
        return String.valueOf(1000 + random.nextInt(9000));
    }
}
