package org.example.network;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;

/**
 * FileServer: Serves selected files and responds to discovery requests.
 * Now includes PIN protection and a web page with clickable downloads.
 */
public class FileServer {

    private static final int DISCOVERY_PORT = 60000; // Fixed port for discovery
    private final int fileServerPort;

    private HttpServer server;
    private DiscoveryServer discoveryServer;
    private final List<File> files;
    private final String pin;

    public FileServer(List<File> files) throws IOException {
        this.files = files;
        this.fileServerPort = findFreePort();
        this.pin = generatePin();
    }

    /** Start both file server and discovery server */
    public void start() throws IOException {
        // Start HTTP file server
        server = HttpServer.create(new InetSocketAddress(fileServerPort), 0);
        server.createContext("/", new RootHandler());
        server.createContext("/files", new FileListHandler());
        server.createContext("/download", new FileDownloadHandler());
        server.createContext("/web", new WebHandler());
        server.createContext("/pin", new PinHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("[FileServer] Running at: " + getAccessUrl());

        // Start discovery responder
        discoveryServer = new DiscoveryServer(fileServerPort);
        discoveryServer.start();
    }

    /** Stop servers */
    public void stop() {
        if (server != null) {
            server.stop(0);
            System.out.println("[FileServer] Stopped.");
        }
        if (discoveryServer != null) {
            discoveryServer.stopServer();
            System.out.println("[DiscoveryServer] Stopped.");
        }
    }

    public String getPin() {
        return pin;
    }

    public String getAccessUrl() throws UnknownHostException {
        return "http://" + InetAddress.getLocalHost().getHostAddress() + ":" + fileServerPort;
    }

    // ------------------- Internal Handlers ------------------------

    /** Root handler with PIN entry form */
    private class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>ByteShare</title>
                </head>
                <body>
                    <h2>Enter PIN to Access Files</h2>
                    <form action="/web" method="get">
                        <label for="pin">PIN:</label>
                        <input type="password" id="pin" name="pin" required>
                        <button type="submit">Submit</button>
                    </form>
                </body>
                </html>
            """;

            byte[] data = html.getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, data.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(data);
            }
        }
    }

    /** Handler for listing files as plain text (API use) */
    private class FileListHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            String providedPin = null;
            if (query != null) {
                for (String param : query.split("&")) {
                    if (param.startsWith("pin=")) {
                        providedPin = URLDecoder.decode(param.substring(4), "UTF-8");
                        break;
                    }
                }
            }

            if (providedPin == null || !providedPin.equals(pin)) {
                exchange.sendResponseHeaders(403, 0);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write("Invalid PIN".getBytes());
                }
                return;
            }

            // Return list of files as plain text
            StringBuilder sb = new StringBuilder();
            for (File file : files) {
                sb.append(file.getName()).append("\n");
            }

            byte[] response = sb.toString().getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    /** Handler for listing files with clickable links (Web UI) */
    private class WebHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            String providedPin = null;

            if (query != null) {
                for (String param : query.split("&")) {
                    if (param.startsWith("pin=")) {
                        providedPin = URLDecoder.decode(param.substring(4), "UTF-8");
                        break;
                    }
                }
            }

            if (providedPin == null || !providedPin.equals(pin)) {
                String errorHtml = """
                    <html><body>
                    <h3>Invalid PIN!</h3>
                    <a href="/">Go Back</a>
                    </body></html>
                """;
                byte[] errorData = errorHtml.getBytes();
                exchange.getResponseHeaders().add("Content-Type", "text/html");
                exchange.sendResponseHeaders(403, errorData.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(errorData);
                }
                return;
            }

            // Show list of files with download links
            StringBuilder sb = new StringBuilder("""
                <html><head><title>ByteShare Files</title></head><body>
                <h2>Available Files</h2><ul>
            """);
            for (File file : files) {
                sb.append("<li><a href='/download?file=")
                  .append(URLEncoder.encode(file.getName(), "UTF-8"))
                  .append("&pin=").append(pin)
                  .append("'>").append(file.getName()).append("</a></li>");
            }
            sb.append("</ul></body></html>");

            byte[] response = sb.toString().getBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    /** Handler for downloading files with PIN validation */
    private class FileDownloadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            if (query == null) {
                exchange.sendResponseHeaders(400, -1);
                exchange.close();
                return;
            }

            String requestedFileName = null;
            String providedPin = null;
            for (String param : query.split("&")) {
                if (param.startsWith("file=")) {
                    requestedFileName = URLDecoder.decode(param.substring(5), "UTF-8");
                } else if (param.startsWith("pin=")) {
                    providedPin = URLDecoder.decode(param.substring(4), "UTF-8");
                }
            }

            if (providedPin == null || !providedPin.equals(pin)) {
                exchange.sendResponseHeaders(403, 0);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write("Invalid PIN".getBytes());
                }
                return;
            }

            final String targetFile = requestedFileName;
            File file = files.stream()
                    .filter(f -> f.getName().equals(targetFile))
                    .findFirst()
                    .orElse(null);

            if (file == null) {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }

            exchange.getResponseHeaders().add("Content-Disposition",
                    "attachment; filename=\"" + file.getName() + "\"");
            exchange.sendResponseHeaders(200, file.length());
            try (OutputStream os = exchange.getResponseBody()) {
                Files.copy(file.toPath(), os);
            }
        }
    }

    /** Handler for verifying PIN (for API use) */
    private class PinHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] response = pin.getBytes();
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    /** Discovery UDP server */
    private static class DiscoveryServer extends Thread {
        private volatile boolean running = true;
        private DatagramSocket socket;
        private final int fileServerPort;

        public DiscoveryServer(int fileServerPort) {
            this.fileServerPort = fileServerPort;
        }

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

    /** Find a free port */
    private int findFreePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        }
    }

    /** Generate 4-digit PIN */
    private String generatePin() {
        Random random = new Random();
        return String.valueOf(1000 + random.nextInt(9000));
    }
}
