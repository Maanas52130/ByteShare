package org.example.network;

import java.net.*;
import java.util.ArrayList;
import java.util.List;

/**
 * NetworkScanner that discovers ByteShare senders using UDP broadcast.
 */
public class NetworkScanner {

    private static final int DISCOVERY_PORT = 60000; // Fixed discovery port
    private static final String DISCOVERY_MESSAGE = "DISCOVER_BYTESHARE";
    private static final int TIMEOUT = 200; // ms per packet

    public static List<String> scanNetwork() {
        List<String> senders = new ArrayList<>();
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setBroadcast(true);
            socket.setSoTimeout(TIMEOUT);

            // Broadcast discovery message
            byte[] data = DISCOVERY_MESSAGE.getBytes();
            DatagramPacket packet = new DatagramPacket(data, data.length,
                    InetAddress.getByName("255.255.255.255"), DISCOVERY_PORT);
            socket.send(packet);

            long start = System.currentTimeMillis();
            while (System.currentTimeMillis() - start < 1000) { // Wait up to 1 sec
                try {
                    byte[] buffer = new byte[512];
                    DatagramPacket response = new DatagramPacket(buffer, buffer.length);
                    socket.receive(response);

                    String message = new String(response.getData(), 0, response.getLength()).trim();
                    if (message.startsWith("BYTESHARE::")) {
                        senders.add(message.substring("BYTESHARE::".length())); // Extract IP:Port
                    }
                } catch (SocketTimeoutException ignored) {
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return senders;
    }
}
