package org.example.controller;

import javafx.animation.ScaleTransition;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.stage.Stage;
import javafx.util.Duration;
import org.example.crypto.CryptoUtils;
import org.example.crypto.KeyExchangeUtils;
import org.example.crypto.KeyManager;
import org.example.network.NetworkScanner;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

public class ReceiverController {

    @FXML
    private StackPane wirelessScanPane;

    @FXML
    private ListView<CheckBox> fileListView;

    private String currentServerUrl = null;
    private String currentPin = null;

    private SecretKey sessionKey;

    @FXML
    private void onBack(javafx.event.ActionEvent event) {
        try {
            Parent mainView = FXMLLoader.load(getClass().getResource("/fxml/main_view.fxml"));
            Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
            stage.setScene(new Scene(mainView));
            stage.show();
        } catch (Exception e) {
            e.printStackTrace();
            showAlert("Navigation Error", "Unable to go back: " + e.getMessage());
        }
    }

    private void askForPin(String serverUrl) {
        TextInputDialog pinDialog = new TextInputDialog();
        pinDialog.setTitle("Enter PIN");
        pinDialog.setHeaderText("Enter the PIN shown on the sender's screen");
        pinDialog.setContentText("PIN:");
        pinDialog.showAndWait().ifPresent(pin -> connectToSender(serverUrl, pin));
    }

    private void connectToSender(String serverUrl, String pin) {
        new Thread(() -> {
            try {
                URL url = new URL(serverUrl + "/pin");
                BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
                String serverPin = reader.readLine().trim();
                reader.close();

                if (serverPin.equals(pin)) {
                    currentServerUrl = serverUrl;
                    currentPin = pin;

                    KeyPair kp = KeyManager.loadOrCreateKeyPair();
                    PublicKey myPub = kp.getPublic();
                    PrivateKey myPriv = kp.getPrivate();

                    String pubB64 = KeyExchangeUtils.publicKeyToBase64(myPub);
                    URL regUrl = new URL(serverUrl + "/register?pin=" + URLEncoder.encode(pin, StandardCharsets.UTF_8));
                    HttpURLConnection conn = (HttpURLConnection) regUrl.openConnection();
                    conn.setDoOutput(true);
                    conn.setRequestMethod("POST");
                    byte[] payload = pubB64.getBytes(StandardCharsets.UTF_8);
                    conn.setFixedLengthStreamingMode(payload.length);
                    conn.setRequestProperty("Content-Type", "text/plain; charset=UTF-8");
                    conn.connect();
                    try (OutputStream os = conn.getOutputStream()) { os.write(payload); }
                    int code = conn.getResponseCode();
                    conn.disconnect();
                    if (code != 200) {
                        Platform.runLater(() -> showAlert("Registration Error", "Sender refused public key registration: HTTP " + code));
                        return;
                    }

                    URL wk = new URL(serverUrl + "/wrappedKey?pin=" + URLEncoder.encode(pin, StandardCharsets.UTF_8));
                    HttpURLConnection wconn = (HttpURLConnection) wk.openConnection();
                    wconn.setRequestMethod("GET");
                    int wc = wconn.getResponseCode();
                    if (wc != 200) {
                        Platform.runLater(() -> showAlert("Key Error", "Failed to get wrapped key: HTTP " + wc));
                        wconn.disconnect();
                        return;
                    }
                    String lineEphemeral;
                    String lineWrapped;
                    try (BufferedReader br = new BufferedReader(new InputStreamReader(wconn.getInputStream(), StandardCharsets.UTF_8))) {
                        lineEphemeral = br.readLine();
                        lineWrapped = br.readLine();
                    }
                    wconn.disconnect();

                    if (lineEphemeral == null || lineWrapped == null) {
                        Platform.runLater(() -> showAlert("Key Error", "Malformed wrapped key response from sender."));
                        return;
                    }

                    PublicKey senderEphemeralPub = KeyExchangeUtils.publicKeyFromBase64(lineEphemeral.trim());
                    byte[] wrappedBytes = Base64.getDecoder().decode(lineWrapped.trim());

                    byte[] aesKeyBytes = KeyExchangeUtils.unwrapAesKeyWithX25519(myPriv, senderEphemeralPub, wrappedBytes);
                    sessionKey = CryptoUtils.secretKeyFromBytes(aesKeyBytes);

                    Platform.runLater(() -> showAlert("Connected", "PIN verified and key exchanged! Fetching file list..."));
                    fetchFilesFromSender();
                } else {
                    Platform.runLater(() -> showAlert("PIN Error", "Incorrect PIN!"));
                }
            } catch (Exception e) {
                e.printStackTrace();
                Platform.runLater(() -> showAlert("Connection Error", "Could not connect: " + e.getMessage()));
            }
        }).start();
    }

    private void fetchFilesFromSender() {
        new Thread(() -> {
            try {
                URL url = new URL(currentServerUrl + "/files?pin=" + URLEncoder.encode(currentPin, StandardCharsets.UTF_8));
                BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
                List<String> files = reader.lines().toList();
                reader.close();

                Platform.runLater(() -> {
                    fileListView.getItems().clear();
                    if (files.isEmpty()) fileListView.getItems().add(new CheckBox("No files available."));
                    else files.forEach(file -> fileListView.getItems().add(new CheckBox(file)));
                });
            } catch (Exception e) {
                Platform.runLater(() -> showAlert("Error", "Could not fetch files: " + e.getMessage()));
            }
        }).start();
    }

    @FXML
    private void onSelectAll() {
        for (CheckBox cb : fileListView.getItems()) cb.setSelected(true);
    }

    @FXML
    private void onDownloadSelected() {
        if (currentServerUrl == null || currentPin == null) {
            showAlert("Error", "Not connected to a sender.");
            return;
        }
        List<String> selectedFiles = fileListView.getItems().stream().filter(CheckBox::isSelected).map(CheckBox::getText).toList();
        if (selectedFiles.isEmpty()) { showAlert("No Selection", "Please select at least one file to download."); return; }
        for (String file : selectedFiles) downloadFile(file);
    }

    private void downloadFile(String fileName) {
        new Thread(() -> {
            try {
                String encodedFileName = URLEncoder.encode(fileName, StandardCharsets.UTF_8);
                URL url = new URL(currentServerUrl + "/download?file=" + encodedFileName +
                        "&pin=" + URLEncoder.encode(currentPin, StandardCharsets.UTF_8));

                Path savePath = Path.of(System.getProperty("user.home"), "Downloads", fileName);
                Files.createDirectories(savePath.getParent());

                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setDoInput(true);
                int code = conn.getResponseCode();
                if (code != 200) {
                    Platform.runLater(() -> showAlert("Download Error", "Server returned HTTP " + code));
                    conn.disconnect();
                    return;
                }

                try (InputStream in = conn.getInputStream();
                     OutputStream fileOut = Files.newOutputStream(savePath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                    CryptoUtils.decryptStream(in, fileOut, sessionKey);
                }
                conn.disconnect();

                Platform.runLater(() -> showAlert("Download Complete", "File saved to: " + savePath));
            } catch (Exception e) {
                e.printStackTrace();
                Platform.runLater(() -> showAlert("Download Error", "Failed to download: " + e.getMessage()));
            }
        }).start();
    }

    @FXML
    private void onWirelessScan() {
        startRippleEffect();
        new Thread(() -> {
            List<String> devices = NetworkScanner.scanNetwork();
            Platform.runLater(() -> displayDevicesAroundRipple(devices));
        }).start();
    }

    private void displayDevicesAroundRipple(List<String> devices) {
        wirelessScanPane.getChildren().removeIf(node -> node.getUserData() != null);
        if (devices.isEmpty()) {
            Label noDeviceLabel = new Label("No devices found");
            noDeviceLabel.setTextFill(Color.RED);
            wirelessScanPane.getChildren().add(noDeviceLabel);
            return;
        }

        double angleStep = 360.0 / devices.size();
        double radius = 100;

        for (int i = 0; i < devices.size(); i++) {
            String deviceInfo = devices.get(i);
            String[] parts = deviceInfo.split(":");
            String ip = parts[0];
            String port = (parts.length > 1) ? parts[1] : "80";

            Circle deviceCircle = new Circle(25, Color.LIGHTBLUE);
            deviceCircle.setStroke(Color.DARKBLUE);
            deviceCircle.setUserData("device");

            Label ipLabel = new Label(ip + ":" + port);
            ipLabel.setTextFill(Color.BLACK);
            StackPane deviceNode = new StackPane(deviceCircle, ipLabel);
            deviceNode.setAlignment(Pos.CENTER);

            double angle = Math.toRadians(angleStep * i);
            deviceNode.setTranslateX(radius * Math.cos(angle));
            deviceNode.setTranslateY(radius * Math.sin(angle));

            deviceNode.setOnMouseClicked(event -> askForPin("http://" + ip + ":" + port));

            wirelessScanPane.getChildren().add(deviceNode);
        }
    }

    private void startRippleEffect() {
        wirelessScanPane.getChildren().clear();
        for (int i = 0; i < 3; i++) {
            Circle ripple = new Circle(50, Color.web("#4CAF50", 0.3));
            ripple.setStroke(Color.web("#4CAF50"));
            ripple.setStrokeWidth(2);
            ripple.setOpacity(0.5);

            ScaleTransition st = new ScaleTransition(Duration.seconds(2 + i), ripple);
            st.setFromX(1);
            st.setFromY(1);
            st.setToX(3);
            st.setToY(3);
            st.setCycleCount(ScaleTransition.INDEFINITE);
            st.setAutoReverse(true);

            wirelessScanPane.getChildren().add(ripple);
            st.play();
        }
    }

    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}
