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
import org.example.network.NetworkScanner;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;

public class ReceiverController {

    @FXML
    private StackPane wirelessScanPane;

    @FXML
    private ListView<CheckBox> fileListView;

    private String currentServerUrl = null;
    private String currentPin = null;

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

    // --- PIN Verification ---
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
                    Platform.runLater(() -> showAlert("Connected", "PIN verified! Fetching file list..."));
                    fetchFilesFromSender();
                } else {
                    Platform.runLater(() -> showAlert("PIN Error", "Incorrect PIN!"));
                }
            } catch (Exception e) {
                Platform.runLater(() -> showAlert("Connection Error", "Could not connect: " + e.getMessage()));
            }
        }).start();
    }

    // --- Fetch and Download Files ---
    private void fetchFilesFromSender() {
        new Thread(() -> {
            try {
                URL url = new URL(currentServerUrl + "/files?pin=" + URLEncoder.encode(currentPin, StandardCharsets.UTF_8));
                BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
                List<String> files = reader.lines().toList();
                reader.close();

                Platform.runLater(() -> {
                    fileListView.getItems().clear();
                    if (files.isEmpty()) {
                        fileListView.getItems().add(new CheckBox("No files available."));
                    } else {
                        files.forEach(file -> fileListView.getItems().add(new CheckBox(file)));
                    }
                });
            } catch (Exception e) {
                Platform.runLater(() -> showAlert("Error", "Could not fetch files: " + e.getMessage()));
            }
        }).start();
    }

    @FXML
    private void onSelectAll() {
        for (CheckBox cb : fileListView.getItems()) {
            cb.setSelected(true);
        }
    }

    @FXML
    private void onDownloadSelected() {
        if (currentServerUrl == null || currentPin == null) {
            showAlert("Error", "Not connected to a sender.");
            return;
        }

        List<String> selectedFiles = fileListView.getItems().stream()
                .filter(CheckBox::isSelected)
                .map(CheckBox::getText)
                .toList();

        if (selectedFiles.isEmpty()) {
            showAlert("No Selection", "Please select at least one file to download.");
            return;
        }

        for (String file : selectedFiles) {
            downloadFile(file);
        }
    }

    private void downloadFile(String fileName) {
        new Thread(() -> {
            try {
                String encodedFileName = URLEncoder.encode(fileName, StandardCharsets.UTF_8);
                URL url = new URL(currentServerUrl + "/download?file=" + encodedFileName +
                        "&pin=" + URLEncoder.encode(currentPin, StandardCharsets.UTF_8));

                Path savePath = Path.of(System.getProperty("user.home"), "Downloads", fileName);
                try (InputStream in = url.openStream()) {
                    Files.copy(in, savePath, StandardCopyOption.REPLACE_EXISTING);
                }
                Platform.runLater(() -> showAlert("Download Complete", "File saved to: " + savePath));
            } catch (Exception e) {
                Platform.runLater(() -> showAlert("Download Error", "Failed to download: " + e.getMessage()));
            }
        }).start();
    }

    // --- Wireless Scan ---
    @FXML
    private void onWirelessScan() {
        startRippleEffect();
        new Thread(() -> {
            List<String> devices = NetworkScanner.scanNetwork(); // Returns IP:PORT
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
            String deviceInfo = devices.get(i); // Format: IP:PORT
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
