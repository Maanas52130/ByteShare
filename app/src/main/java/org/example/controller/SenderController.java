package org.example.controller;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import javafx.embed.swing.SwingFXUtils;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.example.network.FileServer;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class SenderController {

    @FXML
    private ListView<String> fileList;

    @FXML
    private ImageView qrImageView;

    @FXML
    private Label pinLabel;

    private final List<File> selectedFiles = new ArrayList<>();
    private FileServer fileServer;

    @FXML
    private void onBack() {
        if (fileServer != null) {
            fileServer.stop();
        }
        System.out.println("Back to main menu...");
        // TODO: Implement scene switching
    }

    @FXML
    private void onSelectFiles() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select Files to Share");
        List<File> files = fileChooser.showOpenMultipleDialog(new Stage());
        if (files != null) {
            selectedFiles.clear();
            selectedFiles.addAll(files);
            fileList.getItems().clear();
            for (File file : files) {
                fileList.getItems().add(file.getAbsolutePath());
            }
        }
    }

    @FXML
    private void onGenerateQR() {
        if (selectedFiles.isEmpty()) {
            showAlert("No Files Selected", "Please select files before generating a QR code.");
            return;
        }

        if (fileServer != null) {
            Alert confirmAlert = new Alert(Alert.AlertType.CONFIRMATION);
            confirmAlert.setTitle("Confirm QR Regeneration");
            confirmAlert.setHeaderText(null);
            confirmAlert.setContentText("A QR code is already generated. Do you want to generate a new one?");
            Optional<ButtonType> result = confirmAlert.showAndWait();
            if (result.isEmpty() || result.get() != ButtonType.OK) {
                return;
            }
            fileServer.stop();
            fileServer = null;
        }

        try {
            fileServer = new FileServer(selectedFiles);
            fileServer.start();

            String serverUrl = fileServer.getAccessUrl();
            System.out.println("Server URL: " + serverUrl);

            // Generate QR Code for server URL
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(serverUrl, BarcodeFormat.QR_CODE, 250, 250);
            BufferedImage bufferedImage = MatrixToImageWriter.toBufferedImage(bitMatrix);
            Image fxImage = SwingFXUtils.toFXImage(bufferedImage, null);
            qrImageView.setImage(fxImage);

            pinLabel.setText("PIN: " + fileServer.getPin());

        } catch (WriterException | IOException e) {
            e.printStackTrace();
            showAlert("Error", "Could not generate QR code or start server: " + e.getMessage());
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
