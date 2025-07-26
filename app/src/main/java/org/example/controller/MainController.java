package org.example.controller;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import java.io.IOException;

public class MainController {

    @FXML
    private void onSenderClick(javafx.event.ActionEvent event) {
        try {
            Parent senderView = FXMLLoader.load(getClass().getResource("/fxml/sender_view.fxml"));
            Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
            stage.setScene(new Scene(senderView));
            stage.show();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @FXML
    private void onReceiverClick(javafx.event.ActionEvent event) {
        try {
            Parent receiverView = FXMLLoader.load(getClass().getResource("/fxml/receiver_view.fxml"));
            Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
            stage.setScene(new Scene(receiverView));
            stage.show();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
