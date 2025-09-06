package org.example;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class App extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("/fxml/main_view.fxml"));
        Scene scene = new Scene(root, 500, 350);

        scene.getStylesheets().add(getClass().getResource("/css/style.css").toExternalForm());

        primaryStage.setTitle("ByteShare");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void main(String[] args) {
        // Register BouncyCastle as a provider
        Security.addProvider(new BouncyCastleProvider());

        launch(args);
    }
}
