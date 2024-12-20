package com.example.client_app1;

import com.example.client_app1.encryption.AESEncryption;
import com.example.client_app1.model.Credentials;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.stage.Stage;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.NoSuchElementException;
import java.util.regex.Pattern;

public class ClientApplication extends Application {
    private Socket socket;
    private final AESEncryption encryption = new AESEncryption();
    @Override
    public void start(Stage primaryStage) {
        // Create UI elements
        Label hostLabel = new Label("Bootstrapping host:");
        TextField hostField = new TextField();
        hostField.setText("localhost");
        Label portLabel = new Label("Bootstrapping port:");
        TextField portField = new TextField();
        portField.setText("5000");
        TextFormatter<String> textFormatter = new TextFormatter<>(change ->
                (change.getControlNewText().matches("\\d*")) ? change : null);
        portField.setTextFormatter(textFormatter);

        Button submitButton = new Button("Connect");
        submitButton.setOnAction(event -> connectToServerSocket(hostField.getText(),
                Integer.parseInt(portField.getText()), primaryStage));

        // Set up grid pane layout
        GridPane grid = new GridPane();
        grid.setPadding(new Insets(10));
        grid.setVgap(5);
        grid.setHgap(5);
        GridPane.setConstraints(hostLabel, 0, 0);
        GridPane.setConstraints(hostField, 1, 0);
        GridPane.setConstraints(portLabel, 2, 0);
        GridPane.setConstraints(portField, 3, 0);
        GridPane.setConstraints(submitButton, 1, 1);
        grid.getChildren().addAll(hostLabel, hostField, portLabel, portField, submitButton);

        // Create scene and show it
        Scene scene = new Scene(grid, 600, 100);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void connectToServerSocket(String host, int port, Stage stage) {
        try {
            // Connect to server socket
            socket = new Socket(host, port);

            // Display success message on GUI
            Platform.runLater(() -> {
                Alert alert = new Alert(Alert.AlertType.INFORMATION);
                alert.setTitle("Connection Successful");
                alert.setHeaderText("Connected to server socket");
                alert.showAndWait();
                stage.close();
            });

            // Show account creation form
            accountCreationForm();
        } catch (IOException e) {
            // Display error message on GUI
            Platform.runLater(() -> {
                Alert alert = new Alert(Alert.AlertType.ERROR);
                alert.setTitle("Connection Error");
                alert.setHeaderText("Failed to connect to server socket");
                alert.setContentText(e.getMessage());
                alert.showAndWait();
            });
        }
    }

    private void accountCreationForm() {
        // Create UI elements
        Stage accountCreationForm = new Stage();
        Label usernameLabel = new Label("Username:");
        TextField usernameField = new TextField();
        Label passwordLabel = new Label("Password:");
        PasswordField passwordField = new PasswordField();
        Button submitButton = new Button("Create Account");
        submitButton.setOnAction(event -> sendCredentialsToServer(new Credentials(usernameField.getText(), passwordField.getText()),accountCreationForm));

        // Set up grid pane layout
        GridPane grid = new GridPane();
        grid.setPadding(new Insets(10));
        grid.setVgap(5);
        grid.setHgap(5);
        GridPane.setConstraints(usernameLabel, 0, 0);
        GridPane.setConstraints(usernameField, 1, 0);
        GridPane.setConstraints(passwordLabel, 0, 1);
        GridPane.setConstraints(passwordField, 1, 1);
        GridPane.setConstraints(submitButton, 1, 2);
        grid.getChildren().addAll(usernameLabel, usernameField, passwordLabel, passwordField, submitButton);

        // Create scene and show it
        accountCreationForm.setTitle("Account Creation Form");
        Scene scene = new Scene(grid, 300, 150);
        accountCreationForm.setScene(scene);
        accountCreationForm.show();
    }
    private void sendCredentialsToServer(Credentials credentials, Stage stage) {
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            if(!verifyPassword(credentials.getPassword()))
                throw new IllegalArgumentException();

            // Convert credentials to JSON and encrypt
            ObjectMapper objectMapper = new ObjectMapper();
            String json = objectMapper.writeValueAsString(credentials);
            byte[] encrypted = encryption.encrypt(json);

            // Send encrypted credentials to server
            out.writeObject(encrypted);
            out.flush();

            // Receive response from server
            byte[] response = (byte[]) in.readObject();

            if (response != null) {
                // Decrypt response and display data
                String decrypted = encryption.decrypt(response);
                Credentials newCredentials = objectMapper.readValue(decrypted, Credentials.class);
                stage.close();
                displayData(newCredentials);
            } else {
                throw new NoSuchElementException("No response from server");
            }
        } catch (IOException e) {
            // Display error message on GUI
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Connection Error");
            alert.setHeaderText("Failed to send credentials to server");
            alert.setContentText(e.getMessage());
            alert.showAndWait();
        }catch (IllegalArgumentException e) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Invalid Password");
            alert.setHeaderText("The password does not meet the requirement");
            alert.setContentText("The password must be at least 8 characters long.\n" +
                    "The password must contain at least one uppercase letter.\n" +
                    "The password must contain at least one lowercase letter.\n" +
                    "The password must contain at least one digit.");
            alert.showAndWait();
        } catch (NoSuchElementException e) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Wrong password");
            alert.setHeaderText("You entered a wrong password");
            alert.showAndWait();
        } catch (Exception e) {
            // Display error message on GUI
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Error");
            alert.setHeaderText("Failed to process server response");
            alert.setContentText(e.getMessage());
            alert.showAndWait();
        }
    }
    private void displayData(Credentials credentials) {
        // Create labels for the username, password, and node address values
        Label usernameValue = new Label(credentials.getUsername());
        Label passwordValue = new Label(credentials.getPassword());
        Label nodeValue = new Label(credentials.getNodeAddress());

        // Set up a grid pane and add the labels
        GridPane grid = new GridPane();
        grid.setPadding(new Insets(10, 10, 10, 10));
        grid.setVgap(5);
        grid.setHgap(5);
        grid.add(new Label("Username:"), 0, 0);
        grid.add(usernameValue, 1, 0);
        grid.add(new Label("Password:"), 0, 1);
        grid.add(passwordValue, 1, 1);
        grid.add(new Label("Node Address:"), 0, 2);
        grid.add(nodeValue, 1, 2);

        // Create a scene with the grid pane as the root node
        Scene scene = new Scene(grid, 300, 100);

        // Create a new stage for the scene and display it
        Stage stage = new Stage();
        stage.setTitle("Credentials");
        stage.setScene(scene);
        stage.show();
    }
    private boolean verifyPassword(String password) {
        final int MIN_LENGTH = 8;
        final Pattern UPPERCASE_PATTERN = Pattern.compile(".*[A-Z].*");
        final Pattern LOWERCASE_PATTERN = Pattern.compile(".*[a-z].*");
        final Pattern DIGIT_PATTERN = Pattern.compile(".*\\d.*");
        if (password == null || password.length() < MIN_LENGTH) {
            return false;
        }
        if (!UPPERCASE_PATTERN.matcher(password).matches()) {
            return false;
        }
        if (!LOWERCASE_PATTERN.matcher(password).matches()) {
            return false;
        }
        if (!DIGIT_PATTERN.matcher(password).matches()) {
            return false;
        }
        return true;
        }


    public static void main(String[] args) {
        launch();
    }
}