module com.example.client_app1 {
    requires javafx.controls;
    requires javafx.fxml;
    requires com.fasterxml.jackson.databind;


    opens com.example.client_app1 to javafx.fxml;
    exports com.example.client_app1;
    exports com.example.client_app1.model;
}