package com.cerv.ms_security.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
public class Session {
    @Id
    private String _id;
    private String token;
    private String expirationDate;
    private String codeValidation;
    @DBRef //referencia la sesion de ese usuario, no haga redundancia sino que apunta directamente al usuario
    private User user; // This is the user that is logged in

    public Session(String token, String expirationDate) {
        this.token = token;
        this.expirationDate = expirationDate;
    }

    public String get_id() {
        return _id;
    }

    public void set_id(String _id) {
        this._id = _id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(String expirationDate) {
        this.expirationDate = expirationDate;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getCodeValidation() {
        return codeValidation;
    }

    public void setCodeValidation(String codeValidation) {
        this.codeValidation = codeValidation;
    }
}
