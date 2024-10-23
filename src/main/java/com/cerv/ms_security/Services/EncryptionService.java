package com.cerv.ms_security.Services;

import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Service //permite decir que esta clase se puede inyectar en otra
public class EncryptionService { //una contraseña o un texto que quiera se lo mando y mediante SHA-256 me lo representa de esa manera

    public String convertSHA256(String password) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256"); //toma una palabra de entrada y la convierte en otro tipo de salida
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        byte[] hash = md.digest(password.getBytes());
        StringBuffer sb = new StringBuffer();
        for(byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString(); //la cadena cifrada se retorna
    }

    public String validationCode() {
        // Crea 6 dígitos de validación
        return String.valueOf((int)(Math.random() * 900000) + 100000);
    }
}
