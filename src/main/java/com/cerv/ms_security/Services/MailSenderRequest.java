package com.cerv.ms_security.Services;

import com.google.gson.Gson;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
@Service
public class MailSenderRequest {
    Gson gson = new Gson();
    HttpClient client = HttpClient.newHttpClient();

    public void twoFactorEmail(String twoFactorCode, String email, String name) throws IOException, InterruptedException {
        Map<String, Object> bodyMap = new HashMap<>();
        bodyMap.put("subject", "Este es un correo envidado desde la API");
        bodyMap.put("code", twoFactorCode);
        Map<String, String> recipient = new HashMap<>();
        recipient.put("name", name);
        recipient.put("email", email);
        bodyMap.put("recipients", new Map[]{recipient});

        String body = gson.toJson(bodyMap);

        HttpRequest postRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:5000/send-email"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = client.send(postRequest, java.net.http.HttpResponse.BodyHandlers.ofString());

        System.out.println("Response code: " + response.statusCode());
        System.out.println("Response body: " + response.body());
    }
}
