package de.tu.bs.cs.ias.thesis.shared;

import io.micronaut.context.annotation.Value;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public interface KMSClient {

    EncryptionResponse encrypt(byte[] plainText, KeyOptions keyOptions);

    DecryptionResponse decrypt(byte[] cipherText, KeyOptions keyOptions);


    default List<String> readCredentials(String path) {
        List<String> credentials = new ArrayList<>();
        InputStreamReader uri = null;
        try {
            uri = new InputStreamReader(getClass().getClassLoader().getResource(path).openStream());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try (BufferedReader br = new BufferedReader(uri)) {
            String line;
            while ((line = br.readLine()) != null) {
                Stream.of(line)
                        .flatMap(l -> Stream.of(l.split("\n")))
                        .flatMap(keyValue -> Stream.of(keyValue.split("=")[1]))
                        .findFirst()
                        .ifPresent(credentials::add);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return credentials;

    }

}
