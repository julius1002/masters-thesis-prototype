package de.tu.bs.cs.ias.thesis.vault;

import de.tu.bs.cs.ias.thesis.shared.DecryptionResponse;
import de.tu.bs.cs.ias.thesis.shared.EncryptionResponse;
import de.tu.bs.cs.ias.thesis.shared.KMSClient;
import de.tu.bs.cs.ias.thesis.shared.KeyOptions;
import jakarta.inject.Singleton;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;

@Singleton
public class HashiCorpVaultKMSClient implements KMSClient {

    private HttpClient client = HttpClient.newHttpClient();
    private String hcVaultUri = "http://127.0.0.1:53817/";

    private String token;

    public HashiCorpVaultKMSClient() {
        this("vault_credentials.txt");
    }

    public HashiCorpVaultKMSClient(String path) {
        var credentials = readCredentials(path);
        this.token = credentials.get(0);
    }

    void enableTransitEngine() throws IOException, InterruptedException {
        var path = "v1/sys/mounts/transit";
        var body = new JSONObject().put("path", "transit").put("type", "transit").put("config", new JSONObject()).put("generate_signing_key", true);

        var request = HttpRequest.newBuilder()
                .uri(URI.create(hcVaultUri + path))
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .headers("X-Vault-Token", this.token)
                .build();
        var res = client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    void disableTransitEngine() throws IOException, InterruptedException {
        var path = "v1/sys/mounts/transit";
        var request = HttpRequest.newBuilder()
                .uri(URI.create(hcVaultUri + path))
                .DELETE()
                .headers("X-Vault-Token", this.token)
                .build();
        var res = client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    void createEncryptionKey() throws IOException, InterruptedException {
        var path = "v1/transit/keys/dada";

        var body = new JSONObject()
                //.put("generate_signing_key", true)
                .put("backend", "transit")
                .put("convergent_encryption.put(", false)
                .put("convergent_encryption_version", "null")
                .put("deletion_allowed", false)
                .put("derived", false)
                .put("exportable", false)
                .put("keys", new JSONObject())
                .put("latest_version", "null")
                .put("min_decryption_version", 1)
                .put("min_encryption_version", 0)
                .put("name", "dada")
                .put("supports_decryption", false)
                .put("supports_derivation", false)
                .put("supports_encryption", false)
                .put("supports_signing", false)
                .put("type", "aes256-gcm96");

        var request = HttpRequest.newBuilder()
                .uri(URI.create(hcVaultUri + path))
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .headers("X-Vault-Token", this.token)
                .build();
        var res = client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    static String base64Decode(String input) {
        return new String(Base64.getDecoder().decode(input.getBytes(UTF_8)));
    }

    public EncryptionResponse encrypt(byte[] plainText, KeyOptions keyOptions) {
        var path = "v1/transit/encrypt/my_key";
        var base64convertedPlainText = new String(Base64.getEncoder().encode(plainText));
        var body = new JSONObject().put("plaintext", base64convertedPlainText);
        var request = HttpRequest.newBuilder()
                .uri(URI.create(hcVaultUri + path))
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .headers("X-Vault-Token", this.token)
                .build();
        HttpResponse<String> res = null;
        try {
            res = client.send(request, HttpResponse.BodyHandlers.ofString());
            return new EncryptionResponse(new JSONObject(res.body()).getJSONObject("data").getString("ciphertext"));
        } catch (Exception e) {
            return new EncryptionResponse("-1");
        }

    }

    public DecryptionResponse decrypt(byte[] cipherText, KeyOptions keyOptions) {
        var path = "v1/transit/decrypt/my_key";

        var body = new JSONObject().put("ciphertext",
                new String(cipherText));
        var request = HttpRequest.newBuilder()
                .uri(URI.create(hcVaultUri + path))
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .headers("X-Vault-Token", this.token)
                .build();

        HttpResponse<String> res = null;
        try {
            res = client.send(request, HttpResponse.BodyHandlers.ofString());
            var responseBody = new JSONObject(res.body());
            return new DecryptionResponse(base64Decode(responseBody.getJSONObject("data").getString("plaintext")));
        } catch (Exception e) {
            return new DecryptionResponse("-1");
        }
    }
}
