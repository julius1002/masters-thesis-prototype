package de.tu.bs.cs.ias.thesis.azure;

import de.tu.bs.cs.ias.thesis.shared.DecryptionResponse;
import de.tu.bs.cs.ias.thesis.shared.EncryptionResponse;
import de.tu.bs.cs.ias.thesis.shared.KMSClient;
import de.tu.bs.cs.ias.thesis.shared.KeyOptions;
import jakarta.inject.Singleton;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Optional;

@Singleton
public class AzureKMSClient implements KMSClient {

    String accessToken;

    public AzureKMSClient() throws IOException, InterruptedException {
        this("azure_credentials.txt");
    }

    public AzureKMSClient(String path) throws IOException, InterruptedException {
        var credentials = readCredentials(path);

        this.clientId = credentials.get(0);
        this.clientSecret = credentials.get(1);
        this.tenantId = credentials.get(2);

        var jsonObject = this.conductOAuth2ClientCredentialsFlow();
        this.accessToken = jsonObject.getString("access_token");
    }

    private String azureVaultBaseUrl = "https://thesis-keyvault.vault.azure.net";

    private HttpClient httpClient = HttpClient.newHttpClient();
    private String tenantId;
    private String clientId;
    private String grantType = "client_credentials";
    private String resource = "https://vault.azure.net";

    private String clientSecret;

    public JSONObject conductOAuth2ClientCredentialsFlow() throws IOException,
            InterruptedException {

        String path = "https://login.microsoftonline.com/" + tenantId
                + "/oauth2/token";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(path))
                .POST(HttpRequest.BodyPublishers.ofString("&grant_type=" + grantType
                        + "&client_id=" + clientId +
                        "&client_secret=" + clientSecret + "&resource=" + resource))
                .setHeader("Content-Type", "application/x-www-form-urlencoded")
                .build();

        HttpResponse<String> res = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());
        return new JSONObject(res.body());
    }

    // siehe: https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/CreateApplicationBlade/isMSAApp~/false


    public EncryptionResponse encrypt(byte[] plainText, KeyOptions keyOptions) {

        var optResponse = keyOptions.keyVersion().flatMap(withKeyName ->
                keyOptions.chosenKeyName().flatMap(andVersion -> {
                    var path = "/keys/" + withKeyName + "/" + andVersion + "/encrypt?api-version=7.3";
                    var body = new JSONObject()
                            .put("alg", "RSA1_5")
                            .put("value", com.nimbusds.jose.util.Base64.encode(plainText).toString());

                    var request = HttpRequest.newBuilder()
                            .uri(URI.create(azureVaultBaseUrl + path))
                            .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                            .setHeader("Content-Type", "application/json")
                            .setHeader("Authorization", "Bearer " + this.accessToken)
                            .build();
                    try {

                        return Optional.of(httpClient.send(request, HttpResponse.BodyHandlers.ofString()));
                    } catch (Exception e) {

                        return Optional.empty();
                    }
                })
        );

        return optResponse.map(response -> new EncryptionResponse(new JSONObject(response.body()).getString("value")))
                .orElse(new EncryptionResponse(""));

    }

    public DecryptionResponse decrypt(byte[] cipherText, KeyOptions keyOptions) {
        var optResponse = keyOptions.keyVersion().flatMap(withKeyName ->
                keyOptions.chosenKeyName().flatMap(andVersion -> {

                            var path = "/keys/" + withKeyName + "/" + andVersion + "/decrypt?api-version=7.3";
                            var body = new JSONObject()
                                    .put("alg", "RSA1_5")
                                    .put("value", new String(cipherText));

                            var request = HttpRequest.newBuilder()
                                    .uri(URI.create(azureVaultBaseUrl + path))
                                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                                    .setHeader("Content-Type", "application/json")
                                    .setHeader("Authorization", "Bearer " + this.accessToken)
                                    .build();

                            HttpResponse<String> res = null;
                            try {

                                res = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                            } catch (Exception e) {
                                res = null;
                            }
                            return Optional.ofNullable(res);
                        }
                ));

        return optResponse.map(response ->
                new DecryptionResponse(
                        new String(java.util.Base64.getDecoder().decode(new JSONObject(response.body()).getString("value"))))
        ).orElse(new DecryptionResponse(""));

    }

    public JSONObject createKey(String keyName) throws IOException, InterruptedException {
        var path = "/keys/" + keyName + "/create?api-version=7.3";
        var body =
                new JSONObject()
                        .put("attributes", new JSONObject().put("enabled", true))
                        .put("crv", "P-256")
                        .put("key_ops", new JSONArray().putAll(List.of("sign", "verify", "wrapKey", "unwrapKey", "encrypt", "decrypt")))
                        .put("key_size", 2048)
                        .put("kty", "RSA")
                        .put("tags", new JSONObject().put("purpose", "thesis prototype"));

        var request = HttpRequest.newBuilder()
                .uri(URI.create(azureVaultBaseUrl + path))
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .setHeader("Content-Type", "application/json")
                .setHeader("Authorization", "Bearer " + this.accessToken)
                .build();

        var res = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return new JSONObject(res.body());
    }

}
