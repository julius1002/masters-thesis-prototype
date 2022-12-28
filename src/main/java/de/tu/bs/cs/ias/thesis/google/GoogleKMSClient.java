package de.tu.bs.cs.ias.thesis.google;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.SignedJWT;
import de.tu.bs.cs.ias.thesis.shared.DecryptionResponse;
import de.tu.bs.cs.ias.thesis.shared.EncryptionResponse;
import de.tu.bs.cs.ias.thesis.shared.KMSClient;
import de.tu.bs.cs.ias.thesis.shared.KeyOptions;
import jakarta.inject.Singleton;
import org.json.JSONObject;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Singleton
public class GoogleKMSClient implements KMSClient {

    private HttpClient httpClient = HttpClient.newHttpClient();
    String location = "/projects/thesis-357606/locations/global";
    String serviceAccountId;
    String keyStorePassword;
    String keyStorePath;

    String accessToken;

    public GoogleKMSClient() throws UnrecoverableKeyException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, InterruptedException, JOSEException {
        this("google_credentials.txt");

    }

    public GoogleKMSClient(String path) throws UnrecoverableKeyException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, InterruptedException, JOSEException {
        var credentials = readCredentials(path);
        this.serviceAccountId = credentials.get(0);
        this.keyStorePath = credentials.get(1);
        this.keyStorePassword = credentials.get(2);

        var jsonObject = this.conductOAuth2JWTBearerFlow();
        this.accessToken = jsonObject.getString("access_token");
    }


    public JSONObject conductOAuth2JWTBearerFlow() throws IOException, InterruptedException, JOSEException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {

        // https://developers.google.com/identity/protocols/oauth2/service-account#httprest_1
        String serviceAccountId = this.serviceAccountId;
        String grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
        String path = "https://oauth2.googleapis.com/token";
        String[] scope = {"https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/cloudkms"};

        char[] password = this.keyStorePassword.toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        // keypair must be generated through https://console.cloud.google.com/iam-admin/serviceaccounts/details/118171908597271316508;edit=true/keys?project=thesis-357606
        keyStore.load(GoogleKMSClient.class.getClassLoader().getResourceAsStream(this.keyStorePath), password);
        //System.out.println(keyStore.getKey("privatekey", password));
        RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey("privatekey", password);

        String serializedJwt = generateAndSignJwt(serviceAccountId, scope, privateKey);


        var request = HttpRequest.newBuilder()
                .uri(URI.create(path))
                .POST(HttpRequest.BodyPublishers.ofString("&grant_type=" + URLEncoder.encode(grantType, StandardCharsets.UTF_8) + "&assertion=" + serializedJwt))
                .setHeader("Content-Type", "application/x-www-form-urlencoded")
                .build();

        var res = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return new JSONObject(res.body());
    }

    private String generateAndSignJwt(String serviceAccountId, String[] scope, RSAPrivateKey rsaPrivateKey) throws JOSEException {

        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

        JWSSigner signer = new RSASSASigner(rsaPrivateKey);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("https://oauth2.googleapis.com/token")
                .expirationTime(Date.from(Instant.now().plus(Duration.ofHours(1))))
                .issueTime(Date.from(Instant.now()))
                .issuer(serviceAccountId)
                .claim("scope", scope[0] + " " + scope[1])
                .build();

        SignedJWT jwt = new SignedJWT(header, claimsSet);

        jwt.sign(signer);

        return jwt.serialize();
    }


    public String createCryptoKey(String cryptoKeyId, String keyRingId, String withToken) throws IOException, InterruptedException {

        var keyRingUri = URI.create("https://cloudkms.googleapis.com/v1" + location + "/keyRings/" + keyRingId + "/cryptoKeys?cryptoKeyId=" + cryptoKeyId + "&alt=json");

        var requestBody = new JSONObject().put("purpose", "ENCRYPT_DECRYPT");

        var request = HttpRequest.newBuilder()
                .uri(keyRingUri)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .setHeader("Authorization", "Bearer " + withToken)
                .build();


        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        return response.body();
    }

    public String createKeyRing(String keyRingId, String withToken) throws IOException, InterruptedException {

        var keyRingUri = URI.create("https://cloudkms.googleapis.com/v1" + location + "/keyRings?keyRingId=" + keyRingId + "&alt=json");

        var requestBody = new JSONObject();

        var request = HttpRequest.newBuilder()
                .uri(keyRingUri)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .setHeader("Authorization", "Bearer " + withToken)
                .build();


        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        return response.body();
    }

    public String generateRandomBytes(int byteLength, String protectionLevel, String withToken) throws IOException, InterruptedException {

        var randomBytesUri = URI.create("https://cloudkms.googleapis.com/v1" + location + ":generateRandomBytes");

        var requestBody = new JSONObject();
        requestBody.put("lengthBytes", byteLength).put("protectionLevel", protectionLevel);

        var request = HttpRequest.newBuilder()
                .uri(randomBytesUri)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .setHeader("Authorization", "Bearer " + withToken)
                .build();


        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        return response.body();
    }

    public EncryptionResponse encrypt(byte[] plainText, KeyOptions keyOptions) {

        return keyOptions.keyRingId().flatMap(keyRingId ->
                keyOptions.cryptoKeyId().flatMap(
                        cryptoKeyId ->
                        {
                            var plainTextB64 = Base64.getEncoder().encode(plainText);
                            var encryptionUri = URI.create("https://cloudkms.googleapis.com/v1" + location + "/keyRings/" + keyRingId + "/cryptoKeys/" + cryptoKeyId + ":encrypt");

                            var requestBody = new JSONObject();
                            requestBody.put("plaintext", new String(plainTextB64));

                            var request = HttpRequest.newBuilder()
                                    .uri(encryptionUri)
                                    .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                                    .setHeader("Authorization", "Bearer " + this.accessToken)
                                    .build();


                            HttpResponse<String> response = null;
                            try {
                                response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                                System.out.println(response);
                                var responseBody = new JSONObject(response.body());
                                return Optional.of(new EncryptionResponse(responseBody.getString("ciphertext")));
                            } catch (Exception e) {
                                return Optional.empty();
                            }

                        }

                )).orElse(new EncryptionResponse(""));


    }

    public DecryptionResponse decrypt(byte[] cipherText, KeyOptions keyOptions) {

        return keyOptions.keyRingId().flatMap(keyRingId -> keyOptions.cryptoKeyId().flatMap(cryptoKeyId -> {
                    var encryptionUri = URI.create("https://cloudkms.googleapis.com/v1" + location + "/keyRings/" + keyRingId + "/cryptoKeys/" + cryptoKeyId + ":decrypt");

                    var requestBody = new JSONObject();
                    requestBody.put("ciphertext", new String(cipherText));

                    var request = HttpRequest.newBuilder()
                            .uri(encryptionUri)
                            .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                            .setHeader("Authorization", "Bearer " + this.accessToken)
                            .build();

                    HttpResponse<String> response = null;
                    try {
                        response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                        var responseBody = new JSONObject(response.body());
                        return Optional.of(new DecryptionResponse(new String(Base64.getDecoder().decode(responseBody.getString("plaintext").getBytes(StandardCharsets.UTF_8)))));
                    } catch (Exception e) {
                        return Optional.empty();
                    }
                }
        )).orElse(new DecryptionResponse(""));
    }
}
