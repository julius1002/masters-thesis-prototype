package de.tu.bs.cs.ias.thesis.aws;

import de.tu.bs.cs.ias.thesis.shared.DecryptionResponse;
import de.tu.bs.cs.ias.thesis.shared.EncryptionResponse;
import de.tu.bs.cs.ias.thesis.shared.KMSClient;
import de.tu.bs.cs.ias.thesis.shared.KeyOptions;
import jakarta.inject.Singleton;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.*;

@Singleton
public class AWSKMSClient implements KMSClient {

    static HttpClient client = HttpClient.newBuilder().build();
    private String access_key;
    private String secret_key;

    public AWSKMSClient() {
        this("aws_credentials.txt");
    }

    public AWSKMSClient(String path) {
        var credentials = readCredentials(path);
        this.access_key = credentials.get(0);
        this.secret_key = credentials.get(1);
    }

    record SignatureMetadata(String secretKey, String dateStamp, String regionName, String serviceName) {
    }

    public enum EncryptionAlgorithm {SYMMETRIC_DEFAULT, RSAES_OAEP_SHA_1, RSAES_OAEP_SHA_256, SM2PKE}

    // Key derivation functions


    static byte[] HmacSHA256(String data, byte[] key) throws Exception {
        var algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes(UTF_8));
    }

    static byte[] forgeSignatureKey(SignatureMetadata signatureMetadata)
            throws Exception {
        byte[] forgedService = HmacSHA256(signatureMetadata.serviceName,
                HmacSHA256(signatureMetadata.regionName,
                        HmacSHA256(signatureMetadata.dateStamp,
                                ("AWS4" + signatureMetadata.secretKey).getBytes(UTF_8))));

        return HmacSHA256("aws4_request", forgedService);
    }

    public static String toHex(byte[] bytes) {
        var result = new StringBuffer();
        for (byte byt : bytes) result.append(Integer.toString((byt & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    public HttpRequest prepareVersion4Request(Optional<EncryptionAlgorithm> optionalEncAlgoRithm,
                                              Optional<String> optionalEncContext,
                                              List<String> grantTokens,
                                              Optional<String> optionalUsedKeyId,
                                              Optional<String> optionalCipherText,
                                              Optional<String> optionalPlainText,
                                              String target,
                                              String host,
                                              String region,
                                              String method,
                                              String service,
                                              String endpoint) throws Exception {

        var contentType = "application/x-amz-json-1.1";
        var requestBody = new JSONObject().put("GrantTokens", new JSONArray(grantTokens));
        optionalUsedKeyId.ifPresent(kId -> requestBody.put("KeyId", kId));

        optionalCipherText.ifPresent(ct -> requestBody.put("CiphertextBlob", ct));
        optionalPlainText.ifPresent(pt -> requestBody.put("Plaintext", pt));

        optionalEncAlgoRithm.ifPresent(algo -> requestBody.put("EncryptionAlgorithm", algo));
        optionalEncContext.ifPresent(encContext -> requestBody.put("EncryptionContext", new JSONObject("string", encContext)));

        SimpleDateFormat df = new SimpleDateFormat("YYYYMMdd");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        SimpleDateFormat dfxamz = new SimpleDateFormat("YYYYMMdd'T'HHmmss'Z'");
        dfxamz.setTimeZone(TimeZone.getTimeZone("UTC"));
        var xamzDate = dfxamz.format(new Date());

        var dateStamp = df.format(new Date());


        var signedHeaders = "content-type;host;x-amz-date;x-amz-target";
        var digest = MessageDigest.getInstance("SHA-256");
        var hashedPayload = toHex(digest.digest(requestBody.toString().getBytes(UTF_8)));

        var canonicalReq = getCanonicalReq(method, "/", "", getCanonicalHeaders(target, host, contentType, xamzDate), signedHeaders, hashedPayload);

        var scopeOfTheCredential = getScopeOfTheCredential(region, service, dateStamp);

        var unsignedString = getUnsignedString(xamzDate, digest, canonicalReq, scopeOfTheCredential);

        SignatureMetadata signatureMetadata = new SignatureMetadata(secret_key, dateStamp, region, service);

        String signature = toHex(HmacSHA256(unsignedString, forgeSignatureKey(signatureMetadata)));

        return forgeSignature4Request(target, endpoint, contentType, requestBody, xamzDate, "", signedHeaders, "AWS4-HMAC-SHA256", scopeOfTheCredential, signature);
    }

    private static String getCanonicalHeaders(String target, String host, String contentType, String xamzDate) {
        return "content-type:" + contentType +
                "\n" + "host:" + host +
                "\n" + "x-amz-date:" + xamzDate +
                "\n" + "x-amz-target:" + target +
                "\n";
    }

    private static String getCanonicalReq(String method, String canonicalUri, String canonicalQueryString, String canonicalHeaders, String signedHeaders, String hashedPayload) {
        return method +
                "\n" + canonicalUri +
                "\n" + canonicalQueryString +
                "\n" + canonicalHeaders +
                "\n" + signedHeaders +
                "\n" + hashedPayload;
    }



    private static String getUnsignedString(String xamzDate, MessageDigest digest, String canonicalReq, String scopeOfTheCredential) {
        return "AWS4-HMAC-SHA256" +
                "\n" + xamzDate +
                "\n" + scopeOfTheCredential +
                "\n" + toHex(digest.digest(canonicalReq.getBytes(UTF_8)));
    }

    private static String getScopeOfTheCredential(String region, String service, String dateStamp) {
        return dateStamp + "/" + region + "/" + service + "/" + "aws4_request";
    }

    private HttpRequest forgeSignature4Request(String target, String endpoint,
                                               String contentType, JSONObject requestBody,
                                               String xamzDate, String canonicalQueryString,
                                               String signedHeaders, String algorithm,
                                               String credentialScope, String signature) {
        var authorizationHeader = algorithm + " "
                + "Credential=" + access_key
                + "/" + credentialScope
                + ", "
                + "SignedHeaders=" + signedHeaders + ", "
                + "Signature=" + signature;

        return HttpRequest.newBuilder()
                .uri(URI.create(endpoint + "?" + canonicalQueryString))
                .headers("Authorization", authorizationHeader,
                        "Content-Type", contentType,
                        "X-Amz-Date", xamzDate,
                        "X-Amz-Target", target)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .build();
    }

    record Version4Parameters(String host, String region, String method, String service, String target) {

    }


    public DecryptionResponse decrypt(byte[] cipherText, KeyOptions keyOptions) {

        var version4Parameters = new Version4Parameters("kms.us-east-2.amazonaws.com", "us-east-2", "POST", "kms", "TrentService.Decrypt");

        HttpRequest request = null;
        try {
            request = prepareVersion4Request(keyOptions.encAlgoRithm(),
                    keyOptions.encryptionContext(),
                    keyOptions.grantTokens(),
                    keyOptions.keyId(),
                    Optional.of(new String(cipherText)),
                    Optional.empty(),
                    version4Parameters.target,
                    version4Parameters.host,
                    version4Parameters.region,
                    version4Parameters.method,
                    version4Parameters.service,
                    "https://" + version4Parameters.host + "");

            var res = client.send(request, HttpResponse.BodyHandlers.ofString());
            var responseBody = new JSONObject(res.body());
            return new DecryptionResponse(new String(Base64.getDecoder().decode(responseBody.getString("Plaintext"))));
        } catch (Exception e) {
            return new DecryptionResponse("-1");
        }
    }

    public EncryptionResponse encrypt(byte[] plainText, KeyOptions keyOptions) {
        var version4Parameters = new Version4Parameters("kms.us-east-2.amazonaws.com", "us-east-2", "POST", "kms", "TrentService.Encrypt");

        try {
            var request = prepareVersion4Request(keyOptions.encAlgoRithm(),
                    keyOptions.encryptionContext(),
                    keyOptions.grantTokens(),
                    keyOptions.keyId(),
                    Optional.empty(),
                    Optional.of(Base64.getEncoder().encodeToString(plainText)),
                    version4Parameters.target,
                    version4Parameters.host,
                    version4Parameters.region,
                    version4Parameters.method,
                    version4Parameters.service,
                    "https://" + version4Parameters.host + "");
            var response = client.send(request, HttpResponse.BodyHandlers.ofString());

            var responseBody = new JSONObject(response.body()).getString("CiphertextBlob");

            return new EncryptionResponse(responseBody);
        } catch (Exception e) {
            return new EncryptionResponse("");
        }
    }
    public JSONObject createKey() throws Exception {

        var method = "POST";
        var service = "kms";
        var target = "TrentService.CreateKey";
        var host = "kms.us-east-2.amazonaws.com";
        var endpoint = "https://" + host + "";
        var region = "us-east-2";

        var request = prepareVersion4Request(Optional.empty(),
                Optional.empty(),
                List.of(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                target,
                host,
                region,
                method,
                service,
                endpoint);

        var res = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println("ResponseCode: " + res.statusCode() + "\n Body: " + res.body());
        return new JSONObject(res.body());
    }
}


