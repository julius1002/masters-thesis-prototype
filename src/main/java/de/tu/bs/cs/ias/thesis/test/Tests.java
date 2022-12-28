package de.tu.bs.cs.ias.thesis.test;

import com.nimbusds.jose.JOSEException;
import de.tu.bs.cs.ias.thesis.shared.KeyOptions;
import de.tu.bs.cs.ias.thesis.aws.AWSKMSClient;
import de.tu.bs.cs.ias.thesis.azure.AzureKMSClient;
import de.tu.bs.cs.ias.thesis.google.GoogleKMSClient;
import de.tu.bs.cs.ias.thesis.vault.HashiCorpVaultKMSClient;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static de.tu.bs.cs.ias.thesis.aws.AWSKMSClient.EncryptionAlgorithm.SYMMETRIC_DEFAULT;
import static java.nio.charset.StandardCharsets.UTF_8;

public class Tests {
    public static void main (String[] args){
        awsTest();
    }

    static void azureTest() throws IOException, InterruptedException {
        var exampleJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2ZkYzVhNjE1LThjYmMtNGUxOS1iNWFiLTJmOThjMjcyNzVjZi8iLCJpYXQiOjE2NjIzMDIyMjgsIm5iZiI6MTY2MjMwMjIyOCwiZXhwIjoxNjYyMzA2MTI4LCJhaW8iOiJFMlpnWUdpUW45aDBWbmwzcGMrODdHTXpIU3QxQUE9PSIsImFwcGlkIjoiZjY0NDAwYmYtZmIxYy00ZTRhLTljYmUtOTE2ZTk5NTY3OGE0IiwiYXBwaWRhY3IiOiIxIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZmRjNWE2MTUtOGNiYy00ZTE5LWI1YWItMmY5OGMyNzI3NWNmLyIsIm9pZCI6IjlhN2FkMjBiLWY4ZTctNDI2OC1hM2NkLWM2YzkxYTUxYmI0MSIsInJoIjoiMC5BWUlBRmFiRl9ieU1HVTYxcXktWXduSjF6em16cU0taWdocEhvOGtQd0w1NlFKT1ZBQUEuIiwic3ViIjoiOWE3YWQyMGItZjhlNy00MjY4LWEzY2QtYzZjOTFhNTFiYjQxIiwidGlkIjoiZmRjNWE2MTUtOGNiYy00ZTE5LWI1YWItMmY5OGMyNzI3NWNmIiwidXRpIjoiZ3IyLTdsYXBZMGFtUjdWa0lFdWFBQSIsInZlciI6IjEuMCJ9.XPRYsyJKLg_nuBLJeuWxZmWGFK_3Oiq4gdk-gdDOpDzBwI-iMkuUZQLQJoBdyFwn2mt4dNcpSujVNn_QRsvGvZ4Si7kuIAyfOboK9ycGn8h2dqV_t3GUhh0Svkklio73OkeaPqpU9XNm0wussQuLrBkOyjKWQkHAToVGFc1CztX9YGPPLuKtfUq3HejduWwhsZpFCXsbg1fOCg0cZwBAbDp9qRPD0vRiiWrawvLhseducJC_DKmEAQruO5EuO3PYvD1ARakgCu7LEq-HVJ-bvnse7dKeA6kO_MGp0WeWhPHQLK1CD6Giv3gWA0IsHNSHLlNzNKVK2Zr54pT31OHaVQ";

        var azureClient = new AzureKMSClient("azure_credentials.txt");
        //azureClient.encrypt("helloworld", "thesiskey", "9ab9dfe3e54d4c20a65f3575721ae16e", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2ZkYzVhNjE1LThjYmMtNGUxOS1iNWFiLTJmOThjMjcyNzVjZi8iLCJpYXQiOjE2NjM1NzE5NDYsIm5iZiI6MTY2MzU3MTk0NiwiZXhwIjoxNjYzNTc1ODQ2LCJhaW8iOiJFMlpnWUxDeXVjQWxxYjMyZGZVTm9jT05GL2dtQXdBPSIsImFwcGlkIjoiZjY0NDAwYmYtZmIxYy00ZTRhLTljYmUtOTE2ZTk5NTY3OGE0IiwiYXBwaWRhY3IiOiIxIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZmRjNWE2MTUtOGNiYy00ZTE5LWI1YWItMmY5OGMyNzI3NWNmLyIsIm9pZCI6IjlhN2FkMjBiLWY4ZTctNDI2OC1hM2NkLWM2YzkxYTUxYmI0MSIsInJoIjoiMC5BWUlBRmFiRl9ieU1HVTYxcXktWXduSjF6em16cU0taWdocEhvOGtQd0w1NlFKT1ZBQUEuIiwic3ViIjoiOWE3YWQyMGItZjhlNy00MjY4LWEzY2QtYzZjOTFhNTFiYjQxIiwidGlkIjoiZmRjNWE2MTUtOGNiYy00ZTE5LWI1YWItMmY5OGMyNzI3NWNmIiwidXRpIjoiaEFVN1FWalA0a0tUeWVKQW0ybXFBQSIsInZlciI6IjEuMCJ9.uNOvI9YmWCZ7MmLICtipHkNFXWSqHM8rMagePDaagfYOOFrJGKasGnecXsb1cSBJ0JAQrVgLZf3GE2A0xlQnp3u9n0TZlDirNLYBbfLUHydX46xEwJyHUTRwAw1nHCuj6XBzwXqW_itSJRAUGAMVf189Y-pYV7yzekVQsLtBV25v1xNmxN8_q7WUfsRRVlfY7NV_hT3BJswUbZmlSQhlzmOA-TYnU44s6cI2vtcNH4XRcTOBDTPoPP0P6iqsfZJqfev3XAsubpNalXrq7dDQTbvMTa9ahWKue6RtjfVJemMH-nliazP6BEHke2Y3jsgxHoeg512y2eZbC0AJFTyeUQ");
        //azureClient.oauth2tokenRequest();
        System.out.println(azureClient
                .decrypt("YcHj-hLSbA5aTn0mSQFgo9cCpzQh1Wl8-RVcnNVKIjpCPknT70VqRFD7XO9i_K87Z-WsZ7ArHwaindhDd2NuC4QAellyOh53Uaf2T-zf004AhbcCYEjbm2O3wegl_VMZevL4k39E-kk9gEwdYti1i_foTzeaMv_20unVsQj661UCwbJLAc5T0bC_CJ-6XwOF8zh9C_jy095CFMkpJVsxdJMCUn4J-Dg8hbxQy08uTHDuAUC-zBD5Dr6IU8H94lIZFkpTfXZTokFCWsk4k2EHLstRqpzzdFnNrsG_RnMBd8HVbpZZNclWOHMhLiZP4o5pOR3vO7EQWfpbfR6qft3Hfw".getBytes(StandardCharsets.UTF_8),

                        new KeyOptions(Optional.of("thesiskey"),
                                Optional.of("9ab9dfe3e54d4c20a65f3575721ae16e"), Optional.empty(),
                                Optional.empty(), Optional.empty(), Optional.empty(), List.of(), Optional.empty()
                        )));
    }

    static void awsTest(){
        var keyId = "42c29d25-52e2-44c9-bf86-a68d0a80e449";
        var awsKmsClient = new AWSKMSClient("aws_credentials.txt");
        var ciphertext = awsKmsClient.encrypt("1234".getBytes(StandardCharsets.UTF_8), new KeyOptions(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(SYMMETRIC_DEFAULT), Optional.empty(), List.of(), Optional.of(keyId)));
        var plainText = awsKmsClient.decrypt(ciphertext.cipherText().getBytes(UTF_8), new KeyOptions(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.of(SYMMETRIC_DEFAULT), Optional.empty(), List.of(), Optional.of(keyId)));
        System.out.println(plainText);
        // for credentials : https://us-east-1.console.aws.amazon.com/iam/home?region=us-east-1&skipRegion=true#security_credentials
        //
    }

    static void GoogleTest() throws UnrecoverableKeyException, CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException, InterruptedException, JOSEException {
        GoogleKMSClient googleKMSClient = new GoogleKMSClient();
        // Workaround: use api browser and get access token from executed request from devtools request history
        googleKMSClient.conductOAuth2JWTBearerFlow();

        var plainText = "hahahatestests";
        var res = googleKMSClient.encrypt(
                plainText.getBytes(StandardCharsets.UTF_8),
                new KeyOptions(Optional.empty(), Optional.empty(), Optional.of("1"),
                        Optional.of("1"), Optional.empty(), Optional.empty(), List.of(), Optional.empty()));

        System.out.println(res.toString());
        var r = googleKMSClient.decrypt(res.cipherText().getBytes(StandardCharsets.UTF_8),
                new KeyOptions(Optional.empty(), Optional.empty(), Optional.of("1"),
                        Optional.of("1"), Optional.empty(), Optional.empty(), List.of(), Optional.empty()));
        //System.out.println(res);
        System.out.println(r.toString());
    }

    static void HCVaultTest() {
        var hcClient = new HashiCorpVaultKMSClient();
        //hcClient.enableTransitEngine();
        var encryptRes = hcClient.encrypt("helloworld".getBytes(StandardCharsets.UTF_8), null);
        var cipherText = encryptRes.cipherText();
        System.out.println(encryptRes);
        var responseBody = hcClient.decrypt(cipherText.getBytes(StandardCharsets.UTF_8), null);
        System.out.println("decrypted message " + responseBody.plainText());
    }

    static String base64Decode(String input) {
        return new String(Base64.getDecoder().decode(input.getBytes(UTF_8)));
    }
}
