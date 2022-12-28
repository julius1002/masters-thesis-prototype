package de.tu.bs.cs.ias.thesis;

import com.nimbusds.jose.util.IOUtils;
import de.tu.bs.cs.ias.thesis.aws.AWSKMSClient;
import de.tu.bs.cs.ias.thesis.azure.AzureKMSClient;
import de.tu.bs.cs.ias.thesis.google.GoogleKMSClient;
import de.tu.bs.cs.ias.thesis.shared.KMSClient;
import de.tu.bs.cs.ias.thesis.shared.KeyOptions;
import de.tu.bs.cs.ias.thesis.vault.HashiCorpVaultKMSClient;
import io.micronaut.context.annotation.Value;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.*;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.multipart.CompletedFileUpload;
import io.micronaut.runtime.Micronaut;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static de.tu.bs.cs.ias.thesis.aws.AWSKMSClient.EncryptionAlgorithm.SYMMETRIC_DEFAULT;
import static io.micronaut.http.MediaType.*;
import static java.nio.charset.StandardCharsets.UTF_8;

@Controller("/api/web")
public class WebApp {

    private static final Logger logger = LoggerFactory.getLogger(WebApp.class);

    public static void main(String[] args) {
        File theDir = new File("storage");
        if (!theDir.exists()) {
            theDir.mkdirs();
        }

        Micronaut.run(WebApp.class);
    }

    @Inject
    @Named("aws") // Implemenations are { google, aws, azure, HashiCorpVault }
    private KMSClient kmsClient;


    @Consumes(MULTIPART_FORM_DATA)
    @Post("/upload")
    public HttpResponse<?> upload(CompletedFileUpload file, HttpRequest<?> req) throws IOException {

        Optional<Cookie> sessionCookie = req.getCookies().findCookie("Session");

        sessionCookie.map(Cookie::getValue).ifPresent(cookieValue -> logger.info("Incoming 'upload' request from user: " + cookieValue));

        var res = kmsClient.encrypt(file.getBytes(),
                new KeyOptions(Optional.of("thesiskey"),
                        Optional.of("9ab9dfe3e54d4c20a65f3575721ae16e"),
                        /*  google */
                        Optional.of("1"),
                        Optional.of("1"),
                        /*  aws */
                        Optional.of(SYMMETRIC_DEFAULT),
                        Optional.empty(),
                        List.of(),
                        Optional.of("42c29d25-52e2-44c9-bf86-a68d0a80e449")));

        var kmsName = getKMSImpl();
        logger.info("Using " + kmsName + " to encrypt file with filename" + file.getFilename());
        Files.writeString(Path.of("./storage/" + file.getFilename()), res.cipherText());
        return HttpResponse.ok(); // <3>
    }


    @Produces(APPLICATION_OCTET_STREAM)
    @Get("/download/{filename}")
    public byte[] download(@PathVariable("filename") String filename, HttpRequest<?> req) throws IOException, InterruptedException {
        Optional<Cookie> sessionCookie = req.getCookies().findCookie("Session");

        sessionCookie.map(Cookie::getValue).ifPresent(cookieValue -> logger.info("Incoming 'download' request from user: " + cookieValue));

        File file = new File("./storage/" + filename);
        var fileContent = IOUtils.readFileToString(file);
        var res = kmsClient.decrypt(fileContent.getBytes(StandardCharsets.UTF_8),
                new KeyOptions(Optional.of("thesiskey"),
                        Optional.of("9ab9dfe3e54d4c20a65f3575721ae16e"),
                        /*  google */
                        Optional.of("1"),
                        Optional.of("1"),
                        /*  aws */
                        Optional.of(SYMMETRIC_DEFAULT),
                        Optional.empty(),
                        List.of(),
                        Optional.of("42c29d25-52e2-44c9-bf86-a68d0a80e449")));

        var kmsName = getKMSImpl();
        logger.info("Using " + kmsName + " to decrypt file with filename" + filename);
        return res.plainText().getBytes(UTF_8);
    }

    public String getKMSImpl() {
        if (kmsClient instanceof AWSKMSClient) {
            return "AWS KMS";
        }
        if (kmsClient instanceof GoogleKMSClient) {
            return "Google KMS";
        }
        if (kmsClient instanceof HashiCorpVaultKMSClient) {
            return "HashiCorp Vault KMS";
        }
        return "Azure KMS";
    }

}