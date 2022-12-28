package de.tu.bs.cs.ias.thesis;

import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.*;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.views.View;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.micronaut.http.MediaType.APPLICATION_FORM_URLENCODED;


@Controller
public class Views {

    private static final Logger logger = LoggerFactory.getLogger(Views.class);

    @View("home")
    @Get("/")
    public HttpResponse<?> home() {
        return HttpResponse.ok();
    }


    List<String> getFiles() throws IOException {
        return Files.list(new File("./storage").toPath().getFileName()).map(Path::toString).map(filename -> filename.split("storage")[1]).toList();
    }

    Map<String, String> db = new HashMap<>() {{
        put("alice", "kms_password");
        put("bob", "kms_pw");
    }};

    @View("loggedIn")
    @Get(value = "/login")
    public HttpResponse<?> login(HttpRequest<?> req) throws IOException {

        Optional<Cookie> sessionCookie = req.getCookies().findCookie("Session");
        sessionCookie.map(Cookie::getValue).ifPresent(cookieValue -> logger.info("Incoming 'view files' request from : " + cookieValue));

        return sessionCookie
                .flatMap(session -> Optional.of(session.getName())).isEmpty()
                ? HttpResponse.unauthorized() :
                HttpResponse.ok(
                        CollectionUtils.mapOf(
                                "loggedIn", true,
                                "username", sessionCookie.get().getValue(),
                                "files", getFiles()));
    }

    Optional<UsernameAndPassword> lookupUser(UsernameAndPassword usernameAndPassword) {
        var usrname = usernameAndPassword.username();
        var password = usernameAndPassword.password();
        if (db.get(usrname) != null && db.get(usrname).equals(password)) {
            return Optional.of(usernameAndPassword);
        } else {
            return Optional.empty();
        }
    }

    @View("loggedIn")
    @Consumes(APPLICATION_FORM_URLENCODED)
    @Post(value = "/login") //
    public HttpResponse<?> loggedIn(HttpRequest<UsernameAndPassword> req) throws IOException {
        // https://docs.micronaut.io/latest/guide/#sessions for in-memory sessions
        var login =
                req.getBody()
                        .flatMap(this::lookupUser);
        login.ifPresent(loggedInUser -> logger.info("User " + loggedInUser + " logged in"));
        return login.isEmpty() ? HttpResponse.unauthorized() : HttpResponse.ok(
                CollectionUtils.mapOf("loggedIn", true,
                        "username", login.get().username(),
                        "files", getFiles())
        ).cookie(Cookie.of("Session", login.get().username())); //
    }
}
