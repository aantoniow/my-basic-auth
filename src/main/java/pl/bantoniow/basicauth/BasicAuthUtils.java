package pl.bantoniow.basicauth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

class BasicAuthUtils {

    static Optional<Credentials> getBasicAuthCredentials(String authHeader) throws IllegalArgumentException {
        var cutHeader = authHeader.replace("Basic ", "");
        byte[] decodedCredentials;
        try {
            decodedCredentials = Base64.getDecoder().decode(cutHeader);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }

        String usernameAndPassword = new String(decodedCredentials, StandardCharsets.UTF_8);
        int indexOfColon = usernameAndPassword.indexOf(':');
        String uname = usernameAndPassword.substring(0, indexOfColon);
        String pass = usernameAndPassword.substring(indexOfColon + 1);

        if (!uname.isEmpty() && !pass.isEmpty()) {
            return Optional.of(new Credentials(uname, pass));
        }

        return Optional.empty();
    }

}
