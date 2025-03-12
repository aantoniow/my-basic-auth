package pl.bantoniow.basicauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Optional;

@Log4j2
@Component
@AllArgsConstructor(access = AccessLevel.PACKAGE)
class BasicAuthInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith("Basic ")) {
            log.debug("Authorization header not present");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        Optional<Credentials> credentials = BasicAuthUtils
                .getBasicAuthCredentials(authorizationHeader);
        if (credentials.isEmpty()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        String username = credentials.get().username();
        String password = credentials.get().password();
        if (!isValid(username, password)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        return true;
    }

    private boolean isValid(String username, String password) {
        var myUsername = "username";
        var myPassword = "password";
        return myUsername.equals(username) && myPassword.equals(password);
    }

}
