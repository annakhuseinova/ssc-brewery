package guru.sfg.brewery.domain.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
public class CustomAuthenticationManager {

    public boolean customerIdMatches(Authentication authentication, UUID cusomerId){
        User authenticatedUser = (User)authentication.getPrincipal();

        log.debug("Auth user customer id: " + authenticatedUser.getCustomer().getId() + "Customer Id:" + cusomerId);

        return authenticatedUser.getCustomer().getId().equals(cusomerId);
    }

}