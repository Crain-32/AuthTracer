package fixtures.advisors.admin;

import org.springframework.stereotype.Service;

/**
 * Below the package a trailing {@code ..} pointcut names.
 */
@Service
public class AdminLedger {

    public String entries() {
        return "entries";
    }
}
