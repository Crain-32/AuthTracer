package dev.crain.profileservice.profile;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/profiles")
public class ProfileController {

    private static final Logger log = LoggerFactory.getLogger(ProfileController.class);

    private final ProfileService profileService;

    public ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    @GetMapping("/{id}")
    public ProfileView get(@PathVariable long id, Authentication authentication) {
        log.info("GET /profiles/{} by {}", id, authentication.getName());
        return profileService.getProfile(id);
    }

    @GetMapping
    public List<ProfileView> list(Authentication authentication) {
        log.info("GET /profiles by {}", authentication.getName());
        return profileService.listProfiles();
    }
}
