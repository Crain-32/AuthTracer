package fixtures.views;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.Repository;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

/**
 * Server-side views, shaped like spring-petclinic: Thymeleaf templates under templates/.
 */
@Configuration
@EnableWebSecurity
class ViewsSecurityConfig {

    @Bean
    SecurityFilterChain web(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/owners/**").hasRole("STAFF")
                .anyRequest().authenticated()).formLogin(Customizer.withDefaults());
        return http.build();
    }
}

class Owner {

    private Integer id;
    private String firstName;
    private String lastName;
    private String ssn;
    private List<Pet> pets = new ArrayList<>();

    public Integer getId() {
        return id;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getSsn() {
        return ssn;
    }

    public List<Pet> getPets() {
        return pets;
    }
}

class Pet {

    private String name;

    public String getName() {
        return name;
    }
}

interface OwnerRepository extends Repository<Owner, Integer> {

    Optional<Owner> findById(Integer id);

    Page<Owner> findByLastName(String lastName, Pageable pageable);
}

@Controller
class OwnerController {

    private final OwnerRepository owners;

    OwnerController(OwnerRepository owners) {
        this.owners = owners;
    }

    @ModelAttribute("types")
    List<String> types() {
        return List.of("cat", "dog");
    }

    @GetMapping("/owners/{id}")
    ModelAndView show(@PathVariable("id") int id) {
        ModelAndView mav = new ModelAndView("owners/details");
        Owner owner = owners.findById(id).orElseThrow();
        mav.addObject(owner);
        return mav;
    }

    /**
     * Both views show the shared fragment's guarded ssn; the audit view also shows it under a guard of its own.
     */
    @GetMapping("/owners/{id}/audit")
    ModelAndView audit(@PathVariable("id") int id) {
        return new ModelAndView("owners/audit", "owner", owners.findById(id).orElseThrow());
    }

    @GetMapping("/owners/{id}/badge")
    ModelAndView badge(@PathVariable("id") int id) {
        return new ModelAndView("owners/badge", "owner", owners.findById(id).orElseThrow());
    }

    /**
     * The fragment named without ~{}, and a guard in th:if.
     */
    @GetMapping("/owners/{id}/card")
    ModelAndView card(@PathVariable("id") int id) {
        return new ModelAndView("owners/card", "owner", owners.findById(id).orElseThrow());
    }

    /**
     * The model handed over as a map.
     */
    @GetMapping("/owners/search")
    ModelAndView search() {
        Map<String, Object> model = new HashMap<>();
        model.put("listOwners", owners.findByLastName("y", Pageable.unpaged()).getContent());
        return new ModelAndView("owners/list", model);
    }

    @GetMapping("/owners")
    String list(Model model) {
        Page<Owner> page = owners.findByLastName("x", Pageable.unpaged());
        return addPage(model, page);
    }

    private String addPage(Model model, Page<Owner> page) {
        List<Owner> listOwners = page.getContent();
        model.addAttribute("listOwners", listOwners);
        return "owners/list";
    }

    @PostMapping("/owners/new")
    String create(Owner owner) {
        return "redirect:/owners";
    }
}
