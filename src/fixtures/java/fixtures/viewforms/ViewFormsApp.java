package fixtures.viewforms;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.data.repository.Repository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

/**
 * Server-side forms shaped like spring-petclinic's owner pages: a form object bound from the request, a model filled
 * by a {@code @ControllerAdvice} and by a void {@code @ModelAttribute} method, views named through
 * {@code setViewName(..)} and handed a {@code Map.of(..)} model, and the handlers that render no view.
 */
@ControllerAdvice
class GlobalModel {

    @ModelAttribute("currentUser")
    CurrentUser currentUser() {
        return new CurrentUser("ann", "ann@example.com");
    }
}

record CurrentUser(String name, String email) {
}

class Address {

    private String street;
    private String city;

    public String getStreet() {
        return street;
    }

    public String getCity() {
        return city;
    }
}

class Pet {

    private String name;
    private String microchip;

    public String getName() {
        return name;
    }

    public String getMicrochip() {
        return microchip;
    }
}

class Owner {

    private Integer id;
    private String firstName;
    private String lastName;
    private String telephone;
    private Address address;
    private List<Pet> pets = new ArrayList<>();

    public Integer getId() {
        return id;
    }

    public boolean isNew() {
        return id == null;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getTelephone() {
        return telephone;
    }

    public Address getAddress() {
        return address;
    }

    public List<Pet> getPets() {
        return pets;
    }
}

record OwnerSearch(String lastName) {
}

interface OwnerRepository extends Repository<Owner, Integer> {

    Owner findById(Integer id);
}

@Controller
@RequestMapping("/owners")
class OwnerController {

    private static final String VIEWS_OWNER_CREATE_OR_UPDATE_FORM = "owners/createOrUpdateOwnerForm";

    private final OwnerRepository owners;

    OwnerController(OwnerRepository owners) {
        this.owners = owners;
    }

    /**
     * Runs before every handler of the controller: the counts every page shows.
     */
    @ModelAttribute
    void addCounts(Model model) {
        model.addAttribute("counts", Map.of("owners", 1));
    }

    @ModelAttribute(name = "types")
    List<String> populatePetTypes() {
        return List.of("cat", "dog");
    }

    /**
     * The owner is the implicit form object: bound from the request, in the model as "owner".
     */
    @PostMapping("/new")
    String processCreationForm(Owner owner, BindingResult result) {
        if (result.hasErrors()) {
            return VIEWS_OWNER_CREATE_OR_UPDATE_FORM;
        }
        return "redirect:/owners/" + owner.getId();
    }

    /**
     * The query parameters' map is no model; the search form object is, by its name.
     */
    @GetMapping
    String processFindForm(@RequestParam Map<String, String> query, @ModelAttribute("search") OwnerSearch search,
            Map<String, Object> model) {
        model.put("owner", owners.findById(1));
        return "owners/ownersList";
    }

    @GetMapping("/{ownerId}/edit")
    String initUpdateOwnerForm(@PathVariable("ownerId") int ownerId, Model model) {
        model.addAttribute(owners.findById(ownerId));
        return VIEWS_OWNER_CREATE_OR_UPDATE_FORM;
    }

    @PostMapping("/{ownerId}/edit")
    String processUpdateOwnerForm(@ModelAttribute("owner") Owner owner, BindingResult result,
            @PathVariable("ownerId") int ownerId) {
        if (result.hasErrors()) {
            return VIEWS_OWNER_CREATE_OR_UPDATE_FORM;
        }
        return "redirect:/owners/" + ownerId;
    }

    @GetMapping("/{ownerId}")
    ModelAndView showOwner(@PathVariable("ownerId") int ownerId) {
        ModelAndView mav = new ModelAndView();
        mav.setViewName("owners/ownerDetails");
        mav.addObject("owner", owners.findById(ownerId));
        return mav;
    }

    @GetMapping("/{ownerId}/summary")
    ModelAndView summary(@PathVariable("ownerId") int ownerId) {
        return new ModelAndView("owners/summary", Map.of("owner", owners.findById(ownerId), "visits", 3));
    }

    @GetMapping("/find")
    String initFindForm(Map<String, Object> model) {
        model.putIfAbsent("owner", new Owner());
        return "owners/findOwners";
    }

    @GetMapping("/search")
    String search() {
        return "forward:/owners/find";
    }

    /**
     * No template AuthTracer can find: every model attribute, with all its properties.
     */
    @GetMapping("/{ownerId}/print")
    String print(@PathVariable("ownerId") int ownerId, Model model) {
        model.addAttribute("owner", owners.findById(ownerId));
        return "owners/print";
    }

    @GetMapping("/export")
    void export(HttpServletResponse response) {
    }
}

/**
 * {@code @ResponseBody} on the class: its handlers write their return values, they render no view.
 */
@Controller
@ResponseBody
class OwnerApi {

    @GetMapping("/api/owners/{ownerId}/name")
    String name(@PathVariable("ownerId") int ownerId) {
        return "owners/name";
    }
}
