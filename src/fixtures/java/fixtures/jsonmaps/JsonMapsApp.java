package fixtures.jsonmaps;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

record Pet(String name, String chip) {
}

record PetView(String name, String chip) {
}

/**
 * Maps Jackson writes as objects: their values' fields are in the response, under each key.
 */
record ShelterView(Map<String, PetView> petsByName, TreeMap<String, PetView> sorted, Map<String, String> notes,
        Map<String, List<PetView>> byKind) {
}

@RestController
class JsonMapsController {

    private List<Pet> pets() {
        return List.of(new Pet("rex", "123"));
    }

    @GetMapping("/shelter")
    ShelterView shelter() {
        Map<String, PetView> byName = new HashMap<>();
        for (Pet pet : pets()) {
            byName.put(pet.name(), new PetView(pet.name(), pet.chip()));
        }
        return new ShelterView(byName, new TreeMap<>(), new HashMap<>(), new HashMap<>());
    }
}
