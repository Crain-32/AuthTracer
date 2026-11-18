package fixtures.flows;

import java.util.List;

/**
 * A response with a collection of application objects: their fields are in the response too.
 */
public class Shelter {

    private final List<ShelterPet> pets;

    public Shelter(List<ShelterPet> pets) {
        this.pets = pets;
    }

    public List<ShelterPet> getPets() {
        return pets;
    }
}
