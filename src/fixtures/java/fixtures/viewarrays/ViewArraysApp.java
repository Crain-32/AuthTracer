package fixtures.viewarrays;

import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

class Pet {

    private String name;

    public String getName() {
        return name;
    }
}

@Service
class Shelter {

    Pet[] residents() {
        return new Pet[0];
    }
}

/**
 * An array added to the model without a name: Spring names it after its element type, petList.
 */
@Controller
class ShelterController {

    private final Shelter shelter;

    ShelterController(Shelter shelter) {
        this.shelter = shelter;
    }

    @GetMapping("/pets")
    ModelAndView pets() {
        ModelAndView mav = new ModelAndView("pets");
        mav.addObject(shelter.residents());
        return mav;
    }
}
