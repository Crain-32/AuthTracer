package fixtures.deepcalls;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A request path deeper than the call walk follows: the check at the bottom of it isn't read, and the path says so.
 */
@SpringBootApplication
@EnableMethodSecurity
public class DeepCallsApp {
}

@RestController
class DeepController {

    @Autowired
    private Layers layers;

    @Autowired
    private Vault vault;

    @GetMapping("/shallow")
    String shallow() {
        return vault.secret();
    }

    @GetMapping("/deep")
    String deep() {
        return layers.s1();
    }
}

/**
 * Each layer hands on to the next, 42 deep, before the vault is reached.
 */
@Service
class Layers {

    @Autowired
    private Vault vault;

    String s1() {
        return s2();
    }

    String s2() {
        return s3();
    }

    String s3() {
        return s4();
    }

    String s4() {
        return s5();
    }

    String s5() {
        return s6();
    }

    String s6() {
        return s7();
    }

    String s7() {
        return s8();
    }

    String s8() {
        return s9();
    }

    String s9() {
        return s10();
    }

    String s10() {
        return s11();
    }

    String s11() {
        return s12();
    }

    String s12() {
        return s13();
    }

    String s13() {
        return s14();
    }

    String s14() {
        return s15();
    }

    String s15() {
        return s16();
    }

    String s16() {
        return s17();
    }

    String s17() {
        return s18();
    }

    String s18() {
        return s19();
    }

    String s19() {
        return s20();
    }

    String s20() {
        return s21();
    }

    String s21() {
        return s22();
    }

    String s22() {
        return s23();
    }

    String s23() {
        return s24();
    }

    String s24() {
        return s25();
    }

    String s25() {
        return s26();
    }

    String s26() {
        return s27();
    }

    String s27() {
        return s28();
    }

    String s28() {
        return s29();
    }

    String s29() {
        return s30();
    }

    String s30() {
        return s31();
    }

    String s31() {
        return s32();
    }

    String s32() {
        return s33();
    }

    String s33() {
        return s34();
    }

    String s34() {
        return s35();
    }

    String s35() {
        return s36();
    }

    String s36() {
        return s37();
    }

    String s37() {
        return s38();
    }

    String s38() {
        return s39();
    }

    String s39() {
        return s40();
    }

    String s40() {
        return s41();
    }

    String s41() {
        return s42();
    }

    String s42() {
        return vault.secret();
    }
}

@Service
class Vault {

    @PreAuthorize("hasRole('KEEPER')")
    String secret() {
        return "secret";
    }
}
