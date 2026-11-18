package dev.crain.authtracer.conformance;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.data.keyvalue.core.KeyValueTemplate;
import org.springframework.data.repository.CrudRepository;
import org.springframework.util.ReflectionUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * The store datarestlinks' repositories get: one item of each type, linked, kept through a delete.
 */
class StandInStoreTests {

    @Test
    void eachTypeHoldsItemOneLinkedToTheOthersAndKeptThroughADelete() throws Exception {
        DefaultListableBeanFactory registry = new DefaultListableBeanFactory();
        List<String> stored = new ArrayList<>();
        new StandInStore("datarestlinks", stored).postProcessBeanDefinitionRegistry(registry);
        assertEquals(List.of("AccountRepository", "BranchRepository", "TransactionRepository"), stored.stream()
                .sorted().toList());

        KeyValueTemplate template = registry.getBean(KeyValueTemplate.class);
        Class<?> account = Class.forName("fixtures.datarestlinks.Account");
        Class<?> branch = Class.forName("fixtures.datarestlinks.Branch");
        Object item = template.findById(1L, account).orElseThrow();
        assertSame(template.findById(1L, branch).orElseThrow(), field(item, "branch"));
        assertEquals(1, ((Collection<?>) field(item, "transactions")).size());

        // A package-private repository too, its proxy made in its own loader.
        registry.registerBeanDefinition("unused", new RootBeanDefinition(Object.class));
        CrudRepository<?, Long> accounts = (CrudRepository<?, Long>) registry.getBean(
                "conformanceStoreAccountRepository");
        accounts.deleteById(1L);
        assertNotNull(template.findById(1L, account).orElse(null));
    }

    private static Object field(Object owner, String name) {
        var field = ReflectionUtils.findField(owner.getClass(), name);
        ReflectionUtils.makeAccessible(field);
        return ReflectionUtils.getField(field, owner);
    }
}
