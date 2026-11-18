package dev.crain.authtracer.scan;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.env.PropertiesPropertySourceLoader;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.util.PropertyPlaceholderHelper;

/**
 * The scanned application's {@code application.yaml}/{@code application.properties}, for resolving
 * {@code ${...}} placeholders statically, as Spring Boot 4.1.1 finds them on the classpath: {@code config/} over the
 * root, {@code .properties} over YAML. Profiles the configuration itself activates ({@code spring.profiles.active})
 * are applied, their {@code application-<profile>} files and documents over the rest. What the deployment sets
 * (environment, other profiles, a cloud platform, {@code spring.config.import}) isn't known: it is left out, and said so
 * in the log.
 */
@Supports(Feature.APPLICATION_GRAPH)
public final class ConfigurationProperties {

    /**
     * Spring's own placeholder syntax: {@code ${key}}, {@code ${key:default}}, nested ({@code ${a:${b:c}}}), and a
     * value's own placeholders resolved in turn.
     */
    private static final PropertyPlaceholderHelper PLACEHOLDERS = new PropertyPlaceholderHelper("${", "}", ":", '\\',
            false);
    private static final PropertyPlaceholderHelper KNOWN_PLACEHOLDERS = new PropertyPlaceholderHelper("${", "}", ":",
            '\\', true);
    private static final List<String> FILES = List.of("application.properties", "application.yaml", "application.yml");
    private static final List<String> ACTIVATIONS = List.of("spring.config.activate.on-profile",
            "spring.config.activate.on-cloud-platform", "spring.profiles");
    private static final String ON_PROFILE = "spring.config.activate.on-profile";
    private static final Logger log = LoggerFactory.getLogger(ConfigurationProperties.class);

    private final Map<String, String> values;
    private final Set<String> unresolved = ConcurrentHashMap.newKeySet();
    /**
     * The keys by their canonical form, as Spring's relaxed binding compares them.
     */
    private final Map<String, String> canonical = new LinkedHashMap<>();

    private ConfigurationProperties(Map<String, String> values) {
        this.values = values;
        values.keySet().forEach(key -> canonical.putIfAbsent(canonical(key), key));
    }

    /**
     * Spring Boot's relaxed binding: {@code serviceUrl}, {@code service-url} and {@code service_url} are one name, in
     * any case; an index ({@code [0]}, {@code [defaultZone]}) is kept as written.
     */
    private static String canonical(String key) {
        StringBuilder result = new StringBuilder();
        boolean indexed = false;
        for (char c : key.toCharArray()) {
            if (c == '[') {
                indexed = true;
            }
            else if (c == ']') {
                indexed = false;
            }
            if (indexed || c == '.' || c == '[' || c == ']') {
                result.append(c);
            }
            else if (c != '-' && c != '_') {
                result.append(Character.toLowerCase(c));
            }
        }
        return result.toString();
    }

    /**
     * The value of the key as written in the files, or as relaxed binding finds it.
     */
    private String value(String key) {
        String value = values.get(key);
        if (value != null) {
            return value;
        }
        String written = canonical.get(canonical(key));
        return written == null ? null : values.get(written);
    }

    static ConfigurationProperties load(List<Path> resourceDirs) {
        Map<String, String> values = new LinkedHashMap<>();
        Map<String, Map<String, String>> byProfile = new LinkedHashMap<>();
        List<String> read = new ArrayList<>();
        List<String> leftOut = new ArrayList<>();
        // Highest precedence first, each value kept from the first that sets it: config/ over the root (Boot's
        // classpath:/config/ after classpath:/), .properties over YAML.
        for (Path dir : resourceDirs) {
            for (Path location : List.of(dir.resolve("config"), dir)) {
                for (String name : FILES) {
                    Path file = location.resolve(name);
                    if (Files.isRegularFile(file)) {
                        Documents documents = read(file);
                        documents.always().forEach(values::putIfAbsent);
                        documents.byProfile().forEach((profile, set) -> set.forEach((key, value) -> byProfile
                                .computeIfAbsent(profile, k -> new LinkedHashMap<>()).putIfAbsent(key, value)));
                        leftOut.addAll(documents.leftOut().stream().map(what -> file + ": " + what).toList());
                        read.add(dir.relativize(file).toString());
                    }
                }
            }
        }
        List<String> active = new ConfigurationProperties(values).list("spring.profiles.active");
        Map<String, String> profiled = new LinkedHashMap<>();
        // A later active profile wins over an earlier one.
        for (String profile : active.reversed()) {
            for (Path dir : resourceDirs) {
                for (Path location : List.of(dir.resolve("config"), dir)) {
                    for (String name : FILES) {
                        Path file = location.resolve(name.replace("application.", "application-" + profile + "."));
                        if (Files.isRegularFile(file)) {
                            read(file).all().forEach(profiled::putIfAbsent);
                            read.add(dir.relativize(file).toString());
                        }
                    }
                }
            }
            byProfile.getOrDefault(profile, Map.of()).forEach(profiled::putIfAbsent);
        }
        profiled.forEach(values::put);
        for (Path dir : resourceDirs) {
            for (Path location : List.of(dir.resolve("config"), dir)) {
                try (var files = Files.list(location)) {
                    files.map(file -> file.getFileName().toString())
                            .filter(name -> name.startsWith("application-") && FILES.stream().anyMatch(
                                    base -> name.endsWith(base.substring("application".length()))))
                            .filter(name -> active.stream().noneMatch(profile -> name.startsWith(
                                    "application-" + profile + ".")))
                            .forEach(name -> leftOut.add(location.resolve(name) + ": only for its profile, which the"
                                    + " configuration doesn't activate"));
                }
                catch (IOException | UncheckedIOException ex) {
                    // No such directory: nothing there to leave out.
                }
            }
        }
        byProfile.keySet().stream().filter(profile -> !active.contains(profile)).forEach(profile -> leftOut.add(
                "documents for the " + profile + " profile, which the configuration doesn't activate"));
        if (!read.isEmpty()) {
            log.info("Configuration from {}: {}{}", resourceDirs, read,
                    active.isEmpty() ? "" : " (profiles " + active + " active)");
        }
        if (!leftOut.isEmpty()) {
            log.warn("Configuration left out, as the deployment decides it: {}", leftOut);
        }
        if (values.containsKey("spring.config.import")) {
            log.warn("spring.config.import ({}) isn't followed: what it imports isn't read",
                    values.get("spring.config.import"));
        }
        return new ConfigurationProperties(values);
    }

    /**
     * The property's value, its placeholders resolved; empty when it isn't set or a placeholder can't be resolved
     * (the environment sets it), as a default the code applies then is as good a guess as any.
     */
    public Optional<String> get(String key) {
        return Optional.ofNullable(value(key)).flatMap(this::resolve);
    }

    /**
     * The property's value with the placeholders that can be resolved resolved and the others as written: for a name
     * that only has to match the same name elsewhere, such as a destination two services both take from
     * {@code ${orders.topic}}.
     */
    public Optional<String> getResolvingKnown(String key) {
        return Optional.ofNullable(value(key)).map(this::resolveKnown);
    }

    /**
     * A list property: comma-separated ({@code include=health,env}), or a YAML list, which Spring flattens to
     * {@code include[0]}, {@code include[1]}, ...
     */
    public List<String> list(String key) {
        Optional<String> scalar = get(key);
        if (scalar.isPresent()) {
            return Arrays.stream(scalar.get().split(",")).map(String::trim).filter(item -> !item.isEmpty()).toList();
        }
        List<String> items = new ArrayList<>();
        for (int i = 0; value(key + "[" + i + "]") != null; i++) {
            get(key + "[" + i + "]").map(String::trim).filter(item -> !item.isEmpty()).ifPresent(items::add);
        }
        return items;
    }

    /**
     * A boolean property as Spring's binder reads it: {@code true}/{@code false}, {@code on}/{@code off},
     * {@code yes}/{@code no} or {@code 1}/{@code 0}, in any case; empty when it isn't set or is none of them.
     */
    public Optional<Boolean> flag(String key) {
        return get(key).map(value -> value.trim().toLowerCase(Locale.ROOT)).map(value -> switch (value) {
            case "true", "on", "yes", "1" -> Boolean.TRUE;
            case "false", "off", "no", "0" -> Boolean.FALSE;
            default -> null;
        });
    }

    /**
     * Whether any property's name starts with the prefix, e.g. {@code spring.security.oauth2.client.registration.}.
     */
    public boolean hasPrefix(String prefix) {
        String relaxed = canonical(prefix);
        return values.keySet().stream().anyMatch(key -> key.startsWith(prefix) || canonical(key).startsWith(relaxed));
    }

    /**
     * The names of the properties under a prefix, without it: {@code a.b} and {@code a.c} under {@code x.} for
     * {@code x.a.b} and {@code x.a.c}.
     */
    public List<String> namesUnder(String prefix) {
        int elements = prefix.split("\\.", -1).length - 1;
        String relaxed = canonical(prefix);
        return values.keySet().stream().filter(key -> key.startsWith(prefix) || canonical(key).startsWith(relaxed))
                .map(key -> key.startsWith(prefix) ? key.substring(prefix.length())
                        : String.join(".", List.of(key.split("\\.", -1)).subList(elements,
                                key.split("\\.", -1).length)))
                .toList();
    }

    /**
     * Resolves {@code ${key}} and {@code ${key:default}}; empty when a placeholder can't be resolved.
     */
    public Optional<String> resolve(String text) {
        try {
            // A placeholder names a property exactly: Spring doesn't bind ${REALM} to realm.
            return Optional.of(PLACEHOLDERS.replacePlaceholders(text, values::get));
        }
        catch (IllegalArgumentException unresolvable) {
            // Spring's PlaceholderResolutionException, or a circular reference.
            if (unresolved.add(text)) {
                log.info("{} isn't set in the configuration read (the deployment sets it): the code's default is"
                        + " read instead", text);
            }
            return Optional.empty();
        }
    }

    /**
     * Resolves the placeholders that can be resolved and keeps the others as written (see
     * {@link #getResolvingKnown}): {@code ${orders.topic}} stays itself when no file sets it.
     */
    public String resolveKnown(String text) {
        try {
            return KNOWN_PLACEHOLDERS.replacePlaceholders(text, values::get);
        }
        catch (IllegalArgumentException circular) {
            return text;
        }
    }

    /**
     * A file's documents: those that always apply, those for one profile ({@code on-profile} naming just it), and
     * what is left out (a cloud platform's, a profile expression, the legacy {@code spring.profiles}).
     */
    private record Documents(Map<String, String> always, Map<String, Map<String, String>> byProfile,
            List<String> leftOut) {

        Map<String, String> all() {
            Map<String, String> all = new LinkedHashMap<>(always);
            byProfile.values().forEach(all::putAll);
            return all;
        }
    }

    private static Documents read(Path file) {
        Map<String, String> values = new LinkedHashMap<>();
        Map<String, Map<String, String>> byProfile = new LinkedHashMap<>();
        List<String> leftOut = new ArrayList<>();
        try {
            var resource = new FileSystemResource(file);
            List<PropertySource<?>> sources = file.toString().endsWith(".properties")
                    ? new PropertiesPropertySourceLoader().load(file.getFileName().toString(), resource)
                    : new YamlPropertySourceLoader().load(file.getFileName().toString(), resource);
            for (PropertySource<?> source : sources) {
                if (!(source instanceof EnumerablePropertySource<?> enumerable)) {
                    continue;
                }
                Map<String, String> target;
                if (ACTIVATIONS.stream().noneMatch(enumerable::containsProperty)) {
                    target = values;
                }
                else if (enumerable.containsProperty(ON_PROFILE) && ACTIVATIONS.stream().filter(name ->
                        !name.equals(ON_PROFILE)).noneMatch(enumerable::containsProperty)
                        && String.valueOf(enumerable.getProperty(ON_PROFILE)).matches("[\\w-]+")) {
                    target = byProfile.computeIfAbsent(String.valueOf(enumerable.getProperty(ON_PROFILE)),
                            profile -> new LinkedHashMap<>());
                }
                else {
                    leftOut.add("a document for " + ACTIVATIONS.stream().filter(enumerable::containsProperty)
                            .map(name -> name + "=" + enumerable.getProperty(name)).toList());
                    continue;
                }
                // Within a file, a later document overrides an earlier one.
                for (String name : enumerable.getPropertyNames()) {
                    if (!ACTIVATIONS.contains(name)) {
                        target.put(name, String.valueOf(enumerable.getProperty(name)));
                    }
                }
            }
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return new Documents(values, byProfile, leftOut);
    }
}
