package dev.crain.authtracer.cli;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import dev.crain.authtracer.UsageException;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * {@code <command> [--option value | --option=value]...}
 */
@Supports(Feature.COMMAND_LINE)
record CliArguments(String command, Map<String, String> options) {

    static CliArguments parse(String[] args) {
        List<String> remaining = new ArrayList<>(Arrays.asList(args));
        String command = remaining.isEmpty() || remaining.getFirst().startsWith("--") ? "" : remaining.removeFirst();
        Map<String, String> options = new LinkedHashMap<>();
        for (int i = 0; i < remaining.size(); i++) {
            String arg = remaining.get(i);
            if (!arg.startsWith("--")) {
                throw new UsageException("Unexpected argument: " + arg);
            }
            String name = arg.substring(2);
            int equals = name.indexOf('=');
            if (equals >= 0) {
                options.put(name.substring(0, equals), name.substring(equals + 1));
            }
            else if (i + 1 < remaining.size() && !remaining.get(i + 1).startsWith("--")) {
                options.put(name, remaining.get(++i));
            }
            else {
                options.put(name, "true");
            }
        }
        return new CliArguments(command, options);
    }

    /**
     * Refuses an option the command doesn't take, so a mistyped one ({@code --org-fact}) isn't quietly ignored.
     */
    void only(String command, Set<String> known) {
        for (String name : options.keySet()) {
            if (!known.contains(name)) {
                String near = known.stream().filter(candidate -> candidate.startsWith(name)
                        || name.startsWith(candidate)).findFirst().map(candidate -> " (did you mean --" + candidate
                                + "?)").orElse("");
                throw new UsageException(command + " takes no --" + name + near + "; it takes --"
                        + String.join(", --", new TreeSet<>(known)));
            }
        }
    }

    /**
     * A yes/no option: {@code --fail-on-review}, {@code --fail-on-review true} or {@code false}; anything else is
     * refused rather than read as false.
     */
    boolean flag(String name) {
        String value = options.get(name);
        if (value == null || value.equals("false")) {
            return false;
        }
        if (value.equals("true")) {
            return true;
        }
        throw new UsageException("--" + name + " takes true or false, got: " + value);
    }

    /**
     * Paths separated by the platform's separator, each of which must exist, so a mistyped one isn't read as
     * nothing to scan.
     */
    List<Path> existingPaths(String name) {
        List<Path> paths = option(name).stream()
                .flatMap(value -> Arrays.stream(value.split(File.pathSeparator)))
                .filter(entry -> !entry.isBlank()).map(Path::of).toList();
        for (Path path : paths) {
            if (!Files.exists(path)) {
                throw new UsageException("--" + name + ": no such file or directory: " + path);
            }
        }
        return paths;
    }

    Optional<String> option(String name) {
        return Optional.ofNullable(options.get(name));
    }

    String required(String name) {
        return option(name).orElseThrow(() -> new UsageException("Missing --" + name));
    }

    /**
     * An option naming a file to read: given, it must exist, so a mistyped path isn't taken for "no such facts".
     */
    Optional<Path> file(String name) {
        Optional<Path> file = option(name).map(Path::of);
        if (file.isPresent() && !Files.isRegularFile(file.get())) {
            throw new UsageException("--" + name + ": no such file: " + file.get());
        }
        return file;
    }

    /**
     * A whole number option, e.g. {@code --lookback 60}.
     */
    Optional<Long> number(String name) {
        try {
            return option(name).map(Long::parseLong);
        }
        catch (NumberFormatException ex) {
            throw new UsageException("--" + name + " takes a whole number, got: " + options.get(name));
        }
    }

    List<String> list(String name) {
        return option(name).map(value -> Arrays.stream(value.split(",")).map(String::trim)
                .filter(entry -> !entry.isEmpty()).toList()).orElse(List.of());
    }
}
