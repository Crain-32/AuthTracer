package dev.crain.authtracer.conformance;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.List;

import org.springframework.beans.CachedIntrospectionResults;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.util.ReflectionUtils;

/**
 * Loads one fixture package from a directory of its own (the package as it is, or mutated, compiled by
 * mutationMutants; or woven, for conformanceTest) in place of the fixtures' classes, and the conformance harness with it, so that the harness boots
 * that version: {@link FixtureApps} finds the application class, and Spring the package's components, through this
 * loader. Everything else (Spring, the other fixtures) comes from the parent, shared by every version booted.
 */
final class MutantLoader extends URLClassLoader {

    private static final String HARNESS = MutantLoader.class.getPackageName() + ".";

    private final String classes;
    private final String resources;

    MutantLoader(Path fixtureClasses, Path harnessClasses, String fixture, ClassLoader parent) {
        super(urls(fixtureClasses, harnessClasses), parent);
        this.classes = "fixtures." + fixture + ".";
        this.resources = "fixtures/" + fixture + "/";
    }

    private static URL[] urls(Path... dirs) {
        URL[] urls = new URL[dirs.length];
        try {
            for (int i = 0; i < dirs.length; i++) {
                urls[i] = dirs[i].toUri().toURL();
            }
        } catch (MalformedURLException e) {
            throw new UncheckedIOException(e);
        }
        return urls;
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        boolean fixture = name.startsWith(classes);
        boolean harness = name.startsWith(HARNESS) && !name.startsWith(MutantLoader.class.getName())
                && !name.startsWith(MutationTests.class.getName())
                && !name.startsWith(ConformanceTests.class.getName());
        if (!fixture && !harness) {
            return super.loadClass(name, resolve);
        }
        synchronized (getClassLoadingLock(name)) {
            Class<?> loaded = findLoadedClass(name);
            if (loaded == null) {
                try {
                    loaded = findClass(name);
                } catch (ClassNotFoundException e) {
                    if (fixture) {
                        throw e;
                    }
                    return super.loadClass(name, resolve);
                }
            }
            if (resolve) {
                resolveClass(loaded);
            }
            return loaded;
        }
    }

    private boolean own(String name) {
        return name.startsWith(resources) || name.equals(resources.substring(0, resources.length() - 1));
    }

    @Override
    public URL getResource(String name) {
        return own(name) ? findResource(name) : super.getResource(name);
    }

    @Override
    public Enumeration<URL> getResources(String name) throws IOException {
        return own(name) ? findResources(name) : super.getResources(name);
    }

    /**
     * Boots the fixture from {@code classes} in a loader of its own and sends it the probes ({@link MutationProbes});
     * Spring's caches of the loader's classes are cleared after.
     *
     * @return what {@link MutationProbes#run} returns, or {@code NOT_BOOTED} with why
     */
    @SuppressWarnings("unchecked")
    static List<String> probe(Path classes, String fixture, Path resources, List<String> endpointLines,
            List<String> probes) {
        Thread thread = Thread.currentThread();
        ClassLoader previous = thread.getContextClassLoader();
        try (MutantLoader loader = new MutantLoader(classes, harness(), fixture, MutantLoader.class.getClassLoader())) {
            thread.setContextClassLoader(loader);
            try {
                Class<?> bridge = Class.forName(MutationProbes.class.getName(), true, loader);
                return (List<String>) bridge.getMethod("run", String.class, String.class, List.class, List.class)
                        .invoke(null, fixture, resources.toString(), endpointLines, probes);
            } catch (InvocationTargetException e) {
                return List.of("NOT_BOOTED\t" + Clients.root(e.getCause()));
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException(e);
            } finally {
                thread.setContextClassLoader(previous);
                CachedIntrospectionResults.clearClassLoader(loader);
                AnnotationUtils.clearCache();
                ReflectionUtils.clearCache();
                ResolvableType.clearCache();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Path harness() {
        try {
            return Path.of(MutantLoader.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }
}
