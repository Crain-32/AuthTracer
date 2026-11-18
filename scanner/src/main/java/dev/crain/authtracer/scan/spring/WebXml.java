package dev.crain.authtracer.scan.spring;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A war's {@code WEB-INF/web.xml} filters (Servlet 6.1, section 8.2.3): its {@code <filter-mapping>}s in document
 * order, each with the {@code <filter>} it names. A servlet container maps them after the filters an initializer adds
 * with {@code isMatchAfter} false (Spring Boot's registrations, Spring Security's among them, when the war is a Boot
 * application) and before those it adds with {@code isMatchAfter} true.
 */
@Supports(Feature.CALL_PATHS)
final class WebXml {

    static final String FILE = "WEB-INF/web.xml";
    private static final java.util.regex.Pattern METADATA_COMPLETE = java.util.regex.Pattern.compile(
            "<(?:\\w+:)?web-app\\b[^>]*\\bmetadata-complete\\s*=\\s*[\"']true[\"']");

    /**
     * A filter's mapping.
     *
     * @param urls its {@code <url-pattern>}s; {@code null} when it is mapped to servlets by name too, which AuthTracer
     *        reads as any request
     * @param targetBean a {@code DelegatingFilterProxy}'s bean: its {@code targetBeanName} parameter, else its name
     */
    record Mapping(String name, String className, List<String> urls, String targetBean) {
    }

    /**
     * @param unread a web.xml AuthTracer couldn't parse
     */
    record Config(List<Mapping> mappings, Optional<String> unread) {

        static final Config NONE = new Config(List.of(), Optional.empty());
    }

    private WebXml() {
    }

    /**
     * A war's web.xml is among the resources.
     */
    static boolean present(List<Path> resourceDirs) {
        return resourceDirs.stream().anyMatch(dir -> Files.isRegularFile(dir.resolve(FILE)));
    }

    /**
     * Its {@code <web-app metadata-complete="true">}: the container reads no {@code @WebServlet} or {@code @WebFilter}
     * (Tomcat 11's {@code ContextConfig#webConfig}).
     */
    static boolean metadataComplete(List<Path> resourceDirs) {
        for (Path dir : resourceDirs) {
            Path file = dir.resolve(FILE);
            try {
                if (Files.isRegularFile(file) && METADATA_COMPLETE.matcher(Files.readString(file)).find()) {
                    return true;
                }
            }
            catch (IOException | java.io.UncheckedIOException unreadable) {
                // load(..) reports a web.xml it can't read.
            }
        }
        return false;
    }

    static Config load(List<Path> resourceDirs) {
        List<Mapping> mappings = new ArrayList<>();
        for (Path dir : resourceDirs) {
            Path file = dir.resolve(FILE);
            if (!Files.isRegularFile(file)) {
                continue;
            }
            Handler handler = new Handler();
            try {
                SAXParserFactory factory = SAXParserFactory.newInstance();
                factory.setNamespaceAware(true);
                // A configuration file, not a document from outside: still, no external entities.
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                SAXParser parser = factory.newSAXParser();
                parser.parse(new ByteArrayInputStream(Files.readAllBytes(file)), handler);
            }
            catch (IOException | SAXException | ParserConfigurationException ex) {
                return new Config(mappings, Optional.of(dir.relativize(file).toString().replace('\\', '/') + ": "
                        + ex.getMessage()));
            }
            mappings.addAll(handler.mappings());
        }
        return new Config(mappings, Optional.empty());
    }

    private static final class Handler extends DefaultHandler {

        private final Map<String, String> classes = new HashMap<>();
        private final Map<String, String> targets = new HashMap<>();
        private final List<String[]> mapped = new ArrayList<>();
        private final Map<Integer, List<String>> urls = new HashMap<>();
        private final StringBuilder text = new StringBuilder();
        private String filterName;
        private String filterClass;
        private String paramName;
        private String paramValue;
        private boolean inFilter;
        private boolean inMapping;
        private boolean byServlet;

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) {
            text.setLength(0);
            switch (localName) {
                case "filter" -> {
                    inFilter = true;
                    filterName = null;
                    filterClass = null;
                }
                case "filter-mapping" -> {
                    inMapping = true;
                    filterName = null;
                    byServlet = false;
                    urls.put(mapped.size(), new ArrayList<>());
                }
                default -> {
                }
            }
        }

        @Override
        public void characters(char[] ch, int start, int length) {
            text.append(ch, start, length);
        }

        @Override
        public void endElement(String uri, String localName, String qName) {
            String value = text.toString().trim();
            text.setLength(0);
            switch (localName) {
                case "filter-name" -> filterName = value;
                case "filter-class" -> filterClass = value;
                case "param-name" -> paramName = value;
                case "param-value" -> paramValue = value;
                case "init-param" -> {
                    // The schema puts a filter's name before its parameters.
                    if (inFilter && "targetBeanName".equals(paramName)) {
                        targets.put(filterName, paramValue);
                    }
                }
                case "url-pattern" -> {
                    if (inMapping) {
                        urls.get(mapped.size()).add(value);
                    }
                }
                case "servlet-name" -> byServlet |= inMapping;
                case "filter" -> {
                    inFilter = false;
                    // A filter without its class is one an initializer completes (addFilter by name).
                    if (filterClass != null) {
                        classes.put(filterName, filterClass);
                    }
                }
                case "filter-mapping" -> {
                    inMapping = false;
                    mapped.add(new String[] {filterName, Boolean.toString(byServlet)});
                }
                default -> {
                }
            }
        }

        List<Mapping> mappings() {
            List<Mapping> all = new ArrayList<>();
            for (int i = 0; i < mapped.size(); i++) {
                String name = mapped.get(i)[0];
                String className = classes.get(name);
                if (className == null) {
                    continue;
                }
                all.add(new Mapping(name, className, Boolean.parseBoolean(mapped.get(i)[1]) ? null
                        : List.copyOf(urls.get(i)), targets.getOrDefault(name, name)));
            }
            return all;
        }
    }
}
