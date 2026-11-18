package dev.crain.authtracer.scan.spring;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Decision 0035: what a view template (Thymeleaf, JSP or FreeMarker) reads from its model. Every {@code ${..}} and
 * {@code *{..}} expression in an attribute or inline text names model paths, e.g. {@code owner.firstName};
 * {@code th:object} makes {@code *{lastName}} read {@code owner.lastName}, {@code th:each="pet : ${owner.pets}"} makes
 * {@code pet.name} read {@code owner.pets[].name}, and {@code th:with} names a path. A {@code sec:authorize} element
 * (Thymeleaf's Spring Security dialect), or one whose {@code th:if} is just {@code #authorization.expression(..)},
 * guards what is read inside it. Fragments the template inserts ({@code ~{fragments/x :: y}}, or in
 * {@code th:replace}, {@code th:insert} and {@code th:include} without the {@code ~{}}) are read with the same model
 * and their arguments.
 * <p>
 * Decision 0081 (AUTHZ-14): a guard by URL ({@code sec:authorize-url="POST /admin"}, JSP's
 * {@code <sec:authorize url=".." method="..">}) is {@code url:POST /admin}, which the request rules decide; an ACL
 * guard ({@code sec:authorize-acl="${contact} :: 'READ,WRITE'"}, JSP's
 * {@code <sec:accesscontrollist domainObject=".." hasPermission="..">}) asks {@code hasPermission(..)} for each
 * permission.
 */
@Supports(Feature.VIEW_FIELDS)
final class ViewTemplates {

    /**
     * A model path the template reads, e.g. {@code owner.pets[].name}.
     *
     * @param guards the {@code sec:authorize} expressions of the elements around it, outermost first
     * @param guardLine the innermost guarding element's line, {@code 0} when unguarded
     * @param guardTemplate the template that line is in: a fragment's caller can guard it
     */
    record Read(String path, String template, int line, List<String> guards, int guardLine, String guardTemplate) {

        Read(String path, String template, int line, List<String> guards, int guardLine) {
            this(path, template, line, guards, guardLine, template);
        }

        /**
         * The read as the template inserting its fragment sees it: inside the caller's guards.
         */
        Read inside(Call call) {
            if (call.guards().isEmpty()) {
                return this;
            }
            List<String> all = new ArrayList<>(call.guards());
            all.addAll(guards);
            return guards.isEmpty() ? new Read(path, template, line, all, call.guardLine(), call.guardTemplate())
                    : new Read(path, template, line, all, guardLine, guardTemplate);
        }
    }

    /**
     * Where a template inserts a fragment, e.g. {@code ~{fragments/inputField :: input ('Name', 'name', 'text')}}.
     *
     * @param fragment the fragment's name in its template, {@code null} for the whole template
     * @param arguments the arguments, each a model path, a quoted literal ({@code 'name'}) or {@code ?} for computed;
     *        by position, or by name when written {@code name=..}
     * @param selection what {@code *{..}} selects where it is inserted
     */
    record Call(String fragment, List<String> arguments, Map<String, String> named, String selection,
            List<String> guards, int guardLine, String guardTemplate) {

        static Call plain() {
            return new Call(null, List.of(), Map.of(), null, List.of(), 0, null);
        }
    }

    private static final Set<String> VOID_ELEMENTS = Set.of("area", "base", "br", "col", "embed", "hr", "img",
            "input", "link", "meta", "param", "source", "track", "wbr");
    private static final Pattern TAG = Pattern.compile("<(/?)([a-zA-Z][\\w:-]*)((?:\\s+[^\\s=>/]+(?:\\s*=\\s*(?:\"[^\"]*\""
            + "|'[^']*'|[^\\s>]+))?)*)\\s*(/?)>", Pattern.DOTALL);
    private static final Pattern ATTRIBUTE = Pattern.compile("([^\\s=>/]+)(?:\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+))?");
    private static final Pattern EXPRESSION = Pattern.compile("([$*])\\{([^}]*)}");
    /**
     * Attributes that set up an element's scope (its variables, selected object and guard), in Thymeleaf's two
     * forms: what they read is the scope's, not a read of their own.
     */
    private static final Set<String> SCOPE_ATTRIBUTES = Set.of("th:each", "data-th-each", "th:object",
            "data-th-object", "th:with", "data-th-with", "sec:authorize", "data-sec-authorize", "sec:authorize-url",
            "data-sec-authorize-url", "sec:authorize-acl", "data-sec-authorize-acl");
    /**
     * A guard the request rules decide: {@code url:GET /admin}.
     */
    static final String URL_GUARD = "url:";
    private static final Pattern PATH = Pattern.compile("(?<![\\w#.'\"@])([a-zA-Z_]\\w*)((?:\\s*\\??\\.\\s*[a-zA-Z_]\\w*"
            + "|\\[[^]]*])*)");
    private static final Pattern EACH = Pattern.compile("\\s*([a-zA-Z_]\\w*)\\s*(?:,\\s*[a-zA-Z_]\\w*\\s*)?:\\s*(.*)");
    private static final Pattern WITH = Pattern.compile("([a-zA-Z_]\\w*)\\s*=\\s*([$*]\\{[^}]*})");
    private static final Pattern FRAGMENT = Pattern.compile("~\\{\\s*([\\w/.-]+)\\s*(?:::\\s*([\\w-]+)\\s*)?");
    /**
     * A fragment named without {@code ~{}}, which these attributes still accept: {@code fragments/header :: header}.
     */
    private static final Pattern SIMPLE_FRAGMENT = Pattern.compile("\\s*([\\w/.-]+)\\s*(?:::\\s*([\\w-]+)\\s*)?");
    private static final Set<String> INSERTING = Set.of("th:replace", "data-th-replace", "th:insert",
            "data-th-insert", "th:include", "data-th-include");
    /**
     * {@code th:if="${#authorization.expression('hasRole(''ADMIN'')')}"}: the security expression, quotes doubled.
     */
    private static final Pattern AUTHORIZATION_EXPRESSION = Pattern.compile(
            "\\s*\\$\\{\\s*#authorization\\.expression\\(\\s*'((?:[^']|'')*)'\\s*\\)\\s*}\\s*");
    private static final Pattern PREPROCESSED = Pattern.compile("__\\$\\{\\s*([a-zA-Z_]\\w*)\\s*}__");
    private static final Pattern NAMED_ARGUMENT = Pattern.compile("\\s*([a-zA-Z_]\\w*)\\s*=(.*)", Pattern.DOTALL);
    private static final Set<String> KEYWORDS = Set.of("true", "false", "null", "and", "or", "not", "eq", "ne",
            "lt", "gt", "le", "ge", "div", "mod", "instanceof", "new", "T", "this", "root", "param", "session",
            "request", "response", "application");
    private static final int MAX_FRAGMENTS = 50;
    /**
     * A variable whose value is computed, not a model path.
     */
    private static final String COMPUTED = "?";

    /**
     * Thymeleaf, or JSP with JSTL ({@code <c:forEach var items>}, {@code <c:set var value>}), EL ({@code ${..}}
     * anywhere) and Spring Security's taglib ({@code <sec:authorize access="..">}).
     */
    enum Dialect {
        THYMELEAF, JSP,
        /**
         * FreeMarker, rewritten as JSP markup ({@link FreeMarkerMarkup}).
         */
        FREEMARKER
    }

    private static final Pattern JSP_INCLUDE = Pattern.compile("<%@\\s*include\\s+file\\s*=\\s*\"([^\"]+)\"");

    /**
     * The last template {@link #line} was asked about, with the offsets of its line breaks.
     */
    private static final ThreadLocal<Object[]> NEWLINES = new ThreadLocal<>();

    private final List<Path> roots;
    private final String prefix;
    private final String suffix;
    private final Dialect dialect;
    /**
     * By view: a layout and its fragments are read once, however many handlers render them.
     */
    private final Map<String, Optional<List<Read>>> readsByView = new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * @param roots the resource directories (and the web application's root)
     * @param prefix where views are under a root, e.g. {@code templates/} or {@code WEB-INF/jsp/}
     */
    ViewTemplates(List<Path> roots, String prefix, String suffix, Dialect dialect) {
        this.roots = roots;
        this.prefix = prefix;
        this.suffix = suffix;
        this.dialect = dialect;
    }

    /**
     * What the view reads, or empty when there is no such template.
     */
    Optional<List<Read>> reads(String view) {
        Optional<List<Read>> cached = readsByView.get(view);
        if (cached != null) {
            return cached;
        }
        Optional<Path> file = find(view);
        Optional<List<Read>> found = Optional.empty();
        if (file.isPresent()) {
            List<Read> reads = new ArrayList<>();
            Set<String> seen = new LinkedHashSet<>();
            read(view, file.get(), Call.plain(), reads, seen);
            found = Optional.of(List.copyOf(reads));
        }
        readsByView.put(view, found);
        return found;
    }

    /**
     * The template's file, relative to its root, e.g. {@code templates/owners/ownerDetails.html}.
     */
    String file(String template) {
        // A JSP include names its file from the web application's root.
        boolean rooted = dialect == Dialect.JSP && template.startsWith("/");
        String name = template.startsWith("/") ? template.substring(1) : template;
        return rooted ? name : prefix + (name.endsWith(suffix) ? name : name + suffix);
    }

    private Optional<Path> find(String view) {
        String file = file(view);
        return roots.stream().map(dir -> dir.resolve(file)).filter(Files::isRegularFile).findFirst();
    }

    private void read(String view, Path file, Call call, List<Read> reads, Set<String> seen) {
        // The same fragment with other arguments reads other paths.
        if (!seen.add(view + " " + call) || seen.size() > MAX_FRAGMENTS) {
            return;
        }
        String html;
        try {
            html = Files.readString(file);
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        Map<String, String> parameters = parameters(html, call);
        String markup = dialect == Dialect.FREEMARKER ? FreeMarkerMarkup.of(html) : html;
        parse(view, markup, new Fragments() {
            @Override
            public void insert(String template) {
                insert(template, Call.plain());
            }

            @Override
            public void insert(String template, Call inserted) {
                find(template).ifPresent(found -> {
                    List<Read> inner = new ArrayList<>();
                    read(template, found, inserted, inner, seen);
                    inner.forEach(read -> reads.add(read.inside(call)));
                });
            }
        }, dialect == Dialect.FREEMARKER ? Dialect.JSP : dialect, parameters, call.selection())
                .forEach(read -> reads.add(read.inside(call)));
    }

    /**
     * The fragment's parameters bound to the call's arguments: {@code th:fragment="input (label, name, type)"} takes
     * them by position, or by name.
     */
    private static Map<String, String> parameters(String html, Call call) {
        Map<String, String> parameters = new HashMap<>(call.named());
        if (call.fragment() == null || call.arguments().isEmpty()) {
            return parameters;
        }
        Matcher declaration = Pattern.compile("(?:th|data-th)[:-]fragment\\s*=\\s*[\"']\\s*"
                + Pattern.quote(call.fragment()) + "\\s*\\(([^)]*)\\)").matcher(html);
        if (declaration.find()) {
            String[] names = declaration.group(1).split(",");
            for (int i = 0; i < names.length && i < call.arguments().size(); i++) {
                parameters.put(names[i].trim(), call.arguments().get(i));
            }
        }
        return parameters;
    }

    interface Fragments {
        void insert(String template);

        /**
         * A fragment inserted with arguments, inside its caller's selection and guards.
         */
        default void insert(String template, Call call) {
            insert(template);
        }
    }

    /**
     * An element's scope: what {@code *{..}} selects, the variables it declares, and its guard.
     */
    private record Scope(String tag, String selection, Map<String, String> variables, String guard, int line) {
    }

    static List<Read> parse(String template, String html, Fragments fragments) {
        return parse(template, html, fragments, Dialect.THYMELEAF);
    }

    static List<Read> parse(String template, String html, Fragments fragments, Dialect dialect) {
        return parse(template, html, fragments, dialect, Map.of(), null);
    }

    /**
     * @param parameters a fragment's parameters, bound like {@code th:with} variables
     * @param selection what {@code *{..}} selects where the fragment is inserted
     */
    static List<Read> parse(String template, String html, Fragments fragments, Dialect dialect,
            Map<String, String> parameters, String callerSelection) {
        boolean jsp = dialect == Dialect.JSP;
        List<Read> reads = new ArrayList<>();
        Deque<Scope> scopes = new ArrayDeque<>();
        // The page's own scope: a fragment's parameters and selection, JSP's <c:set> variables.
        scopes.push(new Scope("#page", callerSelection, new HashMap<>(parameters), null, 0));
        if (jsp) {
            Matcher include = JSP_INCLUDE.matcher(html);
            while (include.find()) {
                fragments.insert(include.group(1));
            }
        }
        Matcher tag = TAG.matcher(html);
        int textStart = 0;
        while (tag.find()) {
            inline(template, html, textStart, tag.start(), scopes, reads, jsp);
            textStart = tag.end();
            String name = tag.group(2).toLowerCase(Locale.ROOT);
            String local = name.substring(name.indexOf(':') + 1);
            if (!tag.group(1).isEmpty()) {
                // A closing tag closes its element and what was left open inside it (a <p>, an <li>); one whose
                // element isn't open (</input>) closes nothing, as an HTML parser ignores it.
                if (scopes.stream().anyMatch(scope -> scope.tag().equals(name))) {
                    while (!scopes.peek().tag().equals(name)) {
                        scopes.pop();
                    }
                    scopes.pop();
                }
                continue;
            }
            int line = line(html, tag.start());
            Map<String, String> attributes = attributes(tag.group(3));
            String guard = jsp ? jspGuard(local, attributes) : thymeleafGuard(attributes);
            String condition = jsp ? null : attributes.getOrDefault("th:if", attributes.get("data-th-if"));
            Matcher authorization = condition == null ? null : AUTHORIZATION_EXPRESSION.matcher(condition);
            if (guard == null && authorization != null && authorization.matches()) {
                guard = authorization.group(1).replace("''", "'");
            }
            if (jsp && local.equals("include") && attributes.get("page") != null) {
                fragments.insert(attributes.get("page"));
            }
            if (jsp && local.equals("set") && attributes.get("var") != null && attributes.get("value") != null) {
                paths(attributes.get("value"), scopes).stream().findFirst()
                        .ifPresent(path -> scopes.getLast().variables().put(attributes.get("var"), path));
            }
            // Thymeleaf's attribute order: th:each first, then th:with and th:object, which see its variable.
            Map<String, String> variables = new HashMap<>();
            String each = jsp && local.equals("foreach") && attributes.get("var") != null
                    && attributes.get("items") != null ? attributes.get("var") + " : " + attributes.get("items")
                    : attributes.getOrDefault("th:each", attributes.get("data-th-each"));
            if (each != null) {
                Matcher declaration = EACH.matcher(each);
                if (declaration.matches()) {
                    // Iterating a call's result (#numbers.sequence(..)) iterates no model path.
                    String source = declaration.group(2);
                    String iterated = source.contains("(") ? null
                            : paths(source, scopes).stream().findFirst().map(path -> path + "[]").orElse(null);
                    variables.put(declaration.group(1), iterated == null ? COMPUTED : iterated);
                }
            }
            scopes.push(new Scope(name, null, variables, guard, line));
            String with = attributes.getOrDefault("th:with", attributes.get("data-th-with"));
            if (with != null) {
                Matcher assignment = WITH.matcher(with);
                while (assignment.find()) {
                    paths(assignment.group(2), scopes).stream().findFirst()
                            .ifPresent(path -> variables.put(assignment.group(1), path));
                }
            }
            // Spring's form taglib: <form:form modelAttribute=".."> selects what its fields' paths name.
            boolean tagLibrary = jsp && name.contains(":");
            String object = tagLibrary && local.equals("form") ? "${" + attributes.getOrDefault("modelattribute",
                    attributes.getOrDefault("commandname", "command")) + "}"
                    : attributes.getOrDefault("th:object", attributes.get("data-th-object"));
            String selection = object == null ? null : paths(object, scopes).stream().findFirst().orElse(null);
            scopes.pop();
            Scope scope = new Scope(name, selection, variables, guard, line);
            boolean opens = tag.group(4).isEmpty() && !VOID_ELEMENTS.contains(name);
            scopes.push(scope);
            for (Map.Entry<String, String> attribute : attributes.entrySet()) {
                String key = attribute.getKey();
                String value = attribute.getValue();
                if (value == null || SCOPE_ATTRIBUTES.contains(key) || jsp && (local.equals("foreach")
                        && key.equals("items") || local.equals("set") && key.equals("value"))) {
                    continue;
                }
                Matcher fragment = FRAGMENT.matcher(value);
                while (fragment.find()) {
                    fragments.insert(fragment.group(1), call(fragment.group(2), arguments(value, fragment.end()),
                            scopes, template));
                }
                Matcher simple = SIMPLE_FRAGMENT.matcher(value);
                if (!jsp && INSERTING.contains(key) && !value.contains("~{") && simple.lookingAt()) {
                    fragments.insert(simple.group(1), call(simple.group(2), arguments(value, simple.end()), scopes,
                            template));
                }
                if (key.startsWith("th:") || key.startsWith("data-th-") || value.contains("${")
                        || value.contains("*{")) {
                    for (String path : paths(value, scopes)) {
                        reads.add(new Read(path, template, line, guards(scopes), guardLine(scopes)));
                    }
                }
            }
            String bound = tagLibrary ? attributes.get("path") : null;
            if (bound != null) {
                // <form:input path="email"> reads the form object's email; <spring:bind path="contact.email"> names
                // the whole path.
                for (String read : paths((local.equals("bind") ? "${" : "*{") + bound + "}", scopes)) {
                    reads.add(new Read(read, template, line, guards(scopes), guardLine(scopes)));
                }
            }
            // The element's own th:each/th:with sources are read too, under its guard.
            for (String declared : variables.values().stream().filter(path -> !path.startsWith(COMPUTED))
                    .toList()) {
                reads.add(new Read(declared.endsWith("[]") ? declared.substring(0, declared.length() - 2) : declared,
                        template, line, guards(scopes), guardLine(scopes)));
            }
            if (!opens) {
                scopes.pop();
            }
        }
        inline(template, html, textStart, html.length(), scopes, reads, jsp);
        return reads;
    }

    /**
     * The arguments in parentheses after a fragment's name, split at top-level commas; empty without them.
     *
     * @param open just past the name and the whitespace after it, as the fragment patterns match them
     */
    private static List<String> arguments(String value, int open) {
        List<String> arguments = new ArrayList<>();
        if (open >= value.length() || value.charAt(open) != '(') {
            return arguments;
        }
        int depth = 0;
        boolean quoted = false;
        StringBuilder current = new StringBuilder();
        for (int i = open; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\'') {
                quoted = !quoted;
            }
            if (!quoted && (c == '(' || c == '{' || c == '[')) {
                depth++;
                if (depth == 1) {
                    continue;
                }
            }
            if (!quoted && (c == ')' || c == '}' || c == ']')) {
                depth--;
                if (depth == 0) {
                    arguments.add(current.toString().trim());
                    return arguments;
                }
            }
            if (!quoted && c == ',' && depth == 1) {
                arguments.add(current.toString().trim());
                current.setLength(0);
                continue;
            }
            current.append(c);
        }
        return arguments;
    }

    /**
     * A fragment insertion, with its arguments evaluated where it is inserted.
     */
    private static Call call(String fragment, List<String> arguments, Deque<Scope> scopes, String template) {
        List<String> positional = new ArrayList<>();
        Map<String, String> named = new HashMap<>();
        for (String argument : arguments) {
            Matcher name = NAMED_ARGUMENT.matcher(argument);
            if (name.matches() && !name.group(2).startsWith("=")) {
                named.put(name.group(1), value(name.group(2).trim(), scopes));
            }
            else {
                positional.add(value(argument, scopes));
            }
        }
        return new Call(fragment, positional, named, selection(scopes), guards(scopes), guardLine(scopes),
                template);
    }

    /**
     * An argument: a quoted literal, the model path of a lone {@code ${..}}/{@code *{..}}, or computed.
     */
    private static String value(String argument, Deque<Scope> scopes) {
        if (argument.matches("'[^']*'")) {
            return argument;
        }
        if (argument.matches("[$*]\\{[^}]*}")) {
            return paths(argument, scopes).stream().findFirst().orElse(COMPUTED);
        }
        return COMPUTED;
    }

    /**
     * Inline expressions in text: {@code [[${owner.name}]]} and {@code [(${..})]}.
     */
    private static void inline(String template, String html, int start, int end, Deque<Scope> scopes,
            List<Read> reads, boolean jsp) {
        if (start >= end) {
            return;
        }
        String text = html.substring(start, end);
        // Thymeleaf's [[..]] and [(..)]; any EL in a JSP's text.
        if (jsp ? !text.contains("${") : !text.contains("[[") && !text.contains("[(")) {
            return;
        }
        for (String path : paths(text, scopes)) {
            reads.add(new Read(path, template, line(html, start), guards(scopes), guardLine(scopes)));
        }
    }

    /**
     * The model paths an attribute value's expressions read.
     */
    private static List<String> paths(String value, Deque<Scope> scopes) {
        Set<String> found = new LinkedHashSet<>();
        // Preprocessed expressions (__${name}__) are built at render time: from a literal fragment argument, or
        // unknown.
        Matcher preprocessed = PREPROCESSED.matcher(value);
        StringBuilder expanded = new StringBuilder();
        while (preprocessed.find()) {
            String bound = variable(preprocessed.group(1), scopes);
            preprocessed.appendReplacement(expanded, Matcher.quoteReplacement(bound != null && bound.startsWith("'")
                    ? bound.substring(1, bound.length() - 1) : "''"));
        }
        preprocessed.appendTail(expanded);
        Matcher expression = EXPRESSION.matcher(expanded.toString().replaceAll("__.*?__", "''"));
        while (expression.find()) {
            boolean selected = expression.group(1).equals("*");
            // owner['new'] reads the property new; then string literals say nothing.
            String body = expression.group(2).replaceAll("\\[\\s*'([a-zA-Z_]\\w*)'\\s*]", ".$1")
                    .replaceAll("\\[\\s*\"([a-zA-Z_]\\w*)\"\\s*]", ".$1")
                    .replaceAll("'[^']*'", "''").replaceAll("\"[^\"]*\"", "\"\"");
            Matcher path = PATH.matcher(body);
            while (path.find()) {
                String root = path.group(1);
                // A method call's name is not a path: x.y(...) reads x.
                String rest = path.group(2).replaceAll("\\s+", "").replace("?.", ".");
                int after = path.end();
                while (after < body.length() && Character.isWhitespace(body.charAt(after))) {
                    after++;
                }
                boolean call = after < body.length() && body.charAt(after) == '(';
                List<String> segments = new ArrayList<>(List.of(rest.split("\\.")));
                segments.removeIf(String::isEmpty);
                if (call) {
                    if (segments.isEmpty()) {
                        continue;
                    }
                    String method = segments.removeLast();
                    // Getter calls read their property.
                    if (method.startsWith("get") && method.length() > 3) {
                        segments.add(Character.toLowerCase(method.charAt(3)) + method.substring(4));
                    }
                }
                if (KEYWORDS.contains(root)) {
                    continue;
                }
                String resolved = resolve(root, segments, selected, scopes);
                if (resolved != null && !resolved.startsWith(COMPUTED)) {
                    found.add(resolved);
                }
            }
        }
        return List.copyOf(found);
    }

    private static String resolve(String root, List<String> segments, boolean selected, Deque<Scope> scopes) {
        StringBuilder tail = new StringBuilder();
        for (String segment : segments) {
            // An index belongs to its property: pets[0] is pets[].
            String normalized = segment.replaceAll("\\[[^]]*]", "[]");
            tail.append(normalized.startsWith("[") ? "" : ".").append(normalized);
        }
        String head = root.replaceAll("\\[[^]]*]", "[]");
        if (selected) {
            String selection = selection(scopes);
            return selection == null ? head + tail : selection + "." + head + tail;
        }
        String variable = variable(root, scopes);
        if (variable != null) {
            // A literal (a fragment's 'name' argument) is no model path.
            return variable.startsWith("'") ? COMPUTED : variable + tail;
        }
        return head + tail;
    }

    private static String variable(String name, Deque<Scope> scopes) {
        for (Scope scope : scopes) {
            String variable = scope.variables().get(name);
            if (variable != null) {
                return variable;
            }
        }
        return null;
    }

    private static String selection(Deque<Scope> scopes) {
        for (Scope scope : scopes) {
            if (scope.selection() != null) {
                return scope.selection();
            }
        }
        return null;
    }

    /**
     * Spring Security's JSP tags, as 7.x's {@code AbstractAuthorizeTag#authorize} reads them: {@code access} if
     * given, else {@code url} (with {@code method}, {@code GET} by default), else nothing is shown; and
     * {@code accesscontrollist}.
     */
    private static String jspGuard(String local, Map<String, String> attributes) {
        if (local.equals("authorize")) {
            String access = attributes.get("access");
            String url = attributes.get("url");
            return access != null && !access.isBlank() ? access : url != null && !url.isBlank()
                    ? URL_GUARD + attributes.getOrDefault("method", "GET").trim().toUpperCase(Locale.ROOT) + " "
                            + url.trim()
                    : "denyAll";
        }
        if (local.equals("accesscontrollist")) {
            return acl(attributes.get("domainobject"), attributes.get("haspermission"));
        }
        return null;
    }

    /**
     * Thymeleaf's Spring Security dialect: {@code sec:authorize}, {@code sec:authorize-url} ({@code "/admin"} or
     * {@code "POST /admin"}, as thymeleaf-extras-springsecurity6 3.1's {@code AuthorizeUrlAttrProcessor} splits it)
     * and {@code sec:authorize-acl} ({@code "${domainObject} :: permissions"}).
     */
    private static String thymeleafGuard(Map<String, String> attributes) {
        String access = attributes.getOrDefault("sec:authorize", attributes.get("data-sec-authorize"));
        if (access != null) {
            return access;
        }
        String url = attributes.getOrDefault("sec:authorize-url", attributes.get("data-sec-authorize-url"));
        if (url != null) {
            String trimmed = url.trim();
            int space = trimmed.indexOf(' ');
            return URL_GUARD + (space < 0 ? "GET " + trimmed : trimmed.substring(0, space).toUpperCase(Locale.ROOT)
                    + " " + trimmed.substring(space + 1).trim());
        }
        String acl = attributes.getOrDefault("sec:authorize-acl", attributes.get("data-sec-authorize-acl"));
        if (acl != null && acl.contains("::")) {
            return acl(acl.substring(0, acl.indexOf("::")), acl.substring(acl.indexOf("::") + 2));
        }
        return null;
    }

    /**
     * An ACL guard as the {@code hasPermission(..)} it makes for each permission, all of which must be granted.
     */
    private static String acl(String domainObject, String permissions) {
        String object = domainObject == null ? "null" : domainObject.trim().replaceFirst("^[$*]\\{\\s*(.*?)\\s*}$", "$1");
        String listed = permissions == null ? "" : permissions.trim().replaceFirst("^'(.*)'$", "$1");
        List<String> each = Arrays.stream(listed.split(",")).map(String::trim).filter(part -> !part.isEmpty())
                .map(part -> "hasPermission(" + object + ", '" + part + "')").toList();
        return each.isEmpty() ? "denyAll" : String.join(" and ", each);
    }

    private static List<String> guards(Deque<Scope> scopes) {
        List<String> guards = new ArrayList<>();
        scopes.descendingIterator().forEachRemaining(scope -> {
            if (scope.guard() != null) {
                guards.add(scope.guard());
            }
        });
        return guards;
    }

    private static int guardLine(Deque<Scope> scopes) {
        for (Scope scope : scopes) {
            if (scope.guard() != null) {
                return scope.line();
            }
        }
        return 0;
    }

    private static Map<String, String> attributes(String text) {
        Map<String, String> attributes = new LinkedHashMap<>();
        Matcher attribute = ATTRIBUTE.matcher(text);
        while (attribute.find()) {
            String value = attribute.group(2);
            if (value != null && (value.startsWith("\"") || value.startsWith("'"))) {
                value = value.substring(1, value.length() - 1);
            }
            attributes.put(attribute.group(1).toLowerCase(Locale.ROOT), value);
        }
        return attributes;
    }

    private static int line(String html, int offset) {
        // Where the template's lines break, found once per template rather than once per tag.
        Object[] cached = NEWLINES.get();
        int[] newlines;
        if (cached != null && cached[0] == html) {
            newlines = (int[]) cached[1];
        }
        else {
            newlines = java.util.stream.IntStream.range(0, html.length()).filter(i -> html.charAt(i) == '\n')
                    .toArray();
            NEWLINES.set(new Object[] {html, newlines});
        }
        int found = java.util.Arrays.binarySearch(newlines, offset);
        return (found >= 0 ? found : -found - 1) + 1;
    }
}
