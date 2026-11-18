package dev.crain.authtracer.scan.spring;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;

/**
 * Decision 0035: a FreeMarker template rewritten as the JSP markup {@link ViewTemplates} reads, line for line:
 * {@code <#list owner.pets as pet>} is a {@code <c:forEach>}, {@code <#assign x = ..>} a {@code <c:set>},
 * {@code <#include "..">} a {@code <jsp:include>}, the Spring Security taglib's {@code <@sec.authorize access="..">}
 * (or {@code url=".." method=".."}) a {@code <sec:authorize>} and its {@code <@sec.accesscontrollist ..>} a
 * {@code <sec:accesscontrollist>} (decision 0081), Spring's {@code <@spring.formInput "owner.name"/>} a read of that path, and every other
 * directive an element whose expression is read. Interpolations ({@code ${..}}) stay as they are; comments go.
 */
@Supports(Feature.VIEW_FIELDS)
final class FreeMarkerMarkup {

    private static final Pattern COMMENT = Pattern.compile("<#--.*?-->", Pattern.DOTALL);
    // A lambda's -> doesn't end the directive.
    private static final Pattern DIRECTIVE = Pattern.compile("<(/?)([#@])([\\w.]+)((?:->|[^>\"']|\"[^\"]*\"|'[^']*')*?)"
            + "(/?)>", Pattern.DOTALL);
    /**
     * Built-ins that keep a sequence's elements: {@code owner.visits?filter(v -> v.paid)} lists visits.
     */
    private static final Pattern SAME_ELEMENTS = Pattern.compile("\\?(?:filter|sort|sort_by|reverse|take_while|drop_while)"
            + "(?:\\([^()]*\\))?");
    private static final Pattern LIST = Pattern.compile("\\s*(.+?)\\s+as\\s+([a-zA-Z_]\\w*)(?:\\s*,\\s*[a-zA-Z_]\\w*)?"
            + "\\s*", Pattern.DOTALL);
    private static final Pattern ITEMS = Pattern.compile("\\s*as\\s+([a-zA-Z_]\\w*)(?:\\s*,\\s*[a-zA-Z_]\\w*)?\\s*");
    private static final Pattern ASSIGN = Pattern.compile("\\s*([a-zA-Z_]\\w*)\\s*=\\s*(.+?)\\s*", Pattern.DOTALL);
    private static final Pattern STRING = Pattern.compile("\\s*[\"']([^\"']*)[\"']");
    /**
     * A macro's named argument: a string, or an expression ({@code domainObject=contact}).
     */
    private static final Pattern ARGUMENT = Pattern.compile("(\\w+)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([\\w.]+))");
    private static final Set<String> TAG_ARGUMENTS = Set.of("access", "url", "method", "hasPermission");

    private FreeMarkerMarkup() {
    }

    static String of(String template) {
        // Comments go, their lines stay.
        String text = replace(COMMENT.matcher(template), comment -> "\n".repeat(newlines(comment)));
        // <#list xs> .. <#items as x>: the list's source, for its items.
        Deque<String> lists = new ArrayDeque<>();
        Matcher directive = DIRECTIVE.matcher(text);
        StringBuilder markup = new StringBuilder();
        while (directive.find()) {
            boolean closing = !directive.group(1).isEmpty();
            boolean macro = directive.group(2).equals("@");
            String name = directive.group(3);
            String body = directive.group(4);
            String lines = "\n".repeat(newlines(directive.group()));
            String element;
            if (macro) {
                element = macro(name, body, closing, directive.group(5).isEmpty());
            }
            else {
                element = directive(name, body, closing, lists);
            }
            directive.appendReplacement(markup, Matcher.quoteReplacement(element + lines));
        }
        directive.appendTail(markup);
        return markup.toString();
    }

    private static String directive(String name, String body, boolean closing, Deque<String> lists) {
        switch (name) {
            case "list" -> {
                if (closing) {
                    lists.poll();
                    return "</fm:list>";
                }
                Matcher list = LIST.matcher(body);
                if (list.matches()) {
                    lists.push("");
                    return "<fm:list><c:forEach var=\"" + list.group(2) + "\" items=\"${" + elements(list.group(1))
                            + "}\">";
                }
                lists.push(elements(body.trim()));
                return "<fm:list>";
            }
            case "items" -> {
                Matcher items = ITEMS.matcher(body);
                if (closing || !items.matches() || lists.isEmpty()) {
                    return closing ? "</c:forEach>" : "";
                }
                return "<c:forEach var=\"" + items.group(1) + "\" items=\"${" + lists.peek() + "}\">";
            }
            case "assign", "local", "global" -> {
                Matcher assign = ASSIGN.matcher(body);
                return !closing && assign.matches() ? "<c:set var=\"" + assign.group(1) + "\" value=\"${"
                        + quoted(assign.group(2)) + "}\"/>" : "";
            }
            case "include" -> {
                Matcher file = STRING.matcher(body);
                return !closing && file.lookingAt() ? "<jsp:include page=\"" + file.group(1) + "\"/>" : "";
            }
            case "else", "sep", "break", "return", "import", "ftl", "setting", "nt", "t", "lt", "rt" -> {
                return "";
            }
            default -> {
                // #if, #elseif, #switch, #case, #attempt, ... : read their expressions, in an element so a closing
                // directive closes what it opened.
                if (closing) {
                    return "</fm:" + name + ">";
                }
                return "<fm:" + name + (body.isBlank() ? "" : " test=\"${" + quoted(body.trim()) + "}\"")
                        + ">";
            }
        }
    }

    /**
     * {@code <@sec.authorize access="..">} guards; {@code <@spring.formInput "owner.name"/>} and the other Spring
     * form macros read their path.
     */
    private static String macro(String name, String body, boolean closing, boolean opens) {
        String local = name.substring(name.lastIndexOf('.') + 1);
        if (local.equals("authorize") || local.equals("accesscontrollist")) {
            if (closing) {
                return "</sec:" + local + ">";
            }
            StringBuilder tag = new StringBuilder("<sec:" + local);
            Matcher argument = ARGUMENT.matcher(body);
            while (argument.find()) {
                String key = argument.group(1);
                if (TAG_ARGUMENTS.contains(key)) {
                    tag.append(' ').append(key).append("=\"").append(argument.group(2) != null ? argument.group(2)
                            : argument.group(3) != null ? argument.group(3) : argument.group(4)).append('"');
                }
                else if (key.equals("domainObject")) {
                    String object = argument.group(4) != null ? argument.group(4)
                            : argument.group(2) != null ? argument.group(2) : argument.group(3);
                    tag.append(" domainObject=\"").append(object.startsWith("${") ? object : "${" + object + "}")
                            .append('"');
                }
            }
            return tag.append(opens ? ">" : "/>").toString();
        }
        if (closing) {
            return "";
        }
        Matcher path = STRING.matcher(body);
        if ((local.startsWith("form") || local.equals("bind")) && path.lookingAt()) {
            return "<fm:field value=\"${" + path.group(1) + "}\"/>";
        }
        return "";
    }

    private static String elements(String sequence) {
        return quoted(SAME_ELEMENTS.matcher(sequence).replaceAll(""));
    }

    /**
     * An expression inside a double-quoted attribute: its own strings single-quoted.
     */
    private static String quoted(String expression) {
        return expression.replace('"', '\'');
    }

    private static String replace(Matcher matcher, java.util.function.Function<String, String> replacement) {
        StringBuilder replaced = new StringBuilder();
        while (matcher.find()) {
            matcher.appendReplacement(replaced, Matcher.quoteReplacement(replacement.apply(matcher.group())));
        }
        matcher.appendTail(replaced);
        return replaced.toString();
    }

    private static int newlines(String text) {
        return (int) text.chars().filter(c -> c == '\n').count();
    }
}
