package dev.crain.authtracer.api;

import java.io.ByteArrayInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import dev.crain.authtracer.AuthTracerProperties;
import dev.crain.authtracer.annotations.Feature;
import dev.crain.authtracer.annotations.Supports;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UrlPathHelper;

/**
 * Caps the body of the requests that post a graph, which Tomcat's {@code maxPostSize} (forms only) doesn't: a body
 * over {@code authtracer.api.max-body-size} is answered with 413 before anything parses it.
 */
@Supports(Feature.GRAPH_SERVER)
@Component
class RequestBodyLimit extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestBodyLimit.class);

    private static final Set<String> GRAPH_BODIES = Set.of("/api/graphs", "/api/exposures");
    private static final UrlPathHelper PATHS = new UrlPathHelper();

    private final long limit;

    RequestBodyLimit(AuthTracerProperties properties) {
        this.limit = properties.api().maxBodySize().toBytes();
    }

    /**
     * The path as Spring MVC matches it: decoded, without {@code ;} parameters, so {@code /api/graphs;x=1} and
     * {@code /api/%67raphs} are capped too.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equals(request.getMethod())
                || !GRAPH_BODIES.contains(PATHS.getPathWithinApplication(request));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long declared = request.getContentLengthLong();
        if (declared > limit) {
            tooLarge(request, response);
            return;
        }
        if (declared >= 0) {
            chain.doFilter(request, response);
            return;
        }
        // Chunked: no length up front, so the body is read up to the limit before it is passed on.
        byte[] body = request.getInputStream().readNBytes((int) Math.min(limit + 1, Integer.MAX_VALUE - 8));
        if (body.length > limit) {
            tooLarge(request, response);
            return;
        }
        chain.doFilter(new ReadBody(request, body), response);
    }

    private void tooLarge(HttpServletRequest request, HttpServletResponse response) throws IOException {
        log.info("Rejected a body over {} bytes for {} {}", limit, request.getMethod(), request.getRequestURI());
        response.sendError(HttpStatus.CONTENT_TOO_LARGE.value(), "The body is over the " + limit
                + " bytes authtracer.api.max-body-size allows");
    }

    /**
     * A request whose body was read already.
     */
    private static final class ReadBody extends HttpServletRequestWrapper {

        private final byte[] body;

        ReadBody(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public int getContentLength() {
            return body.length;
        }

        @Override
        public long getContentLengthLong() {
            return body.length;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream in = new ByteArrayInputStream(body);
            return new ServletInputStream() {

                @Override
                public int read() {
                    return in.read();
                }

                @Override
                public int read(byte[] buffer, int offset, int length) {
                    return in.read(buffer, offset, length);
                }

                @Override
                public boolean isFinished() {
                    return in.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener listener) {
                    throw new UnsupportedOperationException("The body was read already");
                }
            };
        }

        @Override
        public BufferedReader getReader() {
            Charset charset = getCharacterEncoding() == null ? StandardCharsets.UTF_8
                    : Charset.forName(getCharacterEncoding());
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }
}
