package dev.crain.authtracer.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import dev.crain.authtracer.AuthTracerProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.util.unit.DataSize;

class RequestBodyLimitTests {

    private final RequestBodyLimit limit = new RequestBodyLimit(new AuthTracerProperties(
            new AuthTracerProperties.Zipkin(URI.create("http://localhost:9411"), Duration.ofMinutes(60), 10),
            new AuthTracerProperties.Api(DataSize.ofBytes(10))));

    @Test
    void aBodyOverTheLimitIsTooLargeWhetherItsLengthIsDeclaredOrNot() throws Exception {
        assertThat(filter(post("/api/graphs", "01234567890", false)).getStatus()).isEqualTo(413);
        assertThat(filter(post("/api/exposures", "01234567890", true)).getStatus()).isEqualTo(413);
        // Spring MVC matches these to /api/graphs too.
        assertThat(filter(post("/api/graphs;x=1", "01234567890", true)).getStatus()).isEqualTo(413);
        assertThat(filter(post("/api/%67raphs", "01234567890", true)).getStatus()).isEqualTo(413);
    }

    @Test
    void aBodyWithinTheLimitReachesTheControllerWhole() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse response = new MockHttpServletResponse();
        limit.doFilter(post("/api/graphs", "{\"a\": 1}", true), response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(new String(chain.getRequest().getInputStream().readAllBytes(), StandardCharsets.UTF_8))
                .isEqualTo("{\"a\": 1}");
    }

    @Test
    void aChunkedBodyIsPassedOnAsOneOfItsLengthToReadAsBytesOrText() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        limit.doFilter(post("/api/graphs", "{\"é\": 1}", true), new MockHttpServletResponse(), chain);
        HttpServletRequest passed = (HttpServletRequest) chain.getRequest();

        assertThat(passed.getContentLength()).isEqualTo(9);
        assertThat(passed.getContentLengthLong()).isEqualTo(9);
        ServletInputStream in = passed.getInputStream();
        assertThat(in.isReady()).isTrue();
        assertThat(in.read()).isEqualTo('{');
        assertThat(in.isFinished()).isFalse();
        assertThat(in.readAllBytes()).hasSize(8);
        assertThat(in.isFinished()).isTrue();
        // It was read already: there is nothing to wait for.
        assertThatExceptionOfType(UnsupportedOperationException.class).isThrownBy(() -> in.setReadListener(null));
        // UTF-8 unless the request names its encoding.
        assertThat(passed.getReader().readLine()).isEqualTo("{\"é\": 1}");

        MockHttpServletRequest latin = post("/api/graphs", "", true);
        latin.setCharacterEncoding("ISO-8859-1");
        latin.setContent("{\"é\": 1}".getBytes(StandardCharsets.ISO_8859_1));
        MockFilterChain latinChain = new MockFilterChain();
        limit.doFilter(latin, new MockHttpServletResponse(), latinChain);
        assertThat(((HttpServletRequest) latinChain.getRequest()).getReader().readLine()).isEqualTo("{\"é\": 1}");
    }

    @Test
    void otherRequestsAreLeftAlone() throws Exception {
        assertThat(filter(post("/api/system/link", "01234567890", false)).getStatus()).isEqualTo(200);
        MockHttpServletRequest get = new MockHttpServletRequest("GET", "/api/graphs");
        MockHttpServletResponse response = new MockHttpServletResponse();
        limit.doFilter(get, response, new MockFilterChain());
        assertThat(response.getStatus()).isEqualTo(200);
    }

    private MockHttpServletResponse filter(MockHttpServletRequest request) throws ServletException, IOException {
        MockHttpServletResponse response = new MockHttpServletResponse();
        limit.doFilter(request, response, new MockFilterChain());
        return response;
    }

    /**
     * @param chunked sent without a length, as a chunked body is
     */
    private static MockHttpServletRequest post(String path, String body, boolean chunked) {
        MockHttpServletRequest request = chunked ? new MockHttpServletRequest("POST", path) {

            @Override
            public long getContentLengthLong() {
                return -1;
            }

            @Override
            public int getContentLength() {
                return -1;
            }
        } : new MockHttpServletRequest("POST", path);
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        return request;
    }
}
