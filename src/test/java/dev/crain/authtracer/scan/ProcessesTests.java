package dev.crain.authtracer.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

class ProcessesTests {

    @Test
    void aProcessThatOutlastsItsTimeoutIsKilled() {
        long start = System.nanoTime();

        Processes.Result result = Processes.run(null, Duration.ofMillis(300), List.of("sh", "-c",
                "echo started; sleep 30"));

        assertThat(result.timedOut()).isTrue();
        assertThat(result.succeeded()).isFalse();
        assertThat(result.output()).contains("started");
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(15));
    }

    @Test
    void aProcessGetsNoInputAndItsOutputIsKept() {
        // cat ends when its input does; much output can't fill the pipe while it waits.
        Processes.Result result = Processes.run(null, Duration.ofSeconds(30), List.of("sh", "-c",
                "cat; i=0; while [ $i -lt 20000 ]; do echo line$i; i=$((i+1)); done; exit 3"));

        assertThat(result.timedOut()).isFalse();
        assertThat(result.exitCode()).isEqualTo(3);
        assertThat(result.output().lines()).hasSize(20000).last().isEqualTo("line19999");
    }

    @Test
    void aToolThatIsntInstalledCantBeRun() {
        assertThatThrownBy(() -> Processes.run(null, Duration.ofSeconds(30), List.of("authtracer-no-such-tool")))
                .isInstanceOf(UncheckedIOException.class).hasMessage("Can't run authtracer-no-such-tool");
    }

    @Test
    void anInterruptedWaitKillsTheProcessAndKeepsTheInterrupt() {
        long start = System.nanoTime();
        Thread.currentThread().interrupt();

        assertThatThrownBy(() -> Processes.run(null, Duration.ofSeconds(30), List.of("sleep", "30")))
                .isInstanceOf(IllegalStateException.class).hasMessage("Interrupted while running sleep 30");
        assertThat(Thread.interrupted()).isTrue();
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(15));
    }
}
