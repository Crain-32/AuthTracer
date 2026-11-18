# AuthTracer's scanner: the built Spring Boot jars and wars mounted at /in, their authorization graphs written to /out,
# with no network. Built from build/docker by ./gradlew :scanner-image:dockerImage, which puts the scanner's jars in
# lib/; run with scripts/scan-artifacts.sh. The entrypoint refuses to scan with a network, without /out mounted, or as
# root when it can become /out's owner instead.

# Java 25's runtime, by digest so a rebuild gets the same one (eclipse-temurin:25-jre-noble on 2026-10-18). A JRE is
# enough: nothing is compiled, and the scan reads the JDK's classes from this runtime's own modules.
FROM eclipse-temurin:25-jre-noble@sha256:3f2223fe04b750aa5a8179e29b5c9a1ddf7665fc9bb08bfe11ad01d143bc13a5

LABEL org.opencontainers.image.title="AuthTracer scanner" \
      org.opencontainers.image.description="Scans built Spring Boot jars and wars into authorization graphs, with no network"

# Read-only for every user; directories need their execute bit to be listed.
COPY --chmod=0555 lib/ /opt/authtracer/lib/
COPY --chmod=0555 entrypoint.sh /opt/authtracer/entrypoint.sh

# No USER: GitHub's Docker actions run as the image's root, and the entrypoint becomes /out's owner before it scans.
# No VOLUME: an anonymous volume would take the graphs when /out isn't mounted, where the entrypoint should refuse.
ENTRYPOINT ["/opt/authtracer/entrypoint.sh"]
