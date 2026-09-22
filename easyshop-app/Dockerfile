# easyshop-app — benchmark target container
#
# Built from the pre-packaged Spring Boot jar (target/easyshop-1.0.0.jar).
# If the jar doesn't exist, run `mvn -f easyshop-app/pom.xml package` first.
#
# ⚠️  DO NOT push this image to any registry. The app intentionally ships
# real vulnerabilities (SQLi, IDOR, SSRF, JWT-alg:none, …). It is a local
# / CI-only benchmark target.
#
# Usage:
#   docker build -t api-sentinel-easyshop -f Dockerfile ../..
#   docker run --rm -d -p 8089:8089 --name easyshop-app api-sentinel-easyshop
#   curl http://localhost:8089/web/dashboard  # sanity check
#   # run the benchmark against it:
#   cd ../.. && ./gradlew test --tests BenchmarkIntegrationTest \
#       -Dbenchmark.enabled=true -Dbenchmark.baseUrl=http://localhost:8089

FROM eclipse-temurin:17-jre-alpine

LABEL maintainer="API-Sentinel benchmark"
LABEL description="easyshop-app — EasyShop Spring Boot benchmark target"

# Run as non-root for hygiene (the app only binds 8089 and writes nothing
# persistent). The app's application.properties doesn't pin a user,
# so this is purely a container-level hardening.
RUN addgroup -S app && adduser -S -G app app
WORKDIR /opt/easyshop-app

# Copy the pre-built jar. The context is the API-Sentinel repo root so the
# path is relative to that root (see the -f flag in the build command above).
COPY easyshop-app/target/easyshop-1.0.0.jar /opt/easyshop-app/app.jar

# The app listens on 8089 (application.properties). No TLS — this is a
# local benchmark target, never exposed to a real network.
EXPOSE 8089

USER app

# Spring Boot fat-jar entry. JVM options:
#   -XX:+UseContainerSupport — honor container CPU/memory limits
#   -XX:MaxRAMPercentage=75  — leave headroom for Alpine's malloc overhead
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75", \
            "-jar", "/opt/easyshop-app/app.jar"]
