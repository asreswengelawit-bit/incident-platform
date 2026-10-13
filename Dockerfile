FROM gradle:8.14.3-jdk21 AS build

WORKDIR /workspace
COPY . .
RUN gradle --no-daemon bootJar \
    && find build/libs -maxdepth 1 -type f -name '*.jar' ! -name '*-plain.jar' -exec cp {} /tmp/incident-platform.jar \;

FROM eclipse-temurin:21-jre

WORKDIR /app
RUN mkdir -p /var/lib/incident-platform/evidence && chown -R 10001:0 /var/lib/incident-platform
COPY --from=build /tmp/incident-platform.jar app.jar
USER 10001
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
