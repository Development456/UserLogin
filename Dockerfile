FROM openjdk:11-jdk

LABEL maintainer = "Apurva Bansode"

COPY target/userlogin-0.0.1-SNAPSHOT.jar /app/api.jar
COPY src/main/resources/application.properties /app/config/application.properties

EXPOSE 9003

ENTRYPOINT ["java", "-jar", "-Dspring.config.import=optional:configserver:http://20.232.127.94:8888", "-Dspring.config.name=application", "-Dspring.config.location=file:/app/config/", "/app/api.jar"]
