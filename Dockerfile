FROM openjdk:11-jdk

COPY target/userlogin-0.0.1-SNAPSHOT.jar /app/api.jar
COPY src/main/resources/application.properties /app/config/application.properties

EXPOSE 9003

ENTRYPOINT ["java", "-jar", "-Dspring.config.import=optional:configserver:http://172.174.113.233:8888", "-Dspring.config.name=application", "-Dspring.config.location=file:/app/config/", "/app/api.jar"]
