FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app

# Copy the Maven wrapper and POM file
COPY .mvn/ .mvn/
COPY mvnw mvnw.cmd ./
COPY pom.xml ./

# Make the Maven wrapper executable
RUN chmod +x ./mvnw

# Download dependencies
RUN ./mvnw dependency:go-offline -B

# Copy source code
COPY src ./src

# Build the application
RUN ./mvnw package -DskipTests

# Runtime stage
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Copy the built artifact from the build stage
COPY --from=build /app/target/GithubManager-0.0.1-SNAPSHOT.jar app.jar

# Set environment variables
ENV PORT=8080
ENV SPRING_PROFILES_ACTIVE=prod

# Expose the port
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"] 