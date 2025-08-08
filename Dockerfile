# =========================
# Stage 1: Build the application
# =========================
FROM eclipse-temurin:17-jdk AS build

WORKDIR /app

# Copy Maven Wrapper files trước
COPY mvnw .
COPY .mvn .mvn

# Cấp quyền thực thi cho mvnw
RUN chmod +x mvnw

# Copy file cấu hình Maven và source code
COPY pom.xml .
RUN ./mvnw dependency:go-offline -B

COPY src src

# Build ứng dụng
RUN ./mvnw package -DskipTests

# =========================
# Stage 2: Run the application
# =========================
FROM eclipse-temurin:17-jre

WORKDIR /app

# Copy file jar từ stage build
COPY --from=build /app/target/*.jar app.jar

# Chạy ứng dụng
ENTRYPOINT ["java", "-jar", "app.jar"]
