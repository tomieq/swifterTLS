FROM swift:6.1 AS build

WORKDIR /workspace
COPY Package.swift Package.resolved ./
COPY Sources ./Sources
COPY Tests ./Tests

RUN swift build -c release --product Demo

FROM swift:6.1

WORKDIR /app
COPY --from=build /workspace/.build/release/Demo /app/Demo

EXPOSE 8082
CMD ["/app/Demo"]
