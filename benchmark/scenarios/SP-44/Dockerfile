# ObliRCA benchmark scaffold: SP-44
# Base image chosen from the scenario language.  Replace the placeholder
# commands with the project's own build instructions.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /src

# The incident-version source tree is intentionally not vendored.
# Copy it into ./sources before building, or mount it at /src.
COPY . /src

# Example build hooks (edit per project):
# RUN ./configure && make -j"$(nproc)"
# RUN mvn -q -DskipTests package
# RUN pip install -r requirements.txt

CMD ["/bin/bash", "-lc", "sleep infinity"]
