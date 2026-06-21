FROM node:12-alpine AS build
ENV WORKDIR=/usr/src/app/
WORKDIR $WORKDIR
COPY package*.json $WORKDIR
RUN npm install --production --no-cache

FROM node:12-alpine
ENV USER=node
ENV WORKDIR=/home/$USER/app
WORKDIR $WORKDIR
COPY --from=build /usr/src/app/node_modules node_modules
# Application files and executables remain owned by root. The non-root runtime
# user only needs read/execute permissions, not ownership, which prevents a
# compromised process from modifying or replacing binaries (CWE-282).
COPY . $WORKDIR
# Run as the unprivileged "node" user shipped with the base image.
USER $USER
EXPOSE 4000
# Allow the orchestrator to detect an unhealthy container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:4000/ || exit 1
