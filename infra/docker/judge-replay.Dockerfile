#  The judge-replay image.  A static web page, and deliberately nothing else.
#
#  This is the only MUSTER image that is meant to be reachable by the public,
#  which is why it is defined by what it cannot do rather than by what it
#  serves.  It has **no Python, no control plane, no database driver, no
#  database, no database secret, no signing key, no bucket access, no
#  credential of any kind, and no mutation endpoint**.  Those absences are not
#  configuration to be set correctly at deploy time; there is nothing in the
#  image that could be pointed at any of them.
#
#  The bundle it serves is the replay-only build.  ``npm run build`` produces
#  that by default -- the UI's runtime mode fails closed, so a production
#  bundle has no local Action Gate control unless somebody deliberately asks
#  for one -- and the flag below says so a second time, in the place a reader
#  of this file would look.  What ships is the tracked, sanitized replay
#  artifacts under ``public/cases`` and the code that renders them.
#
#  Serving is GET and HEAD only.  Not because a static server would honour a
#  POST usefully, but because "there is no mutation endpoint" should be true of
#  the thing listening on the port and not only of the thing behind it.

FROM node:22-alpine AS build

WORKDIR /build

#  Manifest first, so a change to the application does not reinstall the world.
COPY packages/muster-ui/package.json packages/muster-ui/package-lock.json ./
RUN npm ci

COPY packages/muster-ui/ ./

#  Explicit, though it is also the default: this bundle exposes no local
#  Action Gate control and makes no request to `/api/demo`.
ENV VITE_MUSTER_LOCAL_GATE=false
RUN npm run build


#  Unprivileged nginx: it runs as a non-root user, keeps its temporary files
#  under /tmp, and needs no capability to bind the port Cloud Run assigns.
FROM nginxinc/nginx-unprivileged:1.27-alpine

#  Cloud Run names the port in the environment; the image's own entrypoint
#  expands this template into the live configuration before nginx starts.
ENV PORT=8080

COPY infra/docker/judge-replay.nginx.conf.template \
     /etc/nginx/templates/default.conf.template

COPY --from=build /build/dist /usr/share/nginx/html

EXPOSE 8080
