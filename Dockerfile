# TRUST404 Track 1 - offline grading image
#   docker build -t noexit .
#   docker run --rm --network none -v "$PWD/cases:/input:ro" noexit /input > out.json
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npx tsc -p tsconfig.json && npm prune --omit=dev
COPY run.sh ./
ENTRYPOINT ["/app/run.sh"]
