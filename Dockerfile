FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
RUN npm run build

FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY --from=build /app/dist ./dist
COPY bin ./bin
COPY docs ./docs
ENV PORT=8791 OPENACCESS_DB=/data/openaccess.db NODE_ENV=production
VOLUME ["/data"]
EXPOSE 8791
CMD ["node", "bin/openaccess.mjs", "serve"]
