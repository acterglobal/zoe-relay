# Website

This website is built using [Docusaurus](https://docusaurus.io/), a modern static website generator.

## Installation

```bash
yarn
```

## Local Development

### Option 1: Direct Node.js

```bash
npm install
npm start
```

This command starts a local development server and opens up a browser window. Most changes are reflected live without having to restart the server.

### Option 2: Docker (Recommended for consistency)

```bash
# Start the documentation service (from project root)
docker compose -f docker-compose.dev.yml --profile docs up -d

# View logs
docker compose -f docker-compose.dev.yml logs -f zoe-dev-docs

# Stop the service
docker compose -f docker-compose.dev.yml --profile docs down
```

The Docker service will:
- Automatically install dependencies
- Copy crate documentation from source
- Start the development server on http://localhost:3000
- Watch for changes and hot-reload

## Build

```bash
yarn build
```

This command generates static content into the `build` directory and can be served using any static contents hosting service.

## Deployment

Using SSH:

```bash
USE_SSH=true yarn deploy
```

Not using SSH:

```bash
GIT_USER=<Your GitHub username> yarn deploy
```

If you are using GitHub pages for hosting, this command is a convenient way to build the website and push to the `gh-pages` branch.
