# Zero Trust Workshop Site

Docusaurus-based documentation and workshop guidance site for the Zero Trust Assessment.

Covers workshop delivery, pillar-specific guidance (Identity, Devices, Network, Data,
Infrastructure, Security Operations, AI), videos, and FAQs in 11 languages.

## Running locally

### Codespaces / Dev Container (recommended)

Dependencies are automatically installed when the dev container starts (`postCreateCommand`
runs `npm install` for both the root and this folder).

```bash
cd src/react
npm run start
# Or for a specific locale:
npm run start -- --locale ja
```

The Docusaurus dev server starts on **port 3000** and is auto-forwarded.

### Local development

1. Install [Node.js](https://nodejs.org/en/download/) 18+
2. Run the following commands:

```bash
cd src/react
npm install     # One-time
npm run start
```

## Build for production

```bash
cd src/react
npm run build   # Output: src/react/build/
npm run serve   # Preview the production build locally
```
