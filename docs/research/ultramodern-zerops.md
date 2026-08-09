# UltraModern.js direct-scan deployment on Zerops

**Ticket:** Prove the UltraModern.js direct-scan Zerops deployment path  
**Researched:** 2026-08-09  
**Decision status:** Proven for the deadline-constrained MVP, with one required framework workaround and explicit production limits.

## Verdict

Ship exactly two Zerops services:

1. **radar** — one Node.js 24 / Ubuntu service containing the UltraModern-powered UI, Hono BFF/API, Streamable HTTP MCP endpoint, PostgreSQL-backed job loop, and directly spawned analyzer subprocesses.
2. **db** — one managed PostgreSQL 18 single-container service.

Do **not** add a scan-worker service. A single Radar process can safely keep its HTTP event loop responsive while it runs one bounded child process at a time with Node's asynchronous <code>spawn</code>. Persist jobs and results in PostgreSQL, keep repositories and analyzer scratch data in per-job temporary directories, and fix the Radar service at one container for this MVP.

The published UltraModern packages are usable, but its full SuperApp generator is the wrong scaffold for this topology. The generator deliberately creates a thin shell plus separate full-stack MicroVerticals and emits one Zerops service per app. It also currently emits <code>nodejs@26</code>, while Zerops officially offers Node 24, 22, 20, and 18. For this MVP, create a minimal Modern.js workspace app and pin its Modern package names to the BleedingDev UltraModern release through npm aliases. This preserves one service and uses the actual forked framework/runtime.

The local probe passed on Node 24.16.0:

~~~text
Modern.js Framework v3.5.0-ultramodern.100
ready   built in 0.76s
info    TS-Go compile succeed
Static directory: .output/static

GET /api/health -> {"ok":true}
GET /api/stream -> first
                   second
~~~

The stream probe returned a native streaming <code>Response</code> in two chunks. That is the framework behavior needed by a request-scoped SSE Streamable HTTP MCP response.

## Decision record

| Question | Decision | Evidence class |
|---|---|---|
| App boundary | UI + API/BFF + MCP + direct analyzers in one Radar service | User constraint; locally proven framework/build path |
| Data boundary | Managed PostgreSQL service | Direct Zerops capability |
| Scan execution | Asynchronous <code>child_process.spawn</code> inside Radar; concurrency 1 | Direct Node capability; bounded-MVP inference |
| UltraModern integration | Standard single Modern app pinned to UltraModern npm aliases | Locally proven workaround |
| UltraModern generator | Do not use the SuperApp generator for this MVP | Direct generator contract conflict |
| Runtime | <code>nodejs@24</code>, <code>os: ubuntu</code>, exact pnpm 11.17.0 | Direct Zerops support plus native-binary compatibility inference |
| MCP | Current MCP TypeScript SDK 2.0.0, one stateless POST endpoint at <code>/api/mcp</code> | Direct current protocol and SDK support |
| Temporary scan storage | <code>os.tmpdir()</code> + <code>mkdtemp</code>; delete in <code>finally</code> | Direct Node capability; runtime persistence limit |
| Horizontal scale | <code>minContainers: 1</code>, <code>maxContainers: 1</code> | MVP correctness choice |
| Challenge service count | Two services are eligible; three is not mandatory | Direct canonical rule plus documented wording disagreement |

## UltraModern release and scaffold

### Current release

The current public fork is [BleedingDev/ultramodern.js](https://github.com/BleedingDev/ultramodern.js), default branch <code>main-ultramodern</code>, MIT licensed. The latest release checked was [ultramodern-v3.5.0-ultramodern.100](https://github.com/BleedingDev/ultramodern.js/releases/tag/ultramodern-v3.5.0-ultramodern.100), published 2026-08-04 from commit <code>b1ec5628d44bb80ef99684b897d5e9a80c014c88</code>.

Pin the following exact versions; do not use floating <code>latest</code> during the challenge:

~~~json
{
  "dependencies": {
    "@modern-js/plugin-bff": "npm:@bleedingdev/modern-js-plugin-bff@3.5.0-ultramodern.100",
    "@modern-js/runtime": "npm:@bleedingdev/modern-js-runtime@3.5.0-ultramodern.100",
    "@modern-js/server-core": "npm:@bleedingdev/modern-js-server-core@3.5.0-ultramodern.100",
    "@modelcontextprotocol/server": "2.0.0",
    "effect": "4.0.0-beta.102"
  },
  "devDependencies": {
    "@modern-js/app-tools": "npm:@bleedingdev/modern-js-app-tools@3.5.0-ultramodern.100",
    "@modern-js/tsconfig": "npm:@bleedingdev/modern-js-tsconfig@3.5.0-ultramodern.100"
  }
}
~~~

The published fork packages declare Node >=20. The generated workspace baseline is Node 26.5.0 and pnpm 11.17.0, but the package engine permits the supported Zerops Node 24 runtime. The probe repeated the build and server smoke test with Node 24.16.0 and pnpm 11.17.0.

### Why the full generator is not the MVP scaffold

The fork's [create README at the release commit](https://github.com/BleedingDev/ultramodern.js/blob/b1ec5628d44bb80ef99684b897d5e9a80c014c88/packages/toolkit/create/README.md) documents:

~~~sh
pnpm dlx @bleedingdev/modern-js-create my-workspace
mise install
pnpm install
pnpm check
pnpm build
~~~

However, the generated shell contract [explicitly forbids API/server/backend surfaces in the shell](https://github.com/BleedingDev/ultramodern.js/blob/b1ec5628d44bb80ef99684b897d5e9a80c014c88/packages/toolkit/create/src/ultramodern-workspace/workspace-validation-contract.ts); full-stack behavior belongs to a MicroVertical. Its [Zerops generator emits a setup for each generated app](https://github.com/BleedingDev/ultramodern.js/blob/b1ec5628d44bb80ef99684b897d5e9a80c014c88/packages/toolkit/create/src/ultramodern-workspace/zerops.ts). Following that contract would create the extra app/service boundary the user rejected.

This is a real disagreement between the framework's opinionated product scaffold and this product's deadline topology. It does not prevent using the forked framework packages in one Modern application.

### Exact scaffold path

Use a minimal pnpm workspace even though there is only one web app. Keeping the app below the repository root avoids an UltraModern TypeScript path-loader defect observed when application-local <code>node_modules</code> sits inside the app directory.

~~~sh
mkdir -p apps
cd apps
pnpm dlx @modern-js/create@3.5.0 radar
cd ..
~~~

At the root:

~~~json
{
  "name": "codebase-radar",
  "private": true,
  "packageManager": "pnpm@11.17.0",
  "scripts": {
    "build": "pnpm --filter @codebase-radar/app build",
    "deploy": "pnpm --filter @codebase-radar/app deploy",
    "start": "node apps/radar/.output/index.js"
  }
}
~~~

~~~yaml
# pnpm-workspace.yaml
packages:
  - apps/*
  - packages/*
~~~

Rename the app package to <code>@codebase-radar/app</code>, replace the relevant <code>@modern-js/*</code> versions with the exact npm aliases above, and add the BFF plugin.

Use Hono function BFF explicitly:

~~~ts
import { appTools, defineConfig } from "@modern-js/app-tools";
import { bffPlugin } from "@modern-js/plugin-bff";

export default defineConfig({
  plugins: [appTools(), bffPlugin()],
  bff: {
    runtimeFramework: "hono"
  }
});
~~~

This explicit setting matters: UltraModern release 100 defaults the BFF runtime framework to Effect unless <code>hono</code> is selected. The file-function API used for health and MCP routes is the Hono lane.

Also include the API tree in <code>apps/radar/tsconfig.json</code>:

~~~json
{
  "include": [
    "src",
    "shared",
    "api",
    "config",
    "modern.config.ts",
    "server"
  ]
}
~~~

Without <code>api</code> in this list, the build reports that TS-Go succeeded but emits an empty <code>.output/api</code>, producing a 404 at runtime. This was reproduced and fixed in the probe.

Build and serve:

~~~sh
pnpm install --frozen-lockfile
pnpm --filter @codebase-radar/app deploy
PORT=3000 node apps/radar/.output/index.js
~~~

Modern.js documents that [modern deploy creates a standalone .output directory](https://modernjs.dev/guides/basic-features/deploy) and that the output starts with Node. Its [web server is Hono-based](https://modernjs.dev/guides/concept/server.html), and its [BFF function convention](https://modernjs.dev/guides/advanced-features/bff/function) maps files under <code>api/lambda</code to routes under the default <code>/api</code prefix.

### Root-app failure to avoid

A standalone app located at repository root failed during <code>modern deploy</code> on both Node 24 and Node 26. The fork's [ts-paths loader](https://github.com/BleedingDev/ultramodern.js/blob/b1ec5628d44bb80ef99684b897d5e9a80c014c88/packages/solutions/app-tools/src/esm/ts-paths-loader.mjs) classified files in root-local <code>node_modules</code> as application files and rewrote a relative dependency load in <code>postcss-flexbugs-fixes</code> to a file URL. The resulting error could not load its <code>./bugs/bug4</code> module.

Putting the app at <code>apps/radar</code> while pnpm keeps the workspace store and virtual modules at the workspace root made the exact UltraModern release build successfully. Do not flatten the app to repository root before this upstream loader behavior is fixed.

## BFF, native responses, and MCP

### BFF routes

The minimum route layout is:

~~~text
apps/radar/api/lambda/health.ts
apps/radar/api/lambda/ready.ts
apps/radar/api/lambda/mcp.ts
~~~

Health is process liveness and must not wait for a scan:

~~~ts
export const get = async () => ({ ok: true });
~~~

Readiness should issue a trivial PostgreSQL query. Use <code>/api/ready</code> for the deployment readiness gate and <code>/api/health</code> for continuous runtime health.

UltraModern's Hono adapter [returns a handler's native Response unchanged](https://github.com/BleedingDev/ultramodern.js/blob/b1ec5628d44bb80ef99684b897d5e9a80c014c88/packages/cli/plugin-bff/src/utils/createHonoRoutes.ts). The probe returned a <code>ReadableStream</code>-backed response in separate chunks, so the framework does not force an MCP SSE response into JSON or buffer it in application code.

### Current Streamable HTTP shape

Use the current [MCP 2026-07-28 Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), not an older design assumption:

- one MCP endpoint accepting POST;
- one JSON-RPC message per POST;
- the response is either one JSON object or request-scoped SSE;
- the 2026-07-28 revision removed the standalone GET stream endpoint and protocol sessions;
- validate <code>Origin</code>, protocol metadata headers, and header/body agreement;
- add <code>X-Accel-Buffering: no</code> when returning SSE.

Pin [@modelcontextprotocol/server 2.0.0](https://www.npmjs.com/package/@modelcontextprotocol/server/v/2.0.0), whose web-standard transport accepts a Fetch <code>Request</code> and returns a Fetch <code>Response</code>. The official [@modelcontextprotocol/hono 2.0.0 adapter](https://www.npmjs.com/package/@modelcontextprotocol/hono/v/2.0.0) demonstrates the integration pattern and, crucially, passing <code>parsedBody</code> when upstream Hono middleware already consumed JSON.

Modern BFF similarly parses a JSON body before calling the file handler. Implement <code>post</code> at <code>/api/mcp</code> with the equivalent pattern:

~~~ts
import { McpServer, WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/server";
import { useHonoContext } from "@modern-js/server-core";

const endpoint = createEndpoint();

async function createEndpoint() {
  const server = new McpServer({
    name: "codebase-radar",
    version: "0.1.0"
  });

  // Register only read-only Scan Result tools here.

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined
  });
  await server.connect(transport);
  return transport;
}

export async function post(input: { data: unknown }) {
  const context = useHonoContext();
  const transport = await endpoint;

  // Reject a present Origin unless it is in the explicit deployment allow-list.
  const response = await transport.handleRequest(context.req.raw, {
    parsedBody: input.data
  });

  if (response.headers.get("content-type")?.includes("text/event-stream")) {
    response.headers.set("x-accel-buffering", "no");
  }
  return response;
}
~~~

Treat this as integration pseudocode until the application types are in place; the SDK owns JSON-RPC/header validation, while the route must add the deployment's Origin policy. Do not put repository secrets or bearer tokens in the route path or query string.

For the eight-hour MVP, read-only tools that return stored Scan Results can usually respond as JSON. Request-scoped SSE is supported by the framework but not required merely to claim Streamable HTTP compliance. After deployment, validate the public proxy path separately with <code>curl -N</code>; the local framework probe cannot prove Zerops balancer flush timing.

## Direct analyzer subprocess design

### One process boundary, no service boundary

The Radar application owns a PostgreSQL-backed queue and runs one in-process async loop:

~~~text
HTTP scan request
    -> INSERT queued Scan Job
    -> return job id immediately

same Radar process
    -> claim one queued job
    -> create temporary workspace
    -> clone one allowed GitHub snapshot
    -> spawn pinned analyzer commands sequentially
    -> normalize/prioritize
    -> store canonical Scan Result in PostgreSQL
    -> delete temporary workspace
~~~

Use one service container for the MVP. On boot, requeue or fail stale <code>running</code> jobs according to a short lease. A PostgreSQL claim such as <code>FOR UPDATE SKIP LOCKED</code> still makes recovery explicit, even though horizontal scale is fixed at one.

### Safe child process contract

Node's official [child_process documentation](https://nodejs.org/api/child_process.html) supports asynchronous <code>spawn</code> with an argument array, <code>cwd</code>, controlled <code>env</code>, <code>signal</code>, <code>timeout</code>, and <code>killSignal</code>. Apply all of these:

- use a fixed map from analyzer ID to an absolute executable path shipped in the deployment;
- pass every option as a separate argument; never concatenate a command string;
- keep <code>shell: false</code>;
- set <code>cwd</code> to the validated per-job repository directory;
- pass an allow-listed environment, not the application's full environment;
- pipe stdout/stderr and stop reading plus terminate when a byte cap is reached;
- abort on deadline, send SIGTERM, then SIGKILL after a short grace period;
- never use <code>exec</code>, <code>execSync</code>, or <code>spawnSync</code> in the HTTP process;
- cap repository size, file count, individual file size, elapsed time, and output size before scoring;
- run analyzers sequentially with global concurrency 1.

Create each workspace with <code>mkdtemp(join(os.tmpdir(), "codebase-radar-"))</code> and validate every derived path remains below it. Remove it in a <code>finally</code> block and sweep stale Radar-prefixed directories on startup. The files are disposable; only PostgreSQL state is durable.

Accept only a parsed GitHub <code>owner/repository</code>, validate both components, and construct the HTTPS URL server-side. Clone one shallow snapshot without submodules:

~~~sh
git -c protocol.file.allow=never +    -c core.hooksPath=/dev/null +    clone --depth=1 --single-branch --no-tags +    https://github.com/OWNER/REPOSITORY.git TARGET
~~~

Set <code>GIT_LFS_SKIP_SMUDGE=1</code>. Do not pass arbitrary clone URLs, follow submodules, install dependencies, or run repository scripts, builds, tests, hooks, or executables.

### Analyzer runtime materialization

Modern's <code>.output</code> dependency pruning cannot discover analyzer CLIs referenced only by string paths. Put all approved, pinned analyzer runtime dependencies in a separate workspace package, for example <code>@codebase-radar/analyzer-runtime</code>, and materialize it during the Zerops build:

~~~sh
pnpm --filter @codebase-radar/app deploy
pnpm --filter @codebase-radar/analyzer-runtime deploy --prod .zerops/analyzer-runtime
~~~

The application then spawns only paths under:

~~~text
/var/www/.zerops/analyzer-runtime/node_modules/.bin/
~~~

Add build-time <code>--version</code> smoke checks for every executable and any separately downloaded TraceDecay binary. Build and run on the same Ubuntu base so native optional dependencies are selected for Linux/glibc, not copied from a developer's macOS store.

This is packaging, not another runtime service.

### Applicability limits

This design bounds accidental resource abuse; it is not adversarial tenant isolation:

- Node can time out a child and cap its output, but it cannot apply a hard per-child cgroup memory/CPU limit by itself.
- A native analyzer can exhaust the app container and cause a restart.
- Temporary storage is local to one runtime container and disappears with it.
- One long scan uses the shared service's CPU, although asynchronous spawn keeps the event loop available.

Those limits are acceptable only for the public-demo boundary: one queued scan, strict repository caps, approved static analyzers, no target execution, and a service resource ceiling. They must be stated in the UI. Production hostile-repository hardening can change the execution substrate later without changing the PostgreSQL job/Scan Result contract. It is explicitly not a reason to add a scan-worker service now.

## PostgreSQL

Zerops currently supports PostgreSQL 18/17/16/14 and documents <code>postgresql:single@18</code> as the development/non-critical topology in its [PostgreSQL overview](https://docs.zerops.io/postgresql/overview). Use:

~~~yaml
- hostname: db
  type: postgresql:single@18
  profile: oltp-staging
~~~

Zerops [generates connection variables](https://docs.zerops.io/postgresql/how-to/connect); another service reads the database's <code>connectionString</code> as <code>db_connectionString</code>. Map it once:

~~~yaml
envVariables:
  DATABASE_URL: ${db_connectionString}
~~~

The internal direct connection uses the private project network on port 5432 without TLS. That is suitable for a long-lived Node connection pool. Port 6432 is TLS-required pgBouncer and is better for high connection churn; it is unnecessary for this one-container, persistent-pool MVP unless the chosen library/workload benefits from transaction pooling.

Persist Audience Profiles, repositories, commit snapshots, jobs, normalized findings, ordered Scan Results, and previous-run comparisons in PostgreSQL. Do not persist cloned source or raw temporary workspaces.

## Zerops configuration

Zerops distinguishes the repository's application pipeline <code>zerops.yaml</code> from the infrastructure import manifest <code>zerops-import.yaml</code>; the [import documentation](https://docs.zerops.io/references/import) warns not to confuse them.

### zerops.yaml

The [official Node pipeline](https://docs.zerops.io/nodejs/how-to/build-pipeline) supports Ubuntu or Alpine, Node 24/22/20/18, build commands, selected deploy files, build caches, runtime ports, health checks, and deployment readiness checks.

Recommended repository-root file:

~~~yaml
zerops:
  - setup: radar
    build:
      os: ubuntu
      base: nodejs@24
      prepareCommands:
        - npm install --global pnpm@11.17.0
      buildCommands:
        - pnpm install --frozen-lockfile --store-dir .pnpm-store
        - pnpm --filter @codebase-radar/app deploy
        - pnpm --filter @codebase-radar/analyzer-runtime deploy --prod .zerops/analyzer-runtime
        - pnpm run verify:runtime-tools
      deployFiles:
        - apps/radar/.output
        - .zerops/analyzer-runtime
      cache:
        - .pnpm-store
        - node_modules
    deploy:
      readinessCheck:
        httpGet:
          port: 3000
          path: /api/ready
    run:
      os: ubuntu
      base: nodejs@24
      ports:
        - port: 3000
          protocol: TCP
          httpSupport: true
      envVariables:
        NODE_ENV: production
        PORT: "3000"
        DATABASE_URL: ${db_connectionString}
        SCAN_CONCURRENCY: "1"
      start: node apps/radar/.output/index.js
      healthCheck:
        httpGet:
          port: 3000
          path: /api/health
~~~

Use <code>ubuntu</code> for both stages because the analyzer toolchain includes native Linux binaries and Ubuntu/glibc is the least surprising common target. Do not install analyzer tools at runtime; ship and smoke-test them in the immutable deploy artifact.

Zerops build commands run from <code>/build/source</code>; selected deploy paths retain their repository-relative layout below <code>/var/www</code>. The start path above therefore matches the deployed path. A build-base, OS, prepare-command, or cache-definition change invalidates the Zerops environment cache. Keep those stable and let pnpm reconcile lockfile changes.

### zerops-import.yaml

~~~yaml
project:
  name: codebase-radar
  description: TraceDecay-powered prioritized code-quality radar
  tags:
    - zerops-challenge

services:
  - hostname: db
    type: postgresql:single@18
    profile: oltp-staging
    priority: 2

  - hostname: radar
    type: nodejs@24
    buildFromGit: https://github.com/BleedingDev/codebase-radar
    zeropsSetup: radar
    enableSubdomainAccess: true
    minContainers: 1
    maxContainers: 1
    priority: 1
~~~

The public Git URL must omit the trailing <code>.git</code> per the current import documentation. The <code>zeropsSetup</code> value and <code>zerops.yaml</code> setup must match. Fixing one container is deliberate: the in-process queue consumer is part of the Radar service and the MVP does not need multi-container coordination or duplicate compute.

Zerops [subdomain access](https://docs.zerops.io/references/networking/public-access) assigns an HTTPS <code>.zerops.app</code> hostname, terminates TLS, and forwards HTTP to the declared port. It is intended for development/demo traffic, has a 50 MB request limit, and must be enabled explicitly. Keep the generated URL live through judging.

### Build and deployment acceptance checks

Before submission:

1. Zerops build log shows the exact UltraModern release and all analyzer <code>--version</code> probes.
2. <code>/api/health</code> is 200 without database or analyzer work.
3. <code>/api/ready</code> is 200 only after a PostgreSQL query succeeds.
4. The public UI loads over HTTPS and can create one bounded scan.
5. Restart Radar while a job is marked running; the lease recovery makes it retry or fail deterministically.
6. Submit one MCP JSON response through the public <code>/api/mcp</code> endpoint.
7. If any MCP tool uses SSE, verify incremental chunks through the public hostname with <code>curl -N</code>.
8. Confirm temporary repository directories disappear after success, failure, timeout, and process restart.
9. Confirm the previous Scan Result remains available after redeploy.

## Challenge eligibility and the “three services” discrepancy

The current canonical [WeMakeDevs challenge page](https://www.wemakedevs.org/hackathons/zerops) says the event runs August 8–9, 2026 and requires a working product deployed on Zerops, reachable through judging, with source available to judges and AI use disclosed. It explicitly says that its illustrated multi-service architecture is not required and “a single container counts.”

The separate [Zerops Launchpad](https://wemakedevs.zerops.io/) says: “No Hello World, aim for at least three services.” “Aim for” is recommendation language, not a minimum, and the canonical rules explicitly allow a single container. Therefore challenge eligibility does **not** mandate three services.

Radar plus managed PostgreSQL already demonstrates meaningful Zerops use: repeatable build/deploy, native runtime packaging, managed persistence, private service networking, environment injection, public TLS routing, health/readiness gates, and persistent availability. Do not invent a third service or split the scanner merely for optics.

## Evidence, inference, and remaining proof

### Directly evidenced

- UltraModern release/version, package engine, generator contract, Zerops generator topology, Hono response passthrough, and default BFF runtime are verified in the fork's release/source.
- Modern's standalone Node deployment and BFF conventions are documented upstream.
- The exact minimal workspace built and served health plus chunked native Response on Node 24.16.0.
- Current MCP transport shape and TypeScript SDK integration are documented by the protocol and official SDK package.
- Zerops Node versions, Ubuntu option, pipeline fields, public access, PostgreSQL service type, environment-variable naming, and health/readiness checks are current official documentation.
- The canonical challenge explicitly permits a single container.

### Inference accepted for the MVP

- <code>/tmp</code> through <code>os.tmpdir()</code> is writable in the Zerops Ubuntu Node runtime. This is a normal Linux runtime property but must be confirmed by the deployment smoke test.
- One async child at a time will preserve enough capacity for the demo UI/API under strict repository and service limits.
- Native analyzer packages selected during an Ubuntu build will execute under the matching Ubuntu runtime when their exact binaries are smoke-tested in the build.

### Not yet proven

- A full analyzer bundle has not yet been built inside Zerops; the analyzer ticket must provide the exact package/binary set.
- Public Zerops proxy flushing for request-scoped SSE has not been measured. JSON MCP responses are sufficient for launch; test <code>curl -N</code> before relying on progress streams.
- No hard hostile-tenant CPU/memory/process isolation exists in this topology.
- The deadline makes PostgreSQL single mode appropriate, not production high availability.

## Immediate implementation recommendations

1. Create the minimal <code>apps/radar</code> pnpm workspace and pin UltraModern <code>3.5.0-ultramodern.100</code>.
2. Set Hono BFF mode and add <code>api</code> to the TypeScript include list before writing routes.
3. Implement health/readiness first; build with Node 24; verify <code>.output</code>.
4. Add the PostgreSQL job lease and a single direct <code>spawn</code> loop in the same application service.
5. Materialize pinned analyzer runtime dependencies into <code>.zerops/analyzer-runtime</code>; do not depend on runtime installation.
6. Implement stateless read-only MCP at <code>/api/mcp</code> using SDK 2.0.0 and the already parsed JSON body.
7. Commit <code>zerops.yaml</code> and <code>zerops-import.yaml</code>, import the two services, enable the generated hostname, and run the acceptance checks above.

This path is decision-complete for the challenge MVP: one application service, one database, direct subprocesses, no scan worker.
