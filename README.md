# RustScope

RustScope checks approved web resources and release dependencies, then shows what it found, what changed, and which fixes it could verify.

## Quick start

With Docker running, open a terminal in this repository and start RustScope.

```sh
docker compose up --build -d
```

1. Open [localhost:3100](http://localhost:3100) and select **Create account**. Choose your own username and a password of at least 12 characters.
2. Create an **Offline demo** project, enter a release name, and select **Start scan**. The report opens automatically and refreshes while the scan runs.

The demo uses built-in evidence and needs no target website. To see how a finding changes across releases, run all four **Demo evidence** options in order in the same project.

Use `docker compose logs -f` to follow the logs and `docker compose down` to stop the app. Your accounts and reports stay in the Docker volume.

## Sample reports

[403 response](examples/reports/forbidden.pdf) shows why a finding stays open when the evidence is unavailable. [Verified fix](examples/reports/fixed.pdf) shows the evidence that closed it. Use **Print / Save PDF** from a report to export your own.

## Project docs

- [Assessment guide](docs/assessment.md) covers live scans, evidence review, and collection limits.
- [Development guide](docs/development.md) covers local builds, testing, and Docker image publishing.
- [DESIGN.md](DESIGN.md) describes the interface and its design reference.
