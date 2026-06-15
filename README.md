# sandbox

`github.com/strongo/sandbox` runs a command in a hardened, single-use Docker
sandbox: inject inputs, run the command to completion under resource and
timeout limits, collect output artifacts, then always tear the container down.

The hardened container profile (read-only rootfs, `CAP_DROP=ALL`, non-root
user, no-new-privileges, default seccomp, init) is applied unconditionally via
the `isolation` subpackage and cannot be weakened through the public API. Only
the tunable knobs (CPU / memory / PID caps, network, timeout) are exposed.

<!-- dev-approach:v1 -->
## Our approach to development

We build with our own tooling:

- **[SpecScore](https://specscore.md)** — specify requirements as `SpecScore.md` artifacts
- **[SpecStudio](https://specscore.studio)** — author & manage specs across their lifecycle
- **[inGitDB](https://ingitdb.com)** — store structured data in Git where applicable
- **[DALgo](https://dalgo.io)** — data access layer for Go
- **[cover100.dev](https://cover100.dev)** — drive toward 100% test coverage
- **[DataTug](https://datatug.io)** — query & explore data
<!-- /dev-approach -->

## Packages

- `github.com/strongo/sandbox` — `RunOnce`, `Job`, `Limits`, `Mount`, `Result`.
- `github.com/strongo/sandbox/isolation` — the shared hardened Docker preset
  (`Preset`, `NonRootUser`, …).

## Testing

`go test ./...` runs the unit tests and never requires a Docker daemon. The
Docker integration test is env-guarded: it is skipped under `go test -short`
and unless `SANDBOX_INTEGRATION=1` is set.

```sh
SANDBOX_INTEGRATION=1 go test -run Integration ./...
```

## License

Apache License 2.0. Copyright 2026 Sneat.co. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
