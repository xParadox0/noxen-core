# Noxen Studio (early foundation)

This repository holds the first working pieces of Noxen Studio, a project that is still at the start. There is no application yet. What is here is small, tested and runs on its own.

## What is in it

- `internal/redact` is a Go library that finds and masks secrets and personal identifiers in text before the text is stored or shown. It has its own tests and a canary test that proves a planted value never survives.
- `tests/support/canary` creates the synthetic canary values those tests use and keeps their registry.
- `tools/commitcheck` checks that commit messages follow a test-first rule (a failing-test commit comes before the commit that fixes it). `.githooks/commit-msg` runs it.
- `tools/depscan` reads the output of `govulncheck` and `pnpm audit` and fails when a finding is not covered.
- `tools/redreplay` replays a recorded failing run against the code to show that a test fails for the stated reason.

## Run it

You need Go 1.27.

```
make check      # go vet and all tests, no network
make vuln-scan  # needs govulncheck and the network
make hooks-install   # use the commit-message hook
```

## Status

This is a prototype of the foundations, not a product. The planning material, the research notes and the review records are not part of this repository.

## License

MIT, see `LICENSE`.
