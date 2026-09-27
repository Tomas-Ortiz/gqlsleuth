# Local SAFE demonstration

Run this helper from a source checkout after the [development install](../CONTRIBUTING.md).
It is not a new installed CLI command and requires no development-only Python packages beyond
the project's runtime dependencies.

```bash
uv run python examples/local_demo.py
uv run python examples/local_demo.py --output ./reports/local-demo
uv run python examples/local_demo.py --verbose
```

Each run starts a temporary GraphQL fixture on **127.0.0.1 with an automatically assigned port**,
runs the normal SAFE CLI scan, then stops the server. The fixture has fake album/user IDs and a
small recursive schema. It reuses existing test infrastructure; no real credentials, external
service, Ollama or ACTIVE confirmation is needed. A process-local guard rejects non-loopback
connections and external DNS lookup attempts. There is no configurable host or target option.

Expect one successful Query from four local HTTP requests (discovery, two introspection requests,
and execution). Schema-based object-lookup/recursive-graph review candidates may appear; these
are manual-review prompts, not Findings. The schema also declares a Mutation so the scan can
demonstrate visibility without executing it. **Zero Mutations execute.**

`--output` creates an HTML report in the supplied directory and prints its path. Open that file
directly in a browser; it needs no CDN or service. Repeated runs get new filenames rather than
silently overwriting files. Without `--output`, no report is written. Report generation adds
zero requests. `--verbose` shows the technical detail behind the compact assessment.

This is a small read-only onboarding fixture, not an intentionally vulnerable application.
Use [README.md](../README.md) for real authorized assessments. Real scan reports, unlike this
fake demonstration, may contain sensitive application data and must be stored appropriately.
