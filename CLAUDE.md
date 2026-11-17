# CoreKit — working rules

- **Every feature goes to every platform.** Change the shared screen in `ui/` once; add the
  platform collectors/handlers in `desktop/` (Windows; Linux later) **and** `android/` in the same
  change, keeping the JSON fields in docs/ARCHITECTURE.md identical.
- After editing `ui/health.html` or `ui/src/net.src.html` run `python3 ui/src/build_assets.py`
  (the pipeline fails if `ui/net.html` is stale).
- Run `./build.sh` before pushing (gofmt, vet, tests, Windows build).
- Bump `VERSION` for a release; the pipeline publishes all platforms as `v<VERSION>`.
- Never commit secrets, proxy links, keystores or built binaries. Tests use dummy links only.
- Windows COM/WebView2 code: `go vet -unsafeptr=false` (vtable calls are intentional).
- Keep user-facing text short, plain English.
