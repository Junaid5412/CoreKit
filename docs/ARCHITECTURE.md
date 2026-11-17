# CoreKit architecture

## One product, three hosts

CoreKit's screens are **web UIs in `ui/`** shared by every platform. Each platform is a
thin *host* that (1) shows those screens in the system web engine and (2) answers the
screens' requests with data collected the platform's own way.

| | Windows | Android | Linux (planned) |
|---|---|---|---|
| Host | Go (`desktop/`) | Kotlin (`android/`) | Go (`desktop/`) |
| Web engine | WebView2 (built into Windows) | Android System WebView | WebKitGTK |
| Health data | PowerShell/CIM (`desktop/scripts/collector.ps1`) | BatteryManager, StatFs, ActivityManager, sensors | /sys, /proc, upower, lsblk/smartctl |
| Network data/fixes | PowerShell (`desktop/scripts/net.ps1`) | ConnectivityManager, WifiManager, LinkProperties | NetworkManager, resolvectl |
| Proxy engine | Xray (downloaded, checksum-verified) | Xray (bundled) | Xray |
| Screen-capture shield | SetWindowDisplayAffinity | FLAG_SECURE | — |

### The contract between UI and host

The UIs never know which platform they run on. They talk to the host through:

* **Health** – `GET api/scan` (Server-Sent Events): `progress`, `log`, `result` events;
  the result JSON schema is the one produced by `collector.ps1` (see `desktop/testdata/sample.json`).
* **Internet** – `GET api/net/scan` (SSE) + `POST api/net/fix` / `GET api/net/fixstatus`
  (schema: `desktop/testdata/net_sample.json`).
* **Browser chrome** – `chrome.webview.postMessage({t: ...})` from the UI and
  `window.__corekit(msg)` / web messages from the host (message list in `desktop/sb_windows.go`
  `onUIMessage`). Android provides the same `chrome.webview` object through a small shim.

Because the contract is identical, **a UI change ships to every platform at once**, and a new
check only needs its collector written per platform, returning the same JSON fields.

## Versions and releases

`VERSION` is the only version number. The pipeline stamps it into the Windows exe
(resources + `main.appVersion`) and the Android app (`versionName`), then publishes
`v<VERSION>` with every platform's file. Bump `VERSION` for a new release; pushes without a
bump refresh the current release.

## Security rules

* No credentials in the repository. Proxy links are entered in the app and stored encrypted
  (Windows DPAPI / Android Keystore).
* With a proxy on, the browser fails closed: local DNS disabled, WebRTC restricted, pages hidden
  until the in-engine leak checks pass.
