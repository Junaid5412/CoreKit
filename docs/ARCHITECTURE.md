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
| Security scan/fixes | PowerShell (`security.ps1`, `security_fix.ps1`) + Go rules (`sec_rules.go`) | PackageManager, AppOps, Settings.Secure, DevicePolicyManager (`SecurityScanner.kt`) | /proc, systemd units, cron (planned) |
| Proxy engine | Xray (downloaded, checksum-verified) | Xray (bundled) | Xray |
| Screen-capture shield | SetWindowDisplayAffinity | FLAG_SECURE | — |

### Shared Go code on Android

Android runs the same Go code as Windows for proxy links, Xray configuration, the tunnel
check, proxy-location lookup, translation and Google-in-your-language: `desktop/` is also
built for `android/arm64` and shipped as `libcorekit.so`; the app calls
`libcorekit.so --helper <command>` with JSON on stdin (see `desktop/helper.go`). The official
Xray Android build is shipped as `libxray.so` (checksum-verified in the pipeline).

### The contract between UI and host

The UIs never know which platform they run on. They talk to the host through:

* **Health** – `GET api/scan` (Server-Sent Events): `progress`, `log`, `result` events;
  the result JSON schema is the one produced by `collector.ps1` (see `desktop/testdata/sample.json`).
* **Internet** – `GET api/net/scan` (SSE) + `POST api/net/fix` / `GET api/net/fixstatus`
  (schema: `desktop/testdata/net_sample.json`).
* **Browser chrome** – `chrome.webview.postMessage({t: ...})` from the UI and
  `window.__corekit(msg)` / web messages from the host (message list in `desktop/sb_windows.go`
  `onUIMessage`). Android provides the same `chrome.webview` object through a small shim.

* **Security** – `GET api/sec/scan` (SSE): `progress`, `done` (result) or `fail`. Other calls use
  the same paths on both platforms: Windows answers `api/sec/<path>` (POST JSON), Android answers
  `CoreKitNative.secCall(id, path, body)` and replies through `window.__secReply(id, json)`.
  Paths: `fix {id, action}`, `fixall {ids}`, `history`, `undo {id}`, `restore {id}`, `qdelete {id}`,
  `settings` (GET; POST `{key}` / `{untrust:[]}`), `shield {on}`, `harden {ids}`, `asr`, `bloat {id}`,
  `protstatus {ids}` (reads the real state of each protection), `inspect {id}` (reverse view of the
  file), `trace {id}` (public DNS/RDAP records for the servers found), `second {id}`, `app {id}` (Windows: uninstall from All apps) / `app {pkg, action}` (Android),
  `installed {pkg, id, name}` (Android: checks the app is gone after Android's uninstall prompt),
  `open {what}` (Android settings screens). Android needs REQUEST_DELETE_PACKAGES for the prompt.
  Result schema (`desktop/sec_rules.go` `secResult`, Android `SecurityScanner.kt`):
  `platform, t, host, os, admin, score (0-100, higher is safer), verdict (clean|attention|danger),
  counts{high,med,low,info}, scanned{processes,autoruns,files,connections,apps,lookups},
  protection[{id,name,state(on|off|warn|unknown),detail,fix}],
  findings[{id,kind(process|autorun|file|setting|threat|app),sev(high|med|low|info),score,title,sub,summary,
  reasons[{t,w}],path,sha256,size,signer,signed,company,origin{by,user,how,url,ref,zone,via,text},inner,
  chain[{pid,name,path,cmd,t,sig}],persist[{kind,where,value}],net[{remote,port,state}],first,last,
  intel[{source,verdict,family,tags,link,first}],actions[{id,label,main}],advice,mitre[],pids[],pkg}],
  bloat[{id,name,publisher,kind,rating(remove|optional|keep),why,size,action,on}],
  apps[{id,name,pkg,publisher,kind(program|store|user|system),source,side,version,size,first,last,sev,score,fid,rating,flags[],canRemove,enabled}],
  notes[], intel, ms`.
  `harden {ids}` replies `{msg, note, items:[{id,name,ok,state(on|off|partial|unknown),detail,err,on,of}]}`:
  each item is applied on its own and then READ BACK from Windows, so `ok` means Windows confirmed it.
  Actions: `quarantine` (restorable), `delete` ("Delete it myself": stops it, removes it, no undo; a
  threat found inside an archive deletes the archive), `defender`, `kill`, `remove`, `trust`.
  `inspect` replies `{exists,kind,kindText,size,md5,sha1,sha256,created,modified,source[{k,v,link}],
  creator[{k,v}],contents[{name,size,flag}],servers[{host,kind,count,why,sev,urls,link}],
  caps[{t,why,ev,sev}],bad[],notes[],risk,summary}`; `trace` replies `{items:[{host,ips,owner,country,
  registrar,created,ageDays,note,sev}]}`. Both come from the shared Go code (`sec_inspect.go`,
  `sec_trace.go`); on Android the same code runs as `libcorekit.so --helper inspect|trace`.
  History is stored as one file per record under `<secdir>/history/`, and settings are re-read when they change on disk, so the app and the Live Shield (separate processes) never overwrite each other's history or miss a newly trusted file. Windows collects with `desktop/scripts/security.ps1` and fixes with `security_fix.ps1` (everything
  removed is backed up for undo); Live Shield is `CoreKit.exe --shield`, started at sign-in by Task
  Scheduler from `Program Files\CoreKit`. Android's Live Shield is a periodic JobScheduler check of
  changed packages (`SecurityJob`).

* **Remote Access** – one Go engine on both platforms (Android runs it inside `libcorekit.so`).
  State: `{t:"state", me, hosting, code, stage, session:{role, peer, since, w, h, ctl, quality,
  tx, rx, capErr}}` (`tx`/`rx` = screen pictures sent/received, `capErr` = why the screen can't
  be captured). Frames: `{t:"frame", w, h, seq, d}` (`d` = base64 JPEG). `events?lite=1` leaves
  out `d`; the page then loads the picture from `remote/frame.jpg` (Android, served from the
  engine's `lastframe`), and falls back to full frames if that fails. Viewer input `{t:"in", k:"lock"}` locks the PC (LockWorkStation — Win+L cannot be injected); `k:"lock", curtain:true` / `k:"unlock"` show and lift CoreKit's full-screen lock curtain, which also lifts itself when the session ends. On Android the screen is captured only once a device connects (no recording indicator while merely waiting).

* **Storage & Performance** – drives and where space goes, every installed program/app (size,
  source, bloat), reclaimable junk (caches, temp, Recycle Bin, hibernation file, Windows.old, old
  downloads) and plain recommendations. Routes `storage/scan` (SSE), `storage/clean {ids,pick}`,
  `storage/uninstall {ids}`, `storage/drill {path}`. Result shape in `desktop/storage.go`
  (`stResult`); Windows collects in `storage_windows.go` (+ `scripts/storage.ps1`), Android in
  `StorageScanner.kt`, both producing the same JSON for the one `storage.html`. Every drive is
  measured top-level folder by folder (parallel, per-folder limits) so the "where did it go" bar
  adds up; programs with no recorded size are measured from their folder. Fields beyond the
  basics: `clean[].group` (Browsers | Windows | Apps | Your files), `big[].mod` and `big[].kind`
  (`folder|file|app`), `apps[].approx` (size is only the package size), and `needs: ["usage"]`
  (Android: the page offers to open Usage access, which unlocks exact app sizes, photo/video/audio
  totals and last-used dates; no media permissions are requested). Routes `storage/usage` and
  `storage/freeup` (Android only) open the matching system screens. Downloads deletes are
  restricted to paths inside the Downloads folder on both platforms. The remote "wants to connect"
  notification buttons go through `AskReceiver` (a broadcast), not the service.

* **Virtual Environment** – not part of CoreKit. Its code (engine, page, image tools and
  workflows) is kept on the `virtual-environment` branch for a separate app.

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
