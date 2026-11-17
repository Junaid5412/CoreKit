# CoreKit

A professional toolkit for checking and securing a computer or phone — one codebase,
released for **Windows**, **Android** and **Linux** together.

| Module | What it does |
|---|---|
| **Health Inspector** | Full hardware scan (battery, storage, memory, CPU/GPU, display…) with health scores — ideal before buying a used laptop or phone. |
| **Internet Troubleshooter** | Finds Wi-Fi, DNS, HTTPS/certificate, clock and proxy problems, fixes them in one click, runs a speed test. |
| **Safe Browser** | Its own browser: left-side vertical tabs, profiles, proxy/VPN (VLESS Reality, VMess, Trojan, Shadowsocks, SOCKS5, HTTP), leak-checked before any page opens, time zone matched to the proxy, translation, history, hidden from screen capture, leave-no-trace mode. |

## Download

Every push to `main` builds all platforms from the same commit and publishes them as
**Releases → v&lt;VERSION&gt;** (`CoreKit.exe`, `CoreKit.apk`).

## Layout

```
VERSION            single version number for every platform
ui/                shared web interface (same screens on all platforms)
desktop/           Windows (and later Linux) app in Go — terminal menu + modules
android/           Android app (Kotlin) — hosts the same ui/ screens
docs/              architecture and conventions
.github/workflows/ one pipeline that builds and releases all platforms
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Build locally

```
./build.sh                       # Windows exe + all Go tests  -> dist/
cd android && gradle assembleRelease   # Android APK (needs Android SDK)
```
