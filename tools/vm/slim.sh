#!/bin/bash
# Builds a slim Android-x86 image for CoreKit's Virtual Environment from an official ISO.
# Usage: slim.sh <official.iso> <out.iso>     (needs: bsdtar squashfs-tools e2fsprogs xorriso, sudo)
set -euo pipefail
ISO=$1; OUT=$2; W=$(mktemp -d)
mkdir -p "$W/iso" "$W/new"
bsdtar -xf "$ISO" -C "$W/iso" kernel initrd.img ramdisk.img system.sfs
unsquashfs -s "$W/iso/system.sfs" | head -8
unsquashfs -q -d "$W/sq" "$W/iso/system.sfs"
ls -la "$W/sq"
IMG="$W/sq/system.img"; [ -f "$IMG" ] || IMG=$(ls "$W"/sq/*.img | head -1)
M=$W/mnt; mkdir -p "$M"; sudo mount -o loop "$IMG" "$M"
S=$M; [ -d "$M/system/app" ] && S=$M/system
echo "== size before"; sudo du -sh "$M"
sudo du -sh "$S"/* 2>/dev/null | sort -h | tail -15
echo "== apps"; sudo du -s "$S"/app/* "$S"/priv-app/* 2>/dev/null | sort -n | tail -70
echo "== lib dirs"; sudo du -sh "$S"/lib/* "$S"/lib64/* 2>/dev/null | sort -h | tail -20
echo "== fonts"; sudo du -sh "$S"/fonts; echo "== media"; sudo du -sh "$S"/media/* 2>/dev/null
if [ -n "${TEST_APK:-}" ]; then f=$(sudo find "$S/app" -iname '*calculator*.apk' | head -1); [ -n "$f" ] && sudo cp "$f" "$TEST_APK" && sudo chmod 644 "$TEST_APK"; fi
# ---- remove what a headless virtual phone never uses
RM_APPS="BasicDreams Browser2 Calendar Camera2 Email Exchange2 Gallery2 Music MusicFX PhotoTable QuickSearchBox
 RSSReader NotePad LiveWallpapers LiveWallpapersPicker Galaxy4 HoloSpiralWallpaper MagicSmokeWallpapers NoiseField
 PhaseBeam VisualizationWallpapers Development DeskClock Calculator Messaging Dialer Contacts Eleven Recorder
 SoundRecorder Terminal TimeZoneUpdater WallpaperBackup WallpaperCropper ThemePicker Camera CtsShimPrebuilt
 CtsShimPrivPrebuilt EasterEgg Stk BookmarkProvider PartnerBookmarksProvider BluetoothMidiService Bluetooth
 BuiltInPrintService Traceur HTMLViewer Email2 FMRadio Gallery Gallery3D SpeechRecorder CaptivePortalLogin
 OneTimeInitializer StorageManager EmergencyInfo
 Taskbar PicoTts Chrome Velvet Gmail2 TermOnePlus Eleven Traceur GoogleFeedback GooglePartnerSetup
 AnalyticsService GoogleRestore SetupWizard WallpaperPicker SettingsIntelligence"
for a in $RM_APPS; do sudo rm -rf "$S/app/$a" "$S/priv-app/$a"; done
sudo rm -rf "$S"/lib/firmware "$S"/vendor/firmware "$M"/vendor/firmware 2>/dev/null || true
for d in media bluetooth staging gpu/drm/amd gpu/drm/radeon gpu/drm/nouveau gpu/drm/i915 sound usb/serial infiniband isdn; do
  sudo find "$S"/lib/modules "$M"/vendor/lib/modules 2>/dev/null -path "*kernel/drivers/$d/*" -name '*.ko' -delete || true
done
sudo find "$S"/lib/modules -path "*kernel/sound/*" -name '*.ko' -delete 2>/dev/null || true
sudo rm -rf "$S"/media/audio "$S"/media/bootanimation.zip "$S"/media/*.mp4 2>/dev/null || true
sudo rm -f "$S"/fonts/NotoSansCJK* "$S"/fonts/NotoSerifCJK* 2>/dev/null || true
# wireless drivers aren't needed, except virt_wifi: Android-x86 shows the network as Wi-Fi through it
sudo find "$S"/lib/modules -path "*kernel/drivers/net/wireless/*" -name '*.ko' ! -name 'virt_wifi.ko' ! -name 'mac80211_hwsim.ko' -delete 2>/dev/null || true
echo "== enable_nativebridge"; sudo cat "$S"/bin/enable_nativebridge 2>/dev/null | head -80 || true
echo "== size after"; sudo du -sh "$M"
# free blocks still hold the deleted files: punch them out so they compress to nothing
sudo fstrim -v "$M" || true
sudo umount "$M"
e2fsck -fy "$IMG" >/dev/null || true
ls -las "$IMG"
COMP=${SQ_COMP:-$(unsquashfs -s "$W/iso/system.sfs" | sed -n 's/^Compression //p')}; COMP=${COMP:-gzip}
mksquashfs "$IMG" "$W/new/system.sfs" -comp "$COMP" $( [ "$COMP" = xz ] && echo -b 1M -Xdict-size 100% ) -noappend -no-progress >/dev/null
cp "$W/iso/kernel" "$W/iso/initrd.img" "$W/iso/ramdisk.img" "$W/new/"
xorriso -as mkisofs -quiet -o "$OUT" -V ANDROID_CK -J -R "$W/new"
ls -la "$W/new" "$OUT"; sha256sum "$OUT"
sudo rm -rf "$W"
