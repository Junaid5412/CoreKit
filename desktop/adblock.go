package main

// Ad and tracker blocking shared by every platform. Requests to these domains (and their
// subdomains) are refused: on Android in the page loader, on Windows by the web engine's
// resolver (direct) or by the Xray tunnel (proxy on).

import "strings"

var adDomains = []string{
	// Google ads / tracking
	"doubleclick.net", "googlesyndication.com", "googleadservices.com", "googletagservices.com", "adservice.google.com",
	"pagead2.googlesyndication.com", "google-analytics.com", "googletagmanager.com", "app-measurement.com", "imasdk.googleapis.com",
	// ad exchanges / networks
	"adnxs.com", "adsrvr.org", "amazon-adsystem.com", "criteo.com", "criteo.net", "pubmatic.com", "rubiconproject.com",
	"openx.net", "casalemedia.com", "indexww.com", "smartadserver.com", "adform.net", "yieldmo.com", "sharethrough.com",
	"teads.tv", "triplelift.com", "33across.com", "3lift.com", "bidswitch.net", "contextweb.com", "gumgum.com", "media.net",
	"advertising.com", "adtechus.com", "yahoo-ads.com", "ads.yahoo.com", "adblade.com", "revcontent.com", "mgid.com",
	"taboola.com", "outbrain.com", "zemanta.com", "propellerads.com", "popads.net", "popcash.net", "exoclick.com",
	"exosrv.com", "juicyads.com", "trafficjunky.net", "adcash.com", "adsterra.com", "hilltopads.net", "clickadu.com",
	"admaven.com", "ad-maven.com", "a-ads.com", "bidvertiser.com", "infolinks.com", "zedo.com", "adroll.com", "quantcast.com",
	"quantserve.com", "scorecardresearch.com", "moatads.com", "moat.com", "doubleverify.com", "adsafeprotected.com",
	"serving-sys.com", "flashtalking.com", "innovid.com", "spotxchange.com", "spotx.tv", "springserve.com", "lijit.com",
	"sovrn.com", "districtm.io", "emxdgt.com", "onetag-sys.com", "seedtag.com", "adkernel.com", "smaato.net", "inmobi.com",
	"applovin.com", "unityads.unity3d.com", "chartboost.com", "vungle.com", "adcolony.com", "ironsrc.com", "startapp.com",
	// social / analytics trackers
	"connect.facebook.net", "pixel.facebook.com", "ads-twitter.com", "static.ads-twitter.com", "analytics.twitter.com",
	"ads.linkedin.com", "px.ads.linkedin.com", "snap.licdn.com", "analytics.tiktok.com", "ads.tiktok.com", "bat.bing.com",
	"clarity.ms", "hotjar.com", "hotjar.io", "mouseflow.com", "fullstory.com", "crazyegg.com", "luckyorange.com",
	"mixpanel.com", "segment.io", "segment.com", "amplitude.com", "heap.io", "branch.io", "app.link", "adjust.com",
	"appsflyer.com", "kochava.com", "newrelic.com", "nr-data.net", "chartbeat.com", "chartbeat.net", "parsely.com",
	"comscore.com", "nielsen.com", "imrworldwide.com", "krxd.net", "bluekai.com", "demdex.net", "omtrdc.net",
	"everesttech.net", "rlcdn.com", "agkn.com", "tapad.com", "liveramp.com", "id5-sync.com", "adsymptotic.com",
	"onesignal.com", "pushwoosh.com", "pushcrew.com", "notix.io",
	// pop-ups / scams / crypto miners
	"coinhive.com", "coin-hive.com", "jsecoin.com", "cryptoloot.pro", "webminepool.com",
}

var adSet = func() map[string]bool {
	m := map[string]bool{}
	for _, d := range adDomains {
		m[d] = true
	}
	return m
}()

// isAdHost reports whether host is an ad/tracker domain or a subdomain of one.
func isAdHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	for {
		if adSet[h] {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return false
		}
		h = h[i+1:]
	}
}

// adResolverRules blocks ad domains in the web engine (used when no proxy is on).
func adResolverRules() []string {
	out := make([]string, 0, len(adDomains)*2)
	for _, d := range adDomains {
		out = append(out, "MAP "+d+" ~NOTFOUND", "MAP *."+d+" ~NOTFOUND")
	}
	return out
}

// adCosmeticScript hides the empty boxes left where ads would have been.
const adCosmeticScript = `(()=>{const css='ins.adsbygoogle,[id^="google_ads_"],[id^="div-gpt-ad"],[data-ad-slot],[data-ad-unit],[data-google-query-id],iframe[src*="doubleclick.net"],iframe[src*="googlesyndication"],iframe[id^="google_ads_iframe"],.ad-container,.ad-slot,.adsbox,.advert,.advertisement,[class*="taboola"],[id*="taboola"],[class*="outbrain"],.OUTBRAIN,[aria-label="Advertisement"]{display:none!important}';const add=()=>{if(document.getElementById('ck-ab'))return;const s=document.createElement('style');s.id='ck-ab';s.textContent=css;(document.head||document.documentElement).appendChild(s)};if(document.documentElement)add();document.addEventListener('DOMContentLoaded',add)})();`

// ---------------------------------------------------------------- language of the VPN country

// countryLang is the main language of a country (for "match language to the VPN country").
var countryLang = map[string]string{
	"DE": "de-DE", "AT": "de-AT", "CH": "de-CH", "FR": "fr-FR", "BE": "nl-BE", "NL": "nl-NL", "LU": "fr-LU", "GB": "en-GB",
	"IE": "en-IE", "US": "en-US", "CA": "en-CA", "AU": "en-AU", "NZ": "en-NZ", "ES": "es-ES", "MX": "es-MX", "AR": "es-AR",
	"IT": "it-IT", "PT": "pt-PT", "BR": "pt-BR", "PL": "pl-PL", "CZ": "cs-CZ", "SK": "sk-SK", "HU": "hu-HU", "RO": "ro-RO",
	"BG": "bg-BG", "GR": "el-GR", "SE": "sv-SE", "NO": "nb-NO", "DK": "da-DK", "FI": "fi-FI", "EE": "et-EE", "LV": "lv-LV",
	"LT": "lt-LT", "UA": "uk-UA", "RU": "ru-RU", "TR": "tr-TR", "IL": "he-IL", "AE": "ar-AE", "QA": "ar-QA", "SA": "ar-SA",
	"KW": "ar-KW", "BH": "ar-BH", "OM": "ar-OM", "EG": "ar-EG", "PK": "ur-PK", "IN": "en-IN", "BD": "bn-BD", "SG": "en-SG",
	"MY": "ms-MY", "ID": "id-ID", "TH": "th-TH", "VN": "vi-VN", "PH": "en-PH", "JP": "ja-JP", "KR": "ko-KR", "CN": "zh-CN",
	"HK": "zh-HK", "TW": "zh-TW", "ZA": "en-ZA", "NG": "en-NG", "KE": "en-KE",
}

// langMatchScript makes navigator.language(s) start with the VPN country's language while
// keeping English, so "language differs from your IP" checks pass and pages stay readable.
func langMatchScript(country string) string {
	l := countryLang[strings.ToUpper(country)]
	if l == "" {
		return ""
	}
	list := []string{l, strings.SplitN(l, "-", 2)[0]}
	if !strings.HasPrefix(l, "en") {
		list = append(list, "en-US", "en")
	}
	js := `["` + strings.Join(list, `","`) + `"]`
	return `(()=>{try{const L=Object.freeze(` + js + `);Object.defineProperty(Navigator.prototype,'language',{get:()=>L[0],configurable:true});Object.defineProperty(Navigator.prototype,'languages',{get:()=>L,configurable:true})}catch(e){}})();`
}
