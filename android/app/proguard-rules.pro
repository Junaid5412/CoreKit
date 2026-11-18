# CoreKit: R8 shrinks the AndroidX libraries only. App code is kept whole (names unchanged),
# so the WebView bridge, services and activities behave exactly as before.
-keep class com.corekit.app.** { *; }
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}
-keepattributes *Annotation*,JavascriptInterface,SourceFile,LineNumberTable
