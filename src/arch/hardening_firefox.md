# Hardening Firefox on Arch

### Fingerprinting

Browser fingerprinting is a tracking technique, often done by third-party
companies that specialize in it. They provide code (usually JavaScript) that a
website owner can embed on their site. When you visit the site, the script runs
in the background, silently collecting data about your device and browser.

The most concerning aspect of browser fingerprinting is that it operates
silently and without user consent. It's not something you can easily see or
something like cookies that you can opt-out or delete. Browser fingerprinting is
stateless meaning that it doesn't need to store any data on your computer. It
can identify you while behind a VPN or in incognito mode as well.

I will go over some of the settings and what they do. If you plan on using the
Arkenfox `user.js` you can jump to that section first as it will set many of
these settings for you.

---

#### Enhanced Tracking Protection (ETP)

- [Enhanced Tracking Protection (ETP)](https://blog.mozilla.org/security/2020/01/07/firefox-72-fingerprinting/)
  blocks known "third-party requests" to companies that participate in
  fingerprinting, according to the
  [Disconnect List](https://disconnect.me/trackerprotection)
  - In `about:preferences#privacy`, setting Enhanced Tracking Protection to
    either Strict or Custom enables FPP as well explained further down.

- [First-Party Isolation](https://wiki.mozilla.org/Security/FirstPartyIsolation)
  From the Tor Uplift Project.

- [Fingerprinting](https://wiki.mozilla.org/Security/Fingerprinting)

- RFP (Resist Fingerprinting) set in `about:config` with
  `privacy.resistFingerprinting`. Resist Fingerprinting alters the following:
  - The timezone is reported as UTC or Icelandic

  - Locale is reported as en-US

  - Several properties of the navigator object are fixed, including the hardware
    concurrency value, application version and build ID. The User Agent version
    is reported to be the major version (for example, 119.0 instead of 119.1)
    - And much more...

  - You can set `privacy.resistFingerprinting.pbMode` (private-browsing) without
    `privacy.resistFingerprinting` and still get certain Resist Fingerprinting
    behaviors on normal windows, because it's impossible to separate these
    behaviors per-window.

- FPP (Fingerprinting Protection) is enabled in normal browsing when Enhanced
  Tracking Protection is set to Strict. Both Known Fingerprinters and Suspected
  Fingerprinters Protection are enabled in Private Browsing and when ETP is set
  to strict. On the Custom level of ETP you can toggle on/off different
  features.

---

## WebRTC

The main reason people disable WebRTC is to prevent an IP address leak. WebRTC
is designed for real-time communication like video calls and file sharing. If
you don't use those features, it makes sense to disable it.

In `about:preferences#privacy` -> `Privacy & Security` -> `Permissions`. Click
`Settings`.

- [x] Block new requests asking to access your microphone

- [x] Block new requests asking to access your camera

- You may also want to block Location, but that isn't involving WebRTC.

You can also use the master switch by going to `about:config` and setting
`media.peerconnection.enabled` to `false`

---

## Canvas Fingerprinting

Canvas Fingerprinting uses the HTML5 `<canvas>` element to generate a
fingerprint. It gets your device to render an image or text on a canvas and then
reads the pixel data. Since devices render things differently, those differences
are identifiable.

When you set `privacy.resistFingerprinting` it modifies both Canvas and WebGL
behavior to make their outputs non-unique.

## WebGL

Similar to canvas fingerprinting, this technique uses the WebGL API to render 2D
and 3D graphics. The way your system renders these graphics provides information
about your GPU and graphics drivers, which contributes to your unique
fingerprint.

> ❗️ NOTE: It's unnecessary to disable webgl if you're already using RFP and
> will likely make you stand out more because most people don't disable it.

It can be disabled in `about:config` by setting `webgl.disabled` to `true`.

## Install Firefox/LibreWolf & ArkenFox

<details>
<summary> ✔️ Click to Expand Arkenfox How To </summary>

The process is the same for both Firefox & LibreWolf. I like LibreWolf for it's
strong defaults but may lag behind Firefox getting security patches.

```bash
paru -S librewolf-bin
sudo pacman -S firefox
```

Read the [ArkenFox Wiki](https://github.com/arkenfox/user.js/wiki)

## Apply

Open `about:support` and look for `Profile Folder` under `Application Basics` It
will bring you to somewhere like `~/.librewolf/pefoo8xx.default-default/` and
that is where you place the `user.js`.

Place the following files in your `Profile Folder`:

- [Arkenfox user.js](https://github.com/arkenfox/user.js/blob/master/user.js)
  Read through the `user.js`, not all settings are applied by default such as
  RFP Fingerprinting protection.

- [updater.sh](https://github.com/arkenfox/user.js/blob/master/updater.sh)

- [prefsCleaner.sh](https://github.com/arkenfox/user.js/blob/master/prefsCleaner.sh)

- Also create your own `user-overrides.js` with any changes you want to make to
  the default `user.js`. These changes are amended to the `user.js` and applied
  last enabling them to override the default settings. It's best to make changes
  here so that updating the Arkenfox `user.js` doesn't make you lose all of your
  customizations.

Example `user-overrides.js` spoofing the user agent:

> ❗️ This is just an example, always check for common useragent strings
> yourself.

```js
user_pref(
  "general.useragent.override",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
);
// Disable Activity Stream on new windows and tab pages
user_pref("browser.newtab.preload", false);
// Enhanced Tracking Protection (ETP)
user_pref("privacy.bounceTrackingProtection.mode", 1); // [FF131+] [ETP FF133+]
user_pref("privacy.trackingprotection.enabled", true);
// Resist Fingerprinting (RFP)
user_pref("privacy.resistFingerprinting", false); // [FF41+]
user_pref("privacy.resistFingerprinting.pbmode", false); // [FF114+]
// WebRTC
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.default_address_only", true);
// WebGL
user_pref("webgl.disabled", false);
// Geolocation
user_pref("geo.enabled", false);
user_pref("full-screen-api.enabled", false);
user_pref(
  "geo.provider.network.url",
  "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%",
);
// Disable studies
user_pref("app.sheild.optoutstudies.enabled", false);
// Master Switches, Be Careful
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.google.gethashURL", "");
user_pref("browser.safebrowsing.provider.google.updateURL", "");
user_pref("browser.safebrowsing.provider.google4.dataSharingURL", "");
user_pref("signon.rememberSignons", false);
user_pref("browser.xul.error_pages.expert_bad_cert", true);
//* [NOTE] Will cause breakage: older modems/routers and some sites e.g banks, vimeo, icloud, instagram ***/
user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.sendRefererHeader", 1);
// 0 is most strict:
user_pref("network.http.referer.trimmingPolicy", 0);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);
```

To apply your prefs you have to run the `updater.sh` script.

```bash
~/.mozilla/firefox/v5kwl3c0.default-release> ./updater.sh

                ############################################################################
                ####                                                                    ####
                ####                          arkenfox user.js                          ####
                ####       Hardening the Privacy and Security Settings of Firefox       ####
                ####           Maintained by @Thorin-Oakenpants and @earthlng           ####
                ####            Updater for macOS and Linux by @overdodactyl            ####
                ####                                                                    ####
                ############################################################################


Documentation for this script is available here: https://github.com/arkenfox/user.js/wiki/5.1-Updater-[Options]#-maclinux

Please observe the following information:
    Firefox profile:  /home/jr/.mozilla/firefox/v5kwl3c0.default-release
    Available online: * version: 140
    Currently using:  * version: 140


This script will update to the latest user.js file and append any custom configurations from user-overrides.js. Continue Y/N?
y

Status: user.js has been backed up and replaced with the latest version!
Status: Override file appended: user-overrides.js
```

## Check

Launch LibreWolf or Firefox and press `Ctrl-Shift-J` to launch Browser Console
Mode, and look for any errors.

Go to `about:config` -> [x] `Show only modified preferences`. You should see
`SUCCESS: No no he's not dead, he's, he's restin'!`

</details>

### User Agent Spoofing

Research what the most common user agent is. You'll need to disable
`privacy.resistFingerprinting` for this to work.

Place the user agent string in `general.useragent.override` something like:
`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`

<https://www.whatsmyuseragent.com>

<https://www.useragentstring.com>

- [BrowserCat Fingerprint Spoofing](https://www.browsercat.com/post/browser-fingerprint-spoofing-explained)
