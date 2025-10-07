# Hardening Firefox on Arch

<details>
<summary> ✔️ Click to Expand Table of Contents</summary>

<!-- toc -->

</details>

> ❗️ NOTE: Browser hardening recommendations have started to change from
> suggesting that you install a bunch of add-ons to choosing secure defaults and
> changing minimal settings to get the most out of it.

### Fingerprinting Explained

Browser fingerprinting is a tracking technique, often done by third-party
companies that specialize in it. They provide code (usually JavaScript) that a
website owner can embed on their site. When you visit the site, the script runs
in the background, silently collecting data about your device and browser.

The most concerning aspect of browser fingerprinting is that it operates
silently and without user consent. It's not something you can easily see or
something like cookies that you can opt-out or delete. Browser fingerprinting is
stateless meaning that it doesn't need to store any data on your computer. It
can identify you while behind a VPN or in incognito mode as well.

There are two main approaches to obfuscating your fingerprint:

- Standardization: Make browsers standardized and therefore have the same
  fingerprint to blend into a crowd. This is what Tor does.

- Randomization: Randomize fingerprint metrics so it's not directly tieable to
  you. Brave has this feature.

Test your browsers fingerprint:

- [CoverYourTracks](https://coveryourtracks.eff.org/)

- [AmIUnique](https://amiunique.org/)

Don't put too much weight into the results as people often check their
fingerprint, change one metric and check it again over and over skewing the
results. It is helpful for knowing what the values actually are and seeing what
the tracking companies see.

You can use something like [NoScript](https://noscript.net/) to block
JavaScript, preventing the scripts from running that do most of the
fingerprinting. Extensions can make you more unique but it's a give and take.

---

## Metasearch Engines

- [Wikipedia Metasearch engine](https://en.wikipedia.org/wiki/Metasearch_engine)

### SearXNG

**SearXNG** an open-source, privacy-respecting metasearch engine that aggregates
results from various search services, such as Google, DuckDuckGo, etc without
tracking you or profiling your searches. You can add SearXNG to firefox by going
to `about:preferences#search` and at the bottom click `Add`, URL will be
`https://searx.be/search?q=%s`.

> ❗️ NOTE: The above searx is the default and doesn't give many relevant
> results. To get relevant results find a
> [public instance](https://searx.space/) with a good rating from your area and
> add the `search?q=%s` to the end of it. For example, I'm using
> `https://priv.au/search?q=%s`. This gives much better results than DDG in my
> opinion.

Searx is a bit different, you can choose which search engine you want for your
current search with `!ddg search term` to use duckduckgo for example.

- [searxng repo](https://github.com/searxng/searxng?tab=readme-ov-file)
  - [Install guide](https://docs.searxng.org/admin/installation.html)

  - [Configuration guide](https://docs.searxng.org/admin/settings/index.html)

---

**Startpage** is another metasearch engine that I've heard good things about.

- [Startpage Privacy Please!](https://www.startpage.com/privacy-please/)

- [Startpage Privacy Protection](https://www.startpage.com/privacy-please/startpage-articles/easy-privacy-control-across-the-internet-introducing-startpage-privacy-protection)

---

#### Encrypted DNS

DNS (Domain Name System) resolution is the process of translating a website's
domain name into its corresponding IP address. By default, this traffic isn't
encrypted, which means anyone on the network, from your ISP to potential
hackers, can see the websites you're trying to visit. **Encrypted DNS** uses
protocols to scramble this information, protecting your queries and responses
from being intercepted and viewed by others.

> ❗ NOTE: There are many other ways for someone monitoring your traffic to see
> what domain you looked up via DNS that it's effectiveness is questionable
> without also using Tor or a VPN. Encrypted DNS will not help you hide any of
> your browsing activity.

There are 3 main types of DNS protection:

- **DNS over HTTPS (DoH)**: Uses the HTTPS protocol to encrypt data between the
  client and the resolver.

- **DNS over TLS (DoT)**: Similar to (DoH), differs in the methods used for
  encryption and delivery using a separate port from HTTPS.

- **DNSCrypt**: Uses end-to-end encryption with the added benefit of being able
  to prevent DNS spoofing attacks.

Useful resources:

<details>
<summary> ✔️ Click to Expand DNS Resources </summary>

- [NixOS Wiki Encrypted DNS](https://wiki.nixos.org/wiki/Encrypted_DNS)

- [Domain Name System (DNS)](https://www.cloudflare.com/learning/dns/what-is-dns/)

- [Wikipedia DNS over HTTPS (DoH)](https://en.wikipedia.org/wiki/DNS_over_HTTPS)

- [Wikipedia DNS over TLS (DoT)](https://en.wikipedia.org/wiki/DNS_over_TLS)

- [Cloudflare Dns Encryption Explained](https://blog.cloudflare.com/dns-encryption-explained/)

- [NordVPN Encrypted Dns Traffic](https://nordvpn.com/blog/encrypted-dns-traffic/)

**Hot Take**:

- [Encrypted DNS is ineffective without a VPN or Tor by madaidan](https://madaidans-insecurities.github.io/encrypted-dns.html)

</details>

I recommend either setting up dnscrypt-proxy:

- [dnscrypt-proxy on Arch](https://mako088.github.io/arch/enc_dns.html)

Or set Firefox's DNS over HTTPS to Max protection with a custom resolver:

In `about:preferences#privacy` scroll down to `DNS over HTTPS`, Select
`Max Protection` -> `Custom` -> `https://dns.quad9.net/dns-query`

---

#### Enhanced Tracking Protection (ETP)

- [Enhanced Tracking Protection (ETP)](https://blog.mozilla.org/security/2020/01/07/firefox-72-fingerprinting/)
  blocks known "third-party requests" to companies that participate in
  fingerprinting, according to the
  [Disconnect List](https://disconnect.me/trackerprotection)
  - In `about:preferences#privacy`, setting Enhanced Tracking Protection to
    either Strict or Custom enables FPP as well explained further down.

  - When you enable ETP strict mode, Total Cookie Protection is enabled by
    default. It confines cookies to the site where they were created, preventing
    companies from using them to track your browsing from site to site.

- [First-Party Isolation](https://wiki.mozilla.org/Security/FirstPartyIsolation)
  From the Tor Uplift Project.

### Fingerprinting

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

---

## WebGL

Similar to canvas fingerprinting, this technique uses the WebGL API to render 2D
and 3D graphics. The way your system renders these graphics provides information
about your GPU and graphics drivers, which contributes to your unique
fingerprint.

> ❗️ NOTE: It's unnecessary to disable webgl if you're already using RFP and
> will likely make you stand out more because most people don't disable it.

It can be disabled in `about:config` by setting `webgl.disabled` to `true`.

---

## Install Firefox/LibreWolf & ArkenFox

Download Firefox from the
[Mozilla FTP site](https://ftp.mozilla.org/pub/firefox/releases/) if you are
worried about the download token, the FTP site lets you download the version you
want without a token.

For example, for the latest firefox as of 09-30-25 for the US:

`https://download.mozilla.org/?product=firefox-latest&os=linux64&lang=en-US`

**LibreWolf** is an open-source fork of Firefox with a strong focus on privacy,
security, and user freedom. LibreWolf enables always HTTPS, includes
uBlockOrigin, and more providing strong defaults.

<details>
<summary> ✔️ Click to Expand Arkenfox How To </summary>

The process is the same for both Firefox & LibreWolf. I like LibreWolf for it's
strong defaults but may lag behind Firefox getting security patches.

```bash
paru -S librewolf-bin
```

Read the [ArkenFox Wiki](https://github.com/arkenfox/user.js/wiki)

## Apply

Open `about:support` and look for `Profile Directory` under `Application Basics`
Select `Open Directory`, it will bring you to somewhere like
`~/.librewolf/pefoo8xx.default-default/` and that is where you place the
`user.js`.

Place the following files in your `Profile Directory`:

1. [Arkenfox user.js](https://github.com/arkenfox/user.js/blob/master/user.js)
   Read through the `user.js`, not all settings are applied by default such as
   RFP Fingerprinting protection.

2. [updater.sh](https://github.com/arkenfox/user.js/blob/master/updater.sh)

3. [prefsCleaner.sh](https://github.com/arkenfox/user.js/blob/master/prefsCleaner.sh)

4. Also create your own `user-overrides.js` with any changes you want to make to
   the default `user.js`. These changes are amended to the `user.js` and applied
   last enabling them to override the default settings. It's best to make
   changes here so that updating the Arkenfox `user.js` doesn't make you lose
   all of your customizations.

Example `user-overrides.js` spoofing the user agent:

> ❗️ This is just an example, always check for common useragent strings
> yourself. Read the Arkenfox Wiki!

```js
<!-- user_pref( -->
  <!-- "general.useragent.override", -->
  <!-- "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", -->
<!-- ); -->
// Disable Activity Stream on new windows and tab pages
user_pref("browser.newtab.preload", false);
// Enhanced Tracking Protection (ETP)
user_pref("privacy.bounceTrackingProtection.mode", 1); // [FF131+] [ETP FF133+]
user_pref("privacy.trackingprotection.enabled", true);
// Resist Fingerprinting (RFP)
user_pref("privacy.resistFingerprinting", true); // [FF41+]
user_pref("privacy.resistFingerprinting.pbmode", true); // [FF114+]
// WebRTC
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.default_address_only", true);
// WebGL
user_pref("webgl.disabled", true);
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

> ❗️ NOTE: Spoofing your useragent alone likely isn't worth the protections you
> lose from disabling `resistFingerprinting`. `resistFingerprinting` spoofs many
> different fingerprinting aspects. If you don't get it right, you will get
> captcha requests constantly.

Research what the most common user agent is. You'll need to disable
`privacy.resistFingerprinting` for this to work.

Place the user agent string in `general.useragent.override` something like:
`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`
<https://www.whatsmyuseragent.com>

<https://www.useragentstring.com>

---

## uBlock Origin

BetterFox does a great job explaining how to use uBlock with solid
recommendations.

- [BetterFox uBlock filterlists](https://github.com/yokoffing/filterlists?tab=readme-ov-file#guidelines)

If you wanted to apply the
[Privacy Essentials](https://github.com/yokoffing/filterlists/blob/main/privacy_essentials.txt)
list you would click
[subscribe](https://subscribe.adblockplus.org/?location=https://raw.githubusercontent.com/yokoffing/filterlists/main/privacy_essentials.txt&title=Privacy%20Essentials),
which launches the uBlock asset viewer where you can see all of the domains that
will be blocked before clicking `Subscribe` again to apply them.

### Adding other lists

- [Hagezi dns-blocklists](https://github.com/hagezi/dns-blocklists)

- [adguard-filter-list](https://github.com/ppfeufer/adguard-filter-list)

Click the uBlock logo, Settings, Filter lists, scroll to the bottom and choose
Import..., Paste the url of your chosen list, and click Apply changes.

For example, Arkenfox suggests adding the Actually Legitimate URL Shortener
Tool. Add
<https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LegitimateURLShortener.txt>
to the Import... section and click Apply changes. If you scroll up, you'll see
that it was added and chosen.

Setup your [Blocking mode](https://github.com/gorhill/uBlock/wiki/Blocking-mode)

Many opt for
[medium mode](https://github.com/gorhill/uBlock/wiki/Blocking-mode:-medium-mode).
To do so you need to:

**Settings pane**:

- Open the dashboard, and choose I am an advanced user.

**Filter lists pane**:

- All of uBO's filter lists: checked

- EasyList: checked

- Peter Lowe's Ad server list: checked

- EasyPrivacy: checked

- Online Malicious URL Blocklist: checked

**My rules pane (4th pane from the left)**:

Underneath Temporary rules add, you literally type this in:

- Add `* * 3p-script block`

- Add `* * 3p-frame block`

- Click `Save`

- Click `<- Commit` (Not required on phone)

**Fallback to
[easy mode](https://github.com/gorhill/uBlock/wiki/Blocking-mode:-easy-mode)**

Click the uBlock logo while on the site you want to use easy mode on. You'll see
the power button to the top right, the Global rules and the Local rules which
start 3 boxes from the left. Click the box under the Local rules for 3rd-party
scripts. The box will change colors, dark gray = NOOP (No Operation). This tells
uBO to ignore the aggressive global block for this site, and let the normal
filter lists handle the blocking.

You can also disable JavaScript in My rules as needed.

<details>
<summary> ✔️ Click to Expand Resources </summary>

- [Welcome to SearXNG](https://docs.searxng.org/)

- [Firefox Hardening Guide](https://brainfucksec.github.io/firefox-hardening-guide)

- [Firefox ghacks](https://www.ghacks.net/2015/08/18/a-comprehensive-list-of-firefox-privacy-and-security-settings/)

- [ArkenFox user.js](https://github.com/arkenfox/user.js) Just right IMO.

- [BetterFox user.js](https://github.com/yokoffing/Betterfox) Easiest to use
  with less breakage.

- [Narsil user.js](https://codeberg.org/Narsil/user.js/src/branch/main/desktop)
  Most hardened.

- [PrivacyTools.io](https://www.privacytools.io/private-browser)

- [simeononsecurity Firefox-Privacy-Script](https://github.com/simeononsecurity/FireFox-Privacy-Script)

- [Browsers for Daily Using](https://anhkhoakz.neocities.org/blog/browsers-for-daily-using/#firefox-but-hardened)

- [brianfucksec firefox-hardening-Guide 2023](https://brainfucksec.github.io/firefox-hardening-guide)

- [STIG Firefox Hardening](https://simeononsecurity.com/guides/enhance-firefox-security-configuring-guide/)

> If you should trust the U.S. Governments recommendations is another story but
> it can be good to compare and contrast with other trusted resources. You'll
> have to think whether the CISA recommending that everyone uses Signal is solid
> advice or guiding you towards a honeypot, I can't say for sure.

- [Mozilla Firefox Security Technical Implementation Guide](https://stigviewer.com/stigs/mozilla_firefox)
  The STIG for Mozilla Firefox (Security Technical Implementation Guide) is a
  set of security configuration standards developed by the U.S. Department of
  Defense. They are created by the Defense Information Systems Agency (DISA) to
  secure and harden DoD information systems and software.

- [Privacy, The New Oil (Why Privacy & Security Matter)](https://thenewoil.org/en/guides/prologue/why/)

- [PrivacyGuides](https://www.privacyguides.org/en/)

- [Firefox Relay](https://relay.firefox.com/accounts/profile/) can be used to
  create email aliases that forward to your real email address. The paid plan
  also lets you create phone number aliases that forward to your phone number.

- [Zebra Crossing digital safety checklist](https://zebracrossing.narwhalacademy.org/)

- [DataDetoxKit](https://datadetoxkit.org/en/privacy/essentials#step-1)

- [DataDetox Degooglise](https://datadetoxkit.org/en/privacy/degooglise/)

- [Tor Browser User Manual](https://tb-manual.torproject.org/)

- [Tor Wiki](https://gitlab.torproject.org/tpo/team/-/wikis/home)

- [BrowserCat Fingerprint Spoofing](https://www.browsercat.com/post/browser-fingerprint-spoofing-explained)

- [cyberinsider Firefox privacy 2025](https://cyberinsider.com/firefox-privacy/)

</details>
