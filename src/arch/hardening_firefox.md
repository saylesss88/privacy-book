# Hardening Firefox on Arch

<details>
<summary> ✔️ Click to Expand Table of Contents</summary>

<!-- toc -->

</details>

## 🔑 Key Terms

- **Browser hardening** focuses on reducing attack surface and blocking tracking
  by disabling or restricting features like JavaScript, cookies, telemetry, and
  third-party scripts.

- **Fingerprint protection**, on the other hand, aims to make your browser
  indistinguishable from others. Instead of just blocking data collection, it
  ensures that your browser’s configuration; screen size, fonts, user agent,
  etc. matches a large group of users, so you blend in.

- **Browser compartmentalization** is a technique where different browsers are
  dedicated to distinct online activities to isolate cookies, trackers, and
  browsing data. For example, Mullvad Browser can be used solely for activities
  where fingerprinting resistance is critical, such as anonymous browsing or
  visiting privacy-sensitive sites. Meanwhile, a hardened LibreWolf or Firefox
  can be used for general browsing, email, or banking where you want solid
  security and feature flexibility but aren't as concerned about fingerprint
  uniqueness.

- **Web APIs**: are sets of rules and protocols that allow browsers or servers
  to communicate and share data or functions over the internet. It lets
  developers access features or data of a web service or application without
  exposing the underlying system details, enabling different software to
  interact smoothly and securely.

- **Anonymity**: Maximizing anonymity often means restricting or masking
  features (setting a generic fingerprint, disabling browser APIs, blocking
  trackers) so the browser blends in with many others. This reduces uniqueness
  but can break website functionality, cause CAPTCHAs, and limit usability.

- **Usability**: Keeping your browser features enabled improves compatibility
  and user experience but increase uniqueness and thus make you easier to track.

- [Entropy](<https://en.wikipedia.org/wiki/Entropy_(computing)>): in this
  context, is a measure of how much unique information a specific browser
  feature contributes to your fingerprint. It's often quantified in **bits of
  entropy**, where higher bits mean more uniqueness (i.e., easier to identify
  you).
  - A "bit" is a basic unit of information for computers. Entropy measuring
    sites results are measured in "bits of identifying information".

- [Origin](https://developer.mozilla.org/en-US/docs/Glossary/Origin): Web
  content's _origin_ is defined by the _scheme_ (protocol), _hostname_ (domain),
  and port of the URL used to access it. Two objects have the same origin only
  when the scheme, hostname, and port all match.

- [Same-origin policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy):
  is a critical security mechanism that restricts how a document or script
  loaded by one origin can interact with a resource from another origin. It
  helps isolate potentially malicious documents, reducing possible attack
  vectors.

- [Firefox Site-Isolation](https://blog.mozilla.org/security/2021/05/18/introducing-site-isolation-in-firefox/).
  Firefox does provide site-isolation as well.

- [Protection from side-channel attacks](https://www.mozilla.org/en-US/security/advisories/mfsa2018-01/)

- [MDN Insecure passwords](https://developer.mozilla.org/en-US/docs/Web/Security/Insecure_passwords)
  - [Risks of reused passwords](https://blog.mozilla.org/tanvi/2016/01/28/no-more-passwords-over-http-please/)

> Tor Browser is **not** the most secure browser, anonymity, and security can
> often be at odds with each other. Having the exact same browser as many other
> people isn't the best security practice, but it is great for anonymity. Tor is
> also based on Firefox Esr, which only receives patches for vulnerabilities
> considered Critical or High which can be taken advantage of.

### Fingerprinting Explained

Modern Web APIs enable highly customized user experiences but also expose
detailed device information that attackers can exploit to create browser
fingerprints, unique identifiers used for covert tracking, even when cookies are
blocked.

**Entropy**, a measure of randomness or uniqueness in data, is a critical metric
for assessing the risk of browser fingerprinting.

Browser fingerprinting is a tracking technique, often done by third-party
companies that specialize in it. They provide code (usually JavaScript) that a
website owner can embed on their site. When you visit the site, the script runs
in the background, silently collecting data about your device and browser.

There are two main approaches to obfuscating your fingerprint:

- **Standardization**: Make browsers standardized and therefore have the same
  fingerprint to blend into a crowd. This is what Tor and Mullvad Browser do.
  Best for anonymity; increases the crowd you blend into, but may decrease
  usability (site breakage, CAPTCHAs); adversaries may still find subtle
  differences.

- **Randomization**: Randomize fingerprint metrics so it's not directly linkable
  to you. Brave has this feature, if you run coveryourtracks with Brave you will
  get a result of "your browser has a randomized fingerprint". This is good for
  privacy but may be detectable by advanced scripts.

Test your browsers fingerprint:

- [CoverYourTracks](https://coveryourtracks.eff.org/)

- [AmIUnique](https://amiunique.org/)

Test how well your browser implements security standards and features:

- [BrowserAudit](https://browseraudit.com)

Test the sites you visit for trackers:

- [Blacklight](https://themarkup.org/ask-the-markup/2020/09/22/i-scanned-the-websites-i-visit-with-blacklight-and-its-horrifying-now-what)

Don't put too much weight into the results as people often check their
fingerprint, change one metric and check it again over and over skewing the
results. It is helpful for knowing the fingerprint values that trackers track.

- [Browser Fingerprinting Tor Forum](https://forum.torproject.org/t/browser-fingerprinting/1228/25)

- [Madaidans Hot Take on Browser Tracking](https://madaidans-insecurities.github.io/browser-tracking.html)

You can use something like [NoScript](https://noscript.net/) to block
JavaScript, preventing the scripts from running that do most of the
fingerprinting. Extensions can make you more unique but it's a give and take.

The following website lists the tracking protection mechanisms implemented by
the major browsers and browser engines:

- [Cookie Status](https://www.cookiestatus.com/)

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

SearXNG is a bit different, you can choose which search engine you want for your
current search with `!ddg search term` to use duckduckgo for example.

- [searxng repo](https://github.com/searxng/searxng?tab=readme-ov-file)
  - [Install guide](https://docs.searxng.org/admin/installation.html)

  - [Configuration guide](https://docs.searxng.org/admin/settings/index.html)

---

**Startpage** is another metasearch engine that I've heard good things about.

- [Startpage Privacy Please!](https://www.startpage.com/privacy-please/)

- [Startpage Privacy Protection](https://www.startpage.com/privacy-please/startpage-articles/easy-privacy-control-across-the-internet-introducing-startpage-privacy-protection)

---

## Defenses

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

Browsers that have a form of tracking protection typically use lists of known
trackers and match each outgoing request against these lists.

Enhanced Tracking Protection is how you deal with cookies and more on Firefox.

- [Enhanced Tracking Protection (ETP)](https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop)
  blocks known "third-party requests" to companies that participate in
  fingerprinting, according to the
  [Disconnect List](https://disconnect.me/trackerprotection)
  - In `about:preferences#privacy`, setting Enhanced Tracking Protection to
    either Strict or Custom enables FPP as well, explained further down.

  - [Total Cookie Protection](https://blog.mozilla.org/mozilla/firefox-rolls-out-total-cookie-protection-by-default-to-all-users-worldwide/)
    is enabled by default in Standard mode.

  - When you set ETP to Strict, it includes
    [Enhanced Cookie Clearing](https://blog.mozilla.org/security/2021/08/10/firefox-91-introduces-enhanced-cookie-clearing/),
    which improves on the removal of third-party cookies, as well as Bounce
    Tracking Protection that prevents redirect trackers.

- [First-Party Isolation](https://wiki.mozilla.org/Security/FirstPartyIsolation)
  From the Tor Uplift Project.

### Resist Fingerprinting

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

## Disable JavaScript

Most trackers run on JavaScript, thus blocking JavaScript prevents them from
gathering much of the info needed to form a browser fingerprint.

- [NoScript](https://noscript.net/) lets you selectively block scripts on
  websites. Its core function is to block all scripts by default on websites,
  allowing you to manually enable scripts on trusted sites.

  [NoScript PrivacyGuides](https://blog.jeaye.com/2017/11/30/noscript/) should

- [uBlock Origin](https://ublockorigin.com/) also lets you block JavaScript,
  just be aware that many sites may break so you'll have to whitelist
  selectively.

## Disable WebRTC

The main reason people disable WebRTC is to prevent an IP address leak. WebRTC
is designed for real-time communication like video calls and file sharing. If
you don't use those features, it makes sense to disable it.

Disabling WebRTC eliminates specific data points that trackers use, reducing
entropy & the uniqueness of your fingerprint.

In `about:preferences#privacy` -> `Privacy & Security` -> `Permissions`. Click
`Settings`.

- [x] Block new requests asking to access your microphone

- [x] Block new requests asking to access your camera

- You may also want to block Location, but that isn't involving WebRTC.

You can also use the master switch by going to `about:config` and setting
`media.peerconnection.enabled` to `false`

`user.js` settings related to WebRTC:

```js
/* 2002: force WebRTC inside the proxy [FF70+] ***/
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
 * When using a system-wide proxy, it uses the proxy interface
 * [1] https://developer.mozilla.org/docs/Web/API/RTCIceCandidate
 * [2] https://wiki.mozilla.org/Media/WebRTC/Privacy ***/
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.obfuscate_host_address", true);
/* 2004: force exclusion of private IPs from ICE candidates [FF51+]
 * [SETUP-HARDEN] This will protect your private IP even in TRUSTED scenarios after you
 * grant device access, but often results in breakage on video-conferencing platforms ***/
user_pref("media.peerconnection.ice.no_host", true);
```

---

## Disable Canvas Fingerprinting

Canvas Fingerprinting uses the HTML5 `<canvas>` element to generate a
fingerprint. It gets your device to render an image or text on a canvas and then
reads the pixel data. Since devices render things differently, those differences
are identifiable.

When the pref `privacy.resistFingerprinting` is set to `true`, restricts APIs
commonly used for fingerprinting, including the HTML5 Canvas API. When enabled,
it returns a randomized or generic canvas output to prevent unique
identification.

---

## Disable WebGL

Similar to canvas fingerprinting, this technique uses the WebGL API to render 2D
and 3D graphics. The way your system renders these graphics provides information
about your GPU and graphics drivers, which contributes to your unique
fingerprint.

> ❗️ NOTE: It's unnecessary to disable webgl if you're already using RFP and
> will likely make you stand out more because most people don't disable it.

It can be disabled in `about:config` by setting `webgl.disabled` to `true`.

---

## Install Firefox/LibreWolf & ArkenFox

> ⚠️ Firefox offers excellent privacy and customization but falls behind
> Chromium-based browsers in isolation and patch timing. Compartmentalization
> can help balance strong privacy with optimal security by using Brave or
> Chromium for high-risk browsing alongside Firefox for general and
> privacy-focused tasks.

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

---

## Set up a SOCKS5 Proxy with Arti

> ❗️ NOTE: This is one example of using a SOCKS5 proxy to circumvent censorship
> or add additional privacy without the Tor Browser. You can also route other
> apps through the proxy, such as email clients, messaging apps, torrent
> clients, and more.

1. Clone the arti repo:

```bash
# clone the repo
git clone https://gitlab.torproject.org/tpo/core/arti.git

# navigate to the directory
cd arti
```

---

2. To build the Arti binary, compile the code and generate the executable run:

These are the safer build options so you can leave the arti repo in your home
directory without it leaking your username:

```bash
RUSTFLAGS="--remap-path-prefix $HOME/.cargo=.cargo --remap-path-prefix $(pwd)=." \
   cargo build --release -p arti
```

---

3. To allow Arti SOCKS proxy traffic you need to add a rule permitting incoming
   connections to port 9150.

For nftables, you would open `/etc/nftables.conf` and add:

```conf
chain input {
  # ...snip...

  # Allow Arti SOCKS proxy (port 9150)
    tcp dport 9150 ct state new accept

  # ...snip...
}
```

Enable it with `sudo nft -f /etc/nftables.conf`

---

4. To run Arti as a SOCKS proxy on port `9150`, execute:

```bash
./target/release/arti proxy
```

---

5. Configure LibreWolf/Firefox to use the Arti proxy:

Open LibreWolf or Firefox

Go to the menu and open `Preferences/Settings`.

Scroll to the bottom `Network Settings` section.

Click on "`Settings...`" under Network Settings.

In the connection settings dialog:

Select "`Manual proxy configuration`".

For "SOCKS Host", enter `127.0.0.1`.

For the port next to SOCKS Host, enter `9150`.

Select the SOCKS version 5 option (`SOCKS v5`).

Optionally check the box "`Proxy DNS when using SOCKS v5`" to route DNS queries
through the proxy for enhanced privacy.

Click "`OK`" to apply the settings.

---

6. Verify Your Proxy Setup Open a new tab and visit `https://dnsleaktest.com`
   and run an `Extended Test`.

Your IP address should now appear as a Tor exit node IP, indicating your traffic
is routed through the Arti proxy.

- Make sure Arti is running in its terminal or background before you start
  browsing.

- If you close the terminal or stop Arti, your browser will lose the proxy
  connection.

This setup only proxies the configured browser traffic; other apps are not
affected unless configured similarly.

This setup turns LibreWolf or Firefox into a Tor-enabled browser without
installing the Tor Browser Bundle, using the Arti SOCKS proxy instead. It can be
useful if you want to use a more customizable or alternative browser while still
accessing the Tor network securely.

> ⚠️ While using LibreWolf with the Arti SOCKS5 proxy provides network-level
> anonymity by routing traffic through the Tor network, it does not include the
> extensive browser-level privacy and security enhancements found in the
> official Tor Browser. For casual or moderate privacy needs the SOCKS proxy can
> be useful but for stronger anonymity guarantees and protection, the Tor
> Browser is recommended.

## Setup an Arti service to run in the background

> Be careful here, its not as easy to tell if Arti failed for some reason.

Create a service file at `/etc/systemd/system/arti.service`:

Replace `your-username` with your username

```.service
[Unit]
Description=Arti Tor Proxy Service
After=network.target

[Service]
ExecStart=/home/your-username/arti/target/release/arti proxy
Restart=on-failure
User=jr
Group=jr
WorkingDirectory=/home/your-username/arti
Environment=RUSTFLAGS="--remap-path-prefix $HOME/.cargo=.cargo --remap-path-prefix $(pwd)=."

[Install]
WantedBy=multi-user.target
```

Enable & Start the service:

```bash
sudo systemctl enable arti
sudo systemctl start arti --now
```

Ensure its running:

```bash
sudo systemctl status arti
```

---

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

- [PrivacyTests.org](https://privacytests.org/)

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

- [Tor Blog](https://blog.torproject.org/)

- [Arti why-rewrite-tor-in-rust](https://gitlab.torproject.org/tpo/core/arti/#why-rewrite-tor-in-rust)

- [The Tor Uplift Project](https://wiki.mozilla.org/Security/Tor_Uplift/Tracking)

- [BrowserCat Fingerprint Spoofing](https://www.browsercat.com/post/browser-fingerprint-spoofing-explained)

- [cyberinsider Firefox privacy 2025](https://cyberinsider.com/firefox-privacy/)

- [cyberinsider Browser Fingerprinting](https://cyberinsider.com/browser-fingerprinting/)

- [Mozilla Web Docs Privacy on the web](https://developer.mozilla.org/en-US/docs/Web/Privacy)

- [Adguard Blog Browser Extensions and Firewalls explained](https://adguard-dns.io/en/blog/techtok-9-browser-extensions-and-firewall.html)

- [searchfox RFPTargetsDefault](https://searchfox.org/firefox-main/source/toolkit/components/resistfingerprinting/RFPTargetsDefault.inc)

- [Wikipedia Entropy (computing)](<https://en.wikipedia.org/wiki/Entropy_(computing)>)

- [Brave Blog](https://brave.com/blog/)

**Cheatsheets**

- [HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

- [Zero Trust Architecture Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Zero_Trust_Architecture_Cheat_Sheet.html)

- [riseup entropy](https://we.riseup.net/riseup+tech/entropy)

- [kicksecure entropy](https://www.kicksecure.com/wiki/Dev/Entropy)

- [riseup Digital Security](https://riseup.net/en/security)

</details>
