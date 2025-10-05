# RethinkDNS

<details>
<summary> ✔️ Click to Expand Table of Contents</summary>

<!-- toc -->

</details>

![RethinkDNS Logo](../images/rethinkdns.cleaned.png)

> I'm not affiliated with RethinkDNS in any way, I'm just a technologist and
> privacy advocate.

### 🔑 Key Terms

<details>

<summary> ✔️ Click to Expand Key Terms </summary>

- **HTTP** (HyperText Transfer Protocol): The standard protocol used by web
  browsers and servers to transfer web pages and related resources over the
  internet.

- **IP** (Internet Protocol): The address system of the internet that routes
  data packets from source to destination devices. IP operates at the network
  layer and does not guarantee delivery order or error checking, which is
  handled by TCP.

- **IP Address** (Internet Protocol Address): A unique numeric label assigned to
  each device on a network, used to identify and locate the device for
  communication.

- **Subnet** (Subnet Range): represents a block of IP addresses grouped together
  under a single rule. Instead of allowing or blocking individual IP addresses
  one by one, you define a subnet to include a wide range of IPs within that
  block.(Useful for apps that you `Isolate`).

- **Host**: Any device connected to a network with an IP address, capable of
  sending and receiving data, including computers, phones, or servers.

- **Client**: A device or software (often your computer or phone) that initiates
  requests to servers to access resources or services, forming the client-server
  model of communication.

- **Port**: A port in networking is a virtual communication endpoint managed by
  a computer's operating system that helps direct network traffic to specific
  apps or services. While an IP address identifies a device on a network, ports
  allow the system to know exactly which app or service should handle the
  incoming or outgoing data. Web traffic commonly uses port 80 (HTTP) or 443
  (HTTPS), so when data arrives for those ports, it's routed to the web server
  application on the device. When we block port 80, we block insecure HTTP
  connections.

- **TCP** (Transmission Control Protocol) is responsible for maintaining a
  connection through a handshake and putting the packets in the correct order.
  TCP will also ask for missing pieces and is known as a reliable but slow
  protocol.

- **UDP** (User Datagram Protocol) (UDP/IP): is a fast protocol used across the
  internet for time-sensitive transmissions such as DNS lookups or VoIP. UDP
  allows a computer to send data straight to another without requiring a
  handshake.

- **DNS** (Domain Name System): stores domain information in a distributed
  database and translates domain names into IP addresses and vice versa. This
  enables us to only have to remember simple domain names rather than complex IP
  addresses.

> Domain Name
>
> ```text
> ssd.eff.org
>  |   |   |
>  |   |  top-level domain
>  |   |
>  |   second-level domain
>  |
> subdomain
> ```
>
> ☝️ The hierarchy is read from right to left, the TLD is the highest-level
> domain (`.org` here), the second-level domain (`eff`) is directly to the left
> of the TLD, and anything further left (like `ssd`) is a subdomain under that
> second-level domain.

- **DNS Server**: When you search for a domain name (rethinkdns.com) it triggers
  a DNS lookup. Several different types of DNS servers typically work together
  to complete a single DNS lookup.

- **DNS Resolver**: is a server or software component that translates domain
  names into IP addresses that devices use to communicate.

- **Recursive resolver** (DNS recursor): is typically the first stop in the
  series of the above servers.

- **Iterative resolver**: In an iterative DNS query, each DNS server responds
  directly to the client with a referral to another server, and the client
  continues querying successive servers until it receives the IP address for the
  requested domain.

- **Proxy**: A proxy, in relation to Orbot with Rethink, is an intermediary
  service that routes internet traffic from your device through the Tor network
  to provide privacy and anonymity.

- **HTTP(S) Proxy**: An HTTP proxy is an intermediary server that forwards
  HTTP/HTTPS web traffic from a client (e.g., a browser or app) to destination
  servers, allowing for privacy, filtering, or routing control while masking the
  user's IP. HTTP proxies only work with web traffic (HTTP/HTTPS).

- **SOCKS5** (Socket Secure 5): Is an internet proxy protocol that transfers
  info from one server to another while redirecting the user's IP address. It
  supports both UDP and TCP and can actually improve speed in some cases.

- [pi-hole](https://github.com/pi-hole/pi-hole): a DNS sinkhole that protects
  your devices content without installing any client-side software.

- [OpenSnitch](https://github.com/evilsocket/opensnitch): is a GNU/Linux
  application firewall.

- _proxifier_: a proxifier acts as a proxy client, routing specific application
  traffic through proxy servers without encrypting data or providing global IP
  masking.

- _VPN_ (Virtual Private Network): a VPN creates an encrypted tunnel that routes
  all network traffic from your device through a remote server, masking your IP
  address and securing your entire connection.

- WireGuard: a modern VPN encryption protocol, its fast and has gained
  widespread adoption among VPN providers.

- OpenVPN: an older, more mature VPN protocol that uses SSL/TLS for encryption.
  It's known for being very reliable and highly configurable but tends to be
  slower and more complex than WireGuard. Good VPNs often give you the choice
  between protocols.

- `Bypass DNS and Firewall`: Bypass the DNS and Firewall for this app, **this
  only works with Rethink's DNS**.

- `Bypass Universal`: Bypass the Universal firewall for this app.

- `Exclude`: The app is excluded from the dns and firewall, Rethink is unaware
  of this app.

- `Isolate`: When an app is isolated, only trusted IPs are allowed. (i.e., IPs
  or domains you explicitly set trust rules for).

- 🛜(Unmetered Wi-Fi): Wi-Fi settings, either blocked or allowed.

- 📶 (Metered mobile): Mobile data settings, either blocked or allowed.

</details>

---

## [RethinkDNS Overview](#rethinkdns-overview)

- `Bypass DNS and Firewall`: Bypass the DNS and Firewall for this app, **this
  only works with Rethink's DNS**.

- `Bypass Universal`: Bypass the Universal firewall for this app.

- `Exclude`: The app is excluded from the dns and firewall, Rethink is unaware
  of this app.

- `Isolate`: When an app is isolated, only trusted IPs are allowed. (i.e., IPs
  or domains you explicitly set trust rules for).

- 🛜(Unmetered Wi-Fi): Wi-Fi settings, either blocked or allowed.

- 📶 (Metered mobile): Mobile data settings, either blocked or allowed.

The DNS mode routes all DNS traffic generated by all apps to **any** user chosen
DNS-over-HTTPS, DNS-over-TLS, DNSCrypt, or Oblivious DNS-over-HTTPS resolver.

Firewalls like Rethink that block both UDP and TCP connections are usually
sufficient because nearly all applications rely on these two protocols for their
networking and communication. Almost every app communicates over TCP or UDP, so
blocking these protocols effectively restricts most network traffic from and to
apps, preventing them from connecting without permission.

I will share how I use RethinkDNS, obviously feel free to make changes based on
your threat model and needs.

I use Obtainium and download my apps through GitHub URLs or Obtainium also lets
you choose other sources such as F-Droid. This isn't required, although there
are benefits to this such as not getting all of the shady tracking packaged into
Google Plays Apps and more features explained further down.

[Obtainium#installation](https://github.com/ImranR98/Obtainium?tab=readme-ov-file#installation)

You will have to allow apps from unknown sources, download the APK that your
phone requires, and follow the instructions to install Obtainium. Once you have
Obtainium installed, Click `Add app` and paste
<https://github.com/celzero/rethink-app> into the `App source URL`, and click
`Add`.

---

## Getting Started

### DNS

Throughout this article, I'll be discussing the **RethinkDNS Android App**.
We'll later reference the **DNS Blocklist configuring website**, which is
available at [rethinkdns.com/configure](https://rethinkdns.com/configure).

> ❗ NOTE: When you switch to an encrypted DNS resolver, you are shifting your
> trust from your ISP's DNS servers to the third-party DNS provider you choose.
> Encryption protects your DNS queries from being seen or intercepted by
> outsiders, like your ISP or network eavesdroppers, which improves privacy.
> However, the DNS resolver itself still sees all your queries and could
> potentially log, analyze, or misuse that data.

That said, it's quite common for ISPs to engage in practices that compromise
user privacy. Do some research, whats their business model, privacy policy, etc.
Unfortunately, with a VPN you are also just shifting the trust. Don't blindly
choose a VPN either, I haven't found a free VPN that I would trust...

- [ISP data-collection](https://cyberinsider.com/internet-service-providers-isp-privacy-data-collection/)

`Configure -> DNS -> Other DNS`:

- Choose the type of resolver you want, I use DNSCrypt. Once you click you can
  choose the specific resolver you want such as Quad9. You may notice that it
  says `Failed: using fallback DNS`. This is only because we haven't turned it
  on yet, we will recheck this once we turn it on.
- If you want a relay in a specific country, you can click the `Relays` tab. For
  DNSCrypt you are given the choice between the Netherlands, France, Sweden, Los
  Angeles, and Singapore. You might do this if you were trying to circumvent
  censorship.

**Rules** set the following:

- `Advanced DNS filtering (experimental)`: Assign unique IP per DNS request.
- `Prompt on blocklist updates`: This is for if you use Rethink's custom
  blocklists.

Leave all the `Advanced` defaults unless you plan on setting up a SOCKS5 proxy,
in which case you will want to enable `Configure -> DNS -> Never proxy DNS`.

---

**Blocklists**:

This is a cool feature, similar to NextDNS if I understand correctly. Since it's
a system-wide DNS filter it applys to any app that is run through Rethink, not
only your browser, **every app**.

Blocklists are available when you use Rethink's DNS.

`Configure -> DNS -> Rethink DNS`:

- Choose between `Sky` with higher uptime and a stub resolver at cloudflare.com,
  OR `Max` which is more private and has its recursive resolver at fly.io.

- Choose between the preconfigured blocklists, OR Click `RDNS Plus`, `EDIT`,
  `ADVANCED`, Search blocklists: `hagezi`, `Multi Pro++ (HaGeZi)`,
  `APPLY (RDNS PLUS)`

- You can manually Check for an update to the blocklists, which you should
  because they are updated regularly with new identified threats. You can also
  enable `Prompt on blocklist update`.

---

**F-Droid & Github Versions**

When on the F-Droid and GitHub versions of the Rethink, you can download
blocklists from `Configure -> DNS -> On-device blocklists`, and have them setup
for **any** DNS upstream.

There is a known bug where it sometimes when you click `DOWNLOAD BLOCKLISTS` it
just keeps listening and never receives anything. The GitHub `v05.5n` that I'm
using was affected by this with the Obtainium App. I haven't solved this yet but
have read different solutions like downgrading and upgrading within the app I'll
report back when I have something useful.

It looks like you can use the
[RethinkDNS Configure Blocklist Website](https://rethinkdns.com/configure)

The HAGEZI blocklists are respected for being updated frequently. There are
different levels with MULTI PRO++ (HAGEZI) being the highest and 4 other lest
strict levels.

Choose between `DoT` and `DoH` by clicking the `DoH` button.

```url
# DoT Example w/ only HAGEZI PRO++
1-aabaqaa.max.rethinkdns.com
```

---

### Network

`Configure -> Network`:

- Set `Use all available networks` to ON. This enables Wifi and mobile data to
  be used at the same time by Rethink. (Optional, may use more battery)
- **Set your IP version**: The default is `IPv4`, you can choose between
  `IPv6 (experimental)` and `Auto (experimental)`.
- Using the `Loopback` sounds like a good idea but it makes many of the
  resolvers fail. You may have better luck, just remember that this could be
  what's causing your connectivity issues if you're having any.
- **Choose fallback DNS**: When your user-preferred DNS is not reachable,
  fallback DNS will be used. I typically choose RethinkDNS as the fallback.
- You may want to experiment with shutting off `Enable network visibility`, just
  keep in mind that some apps may break. "Shutting this off prevents apps from
  accessing all available networks, stopping them from bypassing Rethinks
  tunnel". This caused issues with the browser when turned off.

---

### Firewall

`Configure -> Firewall -> Universal firewall rules` and set the following to ON:

- `Block all apps when device is locked`
- `Block when DNS is bypassed`
- `Block port 80 (insecure HTTP) traffic`

You can get more restrictive from here, but it will take some manual
intervention to get everything working correctly.

---

## Turn ON DNS and Firewall

`Home` 🏠:

- Click the big `Start` button on the bottom of the screen and leave it set to
  the default `DNS and Firewall (default)`

Now that we've started the DNS and Firewall, we can go back to
`Configure -> DNS` and ensure the provider we chose started successfully. You
can also experiment with different types of resolvers, make sure to wait for
below the chosen resolver to say `Connected`.

Now, all apps on your device by default allow both Wi-Fi and mobile data access
**through the RethinkDNS encrypted tunnel**. Try some of your most used Apps to
see if they function correctly.

RethinkDNS’s firewall blocks or restricts any network traffic that isn’t
explicitly allowed. Although by default all apps are allowed network access,
some apps require special permissions or bypasses due to their network behavior.
Many apps rely on multiple external services, backend APIs, etc. that may be
blocked by the firewall.

---

### Apps that Don't work

I will use Reddit as an example, the process is the same for any app. Reddit’s
app and website rely on multiple third-party services and external domains
beyond just `reddit.com` itself.

For apps that don't work it's important to ensure that your Android systems
`Private DNS` is set to `Automatic`.

`Home -> Apps`:

Search for `Reddit`, click on it and the Firewall Rules For Reddit will pop up.
Since it is already allowed `Unmetered` and `Metered` connections and still
doesn't work, we can try one setting at a time until it does work and this is
the same process for other Apps that aren't working.

- First, you should check your logs and see why it's being blocked. Look at the
  domains involved and set trust rules for said domains. If it is unclear why
  networking still isn't working, you can:

- `Bypass Universal`, this allows it to bypass any Universal Firewall rules you
  have set.

- If you're using Rethink's DNS, you can try allowing the app to
  `Bypass DNS & Firewall`. Try the app again, does it work? If not:

- `Exclude` the app. This makes RethinkDNS completely unaware of the app and is
  often what is required for Reddit. It is my understanding that after you
  `Exclude` Reddit for example, your systems Automatic Secure DNS will pick it
  up.

- You can also `Isolate` an App, you then have to set up _trust | allow_ rules
  for domains or IPs over a period of time which can take a while. You can go to
  `Apps` and search for the app in question, click on it and at the bottom of
  the screen you'll see `IP Logs`, and `Domain Logs` to help with this.

---

### Other Methods

Rather than watching the logs and setting trust rules over time, you could use
tools like `nslookup` and `dig` to resolve said domain and reveal IP ranges
used.

```bash
nslookup reddit.com
Server:         127.0.0.1
Address:        127.0.0.1#53

Non-authoritative answer:
Name:   reddit.com
Address: 151.101.129.140
Name:   reddit.com
Address: 151.101.193.140
Name:   reddit.com
Address: 151.101.1.140
Name:   reddit.com
Address: 151.101.65.140
Name:   reddit.com
Address: 2a04:4e42::396
Name:   reddit.com
Address: 2a04:4e42:600::396
Name:   reddit.com
Address: 2a04:4e42:200::396
Name:   reddit.com
Address: 2a04:4e42:400::396
```

Resolving a domain (like `reddit.com`) using tools like `nslookup` or `dig`
reveals multiple IPs because large services use multiple servers across CDNs and
networks for redundancy and performance.

You can then run `whois` on one of those IPs (e.g., `whois 151.101.129.140`) to
identify the subnet ranges owned by Reddit's CDN provider (Fastly in this case),
which helps when setting up subnet range allow rules in Rethink.

<details>

<summary> ✔️ Click to Expand `whois` Example Output </summary>

```bash
whois 151.101.129.140

#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2025, American Registry for Internet Numbers, Ltd.
#


NetRange:       151.101.0.0 - 151.101.255.255
CIDR:           151.101.0.0/16
NetName:        SKYCA-3
NetHandle:      NET-151-101-0-0-1
Parent:         RIPE-ERX-151 (NET-151-0-0-0-0)
NetType:        Direct Allocation
OriginAS:
Organization:   Fastly, Inc. (SKYCA-3)
RegDate:        2016-02-01
Updated:        2021-12-14
Ref:            https://rdap.arin.net/registry/ip/151.101.0.0


OrgName:        Fastly, Inc.
OrgId:          SKYCA-3
Address:        PO Box 78266
City:           San Francisco
StateProv:      CA
PostalCode:     94107
Country:        US
RegDate:        2011-09-16
Updated:        2025-03-25
Ref:            https://rdap.arin.net/registry/entity/SKYCA-3


OrgNOCHandle: FNO19-ARIN
OrgNOCName:   Fastly Network Operations
OrgNOCPhone:  +1-415-404-9374
OrgNOCEmail:  noc@fastly.com
OrgNOCRef:    https://rdap.arin.net/registry/entity/FNO19-ARIN

OrgTechHandle: FRA19-ARIN
OrgTechName:   Fastly RIR Administrator
OrgTechPhone:  +1-415-518-9103
OrgTechEmail:  rir-admin@fastly.com
OrgTechRef:    https://rdap.arin.net/registry/entity/FRA19-ARIN

OrgAbuseHandle: ABUSE4771-ARIN
OrgAbuseName:   Abuse Account
OrgAbusePhone:  +1-415-496-9353
OrgAbuseEmail:  abuse@fastly.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/ABUSE4771-ARIN


#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2025, American Registry for Internet Numbers, Ltd.
```

We can see that:

- The subnet range for that IP: `151.101.0.0 - 151.101.255.255` (CIDR notation:
  `151.101.0.0/16`)

So as a starting point to get Reddit working we could trust the following subnet
range:

- IPv4: `151.101.0.0/16`
- This subnet covers the full range from `151.101.0.0` to `151.101.255.255`,
  which includes all related IPs Reddit uses via Fastly’s CDN.
- The owning organization: `Fastly, Inc.` & More...

</details>

---

### Firefox Encrypted DNS through Rethink

First, make sure you can visit a few sites in Firefox. If you can, then your
browser traffic should be routed through the Rethink tunnel, we will check here.
If you can't, go to `Home -> Apps` and search for Firefox, is networking
enabled?

**RethinkDNS Settings**

For the best experience routing your browser traffic through your custom
endpoint (e.g., DNSCrypt) on both Wi-Fi and mobile data ensure the following are
set:

- Do not turn on `Block any app not in use` in the Universal firewall. After
  some Log digging, I found that this causes the browser to fail more often than
  not.
- `Configure -> Network -> Enable network visibility` set to ON. I had
  experimented with turning this off and certain websites wouldn't load when on
  Wi-Fi and none would load on mobile data. Turning it back on seemed to fix
  both with no leaks detected.

Double check that in Rethink's `Configure -> DNS -> Prevent DNS leaks` is ON, as
well as the Universal Firewalls `Block when DNS is bypassed` ON.

---

**Firefox Settings**

> In Firefox, plug `about:config` into the URL bar and scroll down to
> `network.ttr.mode` and change its value to `3` to prevent leaking DNS queries
> to the System resolver. Also in `about:config` scroll down to
> `media.peerconnection.enabled`, double-click to set it to false to prevent
> WebRTC leaks.

- The trade-off is that disabling WebRTC also disables any websites or apps
  using WebRTC for real-time communication (like video calls or chat functions)
  from working correctly.
  [Wikipedia WebRTC](https://en.wikipedia.org/wiki/WebRTC)

In Firefox `Settings -> Privacy & Security`, set `DNS over HTTPS` to
`Default Protection`, this enables Firefox to use RethinkDNS's DNSCrypt resolver
or whatever you chose.

---

**Checking for DNS Leaks**

Go to:

```text
https://dnsleaktest.com
```

Also crosscheck with:

```text
https://ipleak.net
```

`ipleak.net` may show many more servers but as long as they are all related to
your resolver (i.e., WoodyNet for Quad9) you are not leaking to your ISP or
other third-parties.

For DNSCrypt with Quad9 Security, `dnsleaktest` found 5 servers all with the ISP
`WoodyNet` indicating success through Quad9. Quad9 relies on Packet Clearing
House, that's where the `WoodyNet` name comes from.

When on mobile data, when going to `https://dnsleaktest.com` the results may
show more servers. As long as they are all the same ISP you're good.

A different solution could be to experiment with more strict RethinkDNS settings
and just use the browsers built-in DNS over HTTPS on max protection. Having more
strict defaults for Rethink with all of your apps and configuring your browser
separate may be a better option, the choice is yours.

When hunting down a solution you can go to `Configure -> Logs`, then try to
visit the site that wouldn't work while watching the logs. You should see
`Firefox` pop up, click it, in the top right of the pop up should be the reason
it was blocked.

---

### [DuckDuckGo](#duckduckgo)

I also tested DuckDuckGo with its stock configuration and `dnsleaktest.com`
showed that DDGs traffic was successfully tunneled through Rethink to Quad9s'
servers.

`dnsleaktest.com` showed all `WoodyNet` ISPs indicating success.

---

#### [Chromium Based Browsers (Brave)](#chromium-based-browsers-brave)

Brave would not work when routed through Rethink and Chrome completely ignored
it. Brave is definitely better if you must use a Chrome derivative.

- I tried disabling the Brave Shield `Use Secure DNS` to see if that helped, it
  didn't. There may be more you could do here to get it working...

- I do have Chrome and google apps disabled on my main device and only active in
  the Secure Folder which is like a sandboxed environment. This could very well
  be the reason it ignored Rethink, I don't care to test further...

- [EU Hits Google with 3.5 Billion Antitrust](https://techstory.in/eu-hits-google-with-3-5-billion-antitrust-fine-over-adtech-practices/)

---

### [More Fine Grained Control & Enhanced Privacy](#more-fine-grained-control--enhanced-privacy)

> ❗ NOTE: If you are happy with the functionality as is it is unnecessary to
> follow these steps. If you already only install the minimal apps needed on
> your phone (i.e. Only install what you use) you can probably just go to
> individual Apps and block their networking that you are worried about such as
> Facebook and Google. Routing all of your Apps through RethinkDNS + Firewall
> already gives you great privacy and security benefits.

If you read the following GrapheneOS discussion forum written by an RDNS dev:

- [GrapheneOS Discussion Forum on Rethink](https://discuss.grapheneos.org/d/12728-proton-apps-pinging-google-api-sending-reports-back-after-opting-out/54)

The post suggests you go to `Home -> Apps` and right under `Showing all apps`
click on the grayed out 🛜📶 to set a rule to **block both Metered and Unmetered
connections to all apps by default**. This will block both Wi-Fi and mobile data
connections to **all apps** on your device.

The point here is that not every App on your device needs network access all the
time or at all in some cases. Watch your Logs and see which apps "phone home"
the most. Think about which Apps would leave you the most vulnerable and either
block network access completely or block and unblock as needed based on your
threat model.

I would recommend removing network access from your password manager until you
need it or better yet use something completely offline like
[KeePassDX](https://www.keepassdx.com/).

I have never used `Link to Windows` and I `Disable` & `Force Stop` it and
`Link to Windows` is still my most blocked App of all time by Rethink...

If you go for the default deny, you will have to search for every app that you
use and start by enabling networking and then following the
`Apps that don't work` section for each app until they work as expected. If you
really think about it, the number of apps that require constant networking
should be limited.

---

### [Tor](#tor)

If you want to learn how Tor works, I suggest reading the following in this
order:

1.  [PrivacyGuides In Praise of Tor](https://www.privacyguides.org/articles/2025/04/30/in-praise-of-tor/)

2.  [PrivacyGuides Tor Overview](https://www.privacyguides.org/en/advanced/tor-overview/)

3.  [EFF How to: Use Tor](https://ssd.eff.org/module/how-to-use-tor)

**Tor is at risk, and needs our help**. Despite its strength and history, Tor
isn't safe from the same attacks oppressive regimes and misinformed legislators
direct at encryption and many other privacy-enhancing
technologies.--[How to Support Tor](https://www.privacyguides.org/articles/2025/04/30/in-praise-of-tor/#how-to-support-tor)

<details>
<summary>
✔️ Click to Expand Tor Section
</summary>

The following is a summary of some of the Tor Overview, all credit goes to them.
It is important to spread the word when you can!

If you are fortunate to live outside of oppressive regimes with extreme
censorship, using Tor for every day, mundane activities is likely safe and won’t
put you on any harmful “list.” Even if it did, you'd be in good company, these
lists mostly contain great people working tirelessly to defend human rights and
online privacy worldwide.

By using Tor regularly for ordinary browsing, you help strengthen the network,
making it more robust and anonymous for everyone. This collective support makes
staying private easier for activists, journalists, and anyone facing online
surveillance or censorship. The writer of the PrivacyGuides article mentions
using Tor when he needs to access Google Maps to protect his privacy

So, consider embracing Tor not only for sensitive browsing but also for daily
routine tasks. Every user adds valuable noise to the network, helping protect
privacy and freedom for all.

</details>

---

### [Setting up Orbot with a TCP-only Proxy](#setting-up-orbot-with-a-tcp-only-proxy)

![Orbot Logo](../images/orbot.png)

TCP-Only Proxies forward all TCP-level connections from selected apps to Orbot.

TCP-Only Proxies work best for Apps that use multiple TCP protocols beyond just
basic web browsing (HTTP/HTTPS) like messaging apps (Signal), search apps (DDG),
etc. Because it proxies all TCP traffic, it can cause some apps to slow down or
break if they expect direct DNS or UDP.

First install Orbot, Open `Orbot -> More -> Orbot Settings` and turn on
`Power User Mode`. **This is important**, if you forget this Rethinks auto Orbot
will not let you choose between SOCKS and HTTP proxies.

You should also check `Allow Background Starts` ON.

In `Configure -> Proxy -> Setup Orbot`:

- Click `Add / Remove 0 apps`, search for an app that you want to run through
  Orbot. For simple testing I chose DuckDuckGo with a TCP-only Proxy.

- In `Home -> Apps` search for `Orbot` and set `Orbot -> Bypass Universal` ON

- On the first time starting Orbot through Rethink, you'll have to click the
  `Configure -> Proxy -> Setup Orbot -> Orbot>` to `Connect` as well as grant
  initial permissions. After you start Orbot successfully, check out Rethinks
  `Home` and below the STOP button should say `Protected With Tor`.

Open DuckDuckGo and go to:

```text
https://dnsleaktest.com
# CrossCheck
https://ipcheck.net
```

> ❗ You may see that ipleaktest initially shows a Tor exit relay location such
> as the Netherlands, once you complete a Standard Test, it still shows WoodyNet
> ISPs. Since I configured Rethink to use DNSCrypt with Quad9 this is completely
> expected. This confirms that my DNS traffic is not leaking to my ISP and is
> properly anonymized through Tor and Quad9. As long as you don't see your
> actual ISP's servers in the results, your setup is working as intended.

Now you can add more apps that would benefit from anonymity such as FairMail,
RSS feeds, and crypto wallets. I believe for Signal, it requires that you to set
up the SOCKS5 proxy to work correctly which is pretty straightforward.

Look into an RSS Feed, they give you complete control of the content you
consume, no algorithm involved!

This can also be useful on public Wi-Fi or other insecure networks.

- You can also open Orbot and `Choose How to Connect`, if you want to hide Tor
  use.

- If you live in an area where Tor use isn't discriminated against, consider
  Activating your Orbot `Kindness` tab so others that are in oppressive regimes
  can use your device as a bridge. This is a great way to give back!

---

## [Setting up a SOCKS5 Proxy](#setting-up-a-socks5-proxy)

If you have Orbot set up through auto mode, you'll have to disable it.

Open `Orbot -> More`: Near the bottom of the screen you'll see `HTTP: 8118`, and
`SOCKS: 9050`, these are the Port numbers. We will compare these to Rethinks
defaults. (They match).

Back in Rethink, `Configure -> Proxy -> Setup SOCKS5 Proxy`.

In the App dropdown choose `Orbot`.

- Hostname: `127.0.0.1`

- Port Number: `9050`

- Leave the rest of the defaults and Hit `Set`

- Go `Home`, below the STOP button you should see `Protected With SOCKS Proxy`.
  Now all of your devices traffic that doesn't bypass Rethink is routed through
  the SOCKS5 proxy.

- In `Configure -> DNS` and turn `Never proxy DNS` ON

- Open your browser and visit `https://dnsleaktest.com`, your public IP should
  no longer be your ISPs.

- SOCKS5 alone doesn't encrypt the traffic; it only proxies or routes it. Orbot
  uses SOCKS5 to let apps route traffic into the Tor network. Once inside the
  Tor network, the traffic is encrypted in layers.

- There is a misconception that Orbot is a "free VPN". It’s actually part of an
  anonymity network designed to hide your identity by sending your traffic
  through multiple servers. And the SOCKS5 proxy that Orbot uses isn’t a VPN
  either, it simply directs certain app traffic through a proxy server without
  creating a full encrypted tunnel from your device like a VPN does.

---

## WireGuard/VPN

`Configure -> Proxy -> Setup WireGuard -> +`:

With the WireGuard protocol, the provider usually gives you either a QR Code, or
a configuration file (e.g., `.conf` file) which is a plaintext file that
contains what is needed. You download that file and Click `IMPORT` which brings
up your phones filesystem.

There is also a `CREATE` option for advanced users who are setting up their own
WireGuard network, typically if you host your own VPN server.

After this is setup you should always verify that your traffic is encrypted
(hidden IP) and your DNS queries are protected (no leaks).

You could:

1. First check what your IP address is before enabling WireGuard at
   `whatismyipaddress.com` or `ipleak.net`, take note of your Public IP, ISP,
   and City/Country this is your real info that the VPN needs to hide.

2. Connect to Wireguard/VPN. Choose the server location you want and go back to
   check again.

3. Check for leaks, go to `dnsleaktest.com` and run a Standard test. If you
   don't see your Public IP listed anywhere, you don't have a leak.

---

### [Logs](#logs)

On-device logging is on by default. You can find it in `Configure -> Settings`.
From there, you can set the log level and choose a notification action.

If anyone else uses your phone, it's probably a good idea to enable app lock.

Go to `Configure -> Logs`, and try to access the app that's not working. You
should see said app at the top of the Network Logs, click it. In the top right
of the tab, you'll see the reason why it's not working such as: `App Blocked`,
or `DNS Bypass`.

This `DNS Bypass` means that the App in question is trying to bypass the Rethink
Tunnel and being actively blocked. You can search for said app and try setting
IP or Port Trust rules.

You can also go to `Home -> Apps` and search for the App you need, click on it
and at the bottom of the screen you will see `IP Logs`, and `Domain Logs`.

Once you click on the log of the app in question, you'll be given 3 drop down
options. If you set an app to Bypass DNS and Firewall settings, you will see
that in the first dropdown box.

The next drop down is `Block,trust this IP for this app` where you can set a
rule to `Block` or `Trust`.

---

### [Resources](#resources)

<details>
<summary>
✔️ Click to Expand Resources
</summary>

- [Oblivious DNS over HTTPS](https://research.cloudflare.com/projects/network-privacy/odns/)

- [DNSCrypt Protocol](https://www.ietf.org/archive/id/draft-denis-dprive-dnscrypt-06.html)

- [PrivacyGuides In Praise of Tor](https://www.privacyguides.org/articles/2025/04/30/in-praise-of-tor/)

- [PrivacyGuides Tor Overview](https://www.privacyguides.org/en/advanced/tor-overview/)

- [Orbot app](https://orbot.app/en/)

- Orbot is a free app from the Guardian Project that empowers other apps on your
  device to use the internet more securely. Orbot uses Tor to encrypt your
  internet traffic and hide it by bouncing through a seris of computers around
  the world.
  --[TorProject Orbot](https://support.torproject.org/glossary/orbot/)

- [Guardian Project Orbot](https://guardianproject.info/apps/org.torproject.android/)

- WireGuard is an extremely simple yet fast and modern VPN that utilizes
  state-of-the-art cryptography. --[Wireguard.com](https://www.wireguard.com/)

- [EFF Surveillance Self Defense](https://ssd.eff.org/)

- [EFF Cover Your Tracks](https://coveryourtracks.eff.org/)

- [AmIUnique?](https://amiunique.org/)

- [What is NoScript?](https://noscript.net/)

- [PrivacyGuides DNS Recommendations](https://www.privacyguides.org/en/dns/)

- [What is a DNS Server?](https://www.cloudflare.com/learning/dns/what-is-a-dns-server/)

- [What is UDP?](https://www.cloudflare.com/learning/ddos/glossary/user-datagram-protocol-udp/)

- [Networking-Guides TCP/IP Basics](https://network-guides.com/tcp-ip-basics/)

- [Cloudflare What is recursive DNS?](https://www.cloudflare.com/learning/dns/what-is-recursive-dns/)

- [OpenSnitch](https://github.com/evilsocket/opensnitch)

- [pi-hole](https://github.com/pi-hole/pi-hole)

</details>
