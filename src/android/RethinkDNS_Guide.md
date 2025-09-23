# RethinkDNS

<details>
<summary> ✔️ Click to Expand Table of Contents</summary>

<!-- toc -->

</details>

For the RethinkDNS android app configuration, you can jump to
[Configuring the Rethink Firewall](#configuring-the-rethink-firewall).

If you're in a hurry, jump to the headers that say `Configuring ...` or, check
out the Forum post by a Rethink Dev:

- [GrapheneOS Discussion Forum on Rethink](https://discuss.grapheneos.org/d/12728-proton-apps-pinging-google-api-sending-reports-back-after-opting-out/54)

## RethinkDNS Overview

RethinkDNS is a DNS Resolver service with custom rules and blocklists as well as
a firewall.

The DNS mode gives the end-user their own unique server-endpoint and routes all
DNS traffic from the mobile device to their assigned endpoint encrypted over
TLS.--[the-one-pager](https://blog.rethinkdns.com/the-2021-one-pager)

A **DNS resolver** is an address book of the internet, it helps locate IP
addresses of the servers given a domain name. For example, dns.google.com (a
domain name) is located at 8.8.8.8 (IP address). This mapping is retrieved by a
DNS resolver.

The DNS resolver runs on `Fly.io` and on Cloudflare Workers, a low-latency
serverless environment available in over 300 cities worldwide. This broad
distribution helps enhance anonymity for people using Orbot.

Orbot (Tor) can be used along side RethinkDNS as a Proxy server to change the IP
address. See [Orbot Integration](https://docs.rethinkdns.com/firewall/orbot/)

You can also add a WireGuard configuration to the Rethink DNS + Firewall + VPN
app. See [WireGuard](https://docs.rethinkdns.com/proxy/wireguard/)

You can configure Rethink in your device / internet browser that supports Secure
DNS (aka DNS over HTTPS).

---

## Configure a Custom DNS resolver with Custom blocklists through Rethink website

{{< details title=" ✔️ Click to Expand Rethink Website Section">}} The website
is for devices that support Secure DNS that don't support the app. And
eventually for when they accept registered, paying customers in the
private-beta.

1. Go to: [RethinkDNS Configure](https://www.rethinkdns.com/configure)

2. Use either the `simple ->` for groups of blocklists, or `advanced ->` for
   more fine grained control.

3. Once you have them all selected, decide if you want to use DoH or DoT by
   clicking the `DoH` button under the Rethink Logo.

- DoH resolver addresses' look like: `https://sky.rethinkdns.com/`

- DoT resolver addresses' look like: `1-cbycee6juakjaaa`

For Firefox, open Settings, Privacy & Security, scroll down to Enable DNS over
HTTPS using: Max Protection, Custom, and enter `https://sky.rethinkdns.com/`

Firefox doesn't support DoT natively yet.

{{</details>}}

---

## Rethink on Android

The front-end Android app is open-source:
[rethink-app](https://github.com/celzero/rethink-app)

RethinkDNS doesn't capture or send any user analytics from the app.

RethinkDNS takes over your VPN Slot, it works by creating a local VPN on your
device. It's not a traditional VPN that routes your traffic to a remote server.
Instead, it creates a secure tunnel on your phone that all network traffic
(including DNS queries) must pass through.

Unlike Android's Private DNS, which is a system-wide setting, Rethink gives you
more granular control over how each individual app handles its network traffic.
This enables you to:

- Force all apps to use the same DNS server you've configured through Rethink.

- Block apps that try to bypass your settings.

- Apply different rules to different apps.

- Analyze and log the DNS and network activity for every app, giving you a clear
  view of what your phone is doing in the background.
  - I have never used the Microsoft Link to Windows and even went into settings
    and disabled it and force stopped it and Link to Windows is still the most
    blocked app on my device constantly trying to phone home.

## Rethink Firewall

It's not a traditional firewall, but blocks TCP and UDP connections. This is
sufficient for most apps as they rarely use other forms of TCP/IP transport.

The Firewall app lets you view searchable network logs per connection; lets you
know which apps were blocked and when, and which apps are connected where.

With the Firewall, you can set Universal Rules.

### Configuring the Rethink Firewall

Go to `Configure`, `Firewall`, `Universal firewall rules` and set:

- **Block all apps when device is locked**

- **Block newly Installed Apps**

- **Block port 80 (insecure HTTP) traffic** It's said that over 90% of the web
  now uses HTTPS. Don't visit HTTP sites, it's unnecessary.

- **Block when DNS is bypassed** (as a website a user loads in Firefox won't use
  resolvers set in Resolvers set in Rethink's `Configure -> DNS`)--Rethink dev

- From here you can get more restrictive if you so choose, I choose to block
  apps not in use.

By default after enabling the Universal firewall, all the apps on your device
are set to allow networking traffic. This will give you an idea of which apps
will need more than to allow traffic rule to work. (i.e., Bypass)

## Configuring Rethink App rules

To restrict which Apps have network access, you will have to change that default
enable rule by following the next steps:

- Go to `Configure -> Apps`, and tap the 🛜📶 to block all apps.

- Now, search for the apps you use. Think if they need network access and see if
  they function. If the app does need network access, search for the app and tap
  the 🛜📶 to allow networking. Try the app again to see if it functions
  properly, if it doesn't you can either `Bypass DNS and Firewall`, or `Isolate`
  them.

- If you've done all the above steps and your app still isn't working, you can
  `Exclude` the app which is like you're not using Rethink at all for that app.

- I was able to get my browser working without bypassing anything. All that was
  required was to go to Apps, search for Firefox and tap the 🛜📶 to allow
  networking. This seems to be a good series of steps to first enable networking
  if necessary and only bypass when functionality requires it.

- After some tweaking, I was able to get my browser working without bypassing
  anything.

- Bypass Universal the `Google Play services` app, this is required for updates
  and more.

## Configuring Networking

Go to `Configure -> Network`:

From here you can choose a fallback DNS

- The app defaults to using IPv4, you can either set it to `IPv6(experimental)`,
  or `Auto (experimental)`.

- If you want Rethink to use either wifi or mobile data at the same time, turn
  on `Use all available networks`

- Many of these tips come from the following Forum:
  - [GrapheneOS Discussion Forum on Rethink](https://discuss.grapheneos.org/d/12728-proton-apps-pinging-google-api-sending-reports-back-after-opting-out/54)

## Understanding Encrypted DNS in the RethinkDNS App

It's my understanding that the website is for computer use and you use the
RethinkDNS app for your phone. They are completely separate and not used
together for the time being.

When you configure and enable Rethink to control DNS over HTTPS, if your browser
is also enforcing strict DNS over HTTPS to a different DNS resolver, they will
be blocked by Rethink as a `DNS bypass`.

For Android Firefox, switch the DNS over HTTPS setting to "Default Protection
Firefox will use your system's DNS resolver". This will allow Firefox to use
Rethink's DNS resolver.

## Configuring a Custom DNS

Go to `Configure -> DNS`, `Other DNS`. From there you have quite a few choices.

Let's say you chose DoT for DNS-over-TLS, from there you can choose between 5
providers. Mullvad has a good reputation for keeping minimal data.

If Firefox is set to its default DNS-over-HTTPS (DoH) mode, it should now use
DNS-over-TLS (DoT) through the RethinkDNS app.

While Firefox natively supports only DoH, using the RethinkDNS app unlocks many
more choices.

> In Firefox, plug `about:config` into the URL bar and scroll down to
> `network.ttr.mode` and change its value to `3`. To prevent leaking DNS queries
> to the System resolver. I say scroll because when I did it, the search didn't
> find `network.ttr.mode`.

### Configuring DNS

When you set a user-specified DNS endpoint (like you do with Rethink), the DNS
resolver runs locally on your device or network. Your system is configured to
send DNS queries to this local endpoint (loopback e.g., 127.0.0.1), instead of
directly to a public DNS server like 1.1.1.1

This setup prevents DNS query leaks, meaning no DNS queries bypass the
configured resolver. (What we chose in Configuring a Custom DNS).

In `Configure -> DNS` you can:

- Turn ON `Advanced DNS filtering` to make sure domain to IP address mapping
  isn't polluted.(experimental)

- Turn ON `Prevent DNS leaks` to ensure all DNS queries go through the apps
  secure tunnel.

DNS uses port 53 as its standard communication channel for translating domain
names into DNS queries. Preventing DNS leaks works by capturing all outgoing
packets on port 53 and redirecting them to a user-specified secure DNS endpoint
rather than the system or network default.

## Logs

**By default, no logs are sent or stored**. Only if a paying customer enables
logs are they even captured; otherwise; there's zero information that's stored
on their servers with respect to the DNS requests sent to the Rethink DNS'
resolver.

Currently, you can
[drop them a note](https://rethinkdns.com/cdn-cgi/l/email-protection#b6ded3dadad9f6d5d3daccd3c4d998d5d9db)
to purge the system of your logs.

Go to `Configure`, `Logs`, and try to access the app that's not working. You
should see said app at the top of the Network Logs, click it. In the top right
of the tab, you'll see the reason why it's not working such as: `App Blocked`,
or `DNS Bypass`.

Once you click on the log of the app in question, you'll be given 3 drop down
options. If you set an app to Bypass DNS and Firewall settings, you will see
that in the first dropdown box.

The next drop down is 'Block,trust this IP for this app' where you can set a
rule to 'Block' or 'Trust'.

Apps like Reddit rely on many third-party services, backend APIs etc. to work.
It's my understanding that this fine grained control isn't fully worked out yet
and some connections or domains will stay blocked even with an explicit Trust
Rule. I was eventually able to get Reddit working like normal by Bypassing the
DNS and Firewall Rules.

### Resources

{{< details title=" ✔️ Click to Expand Resources Section">}}

- [Oblivious DNS over HTTPS](https://research.cloudflare.com/projects/network-privacy/odns/)

- [DNSCrypt Protocol](https://www.ietf.org/archive/id/draft-denis-dprive-dnscrypt-06.html)

- [Orbot app](https://orbot.app/en/)

- Orbot is a free app from the Guardian Project that empowers other apps on your
  device to use the internet more securely. Orbot uses Tor to encrypt your
  internet traffic and hide it by bouncing through a seris of computers around
  the world.
  --[TorProject Orbot](https://support.torproject.org/glossary/orbot/)

- WireGuard is an extremely simple yet fast and modern VPN that utilizes
  state-of-the-art cryptography. --[Wireguard.com](https://www.wireguard.com/)

- [EFF Surveillance Self Defense](https://ssd.eff.org/)

- [PrivacyGuides DNS Recommendations](https://www.privacyguides.org/en/dns/)

{{</details>}}
