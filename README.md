# nmap service discovery

A [labdex](https://github.com/reykimedev/labdex) plugin. Scans inventory networks with nmap (TCP connect, no root needed) and lists the services that are actually listening.

**Version** 1.3 · **Works with** labdex >=1.10,<2 · **Plugin id** `nmap`

> [!WARNING]
> Built with AI, for home labs only: labdex and its plugins were written largely with an AI
> coding assistant (Claude), directed and reviewed by a human. They haven't had an independent
> security audit and may contain security problems. Run them on a trusted home network.

## Install

It ships with labdex: **Plugins › Marketplace**, then *Install* (nothing is downloaded). Updates arrive through the official Marketplace (signed with the labdex project key).

## Settings

| Setting | Notes |
| --- | --- |
| Networks to scan | Inventory networks; empty = every network with an IPv4 prefix |
| Extra targets | Addresses or CIDRs; must lie inside an inventory network |
| Exclude | Addresses or CIDRs never to scan |
| Ports | top:N, or an nmap port list like 22,80,443,8000-8100 |
| Also check every declared service port | Ports of the inventory's services are scanned on their hosts even when they aren't in the list above, so a service on port 32400 isn't shown as not answering just because nobody looked |
| Detect service versions (-sV) |  |
| Timing |  |
| Refuse to scan more than … addresses |  |
| Abort after … seconds |  |
| Also scan known IPv6 addresses | A /64 can't be swept: this scans the IPv6 addresses of the inventory's hosts and those Discovery learned (NDP, DHCPv6) inside the chosen networks |

## Actions

- **Scan now** (run)

## Releasing

Bump `version` in `plugin.yaml`, add a `## <version>` section to `CHANGELOG.md`, commit, then
publish a GitHub release tagged `v<version>` (web UI, or `gh release create v<version> --target main --notes ""`).
The release workflow signs the plugin with the `LABDEX_SIGNING_KEY` secret, attaches the zip and
`CHANGELOG.md` to the release and puts that version's CHANGELOG section into its description.
Files listed in `.releaseignore` stay out of the zip.
