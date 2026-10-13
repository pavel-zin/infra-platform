package geo

import "strings"

// Commercial IP-intelligence feeds label addresses as "hosting", "VPN" or
// "residential". This is the free approximation: a list of networks run by
// clouds, hosting companies and VPN providers, plus name keywords. Residential
// ISPs never match; a corporate network occasionally does.

var hostingASNs = map[uint64]bool{
	16509: true, 14618: true, 8987: true, // Amazon
	15169: true, 396982: true, 19527: true, // Google
	8075: true, 8068: true, // Microsoft
	14061: true,               // DigitalOcean
	16276: true,               // OVH
	24940: true, 213230: true, // Hetzner
	63949: true,              // Akamai Connected Cloud (Linode)
	20473: true,              // Vultr
	31898: true,              // Oracle Cloud
	45102: true, 37963: true, // Alibaba
	132203: true, 45090: true, // Tencent
	12876: true,                           // Scaleway
	51167: true,                           // Contabo
	60781: true, 28753: true, 16265: true, // Leaseweb
	9009:  true,               // M247 (many VPN exits)
	60068: true, 212238: true, // Datacamp / CDN77
	13335: true, 209242: true, // Cloudflare (WARP, Private Relay)
	54113: true,              // Fastly (Private Relay)
	20940: true, 16625: true, // Akamai (Private Relay)
	39351:  true, // 31173 Services (Mullvad)
	136787: true, // Tefincom (NordVPN)
	62240:  true, // Clouvider
	21859:  true, // Zenlayer
	53667:  true, // FranTech / BuyVM
	199524: true, // G-Core Labs
	51852:  true, // Private Layer
	47583:  true, // Hostinger
}

var hostingWords = []string{
	"hosting", "cloud", "data center", "datacenter", "server", "vps", "colocation",
	"digitalocean", "linode", "vultr", "hetzner", "ovh", "microsoft", "oracle",
	"alibaba", "tencent", "scaleway", "contabo", "leaseweb", "m247", "datacamp",
	"mullvad", "31173 services", "proton", "nordvpn", "packethub", "akamai", "fastly",
	"zenlayer", "clouvider", "choopa", "ionos", "kamatera", "hivelocity", "psychz",
	"quadranet", "gcore", "g-core", "xtom", "aeza", "selectel", "upcloud", "netcup",
}

// IsHosting reports whether the network belongs to a cloud, hosting or VPN
// provider according to the list above.
func IsHosting(n Network) bool {
	if n.ASN == 0 && n.Org == "" {
		return false
	}
	if hostingASNs[n.ASN] {
		return true
	}
	org := strings.ToLower(n.Org)
	if strings.Contains(org, "google fiber") {
		return false
	}
	for _, w := range hostingWords {
		if strings.Contains(org, w) {
			return true
		}
	}
	return false
}
