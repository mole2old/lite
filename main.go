package main

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

func main() {
	// Execute builds for both geosite and geoip
	build("geosite", &routercommon.GeoSiteList{})
	build("geoip", &routercommon.GeoIPList{})
}

func build(dir string, list proto.Message) {
	files, _ := os.ReadDir("data/" + dir)
	for _, f := range files {
		if f.IsDir() { continue }
		raw, _ := os.ReadFile("data/" + dir + "/" + f.Name())
		tag := strings.ToUpper(f.Name())
		lines := strings.Split(string(raw), "\n")

		if sList, ok := list.(*routercommon.GeoSiteList); ok {
			s := &routercommon.GeoSite{CountryCode: tag}
			for _, l := range lines {
				if l = clean(l); l != "" { s.Domain = append(s.Domain, parseDomain(l)) }
			}
			sList.Entry = append(sList.Entry, s)
		} else if iList, ok := list.(*routercommon.GeoIPList); ok {
			i := &routercommon.GeoIP{CountryCode: tag}
			for _, l := range lines {
				if l = clean(l); l != "" {
					if cidr := parseIPv4(l); cidr != nil { i.Cidr = append(i.Cidr, cidr) }
				}
			}
			iList.Entry = append(iList.Entry, i)
		}
	}

	// Serialize and save binary and checksum
	out, _ := proto.Marshal(list)
	name := dir + ".dat"
	_ = os.WriteFile(name, out, 0644)
	_ = os.WriteFile(name+".sha256sum", []byte(fmt.Sprintf("%x  %s", sha256.Sum256(out), name)), 0644)
}

func clean(l string) string {
	l = strings.TrimSpace(l)
	if l == "" || strings.HasPrefix(l, "#") { return "" }
	return l
}

func parseDomain(l string) *routercommon.Domain {
	l = strings.ToLower(l)
	// Map prefixes to V2Ray domain types (0:Plain, 1:Regex, 2:Domain, 3:Full, 4:Keyword)
	prefixes := []string{"plain:", "regexp:", "domain:", "full:", "keyword:"}
	for i, p := range prefixes {
		if strings.HasPrefix(l, p) {
			return &routercommon.Domain{Type: routercommon.Domain_Type(i), Value: l[len(p):]}
		}
	}
	// Default to Plain (Type 0) if no prefix is found
	return &routercommon.Domain{Type: 0, Value: l}
}

func parseIPv4(l string) *routercommon.CIDR {
	var ip net.IP
	var mask int

	if strings.Contains(l, "/") {
		var n *net.IPNet
		var err error
		ip, n, err = net.ParseCIDR(l)
		if err != nil { return nil }
		mask, _ = n.Mask.Size()
	} else {
		ip = net.ParseIP(l)
		mask = 32
	}

	// Force IPv4 4-byte representation and ignore IPv6
	if ipv4 := ip.To4(); ipv4 != nil {
		return &routercommon.CIDR{Ip: ipv4, Prefix: uint32(mask)}
	}
	return nil
}
