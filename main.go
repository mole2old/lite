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
	build("geosite", &routercommon.GeoSiteList{})
	build("geoip", &routercommon.GeoIPList{})
}

func build(dir string, list proto.Message) {
	files, _ := os.ReadDir("data/" + dir)
	for _, f := range files {
		raw, _ := os.ReadFile("data/" + dir + "/" + f.Name())
		tag := strings.ToUpper(f.Name())
		lines := strings.Split(string(raw), "\n")

		if sList, ok := list.(*routercommon.GeoSiteList); ok {
			s := &routercommon.GeoSite{CountryCode: tag}
			for _, l := range lines {
				if l = filter(l); l != "" { s.Domain = append(s.Domain, parseDomain(l)) }
			}
			sList.Entry = append(sList.Entry, s)
		} else if iList, ok := list.(*routercommon.GeoIPList); ok {
			i := &routercommon.GeoIP{CountryCode: tag}
			for _, l := range lines {
				if l = filter(l); l != "" { i.Cidr = append(i.Cidr, parseIP(l)...) }
			}
			iList.Entry = append(iList.Entry, i)
		}
	}

	out, _ := proto.Marshal(list)
	name := dir + ".dat"
	os.WriteFile(name, out, 0644)
	os.WriteFile(name+".sha256sum", []byte(fmt.Sprintf("%x  %s", sha256.Sum256(out), name)), 0644)
}

func filter(l string) string {
	l = strings.TrimSpace(l)
	if l == "" || strings.HasPrefix(l, "#") { return "" }
	return l
}

func parseDomain(l string) *routercommon.Domain {
	l = strings.ToLower(l)
	prefixes := []string{"plain:", "regexp:", "domain:", "full:", "keyword:"}
	for i, p := range prefixes {
		if strings.HasPrefix(l, p) {
			return &routercommon.Domain{Type: routercommon.Domain_Type(i), Value: l[len(p):]}
		}
	}
	return &routercommon.Domain{Value: l}
}

func parseIP(l string) (res []*routercommon.CIDR) {
	if ip, n, err := net.ParseCIDR(l); err == nil {
		sz, _ := n.Mask.Size()
		res = append(res, &routercommon.CIDR{Ip: ip, Prefix: uint32(sz)})
	} else if ip := net.ParseIP(l); ip != nil {
		res = append(res, &routercommon.CIDR{Ip: ip, Prefix: 32})
	}
	return
}
