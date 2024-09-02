// packageName: networking

/*
This package is used to provide networking functionality to a package.
*/
package networking

import (
	"net"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

func GetLocalAddress() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return strings.Split(localAddr.String(), ":")[0]
}

func GetAllLocalAddresses() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	var localAddrs []string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				localAddrs = append(localAddrs, ipnet.IP.String())
			}
		}
	}

	return localAddrs, nil
}

// Use: Filter |DESCRIPTION| Check if IP address from request is in the list of allowed IP addresses |ARGS| r (http.Request), CIDRRange ([]string)
func Filter(r *http.Request, CIDRRange []string) bool {
	// Check if IP is within a CIDR range in the list at Server.Internal.AllowedCIDRRanges
	for _, cidr := range CIDRRange {
		// Remove subnet mask from CIDR range
		cidr = strings.Split(cidr, "/")[0]
		// Remove last octet from CIDR range
		cidr = strings.Split(cidr, ".")[0] + "." + strings.Split(cidr, ".")[1] + "." + strings.Split(cidr, ".")[2] + "."
		if strings.HasPrefix(r.RemoteAddr, cidr) {
			return true
		}
	}
	log.Warn("Request from IP address: " + r.RemoteAddr + " - Not found in allowed CIDR range list")
	return false

}

// Use: GetRequestIPAddress |DESCRIPTION| Retrieve the IP address from the request |ARGS| r (http.Request)
func GetRequestIPAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Error("Error getting IP address: ", err)
		return ""
	}
	return host
}

// Use: GetURI |DESCRIPTION| Retrieve the URI from the request |ARGS| r (http.Request), query (string | base, scheme+base, protocol, path, full)
func GetURI(r *http.Request, query string) string {
	protocol := strings.ToLower(r.Proto[:strings.IndexByte(r.Proto, '/')])
	scheme := protocol + "://"
	base := r.Host
	path := r.URL.Path
	if query == "base" {
		return base
	} else if query == "scheme+base" {
		return scheme + base
	} else if query == "protocol" {
		return protocol
	} else if query == "path" {
		return path
	} else if query == "full" {
		return scheme + base + path
	}
	return "ERROR"
}
