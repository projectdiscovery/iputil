package iputil

import (
	"net"
	"strconv"
	"strings"

	"github.com/projectdiscovery/mapcidr"
)

// IsIP checks if a string is either IP version 4 or 6. Alias for `net.ParseIP`
func IsIP(str string) bool {
	return net.ParseIP(str) != nil
}

// IsPort checks if a string represents a valid port
func IsPort(str string) bool {
	if i, err := strconv.Atoi(str); err == nil && i > 0 && i < 65536 {
		return true
	}
	return false
}

// IsIPv4 checks if the string is an IP version 4.
func IsIPv4(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ".")
}

// IsIPv6 checks if the string is an IP version 6.
func IsIPv6(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ":")
}

// IsCIDR checks if the string is an valid CIDR notiation (IPV4 & IPV6)
func IsCIDR(str string) bool {
	_, _, err := net.ParseCIDR(str)
	return err == nil
}

// IsCIDR checks if the string is an valid CIDR after replacing - with /
func IsCidrWithExpansion(str string) bool {
	str = strings.ReplaceAll(str, "-", "/")
	return IsCIDR(str)
}

func CountIPsInCIDR(cidr string) int64 {
	_, c, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}

	return mapcidr.CountIPsInCIDR(c).Int64()
}

func ToCidr(item string) *net.IPNet {
	if IsIP(item) {
		item += "/32"
	}
	if IsCIDR(item) {
		_, ipnet, _ := net.ParseCIDR(item)
		return ipnet
	}
	return nil
}

func AsIPV4IpNet(IPV4 string) *net.IPNet {
	if IsIP(IPV4) {
		IPV4 += "/32"
	}
	_, network, err := net.ParseCIDR(IPV4)
	if err != nil {
		return nil
	}
	return network
}

func AsIPV4CIDR(IPV4 string) string {
	if IsIP(IPV4) {
		return IPV4 + "/32"
	}
	return IPV4
}

func AsIPV6CIDR(IPV6 string) string {
	// todo
	return IPV6
}
