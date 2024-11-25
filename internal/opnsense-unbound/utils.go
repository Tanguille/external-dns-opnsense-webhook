package opnsense

import "strings"

// UnboundFQDNSplitter splits a DNSName into two parts,
// [0] Being the top level hostname
// [1] Being the subdomain/domain
//
// TODO: really this should return (hostname, domain string)
func SplitUnboundFQDN(hostname string) []string {
	return strings.SplitN(hostname, ".", 2)
}

func JoinUnboundFQDN(hostname string, domain string) string {
	return strings.Join([]string{hostname, domain}, ".")
}

func PruneUnboundType(unboundType string) string {
	if i := strings.IndexByte(unboundType, ' '); i != -1 {
		return unboundType[:i]
	}
	return unboundType
}

func EmbellishUnboundType(unboundType string) string {
	switch unboundType {
	case "A":
		return unboundType + " (IPv4 address)"
	case "AAAA":
		return unboundType + " (IPv6 address)"
	}
	return unboundType
}

func ParseIngressClassMapping(mapping string) map[string]string {
	result := make(map[string]string)
	if mapping == "" {
		return result
	}

	pairs := strings.Split(mapping, ",")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		if len(kv) == 2 {
			result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	return result
}
