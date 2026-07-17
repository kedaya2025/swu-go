package swu

import "net"

// AssignedIPv4 returns the first INTERNAL_IP4_ADDRESS from the ePDG CP payload.
func (s *Session) AssignedIPv4() net.IP {
	if s == nil || s.cpConfig == nil || len(s.cpConfig.IPv4Addresses) == 0 {
		return nil
	}
	return append(net.IP(nil), s.cpConfig.IPv4Addresses[0]...)
}

// AssignedIPv6 returns the first INTERNAL_IP6_ADDRESS from the ePDG CP payload.
func (s *Session) AssignedIPv6() net.IP {
	if s == nil || s.cpConfig == nil || len(s.cpConfig.IPv6Addresses) == 0 {
		return nil
	}
	return append(net.IP(nil), s.cpConfig.IPv6Addresses[0]...)
}

// DNSServers returns IPv4/IPv6 DNS servers from the ePDG CP payload.
func (s *Session) DNSServers() []string {
	if s == nil || s.cpConfig == nil {
		return nil
	}
	out := make([]string, 0, len(s.cpConfig.IPv4DNS)+len(s.cpConfig.IPv6DNS))
	for _, ip := range s.cpConfig.IPv4DNS {
		if ip != nil {
			out = append(out, ip.String())
		}
	}
	for _, ip := range s.cpConfig.IPv6DNS {
		if ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

// EPDGHost returns the configured ePDG address (host or host:port as stored).
func (s *Session) EPDGHost() string {
	if s == nil || s.cfg == nil {
		return ""
	}
	return s.cfg.EpDGAddr
}
