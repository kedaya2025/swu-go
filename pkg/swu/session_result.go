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

// PCSCFServers returns P-CSCF addresses from the ePDG CP payload.
//
// Order prefers IPv6 then IPv4 (common for VoWiFi where ePDG hands out
// v6-only UE addresses). Upper layers should use these literal IPs for SIP
// REGISTER and must not re-resolve P-CSCF FQDNs via system DNS (Fake-IP).
func (s *Session) PCSCFServers() []string {
	if s == nil || s.cpConfig == nil {
		return nil
	}
	out := make([]string, 0, len(s.cpConfig.IPv6PCSCF)+len(s.cpConfig.IPv4PCSCF))
	for _, ip := range s.cpConfig.IPv6PCSCF {
		if ip != nil {
			out = append(out, ip.String())
		}
	}
	for _, ip := range s.cpConfig.IPv4PCSCF {
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
