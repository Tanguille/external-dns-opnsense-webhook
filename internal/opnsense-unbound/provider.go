package opnsense

import (
	"context"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

// Provider type for interfacing with Opnsense
type Provider struct {
	provider.BaseProvider

	client       *httpClient
	domainFilter endpoint.DomainFilter
	ingressClassMap map[string]string
}

// NewOpnsenseProvider initializes a new DNSProvider.
func NewOpnsenseProvider(domainFilter endpoint.DomainFilter, config *Config) (provider.Provider, error) {
	c, err := newOpnsenseClient(config)

	if err != nil {
		return nil, fmt.Errorf("provider: failed to create the opnsense client: %w", err)
	}

	p := &Provider{
		client:       c,
		domainFilter: domainFilter,
		ingressClassMap: ParseIngressClassMapping(os.Getenv("INGRESS_CLASS_MAPPING")),
	}

	return p, nil
}

// Records returns the list of HostOverride records in Opnsense Unbound.
func (p *Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	log.Debugf("records: retrieving records from opnsense")

	records, err := p.client.GetHostOverrides()
	if err != nil {
		return nil, err
	}

	var endpoints []*endpoint.Endpoint
	for _, record := range records {
		ep := &endpoint.Endpoint{
			DNSName:    JoinUnboundFQDN(record.Hostname, record.Domain),
			RecordType: PruneUnboundType(record.Rr),
			Targets:    endpoint.NewTargets(record.Server),
		}

		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}

		endpoints = append(endpoints, p.convertCNAMEtoA(ep))
	}

	log.Debugf("records: retrieved: %+v", endpoints)

	return endpoints, nil
}

// ApplyChanges applies a given set of changes in the DNS provider.
func (p *Provider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	// Handle deletions
	for _, endpoint := range append(changes.UpdateOld, changes.Delete...) {
		if err := p.client.DeleteHostOverride(endpoint); err != nil {
			return err
		}
	}

	// Handle creations and updates
	for _, endpoint := range append(changes.Create, changes.UpdateNew...) {
		// Convert CNAME to A record if needed
		endpoint = p.convertCNAMEtoA(endpoint)

		if _, err := p.client.CreateHostOverride(endpoint); err != nil {
			return err
		}
	}

	p.client.ReconfigureUnbound()

	return nil
}

// GetDomainFilter returns the domain filter for the provider.
func (p *Provider) GetDomainFilter() endpoint.DomainFilter {
	return p.domainFilter
}

// Add this new method to handle CNAME to A record conversion
func (p *Provider) convertCNAMEtoA(ep *endpoint.Endpoint) *endpoint.Endpoint {
	// Check if this is a CNAME record
	if ep.RecordType != "CNAME" {
		return ep
	}

	// Look for ingress class annotation
	ingressClass, exists := ep.Labels["kubernetes.io/ingress.class"]
	if !exists {
		return ep
	}

	// Check if we have an IP mapping for this ingress class
	ip, exists := p.ingressClassMap[ingressClass]
	if !exists {
		return ep
	}

	// Convert to A record
	return &endpoint.Endpoint{
		DNSName:    ep.DNSName,
		Targets:    endpoint.NewTargets(ip),
		RecordType: "A",
		Labels:     ep.Labels,
	}
}
