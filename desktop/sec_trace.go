package main

// Security › trace servers.
//
// For the server names found inside a file, this looks up PUBLIC registration records only:
// DNS (where the name points) and RDAP (who registered the name or owns the address, and when).
// It never connects to the servers themselves, so it cannot alert whoever runs them.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type inTrace struct {
	Host    string   `json:"host"`
	IPs     []string `json:"ips,omitempty"`
	Owner   string   `json:"owner,omitempty"`
	Country string   `json:"country,omitempty"`
	Reg     string   `json:"registrar,omitempty"`
	Created string   `json:"created,omitempty"`
	AgeDays int      `json:"ageDays"`
	Note    string   `json:"note,omitempty"`
	Sev     string   `json:"sev,omitempty"`
}

func traceHosts(ctx context.Context, hosts []inServer) []inTrace {
	if len(hosts) > 12 {
		hosts = hosts[:12]
	}
	out := make([]inTrace, len(hosts))
	var wg sync.WaitGroup
	cl := &http.Client{Timeout: 9 * time.Second}
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h inServer) {
			defer wg.Done()
			out[i] = traceOne(ctx, cl, h)
		}(i, h)
	}
	wg.Wait()
	return out
}

func traceOne(ctx context.Context, cl *http.Client, s inServer) inTrace {
	t := inTrace{Host: s.Host, AgeDays: -1}
	ip := s.Host
	if s.Kind != "ip" {
		rc, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupHost(rc, s.Host)
		if err != nil || len(addrs) == 0 {
			t.Note = "The name does not point anywhere right now (the server may be gone)."
			t.Sev = "info"
		} else {
			t.IPs = firstN(addrs, 4)
			ip = addrs[0]
		}
		if j := rdap(ctx, cl, "https://rdap.org/domain/"+s.Host); j != nil {
			t.Reg = rdapRegistrar(j)
			for _, e := range asList(j["events"]) {
				m := asMap(e)
				if fmt.Sprint(m["eventAction"]) == "registration" {
					t.Created = fmt.Sprint(m["eventDate"])
				}
			}
			if ct, err := time.Parse(time.RFC3339, t.Created); err == nil {
				t.AgeDays = int(time.Since(ct).Hours() / 24)
				t.Created = ct.Format("2 Jan 2006")
				if t.AgeDays < 90 {
					t.Note = fmt.Sprintf("Registered only %d days ago. Brand-new names are typical of throw-away attack servers.", t.AgeDays)
					t.Sev = "high"
				}
			}
		}
	}
	if net.ParseIP(ip) != nil {
		if j := rdap(ctx, cl, "https://rdap.org/ip/"+ip); j != nil {
			t.Owner = fmt.Sprint(j["name"])
			if t.Owner == "<nil>" {
				t.Owner = ""
			}
			t.Country = fmt.Sprint(j["country"])
			if t.Country == "<nil>" {
				t.Country = ""
			}
			if t.Owner == "" {
				t.Owner = rdapRegistrar(j)
			}
		}
	}
	if t.Owner == "" && t.Reg == "" && t.Created == "" && t.Note == "" {
		t.Note = "No public registration record could be read (offline or hidden by a privacy service)."
	}
	return t
}

func rdap(ctx context.Context, cl *http.Client, u string) map[string]any {
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var j map[string]any
	if json.Unmarshal(b, &j) != nil {
		return nil
	}
	return j
}

func asList(v any) []any { l, _ := v.([]any); return l }
func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// rdapRegistrar finds the organisation name in the vCard of the first registrar/registrant entity.
func rdapRegistrar(j map[string]any) string {
	for _, e := range asList(j["entities"]) {
		m := asMap(e)
		roles := strings.ToLower(fmt.Sprint(m["roles"]))
		if !strings.Contains(roles, "registrar") && !strings.Contains(roles, "registrant") {
			continue
		}
		vc := asList(m["vcardArray"])
		if len(vc) > 1 {
			for _, p := range asList(vc[1]) {
				pl := asList(p)
				if len(pl) >= 4 && fmt.Sprint(pl[0]) == "fn" {
					return fmt.Sprint(pl[3])
				}
			}
		}
	}
	return ""
}
