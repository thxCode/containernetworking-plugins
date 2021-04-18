// Copyright 2017 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/buger/jsonparser"
	"github.com/containernetworking/cni/pkg/types"

	"github.com/containernetworking/plugins/pkg/ip"
)

// NetConf is the CNI spec
type NetConf struct {
	types.NetConf
	// ApiVersion is either 1 or 2, which specifies which hns APIs to call
	ApiVersion int `json:"apiVersion"`
	// V2 Api Policies
	HcnPolicies []hcn.EndpointPolicy `json:"hcnPolicies,omitempty"`
	// V1 Api Policies
	Policies []policy `json:"policies,omitempty"`
	// Options to be passed in by the runtime
	RuntimeConfig RuntimeConfig `json:"runtimeConfig"`
	// If true, adds a policy to endpoints to support loopback direct server return
	LoopbackDSR bool `json:"loopbackDSR"`
}

type RuntimeDNS struct {
	Nameservers []string `json:"servers,omitempty"`
	Search      []string `json:"searches,omitempty"`
}

type PortMapEntry struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIP,omitempty"`
}

type RuntimeConfig struct {
	DNS      RuntimeDNS     `json:"dns"`
	PortMaps []PortMapEntry `json:"portMappings,omitempty"`
}

type policy struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

func GetDefaultDestinationPrefix(ip *net.IP) string {
	destinationPrefix := "0.0.0.0/0"
	if ipv6 := ip.To4(); ipv6 == nil {
		destinationPrefix = "::/0"
	}
	return destinationPrefix
}

// If runtime dns values are there use that else use cni conf supplied dns
func (n *NetConf) GetDNS() types.DNS {
	dnsResult := n.DNS
	if len(n.RuntimeConfig.DNS.Nameservers) > 0 {
		dnsResult.Nameservers = n.RuntimeConfig.DNS.Nameservers
	}
	if len(n.RuntimeConfig.DNS.Search) > 0 {
		dnsResult.Search = n.RuntimeConfig.DNS.Search
	}
	return dnsResult
}

// MarshalPolicies converts the Endpoint policies in Policies
// to HNS specific policies as Json raw bytes
func (n *NetConf) MarshalPolicies() []json.RawMessage {
	if n.Policies == nil {
		n.Policies = make([]policy, 0)
	}

	result := make([]json.RawMessage, 0, len(n.Policies))
	for _, p := range n.Policies {
		if !strings.EqualFold(p.Name, "EndpointPolicy") {
			continue
		}

		result = append(result, p.Value)
	}

	return result
}

func (n *NetConf) ApplyLoopbackDSR(ip *net.IP) {
	if err := hcn.DSRSupported(); err != nil || ip == nil {
		return
	}

	value := fmt.Sprintf(`"Destinations" : ["%s"]`, ip.String())
	if n.ApiVersion == 2 {
		n.HcnPolicies = append(n.HcnPolicies, hcn.EndpointPolicy{
			Type:     "OutBoundNAT",
			Settings: []byte(fmt.Sprintf("{%s}", value)),
		})
		return
	}

	n.Policies = append(n.Policies, policy{
		Name:  "EndpointPolicy",
		Value: []byte(fmt.Sprintf(`{"Type": "OutBoundNAT", %s}`, value)),
	})
}

// ApplyOutboundNatPolicy applies NAT Policy in VFP using HNS
// Simultaneously an exception is added for the network that has to be Nat'd
func (n *NetConf) ApplyOutboundNatPolicy(nwToNat string) {
	_, nwToNatCidr, err := net.ParseCIDR(nwToNat)
	if err != nil {
		return
	}

	if n.ApiVersion == 2 {
		for i := range n.HcnPolicies {
			p := &n.HcnPolicies[i]

			// search OutBoundNAT
			if p.Type != hcn.OutBoundNAT {
				continue
			}

			// leave untouched
			exceptionsValue, dt, _, _ := jsonparser.Get(p.Settings, "Exceptions")
			if dt == jsonparser.Array && len(exceptionsValue) != 0 {
				// only configure the large overlapped network
				masqIP4Net := ip.FromIPNet(nwToNatCidr)
				var exceptionList []string
				_, _ = jsonparser.ArrayEach(exceptionsValue, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
					if dataType == jsonparser.String && len(value) != 0 {
						item := string(value)
						_, itemCidr, err := net.ParseCIDR(item)
						if err != nil {
							return
						}
						itemIP4Net := ip.FromIPNet(itemCidr)
						if masqIP4Net.Overlaps(itemIP4Net) {
							masqIP4Net = itemIP4Net
						} else if !itemIP4Net.Overlaps(masqIP4Net) {
							exceptionList = append(exceptionList, item)
						}
					}
				})
				exceptionList = append(exceptionList, masqIP4Net.ToIPNet().String())
				n.HcnPolicies[i] = hcn.EndpointPolicy{
					Type:     hcn.OutBoundNAT,
					Settings: []byte(`{"Exceptions": ["` + strings.Join(exceptionList, `","`) + `"]}`),
				}
				return
			}
			// or correct with given snat network exception
			n.HcnPolicies[i] = hcn.EndpointPolicy{
				Type:     hcn.OutBoundNAT,
				Settings: []byte(`{"Exceptions": ["` + nwToNat + `"]}`),
			}
			return
		}

		// didn't find the policy, add it
		n.HcnPolicies = append(n.HcnPolicies, hcn.EndpointPolicy{
			Type:     hcn.OutBoundNAT,
			Settings: []byte(`{"Exceptions": ["` + nwToNat + `"]}`),
		})
		return
	}

	for i := range n.Policies {
		p := &n.Policies[i]
		if !strings.EqualFold(p.Name, "EndpointPolicy") {
			continue
		}

		// search OutBoundNAT
		typeValue, _ := jsonparser.GetUnsafeString(p.Value, "Type")
		if typeValue != "OutBoundNAT" {
			continue
		}

		// leave untouched
		exceptionListValue, dt, _, _ := jsonparser.Get(p.Value, "ExceptionList")
		if dt == jsonparser.Array && len(exceptionListValue) != 0 {
			// only configure the large overlapped network
			masqIP4Net := ip.FromIPNet(nwToNatCidr)
			var exceptionList []string
			_, _ = jsonparser.ArrayEach(exceptionListValue, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
				if dataType == jsonparser.String && len(value) != 0 {
					item := string(value)
					_, itemCidr, err := net.ParseCIDR(item)
					if err != nil {
						return
					}
					itemIP4Net := ip.FromIPNet(itemCidr)
					if masqIP4Net.Overlaps(itemIP4Net) {
						masqIP4Net = itemIP4Net
					} else if !itemIP4Net.Overlaps(masqIP4Net) {
						exceptionList = append(exceptionList, item)
					}
				}
			})
			exceptionList = append(exceptionList, masqIP4Net.ToIPNet().String())
			n.Policies[i] = policy{
				Name:  "EndpointPolicy",
				Value: []byte(`{"Type": "OutBoundNAT", "ExceptionList": ["` + strings.Join(exceptionList, `","`) + `"]}`),
			}
			return
		}
		// or correct with given snat network exception
		n.Policies[i] = policy{
			Name:  "EndpointPolicy",
			Value: []byte(`{"Type": "OutBoundNAT", "ExceptionList": ["` + nwToNat + `"]}`),
		}
		return
	}
	// didn't find the policy, add it
	n.Policies = append(n.Policies, policy{
		Name:  "EndpointPolicy",
		Value: []byte(`{"Type": "OutBoundNAT", "ExceptionList": ["` + nwToNat + `"]}`),
	})
}

// ApplyDefaultPAPolicy is used to configure a endpoint PA policy in HNS
func (n *NetConf) ApplyDefaultPAPolicy(paAddress string) {
	if paAddress == "" {
		return
	}

	if n.ApiVersion == 2 {
		// if its already present, leave untouched
		for i := range n.HcnPolicies {
			p := &n.HcnPolicies[i]

			// search PA
			if p.Type != hcn.NetworkProviderAddress {
				continue
			}

			// leave untouched
			paValue, dt, _, _ := jsonparser.Get(p.Settings, "ProviderAddress")
			if dt == jsonparser.String && len(paValue) != 0 {
				return
			}
			// or correct with given provider address
			n.HcnPolicies[i] = hcn.EndpointPolicy{
				Type:     hcn.NetworkProviderAddress,
				Settings: []byte(`{"ProviderAddress": "` + paAddress + `"}`),
			}
			return
		}

		// didn't find the policy, add it
		n.HcnPolicies = append(n.HcnPolicies, hcn.EndpointPolicy{
			Type:     hcn.NetworkProviderAddress,
			Settings: []byte(`{"ProviderAddress": "` + paAddress + `"}`),
		})
		return
	}

	// if its already present, leave untouched
	for i := range n.Policies {
		p := &n.Policies[i]
		if !strings.EqualFold(p.Name, "EndpointPolicy") {
			continue
		}

		// search PA
		typeValue, _ := jsonparser.GetUnsafeString(p.Value, "Type")
		if typeValue != "PA" {
			continue
		}

		// leave untouched
		paValue, dt, _, _ := jsonparser.Get(p.Value, "PA")
		if dt == jsonparser.String && len(paValue) != 0 {
			return
		}
		// or correct with given provider address
		n.Policies[i] = policy{
			Name:  "EndpointPolicy",
			Value: []byte(`{"Type": "PA", "PA": "` + paAddress + `"}`),
		}
		return
	}
	// didn't find the policy, add it
	n.Policies = append(n.Policies, policy{
		Name:  "EndpointPolicy",
		Value: []byte(`{"Type": "PA", "PA": "` + paAddress + `"}`),
	})
}

// ApplyPortMappingPolicy is used to configure HostPort<>ContainerPort mapping in HNS
func (n *NetConf) ApplyPortMappingPolicy(portMappings []PortMapEntry) {
	if portMappings == nil {
		return
	}

	if n.ApiVersion == 2 {
		for i := range portMappings {
			p := &portMappings[i]
			protocol, err := getPortEnumValue(p.Protocol)
			if err != nil {
				continue
			}
			portMappingPolicy := hcn.PortMappingPolicySetting{
				ExternalPort: uint16(p.HostPort),
				InternalPort: uint16(p.ContainerPort),
				Protocol:     protocol,
				VIP:          p.HostIP,
			}
			settings, err := json.Marshal(portMappingPolicy)
			if err != nil {
				continue
			}
			n.HcnPolicies = append(n.HcnPolicies, hcn.EndpointPolicy{
				Type:     hcn.PortMapping,
				Settings: settings,
			})
		}
		return
	}

	for i := range portMappings {
		p := &portMappings[i]
		n.Policies = append(n.Policies, policy{
			Name:  "EndpointPolicy",
			Value: []byte(fmt.Sprintf(`{"Type": "NAT", "InternalPort": %d, "ExternalPort": %d, "Protocol": "%s"}`, p.ContainerPort, p.HostPort, p.Protocol)),
		})
	}
}

func getPortEnumValue(protocol string) (uint32, error) {
	var protocolInt uint32
	u, err := strconv.ParseUint(protocol, 0, 10)
	if err != nil {
		switch strings.ToLower(protocol) {
		case "tcp":
			protocolInt = 6
			break
		case "udp":
			protocolInt = 17
			break
		case "icmpv4":
			protocolInt = 1
			break
		case "icmpv6":
			protocolInt = 58
			break
		case "igmp":
			protocolInt = 2
			break
		default:
			return 0, errors.New("invalid protocol supplied to port mapping policy")
		}
	} else {
		protocolInt = uint32(u)
	}
	return protocolInt, nil
}
