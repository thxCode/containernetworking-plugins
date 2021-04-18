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
	"fmt"
	"net"
	"strings"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"

	"github.com/containernetworking/plugins/pkg/errors"
)

const (
	pauseContainerNetNS = "none"
)

type EndpointInfo struct {
	EndpointName string
	DNS          types.DNS
	NetworkName  string
	NetworkId    string
	Gateway      net.IP
	IpAddress    net.IP
}

func GetSandboxContainerID(containerID string, netNs string) string {
	if len(netNs) != 0 && netNs != pauseContainerNetNS {
		splits := strings.SplitN(netNs, ":", 2)
		if len(splits) == 2 {
			containerID = splits[1]
		}
	}

	return containerID
}

func GetIpString(ip *net.IP) string {
	if len(*ip) == 0 {
		return ""
	} else {
		return ip.String()
	}
}

func ConstructEndpointName(containerID string, netNs string, networkName string) string {
	return GetSandboxContainerID(containerID, netNs) + "_" + networkName
}

func GenerateHnsEndpoint(epInfo *EndpointInfo, n *NetConf) (*hcsshim.HNSEndpoint, error) {
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epInfo.EndpointName)
	if err != nil && !hcsshim.IsNotExist(err) {
		return nil, errors.Annotatef(err, "failed to get HNSEndpoint %q", epInfo.EndpointName)
	}
	if hnsEndpoint != nil {
		if !strings.EqualFold(hnsEndpoint.VirtualNetwork, epInfo.NetworkId) {
			if _, err = hnsEndpoint.Delete(); err != nil {
				return nil, errors.Annotatef(err, "failed to delete corrupted HNSEndpoint %s", epInfo.EndpointName)
			}
		} else {
			return nil, fmt.Errorf("HNSEndpoint %s is already existed", epInfo.EndpointName)
		}
	}

	if n.LoopbackDSR {
		n.ApplyLoopbackDSR(&epInfo.IpAddress)
	}
	hnsEndpoint = &hcsshim.HNSEndpoint{
		Name:           epInfo.EndpointName,
		VirtualNetwork: epInfo.NetworkId,
		DNSServerList:  strings.Join(epInfo.DNS.Nameservers, ","),
		DNSSuffix:      strings.Join(epInfo.DNS.Search, ","),
		GatewayAddress: GetIpString(&epInfo.Gateway),
		IPAddress:      epInfo.IpAddress,
		Policies:       n.MarshalPolicies(),
	}
	return hnsEndpoint, nil
}

type HnsEndpointMakerFunc func() (*hcsshim.HNSEndpoint, error)

func AddHnsEndpoint(epName string, expectedNetworkId string, containerID string, netns string, makeEndpoint HnsEndpointMakerFunc) (*hcsshim.HNSEndpoint, error) {
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epName)
	if err != nil {
		if !hcsshim.IsNotExist(err) {
			return nil, errors.Annotatef(err, "failed to find HNSEndpoint %s", epName)
		}
	}

	// On the second add call we expect that the endpoint already exists. If it
	// does not then we should return an error.
	if netns != pauseContainerNetNS {
		if hnsEndpoint == nil {
			return nil, errors.Annotatef(err, "failed to find HNSEndpoint %s", epName)
		}
	}

	// Check whether endpoint is corrupted
	if hnsEndpoint != nil {
		if !strings.EqualFold(hnsEndpoint.VirtualNetwork, expectedNetworkId) {
			_, err = hnsEndpoint.Delete()
			if err != nil {
				return nil, errors.Annotatef(err, "failed to delete corrupted HNSEndpoint %s", epName)
			}
			hnsEndpoint = nil
		}
	}

	// Create endpoint
	var isNewEndpoint bool
	if hnsEndpoint == nil {
		if hnsEndpoint, err = makeEndpoint(); err != nil {
			return nil, errors.Annotate(err, "failed to make a new HNSEndpoint")
		}
		if hnsEndpoint, err = hnsEndpoint.Create(); err != nil {
			return nil, errors.Annotate(err, "failed to create the new HNSEndpoint")
		}
		isNewEndpoint = true
	}

	// Hot attach
	if err := hcsshim.HotAttachEndpoint(containerID, hnsEndpoint.Id); err != nil {
		if isNewEndpoint {
			if err := RemoveHnsEndpoint(epName, netns, containerID); err != nil {
				return nil, errors.Annotatef(err, "failed to remove the new HNSEndpoint %s after attaching container %s failure", hnsEndpoint.Id, containerID)
			}
		}
		if hcsshim.ErrComputeSystemDoesNotExist == err {
			return hnsEndpoint, nil
		}
		return nil, errors.Annotatef(err, "failed to attach container %s to HNSEndpoint %s", containerID, hnsEndpoint.Id)
	}

	return hnsEndpoint, nil
}

func RemoveHnsEndpoint(epName string, netns string, containerID string) error {
	if len(netns) == 0 {
		return nil
	}

	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(epName)
	if err != nil {
		if hcsshim.IsNotExist(err) {
			return nil
		}
		return errors.Annotatef(err, "failed to find HNSEndpoint %s", epName)
	}

	// Shared endpoint removal
	if netns != pauseContainerNetNS {
		// Do not remove the endpoint
		_ = hnsEndpoint.ContainerDetach(containerID)
		return nil
	}

	// Do not consider this as failure, else this would leak endpoints
	_ = hcsshim.HotDetachEndpoint(containerID, hnsEndpoint.Id)

	// Do not return error
	_, _ = hnsEndpoint.Delete()

	return nil
}

func ConstructHnsResult(hnsNetwork *hcsshim.HNSNetwork, hnsEndpoint *hcsshim.HNSEndpoint) (*current.Result, error) {
	resultInterface := &current.Interface{
		Name: hnsEndpoint.Name,
		Mac:  hnsEndpoint.MacAddress,
	}
	_, ipSubnet, err := net.ParseCIDR(hnsNetwork.Subnets[0].AddressPrefix)
	if err != nil {
		return nil, errors.Annotatef(err, "failed to parse CIDR from %s", hnsNetwork.Subnets[0].AddressPrefix)
	}

	var ipVersion string
	if ipv4 := hnsEndpoint.IPAddress.To4(); ipv4 != nil {
		ipVersion = "4"
	} else if ipv6 := hnsEndpoint.IPAddress.To16(); ipv6 != nil {
		ipVersion = "6"
	} else {
		return nil, fmt.Errorf("IPAddress of HNSEndpoint %s isn't a valid ipv4 or ipv6 Address", hnsEndpoint.Name)
	}

	resultIPConfig := &current.IPConfig{
		Version: ipVersion,
		Address: net.IPNet{
			IP:   hnsEndpoint.IPAddress,
			Mask: ipSubnet.Mask,
		},
		Gateway: net.ParseIP(hnsEndpoint.GatewayAddress),
	}
	result := &current.Result{}
	result.Interfaces = []*current.Interface{resultInterface}
	result.IPs = []*current.IPConfig{resultIPConfig}
	result.DNS = types.DNS{
		Search:      strings.Split(hnsEndpoint.DNSSuffix, ","),
		Nameservers: strings.Split(hnsEndpoint.DNSServerList, ","),
	}

	return result, nil
}

func GenerateHcnEndpoint(epInfo *EndpointInfo, n *NetConf) (*hcn.HostComputeEndpoint, error) {
	hcnEndpoint, err := hcn.GetEndpointByName(epInfo.EndpointName)
	if err != nil && !hcn.IsNotFoundError(err) {
		return nil, errors.Annotatef(err, "failed to get endpoint %q", epInfo.EndpointName)
	}

	if hcnEndpoint != nil {
		if !strings.EqualFold(hcnEndpoint.HostComputeNetwork, epInfo.NetworkId) {
			if err = hcnEndpoint.Delete(); err != nil {
				return nil, errors.Annotatef(err, "failed to delete endpoint %s", epInfo.EndpointName)
			}
		} else {
			return nil, fmt.Errorf("HostComputeNetwork %s is already existed", epInfo.EndpointName)
		}
	}

	if n.LoopbackDSR {
		n.ApplyLoopbackDSR(&epInfo.IpAddress)
	}
	hcnEndpoint = &hcn.HostComputeEndpoint{
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		Name:               epInfo.EndpointName,
		HostComputeNetwork: epInfo.NetworkId,
		Dns: hcn.Dns{
			Domain:     epInfo.DNS.Domain,
			Search:     epInfo.DNS.Search,
			ServerList: epInfo.DNS.Nameservers,
			Options:    epInfo.DNS.Options,
		},
		Routes: []hcn.Route{
			{
				NextHop:           GetIpString(&epInfo.Gateway),
				DestinationPrefix: GetDefaultDestinationPrefix(&epInfo.Gateway),
			},
		},
		IpConfigurations: []hcn.IpConfig{
			{
				IpAddress: GetIpString(&epInfo.IpAddress),
			},
		},
		Policies: func() []hcn.EndpointPolicy {
			if n.HcnPolicies == nil {
				n.HcnPolicies = []hcn.EndpointPolicy{}
			}
			return n.HcnPolicies
		}(),
	}
	return hcnEndpoint, nil
}

type HcnEndpointMakerFunc func() (*hcn.HostComputeEndpoint, error)

func AddHcnEndpoint(epName string, expectedNetworkId string, namespace string, makeEndpoint HcnEndpointMakerFunc) (*hcn.HostComputeEndpoint, error) {
	hcnEndpoint, err := hcn.GetEndpointByName(epName)
	if err != nil {
		if !hcn.IsNotFoundError(err) {
			return nil, errors.Annotatef(err, "failed to find HostComputeEndpoint %s", epName)
		}
	}

	// Check if endpoint already exists
	if hcnEndpoint != nil {
		if !strings.EqualFold(hcnEndpoint.HostComputeNetwork, expectedNetworkId) {
			if err := hcnEndpoint.Delete(); err != nil {
				return nil, errors.Annotatef(err, "failed to delete corrupted HostComputeEndpoint %s", epName)
			}
			hcnEndpoint = nil
		}
	}

	// Create endpoint
	var isNewEndpoint bool
	if hcnEndpoint == nil {
		if hcnEndpoint, err = makeEndpoint(); err != nil {
			return nil, errors.Annotate(err, "failed to make a new HostComputeEndpoint")
		}
		if hcnEndpoint, err = hcnEndpoint.Create(); err != nil {
			return nil, errors.Annotate(err, "failed to create the new HostComputeEndpoint")
		}
		isNewEndpoint = true
	}

	err = hcn.AddNamespaceEndpoint(namespace, hcnEndpoint.Id)
	if err != nil {
		if isNewEndpoint {
			if err := RemoveHcnEndpoint(epName); err != nil {
				return nil, errors.Annotatef(err, "failed to remove the new HostComputeEndpoint %s after adding namespace %s failure", hcnEndpoint.Id, namespace)
			}
		}
		return nil, errors.Annotatef(err, "failed to attach HostComputeEndpoint %s to namespace %s", hcnEndpoint.Id, namespace)
	}
	return hcnEndpoint, nil
}

func RemoveHcnEndpoint(epName string) error {
	hcnEndpoint, err := hcn.GetEndpointByName(epName)
	if err != nil {
		if hcn.IsNotFoundError(err) {
			return nil
		}
		return errors.Annotatef(err, "failed to find HostComputeEndpoint %s", epName)
	}

	// TODO should we ignore the return error ?
	err = hcnEndpoint.Delete()
	if err != nil {
		return errors.Annotatef(err, "failed to remove HostComputeEndpoint %s", epName)
	}

	return nil
}

func ConstructHcnResult(hcnNetwork *hcn.HostComputeNetwork, hcnEndpoint *hcn.HostComputeEndpoint) (*current.Result, error) {
	resultInterface := &current.Interface{
		Name: hcnEndpoint.Name,
		Mac:  hcnEndpoint.MacAddress,
	}
	_, ipSubnet, err := net.ParseCIDR(hcnNetwork.Ipams[0].Subnets[0].IpAddressPrefix)
	if err != nil {
		return nil, err
	}

	var ipVersion string
	ipAddress := net.ParseIP(hcnEndpoint.IpConfigurations[0].IpAddress)
	if ipv4 := ipAddress.To4(); ipv4 != nil {
		ipVersion = "4"
	} else if ipv6 := ipAddress.To16(); ipv6 != nil {
		ipVersion = "6"
	} else {
		return nil, fmt.Errorf("IPAddress of HostComputeEndpoint %s isn't a valid ipv4 or ipv6 Address", hcnEndpoint.Name)
	}

	resultIPConfig := &current.IPConfig{
		Version: ipVersion,
		Address: net.IPNet{
			IP:   ipAddress,
			Mask: ipSubnet.Mask},
		Gateway: net.ParseIP(hcnEndpoint.Routes[0].NextHop),
	}
	result := &current.Result{}
	result.Interfaces = []*current.Interface{resultInterface}
	result.IPs = []*current.IPConfig{resultIPConfig}
	result.DNS = types.DNS{
		Search:      hcnEndpoint.Dns.Search,
		Nameservers: hcnEndpoint.Dns.ServerList,
	}

	return result, nil
}
