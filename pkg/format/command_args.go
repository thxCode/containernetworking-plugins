package format

import (
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
)

func GetCmdArgsString(args *skel.CmdArgs) string {
	var sb strings.Builder
	sb.WriteString("\n   container_id=")
	sb.WriteString(args.ContainerID)
	sb.WriteString("\n   net_namespace=")
	sb.WriteString(args.Netns)
	sb.WriteString("\n   interface_name=")
	sb.WriteString(args.IfName)
	sb.WriteString("\n   args=")
	sb.WriteString(args.Args)
	sb.WriteString("\n   path=")
	sb.WriteString(args.Path)
	sb.WriteString("\n   data=")
	sb.WriteString(string(args.StdinData))
	sb.WriteString("\n ")
	return sb.String()
}
