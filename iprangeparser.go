package iprangeparser

import (
	"bytes"
	"errors"
	"net"
	"strings"
)
func removeDuplicateValues(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func isUnicastIP(ipString string) ([]string, []string, error){
	ip := net.ParseIP(ipString)
	if ip == nil {
		msg := ipString + " is not IP address"
		return nil, nil, errors.New(msg)
	}

	if ! ip.IsGlobalUnicast() {
		msg := ipString + " is not global unicast IP address"
		return nil, []string{msg}, nil
	}
	return []string{ipString}, nil, nil
}

//from github.com/kotakanbe/go-pingscanner
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

//from github.com/kotakanbe/go-pingscanner, updated
func expandCidrIntoIPs(cidr string) ([]string, []string, error) {
	var warnings []string
	splitted := strings.Split(cidr, "/")
	if len(splitted) == 1 || splitted[1] == "32" {
		ip := net.ParseIP(splitted[0])
		if ip == nil {
			msg := splitted[0] + " is not IP address"
			return nil, nil, errors.New(msg)
		}
		if ip.IsGlobalUnicast() {
			return []string{splitted[0]}, nil, nil
		}
		warnings = append(warnings, splitted[0] + " is not global unicast IP address")
		return nil, warnings, nil

	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		if ip.IsGlobalUnicast() {
			ips = append(ips, ip.String())
		} else {
			warnings = append(warnings, ip.String() + " is not global unicast IP address")
		}
	}
	// remove network address and broadcast address
	if len(ips) > 0 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, warnings, nil
}

func expandRangeIntoIPs(ran string) ([]string, []string, error)  {
	var warnings []string
	splitted := strings.Split(ran, "-")
	if len(splitted) != 2 {
		msg := ran + " is not range"
		return nil, nil, errors.New(msg)
	}
	first := net.ParseIP(splitted[0])
	if first == nil {
		msg := splitted[0] + " is not IP address"
		return nil, nil, errors.New(msg)
	}
	last := net.ParseIP(splitted[1])
	if last == nil {
		msg := splitted[1] + " is not IP address"
		return nil, nil, errors.New(msg)
	}

	var ips []string
	for ip := first; bytes.Compare(ip, first) >= 0 && bytes.Compare(ip, last) <= 0; inc(ip) {
		if ip.IsGlobalUnicast() {
			ips = append(ips, ip.String())
		} else {
			warnings = append(warnings, ip.String() + " is not global unicast IP address")
		}
	}
	return ips, warnings, nil

}

//Parce string to ip adresses list
func ParceIPs(ipsList string) ([]string, []string, []error)  {
	var errs []error
	var ips []string
	var warnings []string
	usedFunctions := map[string]func(string) ([]string, []string, error) {
		"cidr": expandCidrIntoIPs,
		"range": expandRangeIntoIPs,
		"ip": isUnicastIP,
	}
	splitted := strings.Split(ipsList, ",")
	for _, element := range splitted {
		var elementType string
		element = strings.TrimSpace(element)
		if strings.Contains(element, "/") {
			elementType = "cidr"
		} else if strings.Contains(element, "-") {
			elementType = "range"
		} else {
			elementType = "ip"
		}
		hosts, warning, err := usedFunctions[elementType](element)
		if err != nil {
			errs = append(errs, err)
		} else {
			if warning != nil {
				for _, msg := range warning{
					warnings = append(warnings, msg)
				}
			}
			for _, host := range hosts {
				ips = append(ips, host)
			}
		}
	}
	ips = removeDuplicateValues(ips)
	return ips, warnings, errs
}

