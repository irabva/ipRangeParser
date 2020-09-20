package iprangeparser

import (
	"bytes"
	"errors"
	"net"
	"strings"
)

func isUnicastIP(ipString string) (bool, error){
	ip := net.ParseIP(ipString)
	if ip == nil {
		msg := ipString + " is not IP address"
		return false, errors.New(msg)
	}

	if ! ip.IsGlobalUnicast() {
		msg := ipString + " is not global unicast IP address"
		return false, errors.New(msg)
	}
	return true, nil
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
	splitted := strings.Split(ipsList, ",")
	for _, element := range splitted {
		element = strings.TrimSpace(element)
		if strings.Contains(element, "/") {
			if hosts, warning, err := expandCidrIntoIPs(element); err != nil {
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
		} else if strings.Contains(element, "-"){
			if hosts, warning, err := expandRangeIntoIPs(element); err != nil {
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
		} else {
			if is, err := isUnicastIP(element); err != nil {
				errs = append(errs, err)
			} else if is {
				ips = append(ips, element)
			}
		}
	}
	return ips, warnings, errs
}

