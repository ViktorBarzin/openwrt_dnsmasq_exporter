package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	dhcpLeasesFile = "/tmp/dhcp.leases"
	outputFile     = "/tmp/dnsmasq.log.parsed"
	filePath       = "/tmp/dnsmasq.log.fifo"
)

var latestReport = make(chan string, 1)
var lastReport = ""

type AccessDetails struct {
	TimesAccessed int
	LastAccessed  time.Time
}

func main() {
	accessMap := map[string]map[string]AccessDetails{}
	// go writeToPipe(outputFile, latestReport)
	go handleRequests()

	for {
		err := createFifo(filePath)
		if err != nil {
			fmt.Printf("failed creating fifo: %s", err)
			return
		}
		file, err := os.OpenFile(filePath, os.O_CREATE, os.ModeNamedPipe)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Starting processor")
		startProcessor(*file, outputFile, accessMap)
		file.Close()
		time.Sleep(time.Second * 2)
		fmt.Println("Restarting processor")
	}
}

// func writeToPipe(file string, values <-chan string) {
// 	for {
// 		f, _ := os.OpenFile(file, os.O_WRONLY, 0600)
// 		fmt.Printf("opened!\n")
// 		v := <-values
// 		fmt.Printf("Writing %s\n", v)
// 		f.WriteString(v)
// 		f.Sync()
// 		f.Close()
// 	}
// }

func startProcessor(inputFifo os.File, outputFile string, accessMap map[string]map[string]AccessDetails) {
	reader := bufio.NewReader(&inputFifo)
	processedLines := 0
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			fmt.Printf("%s\n", err)
			break
		}
		lineStr := string(line)
		if lineStr == "" {
			fmt.Println("empty line")
			continue
		}
		if processedLines%100 == 0 {
			fmt.Printf("DNS exporter processed %d lines\n", processedLines)
			processedLines += 1
		}

		split := strings.Fields(lineStr)
		if len(split) < 10 {
			fmt.Printf("Split less than 10: %s\n", split)
			continue
		}
		// Aug 23 00:55:42 dnsmasq[32386]: 1316 192.168.2.198/49122 query[A] viktorbarzin.me from 192.168.2.198
		isQuery := strings.Contains(split[6], "query[A]")

		if !isQuery {

			// fmt.Printf("Not query: %s\n", split[6])
			continue
		}
		now := time.Now()
		host := split[7]
		src := split[9]
		src = strings.Replace(src, "\n", "", -1)

		if _, ok := accessMap[src]; !ok {
			accessMap[src] = map[string]AccessDetails{host: {TimesAccessed: 0, LastAccessed: now}}
		}

		srcHosts, _ := accessMap[src]
		if _, ok := srcHosts[host]; !ok {
			srcHosts[host] = AccessDetails{}
		}
		srcHostsHost, _ := srcHosts[host]
		srcHosts[host] = AccessDetails{TimesAccessed: srcHostsHost.TimesAccessed + 1, LastAccessed: now}

		if shouldCleanUpLRU(accessMap) {
			deleteLRU(accessMap)
		}

		r := report(accessMap)
		// removed old value and insert new
		if len(latestReport) > 0 {
			<-latestReport
		}
		latestReport <- r
	}
}

func report(accessMap map[string]map[string]AccessDetails) string {
	ipLeases := getDHCPLeases()
	str := strings.Builder{}
	for src, val := range accessMap {
		for host, accessDetails := range val {
			lease, ok := ipLeases[src]
			if !ok {
				// fmt.Printf("No lease for %s in %+v", src, ipLeases)
				// fmt.Printf("Error opening leases file: %s", err)
			}
			kek := fmt.Sprintf("%s,%s,%d,%s,%s,%s,%d\n",
				src,
				host,
				accessDetails.TimesAccessed,
				lease.ClientMac,
				lease.ClientHostname,
				lease.ClientUID,
				lease.ExpirationTime,
			)
			str.WriteString(
				kek,
			)

		}
	}
	return str.String()
}

func shouldCleanUpLRU(accessMap map[string]map[string]AccessDetails) bool {
	entries := 0
	for _, hosts := range accessMap {
		for range hosts {
			entries += 1
		}
	}
	return entries > 750
}

func deleteLRU(accessMap map[string]map[string]AccessDetails) {
	if len(accessMap) == 0 {
		return
	}

	earliestTS := time.Now().Add(time.Second) // in the future
	hostToDel := ""
	clientToDel := ""
	// iterate over all keys
	for client, hosts := range accessMap {
		for host, accessDetails := range hosts {
			if accessDetails.LastAccessed.Before(earliestTS) {
				earliestTS = accessDetails.LastAccessed
				clientToDel = client
				hostToDel = host
			}
		}
	}

	fmt.Printf("Deleting: %s %s", clientToDel, hostToDel)
	newMap := map[string]AccessDetails{}
	for host, accessDetails := range accessMap[clientToDel] {
		if host == hostToDel {
			continue
		}
		newMap[host] = accessDetails
	}
	accessMap[clientToDel] = newMap
}

func handler(w http.ResponseWriter, r *http.Request) {
	var report string
	// fmt.Println("handling scrape request")
	select {
	case val := <-latestReport:
		report = val
		lastReport = report
	case <-time.After(100 * time.Millisecond):
		report = lastReport
	}
	// fmt.Printf("Returning report %s\n", report)
	fmt.Fprintf(w, report)
}

func handleRequests() {
	fmt.Println("Starting web handler")
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":9101", nil))
}

func createFifo(filePath string) error {
	os.Remove(filePath)
	err := syscall.Mkfifo(filePath, 0666)
	return err
}

type DHCPLease struct {
	ExpirationTime int
	ClientMac      string
	ClientIP       string
	ClientHostname string
	ClientUID      string
}

func getDHCPLeases() map[string]DHCPLease {
	// return map[ip address]DHCPLease
	dhcpLeasesBytes, err := ioutil.ReadFile(dhcpLeasesFile)
	if err != nil {
		return map[string]DHCPLease{}
	}
	result := map[string]DHCPLease{}

	for _, line := range strings.Split(string(dhcpLeasesBytes), "\n") {
		if line == "" {
			continue
		}
		// line format:
		// <timestamp of lease expiration> <client mac> <client ip> <client name?> <client uid?>
		// 1631097413 b8:27:eb:de:b2:36 192.168.2.219 raspberrypi 01:b8:27:eb:de:b2:36
		splitLine := strings.Fields(line)
		if len(splitLine) != 5 {
			fmt.Printf("Invalid line in dhcp leases file (%s): %s", dhcpLeasesFile, line)
			continue
		}
		expirationTime, err := strconv.Atoi(splitLine[0])
		if err != nil {
			fmt.Printf("Invalid expiration time, skipping line: %s", line)
			continue
		}

		clientMac := splitLine[1]
		clientIP := splitLine[2]
		clientName := splitLine[3]
		clientUID := splitLine[4]
		result[clientIP] = DHCPLease{
			ExpirationTime: expirationTime,
			ClientMac:      clientMac,
			ClientIP:       clientIP,
			ClientHostname: clientName,
			ClientUID:      clientUID,
		}
	}
	return result
}
