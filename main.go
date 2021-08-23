package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var filePath = "/tmp/dnsmasq.log.fifo"
var outputFile = "/tmp/dnsmasq.log.parsed.fifo"
var latestReport = make(chan string, 1)
var lastReport = ""

type AccessDetails struct {
	TimesAccessed int
	LastAccessed  time.Time
}

func main() {
	file, err := os.OpenFile(filePath, os.O_CREATE, os.ModeNamedPipe)
	if err != nil {
		fmt.Print(err)
		return
	}

	accessMap := map[string]map[string]AccessDetails{}
	// go writeToPipe(outputFile, latestReport)
	go handleRequests()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			fmt.Print(err)
			break
		}
		lineStr := string(line)
		if lineStr == "" {
			fmt.Print("empty line")
			continue
		}

		split := strings.Split(lineStr, " ")
		if len(split) < 10 {
			continue
		}
		// Aug 23 00:55:42 dnsmasq[32386]: 1316 192.168.2.198/49122 query[A] viktorbarzin.me from 192.168.2.198
		isQuery := strings.Contains(split[6], "query[A]")

		if !isQuery {
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

func writeToPipe(file string, values <-chan string) {
	for {
		f, _ := os.OpenFile(file, os.O_WRONLY, 0600)
		fmt.Printf("opened!\n")
		v := <-values
		fmt.Printf("Writing %s\n", v)
		f.WriteString(v)
		f.Sync()
		f.Close()
	}
}

func report(accessMap map[string]map[string]AccessDetails) string {
	str := strings.Builder{}
	for src, val := range accessMap {
		for host, accessDetails := range val {
			str.WriteString(fmt.Sprintf("%s,%s,%d\n", src, host, accessDetails.TimesAccessed))

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
	return entries > 100000
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
	select {
	case val := <-latestReport:
		report = val
		lastReport = report
	case <-time.After(100 * time.Millisecond):
		report = lastReport
	}
	fmt.Fprintf(w, report)
}

func handleRequests() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":9101", nil))
}
