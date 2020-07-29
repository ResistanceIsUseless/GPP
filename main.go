package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/genkiroid/cert"
)
func main() {
	var subdomain string
	//flag.StringVar(&subdomain, "s", "", "Subdomain")
	//flag.StringVar(&subdomain, "subdomain", "", "Subdomain")
	var Subdomains string
	flag.StringVar(&Subdomains, "S", "", "Subdomains")
	flag.StringVar(&Subdomains, "Subdomains", "", "Subdomains")
	//var PHeaders bool
	//flag.BoolVar(&PHeaders, "P", false, "")
	//flag.BoolVar(&PHeaders, "Printheaders", false, "")
	flag.Parse()

	//read file for subdomains
	file, err := os.Open(Subdomains)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	//send file to NewScanner to read each line
	scanner := bufio.NewScanner(file)
	ports := []string{"8080", "80", "443", "1080", "5836", "999", "38801", "53281", "8118", "8888", "9999", "7071", "8081", "8443"}
	//iterate each line of the file to send each subdomain as a new request
	for scanner.Scan() {
		subdomain = scanner.Text()
		if strings.Contains(subdomain, ":") {
			SplitSub := strings.Split(subdomain, ":")
			subdomain = SplitSub[0]
			SinPort := SplitSub[1]
			clientRequest(subdomain, SinPort)
		} else {
			for _, port := range ports {
				clientRequest(subdomain, port)
			}
		}
	}
}
func clientRequest(host string, port string){
	var timeout = 5 * time.Second
	HostPort := net.JoinHostPort(host, port)
	time.Sleep(2 * time.Second)
	_, err := net.DialTimeout("tcp", HostPort, timeout)
	if err != nil {
		//fmt.Println("TCP Failure",HostPort)
	} else {
		//fmt.Println("TCP Success",HostPort)
		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
		time.Sleep(1 * time.Second)
		HTTPSreq, err := http.NewRequest("GET", "https://"+HostPort, nil)
		HTTPSreq.Header.Set("User-Agent", "Mozilla/5.0 (X11; U; Linux i686; rv:1.7.3) Gecko/20040914 Firefox/0.10.1")
		HTTPSResp, err := client.Do(HTTPSreq)

		//If port doesnt accept HTTPS and fails try standard HTTP Request
		if err != nil {
			client := &http.Client{
				Timeout: 5 * time.Second,
			}
			time.Sleep(1 * time.Second)
			HTTPreq, err := http.NewRequest("GET", "http://"+HostPort, nil)
			HTTPreq.Header.Set("User-Agent", "Mozilla/5.0 (X11; U; Linux i686; rv:1.7.3) Gecko/20040914 Firefox/0.10.1")
			HTTPresp, err := client.Do(HTTPreq)
			if err != nil {
				//fmt.Println("HTTP Failure")
				return
			}
			defer HTTPresp.Body.Close()
			//If HTTP is successful no rea
			//fmt.Println("HTTP Success")
			fmt.Println(HostPort, "["+HTTPresp.Status+"]", HTTPresp.Header["Server"])
			ProxyCheck("HTTP://",HostPort)
		} else {
			cert.SkipVerify = true
			defer HTTPSResp.Body.Close()
			Cert := cert.NewCert(HostPort)
			//fmt.Println("HTTPS Success")
			fmt.Println(HostPort, "["+HTTPSResp.Status+"]", HTTPSResp.Header["Server"], Cert.CommonName, Cert.SANs)
			ProxyCheck("HTTPS://",HostPort)
		}
	}
}


func ProxyCheck(proto string, hostport string) {

	proxyURL, err := url.Parse(proto + hostport)
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	if err != nil {
		log.Fatalln(err)
	}
	//
	req, err := http.NewRequest("GET", "http://canhazip.com/", nil)
	if err != nil {
		log.Fatalln(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; U; Linux i686; rv:1.7.3) Gecko/20040914 Firefox/0.10.1")
	//req.Header.Set("X-Forwarded-To", "169.254.169.254")
	time.Sleep(1 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	if string(resp.StatusCode) != "400" {
		headers, _ := httputil.DumpResponse(resp, false)
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalln(err)
		}

		//hacky method but will work for now. Better to create function that compares two requests before and after proxy
		//
		if len(bodyBytes) < 16 {
			fmt.Println(proxyURL, "["+resp.Status+"]", resp.Header["Server"], "Proxy Success")
		} else {
			fmt.Println(proxyURL, "["+resp.Status+"]", resp.Header["Server"], "Response Size:", len(bodyBytes))
			fmt.Println(string(headers))
		}

	}

}
