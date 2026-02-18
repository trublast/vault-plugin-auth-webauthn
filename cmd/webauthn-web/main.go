package main

import (
	_ "embed"
	"io"
	"log"
	"net/http"
	"strings"
)

//go:embed index.html
var indexHTML []byte

const (
	addr         = ":8080"
	vaultURL     = "http://localhost:8200"
	vaultPrefix  = "/vault"
)

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc(vaultPrefix+"/", handleVaultProxy)
	log.Printf("Listening on http://localhost%s", addr)
	log.Printf("Vault proxy: %s -> %s", vaultPrefix, vaultURL)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func handleVaultProxy(w http.ResponseWriter, r *http.Request) {
	targetPath := strings.TrimPrefix(r.URL.Path, vaultPrefix)
	if targetPath == "" {
		targetPath = "/"
	}
	target := vaultURL + targetPath
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequest(r.Method, target, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req.Header = r.Header.Clone()
	req.ContentLength = r.ContentLength

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
