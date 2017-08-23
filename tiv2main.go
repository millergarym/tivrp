package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang/glog"
	"rsc.io/letsencrypt"

	_ "expvar"
	"net/http/httputil"
	_ "net/http/pprof"
)

var (
	bind     = flag.String("listen", ":https", "address to bind to (see -bind)")
	httpbind = flag.String("http-listen", ":http", "address to bind http to")
)

func main() {
	flag.Parse()

	go func() {
		// http.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
		// http.Handle("/debug/vars", expvar.Handler())
		http.HandleFunc("/", RedirectHttp2Https(*bind))
		glog.Infof("HTTP listening %s", *httpbind)
		e := http.ListenAndServe(*httpbind, nil)
		if e != nil {
			glog.Warningf("HTTP listener Error %v", e)
		}
	}()

	var m letsencrypt.Manager
	if err := m.CacheFile("letsencrypt.cache"); err != nil {
		glog.Fatal(err)
	}
	mux := http.NewServeMux()
	target, err := url.Parse("http://10.0.0.100/")
	if err != nil {
		glog.Errorf("url %v", err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
		targetQuery := target.RawQuery
	rp.Director = func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path[len("/tiv2/"):])
		glog.Infof("proxy path %v", req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	mux.Handle("/tiv2/", rp)

	svr := &http.Server{
		Addr: *bind,
		TLSConfig: &tls.Config{
			GetCertificate: m.GetCertificate,
		},
		Handler: mux,
	}
	flag.VisitAll(func(f *flag.Flag) {
		v := fmt.Sprint(f.Value)
		if f.DefValue == v {
			glog.Infof("(default)  -%s %v", f.Name, v)
		} else {
			glog.Infof("(set)      -%s %v", f.Name, v)
		}
	})
	err = svr.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func RedirectHttp2Https(httpsBind string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil || r.Host == "" {
			http.Error(w, "not found", 404)
			glog.Infof("Can't redirect %v", r)
			return
		}

		u := r.URL
		i := strings.Index(httpsBind, ":")
		if i != -1 {
			j := strings.Index(r.Host, ":")
			if j != -1 {
				u.Host = r.Host[:j] + (httpsBind)[i:]
			} else {
				u.Host = r.Host + (httpsBind)[i:]

			}
		} else {
			u.Host = r.Host
		}
		u.Scheme = "https"
		glog.Infof("Redirect to %s", u.String())
		http.Redirect(w, r, u.String(), 302)
	}
}
