package tcp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/rs/zerolog"
)

var log zerolog.Logger

func SetLogger(l zerolog.Logger) { log = l }

// Do - http.Client with support Digest Authorization
func Do(req *http.Request) (*http.Response, error) {
	log.Trace().Str("method", req.Method).Str("url", req.URL.String()).Msg("[tcp] http request")

	var secure *tls.Config

	switch req.URL.Scheme {
	case "httpx":
		log.Debug().Str("url", req.URL.String()).Msg("[tcp] httpx scheme: forcing insecure TLS")
		secure = insecureConfig
		req.URL.Scheme = "https"
	case "https":
		if hostname := req.URL.Hostname(); IsIP(hostname) {
			log.Debug().Str("host", hostname).Msg("[tcp] https with IP address: using insecure TLS")
			secure = insecureConfig
		}
	}

	if secure != nil {
		ctx := context.WithValue(req.Context(), secureKey, secure)
		req = req.WithContext(ctx)
	}

	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()

		dial := transport.DialContext
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Trace().Str("network", network).Str("addr", addr).Msg("[tcp] dial")
			conn, err := dial(ctx, network, addr)
			if err != nil {
				log.Error().Err(err).Str("addr", addr).Msg("[tcp] dial failed")
			}
			if pconn, ok := ctx.Value(connKey).(*net.Conn); ok {
				*pconn = conn
			}
			return conn, err
		}
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Trace().Str("network", network).Str("addr", addr).Msg("[tcp] TLS dial")
			conn, err := dial(ctx, network, addr)
			if err != nil {
				log.Error().Err(err).Str("addr", addr).Msg("[tcp] TLS dial failed")
				return nil, err
			}

			var conf *tls.Config
			if v, ok := ctx.Value(secureKey).(*tls.Config); ok {
				log.Trace().Str("addr", addr).Msg("[tcp] using insecure TLS config")
				conf = v
			} else if host, _, err := net.SplitHostPort(addr); err != nil {
				conf = &tls.Config{ServerName: addr}
			} else {
				conf = &tls.Config{ServerName: host}
			}

			tlsConn := tls.Client(conn, conf)
			if err = tlsConn.Handshake(); err != nil {
				// retry with TLS 1.2 for cameras that don't support TLS 1.3
				log.Warn().Err(err).Str("addr", addr).Msg("[tcp] TLS 1.3 handshake failed, retrying with TLS 1.2")
				_ = tlsConn.Close()
				conn, err = dial(ctx, network, addr)
				if err != nil {
					log.Error().Err(err).Str("addr", addr).Msg("[tcp] reconnect failed before TLS 1.2 retry")
					return nil, err
				}
				conf12 := conf.Clone()
				conf12.MaxVersion = tls.VersionTLS12
				tlsConn = tls.Client(conn, conf12)
				if err = tlsConn.Handshake(); err != nil {
					log.Error().Err(err).Str("addr", addr).Msg("[tcp] TLS 1.2 handshake failed")
					return nil, err
				}
				log.Info().Str("addr", addr).Msg("[tcp] TLS 1.2 handshake succeeded")
			} else {
				log.Trace().Str("addr", addr).Msg("[tcp] TLS handshake succeeded")
			}

			if pconn, ok := ctx.Value(connKey).(*net.Conn); ok {
				*pconn = tlsConn
			}
			return tlsConn, err
		}

		client = &http.Client{Transport: transport}
	}

	user := req.URL.User

	// Hikvision won't answer on Basic auth with any headers
	if strings.HasPrefix(req.URL.Path, "/ISAPI/") {
		req.URL.User = nil
	}

	res, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Str("url", req.URL.String()).Msg("[tcp] http request failed")
		return nil, err
	}

	log.Debug().Int("status", res.StatusCode).Str("url", req.URL.String()).Msg("[tcp] http response")

	if res.StatusCode == http.StatusUnauthorized && user != nil {
		log.Debug().Str("url", req.URL.String()).Msg("[tcp] 401 unauthorized, attempting Digest auth")
		Close(res)

		auth := res.Header.Get("WWW-Authenticate")
		if !strings.HasPrefix(auth, "Digest") {
			log.Error().Str("auth", auth).Msg("[tcp] unsupported auth scheme")
			return nil, errors.New("unsupported auth: " + auth)
		}

		realm := Between(auth, `realm="`, `"`)
		nonce := Between(auth, `nonce="`, `"`)
		qop := Between(auth, `qop="`, `"`)

		username := user.Username()
		password, _ := user.Password()
		ha1 := HexMD5(username, realm, password)

		uri := req.URL.RequestURI()
		ha2 := HexMD5(req.Method, uri)

		var header string

		switch qop {
		case "":
			log.Trace().Str("realm", realm).Msg("[tcp] Digest auth without qop")
			response := HexMD5(ha1, nonce, ha2)
			header = fmt.Sprintf(
				`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
				username, realm, nonce, uri, response,
			)
		case "auth":
			log.Trace().Str("realm", realm).Msg("[tcp] Digest auth with qop=auth")
			nc := "00000001"
			cnonce := core.RandString(32, 64)
			response := HexMD5(ha1, nonce, nc, cnonce, qop, ha2)
			header = fmt.Sprintf(
				`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"`,
				username, realm, nonce, uri, qop, nc, cnonce, response,
			)
		default:
			log.Error().Str("qop", qop).Msg("[tcp] unsupported Digest qop")
			return nil, errors.New("unsupported qop: " + auth)
		}

		req.Header.Set("Authorization", header)

		if res, err = client.Do(req); err != nil {
			log.Error().Err(err).Str("url", req.URL.String()).Msg("[tcp] http request with Digest auth failed")
			return nil, err
		}

		log.Debug().Int("status", res.StatusCode).Str("url", req.URL.String()).Msg("[tcp] http response after Digest auth")
	}

	return res, nil
}

var client *http.Client

type key string

var connKey = key("conn")
var secureKey = key("secure")

var insecureConfig = &tls.Config{
	InsecureSkipVerify: true,
	CipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,

		// this cipher suites disabled starting from https://tip.golang.org/doc/go1.22
		// but cameras can't work without them https://github.com/AlexxIT/go2rtc/issues/1172
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // insecure
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384, // insecure
	},
}

func WithConn() (context.Context, *net.Conn) {
	pconn := new(net.Conn)
	return context.WithValue(context.Background(), connKey, pconn), pconn
}

func Close(res *http.Response) {
	if res.Body != nil {
		_ = res.Body.Close()
	}
}

func IsIP(hostname string) bool {
	return net.ParseIP(hostname) != nil
}
