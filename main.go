package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/mpetavy/common"
	"net/http"
	"os"
	"time"
)

var (
	dir      = flag.String("d", "", "directory to serve")
	port     = flag.Int("c", 1234, "port to serve the directory")
	username = flag.String("u", "", "username")
	password = flag.String("p", "", "password")
	certFile *os.File
	keyFile  *os.File
)

func init() {
	common.Init("1.0.0", "", "", "2017", "simple HTTPS download service", "mpetavy", fmt.Sprintf("https://github.com/mpetavy/%s", common.Title()), common.APACHE, nil, start, nil, nil, 0)
}

type application struct {
	auth struct {
		username string
		password string
	}
}

func start() error {
	app := new(application)

	app.auth.username = *username
	app.auth.password = *password

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.basicAuth(http.FileServer(http.Dir(*dir)).ServeHTTP))

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	tlsConfig, err := common.NewTlsConfigFromFlags()
	if common.Error(err) {
		return err
	}

	certPEM := common.CertificateAsPEM(&tlsConfig.Certificates[0])
	certBytes, _ := pem.Decode(certPEM)
	if certBytes == nil {
		return fmt.Errorf("cannot find PEM block with certificate")
	}

	certFile, err = common.CreateTempFile()
	if common.Error(err) {
		return err
	}

	err = os.WriteFile(certFile.Name(), certPEM, common.DefaultFileMode)
	if common.Error(err) {
		return err
	}

	keyPEM, err := common.PrivateKeyAsPEM(tlsConfig.Certificates[0].PrivateKey.(*ecdsa.PrivateKey))
	if common.Error(err) {
		return err
	}
	keyBytes, _ := pem.Decode(keyPEM)
	if keyBytes == nil {
		return fmt.Errorf("cannot find PEM block with key")
	}

	keyFile, err = common.CreateTempFile()
	if common.Error(err) {
		return err
	}

	err = os.WriteFile(keyFile.Name(), keyPEM, common.DefaultFileMode)
	if common.Error(err) {
		return err
	}

	common.Info("starting server on %s", srv.Addr)
	err = srv.ListenAndServeTLS(certFile.Name(), keyFile.Name())
	if common.Error(err) {
		return err
	}

	return nil
}

func (app *application) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(app.auth.username))
			expectedPasswordHash := sha256.Sum256([]byte(app.auth.password))

			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				common.Info("Successful login: %s %s", r.RemoteAddr, app.auth.username)

				next.ServeHTTP(w, r)
				return
			} else {
				common.Warn("Unsuccessful login: %s %s", r.RemoteAddr, app.auth.username)
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func main() {
	common.Run([]string{"d", "u", "p"})
}
