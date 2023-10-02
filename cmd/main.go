package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

type Endpoint struct {
	Path    string `yaml:"path"`
	Method  string `yaml:"method"`
	Handler string `yaml:"handler"`
	OIDC    OIDC   `yaml:"oidc"`
}

type OIDC struct {
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

type Config struct {
	Endpoints []Endpoint `yaml:"endpoints"`
}

type Server struct {
	router *mux.Router
}

func NewServer() *Server {
	return &Server{
		router: mux.NewRouter(),
	}
}

func (s *Server) RegisterEndpoint(endpoint Endpoint) error {
	handlerFunc, err := getHandlerFunc(endpoint.Handler, endpoint.OIDC)
	if err != nil {
		return err
	}

	s.router.HandleFunc(endpoint.Path, handlerFunc).Methods(endpoint.Method)

	return nil
}

func (s *Server) Start() error {
	fmt.Println("Listening on port 8080...")
	err := http.ListenAndServe(":8080", s.router)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	// Load the YAML configuration file
	configBytes, err := ioutil.ReadFile("./config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	var config Config
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new server
	server := NewServer()

	// Register each endpoint with the server
	for _, endpoint := range config.Endpoints {
		err := server.RegisterEndpoint(endpoint)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Start the server
	err = server.Start()
	if err != nil {
		log.Fatal(err)
	}
}

func getHandlerFunc(handlerName string, oidcConfig OIDC) (func(http.ResponseWriter, *http.Request), error) {
	switch handlerName {
	case "handleHello":
		return func(w http.ResponseWriter, r *http.Request) {
			// Create an OIDC verifier using the provided configuration
			ctx := context.Background()
			provider, err := oidc.NewProvider(ctx, oidcConfig.Issuer)
			if err != nil {
				http.Error(w, "Failed to create OIDC provider", http.StatusInternalServerError)
				return
			}

			verifier := provider.Verifier(&oidc.Config{ClientID: oidcConfig.ClientID})

			// Verify the ID token in the Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header missing", http.StatusUnauthorized)
				return
			}

			idTokenStr := authHeader[len("Bearer "):]
			idToken, err := verifier.Verify(ctx, idTokenStr)
			if err != nil {
				http.Error(w, "Failed to verify ID token", http.StatusUnauthorized)
				return
			}

			// Get the user's email address from the ID token
			email := idToken.Claims("email")

			// Write a response with the user's email address
			fmt.Fprintf(w, "Hello, %s!", email)
		}, nil
	default:
		return nil, fmt.Errorf("handler function not found: %s", handlerName)
	}
}
