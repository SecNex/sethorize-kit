package server

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type ServerOptions struct {
	Host string
	Port int
}

type Server struct {
	Options ServerOptions
	Router  *mux.Router
}

func NewServer(host string, port int) *Server {
	router := mux.NewRouter()

	return &Server{
		Options: ServerOptions{
			Host: host,
			Port: port,
		},
		Router: router,
	}
}

func (s *Server) Start() {
	log.Printf("Starting server on http://%s:%d...", s.Options.Host, s.Options.Port)
	http.ListenAndServe(fmt.Sprintf("%s:%d", s.Options.Host, s.Options.Port), s.Router)
}
