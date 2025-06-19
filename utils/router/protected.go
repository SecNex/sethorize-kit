package router

import (
	"net/http"

	"github.com/gorilla/mux"
)

type ProtectedRouter struct {
	Router *mux.Router
}

type RouteHandler func(w http.ResponseWriter, r *http.Request)

type Route struct {
	Path    string
	Handler RouteHandler
	Method  string
}

func NewProtectedRouter() *ProtectedRouter {
	return &ProtectedRouter{
		Router: mux.NewRouter(),
	}
}

func NewRoute(path string, handler RouteHandler, method string) Route {
	return Route{
		Path:    path,
		Handler: handler,
		Method:  method,
	}
}

func (r *ProtectedRouter) RegisterRoutes(routes []Route) {
	for _, route := range routes {
		r.Router.HandleFunc(route.Path, route.Handler).Methods(route.Method)
	}
}
