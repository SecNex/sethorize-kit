package middleware

import (
	"fmt"
	"net/http"
	"time"
)

type HTTPLogger struct{}

func NewHTTPLogger() *HTTPLogger {
	return &HTTPLogger{}
}

// ResponseWriter wrapper to capture status code and content length
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	contentLength int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	if lrw.statusCode == 0 {
		lrw.statusCode = 200
	}
	size, err := lrw.ResponseWriter.Write(b)
	lrw.contentLength += size
	return size, err
}

// LoggingMiddleware erstellt eine Middleware, die HTTP-Requests im Apache-Format loggt
func (hl *HTTPLogger) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrapper für Response Writer
		lrw := &loggingResponseWriter{
			ResponseWriter: w,
			statusCode:     0,
			contentLength:  0,
		}

		// Request verarbeiten
		next.ServeHTTP(lrw, r)

		// Apache-Log-Format: IP - - [timestamp] "METHOD /path HTTP/1.1" status_code content_length "referer" "user_agent"
		clientIP := r.RemoteAddr
		if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			clientIP = forwardedFor
		}
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			clientIP = realIP
		}

		method := r.Method
		uri := r.RequestURI
		if uri == "" {
			uri = r.URL.RequestURI()
		}
		protocol := r.Proto
		statusCode := lrw.statusCode
		if statusCode == 0 {
			statusCode = 200
		}
		contentLength := lrw.contentLength
		referer := r.Header.Get("Referer")
		if referer == "" {
			referer = "-"
		}
		userAgent := r.Header.Get("User-Agent")
		if userAgent == "" {
			userAgent = "-"
		}

		// Zeitstempel hinzufügen und Apache-Format loggen
		timestamp := time.Now().Format("2006/01/02 15:04:05")
		logLine := fmt.Sprintf(`%s %s - - "%s %s %s" %d %d "%s" "%s" %v`,
			timestamp,
			clientIP,
			method,
			uri,
			protocol,
			statusCode,
			contentLength,
			referer,
			userAgent,
			time.Since(start),
		)

		fmt.Println(logLine)
	})
}
