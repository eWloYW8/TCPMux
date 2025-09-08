package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eWloYW8/TCPMux/config"
	"github.com/eWloYW8/TCPMux/server"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

type Server interface {
	GetActiveConnections() []server.ConnectionInfo
	CloseConnection(id string) bool
	GetRules() []config.Rule
	SetRuleEnabled(index int, enabled bool) bool
}

type Controller struct {
	server     Server
	config     *config.ControllerConfig
	logger     *zap.Logger
	httpServer *http.Server
	hub        *Hub
}

func NewController(s Server, cfg *config.ControllerConfig) *Controller {
	return &Controller{
		server: s,
		config: cfg,
		logger: zap.L().With(zap.String("module", "controller")),
		hub:    NewHub(),
	}
}

func (c *Controller) Start() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	router.Use(ginZapLogger(c.logger))
	router.Use(gin.Recovery())

	api := router.Group("/api")
	api.GET("/logs", c.getLogs)
	api.GET("/ws/logs", c.streamLogs)
	api.GET("/connections", c.getConnections)
	api.POST("/connections/:id/close", c.closeConnection)
	api.GET("/ws/connections", c.wsConnections)
	api.GET("/rules", c.getRules)
	api.POST("/rules/:index/toggle/:enabled", c.toggleRule)

	c.httpServer = &http.Server{
		Addr:    c.config.Listen,
		Handler: router,
	}

	go c.hub.run(c.server)

	c.logger.Info("Starting controller API server", zap.String("listen_addr", c.config.Listen))
	if err := c.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		c.logger.Fatal("Failed to start API server", zap.Error(err))
	}
}

func (c *Controller) Stop(ctx context.Context) {
	if c.httpServer != nil {
		c.httpServer.Shutdown(ctx)
	}
}

func ginZapLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		end := time.Now()
		latency := end.Sub(start)

		if len(c.Errors) > 0 {
			errs := make([]error, len(c.Errors))
			for i, e := range c.Errors {
				errs[i] = e
			}
			logger.Error("Request Error",
				zap.Int("status", c.Writer.Status()),
				zap.String("method", c.Request.Method),
				zap.String("path", path),
				zap.String("query", query),
				zap.String("ip", c.ClientIP()),
				zap.String("user-agent", c.Request.UserAgent()),
				zap.Duration("latency", latency),
				zap.Errors("errors", errs),
			)
		} else {
			logger.Info("Request Handled",
				zap.Int("status", c.Writer.Status()),
				zap.String("method", c.Request.Method),
				zap.String("path", path),
				zap.String("query", query),
				zap.String("ip", c.ClientIP()),
				zap.String("user-agent", c.Request.UserAgent()),
				zap.Duration("latency", latency),
			)
		}
	}
}

func (c *Controller) getLogs(ctx *gin.Context) {
	logFilePath := c.getLogFilePath()
	if logFilePath == "" {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Log file path not configured"})
		return
	}

	content, err := os.ReadFile(logFilePath)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read log file"})
		return
	}

	ctx.Header("Content-Type", "text/plain")
	ctx.String(http.StatusOK, string(content))
}

func (c *Controller) getLogFilePath() string {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		return ""
	}
	return cfg.Logging.File
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (c *Controller) streamLogs(ctx *gin.Context) {
	conn, err := upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
	if err != nil {
		c.logger.Error("Failed to upgrade websocket", zap.Error(err))
		return
	}
	defer conn.Close()

	logFilePath := c.getLogFilePath()
	if logFilePath == "" {
		conn.WriteMessage(websocket.TextMessage, []byte("Log file path not configured"))
		return
	}

	file, err := os.Open(logFilePath)
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("Failed to open log file"))
		return
	}
	defer file.Close()

	var lastSize int64
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		info, err := file.Stat()
		if err != nil {
			c.logger.Error("Failed to stat log file", zap.Error(err))
			return
		}

		currentSize := info.Size()
		if currentSize > lastSize {
			newBytes := make([]byte, currentSize-lastSize)
			file.Seek(lastSize, 0)
			if _, err := file.Read(newBytes); err == nil {
				lines := strings.Split(string(newBytes), "\n")
				for _, line := range lines {
					if line != "" {
						conn.WriteMessage(websocket.TextMessage, []byte(line))
					}
				}
			}
			lastSize = currentSize
		}
	}
}

func (c *Controller) getConnections(ctx *gin.Context) {
	connections := c.server.GetActiveConnections()
	ctx.JSON(http.StatusOK, connections)
}

func (c *Controller) closeConnection(ctx *gin.Context) {
	id := ctx.Param("id")
	if c.server.CloseConnection(id) {
		ctx.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Connection %s closed", id)})
	} else {
		ctx.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Connection %s not found", id)})
	}
}

type jsonRule struct {
	Index       int         `json:"index"`
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	TLSRequired bool        `json:"tls_required"`
	Parameter   interface{} `json:"parameter"`
	Handler     interface{} `json:"handler"`
	Enabled     bool        `json:"enabled"`
}

func (c *Controller) getRules(ctx *gin.Context) {
	rules := c.server.GetRules()
	jsonRules := make([]jsonRule, len(rules))
	for i, r := range rules {
		var parameter interface{}
		r.Parameter.Decode(&parameter)

		var handlerParameter interface{}
		r.Handler.Parameter.Decode(&handlerParameter)

		jsonRules[i] = jsonRule{
			Index:       i,
			Name:        r.Name,
			Type:        r.Type,
			TLSRequired: r.TLSRequired,
			Parameter:   parameter,
			Handler: struct {
				Name      string      `json:"name"`
				Type      string      `json:"type"`
				Parameter interface{} `json:"parameter"`
			}{
				Name:      r.Handler.Name,
				Type:      r.Handler.Type,
				Parameter: handlerParameter,
			},
			Enabled: r.Enabled,
		}
	}

	ctx.JSON(http.StatusOK, jsonRules)
}

func (c *Controller) toggleRule(ctx *gin.Context) {
	indexStr := ctx.Param("index")
	enabledStr := ctx.Param("enabled")

	index, err := strconv.Atoi(indexStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule index"})
		return
	}

	enabled, err := strconv.ParseBool(enabledStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid enabled parameter. Use 'true' or 'false'."})
		return
	}

	if c.server.SetRuleEnabled(index, enabled) {
		ctx.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Rule %d enabled state set to %t", index, enabled)})
	} else {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
	}
}

type Hub struct {
	clients    map[*Client]bool
	register   chan *Client
	unregister chan *Client
	broadcast  chan []byte
	mu         sync.Mutex
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan []byte),
	}
}

func (h *Hub) run(s Server) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			zap.L().Info("New WebSocket connection registered for connections stream", zap.String("client_addr", client.conn.RemoteAddr().String()))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			zap.L().Info("WebSocket client unregistered for connections stream", zap.String("client_addr", client.conn.RemoteAddr().String()))

		case <-ticker.C:
			connections := s.GetActiveConnections()
			data, err := json.Marshal(connections)
			if err != nil {
				zap.L().Error("Failed to marshal connections data", zap.Error(err))
				continue
			}
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- data:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()
		}
	}
}

type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

func (c *Controller) wsConnections(ctx *gin.Context) {
	conn, err := upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
	if err != nil {
		c.logger.Error("Failed to upgrade websocket", zap.Error(err))
		return
	}

	client := &Client{hub: c.hub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client

	go func() {
		defer func() {
			c.hub.unregister <- client
			conn.Close()
		}()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					c.logger.Error("WebSocket read error", zap.Error(err))
				}
				break
			}
		}
	}()

	for message := range client.send {
		if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
			break
		}
	}
}
