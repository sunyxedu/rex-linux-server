package main

import (
	"crypto/rand"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/creack/pty"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// --- Protocol types ---

// Envelope types for the rex.control.v1 WebSocket protocol.
// Client → Server: hello, request
// Server → Client: welcome, response, event, error

type HelloMsg struct {
	Type   string     `json:"type"` // "hello"
	Client HelloClient `json:"client"`
}

type HelloClient struct {
	Kind     string `json:"kind"`
	Platform string `json:"platform"`
	Name     string `json:"name"`
	Version  string `json:"version"`
}

type WelcomeMsg struct {
	Type     string       `json:"type"` // "welcome"
	Protocol string       `json:"protocol"`
	Limits   WelcomeLimits `json:"limits"`
	Client   WelcomeClient `json:"client"`
}

type WelcomeLimits struct {
	MaxMessageBytes int `json:"max_message_bytes"`
}

type WelcomeClient struct {
	ID             string `json:"id"`
	ReconnectToken string `json:"reconnect_token"`
}

type RequestMsg struct {
	Type    string          `json:"type"` // "request"
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type ResponseMsg struct {
	Type    string      `json:"type"` // "response"
	ID      string      `json:"id"`
	Seq     int64       `json:"seq"`
	Payload interface{} `json:"payload"`
}

type ErrorResponseMsg struct {
	Type  string       `json:"type"` // "response"
	ID    string       `json:"id"`
	Seq   int64        `json:"seq"`
	Error *RexAPIError `json:"error"`
}

type RexAPIError struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type EventMsg struct {
	Type    string      `json:"type"` // "event"
	Seq     int64       `json:"seq"`
	Payload interface{} `json:"payload"`
}

// --- Server state ---

var (
	serverHostID    = uuid.New().String()
	serverInstance  = uuid.New().String()
	serverStartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	serverPID       = os.Getpid()

	listenAddr = flag.String("listen", ":7297", "HTTP listen address")
	hostname   = flag.String("hostname", "", "Hostname for status display")
	accountName = flag.String("account", "", "Account name (default: current user)")
)

type Server struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	clients  map[string]*Client
	tickets  map[string]*DataTicket
	seqGen   atomic.Int64
}

type Session struct {
	ID      string
	Label   string
	Windows []*Window
	Blocks  map[string]*Block
	revision int64
}

type Window struct {
	ID             string
	Label          string
	FocusedBlockID string
	Layers         []*Layer
}

type Layer struct {
	ID     string
	Kind   string
	Layout *LayoutNode
	Blocks []*BlockRef
}

type LayoutNode struct {
	Rect    [4]float64 `json:"rect"`
	BlockID string     `json:"block_id,omitempty"`
	Split   string     `json:"split,omitempty"` // "horizontal" or "vertical"
	Ratio   float64    `json:"ratio,omitempty"`
	First   *LayoutNode `json:"first,omitempty"`
	Second  *LayoutNode `json:"second,omitempty"`
}

type BlockRef struct {
	BlockID     string `json:"block_id"`
	Label       string `json:"label"`
	CreatorName string `json:"creator_name"`
	Flavor      string `json:"flavor"`
	HostID      string `json:"host_id"`
	Owner       string `json:"owner"`
}

type Block struct {
	ID          string
	Label       string
	CreatorName string
	Flavor      string
	SessionID   string
	Owner       string

	// Terminal state
	ptmx     *os.File
	cmd      *exec.Cmd
	cols     int
	rows     int
	vt       *GhosttyTerminal       // libghostty-vt terminal emulator for snapshots
	dataSubs map[string]chan []byte // subscriber ID -> channel
	apcID    string                 // APC message ID (from data WELCOME last 8 bytes as LE uint64)
	mu       sync.Mutex
}

// sendAPC sends a Rex APC escape sequence on the data channel
func (b *Block) sendAPC(msgType string, payload interface{}) {
	if b.apcID == "" {
		return
	}
	data, _ := json.Marshal(payload)
	// Format: ESC _ rex1;APC_ID;{JSON} ESC \
	apc := fmt.Sprintf("\x1b_rex1;%s;%s\x1b\\", b.apcID, string(data))

	b.mu.Lock()
	for _, ch := range b.dataSubs {
		select {
		case ch <- []byte(apc):
		default:
		}
	}
	b.mu.Unlock()
}

type Client struct {
	ID        string
	Kind      string
	Platform  string
	Name      string
	Version   string
	AttachedSessions map[string]bool
	conn      *websocket.Conn
	writeMu   sync.Mutex // protects concurrent writes to conn
}

// writeJSON serializes writes to the WebSocket connection
func (c *Client) writeJSON(v interface{}) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.WriteJSON(v)
}

type DataTicket struct {
	Ticket    [16]byte
	SessionID string
	BlockID   string
	DataRefID string
	ClientID  string
	ExpiresAt time.Time
}

func NewServer() *Server {
	return &Server{
		sessions: make(map[string]*Session),
		clients:  make(map[string]*Client),
		tickets:  make(map[string]*DataTicket),
	}
}

// broadcastEvent sends an event to all connected clients
func (s *Server) broadcastEvent(event interface{}) {
	seq := s.nextSeq()
	msg := EventMsg{
		Type:    "event",
		Seq:     seq,
		Payload: event,
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.clients {
		if c.conn != nil {
			c.writeJSON(msg)
		}
	}
}

func (s *Server) broadcastSessionEvent(sessionID string, event interface{}) {
	s.broadcastEvent(map[string]interface{}{
		"type": "session_event",
		"payload": map[string]interface{}{
			"session_id": sessionID,
			"event":      event,
		},
	})
}

func (s *Server) nextSeq() int64 {
	return s.seqGen.Add(1)
}

func newID(prefix string) string {
	return fmt.Sprintf("%s:%s", prefix, uuid.New().String())
}

func randomToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- HTTP handlers ---

var upgrader = websocket.Upgrader{
	Subprotocols:    []string{"rex.control.v1"},
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  65536,
	WriteBufferSize: 65536,
}

var dataUpgrader = websocket.Upgrader{
	Subprotocols:    []string{"rex.data.terminal.v1"},
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  65536,
	WriteBufferSize: 65536,
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("control upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// Step 1: Read HELLO from client
	_, msg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("reading hello: %v", err)
		return
	}

	var hello HelloMsg
	if err := json.Unmarshal(msg, &hello); err != nil {
		log.Printf("parsing hello: %v", err)
		return
	}
	if hello.Type != "hello" {
		log.Printf("expected hello, got %s", hello.Type)
		return
	}

	clientID := newID("client")
	client := &Client{
		ID:               clientID,
		Kind:             hello.Client.Kind,
		Platform:         hello.Client.Platform,
		Name:             hello.Client.Name,
		Version:          hello.Client.Version,
		AttachedSessions: make(map[string]bool),
		conn:             conn,
	}

	s.mu.Lock()
	s.clients[clientID] = client
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, clientID)
		s.mu.Unlock()
	}()

	// Step 2: Send WELCOME
	welcome := WelcomeMsg{
		Type:     "welcome",
		Protocol: "rex.control.v1",
		Limits:   WelcomeLimits{MaxMessageBytes: 1048576},
		Client: WelcomeClient{
			ID:             clientID,
			ReconnectToken: randomToken(),
		},
	}
	if err := client.writeJSON(welcome); err != nil {
		log.Printf("writing welcome: %v", err)
		return
	}

	log.Printf("client connected: %s (%s/%s)", clientID, hello.Client.Name, hello.Client.Platform)

	// Note: client_connected events are sent only when bootstrap is called,
	// not on initial connection. Sending events before bootstrap confuses
	// CLI clients that don't expect events before their first request.

	// Step 3: Process requests
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("client disconnected: %s", clientID)
			} else {
				log.Printf("read error from %s: %v", clientID, err)
			}
			return
		}

		var req RequestMsg
		if err := json.Unmarshal(msg, &req); err != nil {
			log.Printf("parsing request: %v", err)
			continue
		}

		if req.Type != "request" {
			log.Printf("unexpected message type: %s", req.Type)
			continue
		}

		if req.Method == "block.method" || req.Method == "session.own_block" || req.Method == "data.connect" {
			log.Printf("request: %s %s payload=%s", req.ID, req.Method, string(req.Payload))
		} else {
			log.Printf("request: %s %s", req.ID, req.Method)
		}

		result, apiErr := s.handleMethod(req, client)
		if apiErr != nil {
			log.Printf("  -> ERROR %d %s: %s", apiErr.Status, apiErr.Code, apiErr.Message)
			resp := ErrorResponseMsg{
				Type:  "response",
				ID:    req.ID,
				Seq:   0,
				Error: apiErr,
			}
			client.writeJSON(resp)
		} else {
			// Log response payload for debugging (truncated)
			if respBytes, err := json.Marshal(result); err == nil {
				s := string(respBytes)
				if len(s) > 300 {
					s = s[:300] + "..."
				}
				log.Printf("  -> OK: %s", s)
			}
			resp := ResponseMsg{
				Type:    "response",
				ID:      req.ID,
				Seq:     0,
				Payload: result,
			}
			client.writeJSON(resp)
		}
	}
}

func (s *Server) handleMethod(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	switch req.Method {
	case "server.status":
		return s.serverStatus(), nil
	case "server.version":
		return s.serverVersion(), nil
	case "server.whoami":
		return s.serverWhoami(client), nil
	case "session.list":
		return s.sessionList(), nil
	case "session.bootstrap":
		return s.sessionBootstrap(req, client)
	case "session.attach_all":
		return s.sessionAttachAll(req, client)
	case "session.attach":
		return s.sessionAttach(req, client)
	case "session.view":
		return s.sessionView(req)
	case "session.create":
		return s.sessionCreate(req, client)
	case "session.destroy":
		return s.sessionDestroy(req)
	case "session.new_window":
		return s.sessionNewWindow(req, client)
	case "session.new_split":
		return s.sessionNewSplit(req, client)
	case "session.focus_block":
		return s.sessionFocusBlock(req)
	case "session.focus_window":
		return s.sessionFocusWindow(req)
	case "session.focus_next_window":
		return s.sessionFocusNextWindow(req)
	case "session.focus_previous_window":
		return s.sessionFocusPreviousWindow(req)
	case "session.set_label":
		return s.sessionSetLabel(req)
	case "session.set_window_label":
		return s.sessionSetWindowLabel(req)
	case "session.set_block_label":
		return s.sessionSetBlockLabel(req)
	case "session.close_window":
		return s.sessionCloseWindow(req)
	case "block.close":
		return s.blockClose(req)
	case "block.method":
		return s.blockMethod(req, client)
	case "block_creator.list":
		return s.blockCreatorList(), nil
	case "data.connect":
		return s.dataConnect(req, client)
	case "hosts.list":
		return map[string]interface{}{"hosts": []interface{}{}, "hash": ""}, nil
	case "client.list":
		return s.clientList(req)
	case "client.inspect":
		return s.clientInspect(req)
	case "client.set_label":
		return map[string]interface{}{}, nil
	case "client.set_script":
		return map[string]interface{}{}, nil
	case "client.keymap":
		return map[string]interface{}{"bindings": []interface{}{}, "warnings": []interface{}{}}, nil
	case "server.config_reload":
		return map[string]interface{}{}, nil
	case "session.own_block":
		return s.sessionOwnBlock(req, client)
	case "session.disown_block":
		return map[string]interface{}{}, nil
	case "session.list_blocks":
		return s.sessionListBlocks(req)
	case "session.list_clients":
		return map[string]interface{}{"clients": []interface{}{}}, nil
	case "session.move":
		return map[string]interface{}{}, nil
	case "session.move_window":
		return s.revisionResponse(req), nil
	case "session.swap_blocks":
		return s.revisionResponse(req), nil
	case "session.detach":
		return map[string]interface{}{}, nil
	case "session.describe_block":
		return s.sessionDescribeBlock(req)
	case "session.zoom_block":
		return s.revisionResponse(req), nil
	case "session.resize_pane":
		return s.revisionResponse(req), nil
	case "target.resolve":
		return s.targetResolve(req)
	case "target.complete":
		return map[string]interface{}{"completions": []interface{}{}}, nil
	case "block.event":
		log.Printf("block.event payload: %s", string(req.Payload))
		// Handle paste events from Rex.app
		var eventParams struct {
			SessionID string `json:"session_id"`
			BlockID   string `json:"block_id"`
			Event     struct {
				Type    string          `json:"type"`
				Payload json.RawMessage `json:"payload"`
			} `json:"event"`
		}
		if req.Payload != nil {
			json.Unmarshal(req.Payload, &eventParams)
		}
		if eventParams.Event.Type == "mouse" {
			var mouse struct {
				Action string `json:"action"`
				Button string `json:"button"`
				Mods   string `json:"mods"`
				X      int    `json:"x"`
				Y      int    `json:"y"`
			}
			json.Unmarshal(eventParams.Event.Payload, &mouse)
			s.mu.RLock()
			if sess, ok := s.sessions[eventParams.SessionID]; ok {
				if block, ok := sess.Blocks[eventParams.BlockID]; ok {
					if block.ptmx != nil {
						// Map button names to SGR button codes
						btn := 0
						switch mouse.Button {
						case "left": btn = 0
						case "middle": btn = 1
						case "right": btn = 2
						case "unknown": btn = 35 // motion without button
						}
						if mouse.Action == "motion" {
							btn += 32 // motion flag
						}
						// SGR encoding: [<btn;x;y M/m
						suffix := "M"
						if mouse.Action == "release" {
							suffix = "m"
						}
						seq := fmt.Sprintf("\x1b[<%d;%d;%d%s", btn, mouse.X+1, mouse.Y+1, suffix)
						block.ptmx.Write([]byte(seq))
					}
				}
			}
			s.mu.RUnlock()
		} else if eventParams.Event.Type == "paste" {
			var paste struct { Text string `json:"text"` }
			json.Unmarshal(eventParams.Event.Payload, &paste)
			if paste.Text != "" {
				s.mu.RLock()
				if sess, ok := s.sessions[eventParams.SessionID]; ok {
					if block, ok := sess.Blocks[eventParams.BlockID]; ok {
						if block.ptmx != nil {
							// Send with bracketed paste mode
							block.ptmx.Write([]byte("\x1b[200~"))
							block.ptmx.Write([]byte(paste.Text))
							block.ptmx.Write([]byte("\x1b[201~"))
							log.Printf("paste: wrote %d bytes to PTY", len(paste.Text))
						}
					}
				}
				s.mu.RUnlock()
			}
		}
		return map[string]interface{}{}, nil
	case "session.new_block":
		return s.sessionNewBlock(req, client)
	case "session.move_block":
		return s.revisionResponse(req), nil
	case "session.detach_block":
		return s.revisionResponse(req), nil
	case "session.float_block":
		return s.revisionResponse(req), nil
	case "session.close_layer":
		return s.revisionResponse(req), nil
	case "session.new_layer":
		return s.revisionResponse(req), nil
	case "session.raise_layer":
		return s.revisionResponse(req), nil
	case "session.lower_layer":
		return s.revisionResponse(req), nil
	case "session.resize_layer":
		return s.revisionResponse(req), nil
	case "session.focus_direction":
		return s.revisionResponse(req), nil
	case "session.focus_next_pane":
		return s.revisionResponse(req), nil
	case "session.focus_previous_pane":
		return s.revisionResponse(req), nil
	case "client.action":
		return map[string]interface{}{}, nil
	case "client.key":
		log.Printf("client.key payload: %s", string(req.Payload))
		return s.clientKey(req, client)
	case "client.perform":
		return map[string]interface{}{}, nil
	case "client.reply":
		return map[string]interface{}{}, nil
	case "server.tailscale.enable", "server.tailscale.disable", "server.tailscale.login", "server.tailscale.logout", "server.tailscale.rename":
		return map[string]interface{}{}, nil
	case "server.apple.grant_file_access":
		return map[string]interface{}{}, nil
	case "help.all":
		return s.helpAll(), nil
	default:
		log.Printf("unhandled method: %s", req.Method)
		return nil, &RexAPIError{
			Status:  404,
			Code:    "not_found",
			Message: fmt.Sprintf("unknown method %q", req.Method),
		}
	}
}

// --- Method implementations ---

func (s *Server) serverStatus() interface{} {
	s.mu.RLock()
	count := len(s.sessions)
	s.mu.RUnlock()

	hn := *hostname
	if hn == "" {
		hn, _ = os.Hostname()
	}

	return map[string]interface{}{
		"pid":           serverPID,
		"instance_id":   serverInstance,
		"host_id":       serverHostID,
		"started_at":    serverStartedAt,
		"exit_empty":    false,
		"session_count": count,
		"config":        map[string]interface{}{"generation": 1, "hash": ""},
	}
}

func (s *Server) serverVersion() interface{} {
	return map[string]interface{}{
		"rex_version": "0.0.1-compat",
		"platform":    runtime.GOOS + "_" + runtime.GOARCH,
		"commit":      "0000000000000000000000000000000000000000",
		"built_at":    serverStartedAt,
		"dirty":       false,
	}
}

func (s *Server) serverWhoami(client *Client) interface{} {
	u, _ := user.Current()
	account := *accountName
	if account == "" && u != nil {
		account = u.Username
	}
	return map[string]interface{}{
		"principal": map[string]interface{}{
			"kind":      "peer",
			"transport": "http",
			"display":   fmt.Sprintf("uid %s", u.Uid),
			"uid":       json.Number(u.Uid),
		},
		"account": account,
	}
}

func (s *Server) sessionList() interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make([]map[string]string, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, map[string]string{
			"session_id": sess.ID,
			"label":      sess.Label,
		})
	}
	return map[string]interface{}{"sessions": sessions}
}

func (s *Server) sessionBootstrap(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	var params struct {
		EventScope         string   `json:"event_scope"`
		PreferredSessionID string   `json:"preferred_session_id"`
		AttachSessionIDs   []string `json:"attach_session_ids"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}
	if params.EventScope == "" {
		return nil, &RexAPIError{Status: 400, Code: "bad_request", Message: "event_scope is required"}
	}

	// Mark client as attached to all sessions
	s.mu.Lock()
	for sid := range s.sessions {
		client.AttachedSessions[sid] = true
	}
	s.mu.Unlock()

	attachAll := s.sessionList()

	// Select a session for the initial view
	s.mu.RLock()
	var selectedSession interface{}
	for _, sess := range s.sessions {
		// Auto-own unowned blocks for connecting client
		for _, b := range sess.Blocks {
			b.Owner = client.ID
		}
		for _, w := range sess.Windows {
			for _, l := range w.Layers {
				for _, br := range l.Blocks {
					if blk, ok := sess.Blocks[br.BlockID]; ok {
						br.Owner = blk.Owner
						log.Printf("set block %s owner to %s", br.BlockID, br.Owner)
					}
				}
			}
		}

		selectedSession = map[string]interface{}{
			"session": map[string]string{
				"session_id": sess.ID,
				"label":      sess.Label,
			},
			"view": s.buildSessionView(sess),
		}
		break
	}
	s.mu.RUnlock()

	result := map[string]interface{}{
		"client_id":     client.ID,
		"server_status": s.serverStatus(),
		"attach_all":    attachAll,
	}
	if selectedSession != nil {
		result["selected_session"] = selectedSession
	}

	return result, nil
}

func (s *Server) sessionAttachAll(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	s.mu.Lock()
	for sid := range s.sessions {
		client.AttachedSessions[sid] = true
	}
	s.mu.Unlock()

	return s.sessionList(), nil
}

func (s *Server) sessionAttach(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	var params struct {
		SessionID string `json:"session_id"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.RLock()
	sess, ok := s.sessions[params.SessionID]
	s.mu.RUnlock()
	if !ok {
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "session not found"}
	}

	client.AttachedSessions[params.SessionID] = true

	// Auto-own unowned blocks so Rex.app opens data channel
	for _, block := range sess.Blocks {
		block.Owner = client.ID
	}
	for _, win := range sess.Windows {
		for _, layer := range win.Layers {
			for _, br := range layer.Blocks {
				if blk, ok := sess.Blocks[br.BlockID]; ok {
					br.Owner = blk.Owner
						log.Printf("set block %s owner to %s", br.BlockID, br.Owner)
				}
			}
		}
	}

	// Send client_connected event BEFORE the response (matching real Rex server).
	// The CLI may extract client_id from this event.
	client.writeJSON(EventMsg{
		Type: "event",
		Seq:  s.nextSeq(),
		Payload: map[string]interface{}{
			"type": "session_event",
			"payload": map[string]interface{}{
				"session_id": params.SessionID,
				"event": map[string]interface{}{
					"type": "client_connected",
					"payload": map[string]interface{}{
						"client_id": client.ID,
						"principal": map[string]interface{}{
							"kind":      "peer",
							"transport": "tailscale",
							"display":   "hemlix",
						},
					},
				},
			},
		},
	})

	return map[string]interface{}{
		"client_id": client.ID,
		"view":      s.buildSessionView(sess),
	}, nil
}

func (s *Server) sessionView(req RequestMsg) (interface{}, *RexAPIError) {
	var params struct {
		SessionID string `json:"session_id"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.RLock()
	sess, ok := s.sessions[params.SessionID]
	s.mu.RUnlock()
	if !ok {
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "session not found"}
	}

	return s.buildSessionView(sess), nil
}

func (s *Server) buildSessionView(sess *Session) map[string]interface{} {
	windows := make([]interface{}, 0)
	var activeWindowID interface{} = nil

	for i, w := range sess.Windows {
		layers := make([]interface{}, 0)
		blocks := make([]interface{}, 0)

		for _, l := range w.Layers {
			layerBlocks := make([]interface{}, 0)
			for _, br := range l.Blocks {
				layerBlocks = append(layerBlocks, map[string]interface{}{
					"block_id":     br.BlockID,
					"label":        br.Label,
					"creator_name": br.CreatorName,
					"flavor":       br.Flavor,
					"host_id":      serverHostID,
					"owner":        br.Owner,
				})
			}
			blocks = layerBlocks

			layout := map[string]interface{}{
				"rect": []float64{0, 0, 1, 1},
			}
			if l.Layout != nil {
				layout["rect"] = l.Layout.Rect
				if l.Layout.BlockID != "" {
					layout["block_id"] = l.Layout.BlockID
				}
				if l.Layout.Split != "" {
					layout["split"] = l.Layout.Split
					layout["ratio"] = l.Layout.Ratio
					if l.Layout.First != nil {
						layout["first"] = layoutToJSON(l.Layout.First)
					}
					if l.Layout.Second != nil {
						layout["second"] = layoutToJSON(l.Layout.Second)
					}
				}
			}

			layers = append(layers, map[string]interface{}{
				"layer_id": l.ID,
				"kind":     l.Kind,
				"bounds":   []float64{0, 0, 1, 1},
				"layout":   layout,
				"blocks":   blocks,
			})
		}

		win := map[string]interface{}{
			"window_id":        w.ID,
			"label":            w.Label,
			"focused_block_id": w.FocusedBlockID,
			"layers":           layers,
		}
		windows = append(windows, win)

		if i == 0 {
			activeWindowID = w.ID
		}
	}

	if len(sess.Windows) > 0 {
		activeWindowID = sess.Windows[len(sess.Windows)-1].ID
	}

	return map[string]interface{}{
		"revision":          sess.revision,
		"session_id":        sess.ID,
		"label":             sess.Label,
		"active_window_id":  activeWindowID,
		"windows":           windows,
	}
}

func layoutToJSON(n *LayoutNode) map[string]interface{} {
	m := map[string]interface{}{
		"rect": n.Rect,
	}
	if n.BlockID != "" {
		m["block_id"] = n.BlockID
	}
	if n.Split != "" {
		m["split"] = n.Split
		m["ratio"] = n.Ratio
		if n.First != nil {
			m["first"] = layoutToJSON(n.First)
		}
		if n.Second != nil {
			m["second"] = layoutToJSON(n.Second)
		}
	}
	return m
}

func (s *Server) sessionCreate(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	var params struct {
		Label          string `json:"label"`
		InitialWindows []struct {
			WindowLabel string          `json:"window_label"`
			Layout      json.RawMessage `json:"layout"`
		} `json:"initial_windows"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	sessID := newID("session")
	sess := &Session{
		ID:     sessID,
		Label:  params.Label,
		Blocks: make(map[string]*Block),
	}
	if sess.Label == "" {
		sess.Label = "Session"
	}

	var initialWindows []interface{}

	for _, iw := range params.InitialWindows {
		block := s.createTerminalBlock(sessID, client.ID)
		sess.Blocks[block.ID] = block

		win, layer := s.createWindow(iw.WindowLabel, block)
		sess.Windows = append(sess.Windows, win)
		_ = layer

		sess.revision++

		initialWindows = append(initialWindows, map[string]interface{}{
			"window_id": win.ID,
			"block_ids": []string{block.ID},
			"revision":  sess.revision,
		})
	}

	// If no initial windows, create one default
	if len(params.InitialWindows) == 0 {
		block := s.createTerminalBlock(sessID, client.ID)
		sess.Blocks[block.ID] = block
		win, _ := s.createWindow("Window", block)
		sess.Windows = append(sess.Windows, win)
		sess.revision++
	}

	s.mu.Lock()
	s.sessions[sessID] = sess
	s.mu.Unlock()

	result := map[string]interface{}{
		"session_id": sessID,
	}
	if len(initialWindows) > 0 {
		result["initial_windows"] = initialWindows
	}

	log.Printf("created session %s (%s)", sessID, sess.Label)

	// Send session_created event so Rex.app knows to attach and open the terminal
	s.broadcastEvent(map[string]interface{}{
		"type": "session_created",
		"payload": map[string]interface{}{
			"session_id": sessID,
			"label":      sess.Label,
		},
	})

	return result, nil
}

func (s *Server) createTerminalBlock(sessionID, ownerID string) *Block {
	blockID := newID("block")
	block := &Block{
		ID:          blockID,
		Label:       "shell",
		CreatorName: "com.superlogical.terminal",
		Flavor:      "com.superlogical.terminal.shell",
		SessionID:   sessionID,
		Owner:       ownerID,
		cols:        80,
		rows:        24,
		dataSubs:    make(map[string]chan []byte),
	}

	// Create a libghostty-vt terminal emulator for this block.
	// It mirrors all PTY output so we can produce correct GHOSTSNP snapshots.
	vt, err := NewGhosttyTerminal(block.cols, block.rows)
	if err != nil {
		log.Printf("warning: failed to create ghostty terminal for %s: %v (snapshots will be empty)", blockID, err)
	} else {
		block.vt = vt
	}

	// Start a real shell
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	cmd := exec.Command(shell, "-l")
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		fmt.Sprintf("REX_SESSION=%s", sessionID),
		fmt.Sprintf("REX_BLOCK=%s", blockID),
	)

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{
		Rows: uint16(block.rows),
		Cols: uint16(block.cols),
	})
	if err != nil {
		log.Printf("failed to start pty: %v", err)
		return block
	}

	block.ptmx = ptmx
	block.cmd = cmd

	// Read from PTY, feed into ghostty-vt, and distribute to data subscribers
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("pty read error for %s: %v", blockID, err)
				}
				break
			}
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				// Detect OSC 52 clipboard sequences
				detectOSC52(s, block, data)

				// Feed into ghostty-vt so it maintains terminal state
				if block.vt != nil {
					block.vt.Write(data)
				}

				block.mu.Lock()
				for _, ch := range block.dataSubs {
					select {
					case ch <- data:
					default:
						// Drop if subscriber is slow
					}
				}
				block.mu.Unlock()
			}
		}
		// Child exited
		block.mu.Lock()
		for _, ch := range block.dataSubs {
			close(ch)
		}
		block.dataSubs = make(map[string]chan []byte)
		block.mu.Unlock()
		if block.vt != nil {
			block.vt.Free()
			block.vt = nil
		}
	}()

	log.Printf("started terminal block %s (shell: %s, ghostty-vt: %v)", blockID, shell, block.vt != nil)
	return block
}

func (s *Server) createWindow(label string, block *Block) (*Window, *Layer) {
	winID := newID("window")
	layerID := newID("layer")

	if label == "" {
		label = fmt.Sprintf("Window %s", winID[len(winID)-8:])
	}

	layer := &Layer{
		ID:   layerID,
		Kind: "tiled",
		Layout: &LayoutNode{
			Rect:    [4]float64{0, 0, 1, 1},
			BlockID: block.ID,
		},
		Blocks: []*BlockRef{{
			BlockID:     block.ID,
			Label:       block.Label,
			CreatorName: block.CreatorName,
			Flavor:      block.Flavor,
			HostID:      serverHostID,
			Owner:       block.Owner,
		}},
	}

	win := &Window{
		ID:             winID,
		Label:          label,
		FocusedBlockID: block.ID,
		Layers:         []*Layer{layer},
	}

	return win, layer
}

func (s *Server) sessionDestroy(req RequestMsg) (interface{}, *RexAPIError) {
	var params struct {
		SessionID string `json:"session_id"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.Lock()
	sess, ok := s.sessions[params.SessionID]
	if ok {
		// Kill all blocks
		for _, b := range sess.Blocks {
			if b.ptmx != nil {
				b.ptmx.Close()
			}
			if b.cmd != nil && b.cmd.Process != nil {
				b.cmd.Process.Kill()
			}
		}
		delete(s.sessions, params.SessionID)
	}
	s.mu.Unlock()

	if !ok {
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "session not found"}
	}

	return map[string]interface{}{}, nil
}

func (s *Server) sessionNewWindow(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	var params struct {
		SessionID   string          `json:"session_id"`
		WindowLabel string          `json:"window_label"`
		Layout      json.RawMessage `json:"layout"`
		Focus       *bool           `json:"focus"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.Lock()
	sess, ok := s.sessions[params.SessionID]
	if !ok {
		s.mu.Unlock()
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "session not found"}
	}

	block := s.createTerminalBlock(params.SessionID, client.ID)
	sess.Blocks[block.ID] = block

	win, _ := s.createWindow(params.WindowLabel, block)
	sess.Windows = append(sess.Windows, win)
	sess.revision++
	rev := sess.revision
	s.mu.Unlock()

	return map[string]interface{}{
		"revision":  rev,
		"window_id": win.ID,
		"block_ids": []string{block.ID},
	}, nil
}

func (s *Server) sessionNewSplit(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	var params struct {
		SessionID    string          `json:"session_id"`
		BlockID      string          `json:"block_id"`
		Direction    string          `json:"direction"`
		Layout       json.RawMessage `json:"layout"`
		Percent      float64         `json:"percent"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.Lock()
	sess, ok := s.sessions[params.SessionID]
	if !ok {
		s.mu.Unlock()
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "session not found"}
	}

	newBlock := s.createTerminalBlock(params.SessionID, client.ID)
	sess.Blocks[newBlock.ID] = newBlock

	// Find the window containing the anchor block and add the new block
	for _, win := range sess.Windows {
		for _, layer := range win.Layers {
			for _, br := range layer.Blocks {
				if br.BlockID == params.BlockID {
					// Add new block to this layer
					layer.Blocks = append(layer.Blocks, &BlockRef{
						BlockID:     newBlock.ID,
						Label:       newBlock.Label,
						CreatorName: newBlock.CreatorName,
						Flavor:      newBlock.Flavor,
						HostID:      serverHostID,
						Owner:       newBlock.Owner,
					})

					// Update layout to split
					ratio := 0.5
					if params.Percent > 0 {
						ratio = params.Percent / 100.0
					}
					dir := params.Direction
					if dir == "" || dir == "right" {
						dir = "horizontal"
					} else if dir == "down" {
						dir = "vertical"
					}

					layer.Layout = &LayoutNode{
						Rect:  [4]float64{0, 0, 1, 1},
						Split: dir,
						Ratio: ratio,
						First: &LayoutNode{
							Rect:    [4]float64{0, 0, ratio, 1},
							BlockID: params.BlockID,
						},
						Second: &LayoutNode{
							Rect:    [4]float64{ratio, 0, 1, 1},
							BlockID: newBlock.ID,
						},
					}

					sess.revision++
					rev := sess.revision
					s.mu.Unlock()

					return map[string]interface{}{
						"revision": rev,
						"block_id": newBlock.ID,
					}, nil
				}
			}
		}
	}
	s.mu.Unlock()

	return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "anchor block not found"}
}

func (s *Server) blockClose(req RequestMsg) (interface{}, *RexAPIError) {
	var params struct {
		SessionID string `json:"session_id"`
		BlockID   string `json:"block_id"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.Lock()
	sess, ok := s.sessions[params.SessionID]
	if !ok {
		s.mu.Unlock()
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "session not found"}
	}

	block, ok := sess.Blocks[params.BlockID]
	if ok {
		if block.ptmx != nil {
			block.ptmx.Close()
		}
		if block.cmd != nil && block.cmd.Process != nil {
			block.cmd.Process.Kill()
		}
		delete(sess.Blocks, params.BlockID)
	}

	// Remove block from windows
	for _, win := range sess.Windows {
		for _, layer := range win.Layers {
			newBlocks := make([]*BlockRef, 0)
			for _, br := range layer.Blocks {
				if br.BlockID != params.BlockID {
					newBlocks = append(newBlocks, br)
				}
			}
			layer.Blocks = newBlocks
		}
	}

	sess.revision++
	rev := sess.revision
	s.mu.Unlock()

	return map[string]interface{}{"revision": rev}, nil
}

func (s *Server) blockMethod(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	var params struct {
		SessionID string          `json:"session_id"`
		BlockID   string          `json:"block_id"`
		Method    string          `json:"method"`
		Args      json.RawMessage `json:"args"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.RLock()
	sess, ok := s.sessions[params.SessionID]
	if !ok {
		s.mu.RUnlock()
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "session not found"}
	}
	block, ok := sess.Blocks[params.BlockID]
	s.mu.RUnlock()
	if !ok {
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "block not found"}
	}

	fullMethod := params.Method
	// Rex.app may send short method names (e.g. "process") or full names
	// (e.g. "com.superlogical.terminal.process"). Normalize to full name.
	shortMethod := fullMethod
	if !strings.Contains(fullMethod, ".") {
		fullMethod = "com.superlogical.terminal." + fullMethod
	} else {
		// Extract short name after last dot
		idx := strings.LastIndex(fullMethod, ".")
		if idx >= 0 {
			shortMethod = fullMethod[idx+1:]
		}
	}
	_ = shortMethod

	switch fullMethod {
	case "com.superlogical.terminal.resize":
		var args struct {
			Columns     int  `json:"columns"`
			Rows        int  `json:"rows"`
			CellWidthPx *int `json:"cell_width_px"`
			CellHeightPx *int `json:"cell_height_px"`
		}
		if params.Args != nil {
			json.Unmarshal(params.Args, &args)
		}
		if block.ptmx != nil && args.Columns > 0 && args.Rows > 0 {
			pty.Setsize(block.ptmx, &pty.Winsize{
				Rows: uint16(args.Rows),
				Cols: uint16(args.Columns),
			})
			block.cols = args.Columns
			block.rows = args.Rows
		}
		// Also resize the ghostty-vt terminal so snapshots match
		if block.vt != nil && args.Columns > 0 && args.Rows > 0 {
			block.vt.Resize(args.Columns, args.Rows)
		}
		// Send resize APC on data channel (like real Rex server)
		cwpx := 7; chpx := 14
		if args.CellWidthPx != nil { cwpx = *args.CellWidthPx }
		if args.CellHeightPx != nil { chpx = *args.CellHeightPx }
		block.sendAPC("resize", map[string]interface{}{
			"type": "resize", "cols": args.Columns, "rows": args.Rows,
			"cell_width_px": cwpx, "cell_height_px": chpx, "owner": block.Owner,
		})
		return map[string]interface{}{}, nil

	case "com.superlogical.terminal.write":
		var args struct {
			Data string `json:"data"`
		}
		if params.Args != nil {
			json.Unmarshal(params.Args, &args)
		}
		n := 0
		if block.ptmx != nil && len(args.Data) > 0 {
			nn, _ := block.ptmx.Write([]byte(args.Data))
			n = nn
		}
		return map[string]interface{}{"bytes_written": n}, nil

	case "com.superlogical.terminal.size":
		return map[string]interface{}{
			"columns":       block.cols,
			"rows":          block.rows,
			"cell_width_px": 8,
			"cell_height_px": 16,
			"owner":         block.Owner,
			"desired":       []interface{}{},
		}, nil

	case "com.superlogical.terminal.title":
		return map[string]interface{}{"title": "shell"}, nil

	case "com.superlogical.terminal.pwd":
		return map[string]interface{}{"pwd": ""}, nil

	case "com.superlogical.terminal.process":
		result := map[string]interface{}{
			"last_exit": nil,
		}
		if block.cmd != nil && block.cmd.Process != nil {
			result["child"] = map[string]interface{}{
				"pid":     block.cmd.Process.Pid,
				"user_id": os.Getuid(),
				"name":    "shell",
			}
		}
		return result, nil

	case "com.superlogical.terminal.program_status":
		return map[string]interface{}{"records": []interface{}{}}, nil

	case "com.superlogical.terminal.tty_mode":
		return map[string]interface{}{
			"echo":      true,
			"canonical": true,
			"signals":   true,
		}, nil

	case "com.superlogical.terminal.format":
		var fmtArgs struct {
			Format string `json:"format"`
			Trim   bool   `json:"trim"`
		}
		if params.Args != nil { json.Unmarshal(params.Args, &fmtArgs) }
		content := ""
		if block.vt != nil { content = block.vt.Format(fmtArgs.Format, fmtArgs.Trim) }
		return map[string]interface{}{"content": content}, nil

	case "com.superlogical.terminal.reset":
		return map[string]interface{}{}, nil

	case "com.superlogical.terminal.clear":
		return map[string]interface{}{}, nil

	case "com.superlogical.terminal.set_theme":
		// Send theme APC on data channel (like real Rex server)
		var themeArgs map[string]interface{}
		if params.Args != nil {
			json.Unmarshal(params.Args, &themeArgs)
		}
		if themeArgs != nil {
			themeArgs["type"] = "theme"
			block.sendAPC("theme", themeArgs)
		}
		return map[string]interface{}{}, nil

	case "com.superlogical.terminal.list_dir":
		return map[string]interface{}{
			"path":      "/",
			"home":      os.Getenv("HOME"),
			"status":    "ok",
			"entries":   []interface{}{},
			"truncated": false,
		}, nil

	case "com.superlogical.terminal.clipboard_read":
		return map[string]interface{}{
			"id":    0,
			"data":  "",
			"total": 0,
			"eof":   true,
		}, nil

	default:
		log.Printf("unhandled block method: %s", fullMethod)
		return nil, &RexAPIError{
			Status:  404,
			Code:    "not_found",
			Message: fmt.Sprintf("unknown block method %q", fullMethod),
		}
	}
}

func (s *Server) blockCreatorList() interface{} {
	return map[string]interface{}{
		"creators": []interface{}{
			map[string]interface{}{
				"name":        "com.superlogical.terminal",
				"title":       "Terminal",
				"description": "Full interactive terminal emulator.",
				"host_id":     serverHostID,
				"flavors": []interface{}{
					map[string]interface{}{
						"name":        "shell",
						"flavor":      "com.superlogical.terminal.shell",
						"title":       "Shell",
						"description": "An interactive terminal shell.",
						"options_schema": map[string]interface{}{
							"type":                 "object",
							"additionalProperties": false,
							"properties": map[string]interface{}{
								"shell":   map[string]string{"type": "string"},
								"cwd":     map[string]string{"type": "string"},
							},
						},
					},
				},
				"features": []string{"data"},
				"api": map[string]interface{}{
					"methods": map[string]interface{}{
						"write":    map[string]interface{}{"description": "Write bytes to the terminal."},
						"resize":   map[string]interface{}{"description": "Request a grid size."},
						"size":     map[string]interface{}{"description": "Return the grid size."},
						"title":    map[string]interface{}{"description": "Return the current terminal title."},
						"pwd":      map[string]interface{}{"description": "Return the working directory."},
						"process":  map[string]interface{}{"description": "Return child process info."},
						"format":   map[string]interface{}{"description": "Format the screen."},
						"reset":    map[string]interface{}{"description": "Reset the emulator."},
						"clear":    map[string]interface{}{"description": "Clear screen and scrollback."},
						"tty_mode": map[string]interface{}{"description": "Return tty mode."},
						"set_theme": map[string]interface{}{"description": "Set terminal colors."},
						"list_dir":  map[string]interface{}{"description": "List directory."},
						"program_status": map[string]interface{}{"description": "Return program status."},
						"clipboard_read": map[string]interface{}{"description": "Read clipboard."},
					},
					"events": map[string]interface{}{
						"bell": map[string]interface{}{},
						"child_exited": map[string]interface{}{},
						"clipboard_written": map[string]interface{}{},
						"desktop_notification": map[string]interface{}{},
						"process_changed": map[string]interface{}{},
						"program_status_changed": map[string]interface{}{},
						"program_status_removed": map[string]interface{}{},
						"progress_report": map[string]interface{}{},
						"pwd_changed": map[string]interface{}{},
						"selection_copied": map[string]interface{}{},
						"size_changed": map[string]interface{}{},
						"title_changed": map[string]interface{}{},
						"url_clicked": map[string]interface{}{},
					},
				},
			},
		},
	}
}

func (s *Server) dataConnect(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	var params struct {
		SessionID   string `json:"session_id"`
		BlockID     string `json:"block_id"`
		DataRefID   string `json:"data_ref_id"`
		Subprotocol string `json:"subprotocol"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	// Verify the block exists
	s.mu.RLock()
	sess, ok := s.sessions[params.SessionID]
	if !ok {
		s.mu.RUnlock()
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "session not found"}
	}
	_, ok = sess.Blocks[params.BlockID]
	s.mu.RUnlock()
	if !ok {
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "block not found"}
	}

	// Generate a ticket
	var ticket [16]byte
	rand.Read(ticket[:])

	dt := &DataTicket{
		Ticket:    ticket,
		SessionID: params.SessionID,
		BlockID:   params.BlockID,
		DataRefID: params.DataRefID,
		ClientID:  client.ID,
		ExpiresAt: time.Now().Add(60 * time.Second),
	}

	ticketKey := base64.RawURLEncoding.EncodeToString(ticket[:])
	s.mu.Lock()
	s.tickets[ticketKey] = dt
	s.mu.Unlock()

	// Return ticket as base64url string (no padding), matching real Rex server
	ticketStr := base64.RawURLEncoding.EncodeToString(ticket[:])

	return map[string]interface{}{
		"ticket":        ticketStr,
		"expires_in_ms": 60000,
	}, nil
}

// Data channel handler
func (s *Server) handleData(w http.ResponseWriter, r *http.Request) {
	conn, err := dataUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("data upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// Read HELLO - it's a binary frame: 1 byte version + 16 byte ticket + data_ref_id string
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	msgType, msg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("data: reading hello: %v", err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	if msgType != websocket.BinaryMessage {
		log.Printf("data: expected binary hello, got %d", msgType)
		return
	}

	if len(msg) < 17 {
		log.Printf("data: hello too short: %d bytes", len(msg))
		// Send REJECT
		conn.WriteMessage(websocket.BinaryMessage, []byte{0x82, 0x01}) // REJECT
		return
	}

	// Parse: version(1) + ticket(16) + data_ref_id(rest)
	// version := msg[0]
	ticketBytes := msg[1:17]
	dataRefID := string(msg[17:])

	ticketKey := base64.RawURLEncoding.EncodeToString(ticketBytes)

	s.mu.Lock()
	dt, ok := s.tickets[ticketKey]
	if ok {
		delete(s.tickets, ticketKey)
	}
	s.mu.Unlock()

	if !ok || time.Now().After(dt.ExpiresAt) {
		log.Printf("data: invalid or expired ticket")
		conn.WriteMessage(websocket.BinaryMessage, []byte{0x82, 0x02}) // REJECT - bad ticket
		return
	}

	_ = dataRefID

	// Find the block
	s.mu.RLock()
	sess, ok := s.sessions[dt.SessionID]
	if !ok {
		s.mu.RUnlock()
		conn.WriteMessage(websocket.BinaryMessage, []byte{0x82, 0x03})
		return
	}
	block, ok := sess.Blocks[dt.BlockID]
	s.mu.RUnlock()
	if !ok {
		conn.WriteMessage(websocket.BinaryMessage, []byte{0x82, 0x03})
		return
	}

	// Send WELCOME: opcode(1) + reconnect_token(16) + reserved(4) + timeout_ms_le(4) + extra(8)
	// Opcode 0x81 = WELCOME, 0x82 = REJECT
	welcomeData := make([]byte, 32)
	welcomeData[0] = 0x81 // WELCOME opcode
	rand.Read(welcomeData[1:17]) // reconnect token
	// bytes 17-20: reserved/zero
	// bytes 21-24: timeout in ms, little-endian uint32 (60000 = 0xEA60)
	welcomeData[21] = 0x60
	welcomeData[22] = 0xEA
	welcomeData[23] = 0x00
	welcomeData[24] = 0x00
	rand.Read(welcomeData[25:32]) // extra token data — this is also the APC ID

	// Extract APC ID: last 8 bytes of WELCOME as little-endian uint64
	// APC ID is bytes 24-31 of WELCOME (last 8 bytes) as LE uint64
	apcIDVal := binary.LittleEndian.Uint64(welcomeData[24:32])
	block.mu.Lock()
	block.apcID = fmt.Sprintf("%d", apcIDVal)
	block.mu.Unlock()

	if err := conn.WriteMessage(websocket.BinaryMessage, welcomeData); err != nil {
		log.Printf("data: writing welcome: %v", err)
		return
	}

	// Generate a REAL snapshot from libghostty-vt (reflects actual terminal state)
	// or fall back to the static snapshot if ghostty-vt is not available.
	var snapshot []byte
	if block.vt != nil {
		var err error
		snapshot, err = block.vt.Snapshot()
		if err != nil {
			log.Printf("data: ghostty snapshot failed: %v, using static fallback", err)
			snapshot = ghosttyRealSnapshot()
		} else {
			log.Printf("data: generated live ghostty snapshot (%d bytes)", len(snapshot))
		}
	} else {
		snapshot = ghosttyRealSnapshot()
	}

	// Send snapshot split at 65536 bytes (matching real Rex server behavior).
	split := 65536
	if split > len(snapshot) { split = len(snapshot) }
	if err := conn.WriteMessage(websocket.BinaryMessage, snapshot[:split]); err != nil {
		log.Printf("data: writing snapshot part 1: %v", err)
		return
	}
	if split < len(snapshot) {
		if err := conn.WriteMessage(websocket.BinaryMessage, snapshot[split:]); err != nil {
			log.Printf("data: writing snapshot part 2: %v", err)
			return
		}
	}
	log.Printf("data: sent snapshot (%d bytes in %d messages)", len(snapshot), 1 + boolToInt(split < len(snapshot)))

	log.Printf("data: connected to block %s (ref: %s)", dt.BlockID, dt.DataRefID)

	// Subscribe to block output
	subID := randomToken()
	dataCh := make(chan []byte, 256)
	block.mu.Lock()
	block.dataSubs[subID] = dataCh
	block.mu.Unlock()

	defer func() {
		block.mu.Lock()
		delete(block.dataSubs, subID)
		block.mu.Unlock()
	}()

	// Bidirectional: client writes -> PTY stdin, PTY stdout -> client
	done := make(chan struct{})

	// PTY output -> client
	go func() {
		defer func() { close(done) }()
		for data := range dataCh {
			log.Printf("data: sending %d bytes to client", len(data))
			if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
				log.Printf("data: write to client error: %v", err)
				return
			}
		}
	}()

	// Client input -> PTY
	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				log.Printf("data: client read error: %v", err)
				return
			}
			log.Printf("DATA_INPUT: received %d bytes from client: %q", len(msg), string(msg)[:min(50, len(msg))])
			if block.ptmx != nil && len(msg) > 0 {
				n, err := block.ptmx.Write(msg)
				log.Printf("data: wrote %d bytes to PTY (err=%v)", n, err)
			}
		}
	}()

	<-done
}

func (s *Server) sessionFocusBlock(req RequestMsg) (interface{}, *RexAPIError) {
	return s.revisionResponse(req), nil
}

func (s *Server) sessionFocusWindow(req RequestMsg) (interface{}, *RexAPIError) {
	return s.revisionResponse(req), nil
}

func (s *Server) sessionFocusNextWindow(req RequestMsg) (interface{}, *RexAPIError) {
	return s.revisionResponse(req), nil
}

func (s *Server) sessionFocusPreviousWindow(req RequestMsg) (interface{}, *RexAPIError) {
	return s.revisionResponse(req), nil
}

func (s *Server) sessionSetLabel(req RequestMsg) (interface{}, *RexAPIError) {
	var params struct {
		SessionID string `json:"session_id"`
		Label     string `json:"label"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}
	s.mu.Lock()
	if sess, ok := s.sessions[params.SessionID]; ok {
		sess.Label = params.Label
	}
	s.mu.Unlock()
	return map[string]interface{}{}, nil
}

func (s *Server) sessionSetWindowLabel(req RequestMsg) (interface{}, *RexAPIError) {
	return s.revisionResponse(req), nil
}

func (s *Server) sessionSetBlockLabel(req RequestMsg) (interface{}, *RexAPIError) {
	return s.revisionResponse(req), nil
}

func (s *Server) sessionCloseWindow(req RequestMsg) (interface{}, *RexAPIError) {
	var params struct {
		SessionID string `json:"session_id"`
		WindowID  string `json:"window_id"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.Lock()
	sess, ok := s.sessions[params.SessionID]
	if !ok {
		s.mu.Unlock()
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "session not found"}
	}

	newWindows := make([]*Window, 0)
	for _, w := range sess.Windows {
		if w.ID != params.WindowID {
			newWindows = append(newWindows, w)
		} else {
			// Kill blocks in this window
			for _, layer := range w.Layers {
				for _, br := range layer.Blocks {
					if b, ok := sess.Blocks[br.BlockID]; ok {
						if b.ptmx != nil {
							b.ptmx.Close()
						}
						if b.cmd != nil && b.cmd.Process != nil {
							b.cmd.Process.Kill()
						}
						delete(sess.Blocks, br.BlockID)
					}
				}
			}
		}
	}
	sess.Windows = newWindows
	sess.revision++
	rev := sess.revision
	s.mu.Unlock()

	return map[string]interface{}{"revision": rev}, nil
}

func (s *Server) clientList(req RequestMsg) (interface{}, *RexAPIError) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]interface{}, 0)
	for _, c := range s.clients {
		clients = append(clients, map[string]interface{}{
			"client_id": c.ID,
			"info": map[string]interface{}{
				"kind":     c.Kind,
				"platform": c.Platform,
				"name":     c.Name,
				"version":  c.Version,
			},
			"principal": map[string]interface{}{
				"kind":      "peer",
				"transport": "http",
				"display":   "remote",
			},
		})
	}
	return map[string]interface{}{"clients": clients}, nil
}

func (s *Server) clientInspect(req RequestMsg) (interface{}, *RexAPIError) {
	var params struct {
		ClientID string `json:"client_id"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.RLock()
	c, ok := s.clients[params.ClientID]
	s.mu.RUnlock()
	if !ok {
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "client not found"}
	}

	return map[string]interface{}{
		"client_id": c.ID,
		"info": map[string]interface{}{
			"kind":     c.Kind,
			"platform": c.Platform,
			"name":     c.Name,
			"version":  c.Version,
		},
		"principal": map[string]interface{}{
			"kind":      "peer",
			"transport": "http",
			"display":   "remote",
		},
		"actions": []interface{}{},
	}, nil
}

func (s *Server) sessionOwnBlock(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	var params struct {
		SessionID string   `json:"session_id"`
		BlockIDs  []string `json:"block_ids"`
		Mode      string   `json:"mode"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	var result []map[string]interface{}
	var ownerChanges []map[string]interface{}

	s.mu.Lock()
	sessionID := params.SessionID
	if sess, ok := s.sessions[params.SessionID]; ok {
		blockIDs := params.BlockIDs
		if len(blockIDs) == 0 {
			for bid := range sess.Blocks {
				blockIDs = append(blockIDs, bid)
			}
		}
		for _, bid := range blockIDs {
			if b, ok := sess.Blocks[bid]; ok {
				mode := params.Mode
				if mode == "" {
					mode = "take"
				}
				oldOwner := b.Owner
				if mode == "take" || (mode == "request" && b.Owner == "") {
					b.Owner = client.ID
				}
				entry := map[string]interface{}{
					"block_id": bid,
				}
				if b.Owner != "" {
					entry["owner"] = b.Owner
				}
				result = append(result, entry)
				if b.Owner != oldOwner {
					ownerChanges = append(ownerChanges, map[string]interface{}{
						"block_id":       bid,
						"owner":          b.Owner,
						"previous_owner": oldOwner,
					})
				}
			}
		}
	}
	s.mu.Unlock()

	// Emit block_owner_changed events
	for _, change := range ownerChanges {
		s.broadcastSessionEvent(sessionID, map[string]interface{}{
			"type":    "block_owner_changed",
			"payload": change,
		})
	}

	if result == nil {
		result = []map[string]interface{}{}
	}

	return map[string]interface{}{"blocks": result}, nil
}

func (s *Server) sessionNewBlock(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	var params struct {
		SessionID string                 `json:"session_id"`
		Creator   string                 `json:"creator"`
		Flavor    string                 `json:"flavor"`
		Label     string                 `json:"label"`
		Options   map[string]interface{} `json:"options"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.Lock()
	sess, ok := s.sessions[params.SessionID]
	if !ok {
		s.mu.Unlock()
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "session not found"}
	}

	block := s.createTerminalBlock(params.SessionID, client.ID)
	sess.revision++
	rev := sess.revision
	s.mu.Unlock()

	return map[string]interface{}{
		"block_id": block.ID,
		"revision": rev,
	}, nil
}

func (s *Server) sessionListBlocks(req RequestMsg) (interface{}, *RexAPIError) {
	var params struct {
		SessionID string `json:"session_id"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.RLock()
	sess, ok := s.sessions[params.SessionID]
	if !ok {
		s.mu.RUnlock()
		return nil, &RexAPIError{Status: 404, Code: "not_found", Message: "session not found"}
	}

	blocks := make([]interface{}, 0)
	for _, b := range sess.Blocks {
		blocks = append(blocks, map[string]interface{}{
			"block_id":     b.ID,
			"label":        b.Label,
			"creator_name": b.CreatorName,
			"flavor":       b.Flavor,
			"host_id":      serverHostID,
			"owner":        b.Owner,
			"state":        "placed",
		})
	}
	s.mu.RUnlock()

	return map[string]interface{}{"blocks": blocks}, nil
}

func (s *Server) sessionDescribeBlock(req RequestMsg) (interface{}, *RexAPIError) {
	return map[string]interface{}{
		"creator_name": "com.superlogical.terminal",
		"flavor":       "com.superlogical.terminal.shell",
		"api":          s.blockCreatorList().(map[string]interface{})["creators"].([]interface{})[0].(map[string]interface{})["api"],
	}, nil
}

func (s *Server) revisionResponse(req RequestMsg) interface{} {
	var params struct {
		SessionID string `json:"session_id"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.RLock()
	rev := int64(0)
	if sess, ok := s.sessions[params.SessionID]; ok {
		rev = sess.revision
	}
	s.mu.RUnlock()

	return map[string]interface{}{"revision": rev}
}

func (s *Server) targetResolve(req RequestMsg) (interface{}, *RexAPIError) {
	var params struct {
		Queries []string `json:"queries"`
		Kinds   []string `json:"kinds"`
		Context struct {
			SessionID string `json:"session_id"`
			BlockID   string `json:"block_id"`
		} `json:"context"`
		Scope struct {
			Session string `json:"session"`
			Window  string `json:"window"`
		} `json:"scope"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	var results []interface{}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, query := range params.Queries {
		resolved := false
		for _, kind := range params.Kinds {
			switch kind {
			case "session":
				for _, sess := range s.sessions {
					if query == "" || query == sess.ID || query == sess.Label || matchesSuffix(sess.ID, query) {
						results = append(results, map[string]interface{}{
							"query":  query,
							"status": "resolved",
							"target": map[string]interface{}{
								"kind":       "session",
								"session_id": sess.ID,
								"label":      sess.Label,
								"where":      sess.Label,
							},
						})
						resolved = true
						break
					}
				}
			case "window":
				for _, sess := range s.sessions {
					if params.Context.SessionID != "" && sess.ID != params.Context.SessionID {
						continue
					}
					for i, win := range sess.Windows {
						if query == "" || query == win.ID || query == win.Label || matchesSuffix(win.ID, query) {
							results = append(results, map[string]interface{}{
								"query":  query,
								"status": "resolved",
								"target": map[string]interface{}{
									"kind":       "window",
									"session_id": sess.ID,
									"window_id":  win.ID,
									"label":      win.Label,
									"where":      fmt.Sprintf("window %d", i+1),
									"ordinal":    i + 1,
								},
							})
							resolved = true
							break
						}
					}
					if resolved {
						break
					}
				}
			case "block":
				for _, sess := range s.sessions {
					if params.Context.SessionID != "" && sess.ID != params.Context.SessionID {
						continue
					}
					for _, block := range sess.Blocks {
						if query == "" || query == block.ID || query == block.Label || matchesSuffix(block.ID, query) {
							// Find which window contains this block
							winID := ""
							where := "detached"
							for wi, win := range sess.Windows {
								for _, layer := range win.Layers {
									for _, lb := range layer.Blocks {
										if lb.BlockID == block.ID {
											winID = win.ID
											where = fmt.Sprintf("window %d", wi+1)
										}
									}
								}
							}
							results = append(results, map[string]interface{}{
								"query":  query,
								"status": "resolved",
								"target": map[string]interface{}{
									"kind":       "block",
									"session_id": sess.ID,
									"window_id":  winID,
									"block_id":   block.ID,
									"label":      block.Label,
									"where":      where,
								},
							})
							resolved = true
							break
						}
					}
					if resolved {
						break
					}
				}
			}
			if resolved {
				break
			}
		}
		if !resolved {
			results = append(results, map[string]interface{}{
				"query":  query,
				"status": "not_found",
			})
		}
	}

	if results == nil {
		results = []interface{}{}
	}

	return map[string]interface{}{"results": results}, nil
}

func matchesSuffix(id, query string) bool {
	if len(query) < 4 || len(query) > 32 {
		return false
	}
	return len(id) >= len(query) && id[len(id)-len(query):] == query
}

func (s *Server) helpAll() interface{} {
	return map[string]interface{}{
		"methods":     []interface{}{},
		"block_types": []interface{}{},
	}
}

// --- M
// detectOSC52 scans PTY output for OSC 52 clipboard sequences and sends
// clipboard_written events on the control channel so Rex.app sets the clipboard.
func detectOSC52(s *Server, block *Block, data []byte) {
	// Look for OSC 52: \x1b]52;
	prefix := []byte("\x1b]52;")
	idx := bytes.Index(data, prefix)
	if idx < 0 {
		return
	}
	// Find the end: BEL (0x07) or ST (\x1b\\)
	rest := data[idx+len(prefix):]
	endBEL := bytes.IndexByte(rest, 0x07)
	endST := bytes.Index(rest, []byte("\x1b\\"))
	end := -1
	if endBEL >= 0 && (endST < 0 || endBEL < endST) {
		end = endBEL
	} else if endST >= 0 {
		end = endST
	}
	if end < 0 {
		return
	}
	payload := string(rest[:end])
	// payload is "c;BASE64" or "p;BASE64"
	parts := strings.SplitN(payload, ";", 2)
	if len(parts) != 2 {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	text := string(decoded)
	log.Printf("OSC 52 clipboard: %d chars", len(text))
	// Send clipboard_written event on control channel
	s.broadcastSessionEvent(block.SessionID, map[string]interface{}{
		"type": "block_event",
		"payload": map[string]interface{}{
			"block_id":     block.ID,
			"creator_name": "com.superlogical.terminal",
			"name":         "clipboard_written",
			"payload": map[string]interface{}{
				"text":  text,
				"id":    0,
				"bytes": len(text),
			},
		},
	})
	// Also send selection_copied event
	s.broadcastSessionEvent(block.SessionID, map[string]interface{}{
		"type": "block_event",
		"payload": map[string]interface{}{
			"block_id":     block.ID,
			"creator_name": "com.superlogical.terminal",
			"name":         "selection_copied",
			"payload": map[string]interface{}{
				"text": text,
			},
		},
	})
}


func main() {
	flag.Parse()

	srv := NewServer()

	// Create a default session
	defaultSess := &Session{
		ID:     newID("session"),
		Label:  "Default",
		Blocks: make(map[string]*Block),
	}
	block := srv.createTerminalBlock(defaultSess.ID, "")
	defaultSess.Blocks[block.ID] = block
	win, _ := srv.createWindow("Terminal", block)
	defaultSess.Windows = append(defaultSess.Windows, win)
	defaultSess.revision = 1
	srv.sessions[defaultSess.ID] = defaultSess

	mux := http.NewServeMux()
	mux.HandleFunc("/api/control", srv.handleControl)
	mux.HandleFunc("/api/data", srv.handleData)

	// Health check
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("rex-compat-server\n"))
			return
		}
		http.NotFound(w, r)
	})

	log.Printf("Rex-compatible server starting on %s", *listenAddr)
	log.Printf("  host_id:    %s", serverHostID)
	log.Printf("  instance:   %s", serverInstance)

	if err := http.ListenAndServe(*listenAddr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func (s *Server) clientKey(req RequestMsg, client *Client) (interface{}, *RexAPIError) {
	var params struct {
		SessionID string `json:"session_id"`
		BlockID   string `json:"block_id"`
		Key       struct {
			Key               string `json:"key"`
			Mods              string `json:"mods"`
			ConsumedMods      string `json:"consumed_mods"`
			Text              string `json:"text"`
			UnshiftedCodepoint int   `json:"unshifted_codepoint"`
			Composing         bool   `json:"composing"`
			Action            string `json:"action"`
		} `json:"key"`
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	// Only handle press and repeat, not release
	if params.Key.Action != "press" && params.Key.Action != "repeat" {
		return map[string]interface{}{"handled": false}, nil
	}

	mods := params.Key.Mods

	// Super (Cmd) keys are CLIENT-SIDE shortcuts (copy, paste, new tab, etc.)
	// Do NOT send to PTY - return handled:false so Rex.app handles them.
	if strings.Contains(mods, "super") {
		return map[string]interface{}{"handled": false}, nil
	}

	// Super (Cmd) keys are CLIENT-SIDE shortcuts - don't send to PTY
	if strings.Contains(params.Key.Mods, "super") {
		return map[string]interface{}{"handled": false}, nil
	}


	// Find the target block
	s.mu.RLock()
	sess, ok := s.sessions[params.SessionID]
	if !ok {
		s.mu.RUnlock()
		return map[string]interface{}{"handled": false}, nil
	}
	blockID := params.BlockID
	if blockID == "" {
		for _, win := range sess.Windows {
			if win.FocusedBlockID != "" {
				blockID = win.FocusedBlockID
				break
			}
		}
	}
	block, ok := sess.Blocks[blockID]
	s.mu.RUnlock()
	if !ok || block.ptmx == nil {
		return map[string]interface{}{"handled": false}, nil
	}

	var data []byte
	hasCtrl := strings.Contains(mods, "ctrl")
	hasAlt := strings.Contains(mods, "alt")

	// Handle Ctrl+key combinations FIRST (before checking text)
	if hasCtrl {
		// Use unshifted_codepoint for ctrl mapping (works even when text is empty)
		cp := params.Key.UnshiftedCodepoint
		if cp >= 97 && cp <= 122 { // a-z
			data = []byte{byte(cp - 96)} // ctrl+a=1, ctrl+c=3, ctrl+z=26
		} else if cp >= 65 && cp <= 90 { // A-Z
			data = []byte{byte(cp - 64)}
		} else {
			switch params.Key.Key {
			case "bracket_left":  data = []byte{0x1b} // ctrl+[ = ESC
			case "bracket_right": data = []byte{0x1d} // ctrl+]
			case "backslash":     data = []byte{0x1c} // ctrl+\  
			case "slash":         data = []byte{0x1f} // ctrl+/
			case "digit_2", "space": data = []byte{0x00} // ctrl+space/ctrl+2 = NUL
			}
		}
	} else if hasAlt {
		// Alt+key sends ESC prefix + character
		if params.Key.Text != "" {
			data = append([]byte{0x1b}, []byte(params.Key.Text)...)
		} else if params.Key.UnshiftedCodepoint > 0 && params.Key.UnshiftedCodepoint < 128 {
			data = []byte{0x1b, byte(params.Key.UnshiftedCodepoint)}
		}
	} else if params.Key.Text != "" {
		// Normal text input
		data = []byte(params.Key.Text)
	} else {
		// Special keys without text
		switch params.Key.Key {
		case "enter":      data = []byte("\r")
		case "backspace":  data = []byte{0x7f}
		case "tab":        data = []byte("\t")
		case "escape":     data = []byte{0x1b}
		case "arrow_up":   data = []byte("\x1b[A")
		case "arrow_down": data = []byte("\x1b[B")
		case "arrow_right":data = []byte("\x1b[C")
		case "arrow_left": data = []byte("\x1b[D")
		case "home":       data = []byte("\x1b[H")
		case "end":        data = []byte("\x1b[F")
		case "page_up":    data = []byte("\x1b[5~")
		case "page_down":  data = []byte("\x1b[6~")
		case "delete":     data = []byte("\x1b[3~")
		case "insert":     data = []byte("\x1b[2~")
		case "f1":  data = []byte("\x1bOP")
		case "f2":  data = []byte("\x1bOQ")
		case "f3":  data = []byte("\x1bOR")
		case "f4":  data = []byte("\x1bOS")
		case "f5":  data = []byte("\x1b[15~")
		case "f6":  data = []byte("\x1b[17~")
		case "f7":  data = []byte("\x1b[18~")
		case "f8":  data = []byte("\x1b[19~")
		case "f9":  data = []byte("\x1b[20~")
		case "f10": data = []byte("\x1b[21~")
		case "f11": data = []byte("\x1b[23~")
		case "f12": data = []byte("\x1b[24~")
		}
	}

	if len(data) > 0 {
		block.ptmx.Write(data)
	}

	return map[string]interface{}{"handled": false}, nil
}

func ghosttyRealSnapshot() []byte {
    // Official Ghostty test fixture: empty 2x3 terminal
    return []byte{0x47, 0x48, 0x4f, 0x53, 0x54, 0x53, 0x4e, 0x50, 0x01, 0x00, 0x01, 0x00, 0xb8, 0x03, 0x00, 0x00, 0xe3, 0x5f, 0x8b, 0xcc, 0x02, 0x00, 0x03, 0x00, 0x20, 0x03, 0x00, 0x00, 0x58, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x65, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x22, 0x00, 0x64, 0x10, 0x00, 0x00, 0x00, 0x04, 0x22, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x04, 0x22, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x1d, 0x1f, 0x21, 0xcc, 0x66, 0x66, 0xb5, 0xbd, 0x68, 0xf0, 0xc6, 0x74, 0x81, 0xa2, 0xbe, 0xb2, 0x94, 0xbb, 0x8a, 0xbe, 0xb7, 0xc5, 0xc8, 0xc6, 0x66, 0x66, 0x66, 0xd5, 0x4e, 0x53, 0xb9, 0xca, 0x4a, 0xe7, 0xc5, 0x47, 0x7a, 0xa6, 0xda, 0xc3, 0x97, 0xd8, 0x70, 0xc0, 0xb1, 0xea, 0xea, 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5f, 0x00, 0x00, 0x87, 0x00, 0x00, 0xaf, 0x00, 0x00, 0xd7, 0x00, 0x00, 0xff, 0x00, 0x5f, 0x00, 0x00, 0x5f, 0x5f, 0x00, 0x5f, 0x87, 0x00, 0x5f, 0xaf, 0x00, 0x5f, 0xd7, 0x00, 0x5f, 0xff, 0x00, 0x87, 0x00, 0x00, 0x87, 0x5f, 0x00, 0x87, 0x87, 0x00, 0x87, 0xaf, 0x00, 0x87, 0xd7, 0x00, 0x87, 0xff, 0x00, 0xaf, 0x00, 0x00, 0xaf, 0x5f, 0x00, 0xaf, 0x87, 0x00, 0xaf, 0xaf, 0x00, 0xaf, 0xd7, 0x00, 0xaf, 0xff, 0x00, 0xd7, 0x00, 0x00, 0xd7, 0x5f, 0x00, 0xd7, 0x87, 0x00, 0xd7, 0xaf, 0x00, 0xd7, 0xd7, 0x00, 0xd7, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0x5f, 0x00, 0xff, 0x87, 0x00, 0xff, 0xaf, 0x00, 0xff, 0xd7, 0x00, 0xff, 0xff, 0x5f, 0x00, 0x00, 0x5f, 0x00, 0x5f, 0x5f, 0x00, 0x87, 0x5f, 0x00, 0xaf, 0x5f, 0x00, 0xd7, 0x5f, 0x00, 0xff, 0x5f, 0x5f, 0x00, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x87, 0x5f, 0x5f, 0xaf, 0x5f, 0x5f, 0xd7, 0x5f, 0x5f, 0xff, 0x5f, 0x87, 0x00, 0x5f, 0x87, 0x5f, 0x5f, 0x87, 0x87, 0x5f, 0x87, 0xaf, 0x5f, 0x87, 0xd7, 0x5f, 0x87, 0xff, 0x5f, 0xaf, 0x00, 0x5f, 0xaf, 0x5f, 0x5f, 0xaf, 0x87, 0x5f, 0xaf, 0xaf, 0x5f, 0xaf, 0xd7, 0x5f, 0xaf, 0xff, 0x5f, 0xd7, 0x00, 0x5f, 0xd7, 0x5f, 0x5f, 0xd7, 0x87, 0x5f, 0xd7, 0xaf, 0x5f, 0xd7, 0xd7, 0x5f, 0xd7, 0xff, 0x5f, 0xff, 0x00, 0x5f, 0xff, 0x5f, 0x5f, 0xff, 0x87, 0x5f, 0xff, 0xaf, 0x5f, 0xff, 0xd7, 0x5f, 0xff, 0xff, 0x87, 0x00, 0x00, 0x87, 0x00, 0x5f, 0x87, 0x00, 0x87, 0x87, 0x00, 0xaf, 0x87, 0x00, 0xd7, 0x87, 0x00, 0xff, 0x87, 0x5f, 0x00, 0x87, 0x5f, 0x5f, 0x87, 0x5f, 0x87, 0x87, 0x5f, 0xaf, 0x87, 0x5f, 0xd7, 0x87, 0x5f, 0xff, 0x87, 0x87, 0x00, 0x87, 0x87, 0x5f, 0x87, 0x87, 0x87, 0x87, 0x87, 0xaf, 0x87, 0x87, 0xd7, 0x87, 0x87, 0xff, 0x87, 0xaf, 0x00, 0x87, 0xaf, 0x5f, 0x87, 0xaf, 0x87, 0x87, 0xaf, 0xaf, 0x87, 0xaf, 0xd7, 0x87, 0xaf, 0xff, 0x87, 0xd7, 0x00, 0x87, 0xd7, 0x5f, 0x87, 0xd7, 0x87, 0x87, 0xd7, 0xaf, 0x87, 0xd7, 0xd7, 0x87, 0xd7, 0xff, 0x87, 0xff, 0x00, 0x87, 0xff, 0x5f, 0x87, 0xff, 0x87, 0x87, 0xff, 0xaf, 0x87, 0xff, 0xd7, 0x87, 0xff, 0xff, 0xaf, 0x00, 0x00, 0xaf, 0x00, 0x5f, 0xaf, 0x00, 0x87, 0xaf, 0x00, 0xaf, 0xaf, 0x00, 0xd7, 0xaf, 0x00, 0xff, 0xaf, 0x5f, 0x00, 0xaf, 0x5f, 0x5f, 0xaf, 0x5f, 0x87, 0xaf, 0x5f, 0xaf, 0xaf, 0x5f, 0xd7, 0xaf, 0x5f, 0xff, 0xaf, 0x87, 0x00, 0xaf, 0x87, 0x5f, 0xaf, 0x87, 0x87, 0xaf, 0x87, 0xaf, 0xaf, 0x87, 0xd7, 0xaf, 0x87, 0xff, 0xaf, 0xaf, 0x00, 0xaf, 0xaf, 0x5f, 0xaf, 0xaf, 0x87, 0xaf, 0xaf, 0xaf, 0xaf, 0xaf, 0xd7, 0xaf, 0xaf, 0xff, 0xaf, 0xd7, 0x00, 0xaf, 0xd7, 0x5f, 0xaf, 0xd7, 0x87, 0xaf, 0xd7, 0xaf, 0xaf, 0xd7, 0xd7, 0xaf, 0xd7, 0xff, 0xaf, 0xff, 0x00, 0xaf, 0xff, 0x5f, 0xaf, 0xff, 0x87, 0xaf, 0xff, 0xaf, 0xaf, 0xff, 0xd7, 0xaf, 0xff, 0xff, 0xd7, 0x00, 0x00, 0xd7, 0x00, 0x5f, 0xd7, 0x00, 0x87, 0xd7, 0x00, 0xaf, 0xd7, 0x00, 0xd7, 0xd7, 0x00, 0xff, 0xd7, 0x5f, 0x00, 0xd7, 0x5f, 0x5f, 0xd7, 0x5f, 0x87, 0xd7, 0x5f, 0xaf, 0xd7, 0x5f, 0xd7, 0xd7, 0x5f, 0xff, 0xd7, 0x87, 0x00, 0xd7, 0x87, 0x5f, 0xd7, 0x87, 0x87, 0xd7, 0x87, 0xaf, 0xd7, 0x87, 0xd7, 0xd7, 0x87, 0xff, 0xd7, 0xaf, 0x00, 0xd7, 0xaf, 0x5f, 0xd7, 0xaf, 0x87, 0xd7, 0xaf, 0xaf, 0xd7, 0xaf, 0xd7, 0xd7, 0xaf, 0xff, 0xd7, 0xd7, 0x00, 0xd7, 0xd7, 0x5f, 0xd7, 0xd7, 0x87, 0xd7, 0xd7, 0xaf, 0xd7, 0xd7, 0xd7, 0xd7, 0xd7, 0xff, 0xd7, 0xff, 0x00, 0xd7, 0xff, 0x5f, 0xd7, 0xff, 0x87, 0xd7, 0xff, 0xaf, 0xd7, 0xff, 0xd7, 0xd7, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0x00, 0x5f, 0xff, 0x00, 0x87, 0xff, 0x00, 0xaf, 0xff, 0x00, 0xd7, 0xff, 0x00, 0xff, 0xff, 0x5f, 0x00, 0xff, 0x5f, 0x5f, 0xff, 0x5f, 0x87, 0xff, 0x5f, 0xaf, 0xff, 0x5f, 0xd7, 0xff, 0x5f, 0xff, 0xff, 0x87, 0x00, 0xff, 0x87, 0x5f, 0xff, 0x87, 0x87, 0xff, 0x87, 0xaf, 0xff, 0x87, 0xd7, 0xff, 0x87, 0xff, 0xff, 0xaf, 0x00, 0xff, 0xaf, 0x5f, 0xff, 0xaf, 0x87, 0xff, 0xaf, 0xaf, 0xff, 0xaf, 0xd7, 0xff, 0xaf, 0xff, 0xff, 0xd7, 0x00, 0xff, 0xd7, 0x5f, 0xff, 0xd7, 0x87, 0xff, 0xd7, 0xaf, 0xff, 0xd7, 0xd7, 0xff, 0xd7, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0x5f, 0xff, 0xff, 0x87, 0xff, 0xff, 0xaf, 0xff, 0xff, 0xd7, 0xff, 0xff, 0xff, 0x08, 0x08, 0x08, 0x12, 0x12, 0x12, 0x1c, 0x1c, 0x1c, 0x26, 0x26, 0x26, 0x30, 0x30, 0x30, 0x3a, 0x3a, 0x3a, 0x44, 0x44, 0x44, 0x4e, 0x4e, 0x4e, 0x58, 0x58, 0x58, 0x62, 0x62, 0x62, 0x6c, 0x6c, 0x6c, 0x76, 0x76, 0x76, 0x80, 0x80, 0x80, 0x8a, 0x8a, 0x8a, 0x94, 0x94, 0x94, 0x9e, 0x9e, 0x9e, 0xa8, 0xa8, 0xa8, 0xb2, 0xb2, 0xb2, 0xbc, 0xbc, 0xbc, 0xc6, 0xc6, 0xc6, 0xd0, 0xd0, 0xd0, 0xda, 0xda, 0xda, 0xe4, 0xe4, 0xe4, 0xee, 0xee, 0xee, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x14, 0x00, 0x00, 0x00, 0x66, 0x69, 0x6c, 0x65, 0x3a, 0x2f, 0x2f, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x11, 0x00, 0x00, 0x00, 0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x20, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x02, 0x00, 0x36, 0x00, 0x00, 0x00, 0x67, 0x31, 0x0e, 0xc6, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x24, 0x00, 0x00, 0x00, 0xa2, 0x4f, 0x26, 0xd1, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xc0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x43, 0x00, 0x01, 0x00, 0x44, 0x00, 0x01, 0x00, 0x45, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x36, 0x00, 0x00, 0x00, 0xce, 0x1f, 0x9f, 0x08, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x26, 0x00, 0x00, 0x00, 0x62, 0x1c, 0xab, 0x7b, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0xc0, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x03, 0x02, 0x00, 0x72, 0x6e, 0x03, 0x02, 0x00, 0x61, 0x74, 0x02, 0x01, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27, 0x80, 0x63, 0xd1, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe4, 0x20, 0xef, 0x0a, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x20, 0x32, 0xed, 0xe1, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x4a, 0xed, 0x2f, 0xc2, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xc0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x23, 0x6a, 0x6b, 0x19, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xc0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0xb8, 0x7a, 0xba, 0xb1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0xeb, 0x53, 0x3e}
}

func boolToInt(b bool) int { if b { return 1 }; return 0 }

