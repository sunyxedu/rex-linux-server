package main

import (
	"crypto/rand"
	"encoding/base64"
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
	dataSubs map[string]chan []byte // data_ref_id -> channel for subscribers
	mu       sync.Mutex
}

type Client struct {
	ID        string
	Kind      string
	Platform  string
	Name      string
	Version   string
	AttachedSessions map[string]bool
	conn      *websocket.Conn
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
	if err := conn.WriteJSON(welcome); err != nil {
		log.Printf("writing welcome: %v", err)
		return
	}

	log.Printf("client connected: %s (%s/%s)", clientID, hello.Client.Name, hello.Client.Platform)

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

		log.Printf("request: %s %s", req.ID, req.Method)

		result, apiErr := s.handleMethod(req, client)
		if apiErr != nil {
			resp := ErrorResponseMsg{
				Type:  "response",
				ID:    req.ID,
				Seq:   0,
				Error: apiErr,
			}
			conn.WriteJSON(resp)
		} else {
			resp := ResponseMsg{
				Type:    "response",
				ID:      req.ID,
				Seq:     0,
				Payload: result,
			}
			conn.WriteJSON(resp)
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

	// Read from PTY and distribute to data subscribers
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
	}()

	log.Printf("started terminal block %s (shell: %s)", blockID, shell)
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
		return map[string]interface{}{"content": ""}, nil

	case "com.superlogical.terminal.reset":
		return map[string]interface{}{}, nil

	case "com.superlogical.terminal.clear":
		return map[string]interface{}{}, nil

	case "com.superlogical.terminal.set_theme":
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
					"events": map[string]interface{}{},
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

	// Return ticket as byte array
	ticketBytes := make([]int, 16)
	for i, b := range ticket {
		ticketBytes[i] = int(b)
	}

	return map[string]interface{}{
		"ticket":        ticketBytes,
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
		conn.WriteMessage(websocket.BinaryMessage, []byte{0x01, 0x01}) // REJECT
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
		conn.WriteMessage(websocket.BinaryMessage, []byte{0x01, 0x02}) // REJECT - bad ticket
		return
	}

	_ = dataRefID

	// Find the block
	s.mu.RLock()
	sess, ok := s.sessions[dt.SessionID]
	if !ok {
		s.mu.RUnlock()
		conn.WriteMessage(websocket.BinaryMessage, []byte{0x01, 0x03})
		return
	}
	block, ok := sess.Blocks[dt.BlockID]
	s.mu.RUnlock()
	if !ok {
		conn.WriteMessage(websocket.BinaryMessage, []byte{0x01, 0x03})
		return
	}

	// Send WELCOME (single byte 0x00)
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte{0x00}); err != nil {
		log.Printf("data: writing welcome: %v", err)
		return
	}

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
			if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
				return
			}
		}
	}()

	// Client input -> PTY
	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if block.ptmx != nil && len(msg) > 0 {
				block.ptmx.Write(msg)
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
	}
	if req.Payload != nil {
		json.Unmarshal(req.Payload, &params)
	}

	s.mu.Lock()
	if sess, ok := s.sessions[params.SessionID]; ok {
		for _, bid := range params.BlockIDs {
			if b, ok := sess.Blocks[bid]; ok {
				b.Owner = client.ID
			}
		}
	}
	s.mu.Unlock()

	return map[string]interface{}{}, nil
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
	return map[string]interface{}{
		"resources": []interface{}{},
	}, nil
}

func (s *Server) helpAll() interface{} {
	return map[string]interface{}{
		"methods":     []interface{}{},
		"block_types": []interface{}{},
	}
}

// --- Main ---

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
