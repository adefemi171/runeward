// Package agent implements the in-sandbox agent, a small HTTP server exposing
// shell, code, and file operations over JSON. All file operations are confined
// to a single workspace root; resolve rejects ".." traversal and absolute-path
// escapes.
package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// maxSearchMatches caps /v1/file/search results.
const maxSearchMatches = 500

// Server exposes shell, code, and file operations over HTTP, with file access
// confined to root.
type Server struct {
	root string // absolute, cleaned workspace dir
}

// New constructs a Server whose file operations are confined to root.
func New(root string) *Server {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = filepath.Clean(root)
	}
	return &Server{root: abs}
}

// Handler returns the mux wiring every agent endpoint.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/shell/exec", s.handleShellExec)
	mux.HandleFunc("/v1/code/python", s.handlePython)
	mux.HandleFunc("/v1/code/node", s.handleNode)
	mux.HandleFunc("/v1/file/read", s.handleFileRead)
	mux.HandleFunc("/v1/file/write", s.handleFileWrite)
	mux.HandleFunc("/v1/file/edit", s.handleFileEdit)
	mux.HandleFunc("/v1/file/list", s.handleFileList)
	mux.HandleFunc("/v1/file/search", s.handleFileSearch)
	return mux
}

// resolve joins rel with root and errors if the cleaned result escapes it,
// rejecting absolute paths and ".." traversal.
func (s *Server) resolve(rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("path %q must be relative to root", rel)
	}
	joined := filepath.Join(s.root, rel)
	cleaned := filepath.Clean(joined)
	if cleaned != s.root && !strings.HasPrefix(cleaned, s.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes workspace root", rel)
	}
	return cleaned, nil
}

// --- request / response payloads ---

type execResponse struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int64  `json:"duration_ms"`
}

type shellExecRequest struct {
	Command   []string          `json:"command"`
	Workdir   string            `json:"workdir"`
	Env       map[string]string `json:"env"`
	TimeoutMS int               `json:"timeout_ms"`
}

type codeRequest struct {
	Code string `json:"code"`
}

type fileReadRequest struct {
	Path string `json:"path"`
}

type fileReadResponse struct {
	Content string `json:"content"`
}

type fileWriteRequest struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type fileWriteResponse struct {
	Bytes int `json:"bytes"`
}

type fileEditRequest struct {
	Path string `json:"path"`
	Old  string `json:"old"`
	New  string `json:"new"`
	All  bool   `json:"all"`
}

type fileEditResponse struct {
	Replacements int `json:"replacements"`
}

type fileListRequest struct {
	Path string `json:"path"`
}

type fileEntry struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size"`
}

type fileListResponse struct {
	Entries []fileEntry `json:"entries"`
}

type fileSearchRequest struct {
	Path  string `json:"path"`
	Query string `json:"query"`
	Glob  string `json:"glob"`
}

type searchMatch struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

type fileSearchResponse struct {
	Matches []searchMatch `json:"matches"`
}

// --- handlers ---

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleShellExec(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[shellExecRequest](w, r)
	if !ok {
		return
	}
	if len(req.Command) == 0 {
		writeError(w, http.StatusBadRequest, "command must not be empty")
		return
	}

	workdir := s.root
	if req.Workdir != "" {
		resolved, err := s.resolve(req.Workdir)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		workdir = resolved
	}

	res := s.runCommand(r.Context(), req.Command, workdir, req.Env, req.TimeoutMS)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handlePython(w http.ResponseWriter, r *http.Request) {
	s.runScript(w, r, "python3", ".py")
}

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) {
	s.runScript(w, r, "node", ".js")
}

// runScript writes the request code to a temp file, runs it with the given
// interpreter, and cleans up.
func (s *Server) runScript(w http.ResponseWriter, r *http.Request, interpreter, ext string) {
	req, ok := decode[codeRequest](w, r)
	if !ok {
		return
	}

	f, err := os.CreateTemp("", "runeward-agent-*"+ext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create temp file: "+err.Error())
		return
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)

	if _, err := f.WriteString(req.Code); err != nil {
		f.Close()
		writeError(w, http.StatusInternalServerError, "failed to write temp file: "+err.Error())
		return
	}
	if err := f.Close(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to close temp file: "+err.Error())
		return
	}

	res := s.runCommand(r.Context(), []string{interpreter, tmpPath}, s.root, nil, 0)
	writeJSON(w, http.StatusOK, res)
}

// runCommand executes argv (no shell) in workdir. Non-zero exit codes are
// reported in the response, not as HTTP errors.
func (s *Server) runCommand(ctx context.Context, argv []string, workdir string, env map[string]string, timeoutMS int) execResponse {
	if timeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMS)*time.Millisecond)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = workdir
	if len(env) > 0 {
		cmd.Env = os.Environ()
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	res := execResponse{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		DurationMS: duration.Milliseconds(),
	}

	switch {
	case err == nil:
		res.ExitCode = 0
	default:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		} else {
			// Failed to start (missing interpreter) or killed by the deadline.
			res.ExitCode = -1
			if res.Stderr != "" {
				res.Stderr += "\n"
			}
			res.Stderr += err.Error()
		}
	}
	return res
}

func (s *Server) handleFileRead(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[fileReadRequest](w, r)
	if !ok {
		return
	}
	abs, err := s.resolve(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, fileReadResponse{Content: string(data)})
}

func (s *Server) handleFileWrite(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[fileWriteRequest](w, r)
	if !ok {
		return
	}
	abs, err := s.resolve(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "mkdir failed: "+err.Error())
		return
	}
	if err := os.WriteFile(abs, []byte(req.Content), 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "write failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, fileWriteResponse{Bytes: len(req.Content)})
}

func (s *Server) handleFileEdit(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[fileEditRequest](w, r)
	if !ok {
		return
	}
	if req.Old == "" {
		writeError(w, http.StatusBadRequest, "old must not be empty")
		return
	}
	abs, err := s.resolve(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read failed: "+err.Error())
		return
	}
	content := string(data)
	count := strings.Count(content, req.Old)
	if count == 0 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("old string %q not found", req.Old))
		return
	}

	var updated string
	var replacements int
	if req.All {
		updated = strings.ReplaceAll(content, req.Old, req.New)
		replacements = count
	} else {
		updated = strings.Replace(content, req.Old, req.New, 1)
		replacements = 1
	}

	if err := os.WriteFile(abs, []byte(updated), 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "write failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, fileEditResponse{Replacements: replacements})
}

func (s *Server) handleFileList(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[fileListRequest](w, r)
	if !ok {
		return
	}
	abs, err := s.resolve(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dirEntries, err := os.ReadDir(abs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "list failed: "+err.Error())
		return
	}
	entries := make([]fileEntry, 0, len(dirEntries))
	for _, de := range dirEntries {
		info, err := de.Info()
		var size int64
		if err == nil {
			size = info.Size()
		}
		entries = append(entries, fileEntry{
			Name: de.Name(),
			Dir:  de.IsDir(),
			Size: size,
		})
	}
	writeJSON(w, http.StatusOK, fileListResponse{Entries: entries})
}

func (s *Server) handleFileSearch(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[fileSearchRequest](w, r)
	if !ok {
		return
	}
	if req.Query == "" {
		writeError(w, http.StatusBadRequest, "query must not be empty")
		return
	}
	root, err := s.resolve(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	matches := make([]searchMatch, 0)
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable entries rather than aborting the walk.
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if req.Glob != "" {
			ok, matchErr := filepath.Match(req.Glob, d.Name())
			if matchErr != nil {
				return matchErr
			}
			if !ok {
				return nil
			}
		}
		fileMatches, ferr := searchFile(path, req.Query, s.root, maxSearchMatches-len(matches))
		if ferr != nil {
			return nil
		}
		matches = append(matches, fileMatches...)
		if len(matches) >= maxSearchMatches {
			return errStopWalk
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, errStopWalk) {
		writeError(w, http.StatusBadRequest, "search failed: "+walkErr.Error())
		return
	}
	if len(matches) > maxSearchMatches {
		matches = matches[:maxSearchMatches]
	}
	writeJSON(w, http.StatusOK, fileSearchResponse{Matches: matches})
}

// errStopWalk halts filepath.WalkDir once the match cap is reached.
var errStopWalk = errors.New("stop walk")

// searchFile scans one file for query, returning up to limit matches with paths
// relative to root.
func searchFile(path, query, root string, limit int) ([]searchMatch, error) {
	if limit <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rel, relErr := filepath.Rel(root, path)
	if relErr != nil {
		rel = path
	}

	var out []searchMatch
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if strings.Contains(text, query) {
			out = append(out, searchMatch{Path: rel, Line: line, Text: text})
			if len(out) >= limit {
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// --- helpers ---

// decode enforces POST and decodes a JSON body into T, writing a 400 on
// failure.
func decode[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return v, false
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return v, false
	}
	return v, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
