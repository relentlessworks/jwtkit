package store

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/relentlessworks/jwtkit/internal/model"
)

// Data is the on-disk JSON structure.
type Data struct {
	Workspaces map[string]*model.Workspace `json:"workspaces"`
	Keys       map[string]*model.Key       `json:"keys"`
	Tokens     map[string]*model.Token     `json:"tokens"`
	OTPs       map[string]*model.OTP       `json:"otps"`
}

// Store is a JSON-file-backed data store with an in-memory cache.
type Store struct {
	mu   sync.RWMutex
	data *Data
	path string
}

// New opens (or creates) a store at the given file path.
func New(path string) (*Store, error) {
	s := &Store{
		path: path,
		data: &Data{
			Workspaces: make(map[string]*model.Workspace),
			Keys:       make(map[string]*model.Key),
			Tokens:     make(map[string]*model.Token),
			OTPs:       make(map[string]*model.OTP),
		},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // fresh start
		}
		return err
	}
	return json.Unmarshal(b, s.data)
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0644)
}

// Close flushes the store to disk.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save()
}

// --- Workspace ---

func (s *Store) GetWorkspace(id string) (*model.Workspace, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ws, ok := s.data.Workspaces[id]
	return ws, ok
}

func (s *Store) CreateWorkspace(ws *model.Workspace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Workspaces[ws.ID] = ws
	return s.save()
}

// --- Key ---

func (s *Store) CreateKey(k *model.Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Keys[k.Handle] = k
	return s.save()
}

func (s *Store) GetKey(handle string) (*model.Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.data.Keys[handle]
	return k, ok
}

func (s *Store) ListKeys(workspaceID string) []*model.Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []*model.Key
	for _, k := range s.data.Keys {
		if k.WorkspaceID == workspaceID {
			keys = append(keys, k)
		}
	}
	return keys
}

func (s *Store) DeleteKey(handle, workspaceID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.data.Keys[handle]
	if !ok || k.WorkspaceID != workspaceID {
		return false
	}
	delete(s.data.Keys, handle)
	_ = s.save()
	return true
}

// --- Token ---

func (s *Store) CreateToken(t *model.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Tokens[t.Handle] = t
	return s.save()
}

func (s *Store) GetTokenByHash(hash string) (*model.Token, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.data.Tokens {
		if t.TokenHash == hash {
			return t, true
		}
	}
	return nil, false
}

func (s *Store) DeleteToken(handle string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data.Tokens[handle]
	if !ok {
		return false
	}
	delete(s.data.Tokens, handle)
	_ = s.save()
	return true
}

// --- OTP ---

func (s *Store) SaveOTP(otp *model.OTP) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.OTPs[otp.Email] = otp
	return s.save()
}

func (s *Store) GetOTP(email string) (*model.OTP, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	otp, ok := s.data.OTPs[email]
	return otp, ok
}

func (s *Store) MarkOTPUsed(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if otp, ok := s.data.OTPs[email]; ok {
		otp.Used = true
		_ = s.save()
	}
}

// CleanupOTPs removes expired OTP entries.
func (s *Store) CleanupOTPs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for email, otp := range s.data.OTPs {
		if now.After(otp.ExpiresAt) {
			delete(s.data.OTPs, email)
		}
	}
	_ = s.save()
}
