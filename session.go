package otf

import (
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

// Session is a user session
type Session struct {
	Token       string
	Expiry      time.Time
	SessionData `db:"data"`

	// Timestamps records timestamps of lifecycle transitions
	Timestamps

	// Session belongs to a user
	UserID string
}

func (s *Session) GetID() string  { return s.Token }
func (s *Session) String() string { return s.Token }

func newSession(u *User, data *SessionData) (*Session, error) {
	token, err := generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("generating session token: %w", err)
	}

	session := Session{
		Token:       token,
		SessionData: *data,
		Expiry:      time.Now().Add(DefaultSessionExpiry),
		UserID:      u.ID,
	}

	return &session, nil
}

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SessionData is various session data serialised to the session store as JSON.
type SessionData struct {
	Address string
	Flash   *Flash
}

// Value: struct -> db
func (sd SessionData) Value() (driver.Value, error) {
	return json.Marshal(sd)
}

// Scan: db -> struct
func (sd SessionData) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion to []byte failed")
	}
	return json.Unmarshal(b, &sd)
}

func (sd *SessionData) SetFlash(t FlashType, msg ...interface{}) {
	sd.Flash = &Flash{
		Type:    t,
		Message: fmt.Sprint(msg...),
	}
}

func (sd *SessionData) PopFlash() *Flash {
	ret := sd.Flash
	sd.Flash = nil
	return ret
}

type Flash struct {
	Type    FlashType
	Message string
}

type FlashType string

const (
	FlashSuccessType = "success"
	FlashErrorType   = "error"
)
