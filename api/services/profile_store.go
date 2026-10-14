package services

import (
	"database/sql"
	"time"
)

// ensureProfileTable lazily creates the per-user profile/preferences table.
func (s *DBStore) ensureProfileTable() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS user_profiles (
		user_id INTEGER PRIMARY KEY,
		data TEXT NOT NULL DEFAULT '{}',
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`)
	return err
}

// GetUserProfile returns the raw JSON profile document for a user ("{}" when none saved yet)
// along with the last update time (zero when never saved).
func (s *DBStore) GetUserProfile(userID int64) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureProfileTable(); err != nil {
		return "{}", time.Time{}, err
	}

	var data, updated string
	err := s.db.QueryRow("SELECT data, COALESCE(updated_at, '') FROM user_profiles WHERE user_id = ?", userID).Scan(&data, &updated)
	if err == sql.ErrNoRows {
		return "{}", time.Time{}, nil
	}
	if err != nil {
		return "{}", time.Time{}, err
	}
	t, _ := time.Parse("2006-01-02 15:04:05", updated)
	return data, t, nil
}

// SaveUserProfile upserts the JSON profile document for a user.
func (s *DBStore) SaveUserProfile(userID int64, data string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureProfileTable(); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO user_profiles (user_id, data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`, userID, data)
	return err
}
