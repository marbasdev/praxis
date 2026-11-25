package config

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"praxis/internal/domain"
)

const (
	sealedSecretPrefix = "enc:v1:"
	vaultMasterKeyName = "master.key"
	vaultKeyLen        = 32
)

func MasterKeyFilePath(dataDir string) string {
	dir := strings.TrimSpace(dataDir)
	if dir == "" {
		return ""
	}
	return filepath.Join(filepath.Clean(dir), vaultMasterKeyName)
}

func IsSealedSecret(val string) bool {
	return strings.HasPrefix(strings.TrimSpace(val), sealedSecretPrefix)
}

func isSecretConfigKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	switch k {
	case "gemini_api_key", "typesafe_api_key", "local_api_key":
		return true
	}
	return strings.HasSuffix(k, "_api_key") || strings.HasSuffix(k, "_secret") || strings.HasSuffix(k, "_token")
}

func readExistingVaultKey(keyPath string) ([]byte, error) {
	info, err := os.Lstat(keyPath)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("vault key %s must be a regular non-symlink file", keyPath)
	}
	if info.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(keyPath, 0o600)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		time.Sleep(5 * time.Millisecond)
		raw, err = os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
	}
	if len(raw) != vaultKeyLen {
		return nil, fmt.Errorf("invalid vault key length (%d bytes)", len(raw))
	}
	return raw, nil
}

func loadOrCreateVaultKey(dataDir string, createIfMissing bool) ([]byte, error) {
	keyPath := MasterKeyFilePath(dataDir)
	if keyPath == "" {
		return nil, errors.New("empty vault data directory")
	}
	if key, err := readExistingVaultKey(keyPath); err == nil {
		return key, nil
	} else if !os.IsNotExist(err) || !createIfMissing {
		return nil, err
	}

	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fresh := make([]byte, vaultKeyLen)
	if _, err := io.ReadFull(rand.Reader, fresh); err != nil {
		return nil, err
	}
	tf, err := os.CreateTemp(dir, vaultMasterKeyName+".tmp-*")
	if err != nil {
		return nil, err
	}
	tmp := tf.Name()
	_, werr := tf.Write(fresh)
	_ = tf.Sync()
	cerr := tf.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		if werr != nil {
			return nil, werr
		}
		return nil, cerr
	}
	_ = os.Chmod(tmp, 0o600)

	// os.Link places the complete 0600 key without overwriting a concurrent winner.
	if lerr := os.Link(tmp, keyPath); lerr == nil {
		_ = os.Remove(tmp)
		if key, rerr := readExistingVaultKey(keyPath); rerr == nil {
			return key, nil
		}
		return fresh, nil
	}
	_ = os.Remove(tmp)
	if key, rerr := readExistingVaultKey(keyPath); rerr == nil {
		return key, nil
	}
	// Fallback for filesystems without hardlinks: O_CREATE|O_EXCL never clobbers an existing winner.
	ef, oerr := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if oerr != nil {
		if key, rerr := readExistingVaultKey(keyPath); rerr == nil {
			return key, nil
		}
		return nil, oerr
	}
	_, werr = ef.Write(fresh)
	_ = ef.Sync()
	cerr = ef.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(keyPath)
		if werr != nil {
			return nil, werr
		}
		return nil, cerr
	}
	return fresh, nil
}

func vaultAAD(name string) []byte {
	return []byte("praxis:v1:" + strings.ToLower(strings.TrimSpace(name)))
}

func sealSecret(dataDir, aadName, plain string) (string, error) {
	trimmed := strings.TrimSpace(plain)
	if trimmed == "" || strings.TrimSpace(dataDir) == "" {
		return trimmed, nil
	}
	if IsSealedSecret(trimmed) {
		if _, ok := openSecret(dataDir, aadName, trimmed); ok {
			return trimmed, nil
		}
	}
	key, err := loadOrCreateVaultKey(dataDir, true)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(trimmed), vaultAAD(aadName))
	return sealedSecretPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func openSecret(dataDir, aadName, stored string) (string, bool) {
	trimmed := strings.TrimSpace(stored)
	if !IsSealedSecret(trimmed) {
		return trimmed, true
	}
	if strings.TrimSpace(dataDir) == "" {
		return "", false
	}
	key, err := loadOrCreateVaultKey(dataDir, false)
	if err != nil {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(trimmed, sealedSecretPrefix))
	if err != nil {
		return "", false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(raw) < gcm.NonceSize() {
		return "", false
	}
	ns := gcm.NonceSize()
	plain, err := gcm.Open(nil, raw[:ns], raw[ns:], vaultAAD(aadName))
	if err != nil {
		return "", false
	}
	return string(plain), true
}

func resolveDBDataDir(ctx context.Context, db *sql.DB) string {
	if db == nil {
		return ""
	}
	var dbFile string
	if err := db.QueryRowContext(ctx, `SELECT file FROM pragma_database_list WHERE name = 'main'`).Scan(&dbFile); err != nil {
		return ""
	}
	return DataDirForDBPath(dbFile)
}

const (
	CfgActiveProvider           = "active_provider"
	CfgGGUFEndpoint             = "gguf_endpoint"
	CfgGGUFModel                = "gguf_model"
	CfgIncludePersonalInProject = "include_personal_in_project"
	CfgDefaultAccount           = "default_account"
	CfgPresetCategories         = "preset_categories"
	CfgRulePackAuthor           = "rulepack_author"

	CfgProgressRetentionDays   = "progress_retention_days"
	CfgGuardrailRetentionDays  = "guardrail_retention_days"
	CfgGuardrailIncludeBlocked = "guardrail_retention_include_blocked"
	// CfgProgressPrunedMemHWM stores the highest pruned memory ID per scope to prevent resurrection.
	CfgProgressPrunedMemHWM = "progress_pruned_mem_hwm:"
)

func LoadRetentionPolicy(ctx context.Context, db *sql.DB) domain.RetentionPolicy {
	cfg := GetConfigMap(ctx, db)
	progDays := 0
	if raw, ok := cfg[CfgProgressRetentionDays]; ok && strings.TrimSpace(raw) != "" {
		if v, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			progDays = domain.NormalizeRetentionDays(v)
		}
	}
	grDays := 0
	if raw, ok := cfg[CfgGuardrailRetentionDays]; ok && strings.TrimSpace(raw) != "" {
		if v, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			grDays = domain.NormalizeRetentionDays(v)
		}
	}
	return domain.RetentionPolicy{
		ProgressDays:            progDays,
		GuardrailDays:           grDays,
		GuardrailIncludeBlocked: cfg[CfgGuardrailIncludeBlocked] == "1",
	}
}

func GetConfigMap(ctx context.Context, db *sql.DB) map[string]string {
	out := make(map[string]string)
	if db == nil {
		return out
	}
	rows, err := db.QueryContext(ctx, `SELECT key, val FROM config`)
	if err != nil {
		return out
	}
	var sealedKeys []string
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			out[k] = v
			if isSecretConfigKey(k) && IsSealedSecret(v) {
				sealedKeys = append(sealedKeys, k)
			}
		}
	}
	_ = rows.Close()
	if len(sealedKeys) > 0 {
		dir := resolveDBDataDir(ctx, db)
		for _, k := range sealedKeys {
			if plain, ok := openSecret(dir, k, out[k]); ok {
				out[k] = plain
			} else {
				out[k] = ""
			}
		}
	}
	return out
}

// SaveConfig atomically upserts key/value configuration pairs (sealing secret keys via AES-GCM on persistent DBs)
// and re-enforces 0600 file permissions.
func SaveConfig(ctx context.Context, db *sql.DB, dbPath string, pairs map[string]string) error {
	if db == nil {
		return nil
	}
	dir := DataDirForDBPath(dbPath)
	prepared := make(map[string]string, len(pairs))
	wroteSecret := false
	for k, v := range pairs {
		trimmed := strings.TrimSpace(v)
		if dir != "" && trimmed != "" && isSecretConfigKey(k) {
			sealed, err := sealSecret(dir, k, trimmed)
			if err != nil {
				return err
			}
			trimmed = sealed
			wroteSecret = true
		}
		prepared[k] = trimmed
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, v := range prepared {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO config(key, val) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET val = excluded.val`,
			k, v); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if wroteSecret {
		_, _ = db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	}
	RestrictDBPermissions(dbPath)
	return nil
}

// MigratePlaintextSecrets upgrades any legacy unencrypted secret values in SQLite config and remotes.json to AES-GCM.
func MigratePlaintextSecrets(ctx context.Context, db *sql.DB, dbPath string) {
	dir := DataDirForDBPath(dbPath)
	if db == nil || dir == "" {
		return
	}
	rows, err := db.QueryContext(ctx, `SELECT key, val FROM config`)
	if err == nil {
		toSeal := make(map[string]string)
		for rows.Next() {
			var k, v string
			if rows.Scan(&k, &v) == nil {
				v = strings.TrimSpace(v)
				if v != "" && isSecretConfigKey(k) && !IsSealedSecret(v) {
					toSeal[k] = v
				}
			}
		}
		_ = rows.Close()
		if len(toSeal) > 0 {
			_ = SaveConfig(domain.WithAdminBypass(ctx), db, dbPath, toSeal)
		}
	}
	migratePlaintextRemotes(dir)
}

func SyncManagedGGUFEndpoint(ctx context.Context, db *sql.DB, dbPath, ep string) error {
	if db == nil || strings.TrimSpace(ep) == "" {
		return nil
	}
	if strings.TrimSpace(os.Getenv("LOCAL_GGUF_URL")) != "" {
		return nil
	}
	raw := GetConfigMap(ctx, db)
	cur := strings.TrimSpace(raw[CfgGGUFEndpoint])
	if cur != "" && !domain.IsLoopbackEndpoint(cur) {
		return nil
	}
	trimmed := strings.TrimRight(strings.TrimSpace(ep), "/")
	if strings.TrimRight(cur, "/") == trimmed {
		return nil
	}
	return SaveConfig(domain.WithAdminBypass(ctx), db, dbPath, map[string]string{CfgGGUFEndpoint: trimmed})
}
