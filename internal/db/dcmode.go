package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// DC modes recorded in telegram_dc_mode (issue #854).
const (
	DCModeProduction = "production"
	DCModeTest       = "test"
)

// ErrDCModeMismatch means the store's sessions belong to the other set of
// Telegram datacenters than the ones this process is configured for.
var ErrDCModeMismatch = errors.New("telegram DC mode does not match this store")

// EnsureDCMode checks that the sessions in this store belong to mode
// (DCModeProduction or DCModeTest) and stamps the store on first use.
//
// Telegram's test DCs hold their own accounts, so a production session sent
// to them, or the reverse, is rejected, and the client pool revokes a
// rejected session. A process pointed at the wrong DCs would therefore revoke
// every session it touched. EnsureDCMode is the boot check that prevents it.
//
// A store with no stamp is stamped with mode, except that a store that
// already holds a telegram_accounts row predates the stamp and was
// production: it is stamped production whatever mode asks for. A failed
// read is an error, never a pass.
func (s *Store) EnsureDCMode(ctx context.Context, mode string) error {
	if mode != DCModeProduction && mode != DCModeTest {
		return fmt.Errorf("EnsureDCMode: unknown mode %q", mode)
	}
	stamped, err := s.dcMode(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		var accounts int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM telegram_accounts`).Scan(&accounts); err != nil {
			return fmt.Errorf("EnsureDCMode: count accounts: %w", err)
		}
		stamp := mode
		if accounts > 0 {
			stamp = DCModeProduction
		}
		// DO NOTHING: another replica booting at the same moment may stamp
		// first; the re-read below then checks against its stamp.
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO telegram_dc_mode (id, mode) VALUES (1, $1) ON CONFLICT (id) DO NOTHING`, stamp); err != nil {
			return fmt.Errorf("EnsureDCMode: stamp: %w", err)
		}
		stamped, err = s.dcMode(ctx)
	}
	if err != nil {
		return fmt.Errorf("EnsureDCMode: read stamp: %w", err)
	}
	if stamped != mode {
		return fmt.Errorf("%w: the store holds %s-DC sessions but this process is configured for the %s DCs", ErrDCModeMismatch, stamped, mode)
	}
	return nil
}

func (s *Store) dcMode(ctx context.Context) (string, error) {
	var mode string
	err := s.DB.QueryRowContext(ctx, `SELECT mode FROM telegram_dc_mode WHERE id = 1`).Scan(&mode)
	return mode, err
}

// DCModeFor maps a TG_TEST_DC setting to the mode EnsureDCMode expects.
func DCModeFor(testDC bool) string {
	if testDC {
		return DCModeTest
	}
	return DCModeProduction
}
