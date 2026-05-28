package rbac

import (
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/jmoiron/sqlx"

	"github.com/tursom/turjmp/internal/repository"
)

type Adapter struct {
	db *repository.DB
}

func NewAdapter(db *repository.DB) *Adapter {
	return &Adapter{db: db}
}

func (a *Adapter) LoadPolicy(m model.Model) error {
	rows, err := a.db.Queryx(`SELECT ptype, v0, v1, v2, v3, v4, v5 FROM casbin_rules ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ptype string
		vals := make([]string, 6)
		if err := rows.Scan(&ptype, &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]); err != nil {
			return err
		}
		line := ptype
		for _, v := range vals {
			if v == "" {
				continue
			}
			line += ", " + v
		}
		persist.LoadPolicyLine(line, m)
	}
	return rows.Err()
}

func (a *Adapter) SavePolicy(m model.Model) error {
	return withTx(a.db.DB, func(tx *sqlx.Tx) error {
		if _, err := tx.Exec(`DELETE FROM casbin_rules`); err != nil {
			return err
		}
		for ptype, ast := range m["p"] {
			for _, rule := range ast.Policy {
				if err := a.insertRule(tx, ptype, rule); err != nil {
					return err
				}
			}
		}
		for ptype, ast := range m["g"] {
			for _, rule := range ast.Policy {
				if err := a.insertRule(tx, ptype, rule); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.insertRule(a.db.DB, ptype, rule)
}

func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	vals := padded(rule)
	q := a.db.Rebind(`DELETE FROM casbin_rules WHERE ptype = ? AND v0 = ? AND v1 = ? AND v2 = ? AND v3 = ? AND v4 = ? AND v5 = ?`)
	_, err := a.db.Exec(q, ptype, vals[0], vals[1], vals[2], vals[3], vals[4], vals[5])
	return err
}

func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	clauses := []string{"ptype = ?"}
	args := []any{ptype}
	for i, value := range fieldValues {
		if value == "" {
			continue
		}
		field := fieldIndex + i
		if field < 0 || field > 5 {
			return fmt.Errorf("invalid casbin field index %d", field)
		}
		clauses = append(clauses, fmt.Sprintf("v%d = ?", field))
		args = append(args, value)
	}
	_, err := a.db.Exec(a.db.Rebind("DELETE FROM casbin_rules WHERE "+strings.Join(clauses, " AND ")), args...)
	return err
}

func (a *Adapter) insertRule(ext sqlx.Ext, ptype string, rule []string) error {
	vals := padded(rule)
	q := a.db.Rebind(`INSERT INTO casbin_rules (ptype, v0, v1, v2, v3, v4, v5)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	_, err := ext.Exec(q, ptype, vals[0], vals[1], vals[2], vals[3], vals[4], vals[5])
	if err != nil && isUniqueViolation(err) {
		return nil
	}
	return err
}

func padded(rule []string) []string {
	vals := make([]string, 6)
	copy(vals, rule)
	return vals
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}

func withTx(db *sqlx.DB, fn func(*sqlx.Tx) error) error {
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

var _ persist.Adapter = (*Adapter)(nil)
