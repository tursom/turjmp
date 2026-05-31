// 包 rbac 提供 Casbin 数据库适配器，将 casbin_rules 表映射为 Casbin 的策略模型。
//
// casbin_rules 表结构：ptype（策略类型，p 为权限规则、g 为角色分配）和 6 个值字段 v0~v5。
// 适配器实现 persist.Adapter 接口，支持策略的增删改查和批量同步。
// 写入时自动忽略唯一约束冲突（幂等），使 ensureDefaultPolicies 可安全重复调用。
package rbac

import (
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/jmoiron/sqlx"

	"github.com/tursom/turjmp/internal/repository"
)

// Adapter 是 Casbin 的数据库策略适配器，将策略数据读写到 casbin_rules 表。
type Adapter struct {
	db *repository.DB
}

// NewAdapter 创建 DB 适配器实例。
func NewAdapter(db *repository.DB) *Adapter {
	return &Adapter{db: db}
}

// LoadPolicy 从 casbin_rules 表读取所有策略并加载到 Casbin 模型中。
// 每行记录的 ptype 与 v0~v5 按 Casbin policy line 格式拼接（逗号分隔）。
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

// SavePolicy 将模型中的所有策略全量同步到数据库。
// 先清空 casbin_rules 表，再写入 p（权限）和 g（角色）类型的所有策略。
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

// AddPolicy 向 casbin_rules 表添加一条策略规则。
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.insertRule(a.db.DB, ptype, rule)
}

// RemovePolicy 从 casbin_rules 表精确删除一条策略规则。
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	vals := padded(rule)
	q := a.db.Rebind(`DELETE FROM casbin_rules WHERE ptype = ? AND v0 = ? AND v1 = ? AND v2 = ? AND v3 = ? AND v4 = ? AND v5 = ?`)
	_, err := a.db.Exec(q, ptype, vals[0], vals[1], vals[2], vals[3], vals[4], vals[5])
	return err
}

// RemoveFilteredPolicy 按字段条件过滤删除策略规则。
// fieldIndex 指定起始字段索引（0~5），fieldValues 中非空值用于 WHERE 条件过滤。
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	clauses := []string{"ptype = ?"}
	args := []any{ptype}
	for i, value := range fieldValues {
		if value == "" {
			continue
		}
		field := fieldIndex + i
		if field < 0 || field > 5 {
			return fmt.Errorf("无效的 casbin 字段索引：%d", field)
		}
		clauses = append(clauses, fmt.Sprintf("v%d = ?", field))
		args = append(args, value)
	}
	_, err := a.db.Exec(a.db.Rebind("DELETE FROM casbin_rules WHERE "+strings.Join(clauses, " AND ")), args...)
	return err
}

// insertRule 向 casbin_rules 表插入一条策略规则。
// 规则数组自动补齐至 6 个元素（不足补空字符串），若发生唯一约束冲突则静默忽略（幂等写入）。
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

// padded 将规则切片补齐至 6 个元素，不足部分填充空字符串。
func padded(rule []string) []string {
	vals := make([]string, 6)
	copy(vals, rule)
	return vals
}

// isUniqueViolation 判断数据库错误是否为唯一约束冲突，用于幂等写入策略。
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}

// withTx 在数据库事务中执行回调函数，自动处理 begin/commit/rollback。
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
