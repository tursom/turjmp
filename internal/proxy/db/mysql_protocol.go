// Package dbproxy 实现数据库协议代理和 Web 数据库终端。
//
// 本文件实现 MySQL 客户端/服务器协议（wire protocol）的子集，用于代理场景：
//   - 服务器端：发送握手包、解析握手响应、发送 OK/ERR/EOF/结果集包
//   - 不需要完整的 MySQL 协议实现，仅覆盖代理所需的命令和包类型
//
// MySQL 协议包格式（packet framing）：
//   每个包 = 4 字节头部 + payload
//   头部：[3 字节 payload 长度（小端序）] [1 字节序列号]
//   最大 payload 大小：16MB - 1（0xFFFFFF）
//
// 握手流程（HandshakeV10）：
//   1. 服务器 → 客户端：Initial Handshake Packet（协议版本、服务器版本、连接 ID、认证盐、能力标志等）
//   2. 客户端 → 服务器：Handshake Response Packet（能力标志、用户名、认证响应、数据库名等）
//   3. 服务器 → 客户端：OK Packet（认证成功）或 ERR Packet（认证失败）
//
// 结果集序列化格式：
//   1. 列数（Length-Encoded Integer）
//   2. 每列的 Column Definition Packet（"def" catalog、schema、table、name、类型、长度等）
//   3. EOF Packet（标记列定义结束）
//   4. 每行的 Row Data Packet（每个字段以 Length-Encoded String 编码，NULL 用 0xFB 表示）
//   5. EOF Packet（标记结果集结束）
//
// Length-Encoded Integer 编码规则：
//   < 251         — 1 字节直接存储
//   251-65535     — 0xFC + 2 字节 uint16（小端序）
//   65536-16777215— 0xFD + 3 字节（小端序）
//   >= 16777216   — 0xFE + 8 字节 uint64（小端序）
package dbproxy

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// MySQL 协议常量定义

// mysqlProtocolVersion MySQL 握手协议版本号（HandshakeV10）。
const mysqlProtocolVersion = 10

// mysqlMaxPacketSize MySQL 协议包的最大 payload 大小（16MB - 1）。
const mysqlMaxPacketSize = 1<<24 - 1

// mysqlServerVersion 伪装为 MySQL 8.0 的服务器版本字符串，后缀 -turjmp 表示代理标识。
const mysqlServerVersion = "8.0.0-turjmp"

// 客户端能力标志（CLIENT_* flags），在握手包中声明代理支持的功能。
const (
	mysqlClientLongPassword     uint32 = 1 << 0  // CLIENT_LONG_PASSWORD — 支持新版密码认证（始终设置）
	mysqlClientLongFlag         uint32 = 1 << 2  // CLIENT_LONG_FLAG — 支持协议 4.1 的扩展标志
	mysqlClientConnectWithDB    uint32 = 1 << 3  // CLIENT_CONNECT_WITH_DB — 客户端可在握手时指定默认数据库
	mysqlClientProtocol41       uint32 = 1 << 9  // CLIENT_PROTOCOL_41 — 使用协议版本 4.1
	mysqlClientTransactions     uint32 = 1 << 13 // CLIENT_TRANSACTIONS — 支持事务状态标志
	mysqlClientSecureConn       uint32 = 1 << 15 // CLIENT_SECURE_CONNECTION — 支持安全连接认证（4.1.1 风格）
	mysqlClientMultiResults     uint32 = 1 << 17 // CLIENT_MULTI_RESULTS — 支持多结果集
	mysqlClientPluginAuth       uint32 = 1 << 19 // CLIENT_PLUGIN_AUTH — 支持认证插件机制
	mysqlClientPluginAuthLenEnc uint32 = 1 << 21 // CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA — 认证响应长度使用 Length-Encoded 编码
)

// mysqlStatusAutocommit 标识会话处于自动提交模式（SERVER_STATUS_AUTOCOMMIT）。
const mysqlStatusAutocommit uint16 = 2

// MySQL 命令类型字节（payload[0]），客户端发送给服务器的命令标识。
const (
	mysqlComQuit        byte = 0x01 // COM_QUIT — 断开连接
	mysqlComInitDB      byte = 0x02 // COM_INIT_DB — 切换数据库
	mysqlComQuery       byte = 0x03 // COM_QUERY — 执行 SQL 文本查询
	mysqlComPing        byte = 0x0e // COM_PING — 心跳检测
	mysqlComStmtPrepare byte = 0x16 // COM_STMT_PREPARE — 准备预处理语句
	mysqlComStmtExecute byte = 0x17 // COM_STMT_EXECUTE — 执行预处理语句
	mysqlComStmtClose   byte = 0x19 // COM_STMT_CLOSE — 关闭预处理语句
)

// MySQL 列类型常量（Column Type），用于结果集的 Column Definition Packet。
const (
	mysqlTypeDecimal   byte = 0x00 // MYSQL_TYPE_DECIMAL — 定点数
	mysqlTypeLong      byte = 0x03 // MYSQL_TYPE_LONG — 32 位整数
	mysqlTypeFloat     byte = 0x04 // MYSQL_TYPE_FLOAT — 单精度浮点数
	mysqlTypeDouble    byte = 0x05 // MYSQL_TYPE_DOUBLE — 双精度浮点数
	mysqlTypeTimestamp byte = 0x07 // MYSQL_TYPE_TIMESTAMP — 时间戳
	mysqlTypeLongLong  byte = 0x08 // MYSQL_TYPE_LONGLONG — 64 位整数
	mysqlTypeDate      byte = 0x0a // MYSQL_TYPE_DATE — 日期
	mysqlTypeTime      byte = 0x0b // MYSQL_TYPE_TIME — 时间
	mysqlTypeDateTime  byte = 0x0c // MYSQL_TYPE_DATETIME — 日期时间
	mysqlTypeVarString byte = 0xfd // MYSQL_TYPE_VAR_STRING — 变长字符串（默认类型）
	mysqlTypeJSON      byte = 0xf5 // MYSQL_TYPE_JSON — JSON 类型
)

// handshakeResponse 解析后的客户端握手响应数据。
// 包含能力标志、用户名、密码（认证响应）和可选的数据库名。
type handshakeResponse struct {
	Username string // 客户端用户名（可能包含 #token 格式的连接 token）
	Password string // 认证响应（在此代理中用作密码或 token）
	Database string // 客户端指定的默认数据库（可为空）
}

// readMySQLPacket 从 TCP 连接读取一个完整的 MySQL 协议包。
// 返回 payload 数据、序列号和错误。
// 包格式：4 字节头部（3 字节长度 + 1 字节序列号），后跟 payload。
func readMySQLPacket(conn net.Conn) ([]byte, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, 0, err
	}
	// 小端序解析 3 字节 payload 长度
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	seq := header[3]
	if length > mysqlMaxPacketSize {
		return nil, seq, fmt.Errorf("mysql packet too large: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, seq, err
	}
	return payload, seq, nil
}

// writeMySQLPacket 向 TCP 连接写入一个 MySQL 协议包。
// 自动构建 4 字节头部（3 字节长度 + 1 字节序列号）。
func writeMySQLPacket(conn net.Conn, seq byte, payload []byte) error {
	if len(payload) > mysqlMaxPacketSize {
		return fmt.Errorf("mysql packet too large: %d", len(payload))
	}
	packet := make([]byte, 4+len(payload))
	packet[0] = byte(len(payload))
	packet[1] = byte(len(payload) >> 8)
	packet[2] = byte(len(payload) >> 16)
	packet[3] = seq
	copy(packet[4:], payload)
	_, err := conn.Write(packet)
	return err
}

// writeHandshake 向客户端发送 MySQL Initial Handshake Packet（HandshakeV10）。
// 包结构（按顺序）：
//
//	1 字节   协议版本 (10)
//	变长     服务器版本字符串（null 结尾）
//	4 字节   连接 ID（使用纳秒时间戳模拟）
//	8 字节   认证盐前半部分 (salt1)
//	1 字节   0x00（分隔符）
//	2 字节   能力标志低 16 位
//	1 字节   字符集（33 = utf8mb4_general_ci）
//	2 字节   服务器状态标志
//	2 字节   能力标志高 16 位
//	1 字节   认证盐后半部分长度
//	10 字节  保留（0x00）
//	变长     认证盐后半部分 (salt2，null 结尾）
//	变长     认证插件名 ("mysql_native_password"，null 结尾）
func writeHandshake(conn net.Conn) error {
	caps := mysqlClientLongPassword |
		mysqlClientLongFlag |
		mysqlClientConnectWithDB |
		mysqlClientProtocol41 |
		mysqlClientTransactions |
		mysqlClientSecureConn |
		mysqlClientMultiResults |
		mysqlClientPluginAuth |
		mysqlClientPluginAuthLenEnc
	salt1 := []byte("turjmp01")     // 认证盐前半部分
	salt2 := []byte("turjmp-dbproxy") // 认证盐后半部分
	var payload bytes.Buffer
	payload.WriteByte(mysqlProtocolVersion)                                   // 协议版本
	payload.WriteString(mysqlServerVersion)                                  // 服务器版本
	payload.WriteByte(0)                                                     // null 终止符
	_ = binary.Write(&payload, binary.LittleEndian, uint32(time.Now().UnixNano())) // 连接 ID
	payload.Write(salt1)                                                     // 盐 1
	payload.WriteByte(0)                                                     // null 终止
	_ = binary.Write(&payload, binary.LittleEndian, uint16(caps))            // 能力标志低 16 位
	payload.WriteByte(33)                                                    // 字符集 utf8mb4_general_ci
	_ = binary.Write(&payload, binary.LittleEndian, mysqlStatusAutocommit)   // 服务器状态
	_ = binary.Write(&payload, binary.LittleEndian, uint16(caps>>16))        // 能力标志高 16 位
	payload.WriteByte(21)                                                    // 盐 2 长度（含 null）
	payload.Write(make([]byte, 10))                                          // 保留 10 字节
	payload.Write(salt2)                                                     // 盐 2
	payload.WriteByte(0)                                                     // null 终止
	payload.WriteString("mysql_native_password")                             // 认证插件
	payload.WriteByte(0)                                                     // null 终止
	return writeMySQLPacket(conn, 0, payload.Bytes())
}

// parseHandshakeResponse 解析客户端握手响应包。
// 包结构：
//
//	4 字节         能力标志
//	4 字节         最大包大小
//	1 字节         字符集
//	23 字节        保留（全 0）
//	变长（null 结尾）用户名
//	变长            认证响应（长度取决于能力标志中的 CLIENT_SECURE_CONNECTION 和 CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA）
//	变长（null 结尾）数据库名（仅当 CLIENT_CONNECT_WITH_DB 标志置位）
func parseHandshakeResponse(payload []byte) (handshakeResponse, error) {
	if len(payload) < 32 {
		return handshakeResponse{}, fmt.Errorf("short mysql handshake response")
	}
	flags := binary.LittleEndian.Uint32(payload[:4]) // 客户端能力标志
	pos := 4 + 4 + 1 + 23                             // 跳过：caps(4) + maxPacket(4) + charset(1) + reserved(23)
	// 读取用户名（null 结尾字符串）
	username, next, ok := readNullString(payload, pos)
	if !ok {
		return handshakeResponse{}, fmt.Errorf("missing mysql username")
	}
	pos = next
	// 读取认证响应（密码）
	authResp, next, ok := readAuthResponse(payload, pos, flags)
	if !ok {
		return handshakeResponse{}, fmt.Errorf("invalid mysql auth response")
	}
	pos = next
	var database string
	// 若客户端请求连接时指定了数据库，读取数据库名
	if flags&mysqlClientConnectWithDB != 0 && pos < len(payload) {
		database, _, _ = readNullString(payload, pos)
	}
	return handshakeResponse{
		Username: username,
		Password: printableAuthResponse(authResp),
		Database: database,
	}, nil
}

// readAuthResponse 读取握手响应中的认证响应字段。
// 根据能力标志选择不同的长度编码方式：
//   - CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA：长度使用 Length-Encoded Integer
//   - CLIENT_SECURE_CONNECTION：1 字节长度 + 数据
//   - 否则：null 结尾字符串（旧版协议）
func readAuthResponse(payload []byte, pos int, flags uint32) ([]byte, int, bool) {
	if pos > len(payload) {
		return nil, pos, false
	}
	switch {
	case flags&mysqlClientPluginAuthLenEnc != 0:
		// 长度使用 Length-Encoded Integer 编码
		n, next, ok := readLenEncInt(payload, pos)
		if !ok || next+int(n) > len(payload) {
			return nil, pos, false
		}
		return payload[next : next+int(n)], next + int(n), true
	case flags&mysqlClientSecureConn != 0:
		// 1 字节长度 + 数据
		if pos >= len(payload) {
			return nil, pos, false
		}
		n := int(payload[pos])
		pos++
		if pos+n > len(payload) {
			return nil, pos, false
		}
		return payload[pos : pos+n], pos + n, true
	default:
		// 旧版协议：null 结尾字符串
		value, next, ok := readNullBytes(payload, pos)
		return value, next, ok
	}
}

// readNullString 读取一个 null 结尾的字符串。
func readNullString(payload []byte, pos int) (string, int, bool) {
	value, next, ok := readNullBytes(payload, pos)
	return string(value), next, ok
}

// readNullBytes 读取一个 null 结尾的字节序列。
// 返回 null 字节之前的内容、null 字节之后的位置、以及是否成功。
func readNullBytes(payload []byte, pos int) ([]byte, int, bool) {
	if pos > len(payload) {
		return nil, pos, false
	}
	idx := bytes.IndexByte(payload[pos:], 0)
	if idx < 0 {
		return nil, pos, false
	}
	return payload[pos : pos+idx], pos + idx + 1, true
}

// printableAuthResponse 将认证响应字节转为可打印的字符串。
// 过滤掉 null 字节、非 UTF-8 字节和控制字符，确保可用于 token 提取。
func printableAuthResponse(raw []byte) string {
	raw = bytes.TrimRight(raw, "\x00")
	if len(raw) == 0 || !utf8.Valid(raw) {
		return ""
	}
	for _, b := range raw {
		if b < 0x20 || b == 0x7f {
			return ""
		}
	}
	return string(raw)
}

// writeOKPacket 向客户端发送 OK 包（认证成功或命令执行成功）。
// 包结构：
//
//	1 字节          Header 0x00（OK）或 0xFE（EOF 场景下表示 OK）
//	变长            受影响行数（Length-Encoded Integer）
//	变长            最后插入 ID（Length-Encoded Integer）
//	2 字节           服务器状态标志
//	2 字节           警告计数
func writeOKPacket(conn net.Conn, seq byte, affectedRows, lastInsertID uint64) error {
	var payload bytes.Buffer
	payload.WriteByte(0) // OK 包标识
	writeLenEncInt(&payload, affectedRows)
	writeLenEncInt(&payload, lastInsertID)
	_ = binary.Write(&payload, binary.LittleEndian, mysqlStatusAutocommit)
	_ = binary.Write(&payload, binary.LittleEndian, uint16(0)) // 警告计数
	return writeMySQLPacket(conn, seq, payload.Bytes())
}

// writeEOFPacket 向客户端发送 EOF 包（标记结果集的列定义或行数据结束）。
// 包结构：[0xFE, 警告计数(2), 状态标志(2)]
// 在协议 4.1 中，EOF 包使用 0xFE 作为首字节（需防止与 payload 长度冲突的 0xFE 混淆）。
func writeEOFPacket(conn net.Conn, seq byte) error {
	return writeMySQLPacket(conn, seq, []byte{0xfe, 0, 0, byte(mysqlStatusAutocommit), byte(mysqlStatusAutocommit >> 8)})
}

// writeErrorPacket 向客户端发送 ERR 包（错误响应）。
// 包结构：
//
//	1 字节    Header 0xFF
//	2 字节    SQL 错误码（小端序）
//	1 字节    '#' 分隔符
//	5 字节    SQL 状态码（如 "HY000"）
//	变长      错误消息字符串
func writeErrorPacket(conn net.Conn, seq byte, code uint16, msg string) error {
	var payload bytes.Buffer
	payload.WriteByte(0xff)
	_ = binary.Write(&payload, binary.LittleEndian, code)
	payload.WriteByte('#')
	payload.WriteString("HY000") // SQL 状态码（一般错误）
	payload.WriteString(msg)
	return writeMySQLPacket(conn, seq, payload.Bytes())
}

// writeResultSet 将 database/sql 的查询结果序列化为 MySQL 结果集协议格式并发送。
// 序列化流程（3 段）：
//
//	段 1: 列数 + N 个列定义包 + EOF
//	段 2: M 个行数据包
//	段 3: EOF（标记结果集结束）
//
// 返回值：成功写入的行数。
func writeResultSet(conn net.Conn, rows *sql.Rows) (int64, error) {
	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	colTypes, _ := rows.ColumnTypes()
	seq := byte(1)
	// 段 1: 发送列数
	var header bytes.Buffer
	writeLenEncInt(&header, uint64(len(cols)))
	if err := writeMySQLPacket(conn, seq, header.Bytes()); err != nil {
		return 0, err
	}
	seq++
	// 段 1: 发送每个列的定义包
	for i, col := range cols {
		dbType := ""
		if i < len(colTypes) {
			dbType = colTypes[i].DatabaseTypeName()
		}
		if err := writeMySQLPacket(conn, seq, columnDefinitionPacket("", "", col, mysqlColumnType(dbType))); err != nil {
			return 0, err
		}
		seq++
	}
	// 段 1: EOF 标记列定义结束
	if err := writeEOFPacket(conn, seq); err != nil {
		return 0, err
	}
	seq++
	// 段 2: 逐行读取并发送行数据包
	values := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range values {
		ptrs[i] = &values[i]
	}
	var count int64
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return count, err
		}
		if err := writeMySQLPacket(conn, seq, rowPacket(values)); err != nil {
			return count, err
		}
		seq++
		count++
	}
	if err := rows.Err(); err != nil {
		return count, err
	}
	// 段 3: EOF 标记结果集结束
	if err := writeEOFPacket(conn, seq); err != nil {
		return count, err
	}
	return count, nil
}

// columnDefinitionPacket 构造一个 MySQL 列定义包（Column Definition Packet）。
// 包结构（协议 4.1）：
//
//	lenenc  "def"（catalog 标识）
//	lenenc  schema（数据库名）
//	lenenc  table（表名，别名为空）
//	lenenc  org_table（原始表名）
//	lenenc  name（列名）
//	lenenc  org_name（原始列名）
//	1 字节   fixed field length (0x0c = 12 字节后续固定字段)
//	2 字节   字符集编号（33 = utf8mb4_general_ci）
//	4 字节   列长度（1024）
//	1 字节   列类型
//	2 字节   标志
//	1 字节   小数位数
//	2 字节   填充（0x00 0x00）
func columnDefinitionPacket(schema, table, name string, typ byte) []byte {
	var payload bytes.Buffer
	writeLenEncString(&payload, "def")    // catalog
	writeLenEncString(&payload, schema)   // schema
	writeLenEncString(&payload, table)    // table（别名）
	writeLenEncString(&payload, table)    // org_table（原始表名）
	writeLenEncString(&payload, name)     // name（别名）
	writeLenEncString(&payload, name)     // org_name（原始列名）
	payload.WriteByte(0x0c)               // 固定字段长度 = 12
	_ = binary.Write(&payload, binary.LittleEndian, uint16(33))   // 字符集 utf8mb4_general_ci
	_ = binary.Write(&payload, binary.LittleEndian, uint32(1024)) // 列最大显示长度
	payload.WriteByte(typ)                                          // MySQL 列类型
	_ = binary.Write(&payload, binary.LittleEndian, uint16(0))    // 标志（无特殊标志）
	payload.WriteByte(0)                                            // 小数位数
	payload.Write([]byte{0, 0})                                     // 填充
	return payload.Bytes()
}

// rowPacket 构造一个 MySQL 行数据包（Row Data Packet）。
// 每个字段值以 Length-Encoded String 编码；NULL 值用 0xFB 表示。
func rowPacket(values []any) []byte {
	var payload bytes.Buffer
	for _, value := range values {
		if value == nil {
			// NULL 值编码为 0xFB
			payload.WriteByte(0xfb)
			continue
		}
		writeLenEncString(&payload, mysqlValueString(value))
	}
	return payload.Bytes()
}

// mysqlValueString 将 Go 值转为 MySQL 协议文本表示的字符串。
//   - []byte → 直接转 string
//   - time.Time → "2006-01-02 15:04:05.999999" 格式
//   - 其他 → fmt.Sprint
func mysqlValueString(value any) string {
	switch v := value.(type) {
	case []byte:
		return string(v)
	case time.Time:
		return v.Format("2006-01-02 15:04:05.999999")
	default:
		return fmt.Sprint(v)
	}
}

// mysqlColumnType 将 database/sql 返回的数据库类型名映射为 MySQL 协议列类型字节。
// 用于结果集的 Column Definition Packet 中正确标记每列的类型。
func mysqlColumnType(dbType string) byte {
	switch strings.ToUpper(dbType) {
	case "TINYINT", "SMALLINT", "MEDIUMINT", "INT", "INTEGER":
		return mysqlTypeLong
	case "BIGINT":
		return mysqlTypeLongLong
	case "FLOAT":
		return mysqlTypeFloat
	case "DOUBLE", "REAL":
		return mysqlTypeDouble
	case "DECIMAL", "NUMERIC", "NEWDECIMAL":
		return mysqlTypeDecimal
	case "DATE":
		return mysqlTypeDate
	case "TIME":
		return mysqlTypeTime
	case "DATETIME":
		return mysqlTypeDateTime
	case "TIMESTAMP":
		return mysqlTypeTimestamp
	case "JSON":
		return mysqlTypeJSON
	default:
		return mysqlTypeVarString // 未知类型默认作为变长字符串处理
	}
}

// writeLenEncString 以 Length-Encoded String 格式写入一个字符串。
// 格式：Length-Encoded Integer（字符串字节长度） + 字符串内容。
func writeLenEncString(buf *bytes.Buffer, value string) {
	writeLenEncInt(buf, uint64(len(value)))
	buf.WriteString(value)
}

// writeLenEncInt 以 Length-Encoded Integer 格式写入一个无符号整数。
// 编码规则：
//
//	n < 251           → 1 字节直接写入
//	n ≤ 65535         → 0xFC + 2 字节 uint16（小端序）
//	n ≤ 16777215      → 0xFD + 3 字节（小端序）
//	n > 16777215      → 0xFE + 8 字节 uint64（小端序）
func writeLenEncInt(buf *bytes.Buffer, n uint64) {
	switch {
	case n < 251:
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(0xfc)
		_ = binary.Write(buf, binary.LittleEndian, uint16(n))
	case n <= 0xffffff:
		buf.WriteByte(0xfd)
		buf.WriteByte(byte(n))
		buf.WriteByte(byte(n >> 8))
		buf.WriteByte(byte(n >> 16))
	default:
		buf.WriteByte(0xfe)
		_ = binary.Write(buf, binary.LittleEndian, n)
	}
}

// readLenEncInt 从 payload 的 pos 位置读取一个 Length-Encoded Integer。
// 返回解析出的 uint64 值、下一个读取位置和是否成功。
func readLenEncInt(payload []byte, pos int) (uint64, int, bool) {
	if pos >= len(payload) {
		return 0, pos, false
	}
	switch first := payload[pos]; first {
	case 0xfc:
		if pos+3 > len(payload) {
			return 0, pos, false
		}
		return uint64(binary.LittleEndian.Uint16(payload[pos+1 : pos+3])), pos + 3, true
	case 0xfd:
		if pos+4 > len(payload) {
			return 0, pos, false
		}
		n := uint64(payload[pos+1]) | uint64(payload[pos+2])<<8 | uint64(payload[pos+3])<<16
		return n, pos + 4, true
	case 0xfe:
		if pos+9 > len(payload) {
			return 0, pos, false
		}
		return binary.LittleEndian.Uint64(payload[pos+1 : pos+9]), pos + 9, true
	default:
		return uint64(first), pos + 1, true
	}
}

// isResultQuery 判断 SQL 语句是否预期返回结果集（SELECT 类查询）。
// 检查第一个关键字：SELECT、SHOW、DESCRIBE、DESC、EXPLAIN、WITH、CALL 视为结果集查询。
func isResultQuery(query string) bool {
	fields := strings.Fields(strings.TrimSpace(query))
	if len(fields) == 0 {
		return false
	}
	switch strings.ToLower(fields[0]) {
	case "select", "show", "describe", "desc", "explain", "with", "call":
		return true
	default:
		return false
	}
}

// quoteMySQLIdent 用反引号包裹 MySQL 标识符（数据库名、表名、列名），防止 SQL 注入。
// 标识符中的反引号会被转义为双反引号（``）。
func quoteMySQLIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// strconvUint64 将 int64 安全转为 uint64，负数转为 0。
func strconvUint64(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// strconvInt64 将字符串解析为 int64，解析失败返回 0。
func strconvInt64(value string) int64 {
	n, _ := strconv.ParseInt(value, 10, 64)
	return n
}
