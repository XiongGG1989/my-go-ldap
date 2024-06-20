package conn

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/go-ldap/ldap/v3"
)

// Config 结构体定义
type Config struct {
	LDAPBaseDN string `json:"ldapBaseDN"`
	AdminDN    string `json:"adminDN"`
	AdminPass  string `json:"adminPass"`
	LDAPURL    string `json:"ldapURL"`
	UserOU     string `json:"userOU"`
	GroupOU    string `json:"groupOU"`
	DomainMail string `json:"domainMail"`
}

// LoadConfig 从文件中加载配置
func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("无法打开配置文件: %v", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("无法读取配置文件: %v", err)
	}

	var config Config
	if err := json.Unmarshal(bytes, &config); err != nil {
		return nil, fmt.Errorf("无法解析配置文件: %v", err)
	}

	return &config, nil
}
func GetLDAPConnection(config *Config) (*ldap.Conn, error) {
	// 连接到LDAP服务器
	conn, err := ldap.DialURL(config.LDAPURL)
	if err != nil {
		return nil, fmt.Errorf("连接失败: %v", err)
	}

	// 进行绑定操作
	err = conn.Bind(config.AdminDN, config.AdminPass)
	if err != nil {
		return nil, fmt.Errorf("认证失败: %v", err)
	}
	return conn, nil
}
