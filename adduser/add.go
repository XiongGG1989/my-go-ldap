package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"ldap/conn"
	"log"
	"os"

	"github.com/go-ldap/ldap/v3"
)

// User 结构体定义
type User struct {
	Username string
	Password string
	SN, CN   string
	Email    string
}

func (user *User) addUser(config *conn.Config, userOU, baseDN string) error {
	userDN := fmt.Sprintf("uid=%s,%s,%s", user.Username, userOU, baseDN)

	// 获取 LDAP 连接
	conn, err := conn.GetLDAPConnection(config)
	if err != nil {
		return fmt.Errorf("连接 LDAP 时出错: %v", err)
	}
	defer conn.Close()

	// 加密用户密码
	hashedPassword, err := hashPasswordSHA(user.Password)
	if err != nil {
		return fmt.Errorf("哈希密码失败: %v", err)
	}

	// 创建添加请求
	addRequest := ldap.NewAddRequest(userDN, nil)
	// 定义要添加的属性
	Attributes := map[string][]string{
		"objectClass":  {"inetOrgPerson", "person", "organizationalPerson", "top"},
		"userPassword": {hashedPassword},
		"sn":           {user.SN},
		"cn":           {user.CN},
		"uid":          {user.Username},
		"mail":         {user.Email},
		"displayname":  {user.SN},
		"givenname":    {user.SN},
	}

	for attr, values := range Attributes {
		addRequest.Attribute(attr, values)
	}

	// 执行添加操作
	if err := conn.Add(addRequest); err != nil {
		return fmt.Errorf("添加用户失败: %v", err)
	}

	return nil
}

// hashPasswordSHA 使用 SHA-1 哈希算法加密密码
func hashPasswordSHA(password string) (string, error) {
	hash := sha1.New()
	_, err := hash.Write([]byte(password))
	if err != nil {
		return "", err
	}
	hashedPassword := hash.Sum(nil)
	encodedPassword := base64.StdEncoding.EncodeToString(hashedPassword)
	return fmt.Sprintf("{SHA}%s", encodedPassword), nil
}

func main() {
	// 从配置文件加载配置
	config, err := conn.LoadConfig("config.json")
	if err != nil {
		log.Fatalf("加载配置时出错: %v", err)
	}
	// 从命令行参数获取用户信息
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s <username> <password> <用户名>", os.Args[0])
	}
	// 传入用户信息
	user := &User{
		Username: os.Args[1],
		Password: os.Args[2],
		SN:       os.Args[3],
		CN:       os.Args[1],
		Email:    os.Args[1] + "@" + config.DomainMail,
	}

	// 添加用户
	if err = user.addUser(config, config.UserOU, config.LDAPBaseDN); err != nil {
		log.Fatalf("添加用户时出错: %v", err)
	}
	fmt.Println("用户添加成功")
}
