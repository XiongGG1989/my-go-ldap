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

type UserDNFetcher interface {
	FetchUserDN(conn *ldap.Conn, username string) (string, error)
}

type LDAPUserDNFetcher struct {
	Config *conn.Config
}

func (f *LDAPUserDNFetcher) FetchUserDN(conn *ldap.Conn, username string) (string, error) {
	searchRequest := ldap.NewSearchRequest(
		f.Config.LDAPBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", username),
		[]string{"dn"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("搜索用户失败: %v", err)
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("未找到用户")
	}

	return sr.Entries[0].DN, nil
}

// ModifyUserPassword 修改用户的密码
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

func ModifyUserPassword(f UserDNFetcher, config *conn.Config, username, newPassword string) error {
	conn, err := conn.GetLDAPConnection(config)
	if err != nil {
		return fmt.Errorf("连接 LDAP 时出错: %v", err)
	}
	defer conn.Close()

	userDN, err := f.FetchUserDN(conn, username)
	if err != nil {
		return fmt.Errorf("获取用户 DN 失败: %v", err)
	}
	// 对新密码进行哈希处理
	hashedPassword, err := hashPasswordSHA(newPassword)
	if err != nil {
		return fmt.Errorf("哈希密码失败: %v", err)
	}

	// 创建修改请求
	modifyRequest := ldap.NewModifyRequest(userDN, nil)
	modifyRequest.Replace("userPassword", []string{hashedPassword})

	// 执行修改请求
	if err := conn.Modify(modifyRequest); err != nil {
		return fmt.Errorf("修改用户密码失败: %v", err)
	}

	return nil
}

// 增加用户的属性或者属性值
func AddUserattrName(f UserDNFetcher, config *conn.Config, username string, attrName string, values []string) error {
	conn, err := conn.GetLDAPConnection(config)
	if err != nil {
		return fmt.Errorf("连接 LDAP 时出错: %v", err)
	}
	defer conn.Close()

	userDN, err := f.FetchUserDN(conn, username)
	if err != nil {
		return fmt.Errorf("获取用户 DN 失败: %v", err)
	}
	// 创建修改请求
	modifyRequest := ldap.NewModifyRequest(userDN, nil)
	if len(values) > 0 {
		if attrName == "title" {
			// 只有当 attrName 为 "title" 时，才附加GroupOU 和LDAPBaseDN
			for i := range values {
				values[i] = fmt.Sprintf("cn=%s,%s,%s", values[i], config.GroupOU, config.LDAPBaseDN)
			}
		}
		modifyRequest.Add(attrName, values)
	}

	// 执行修改请求
	if err := conn.Modify(modifyRequest); err != nil {
		return fmt.Errorf("修改用户失败: %v", err)
	}

	return nil
}

// AddUserToGroups 将用户添加到指定的组
func AddUserToGroups(f UserDNFetcher, config *conn.Config, username string, groups []string) error {
	conn, err := conn.GetLDAPConnection(config)
	if err != nil {
		return fmt.Errorf("连接 LDAP 时出错: %v", err)
	}
	defer conn.Close()

	userDN, err := f.FetchUserDN(conn, username)
	if err != nil {
		return fmt.Errorf("获取用户 DN 失败: %v", err)
	}
	// 将用户添加到每个指定的组
	for _, group := range groups {
		groupDN := fmt.Sprintf("cn=%s,%s,%s", group, config.GroupOU, config.LDAPBaseDN)
		modifyRequest := ldap.NewModifyRequest(groupDN, nil)
		modifyRequest.Add("member", []string{userDN})

		// 执行修改请求
		if err := conn.Modify(modifyRequest); err != nil {
			return fmt.Errorf("无法将用户添加到组中 %s: %v", group, err)
		}
	}

	return nil
}

// delUserFromGroups 将用户从指定的组移除
func delUserFromGroups(config *conn.Config, username string, groupName string) error {
	conn, err := conn.GetLDAPConnection(config)
	if err != nil {
		return fmt.Errorf("连接 LDAP 时出错: %v", err)
	}
	defer conn.Close()

	// 设置搜索请求以获取用户的 DN
	searchRequest := ldap.NewSearchRequest(
		config.LDAPBaseDN, // 搜索的Base DN
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=inetOrgPerson)(uid=%s))", username), // 搜索过滤器
		[]string{"dn"}, // 只检索 DN
		nil,
	)

	// 执行搜索请求
	sr, err := conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("搜索用户失败: %v", err)
	}

	// 检查搜索结果
	if len(sr.Entries) == 0 {
		return fmt.Errorf("未找到用户")
	}

	// 获取用户的 DN
	userDN := sr.Entries[0].DN

	// 搜索组的 DN
	OUbase := fmt.Sprintf("%s,%s", config.GroupOU, config.LDAPBaseDN)
	groupSearchRequest := ldap.NewSearchRequest(
		OUbase,                 // 搜索的 Base DN
		ldap.ScopeWholeSubtree, // 搜索范围
		ldap.NeverDerefAliases, // 不展开别名
		0,                      // 搜索结果数量限制
		0,                      // 时间限制
		false,                  // 不分页
		fmt.Sprintf("(&(objectClass=groupOfNames)(cn=%s))", groupName), // 搜索过滤器
		[]string{"dn", "member"}, // 要检索的属性
		nil,
	)

	groupSearchResult, err := conn.Search(groupSearchRequest)
	if err != nil {
		return fmt.Errorf("搜索OU失败: %v", err)
	}
	if len(groupSearchResult.Entries) == 0 {
		return fmt.Errorf("OU '%s' 未找到", groupName)
	}
	groupDN := groupSearchResult.Entries[0].DN
	members := groupSearchResult.Entries[0].GetAttributeValues("member")

	// 检查用户是否在组中
	userInGroup := false
	for _, member := range members {
		if member == userDN {
			userInGroup = true
			break
		}
	}
	if !userInGroup {
		return fmt.Errorf("用户 '%s' 不在 '%s' 组中", username, groupName)
	}

	// 将用户从指定的组移除
	modifyRequest := ldap.NewModifyRequest(groupDN, nil)
	modifyRequest.Delete("member", []string{userDN})

	// 执行修改请求
	if err := conn.Modify(modifyRequest); err != nil {
		return fmt.Errorf("移除用户失败: %v", err)
	}

	return nil
}

// 打印使用信息
func printUsage() {
	fmt.Println("Usage:")
	fmt.Printf("%s <command> [<args>]\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("  modify_user_pass <username> <newPassword>                        - 修改用户密码")
	fmt.Println("  add_user_group <username> <group1> [<group2> ...]                - 将用户添加到组,可以添加到多个组")
	fmt.Println("  del_user_from_groups <username> <group>                          - 从组中删除用户")
	fmt.Println("  add_user_attr <username> <attributename> <value1> [<value2> ...] - 为用户添加属性,可以指定多个属性值;也可以为已存在属性添加一个或者多个值")
	fmt.Println("                                                                     当属性为title时,自动为值追加groupOU和ldapBaseDN")
}
func main() {
	// 从配置文件加载配置
	config, err := conn.LoadConfig("config.json")
	if err != nil {
		log.Fatalf("加载配置时出错: %v", err)
	}

	fetcher := &LDAPUserDNFetcher{Config: config}

	// 从命令行参数获取命令和其他信息
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "modify_user_pass":
		if len(os.Args) != 4 {
			log.Fatalf("Usage: %s modify_user_pass <username> <newPassword>", os.Args[0])
		}
		username := os.Args[2]
		newPassword := os.Args[3]

		// 修改用户密码
		if err := ModifyUserPassword(fetcher, config, username, newPassword); err != nil {
			log.Fatalf("修改用户密码时出错: %v", err)
		}
		fmt.Println("用户密码修改成功")

	case "add_user_attr":
		if len(os.Args) < 5 {
			log.Fatalf("Usage: %s add_user_attr <username> <attrName> <value1> [<value2> ...]", os.Args[0])
		}
		username := os.Args[2]
		attrName := os.Args[3]
		values := os.Args[4:]

		// 增加用户attrName或者值
		if err := AddUserattrName(fetcher, config, username, attrName, values); err != nil {
			log.Fatalf("属性添加出错: %v", err)
		}
		fmt.Println("属性添加成功")
	case "add_user_group":
		if len(os.Args) < 4 {
			log.Fatalf("Usage: %s add_user_group <username> <group1> [<group2> ...]", os.Args[0])
		}
		username := os.Args[2]
		groups := os.Args[3:]

		// 增加用户到组
		if err := AddUserToGroups(fetcher, config, username, groups); err != nil {
			log.Fatalf("将用户添加到组时出错: %v", err)
		}
		fmt.Println("用户已成功添加到群组")
	case "del_user_from_groups":
		if len(os.Args) < 4 {
			log.Fatalf("Usage: %s del_user_from_groups <username> <group>", os.Args[0])
		}
		username := os.Args[2]
		groupName := os.Args[3]

		// 从组中删除用户
		if err := delUserFromGroups(config, username, groupName); err != nil {
			log.Fatalf("将用户移除组时出错: %v", err)
		}
		fmt.Printf("用户 '%s' 已成功从 '%s' 中移除\n", username, groupName)
	default:
		fmt.Printf("未知的命令: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}
