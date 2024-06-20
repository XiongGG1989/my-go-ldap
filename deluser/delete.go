package main

import (
	"fmt"
	"ldap/conn"
	"log"
	"os"

	"github.com/go-ldap/ldap/v3"
)

func deleteUser(config *conn.Config, username string) error {
	// 获取 LDAP 连接
	conn, err := conn.GetLDAPConnection(config)
	if err != nil {
		return fmt.Errorf("连接 LDAP 时出错: %v", err)
	}
	defer conn.Close()
	// 设置搜索请求
	searchRequest := ldap.NewSearchRequest(
		config.LDAPBaseDN,                 // 搜索的Base DN
		ldap.ScopeWholeSubtree,            // 搜索范围
		ldap.NeverDerefAliases,            // 不搜索别名
		0,                                 // 搜索结果数量限制
		0,                                 // 搜索时间限制
		false,                             // 不分页
		fmt.Sprintf("(uid=%s)", username), // 搜索过滤器
		[]string{"dn"},                    // 要检索的属性
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

	//创建删除请求
	userDN := sr.Entries[0].DN
	delRequest := ldap.NewDelRequest(userDN, nil)

	//执行删除请求
	err = conn.Del(delRequest)
	if err != nil {
		return fmt.Errorf("删除用户失败: %v", err)
	}

	return nil
}

func main() {
	config, err := conn.LoadConfig("config.json")
	if err != nil {
		log.Fatalf("加载配置时出错: %v", err)
	}

	// 从命令行参数获取用户信息
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <username> ", os.Args[0])
	}

	username := os.Args[1]
	if err = deleteUser(config, username); err != nil {
		log.Fatalf("删除用户失败: %v", err)
	}
	fmt.Println("用户删除成功")
}
