package main

import (
	"fmt"
	"ldap/conn"
	"log"
	"os"

	"github.com/go-ldap/ldap/v3"
)

// 搜索用户
func searchUser(config *conn.Config, username string) error {
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
		[]string{"dn", "cn", "displayName", "mail", "title"}, // 要检索的属性
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

	// 输出用户信息
	entry := sr.Entries[0]
	titles := entry.GetAttributeValues("title")
	fmt.Printf("DN: %s\n", entry.DN)
	fmt.Printf("CN: %s\n", entry.GetAttributeValue("cn"))
	fmt.Printf("DisPlayName: %s\n", entry.GetAttributeValue("displayName"))
	fmt.Printf("Email: %s\n", entry.GetAttributeValue("mail"))
	fmt.Printf("Titles:\n")
	for _, title := range titles {
		fmt.Printf("  - %s\n", title)
	}

	return nil
}

func searchOU(config *conn.Config, ouname string) error {
	conn, err := conn.GetLDAPConnection(config)
	if err != nil {
		return fmt.Errorf("连接 LDAP 时出错: %v", err)
	}
	defer conn.Close()

	// 设置搜索请求
	var searchRequest *ldap.SearchRequest
	if ouname == "" {
		// 设置搜索请求以列出所有 OU
		searchRequest = ldap.NewSearchRequest(
			config.LDAPBaseDN,            // 搜索的Base DN
			ldap.ScopeWholeSubtree,       // 搜索范围
			ldap.NeverDerefAliases,       // 不展开别名
			0,                            // 搜索结果数量限制
			0,                            // 时间限制
			false,                        // 不分页
			"(objectClass=groupOfNames)", // 搜索过滤器
			[]string{"cn"},               // 要检索的属性
			nil,
		)
	} else {
		OUbase := fmt.Sprintf("%s,%s", config.GroupOU, config.LDAPBaseDN)
		searchRequest = ldap.NewSearchRequest(
			OUbase,                 // 搜索的Base DN
			ldap.ScopeWholeSubtree, // 搜索范围
			ldap.NeverDerefAliases, // 不展开别名
			0,                      // 搜索结果数量限制
			0,                      // 时间限制
			false,                  // 不分页
			fmt.Sprintf("(&(objectClass=groupOfNames)(cn=%s))", ouname), // 搜索过滤器
			[]string{"cn", "member"},                                    // 要检索的属性
			nil,
		)
	}

	// 执行搜索请求
	sr, err := conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("搜索OU失败: %v", err)
	}
	// 检查搜索结果
	if len(sr.Entries) == 0 {
		return fmt.Errorf("OU '%s' 未找到", ouname)
	}
	// 打印搜索结果
	for _, entry := range sr.Entries {
		if ouname == "" {
			fmt.Printf("OU: %s\n", entry.GetAttributeValue("cn"))
		} else {
			fmt.Printf("Group: %s\n", entry.GetAttributeValue("cn"))
			members := entry.GetAttributeValues("member")
			for _, member := range members {
				fmt.Printf("  Member: %s\n", member)
			}

		}

	}
	return nil
}

// 打印使用信息
func printUsage() {
	fmt.Println("Usage:")
	fmt.Printf(" %s <command> [<args>]\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("  searchUser <username>   - 按用户名搜索用户")
	fmt.Println("  searchOU [ouname]       - 搜索特定组织单位 (OU) 内的用户")
	fmt.Println("                            如果提供了 <ouname>，则搜索指定的 OU 并列出其成员.")
	fmt.Println("                            如果未提供 <ouname>，则列出所有 OU.")
}
func main() {
	// 从配置文件加载配置
	config, err := conn.LoadConfig("config.json")
	if err != nil {
		log.Fatalf("加载配置时出错: %v", err)
	}

	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "searchUser":
		// 从命令行参数获取用户名
		if len(os.Args) != 3 {
			log.Fatalf("Usage: %s searchUser <username>", os.Args[0])
		}
		username := os.Args[2]
		// 搜索用户
		err = searchUser(config, username)
		if err != nil {
			log.Fatalf("搜索用户时出错: %v", err)
		}
	case "searchOU":
		if len(os.Args) < 2 {
			log.Fatalf("Usage: %s searchOU <ouname>", os.Args[0])
		}
		// 检查是否提供了 ouname
		var ouname string
		if len(os.Args) >= 3 {
			ouname = os.Args[2]
		}
		// 搜索分组
		err = searchOU(config, ouname)
		if err != nil {
			log.Fatalf("搜索 ou 时出错: %v", err)
		}
	default:
		fmt.Printf("未知的命令: %s\n", command)
		printUsage()
		os.Exit(1)
	}

}
