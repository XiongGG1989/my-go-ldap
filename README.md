
## 配置文件

将 `config.json` 文件复制到编译后的二进制文件目录中,修改 `ldap` 相关的配置信息, 示例内容如下:
```json
{
  "ldapBaseDN": "dc=example,dc=com",
  "adminDN": "cn=admin,dc=example,dc=com",
  "adminPass": "adminpassword",
  "ldapURL": "ldap://localhost:389",
  "userOU": "ou=people",
  "groupOU": "ou=groups",
  "DomainMail": "example.com"
}
```
## 编译为可执行文件

以 `adduser` 示例,进入到 `adduser` 目录：

```bash 
Linux
GOOS=linux GOARCH=amd64 go build -o adduser

Win
GOOS=windows GOARCH=amd64 go build -o adduser.exe

Mac
GOOS=darwin GOARCH=amd64 go build -o adduser
```

## 功能
### ADD
- 添加用户
### DELETE
- 删除用户
### MODIFY
- 添加用户属性,可以同时增加一个或者多个值
- 修改用户密码
- 添加用户到指定组,可以同时加入多个组
- 从指定组中移除用户
### SEARCH
- 搜索用户
- 搜索组
- 搜索指定组中所有成员
