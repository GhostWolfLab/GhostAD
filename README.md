# GhostAD - Active Directory Enumeration Tool

## 概述

GhostAD 是一个轻量级的 Active Directory 枚举工具，用于收集域环境中的信息，包括域信息、域信任关系、密码策略、管理员账户等。该工具使用 LDAP 协议直接查询 Active Directory，无需依赖 Active Directory PowerShell 模块。

## 功能特点

- **域信息枚举**：收集域控制器、域功能级别等基本信息
- **域信任关系**：枚举域信任关系及其属性
- **用户账户枚举**：识别特权用户、管理员账户和其他敏感账户
- **计算机账户枚举**：识别域控制器、不受约束的委派计算机等
- **组策略对象 (GPO) 枚举**：收集 GPO 信息及其链接
- **ACL 分析**：分析重要 AD 对象的访问控制列表
- **HTML 报告生成**：将结果导出为格式化的 HTML 报告

## 使用方法

### 基本用法

```powershell
# 在当前域中运行所有枚举模块
Invoke-GhostAD

# 枚举指定域
Invoke-GhostAD -Domain 'contoso.com'

# 使用指定的域控制器
Invoke-GhostAD -Domain 'contoso.com' -Server 'DC01.contoso.com'

# 使用提供的凭据
Invoke-GhostAD -Domain 'contoso.com' -Credential (Get-Credential)

# 将结果导出为 HTML 报告
Invoke-GhostAD -OutputFile "C:\Temp\ADReport.html"
```

### 参数说明

- **Domain**：要枚举的域。如果未指定，将使用当前域。
- **Server**：要连接的域控制器。如果未指定，将自动选择一个。
- **Credential**：用于域访问的凭据。
- **OutputFile**：HTML 报告输出的路径。如果未指定，将不生成 HTML 文件。

## 技术细节

### 依赖项

GhostAD 使用以下 .NET 程序集：

- System.DirectoryServices
- System.DirectoryServices.Protocols
- System.Security.Principal.Windows

### 错误处理

该工具包含全面的错误处理机制，可以处理各种 Active Directory 环境中的异常情况：

- 空或缺失的 LDAP 属性
- 域控制器连接问题
- 权限不足的情况
- 特殊字符和编码问题

## 安全注意事项

- 该工具仅用于授权的安全评估和系统管理目的
- 运行该工具的账户应具有适当的权限
- 生成的报告可能包含敏感信息，应妥善保管

## 故障排除

如果遇到问题，可以尝试以下方法：

1. 使用 `-Verbose` 参数获取详细的执行信息
2. 确保运行脚本的账户具有足够的权限
3. 检查域控制器连接是否正常
4. 验证 LDAP 查询是否受到防火墙或安全策略的限制

## 最近修复

1. 修复了字典键冲突问题，防止在 ImportantObjects 字典中出现重复的 'Name' 键
2. 改进了安全描述符处理和错误处理机制
3. 添加了 Get-LdapAttributeValue 辅助函数，用于安全地获取 LDAP 属性
4. 修复了 ACL 枚举过程中的错误处理
5. 改进了 HTML 报告生成功能

## 贡献

欢迎提交问题报告和改进建议，共同完善这个工具。
