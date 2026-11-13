# WAF-LFI-Defender (基于文件包含攻击检测的 Web 安全防护系统)

## 📖 项目简介
本项目基于 Python Flask 框架开发，是一款轻量级 Web 应用防火墙 (WAF)。针对 OWASP Top 10 中的文件包含漏洞（LFI/RFI），实现了对 URL 参数和 POST 数据的安全检测、拦截与日志可视化展示。

## ✨ 核心功能
- **多重解码防御**：对 Payload 进行多次 URL 解码，防止 `%252e` 等编码绕过。
- **正则特征匹配**：内置正则规则，精准识别路径遍历、PHP 伪协议、敏感文件读取。
- **Web 可视化日志**：拦截攻击后自动记录 IP/Payload 至日志文件，并提供 Web 页面 `/waf_logs` 查看。

## 🛠️ 技术栈
- Python 3.13 / Flask / Requests
- 部署环境: Docker + DVWA 靶场

## 🚀 快速开始
1. 安装依赖: `pip install -r requirements.txt`
2. 启动后端靶场 (需 Docker): `docker run -d -p 8080:80 vulnerables/web-dvwa`
3. 启动 WAF: `python app.py`
4. 访问测试: `http://127.0.0.1:5000`