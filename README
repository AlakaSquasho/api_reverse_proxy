# api_reverse_proxy

反向代理api接口地址，实现无需科学上网即可使用。另外为了安全已添加访问速率限制以及https支持。该脚本需部署在服务器端。

---

## Usage

使用该脚本需要一台服务器、一个域名、一个邮箱( 用于Let's Encrypt )



- 运行脚本
- 输入域名(`mydomain.com`)
- 输入子域名前缀( 默认 `api` )
- 输入https端口号( 默认 `8443` )
- 输入http端口号( 默认 `8080` )
- 输入速率限制[ 每分钟请求次数 ] ( 默认 `100` )
- 输入突发请求限制( 默认 `20` )
- 输入用于SSL证书申请的邮箱



完成后，即可使用 `https://api.mydomain.com:8443/gemini` 接口代理原始gemini api接口 `https://generativelanguage.googleapis.com` ，另外可针对不同服务商自行扩展。