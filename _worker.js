import { connect } from 'cloudflare:sockets';
let 临时TOKEN, 永久TOKEN;
let parsedSocks5Address = {};
export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const UA = request.headers.get('User-Agent') || 'null';
        const currentDate = new Date();
        const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 60 * 12)); // 每12小时一个时间戳
        临时TOKEN = await 双重哈希(url.hostname + timestamp + UA);
        永久TOKEN = env.TOKEN || 临时TOKEN;
        if (url.pathname.toLowerCase() === "/check") {
            if (env.TOKEN) {
                if (!url.searchParams.has('token') || url.searchParams.get('token') !== 永久TOKEN) {
                    return new Response(JSON.stringify({
                        status: "error",
                        message: `IP查询失败: 无效的TOKEN`,
                        timestamp: new Date().toISOString()
                    }, null, 4), {
                        status: 403,
                        headers: {
                            "content-type": "application/json; charset=UTF-8",
                            'Access-Control-Allow-Origin': '*'
                        }
                    });
                }
            }
            if (url.searchParams.has("socks5")) {
                const 代理参数 = url.searchParams.get("socks5");
                return new Response(JSON.stringify(await SOCKS5可用性验证('socks5', 代理参数)));
            } else if (url.searchParams.has("http")) {
                const 代理参数 = url.searchParams.get("http");
                return new Response(JSON.stringify(await SOCKS5可用性验证('http', 代理参数)));
            } else if (url.searchParams.has("proxy")) {
                const 代理参数 = url.searchParams.get("proxy");
                if (代理参数.toLowerCase().startsWith("socks5://")) {
                    return new Response(JSON.stringify(await SOCKS5可用性验证('socks5', 代理参数.split("socks5://")[1])));
                } else if (代理参数.toLowerCase().startsWith("http://")) {
                    return new Response(JSON.stringify(await SOCKS5可用性验证('http', 代理参数.split("http://")[1])));
                } else if (代理参数.toLowerCase().startsWith("https://")) {
                    return new Response(JSON.stringify(await SOCKS5可用性验证('https', 代理参数.split("https://")[1])));
                }
            }
            // 如果没有提供有效的代理参数，返回错误响应
            return new Response(JSON.stringify({
                success: false,
                error: "请提供有效的代理参数：socks5、http 或 proxy"
            }, null, 2), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        } else if (url.pathname.toLowerCase() === '/ip-info') {
            if (!url.searchParams.has('token') || (url.searchParams.get('token') !== 临时TOKEN) && (url.searchParams.get('token') !== 永久TOKEN)) {
                return new Response(JSON.stringify({
                    status: "error",
                    message: `IP查询失败: 无效的TOKEN`,
                    timestamp: new Date().toISOString()
                }, null, 4), {
                    status: 403,
                    headers: {
                        "content-type": "application/json; charset=UTF-8",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
            const ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
            try {
                const data = await getIpInfo(ip);
                // 返回数据给客户端，并添加CORS头
                return new Response(JSON.stringify(data, null, 4), {
                    headers: {
                        "content-type": "application/json; charset=UTF-8",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            } catch (error) {
                console.error("IP查询失败:", error);
                return new Response(JSON.stringify({
                    status: "error",
                    message: `IP查询失败: ${error.message}`,
                    code: "API_REQUEST_FAILED",
                    query: ip,
                    timestamp: new Date().toISOString(),
                    details: {
                        errorType: error.name,
                        stack: error.stack ? error.stack.split('\n')[0] : null
                    }
                }, null, 4), {
                    status: 500,
                    headers: {
                        "content-type": "application/json; charset=UTF-8",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        }
        if (env.TOKEN) {
            return new Response(await nginx(), {
                headers: {
                    'Content-Type': 'text/html; charset=UTF-8',
                },
            });
        } else if (env.URL302) return Response.redirect(env.URL302, 302);
        else if (env.URL) return await 代理URL(env.URL, url);
        else {
            const 网站图标 = env.ICO ? `<link rel="icon" href="${env.ICO}" type="image/x-icon">` : '';
            const 网络备案 = env.BEIAN || `&copy; 2025 Check Socks5/HTTP - 基于 Cloudflare Workers 构建的高性能代理验证服务 | IP数据来源: ipapi.is | by: cmliu`;
            let img = 'background: #ffffff;';
            if (env.IMG) {
                const imgs = await 整理(env.IMG);
                img = `background-image: url('${imgs[Math.floor(Math.random() * imgs.length)]}');`;
            }
            return await HTML(网站图标, 网络备案, img);
        }
    },
};
///////////////////////////////////////////功能性函数//////////////////////////////////////////
async function SOCKS5可用性验证(代理协议 = 'socks5', 代理参数) {
    // 记录开始时间
    const startTime = Date.now();
    
    // 解析代理参数
    try {
        parsedSocks5Address = await 获取SOCKS5账号(代理参数);
    } catch (err) {
        return {
            success: false,
            error: err.message,
            proxy: 代理协议 + "://" + 代理参数,
            responseTime: Date.now() - startTime
        };
    }

    const { username, password, hostname, port } = parsedSocks5Address;
    const 完整代理参数 = username && password
        ? `${username}:${password}@${hostname}:${port}`
        : `${hostname}:${port}`;

    try {
        // 根据协议类型建立连接
        const tcpSocket = 代理协议 == 'socks5'
            ? await socks5Connect('check.socks5.090227.xyz', 80)
            : await httpConnect('check.socks5.090227.xyz', 80);

        if (!tcpSocket) {
            return {
                success: false,
                error: '无法连接到代理服务器',
                proxy: 代理协议 + "://" + 完整代理参数,
                responseTime: Date.now() - startTime
            };
        }

        try {
            // 发送HTTP请求
            const writer = tcpSocket.writable.getWriter();
            const encoder = new TextEncoder();
            const request = `GET /cdn-cgi/trace HTTP/1.1\r\nHost: check.socks5.090227.xyz\r\nConnection: close\r\n\r\n`;
            await writer.write(encoder.encode(request));
            writer.releaseLock();

            // 读取响应
            const reader = tcpSocket.readable.getReader();
            const decoder = new TextDecoder();
            let response = '';

            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    response += decoder.decode(value, { stream: true });
                }
            } finally {
                reader.releaseLock();
            }

            // 关闭连接
            await tcpSocket.close();

            // 解析响应获取IP和位置信息
            const ipMatch = response.match(/ip=(.*)/);
            const locMatch = response.match(/loc=(.*)/);
            const 代理落地IP = response.match(/ip=(.*)/)[1];

            // 直接调用IP查询逻辑，而不是发送HTTP请求
            const ipInfo = await getIpInfo(代理落地IP);
            return {
                success: true,
                proxy: 代理协议 + "://" + 完整代理参数,
                ip: ipMatch ? ipMatch[1] : 'N/A',
                loc: locMatch ? locMatch[1] : 'N/A',
                responseTime: Date.now() - startTime,
                ...ipInfo
            };
        } catch (error) {
            // 清理连接资源
            try {
                await tcpSocket.close();
            } catch (e) {
                console.log('关闭连接时出错:', e);
            }

            return {
                success: false,
                error: error.message,
                proxy: 代理协议 + "://" + 完整代理参数,
                responseTime: Date.now() - startTime
            };
        }
    } catch (error) {
        return {
            success: false,
            error: error.message,
            proxy: 代理协议 + "://" + 代理参数,
            responseTime: Date.now() - startTime
        };
    }
}

async function 获取SOCKS5账号(address) {
    if (address.includes('@')) {
        const lastAtIndex = address.lastIndexOf('@');
        let userPassword = address.substring(0, lastAtIndex).replaceAll('%3D', '=');
        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
        address = `${userPassword}@${address.substring(lastAtIndex + 1)}`;
    }
    const atIndex = address.lastIndexOf("@");
    const [hostPart, authPart] = atIndex === -1 ? [address, undefined] : [address.substring(atIndex + 1), address.substring(0, atIndex)];

    // 解析认证
    let username, password;
    if (authPart) {
        [username, password] = authPart.split(":");
        if (!password) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
    }

    // 解析主机端口
    let hostname, port;
    if (hostPart.includes("]:")) { // IPv6带端口
        [hostname, port] = [hostPart.split("]:")[0] + "]", Number(hostPart.split("]:")[1].replace(/[^\d]/g, ''))];
    } else if (hostPart.startsWith("[")) { // IPv6无端口
        [hostname, port] = [hostPart, 80];
    } else { // IPv4/域名
        const parts = hostPart.split(":");
        [hostname, port] = parts.length === 2 ? [parts[0], Number(parts[1].replace(/[^\d]/g, ''))] : [hostPart, 80];
    }

    if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    if (hostname.includes(":") && !/^\[.*\]$/.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');

    return { username, password, hostname, port };
}

////////////////////////////////SOCKS5/HTTP函数///////////////////////////////////////////////
async function httpConnect(addressRemote, portRemote) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const sock = await connect({ hostname, port });
    const writer = sock.writable.getWriter();
    const reader = sock.readable.getReader();
    
    try {
        // 构建 HTTP CONNECT 请求
        let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
        connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;
        
        // 如果有用户名和密码,添加 Proxy-Authorization 头
        if (username && password) {
            const auth = btoa(`${username}:${password}`);
            connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        
        connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n`;
        connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
        connectRequest += `Connection: Keep-Alive\r\n`;
        connectRequest += '\r\n';
        
        // 发送 CONNECT 请求
        await writer.write(new TextEncoder().encode(connectRequest));
        
        // 读取响应头
        let responseBuffer = new Uint8Array(0);
        let headerEndIndex = -1;
        let bytesRead = 0;
        const maxHeaderSize = 8192; // 最大响应头大小
        
        // 循环读取数据直到找到响应头结束标记
        while (headerEndIndex === -1 && bytesRead < maxHeaderSize) {
            const { done, value } = await reader.read();
            if (done) {
                throw new Error('HTTP代理连接中断，未收到完整响应');
            }
            
            // 合并新数据到缓冲区
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            bytesRead = responseBuffer.length;
            
            // 查找响应头结束标记 \r\n\r\n
            for (let i = 0; i < responseBuffer.length - 3; i++) {
                if (responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a &&
                    responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a) {
                    headerEndIndex = i + 4;
                    break;
                }
            }
        }
        
        if (headerEndIndex === -1) {
            throw new Error('HTTP代理响应格式无效，未找到响应头结束标记');
        }
        
        // 解析响应头
        const headerText = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex));
        const statusLine = headerText.split('\r\n')[0];
        const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
        
        if (!statusMatch) {
            throw new Error(`HTTP代理响应格式无效: ${statusLine}`);
        }
        
        const statusCode = parseInt(statusMatch[1]);
        
        // 检查状态码,支持 2xx 成功状态码
        if (statusCode < 200 || statusCode >= 300) {
            throw new Error(`HTTP代理连接失败 [${statusCode}]: ${statusLine}`);
        }
        
        // 如果响应中有多余的数据(通常不应该有),需要处理
        // 通过创建新的可读流来传递这些数据
        if (headerEndIndex < responseBuffer.length) {
            const remainingData = responseBuffer.slice(headerEndIndex);
            const { readable, writable } = new TransformStream();
            
            // 将剩余数据写入新流
            new ReadableStream({
                start(controller) {
                    controller.enqueue(remainingData);
                }
            }).pipeTo(writable).catch(() => {});
            
            // 替换 socket 的 readable 流
            // @ts-ignore
            sock.readable = readable;
        }
        
        writer.releaseLock();
        reader.releaseLock();
        
        return sock;
        
    } catch (error) {
        // 清理资源
        try {
            writer.releaseLock();
        } catch (e) {}
        try {
            reader.releaseLock();
        } catch (e) {}
        try {
            sock.close();
        } catch (e) {}
        
        throw new Error(`HTTP代理连接失败: ${error.message}`);
    }
}

async function socks5Connect(addressRemote, portRemote, addressType = 3) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({ hostname, port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();

    // SOCKS5 握手: VER(5) + NMETHODS(2) + METHODS(0x00,0x02)
    await writer.write(new Uint8Array([5, 2, 0, 2]));
    let res = (await reader.read()).value;
    if (res[0] !== 0x05 || res[1] === 0xff) return;

    // 如果需要用户名密码认证
    if (res[1] === 0x02) {
        if (!username || !password) return;
        await writer.write(new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]));
        res = (await reader.read()).value;
        if (res[0] !== 0x01 || res[1] !== 0x00) return;
    }

    // 构建目标地址 (ATYP + DST.ADDR)
    const DSTADDR = addressType === 1 ? new Uint8Array([1, ...addressRemote.split('.').map(Number)])
        : addressType === 3 ? new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)])
            : new Uint8Array([4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]);

    // 发送连接请求: VER(5) + CMD(1=CONNECT) + RSV(0) + DSTADDR + DST.PORT
    await writer.write(new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]));
    res = (await reader.read()).value;
    if (res[1] !== 0x00) return;

    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

////////////////////////////////////////////辅助函数///////////////////////////////////////////////
/**
 * 获取IP信息的通用函数
 * @param {string} ip IP地址或域名
 * @returns {Promise<Object>} IP信息对象
 */
async function getIpInfo(ip) {
    // IPv4 正则表达式
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

    // IPv6 正则表达式（完整版，包含所有常见格式）
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*$|^[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*::$|^[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*$|^::$|^::1$/;

    let finalIp = ip;
    let allIps = null; // 存储所有解析的IP地址

    // 检查是否是标准的 IPv4 或 IPv6 格式
    if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
        // 不是标准 IP 格式，尝试 DNS 解析
        try {
            console.log(`正在解析域名: ${ip}`);

            // 并发获取 A 记录（IPv4）和 AAAA 记录（IPv6）
            const [ipv4Records, ipv6Records] = await Promise.all([
                fetchDNSRecords(ip, 'A').catch(() => []),
                fetchDNSRecords(ip, 'AAAA').catch(() => [])
            ]);

            // 提取 IP 地址
            const ipv4Addresses = ipv4Records.map(record => record.data).filter(Boolean);
            const ipv6Addresses = ipv6Records.map(record => record.data).filter(Boolean);

            // 合并所有 IP 地址
            allIps = [...ipv4Addresses, ...ipv6Addresses];

            if (allIps.length === 0) {
                throw new Error(`无法解析域名 ${ip} 的 IP 地址`);
            }

            // 随机选择一个 IP 地址
            finalIp = allIps[Math.floor(Math.random() * allIps.length)];
            console.log(`域名 ${ip} 解析为: ${finalIp}`);

        } catch (dnsError) {
            console.error(`DNS 解析失败:`, dnsError);
            throw new Error(`无法解析域名 ${ip}: ${dnsError.message}`);
        }
    } else {
        console.log(`识别为有效IP地址: ${ip}`);
    }

    // 使用最终确定的 IP 地址查询信息
    const response = await fetch(`https://api.ipapi.is/?q=${finalIp}`);

    if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}`);
    }

    const data = await response.json();

    // 添加时间戳到成功的响应数据中
    data.timestamp = new Date().toISOString();

    // 如果原始输入是域名，添加域名解析信息
    if (finalIp !== ip && allIps) {
        data.domain = ip; // 原始域名
        data.resolved_ip = finalIp; // 当前查询使用的IP
        data.ips = allIps; // 所有解析到的IP地址数组

        // 添加解析统计信息
        const ipv4Count = allIps.filter(addr => ipv4Regex.test(addr)).length;
        const ipv6Count = allIps.filter(addr => ipv6Regex.test(addr)).length;

        data.dns_info = {
            total_ips: allIps.length,
            ipv4_count: ipv4Count,
            ipv6_count: ipv6Count,
            selected_ip: finalIp,
            all_ips: allIps
        };
    }

    return data;
}

async function 代理URL(代理网址, 目标网址) {
    const 网址列表 = await 整理(代理网址);
    const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];

    // 解析目标 URL
    const 解析后的网址 = new URL(完整网址);
    console.log(解析后的网址);
    // 提取并可能修改 URL 组件
    const 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
    const 主机名 = 解析后的网址.hostname;
    let 路径名 = 解析后的网址.pathname;
    const 查询参数 = 解析后的网址.search;

    // 处理路径名
    if (路径名.charAt(路径名.length - 1) == '/') {
        路径名 = 路径名.slice(0, -1);
    }
    路径名 += 目标网址.pathname;

    // 构建新的 URL
    const 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;

    // 反向代理请求
    const 响应 = await fetch(新网址);

    // 创建新的响应
    let 新响应 = new Response(响应.body, {
        status: 响应.status,
        statusText: 响应.statusText,
        headers: 响应.headers
    });

    // 添加自定义头部，包含 URL 信息
    //新响应.headers.set('X-Proxied-By', 'Cloudflare Worker');
    //新响应.headers.set('X-Original-URL', 完整网址);
    新响应.headers.set('X-New-URL', 新网址);

    return 新响应;
}

async function 双重哈希(文本) {
    const 编码器 = new TextEncoder();

    const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
    const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
    const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
    const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
    const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    return 第二次十六进制.toLowerCase();
}

async function 整理(内容) {
    // 将制表符、双引号、单引号和换行符都替换为逗号
    // 然后将连续的多个逗号替换为单个逗号
    var 替换后的内容 = 内容.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');

    // 删除开头和结尾的逗号（如果有的话）
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);

    // 使用逗号分割字符串，得到地址数组
    const 地址数组 = 替换后的内容.split(',');

    return 地址数组;
}

async function fetchDNSRecords(domain, type) {
    // 构建查询参数
    const query = new URLSearchParams({
        name: domain,
        type: type
    });
    const url = `https://cloudflare-dns.com/dns-query?${query.toString()}`;

    // 发送HTTP GET请求
    const response = await fetch(url, {
        method: 'GET',
        headers: {
            'Accept': 'application/dns-json' // 接受DNS JSON格式的响应
        }
    });

    // 检查响应是否成功
    if (!response.ok) {
        throw new Error(`获取DNS记录失败: ${response.statusText}`);
    }

    // 解析响应数据
    const data = await response.json();
    return data.Answer || [];
}

////////////////////////////////////////////HTML///////////////////////////////////////////////

async function nginx() {
    const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
    return text;
}

async function HTML(网站图标, 网络备案, img) {
    const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Socks5/HTTP</title>
    ${网站图标}
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            ${img}
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            background-repeat: no-repeat;
            position: relative;
            min-height: 100vh;
            padding: 20px;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(2px);
            -webkit-backdrop-filter: blur(2px);
            z-index: 0;
            pointer-events: none;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(25px) saturate(180%);
            -webkit-backdrop-filter: blur(25px) saturate(180%);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1), 
                        0 10px 20px rgba(0, 0, 0, 0.05),
                        inset 0 1px 0 rgba(255, 255, 255, 0.4),
                        inset 0 -1px 0 rgba(255, 255, 255, 0.1);
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.3);
            position: relative;
            z-index: 1;
        }
        
        .container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, 
                rgba(255, 255, 255, 0.15) 0%, 
                rgba(255, 255, 255, 0.08) 30%,
                rgba(255, 255, 255, 0.03) 70%, 
                rgba(255, 255, 255, 0.01) 100%);
            pointer-events: none;
            z-index: 1;
        }
        
        .container::after {
            content: '';
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            bottom: -2px;
            background: rgba(200, 200, 200, 0.2);
            border-radius: 22px;
            z-index: -1;
            filter: blur(4px);
            opacity: 0.3;
        }
        
        .container > * {
            position: relative;
            z-index: 2;
        }
        
        .header {
            background: linear-gradient(45deg, #2e7d32, #4caf50);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            color: #fff;
            padding: 25px 35px;
            position: relative;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 30px;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, rgba(46, 125, 50, 0.3), rgba(76, 175, 80, 0.2), rgba(102, 187, 106, 0.3));
            pointer-events: none;
        }
        
        .header-content {
            position: relative;
            z-index: 1;
            flex-shrink: 0;
        }
        
        .header h1 {
            font-size: 1.8em;
            margin: 0 0 8px 0;
            text-shadow: 2px 2px 6px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 0.95em;
            opacity: 0.95;
            margin: 0;
            text-shadow: 1px 1px 3px rgba(0,0,0,0.2);
        }
        
        .header-input {
            position: relative;
            z-index: 1;
            flex: 1;
            max-width: 600px;
            display: flex;
            gap: 15px;
            align-items: center;
        }
        
        .header-input input {
            flex: 1;
            padding: 14px 20px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 12px;
            font-size: 15px;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.95);
            color: #333333;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        
        .header-input input:focus {
            outline: none;
            border-color: rgba(255, 255, 255, 0.8);
            box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.2), 0 2px 8px rgba(0, 0, 0, 0.15);
            background: #ffffff;
        }
        
        .header-input input::placeholder {
            color: #888888;
        }
        
        .header-input button {
            padding: 14px 28px;
            background: rgba(255, 255, 255, 0.2);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            color: white;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 12px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
            position: relative;
            overflow: hidden;
            white-space: nowrap;
        }
        
        .header-input button::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s ease;
        }
        
        .header-input button:hover::before {
            left: 100%;
        }
        
        .header-input button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
            background: rgba(255, 255, 255, 0.3);
            border-color: rgba(255, 255, 255, 0.5);
        }
        
        .header-input button:active {
            transform: translateY(0);
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
        }
        
        .header-input button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
            background: rgba(150, 150, 150, 0.3);
            border-color: rgba(150, 150, 150, 0.3);
        }
        
        .header-input button:disabled::before {
            display: none;
        }

        .input-section {
            display: none;
        }
        
        .input-group {
            display: flex;
            gap: 15px;
            align-items: center;
            max-width: 800px;
            margin: 0 auto;
        }
        
        .input-group input {
            flex: 1;
            padding: 16px 22px;
            border: 2px solid rgba(200, 200, 200, 0.6);
            border-radius: 12px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: #ffffff;
            color: #333333;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        
        .input-group input:focus {
            outline: none;
            border-color: #666666;
            box-shadow: 0 0 0 3px rgba(100, 100, 100, 0.2), 0 2px 8px rgba(0, 0, 0, 0.15);
        }
        
        .input-group input::placeholder {
            color: #888888;
        }
        
        .input-group button {
            padding: 16px 32px;
            background: linear-gradient(45deg, #2e7d32, #4caf50);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            color: white;
            border: 2px solid rgba(76, 175, 80, 0.6);
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(76, 175, 80, 0.3);
            text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
            position: relative;
            overflow: hidden;
        }
        
        .input-group button::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s ease;
        }
        
        .input-group button:hover::before {
            left: 100%;
        }
        
        .input-group button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 18px rgba(76, 175, 80, 0.4);
            background: linear-gradient(45deg, #1b5e20, #2e7d32);
            border-color: rgba(76, 175, 80, 0.8);
        }
        
        .input-group button:active {
            transform: translateY(0);
            box-shadow: 0 2px 8px rgba(76, 175, 80, 0.3);
        }
        
        .input-group button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
            box-shadow: 0 2px 6px rgba(76, 175, 80, 0.2);
            background: linear-gradient(45deg, #424242, #616161);
            border-color: rgba(150, 150, 150, 0.4);
        }
        
        .input-group button:disabled::before {
            display: none;
        }
        
        .results-section {
            padding: 35px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
        }
        
        .info-card {
            background: rgba(255, 255, 255, 0.25);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.1),
                        inset 0 1px 0 rgba(255, 255, 255, 0.4);
            transition: all 0.3s ease;
        }
        
        .info-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15),
                        inset 0 1px 0 rgba(255, 255, 255, 0.5);
            background: rgba(255, 255, 255, 0.3);
        }
        
        .info-card h3 {
            background: linear-gradient(45deg, #2e7d32, #4caf50);
            color: white;
            padding: 22px;
            margin: 0;
            font-size: 1.3em;
            text-align: center;
            font-weight: 600;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .info-content {
            padding: 28px;
            background: #ffffff;
            border-top: 1px solid rgba(200, 200, 200, 0.3);
        }
        
        .info-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 0;
            border-bottom: 1px solid rgba(200, 200, 200, 0.3);
        }
        
        .info-item:last-child {
            border-bottom: none;
        }
        
        .info-label {
            font-weight: 600;
            color: #333333;
            min-width: 120px;
        }
        
        .info-value {
            text-align: right;
            flex: 1;
            color: #666666;
        }

        .ip-selector {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 8px;
        }

        .more-ip-btn {
            background: rgba(76, 175, 80, 0.1);
            color: #2e7d32;
            border: 1px solid rgba(76, 175, 80, 0.3);
            border-radius: 4px;
            padding: 2px 8px;
            font-size: 0.8em;
            cursor: pointer;
            transition: all 0.3s ease;
            order: 1;
        }

        .more-ip-btn:hover {
            background: rgba(76, 175, 80, 0.2);
            border-color: rgba(76, 175, 80, 0.5);
        }

        .ip-text {
            order: 2;
        }

        .ip-dropdown {
            position: absolute;
            right: 0;
            top: 100%;
            background: white;
            border: 1px solid rgba(200, 200, 200, 0.5);
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            z-index: 1000;
            min-width: 200px;
            max-height: 200px;
            overflow-y: auto;
            display: none;
        }

        .ip-dropdown.show {
            display: block;
        }

        .ip-option {
            padding: 8px 12px;
            cursor: pointer;
            transition: background 0.2s ease;
            border-bottom: 1px solid rgba(200, 200, 200, 0.3);
            font-size: 0.9em;
        }

        .ip-option:last-child {
            border-bottom: none;
        }

        .ip-option:hover {
            background: rgba(76, 175, 80, 0.1);
        }

        .ip-option.active {
            background: rgba(76, 175, 80, 0.2);
            color: #2e7d32;
            font-weight: 600;
        }

        .ip-value-container {
            position: relative;
        }
        
        .status-yes {
            background: rgba(211, 47, 47, 0.8);
            color: white;
            padding: 5px 10px;
            border-radius: 8px;
            font-size: 0.9em;
            font-weight: 500;
        }
        
        .status-no {
            background: rgba(54,137,61, 0.8);
            color: white;
            padding: 5px 10px;
            border-radius: 8px;
            font-size: 0.9em;
            font-weight: 500;
        }
        
        .loading {
            text-align: center;
            padding: 45px;
            color: #666666;
            font-size: 1.1em;
        }
        
        .error {
            text-align: center;
            padding: 45px;
            color: rgba(211, 47, 47, 0.9);
            font-size: 1.1em;
            background: rgba(244, 67, 54, 0.1);
            border-radius: 8px;
            margin: 10px;
            border: 1px solid rgba(244, 67, 54, 0.2);
        }
        
        .waiting {
            text-align: center;
            padding: 45px;
            color: #666666;
            font-size: 1.1em;
        }
        
        .spinner {
            border: 3px solid rgba(200, 200, 200, 0.4);
            border-top: 3px solid rgba(100, 100, 100, 0.8);
            border-radius: 50%;
            width: 32px;
            height: 32px;
            animation: spin 1s linear infinite;
            margin: 0 auto 18px;
        }
        
        .github-corner svg {
            fill: #53b156;
            color: #ffffff;
            position: fixed;
            top: 0;
            right: 0;
            border: 0;
            width: 80px;
            height: 80px;
        }

        .github-corner:hover .octo-arm {
        animation: octocat-wave 560ms ease-in-out;
        }

        @keyframes octocat-wave {
            0%, 100% { transform: rotate(0); }
            20%, 60% { transform: rotate(-25deg); }
            40%, 80% { transform: rotate(10deg); }
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                align-items: stretch;
                gap: 20px;
                padding: 25px;
            }
            
            .header-content {
                text-align: center;
            }
            
            .header h1 {
                font-size: 1.6em;
            }
            
            .header p {
                font-size: 0.9em;
            }
            
            .header-input {
                max-width: none;
            }
            
            .header-input input,
            .header-input button {
                width: 100%;
            }
            
            .header-input {
                flex-direction: column;
                gap: 15px;
            }
            
            .results-section {
                grid-template-columns: 1fr;
            }
            
            .input-group {
                flex-direction: column;
            }
            
            .input-group input,
            .input-group button {
                width: 100%;
            }
            
            .container {
                margin: 10px;
                border-radius: 16px;
            }

            .github-corner:hover .octo-arm {
                animation: none;
            }

            .github-corner .octo-arm {
                animation: octocat-wave 560ms ease-in-out;
            }
        }

        .footer {
            text-align: center;
            padding: 25px;
            color: #666666;
            font-size: 14px;
            border-top: 1px solid rgba(255, 255, 255, 0.3);
            background: rgba(255, 255, 255, 0.2);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
        }
    </style>
</head>
<body>
  <a href="https://github.com/cmliu/CF-Workers-CheckSocks5" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true">
      <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
      <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
      <path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
    </svg>
  </a>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>代理检测工具</h1>
                <p>检测代理服务器的出入口信息，支持 SOCKS5 和 HTTP 代理</p>
            </div>
            <div class="header-input">
                <input type="text" id="proxyInput" placeholder="输入代理链接，例如：socks5://username:password@host:port" />
                <button id="checkBtn" onclick="checkProxy()">检查代理</button>
            </div>
        </div>
        
        <div class="input-section">
            <div class="input-group">
                <input type="text" id="proxyInput" placeholder="输入代理链接，例如：socks5://username:password@host:port" />
                <button id="checkBtn" onclick="checkProxy()">检查代理</button>
            </div>
        </div>
        
        <div class="results-section">
            <div class="info-card">
                <h3>入口信息</h3>
                <div class="info-content" id="entryInfo">
                    <div class="waiting">请输入代理链接并点击检查</div>
                </div>
            </div>
            
            <div class="info-card">
                <h3 id="exitInfoTitle">出口信息</h3>
                <div class="info-content" id="exitInfo">
                    <div class="waiting">请输入代理链接并点击检查</div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            ${网络备案}
        </div>
    </div>

    <script>
        let currentDomainInfo = null; // 存储当前域名的所有IP信息
        let currentProxyTemplate = null; // 存储代理模板

        function preprocessProxyUrl(input) {
            let processed = input.trim();
            
            // 如果包含 # 号，只保留 # 前面的代理部分
            if (processed.includes('#')) {
                processed = processed.split('#')[0].trim();
            }
            
            // 删除开头的斜杠
            while (processed.startsWith('/')) {
                processed = processed.substring(1);
            }
            
            // 如果不包含协议，自动添加 socks5://
            if (!processed.includes('://')) {
                processed = 'socks5://' + processed;
            }
            
            // 检查是否包含IPv6地址需要方括号处理
            // 如果用户直接输入了没有方括号的IPv6地址，自动添加方括号
            const urlPart = processed.includes('://') ? processed.split('://')[1] : processed;
            let processedUrlPart = urlPart;
            
            // 处理认证信息
            let authPart = '';
            if (processedUrlPart.includes('@')) {
                const lastAtIndex = processedUrlPart.lastIndexOf('@');
                authPart = processedUrlPart.substring(0, lastAtIndex + 1);
                processedUrlPart = processedUrlPart.substring(lastAtIndex + 1);
            }
            
            // 分离主机和端口
            const parts = processedUrlPart.split(':');
            if (parts.length > 2) {
                // 可能是IPv6地址，检查主机部分
                const port = parts[parts.length - 1];
                const hostPart = parts.slice(0, -1).join(':');
                
                if (isIPv6Address(hostPart) && !hostPart.startsWith('[')) {
                    // 重构URL，为IPv6地址添加方括号
                    const protocol = processed.includes('://') ? processed.split('://')[0] : 'socks5';
                    processed = protocol + '://' + authPart + '[' + hostPart + ']:' + port;
                }
            }
            
            return processed;
        }
        
        function extractHostFromProxy(proxyUrl) {
            try {
                // 移除协议前缀
                let urlPart = proxyUrl.includes('://') ? proxyUrl.split('://')[1] : proxyUrl;
                
                // 处理认证信息 (username:password@host:port)
                if (urlPart.includes('@')) {
                    // 使用 lastIndexOf 获取最后一个 @ 符号的位置
                    const lastAtIndex = urlPart.lastIndexOf('@');
                    urlPart = urlPart.substring(lastAtIndex + 1);
                }
                
                // 处理IPv6地址格式 [ipv6]:port
                if (urlPart.startsWith('[') && urlPart.includes(']:')) {
                    // IPv6地址带端口格式：[2001:db8::1]:8080
                    const host = urlPart.substring(1, urlPart.indexOf(']:'));
                    return host;
                }
                
                // 提取主机名（移除端口）
                let host = urlPart.split(':')[0];
                
                // 处理IPv6地址（已经有方括号的情况）
                if (host.startsWith('[') && host.includes(']')) {
                    host = host.substring(1, host.indexOf(']'));
                }
                
                return host;
            } catch (error) {
                throw new Error('无法解析代理链接格式');
            }
        }

        function isIPAddress(host) {
            // IPv4 正则表达式
            const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            // IPv6 正则表达式
            const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*$|^[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*::$|^[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*$|^::$|^::1$/;
            
            return ipv4Regex.test(host) || ipv6Regex.test(host);
        }

        function isIPv6Address(host) {
            // IPv6 正则表达式 - 支持完整IPv6地址格式和简化格式
            const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*$|^[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*::$|^[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*$|^::$|^::1$/;
            
            return ipv6Regex.test(host);
        }

        function replaceHostInProxy(proxyUrl, newHost) {
            try {
                const [protocol, rest] = proxyUrl.split('://');
                let urlPart = rest;
                let authPart = '';
                
                // 处理认证信息
                if (urlPart.includes('@')) {
                    // 使用 lastIndexOf 获取最后一个 @ 符号的位置
                    const lastAtIndex = urlPart.lastIndexOf('@');
                    authPart = urlPart.substring(0, lastAtIndex + 1);
                    urlPart = urlPart.substring(lastAtIndex + 1);
                }
                
                // 分离主机和端口
                const parts = urlPart.split(':');
                const port = parts[parts.length - 1];
                
                // 检查新主机是否是IPv6地址，如果是且没有方括号则自动添加
                let processedNewHost = newHost;
                if (isIPv6Address(newHost) && !newHost.startsWith('[')) {
                    processedNewHost = '[' + newHost + ']';
                }
                
                // 构建新的代理URL
                return protocol + '://' + authPart + processedNewHost + ':' + port;
            } catch (error) {
                throw new Error('无法替换代理链接中的主机');
            }
        }

        async function fetchDNSRecords(domain, type) {
            const query = new URLSearchParams({
                name: domain,
                type: type
            });
            const url = \`https://cloudflare-dns.com/dns-query?\${query.toString()}\`;

            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Accept': 'application/dns-json'
                }
            });

            if (!response.ok) {
                throw new Error(\`获取DNS记录失败: \${response.statusText}\`);
            }

            const data = await response.json();
            return data.Answer || [];
        }

        async function resolveDomainIPs(domain) {
            try {
                const [ipv4Records, ipv6Records] = await Promise.all([
                    fetchDNSRecords(domain, 'A').catch(() => []),
                    fetchDNSRecords(domain, 'AAAA').catch(() => [])
                ]);

                const ipv4Addresses = ipv4Records.map(record => record.data).filter(Boolean);
                const ipv6Addresses = ipv6Records.map(record => record.data).filter(Boolean);

                const allIPs = [...ipv4Addresses, ...ipv6Addresses];

                if (allIPs.length === 0) {
                    throw new Error(\`无法解析域名 \${domain} 的 IP 地址\`);
                }

                return {
                    domain: domain,
                    all_ips: allIPs,
                    ipv4_addresses: ipv4Addresses,
                    ipv6_addresses: ipv6Addresses,
                    default_ip: allIPs[0]
                };
            } catch (error) {
                throw new Error(\`DNS解析失败: \${error.message}\`);
            }
        }
        
        function formatIpType(type) {
            if (!type) return '<span class="ip-type-unknown">未知</span>';
            
            const typeMap = {
                'isp': { text: '住宅', style: 'color: #36893dcc; font-weight: bold;' },
                'hosting': { text: '机房', style: 'font-weight: bold;' },
                'business': { text: '商用', style: 'color: #eab308; font-weight: bold;' }
            };
            
            const typeInfo = typeMap[type.toLowerCase()];
            if (!typeInfo) return '<span style="font-weight: bold;">' + type + '</span>';
            return \`<span style="\${typeInfo.style}">\${typeInfo.text}</span>\`;
        }
        
        function calculateAbuseScore(companyScore, asnScore, securityFlags = {}) {
            // 如果两个分数都无效，返回null
            if (!companyScore || companyScore === '未知') companyScore = 0;
            if (!asnScore || asnScore === '未知') asnScore = 0;
            
            const company = parseFloat(companyScore) || 0;
            const asn = parseFloat(asnScore) || 0;
            
            // 计算基础评分：(company + asn) / 2 * 5
            let baseScore = ((company + asn) / 2) * 5;
            
            // 计算安全风险附加分
            let riskAddition = 0;
            
            // 检查虚假IP (Bogon)，如果是则增加100%
            if (securityFlags.is_bogon === true) {
                riskAddition += 1.0; // 虚假IP增加100%
            }
            
            // 其他风险项各增加15%
            const otherRiskFlags = [
                securityFlags.is_crawler,   // 爬虫
                securityFlags.is_proxy,     // 代理服务器
                securityFlags.is_vpn,       // VPN
                securityFlags.is_tor,       // Tor 网络
                securityFlags.is_abuser     // 滥用 IP
            ];
            
            // 统计其他风险项中为 true 的数量
            const otherRiskCount = otherRiskFlags.filter(flag => flag === true).length;
            riskAddition += otherRiskCount * 0.15; // 每个风险项增加 15%
            
            // 最终评分 = 基础评分 + 风险附加分
            const finalScore = baseScore + riskAddition;
            
            // 如果基础评分和风险附加分都是0，返回null
            if (baseScore === 0 && riskAddition === 0) return null;
            
            return finalScore;
        }
        
        function getAbuseScoreBadgeClass(percentage) {
            if (percentage === null || percentage === undefined) return 'badge-info';
            
            if (percentage >= 100) return 'badge-critical';      // 危险红色 >= 100%
            if (percentage >= 20) return 'badge-high';           // 橘黄色 15-99.99%
            if (percentage >= 5) return 'badge-elevated';     // 黄色 5-14.99%
            if (percentage >= 0.25) return 'badge-low';          // 淡绿色 0.25-4.99%
            return 'badge-verylow';                              // 绿色 < 0.25%
        }
        
        function getRiskLevelColor(riskLevel) {
            // 根据风险等级返回对应的背景色
            const colorMap = {
                '极度危险': 'rgb(220, 38, 38)',      // 深红色
                '高风险': 'rgb(239, 68, 68)',        // 红色
                '轻微风险': 'rgb(249, 115, 22)',     // 橙色
                '纯净': 'rgb(22, 163, 74)',        // 深绿色
                '极度纯净':  'rgb(34, 197, 94)',        // 绿色
            };
            return colorMap[riskLevel] || 'rgb(100, 100, 100)';
        }
        
        function formatAbuseScorePercentage(score) {
            if (score === null || score === undefined) return '未知';
            
            const percentage = score * 100;
            return percentage.toFixed(2) + '%';
        }
        
        function getAbusescoreColor(score) {
            // 提取数字部分并转换为百分比
            const match = score.match(/([0-9.]+)/);
            if (!match) return '#28a745';
            
            const percentage = parseFloat(match[1]) * 100;
            
            // 0% 绿色到 100% 红色的渐变
            const red = Math.min(255, Math.round(percentage * 2.55));
            const green = Math.min(255, Math.round((100 - percentage) * 2.55));
            
            return \`rgb(\${red}, \${green}, 0)\`;
        }
        
        function formatInfoDisplay(data, containerId, showIPSelector = false, responseTime = null) {
            const container = document.getElementById(containerId);
            
            // 如果是出口信息，更新标题
            if (containerId === 'exitInfo' && document.getElementById('exitInfoTitle')) {
                const titleElement = document.getElementById('exitInfoTitle');
                if (responseTime !== null && data && data.success) {
                    // 将毫秒转换为秒，保留两位小数
                    const seconds = (responseTime / 1000).toFixed(2);
                    titleElement.textContent = \`出口信息(响应时间: \${seconds}秒)\`;
                } else if (data && !data.success) {
                    titleElement.textContent = '出口信息(代理不可用)';
                } else if (data && data.error) {
                    titleElement.textContent = '出口信息(代理不可用)';
                } else {
                    titleElement.textContent = '出口信息';
                }
            }
            
            if (!data || data.error) {
                container.innerHTML = '<div class="error">数据获取失败，请稍后重试</div>';
                return;
            }
            
            // 计算综合滥用评分
            const companyScore = data.company?.abuser_score;
            const asnScore = data.asn?.abuser_score;
            const securityFlags = {
                is_crawler: data.is_crawler,
                is_proxy: data.is_proxy,
                is_vpn: data.is_vpn,
                is_tor: data.is_tor,
                is_abuser: data.is_abuser,
                is_bogon: data.is_bogon
            };
            
            const combinedScore = calculateAbuseScore(companyScore, asnScore, securityFlags);
            let abuseScoreHTML = '';
            
            if (combinedScore !== null) {
                const scorePercentage = combinedScore * 100;
                const badgeClass = getAbuseScoreBadgeClass(scorePercentage);
                const formattedScore = formatAbuseScorePercentage(combinedScore);
                
                // 根据百分比确定风险等级文本
                let riskLevel = '';
                if (scorePercentage >= 100) riskLevel = '极度危险';
                else if (scorePercentage >= 20) riskLevel = '高风险';
                else if (scorePercentage >= 5) riskLevel = '轻微风险';
                else if (scorePercentage >= 0.25) riskLevel = '纯净';
                else riskLevel = '极度纯净';
                
                const riskLevelColor = getRiskLevelColor(riskLevel);
                abuseScoreHTML = \`<span style="background-color: \${riskLevelColor}; color: white; padding: 4px 8px; border-radius: 5px; font-size: 0.9em; font-weight: bold;">\${formattedScore} \${riskLevel}</span>\`;
            } else {
                abuseScoreHTML = '未知';
            }
            
            const ipDisplay = showIPSelector && currentDomainInfo && currentDomainInfo.all_ips.length > 1 
                ? \`<div class="ip-selector">
                     <button class="more-ip-btn" onclick="toggleIPDropdown()">更多IP</button>
                     <span class="ip-text">\${data.ip || 'N/A'}</span>
                     <div class="ip-dropdown" id="ipDropdown">
                         \${currentDomainInfo.all_ips.map(ip => 
                             \`<div class="ip-option \${ip === data.ip ? 'active' : ''}" onclick="selectIP('\${ip}')">\${ip}</div>\`
                         ).join('')}
                     </div>
                   </div>\`
                : data.ip || 'N/A';
            
            container.innerHTML = \`
                <div class="info-item">
                    <span class="info-label">IP地址:</span>
                    <span class="info-value">
                        <div class="ip-value-container">
                            \${ipDisplay}
                        </div>
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">运营商 / ASN 类型:</span>
                    <span class="info-value">
                        \${formatIpType(data.company?.type)} / \${formatIpType(data.asn?.type)}
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">综合滥用评分:</span>
                    <span class="info-value">
                        \${abuseScoreHTML}
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">网络爬虫:</span>
                    <span class="info-value">
                        <span class="\${data.is_crawler ? 'status-yes' : 'status-no'}">
                            \${data.is_crawler ? '是' : '否'}
                        </span>
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">Tor网络:</span>
                    <span class="info-value">
                        <span class="\${data.is_tor ? 'status-yes' : 'status-no'}">
                            \${data.is_tor ? '是' : '否'}
                        </span>
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">代理:</span>
                    <span class="info-value">
                        <span class="\${data.is_proxy ? 'status-yes' : 'status-no'}">
                            \${data.is_proxy ? '是' : '否'}
                        </span>
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">VPN:</span>
                    <span class="info-value">
                        <span class="\${data.is_vpn ? 'status-yes' : 'status-no'}">
                            \${data.is_vpn ? '是' : '否'}
                        </span>
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">滥用 IP:</span>
                    <span class="info-value">
                        <span class="\${data.is_abuser ? 'status-yes' : 'status-no'}">
                            \${data.is_abuser ? '是' : '否'}
                        </span>
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">虚假 IP:</span>
                    <span class="info-value">
                        <span class="\${data.is_bogon ? 'status-yes' : 'status-no'}">
                            \${data.is_bogon ? '是' : '否'}
                        </span>
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">自治系统编号:</span>
                    <span class="info-value">\${'AS' + data.asn?.asn || 'N/A'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">所属组织:</span>
                    <span class="info-value">\${data.asn?.org || 'N/A'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">国家:</span>
                    <span class="info-value">\${data.location?.country_code || 'N/A'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">城市:</span>
                    <span class="info-value">\${data.location?.city || 'N/A'}</span>
                </div>
            \`;
        }

        function toggleIPDropdown() {
            const dropdown = document.getElementById('ipDropdown');
            dropdown.classList.toggle('show');
            
            // 点击其他地方关闭下拉菜单
            document.addEventListener('click', function closeDropdown(e) {
                if (!e.target.closest('.ip-value-container')) {
                    dropdown.classList.remove('show');
                    document.removeEventListener('click', closeDropdown);
                }
            });
        }

        async function selectIP(selectedIP) {
            const dropdown = document.getElementById('ipDropdown');
            dropdown.classList.remove('show');
            
            const checkBtn = document.getElementById('checkBtn');
            const entryInfo = document.getElementById('entryInfo');
            const exitInfo = document.getElementById('exitInfo');
            
            checkBtn.disabled = true;
            entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在获取入口信息...</div>';
            exitInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在获取出口信息...</div>';
            
            try {
                // 准备用于入口信息查询的IP（去掉IPv6的方括号）
                let entryQueryIP = selectedIP;
                if (selectedIP.startsWith('[') && selectedIP.endsWith(']')) {
                    entryQueryIP = selectedIP.substring(1, selectedIP.length - 1);
                }
                
                // 更新入口信息
                const entryData = await fetchEntryInfo(entryQueryIP);
                if (entryData.error) {
                    entryInfo.innerHTML = '<div class="error">入口信息获取失败，请稍后重试</div>';
                } else {
                    formatInfoDisplay(entryData, 'entryInfo', true);
                }
                
                // 更新出口信息
                const newProxyUrl = replaceHostInProxy(currentProxyTemplate, selectedIP);
                const encodedProxy = encodeURIComponent(newProxyUrl);
                const proxyResponse = await fetch(\`/check?proxy=\${encodedProxy}\`);
                const proxyData = await proxyResponse.json();
                
                if (!proxyData.success) {
                    document.getElementById('exitInfoTitle').textContent = '出口信息(代理不可用)';
                    exitInfo.innerHTML = '<div class="error">代理检测失败，请稍后重试</div>';
                } else {
                    formatInfoDisplay(proxyData, 'exitInfo', false, proxyData.responseTime);
                }
                
            } catch (error) {
                console.error('切换IP时出现错误:', error);
                entryInfo.innerHTML = '<div class="error">切换失败，请稍后重试</div>';
                exitInfo.innerHTML = '<div class="error">切换失败，请稍后重试</div>';
            } finally {
                checkBtn.disabled = false;
            }
        }
        
        async function fetchEntryInfo(host, retryCount = 0) {
            try {
                const response = await fetch(\`/ip-info?ip=\${encodeURIComponent(host)}&token=${临时TOKEN}\`);
                const data = await response.json();
                
                if (data.error && retryCount < 3) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    return fetchEntryInfo(host, retryCount + 1);
                }
                
                return data;
            } catch (error) {
                if (retryCount < 3) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    return fetchEntryInfo(host, retryCount + 1);
                }
                throw error;
            }
        }
        
        async function checkProxy() {
            const proxyInput = document.getElementById('proxyInput');
            const checkBtn = document.getElementById('checkBtn');
            const entryInfo = document.getElementById('entryInfo');
            const exitInfo = document.getElementById('exitInfo');
            
            const rawProxyUrl = proxyInput.value.trim();
            if (!rawProxyUrl) {
                alert('请输入代理链接');
                return;
            }
            
            // 预处理代理链接
            const proxyUrl = preprocessProxyUrl(rawProxyUrl);
            currentProxyTemplate = proxyUrl;
            
            // 更新输入框显示处理后的链接
            proxyInput.value = proxyUrl;
            
            checkBtn.disabled = true;
            // 重置出口信息标题
            document.getElementById('exitInfoTitle').textContent = '出口信息';
            entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在解析代理信息...</div>';
            exitInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在解析代理信息...</div>';
            
            try {
                const host = extractHostFromProxy(proxyUrl);
                let targetIP = host;
                let targetProxyUrl = proxyUrl;
                currentDomainInfo = null;
                
                // 检查是否是域名
                if (!isIPAddress(host)) {
                    entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在解析域名...</div>';
                    
                    try {
                        // 解析域名获取所有IP
                        currentDomainInfo = await resolveDomainIPs(host);
                        targetIP = currentDomainInfo.default_ip;
                        targetProxyUrl = replaceHostInProxy(proxyUrl, targetIP);
                        currentProxyTemplate = proxyUrl; // 保存原始模板
                        
                        console.log(\`域名 \${host} 解析为 IP: \${targetIP}\`);
                        console.log(\`所有IP: \${currentDomainInfo.all_ips.join(', ')}\`);
                    } catch (dnsError) {
                        entryInfo.innerHTML = \`<div class="error">域名解析失败: \${dnsError.message}</div>\`;
                        exitInfo.innerHTML = \`<div class="error">域名解析失败: \${dnsError.message}</div>\`;
                        return;
                    }
                }
                
                // 同时开始获取入口和出口信息
                entryInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在获取入口信息...</div>';
                exitInfo.innerHTML = '<div class="loading"><div class="spinner"></div>正在检测代理...</div>';
                
                // 准备用于入口信息查询的IP（去掉IPv6的方括号）
                let entryQueryIP = targetIP;
                if (targetIP.startsWith('[') && targetIP.endsWith(']')) {
                    entryQueryIP = targetIP.substring(1, targetIP.length - 1);
                }
                
                const [entryPromise, exitPromise] = await Promise.allSettled([
                    fetchEntryInfo(entryQueryIP),
                    (async () => {
                        const encodedProxy = encodeURIComponent(targetProxyUrl);
                        const proxyResponse = await fetch(\`/check?proxy=\${encodedProxy}\`);
                        return proxyResponse.json();
                    })()
                ]);
                
                // 处理入口信息结果
                if (entryPromise.status === 'fulfilled') {
                    const entryData = entryPromise.value;
                    if (entryData.error) {
                        entryInfo.innerHTML = '<div class="error">入口信息获取失败，请稍后重试</div>';
                    } else {
                        formatInfoDisplay(entryData, 'entryInfo', currentDomainInfo && currentDomainInfo.all_ips.length > 1);
                    }
                } else {
                    entryInfo.innerHTML = '<div class="error">入口信息获取失败，请稍后重试</div>';
                }
                
                // 处理出口信息结果
                if (exitPromise.status === 'fulfilled') {
                    const proxyData = exitPromise.value;
                    if (!proxyData.success) {
                        document.getElementById('exitInfoTitle').textContent = '出口信息(代理不可用)';
                        exitInfo.innerHTML = \`<div class="error">代理检测失败: \${proxyData.error || '请检查代理链接'}</div>\`;
                    } else {
                        formatInfoDisplay(proxyData, 'exitInfo', false, proxyData.responseTime);
                    }
                } else {
                    document.getElementById('exitInfoTitle').textContent = '出口信息(代理不可用)';
                    exitInfo.innerHTML = '<div class="error">代理检测失败，请稍后重试</div>';
                }
                
            } catch (error) {
                console.error('检测过程中出现错误:', error);
                entryInfo.innerHTML = '<div class="error">检测失败，请稍后重试</div>';
                document.getElementById('exitInfoTitle').textContent = '出口信息(代理不可用)';
                exitInfo.innerHTML = '<div class="error">检测失败，请稍后重试</div>';
            } finally {
                checkBtn.disabled = false;
            }
        }
        
        // 回车键触发检查
        document.getElementById('proxyInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                checkProxy();
            }
        });
    </script>
</body>
</html>
    `;

    return new Response(html, {
        headers: { "content-type": "text/html;charset=UTF-8" }
    });
}