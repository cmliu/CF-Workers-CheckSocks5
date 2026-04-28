import { connect } from 'cloudflare:sockets';

const CHECK_TIMEOUT_MS = 12000;
const CONNECT_TIMEOUT_MS = 9999;
const READ_TIMEOUT_MS = 8000;
const MAX_RESPONSE_BYTES = 96 * 1024;
const RESOLVE_BATCH_LIMIT = 50;
const PROXY_TYPES = ['socks5', 'http', 'https', 'turn'];
const DEFAULT_PORTS = {
	socks5: 1080,
	http: 80,
	https: 443,
	turn: 3478
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const DEFAULT_BEIAN_CONTENT = `© 2025 - 2026 Check Socks5 · 基于 <a href="https://github.com/cmliu/CF-Workers-CheckSocks5" target="_blank" rel="noreferrer">Cloudflare Workers 构建与运行</a> · 今日访问人数：<span id="visit-count">···</span> · 站点维护：<a href="https://t.me/CMLiussss" target="_blank" rel="noreferrer">CMLiussss</a>
<script>
(function () {
	const visitCountElement = document.getElementById('visit-count');
	if (!visitCountElement) return;

	const hostname = String(window.location.hostname || window.location.host || '').trim().toLowerCase();
	const statsId = hostname || 'unknown-host';

	fetch('https://tongji.090227.xyz/?id=' + encodeURIComponent(statsId))
		.then(function (response) {
			if (!response.ok) throw new Error('Failed to load visit count: ' + response.status);
			return response.json();
		})
		.then(function (data) {
			if (data && data.visitCount !== undefined) {
				visitCountElement.textContent = data.visitCount;
				return;
			}
			throw new Error('visitCount is missing in response');
		})
		.catch(function (error) {
			console.error('Failed to fetch visit count', error);
			visitCountElement.textContent = '加载失败';
		});
})();
</script>`;

export default {
	async fetch(request, env, ctx) {
		const 备案内容 = env.BEIAN ?? DEFAULT_BEIAN_CONTENT;
		const url = new URL(fixRequestUrl(request.url));
		const origin = request.headers.get('Origin') || '';

		if (request.method === 'OPTIONS') {
			return new Response(null, { status: 204, headers: corsHeaders(origin) });
		}

		try {
			if (url.pathname === '/ip.json') {
				const headers = jsonHeaders(origin);
				const clientIP = url.searchParams.get('ip')
					|| request.headers.get('CF-Connecting-IP')
					|| request.headers.get('X-Forwarded-For')
					|| request.headers.get('X-Real-IP')
					|| request.headers.get('True-Client-IP')
					|| null;
				return handleIpJson({ request, clientIP, headers });
			}

			if (url.pathname.toLowerCase() === '/resolve') {
				const target = url.searchParams.get('proxyip') || url.searchParams.get('target') || url.searchParams.get('host');
				if (!target) return jsonResponse({ error: 'Missing proxyip' }, { status: 400, origin });
				return jsonResponse(await handleResolve(target), { origin });
			}

			if (url.pathname.toLowerCase() === '/resolve-batch') {
				return handleResolveBatchRequest(request, origin);
			}

			if (url.pathname.toLowerCase().startsWith('/check')) {
				const checkParams = parseCheckRequest(url);
				if (!checkParams) {
					return jsonResponse({
						success: false,
						error: 'Missing proxy parameter. Use /check?socks5=host:port, /check?http=host:port, /check?https=host:port, /check?turn=host:port or /check?proxy=socks5://host:port'
					}, { status: 400, origin });
				}
				const result = await checkProxy(checkParams);
				return jsonResponse(result, { origin });
			}

			return new Response(generateHTML(备案内容), {
				headers: {
					'Content-Type': 'text/html; charset=UTF-8',
					'Cache-Control': 'no-cache, no-store, must-revalidate'
				}
			});
		} catch (error) {
			return jsonResponse({
				success: false,
				error: error?.message || String(error),
				timestamp: new Date().toISOString()
			}, { status: 500, origin });
		}
	}
};

function corsHeaders(origin = '') {
	return {
		'Access-Control-Allow-Origin': origin || '*',
		'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
		'Access-Control-Allow-Headers': 'Content-Type, Authorization',
		'Access-Control-Max-Age': '86400'
	};
}

function jsonHeaders(origin = '') {
	return {
		...corsHeaders(origin),
		'Content-Type': 'application/json; charset=UTF-8',
		'Cache-Control': 'no-cache, no-store, must-revalidate'
	};
}

function jsonResponse(data, { status = 200, origin = '' } = {}) {
	return new Response(JSON.stringify(data, null, 2), {
		status,
		headers: jsonHeaders(origin)
	});
}

function handleIpJson({ request, clientIP, headers }) {
	const cf = request.cf || {};
	const timezone = cf.timezone || 'UTC';
	const data = {
		ip: clientIP,
		ipType: clientIP ? (clientIP.includes(':') && !clientIP.includes('.') ? 'ipv6' : 'ipv4') : null,
		colo: cf.colo || null,
		asn: cf.asn || null,
		asOrganization: cf.asOrganization || null,
		org: cf.asn && cf.asOrganization ? `AS${cf.asn} ${cf.asOrganization}` : null,
		continent: cf.continent || null,
		country: cf.country || null,
		regionCode: cf.regionCode || null,
		region: cf.region || null,
		city: cf.city || null,
		postalCode: cf.postalCode || null,
		timezone,
		loc: cf.latitude && cf.longitude ? `${cf.latitude},${cf.longitude}` : null,
		longitude: cf.longitude || null,
		latitude: cf.latitude || null,
		time: new Date().toLocaleString('zh-CN', { timeZone: timezone }),
		timeStamp: Date.now()
	};
	return new Response(JSON.stringify(data, null, 2), { headers });
}

function parseCheckRequest(url) {
	for (const type of PROXY_TYPES) {
		if (url.searchParams.has(type)) {
			return { type, value: url.searchParams.get(type) || '' };
		}
	}

	if (url.searchParams.has('proxy')) {
		const value = url.searchParams.get('proxy') || '';
		const parsed = splitProxyScheme(value);
		if (parsed?.type) return { type: parsed.type, value: parsed.rest };
	}

	const tail = decodeURIComponent(url.pathname.slice('/check'.length).replace(/^\/+/, ''));
	const pathMatch = tail.match(/^(socks5|http|https|turn|proxy)=(.+)$/i);
	if (pathMatch) {
		const key = pathMatch[1].toLowerCase();
		const value = pathMatch[2];
		if (key === 'proxy') {
			const parsed = splitProxyScheme(value);
			if (parsed?.type) return { type: parsed.type, value: parsed.rest };
		}
		if (PROXY_TYPES.includes(key)) return { type: key, value };
	}

	return null;
}

async function checkProxy({ type, value }) {
	const startedAt = Date.now();
	let proxy;

	try {
		proxy = parseProxyAddress(value, type, DEFAULT_PORTS[type]);
	} catch (error) {
		return buildCheckResult({
			type,
			rawValue: value,
			proxy: null,
			success: false,
			error: error.message,
			responseTime: Date.now() - startedAt
		});
	}

	let tunnel = null;
	const targetHost = 'api.ipapi.is';
	const targetPort = 443;

	try {
		tunnel = await withTimeout(openProxyTunnel(proxy, targetHost, targetPort), CHECK_TIMEOUT_MS, 'Proxy connection timed out');
		const exit = await requestIpJsonOverTlsTunnel(tunnel, targetHost);

		return buildCheckResult({
			type,
			rawValue: value,
			proxy,
			success: true,
			exit,
			responseTime: Date.now() - startedAt
		});
	} catch (error) {
		return buildCheckResult({
			type,
			rawValue: value,
			proxy,
			success: false,
			error: error?.message || String(error),
			responseTime: Date.now() - startedAt
		});
	} finally {
		try { tunnel?.close?.(); } catch (e) { }
	}
}

function buildCheckResult({ type, rawValue, proxy, success, exit = null, error = null, responseTime }) {
	const candidate = proxy ? formatProxyAuthority(proxy) : stripProxyScheme(rawValue);
	const result = {
		candidate,
		type,
		username: proxy?.username ?? null,
		password: proxy?.password ?? null,
		hostname: proxy?.hostname ?? null,
		port: proxy?.port ?? null,
		link: proxy ? formatProxyLink(proxy) : `${type}://${candidate}`,
		success,
		responseTime
	};
	if (success) result.exit = exit;
	else result.error = error || 'Proxy check failed';
	return result;
}

async function openProxyTunnel(proxy, targetHost, targetPort) {
	if (proxy.type === 'socks5') return socks5Connect(proxy, targetHost, targetPort);
	if (proxy.type === 'http') return httpConnect(proxy, targetHost, targetPort, false);
	if (proxy.type === 'https') {
		if (isIPHostname(proxy.hostname)) return httpsConnect(proxy, targetHost, targetPort);
		return httpConnect(proxy, targetHost, targetPort, true);
	}
	if (proxy.type === 'turn') return turnConnect(proxy, targetHost, targetPort);
	throw new Error(`Unsupported proxy type: ${proxy.type}`);
}

async function requestIpJsonOverTlsTunnel(tunnel, targetHost) {
	const tlsSocket = new TlsClient(tunnel, {
		serverName: stripIPv6Brackets(targetHost),
		timeout: READ_TIMEOUT_MS,
		allowChacha: true
	});
	try {
		await withTimeout(tlsSocket.handshake(), CHECK_TIMEOUT_MS, 'Target TLS handshake timed out');
		await tlsSocket.write(encoder.encode(buildIpJsonRequest(targetHost)));
		const responseBytes = await readTlsHttpResponse(tlsSocket);
		return parseIpJsonResponse(responseBytes);
	} finally {
		try { tlsSocket.close(); } catch (e) { }
	}
}

async function requestIpJsonOverPlainTunnel(tunnel, targetHost) {
	const writer = tunnel.writable.getWriter();
	try {
		await writer.write(encoder.encode(buildIpJsonRequest(targetHost)));
	} finally {
		try { writer.releaseLock(); } catch (e) { }
	}
	const responseBytes = await readStreamHttpResponse(tunnel.readable);
	return parseIpJsonResponse(responseBytes);
}

function buildIpJsonRequest(targetHost) {
	return [
		'GET / HTTP/1.1',
		`Host: ${targetHost}`,
		'User-Agent: Mozilla/5.0 CF-Workers-CheckProxy/2.0',
		'Accept: application/json',
		'Connection: close',
		'',
		''
	].join('\r\n');
}

async function readTlsHttpResponse(tlsSocket) {
	let responseBuffer = new Uint8Array(0);
	while (responseBuffer.byteLength < MAX_RESPONSE_BYTES) {
		const value = await withTimeout(tlsSocket.read(), READ_TIMEOUT_MS, 'Reading target response timed out');
		if (!value) break;
		if (!value.byteLength) continue;
		responseBuffer = concatUint8(responseBuffer, value);
		if (isHttpResponseComplete(responseBuffer)) break;
	}
	if (!responseBuffer.byteLength) throw new Error('Target returned no data');
	return responseBuffer;
}

async function readStreamHttpResponse(readable) {
	const reader = readable.getReader();
	let responseBuffer = new Uint8Array(0);
	try {
		while (responseBuffer.byteLength < MAX_RESPONSE_BYTES) {
			const { done, value } = await withTimeout(reader.read(), READ_TIMEOUT_MS, 'Reading target response timed out');
			if (done) break;
			if (!value?.byteLength) continue;
			responseBuffer = concatUint8(responseBuffer, value);
			if (isHttpResponseComplete(responseBuffer)) break;
		}
	} finally {
		try { reader.releaseLock(); } catch (e) { }
	}
	if (!responseBuffer.byteLength) throw new Error('Target returned no data');
	return responseBuffer;
}

function parseIpJsonResponse(responseBuffer) {
	const headerEndIndex = indexOfHeaderEnd(responseBuffer);
	if (headerEndIndex === -1) throw new Error('Invalid target response headers');
	const headerText = decoder.decode(responseBuffer.slice(0, headerEndIndex));
	const statusLine = headerText.split('\r\n')[0] || '';
	const statusMatch = statusLine.match(/HTTP\/\d(?:\.\d)?\s+(\d+)/i);
	const statusCode = statusMatch ? Number(statusMatch[1]) : NaN;
	if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) {
		throw new Error(`Target /ip.json request failed: ${statusLine || 'invalid status'}`);
	}

	let bodyBytes = responseBuffer.slice(headerEndIndex);
	const lengthMatch = headerText.match(/\r\ncontent-length:\s*(\d+)/i);
	if (lengthMatch) bodyBytes = bodyBytes.slice(0, Number(lengthMatch[1]));

	let bodyText = decoder.decode(bodyBytes);
	if (/\r\ntransfer-encoding:\s*chunked/i.test(headerText)) {
		bodyText = decodeChunkedBody(bodyText);
	}

	try {
		return JSON.parse(bodyText.trim());
	} catch (error) {
		throw new Error('Target /ip.json did not return valid JSON');
	}
}

function isHttpResponseComplete(buffer) {
	const headerEndIndex = indexOfHeaderEnd(buffer);
	if (headerEndIndex === -1) return false;
	const headerText = decoder.decode(buffer.slice(0, headerEndIndex));
	const lengthMatch = headerText.match(/\r\ncontent-length:\s*(\d+)/i);
	if (lengthMatch) return buffer.byteLength >= headerEndIndex + Number(lengthMatch[1]);
	if (/\r\ntransfer-encoding:\s*chunked/i.test(headerText)) return decoder.decode(buffer).includes('\r\n0\r\n\r\n');
	return false;
}

function decodeChunkedBody(text) {
	let cursor = 0;
	let output = '';
	while (cursor < text.length) {
		const lineEnd = text.indexOf('\r\n', cursor);
		if (lineEnd === -1) break;
		const sizeText = text.slice(cursor, lineEnd).split(';')[0].trim();
		const size = parseInt(sizeText, 16);
		if (!Number.isFinite(size)) break;
		cursor = lineEnd + 2;
		if (size === 0) break;
		output += text.slice(cursor, cursor + size);
		cursor += size + 2;
	}
	return output || text;
}

function indexOfHeaderEnd(buffer) {
	for (let i = 0; i < buffer.byteLength - 3; i++) {
		if (buffer[i] === 0x0d && buffer[i + 1] === 0x0a && buffer[i + 2] === 0x0d && buffer[i + 3] === 0x0a) return i + 4;
	}
	return -1;
}

const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);
const TURN_STUN_TYPE = {
	ALLOCATE_REQUEST: 0x0003,
	ALLOCATE_SUCCESS: 0x0103,
	ALLOCATE_ERROR: 0x0113,
	CREATE_PERMISSION_REQUEST: 0x0008,
	CREATE_PERMISSION_SUCCESS: 0x0108,
	CONNECT_REQUEST: 0x000a,
	CONNECT_SUCCESS: 0x010a,
	CONNECTION_BIND_REQUEST: 0x000b,
	CONNECTION_BIND_SUCCESS: 0x010b
};
const TURN_STUN_ATTR = {
	USERNAME: 0x0006,
	MESSAGE_INTEGRITY: 0x0008,
	ERROR_CODE: 0x0009,
	XOR_PEER_ADDRESS: 0x0012,
	REALM: 0x0014,
	NONCE: 0x0015,
	REQUESTED_TRANSPORT: 0x0019,
	CONNECTION_ID: 0x002a
};

function turnStunPadding(length) {
	return -length & 3;
}

function readUint16BE(bytes, offset = 0) {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

function createTurnStunAttribute(type, value) {
	const body = 数据转Uint8Array(value);
	const attribute = new Uint8Array(4 + body.byteLength + turnStunPadding(body.byteLength));
	const view = new DataView(attribute.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	attribute.set(body, 4);
	return attribute;
}

function createTurnStunMessage(type, transactionId, attributes) {
	const body = concatUint8(...attributes);
	const header = new Uint8Array(20);
	const view = new DataView(header.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	header.set(TURN_STUN_MAGIC_COOKIE, 4);
	header.set(transactionId, 8);
	return concatUint8(header, body);
}

function createTurnXorPeerAddress(ip, port) {
	if (!isIPv4(ip)) throw new Error('TURN CONNECT currently requires an IPv4 target address');
	const address = new Uint8Array(8);
	address[1] = 1;
	new DataView(address.buffer).setUint16(2, port ^ 0x2112);
	ip.split('.').forEach((value, index) => {
		address[4 + index] = Number(value) ^ TURN_STUN_MAGIC_COOKIE[index];
	});
	return address;
}

/** @typedef {{ type: number, attributes: Record<number, Uint8Array> }} TurnStunMessage */

/** @returns {TurnStunMessage | null} */
function parseTurnStunMessage(data) {
	const buffer = 数据转Uint8Array(data);
	if (buffer.byteLength < 20 || TURN_STUN_MAGIC_COOKIE.some((value, index) => buffer[4 + index] !== value)) return null;

	const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
	const messageLength = view.getUint16(2);
	/** @type {Record<number, Uint8Array>} */
	const attributes = {};

	for (let offset = 20; offset + 4 <= 20 + messageLength;) {
		const type = view.getUint16(offset);
		const length = view.getUint16(offset + 2);
		if (offset + 4 + length > buffer.byteLength) break;

		attributes[type] = buffer.slice(offset + 4, offset + 4 + length);
		offset += 4 + length + turnStunPadding(length);
	}

	return {
		type: view.getUint16(0),
		attributes
	};
}

function parseTurnErrorCode(data) {
	return data?.byteLength >= 4 ? (data[2] & 7) * 100 + data[3] : 0;
}

function randomTurnTransactionId() {
	return crypto.getRandomValues(new Uint8Array(12));
}

async function addTurnMessageIntegrity(message, key) {
	const signedMessage = new Uint8Array(message);
	const view = new DataView(signedMessage.buffer);
	view.setUint16(2, view.getUint16(2) + 24);

	const hmacKey = await crypto.subtle.importKey(
		'raw',
		key,
		{ name: 'HMAC', hash: 'SHA-1' },
		false,
		['sign']
	);
	const signature = await crypto.subtle.sign('HMAC', hmacKey, signedMessage);
	return concatUint8(
		signedMessage,
		createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature))
	);
}

/** @returns {Promise<{ message: TurnStunMessage, extraData: Uint8Array | null }>} */
async function readTurnStunMessage(reader, bufferedData = null, timeoutMessage = 'TURN response timed out') {
	let buffer = 有效数据长度(bufferedData) ? 数据转Uint8Array(bufferedData) : new Uint8Array(0);
	const pull = async () => {
		const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, timeoutMessage);
		if (done) throw new Error('TURN server closed connection');
		if (value?.byteLength) buffer = concatUint8(buffer, value);
	};

	while (buffer.byteLength < 20) await pull();

	const messageLength = 20 + readUint16BE(buffer, 2);
	if (messageLength > 65555) throw new Error('TURN response is too large');
	while (buffer.byteLength < messageLength) await pull();

	const message = parseTurnStunMessage(buffer.subarray(0, messageLength));
	if (!message) throw new Error('Invalid TURN/STUN response');

	return {
		message,
		extraData: buffer.byteLength > messageLength ? buffer.subarray(messageLength) : null
	};
}

async function resolveTurnTargetIPv4(hostname) {
	const host = stripIPv6Brackets(hostname);
	if (isIPv4(host)) return host;

	const records = await dohQuery(host, 'A');
	const record = records.find(item => item.type === 1 && isIPv4(item.data));
	return record?.data || null;
}

async function createTurnLongTermCredentialKey(value) {
	return new Uint8Array(await crypto.subtle.digest('MD5', encoder.encode(value)));
}

async function writeTurnBytes(writer, bytes, timeoutMessage) {
	await withTimeout(writer.write(bytes), CONNECT_TIMEOUT_MS, timeoutMessage);
}

async function allocateTurnRelay(writer, reader, transport, credentials, pipeline) {
	const requestedTransport = new Uint8Array([transport, 0, 0, 0]);
	await writeTurnBytes(writer, createTurnStunMessage(
		TURN_STUN_TYPE.ALLOCATE_REQUEST,
		randomTurnTransactionId(),
		[createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport)]
	), 'TURN Allocate request timed out');

	let turnResponse = await readTurnStunMessage(reader, null, 'TURN Allocate response timed out');
	let message = turnResponse.message;
	let extraData = turnResponse.extraData;
	let integrityKey = null;
	let authAttributes = [];
	const sign = messageToSign => (
		integrityKey ? addTurnMessageIntegrity(messageToSign, integrityKey) : Promise.resolve(messageToSign)
	);

	if (
		message.type === TURN_STUN_TYPE.ALLOCATE_ERROR
		&& credentials.username !== null
		&& credentials.password !== null
		&& parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]) === 401
	) {
		const realmBytes = message.attributes[TURN_STUN_ATTR.REALM];
		const nonce = message.attributes[TURN_STUN_ATTR.NONCE];
		if (!realmBytes?.byteLength || !nonce?.byteLength) throw new Error('TURN authentication challenge is missing realm or nonce');

		const realm = decoder.decode(realmBytes);
		integrityKey = await createTurnLongTermCredentialKey(`${credentials.username}:${realm}:${credentials.password}`);
		authAttributes = [
			createTurnStunAttribute(TURN_STUN_ATTR.USERNAME, encoder.encode(credentials.username)),
			createTurnStunAttribute(TURN_STUN_ATTR.REALM, encoder.encode(realm)),
			createTurnStunAttribute(TURN_STUN_ATTR.NONCE, nonce)
		];

		const allocateRequest = await addTurnMessageIntegrity(createTurnStunMessage(
			TURN_STUN_TYPE.ALLOCATE_REQUEST,
			randomTurnTransactionId(),
			[
				createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport),
				...authAttributes
			]
		), integrityKey);

		const pipelinedMessages = pipeline ? await Promise.all(pipeline(authAttributes, sign)) : [];
		await writeTurnBytes(
			writer,
			pipelinedMessages.length ? concatUint8(allocateRequest, ...pipelinedMessages) : allocateRequest,
			'TURN authenticated Allocate request timed out'
		);

		turnResponse = await readTurnStunMessage(reader, extraData, 'TURN authenticated Allocate response timed out');
		message = turnResponse.message;
		extraData = turnResponse.extraData;
	} else if (pipeline && message.type === TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
		const pipelinedMessages = await Promise.all(pipeline(authAttributes, sign));
		if (pipelinedMessages.length) {
			await writeTurnBytes(writer, concatUint8(...pipelinedMessages), 'TURN pipelined request timed out');
		}
	}

	if (message.type !== TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
		const errorCode = parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]);
		throw new Error(errorCode ? `TURN Allocate failed with ${errorCode}` : 'TURN Allocate failed');
	}

	return { authAttributes, extraData, sign };
}

async function turnConnect(proxy, targetHost, targetPort) {
	const targetIp = await resolveTurnTargetIPv4(targetHost);
	if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for TURN CONNECT`);

	const turnHost = stripIPv6Brackets(proxy.hostname);
	let controlSocket = null;
	let dataSocket = null;
	let controlWriter = null;
	let controlReader = null;
	let dataWriter = null;
	let dataReader = null;
	let dataReaderReleased = false;

	const close = () => {
		try { controlSocket?.close?.(); } catch (e) { }
		try { dataSocket?.close?.(); } catch (e) { }
	};
	const releaseDataReader = () => {
		if (dataReaderReleased) return;
		dataReaderReleased = true;
		try { dataReader?.releaseLock?.(); } catch (e) { }
	};

	try {
		controlSocket = connect({ hostname: turnHost, port: proxy.port });
		await withTimeout(controlSocket.opened, CONNECT_TIMEOUT_MS, 'TURN server connection timed out');
		controlWriter = controlSocket.writable.getWriter();
		controlReader = controlSocket.readable.getReader();

		const peerAddress = createTurnStunAttribute(
			TURN_STUN_ATTR.XOR_PEER_ADDRESS,
			createTurnXorPeerAddress(targetIp, targetPort)
		);

		const allocation = await allocateTurnRelay(
			controlWriter,
			controlReader,
			6,
			{ username: proxy.username, password: proxy.password },
			(authAttributes, sign) => [
				sign(createTurnStunMessage(
					TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST,
					randomTurnTransactionId(),
					[peerAddress, ...authAttributes]
				)),
				sign(createTurnStunMessage(
					TURN_STUN_TYPE.CONNECT_REQUEST,
					randomTurnTransactionId(),
					[peerAddress, ...authAttributes]
				))
			]
		);

		let bufferedData = allocation.extraData;
		dataSocket = connect({ hostname: turnHost, port: proxy.port });

		let turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CreatePermission response timed out');
		let message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS) throw new Error('TURN CreatePermission failed');

		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CONNECT response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECT_SUCCESS || !message.attributes[TURN_STUN_ATTR.CONNECTION_ID]) {
			throw new Error('TURN CONNECT failed');
		}

		await withTimeout(dataSocket.opened, CONNECT_TIMEOUT_MS, 'TURN data connection timed out');
		dataWriter = dataSocket.writable.getWriter();
		dataReader = dataSocket.readable.getReader();

		await writeTurnBytes(dataWriter, await allocation.sign(createTurnStunMessage(
			TURN_STUN_TYPE.CONNECTION_BIND_REQUEST,
			randomTurnTransactionId(),
			[
				createTurnStunAttribute(TURN_STUN_ATTR.CONNECTION_ID, message.attributes[TURN_STUN_ATTR.CONNECTION_ID]),
				...allocation.authAttributes
			]
		)), 'TURN ConnectionBind request timed out');

		let extraPayload = null;
		turnResponse = await readTurnStunMessage(dataReader, null, 'TURN ConnectionBind response timed out');
		message = turnResponse.message;
		extraPayload = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS) throw new Error('TURN ConnectionBind failed');

		controlWriter.releaseLock();
		controlWriter = null;
		controlReader.releaseLock();
		controlReader = null;
		dataWriter.releaseLock();
		dataWriter = null;

		const readable = new ReadableStream({
			start(controller) {
				if (extraPayload?.byteLength) controller.enqueue(extraPayload);
			},
			pull(controller) {
				return dataReader.read().then(({ done, value }) => {
					if (done) {
						releaseDataReader();
						controller.close();
					} else if (value?.byteLength) {
						controller.enqueue(new Uint8Array(value));
					}
				});
			},
			cancel() {
				try { dataReader?.cancel?.(); } catch (e) { }
				releaseDataReader();
				close();
			}
		});

		return {
			readable,
			writable: dataSocket.writable,
			closed: dataSocket.closed,
			close
		};
	} catch (error) {
		try { controlWriter?.releaseLock?.(); } catch (e) { }
		try { controlReader?.releaseLock?.(); } catch (e) { }
		try { dataWriter?.releaseLock?.(); } catch (e) { }
		releaseDataReader();
		close();
		throw error;
	}
}

async function socks5Connect(proxy, targetHost, targetPort) {
	const socket = connect({ hostname: stripIPv6Brackets(proxy.hostname), port: proxy.port });
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();
	try {
		await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, 'SOCKS5 proxy connection timed out');
		const authMethods = proxy.username !== null && proxy.password !== null
			? new Uint8Array([0x05, 0x02, 0x00, 0x02])
			: new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);

		let response = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, 'SOCKS5 authentication negotiation timed out');
		if (response.done || response.value.byteLength < 2) throw new Error('SOCKS5 method selection failed');
		const selectedMethod = response.value[1];

		if (selectedMethod === 0x02) {
			if (proxy.username === null || proxy.password === null) throw new Error('SOCKS5 requires authentication');
			const userBytes = encoder.encode(proxy.username);
			const passBytes = encoder.encode(proxy.password);
			if (userBytes.byteLength > 255 || passBytes.byteLength > 255) throw new Error('SOCKS5 username/password is too long');
			await writer.write(new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]));
			response = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, 'SOCKS5 username/password authentication timed out');
			if (response.done || response.value[1] !== 0x00) throw new Error('SOCKS5 authentication failed');
		} else if (selectedMethod !== 0x00) {
			throw new Error(`SOCKS5 unsupported auth method: ${selectedMethod}`);
		}

		const hostBytes = encoder.encode(targetHost);
		if (hostBytes.byteLength > 255) throw new Error('Target hostname is too long for SOCKS5');
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, 'SOCKS5 CONNECT timed out');
		if (response.done || response.value[1] !== 0x00) throw new Error(`SOCKS5 connection failed: ${response.value?.[1] ?? 'closed'}`);

		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock(); } catch (e) { }
		try { reader.releaseLock(); } catch (e) { }
		try { socket.close(); } catch (e) { }
		throw error;
	}
}

async function httpConnect(proxy, targetHost, targetPort, secureProxy = false) {
	const socket = secureProxy
		? connect({ hostname: stripIPv6Brackets(proxy.hostname), port: proxy.port }, { secureTransport: 'on', allowHalfOpen: false })
		: connect({ hostname: stripIPv6Brackets(proxy.hostname), port: proxy.port });
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();
	try {
		await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, `${secureProxy ? 'HTTPS' : 'HTTP'} proxy connection timed out`);
		const auth = proxy.username !== null && proxy.password !== null
			? `Proxy-Authorization: Basic ${btoa(`${proxy.username}:${proxy.password}`)}\r\n`
			: '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0);
		let headerEndIndex = -1;
		while (headerEndIndex === -1 && responseBuffer.byteLength < 8192) {
			const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, `${secureProxy ? 'HTTPS' : 'HTTP'} proxy CONNECT response timed out`);
			if (done || !value) throw new Error(`${secureProxy ? 'HTTPS' : 'HTTP'} proxy closed before returning CONNECT response`);
			responseBuffer = concatUint8(responseBuffer, value);
			headerEndIndex = indexOfHeaderEnd(responseBuffer);
		}

		if (headerEndIndex === -1) throw new Error('Proxy CONNECT response headers are too large or invalid');
		const statusLine = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0] || '';
		const statusMatch = statusLine.match(/HTTP\/\d(?:\.\d)?\s+(\d+)/i);
		const statusCode = statusMatch ? Number(statusMatch[1]) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`CONNECT failed: ${statusLine || statusCode}`);

		reader.releaseLock();
		if (responseBuffer.byteLength > headerEndIndex) {
			return wrapSocketWithBufferedData(socket, responseBuffer.slice(headerEndIndex));
		}
		return socket;
	} catch (error) {
		try { writer.releaseLock(); } catch (e) { }
		try { reader.releaseLock(); } catch (e) { }
		try { socket.close(); } catch (e) { }
		throw error;
	}
}

async function httpsConnect(proxy, targetHost, targetPort) {
	let tlsSocket = null;
	const tlsServerName = isIPHostname(proxy.hostname) ? '' : stripIPv6Brackets(proxy.hostname);
	const openProxyTls = async (allowChacha = false) => {
		const proxySocket = connect({ hostname: stripIPv6Brackets(proxy.hostname), port: proxy.port });
		try {
			await withTimeout(proxySocket.opened, CONNECT_TIMEOUT_MS, 'HTTPS proxy TCP connection timed out');
			const socket = new TlsClient(proxySocket, { serverName: tlsServerName, timeout: READ_TIMEOUT_MS, allowChacha });
			await withTimeout(socket.handshake(), CHECK_TIMEOUT_MS, 'HTTPS proxy TLS handshake timed out');
			return socket;
		} catch (error) {
			try { proxySocket.close(); } catch (e) { }
			throw error;
		}
	};

	try {
		try {
			tlsSocket = await openProxyTls(false);
		} catch (error) {
			if (!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(error?.message || String(error))) throw error;
			tlsSocket = await openProxyTls(true);
		}

		const auth = proxy.username !== null && proxy.password !== null
			? `Proxy-Authorization: Basic ${btoa(`${proxy.username}:${proxy.password}`)}\r\n`
			: '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n`;
		await tlsSocket.write(encoder.encode(request));

		let responseBuffer = new Uint8Array(0);
		let headerEndIndex = -1;
		while (headerEndIndex === -1 && responseBuffer.byteLength < 8192) {
			const value = await withTimeout(tlsSocket.read(), CONNECT_TIMEOUT_MS, 'HTTPS proxy CONNECT response timed out');
			if (!value) throw new Error('HTTPS proxy closed before returning CONNECT response');
			responseBuffer = concatUint8(responseBuffer, value);
			headerEndIndex = indexOfHeaderEnd(responseBuffer);
		}

		if (headerEndIndex === -1) throw new Error('HTTPS proxy CONNECT response headers are too large or invalid');
		const statusLine = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0] || '';
		const statusMatch = statusLine.match(/HTTP\/\d(?:\.\d)?\s+(\d+)/i);
		const statusCode = statusMatch ? Number(statusMatch[1]) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`CONNECT failed: ${statusLine || statusCode}`);

		return wrapTlsSocket(tlsSocket, responseBuffer.byteLength > headerEndIndex ? responseBuffer.slice(headerEndIndex) : null);
	} catch (error) {
		try { tlsSocket?.close?.(); } catch (e) { }
		throw error;
	}
}

function parseProxyAddress(input, type, defaultPort = 80) {
	let address = stripProxyScheme(String(input || '').trim()).split('#')[0].trim();
	if (!address) throw new Error('Proxy address cannot be empty');

	const atIndex = address.lastIndexOf('@');
	let authPart = '';
	let hostPart = address;
	if (atIndex !== -1) {
		authPart = address.slice(0, atIndex).replaceAll('%3D', '=');
		if (!authPart.includes(':') && BASE64_AUTH_RE.test(authPart)) {
			try { authPart = atob(authPart); } catch (e) { }
		}
		hostPart = address.slice(atIndex + 1);
	}

	let username = null;
	let password = null;
	if (authPart) {
		const colonIndex = authPart.indexOf(':');
		if (colonIndex === -1) throw new Error('Proxy auth must use username:password format');
		username = safeDecode(authPart.slice(0, colonIndex));
		password = safeDecode(authPart.slice(colonIndex + 1));
	}

	hostPart = hostPart.split('/')[0].trim();
	let hostname = hostPart;
	let port = defaultPort;
	if (hostPart.startsWith('[')) {
		const closeIndex = hostPart.indexOf(']');
		if (closeIndex === -1) throw new Error('IPv6 address is missing the closing bracket');
		hostname = hostPart.slice(0, closeIndex + 1);
		if (hostPart.slice(closeIndex + 1).startsWith(':')) {
			port = Number(hostPart.slice(closeIndex + 2).replace(/[^\d]/g, ''));
		}
	} else {
		const colonCount = (hostPart.match(/:/g) || []).length;
		if (colonCount === 1) {
			const separator = hostPart.lastIndexOf(':');
			hostname = hostPart.slice(0, separator);
			port = Number(hostPart.slice(separator + 1).replace(/[^\d]/g, ''));
		} else if (colonCount > 1) {
			throw new Error('IPv6 address must be wrapped in brackets, for example [2001:db8::1]:1080');
		}
	}

	hostname = safeDecode(hostname.trim());
	if (!hostname) throw new Error('Missing proxy hostname');
	if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Port must be a number between 1 and 65535');
	if (hostname.includes(':') && !hostname.startsWith('[')) throw new Error('IPv6 address must be wrapped in brackets');

	return { type, username, password, hostname, port };
}

const BASE64_AUTH_RE = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;

function splitProxyScheme(input) {
	const text = String(input || '').trim();
	const match = text.match(/^(socks5|http|https|turn):\/\/(.+)$/i);
	return match ? { type: match[1].toLowerCase(), rest: match[2] } : null;
}

function stripProxyScheme(input) {
	return String(input || '').replace(/^(socks5|http|https|turn):\/\//i, '');
}

function formatProxyAuthority(proxy) {
	const auth = proxy.username !== null && proxy.password !== null ? `${proxy.username}:${proxy.password}@` : '';
	return `${auth}${proxy.hostname}:${proxy.port}`;
}

function formatProxyLink(proxy) {
	return `${proxy.type}://${formatProxyAuthority(proxy)}`;
}

function safeDecode(value) {
	try { return decodeURIComponent(value); } catch (e) { return value; }
}

function fixRequestUrl(urlText) {
	const hashIndex = urlText.indexOf('#');
	const main = hashIndex === -1 ? urlText : urlText.slice(0, hashIndex);
	const tail = hashIndex === -1 ? '' : urlText.slice(hashIndex);
	if (main.includes('?') || !/%3f/i.test(main)) return urlText;
	return main.replace(/%3f/i, '?') + tail;
}

async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => {
				timer = setTimeout(() => reject(new Error(message)), timeoutMs);
			})
		]);
	} finally {
		clearTimeout(timer);
	}
}

function 数据转Uint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function 有效数据长度(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

function concatUint8(...chunks) {
	const arrays = chunks.filter(Boolean).map(数据转Uint8Array);
	const length = arrays.reduce((sum, chunk) => sum + chunk.byteLength, 0);
	const output = new Uint8Array(length);
	let offset = 0;
	for (const chunk of arrays) {
		output.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return output;
}

function 拼接字节数据(...chunks) {
	return concatUint8(...chunks);
}

function wrapSocketWithBufferedData(socket, bufferedData) {
	if (!有效数据长度(bufferedData)) return socket;
	const readable = new ReadableStream({
		async start(controller) {
			try {
				controller.enqueue(数据转Uint8Array(bufferedData));
				const reader = socket.readable.getReader();
				try {
					while (true) {
						const { done, value } = await reader.read();
						if (done) break;
						if (value?.byteLength) controller.enqueue(value);
					}
					controller.close();
				} finally {
					try { reader.releaseLock(); } catch (e) { }
				}
			} catch (error) {
				controller.error(error);
			}
		},
		cancel() {
			try { socket.close(); } catch (e) { }
		}
	});
	return {
		readable,
		writable: socket.writable,
		closed: socket.closed,
		close: () => socket.close()
	};
}

function wrapTlsSocket(tlsSocket, bufferedData = null) {
	let closedSettled = false;
	let resolveClosed;
	let rejectClosed;
	const closed = new Promise((resolve, reject) => {
		resolveClosed = resolve;
		rejectClosed = reject;
	});
	const settleClosed = (settle, value) => {
		if (closedSettled) return;
		closedSettled = true;
		settle(value);
	};
	const close = () => {
		try { tlsSocket.close(); } catch (e) { }
		settleClosed(resolveClosed);
	};

	const readable = new ReadableStream({
		async start(controller) {
			try {
				if (有效数据长度(bufferedData) > 0) controller.enqueue(数据转Uint8Array(bufferedData));
				while (true) {
					const data = await tlsSocket.read();
					if (!data) break;
					if (data.byteLength > 0) controller.enqueue(data);
				}
				controller.close();
				settleClosed(resolveClosed);
			} catch (error) {
				try { controller.error(error); } catch (e) { }
				settleClosed(rejectClosed, error);
			}
		},
		cancel() {
			close();
		}
	});

	const writable = new WritableStream({
		async write(chunk) {
			await tlsSocket.write(数据转Uint8Array(chunk));
		},
		close,
		abort(error) {
			close();
			if (error) settleClosed(rejectClosed, error);
		}
	});

	return { readable, writable, closed, close };
}

function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	if (isIPv4(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}

function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => {
		if (!/^\d{1,3}$/.test(part)) return false;
		const num = Number(part);
		return num >= 0 && num <= 255;
	});
}

async function handleResolveBatchRequest(request, origin = '') {
	const headers = jsonHeaders(origin);
	if (request.method !== 'POST') {
		return new Response(JSON.stringify({ error: 'Method not allowed' }), {
			status: 405,
			headers: { ...headers, Allow: 'POST, OPTIONS' }
		});
	}

	let payload;
	try {
		payload = await request.json();
	} catch (error) {
		return new Response(JSON.stringify({ error: 'Invalid JSON body' }), { status: 400, headers });
	}

	const inputs = uniqueStrings((Array.isArray(payload?.targets) ? payload.targets : (Array.isArray(payload?.proxyips) ? payload.proxyips : []))
		.map(value => String(value || '').trim())
		.filter(Boolean));

	if (!inputs.length) return new Response(JSON.stringify({ error: 'Missing targets' }), { status: 400, headers });
	if (inputs.length > RESOLVE_BATCH_LIMIT) return new Response(JSON.stringify({ error: `Resolve batch limit is ${RESOLVE_BATCH_LIMIT}` }), { status: 400, headers });

	const results = await Promise.all(inputs.map(async input => {
		try {
			return { input, targets: await handleResolve(input) };
		} catch (error) {
			return { input, targets: [], error: error.message };
		}
	}));

	return new Response(JSON.stringify({ results }, null, 2), { headers });
}

async function handleResolve(input) {
	let { host, port } = parseTarget(input);
	const tpPortMatch = host.toLowerCase().match(/\.tp(\d{1,5})\./);
	if (tpPortMatch) {
		const tpPort = Number(tpPortMatch[1]);
		if (tpPort >= 1 && tpPort <= 65535) port = tpPort;
	}

	const bracketedIPv6 = host.startsWith('[') && host.endsWith(']');
	const rawIPv6 = /^[0-9a-fA-F:]+$/.test(host) && host.includes(':');
	if (isIPv4(host) || bracketedIPv6 || rawIPv6) {
		const finalHost = rawIPv6 && !bracketedIPv6 ? `[${host}]` : host;
		return [`${finalHost}:${port}`];
	}

	if (host.toLowerCase().includes('.william.')) {
		const txtRecords = await dohQuery(host, 'TXT');
		const targets = [];
		for (const record of txtRecords) {
			for (const part of normalizeTxtValue(record.data).split(',')) {
				const candidate = part.trim();
				if (candidate) targets.push(candidate);
			}
		}
		if (targets.length) return uniqueStrings(targets);
	}

	let [aRecords, aaaaRecords] = await Promise.all([
		dohQuery(host, 'A'),
		dohQuery(host, 'AAAA')
	]);

	let results = recordsToTargets(aRecords, aaaaRecords, port);
	if (!results.length) throw new Error('Could not resolve domain');
	return uniqueStrings(results);
}

function parseTarget(input) {
	let text = String(input || '').trim().split('#')[0].trim();
	const proxy = splitProxyScheme(text);
	if (proxy) text = proxy.rest;
	if (text.includes('@')) text = text.slice(text.lastIndexOf('@') + 1);

	let host = text;
	let port = 443;
	if (host.startsWith('[')) {
		const ipv6PortIndex = host.lastIndexOf(']:');
		if (ipv6PortIndex !== -1) {
			const maybePort = Number(host.slice(ipv6PortIndex + 2));
			if (Number.isInteger(maybePort) && maybePort >= 1 && maybePort <= 65535) {
				port = maybePort;
				host = host.slice(0, ipv6PortIndex + 1);
			}
		}
		return { host, port };
	}

	const colonMatches = host.match(/:/g) || [];
	if (colonMatches.length === 1) {
		const separatorIndex = host.lastIndexOf(':');
		const maybePort = Number(host.slice(separatorIndex + 1));
		if (Number.isInteger(maybePort) && maybePort >= 1 && maybePort <= 65535) {
			port = maybePort;
			host = host.slice(0, separatorIndex);
		}
	}
	return { host, port };
}

function recordsToTargets(aRecords, aaaaRecords, port) {
	const results = [];
	for (const record of aRecords.filter(item => item.type === 1 && item.data)) results.push(`${record.data}:${port}`);
	for (const record of aaaaRecords.filter(item => item.type === 28 && item.data)) results.push(`[${record.data}]:${port}`);
	return results;
}

function uniqueStrings(values) {
	const seen = new Set();
	return values.filter(value => {
		if (seen.has(value)) return false;
		seen.add(value);
		return true;
	});
}

function normalizeTxtValue(value) {
	const text = String(value ?? '').trim();
	if (text.startsWith('"') && text.endsWith('"')) return text.slice(1, -1).replace(/\\"/g, '"');
	return text.replace(/\\"/g, '"');
}

async function dohQuery(name, type, endpoint = 'https://cloudflare-dns.com/dns-query') {
	try {
		const response = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`, {
			headers: { accept: 'application/dns-json' }
		});
		if (!response.ok) return [];
		const payload = await response.json();
		if (!Array.isArray(payload.Answer)) return [];
		return payload.Answer.map(answer => ({
			name: answer.name || name,
			type: answer.type,
			TTL: answer.TTL,
			data: answer.type === 16 ? normalizeTxtValue(answer.data) : answer.data
		}));
	} catch (error) {
		return [];
	}
}

function generateHTML(备案内容) {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="color-scheme" content="light dark">
	<title>Check Socks5</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
	<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
	<script>
		(function () {
			const storageKey = 'cf_proxy_theme';
			let theme = 'dark';
			try {
				const storedTheme = localStorage.getItem(storageKey);
				if (storedTheme === 'light' || storedTheme === 'dark') {
					theme = storedTheme;
				} else {
					theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
				}
			} catch (error) {
				theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
			}
			document.documentElement.dataset.theme = theme;
			document.documentElement.style.colorScheme = theme;
		})();
	</script>
	<style>
		:root {
			--bg-base: #07111d;
			--bg-deep: #0b1726;
			--panel: rgba(10, 24, 40, 0.78);
			--panel-strong: rgba(15, 31, 49, 0.92);
			--line: rgba(144, 180, 212, 0.18);
			--text: #edf7ff;
			--text-soft: #d4e4f3;
			--muted: #8ea6bc;
			--accent: #61dbff;
			--accent-strong: #2dd4bf;
			--accent-warm: #ffb869;
			--success: #34d399;
			--error: #fb7185;
			--warning: #fbbf24;
			--shadow: 0 24px 80px rgba(0, 0, 0, 0.34);
			--shadow-soft: 0 16px 44px rgba(0, 0, 0, 0.26);
			--radius-xl: 30px;
			--radius-lg: 24px;
			--radius-md: 20px;
		}

		html {
			color-scheme: dark;
		}

		html[data-theme='light'] {
			color-scheme: light;
			--bg-base: #eef6fb;
			--bg-deep: #ffffff;
			--panel: rgba(255, 255, 255, 0.72);
			--panel-strong: rgba(255, 255, 255, 0.92);
			--line: rgba(95, 123, 150, 0.18);
			--text: #10253d;
			--text-soft: #23415a;
			--muted: #61778f;
			--accent: #0ea5e9;
			--accent-strong: #14b8a6;
			--accent-warm: #f59e0b;
			--success: #059669;
			--error: #e11d48;
			--warning: #d97706;
			--shadow: 0 24px 64px rgba(43, 67, 91, 0.14);
			--shadow-soft: 0 16px 34px rgba(43, 67, 91, 0.1);
		}

		* {
			box-sizing: border-box;
		}

		html, body {
			margin: 0;
			min-height: 100%;
		}

		body {
			font-family: 'Plus Jakarta Sans', system-ui, sans-serif;
			color: var(--text);
			background:
				radial-gradient(circle at top left, rgba(45, 212, 191, 0.18), transparent 28%),
				radial-gradient(circle at 85% 12%, rgba(97, 219, 255, 0.18), transparent 24%),
				radial-gradient(circle at 50% 110%, rgba(255, 184, 105, 0.16), transparent 30%),
				linear-gradient(180deg, #06101b 0%, #081321 38%, #0a1624 100%);
			overflow-x: hidden;
			transition: background 0.28s ease, color 0.28s ease;
		}

		body::before {
			content: '';
			position: fixed;
			inset: 0;
			pointer-events: none;
			background-image:
				linear-gradient(rgba(255, 255, 255, 0.035) 1px, transparent 1px),
				linear-gradient(90deg, rgba(255, 255, 255, 0.035) 1px, transparent 1px);
			background-size: 46px 46px;
			mask-image: linear-gradient(180deg, rgba(0, 0, 0, 0.38), transparent 92%);
			opacity: 0.12;
		}

		html[data-theme='light'] body {
			background:
				radial-gradient(circle at top left, rgba(20, 184, 166, 0.16), transparent 30%),
				radial-gradient(circle at 88% 12%, rgba(14, 165, 233, 0.14), transparent 24%),
				radial-gradient(circle at 50% 110%, rgba(245, 158, 11, 0.12), transparent 28%),
				linear-gradient(180deg, #f6fbff 0%, #eef5fb 44%, #e8f1f7 100%);
		}

		html[data-theme='light'] body::before {
			background-image:
				linear-gradient(rgba(16, 37, 61, 0.05) 1px, transparent 1px),
				linear-gradient(90deg, rgba(16, 37, 61, 0.05) 1px, transparent 1px);
			mask-image: linear-gradient(180deg, rgba(255, 255, 255, 0.68), transparent 92%);
			opacity: 0.28;
		}

		button,
		input,
		select,
		textarea {
			font: inherit;
		}

		body,
		.surface-card,
		.input-control,
		.history-toggle,
		.history-dropdown,
		.mode-card,
		.progress-container,
		.metric-card,
		.results-pill,
		.results-empty,
		.results-filters,
		.filter-toggle,
		.filter-panel,
		.filter-chip,
		.filter-empty,
		.empty-visual,
		.result-item,
		.status-badge,
		.meta-chip,
		.exit-ip-btn,
		.map-container-wrapper,
		.theme-toggle {
			transition: background 0.28s ease, border-color 0.28s ease, color 0.28s ease, box-shadow 0.28s ease, opacity 0.28s ease;
		}

		.page-shell {
			position: relative;
			min-height: 100vh;
			padding: 32px 24px 40px;
		}

		.ambient {
			position: fixed;
			border-radius: 999px;
			filter: blur(80px);
			pointer-events: none;
			z-index: 0;
			opacity: 0.28;
		}

		.ambient-one {
			width: 34rem;
			height: 34rem;
			left: -9rem;
			top: 10rem;
			background: rgba(97, 219, 255, 0.22);
		}

		.ambient-two {
			width: 28rem;
			height: 28rem;
			right: -6rem;
			top: -3rem;
			background: rgba(45, 212, 191, 0.18);
		}

		html[data-theme='light'] .ambient-one {
			background: rgba(56, 189, 248, 0.2);
		}

		html[data-theme='light'] .ambient-two {
			background: rgba(45, 212, 191, 0.16);
		}

		.site-header,
		.site-main,
		.site-footer {
			position: relative;
			z-index: 1;
			max-width: 1200px;
			margin: 0 auto;
		}

		.site-header {
			display: flex;
			justify-content: space-between;
			align-items: center;
			gap: 24px;
			margin-bottom: 24px;
		}

		.brand {
			display: flex;
			flex-direction: column;
			gap: 12px;
		}

		.brand-chip {
			display: inline-flex;
			align-items: center;
			justify-content: space-between;
			gap: 14px;
			align-self: flex-start;
			padding: 8px 10px 8px 14px;
			border-radius: 999px;
			border: 1px solid rgba(97, 219, 255, 0.16);
			background: rgba(12, 26, 43, 0.66);
			color: #bfeeff;
			font-size: 0.78rem;
			letter-spacing: 0.08em;
			text-transform: uppercase;
			backdrop-filter: blur(12px);
		}

		.brand-chip-text {
			display: inline-flex;
			align-items: center;
			gap: 10px;
			min-width: 0;
		}

		.brand-dot {
			width: 8px;
			height: 8px;
			border-radius: 50%;
			background: linear-gradient(135deg, var(--accent), var(--accent-strong));
			box-shadow: 0 0 18px rgba(97, 219, 255, 0.7);
		}

		.brand-title {
			font-family: 'Space Grotesk', 'Plus Jakarta Sans', sans-serif;
			font-size: clamp(1.7rem, 4vw, 2.75rem);
			font-weight: 700;
			line-height: 0.98;
			letter-spacing: -0.04em;
			text-transform: uppercase;
			color: #f7fbff;
			text-wrap: balance;
		}

		.header-note {
			max-width: 420px;
			color: var(--muted);
			line-height: 1.7;
			text-align: right;
			flex: 0 1 420px;
		}

		.theme-toggle {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			padding: 0;
			border: none;
			border-radius: 0;
			background: transparent;
			color: var(--text);
			box-shadow: none;
			backdrop-filter: none;
			cursor: pointer;
			min-width: 0;
			transition: color 0.28s ease;
		}

		.theme-toggle:hover {
			transform: none;
		}

		.theme-toggle:focus-visible {
			outline: none;
		}

		.theme-toggle-switch {
			position: relative;
			width: 56px;
			height: 30px;
			flex: none;
			border-radius: 999px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background: linear-gradient(135deg, rgba(97, 219, 255, 0.18), rgba(45, 212, 191, 0.12));
			box-shadow: 0 10px 24px rgba(0, 0, 0, 0.18);
			transition: transform 0.2s ease, background 0.28s ease, border-color 0.28s ease, box-shadow 0.28s ease;
		}

		.theme-toggle:hover .theme-toggle-switch {
			transform: translateY(-1px);
			border-color: rgba(97, 219, 255, 0.2);
			box-shadow: 0 12px 28px rgba(0, 0, 0, 0.22);
		}

		.theme-toggle:focus-visible .theme-toggle-switch {
			box-shadow: 0 0 0 4px rgba(97, 219, 255, 0.12), 0 10px 24px rgba(0, 0, 0, 0.18);
		}

		.theme-toggle-icon {
			position: absolute;
			top: 9px;
			width: 12px;
			height: 12px;
			color: rgba(255, 255, 255, 0.72);
			pointer-events: none;
		}

		.theme-toggle-icon-light {
			left: 8px;
			color: #ffd97d;
		}

		.theme-toggle-icon-dark {
			right: 8px;
			color: #d9efff;
		}

		.theme-toggle-thumb {
			position: absolute;
			top: 3px;
			left: 3px;
			width: 22px;
			height: 22px;
			border-radius: 50%;
			background: linear-gradient(135deg, #ffffff, #d9e9f7);
			box-shadow: 0 6px 14px rgba(0, 0, 0, 0.24);
			transform: translateX(28px);
			transition: transform 0.28s ease, background 0.28s ease, box-shadow 0.28s ease;
		}

		html[data-theme='light'] .theme-toggle-thumb {
			transform: translateX(0);
			background: linear-gradient(135deg, #fff9d9, #ffd88a);
			box-shadow: 0 8px 16px rgba(168, 116, 23, 0.18);
		}

		html[data-theme='light'] .theme-toggle-switch {
			border-color: rgba(84, 112, 139, 0.14);
			background: linear-gradient(135deg, rgba(254, 240, 138, 0.56), rgba(125, 211, 252, 0.34));
		}

		html[data-theme='light'] .theme-toggle-icon {
			color: #53708d;
		}

		html[data-theme='light'] .theme-toggle-icon-light {
			color: #d97706;
		}

		html[data-theme='light'] .theme-toggle-icon-dark {
			color: #2563eb;
		}

		.surface-card {
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.03), transparent 36%),
				var(--panel);
			border: 1px solid var(--line);
			border-radius: var(--radius-xl);
			box-shadow: var(--shadow);
			backdrop-filter: blur(18px);
		}

		.section-kicker {
			display: inline-flex;
			align-items: center;
			gap: 10px;
			margin: 0 0 18px;
			font-size: 0.82rem;
			letter-spacing: 0.14em;
			text-transform: uppercase;
			color: #9feaff;
		}

		.section-kicker::before {
			content: '';
			width: 26px;
			height: 1px;
			background: linear-gradient(90deg, transparent, rgba(97, 219, 255, 0.85));
		}

		.panel-copy,
		.field-hint,
		.summary-description,
		.results-subtitle,
		.empty-copy p,
		.site-footer {
			color: var(--muted);
			line-height: 1.8;
		}

		.summary-description,
		.empty-copy p {
			margin: 0;
		}

		.workspace-grid {
			display: grid;
			grid-template-columns: minmax(0, 1.55fr) minmax(320px, 0.9fr);
			gap: 24px;
			align-items: stretch;
			margin-top: 0;
			position: relative;
			z-index: 4;
		}

		.control-panel {
			padding: 30px;
			display: flex;
			flex-direction: column;
			min-height: 100%;
			position: relative;
			z-index: 5;
		}

		.panel-header,
		.results-header {
			display: flex;
			justify-content: space-between;
			align-items: flex-start;
			gap: 20px;
		}

		.panel-title,
		.summary-title,
		.results-title,
		.empty-copy h3 {
			margin: 0;
			font-size: 1.45rem;
			font-weight: 700;
			letter-spacing: -0.02em;
		}

		.panel-copy {
			margin: 10px 0 0;
			max-width: 58ch;
		}

		.panel-badge {
			padding: 10px 14px;
			border-radius: 999px;
			background: rgba(97, 219, 255, 0.08);
			border: 1px solid rgba(97, 219, 255, 0.16);
			color: #c6f5ff;
			font-size: 0.82rem;
			white-space: nowrap;
		}

		.input-zone {
			margin-top: 24px;
		}

		.field-label {
			display: block;
			margin-bottom: 12px;
			font-size: 0.9rem;
			font-weight: 600;
			color: #d9efff;
		}

		.input-wrapper {
			position: relative;
		}

		.input-control {
			width: 100%;
			padding: 18px 64px 18px 20px;
			border: 1px solid var(--line);
			border-radius: 22px;
			background: rgba(4, 14, 24, 0.52);
			color: var(--text);
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
			transition: border-color 0.24s ease, box-shadow 0.24s ease, background 0.24s ease;
		}

		.input-control::placeholder {
			color: #7390a9;
		}

		.input-control:focus {
			outline: none;
			background: rgba(5, 18, 29, 0.74);
			border-color: rgba(97, 219, 255, 0.34);
			box-shadow: 0 0 0 4px rgba(97, 219, 255, 0.08);
		}

		textarea.input-control {
			min-height: 188px;
			resize: vertical;
			padding-right: 20px;
			line-height: 1.75;
		}

		.field-hint {
			margin: 12px 0 0;
			font-size: 0.9rem;
		}

		.history-toggle {
			position: absolute;
			right: 16px;
			top: 50%;
			transform: translateY(-50%);
			display: inline-flex;
			align-items: center;
			justify-content: center;
			width: 38px;
			height: 38px;
			border-radius: 14px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background: rgba(255, 255, 255, 0.03);
			color: #b1c7db;
			cursor: pointer;
			transition: background 0.2s ease, color 0.2s ease, transform 0.2s ease;
		}

		.history-toggle:hover {
			color: #f7fbff;
			background: rgba(97, 219, 255, 0.08);
			transform: translateY(calc(-50% - 1px));
		}

		.history-dropdown {
			position: absolute;
			top: calc(100% + 10px);
			left: 0;
			right: 0;
			display: none;
			padding: 8px;
			border-radius: 20px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background: rgba(8, 19, 32, 0.96);
			box-shadow: 0 18px 42px rgba(0, 0, 0, 0.42);
			max-height: 280px;
			overflow-y: auto;
			z-index: 80;
		}

		.history-item {
			width: 100%;
			padding: 13px 14px;
			border: none;
			background: transparent;
			border-radius: 14px;
			color: var(--text-soft);
			text-align: left;
			cursor: pointer;
			transition: background 0.2s ease, color 0.2s ease;
		}

		.history-item:hover {
			background: rgba(97, 219, 255, 0.08);
			color: #ffffff;
		}

		.history-item.is-empty {
			color: #69839a;
			cursor: default;
		}

		.control-row {
			display: flex;
			gap: 16px;
			align-items: stretch;
			margin-top: 18px;
		}

		.mode-card {
			min-width: 238px;
			display: flex;
			align-items: center;
			justify-content: space-between;
			gap: 16px;
			padding: 18px 18px 18px 20px;
			border-radius: 22px;
			background: rgba(255, 255, 255, 0.03);
			border: 1px solid rgba(255, 255, 255, 0.07);
		}

		.mode-copy strong {
			display: block;
			margin-bottom: 6px;
			font-size: 0.98rem;
		}

		.mode-state {
			font-size: 0.88rem;
			color: var(--muted);
		}

		.switch {
			position: relative;
			display: inline-block;
			width: 54px;
			height: 30px;
			flex: none;
		}

		.switch input {
			opacity: 0;
			width: 0;
			height: 0;
		}

		.slider {
			position: absolute;
			inset: 0;
			cursor: pointer;
			border-radius: 999px;
			background: rgba(255, 255, 255, 0.12);
			border: 1px solid rgba(255, 255, 255, 0.08);
			transition: 0.28s ease;
		}

		.slider::before {
			content: '';
			position: absolute;
			width: 22px;
			height: 22px;
			left: 3px;
			top: 3px;
			border-radius: 50%;
			background: #ffffff;
			box-shadow: 0 6px 18px rgba(0, 0, 0, 0.24);
			transition: 0.28s ease;
		}

		.switch input:checked + .slider {
			background: linear-gradient(135deg, rgba(97, 219, 255, 0.92), rgba(45, 212, 191, 0.84));
			border-color: transparent;
		}

		.switch input:checked + .slider::before {
			transform: translateX(24px);
		}

		.primary-btn {
			flex: 1;
			display: flex;
			flex-direction: column;
			align-items: center;
			justify-content: center;
			gap: 4px;
			border: none;
			padding: 16px 20px;
			border-radius: 22px;
			background: linear-gradient(135deg, var(--accent), #8cf2ff 52%, var(--accent-warm));
			color: #052538;
			font-weight: 800;
			cursor: pointer;
			box-shadow: 0 18px 34px rgba(97, 219, 255, 0.28);
			transition: transform 0.2s ease, box-shadow 0.2s ease, opacity 0.2s ease;
		}

		.primary-btn small {
			color: rgba(5, 37, 56, 0.78);
			font-size: 0.8rem;
			font-weight: 700;
			letter-spacing: 0.06em;
			text-transform: uppercase;
		}

		.primary-btn:hover {
			transform: translateY(-2px);
			box-shadow: 0 24px 42px rgba(97, 219, 255, 0.34);
		}

		.primary-btn.is-stop {
			background: linear-gradient(135deg, #ef4444, #fb7185);
			color: #fff7f7;
			box-shadow: 0 18px 34px rgba(239, 68, 68, 0.28);
		}

		.primary-btn.is-stop small {
			color: rgba(255, 247, 247, 0.78);
		}

		.primary-btn.is-stop:hover {
			box-shadow: 0 24px 42px rgba(239, 68, 68, 0.34);
		}

		.primary-btn:disabled {
			cursor: wait;
			transform: none;
			opacity: 0.74;
			box-shadow: 0 14px 26px rgba(97, 219, 255, 0.18);
		}

		.progress-container {
			display: grid;
			gap: 10px;
			margin-top: 18px;
			padding: 16px;
			border-radius: 22px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.035), rgba(255, 255, 255, 0.015)),
				rgba(255, 255, 255, 0.03);
		}

		.progress-head {
			display: flex;
			justify-content: space-between;
			align-items: center;
			gap: 12px;
			font-size: 0.92rem;
			color: var(--text-soft);
		}

		.progress-track {
			position: relative;
			height: 12px;
			border-radius: 999px;
			overflow: hidden;
			background: rgba(255, 255, 255, 0.08);
		}

		.progress-bar {
			width: 0%;
			height: 100%;
			border-radius: inherit;
			background: linear-gradient(90deg, var(--accent), var(--accent-strong), var(--accent-warm));
			transition: width 0.32s ease;
		}

		.side-column {
			display: grid;
			gap: 24px;
			min-height: 100%;
		}

		.side-card {
			padding: 26px;
			min-height: 100%;
		}

		.summary-description {
			margin-top: 10px;
		}

		.summary-grid {
			display: grid;
			grid-template-columns: repeat(2, minmax(0, 1fr));
			gap: 12px;
			margin-top: 14px;
		}

		.metric-card {
			padding: 16px;
			border-radius: 18px;
			background: rgba(255, 255, 255, 0.03);
			border: 1px solid rgba(255, 255, 255, 0.06);
		}

		.metric-card span {
			display: block;
			margin-bottom: 6px;
			font-size: 0.82rem;
			color: var(--muted);
		}

		.metric-card strong {
			font-family: 'Space Grotesk', 'Plus Jakarta Sans', sans-serif;
			font-size: 1.65rem;
			letter-spacing: -0.04em;
		}

		.results-shell {
			margin-top: 24px;
			padding: 28px;
			position: relative;
			z-index: 1;
		}

		.results-subtitle {
			margin: 10px 0 0;
		}

		.results-pill {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			padding: 10px 14px;
			border-radius: 999px;
			font-size: 0.82rem;
			font-weight: 700;
			border: 1px solid rgba(255, 255, 255, 0.1);
			background: rgba(255, 255, 255, 0.04);
			color: #e8f5ff;
			white-space: nowrap;
		}

		.results-pill.state-idle {
			color: #d5e6f6;
		}

		.results-pill.state-resolving {
			background: rgba(251, 191, 36, 0.12);
			border-color: rgba(251, 191, 36, 0.22);
			color: #ffd97d;
		}

		.results-pill.state-running {
			background: rgba(97, 219, 255, 0.12);
			border-color: rgba(97, 219, 255, 0.24);
			color: #bff4ff;
		}

		.results-pill.state-done {
			background: rgba(52, 211, 153, 0.12);
			border-color: rgba(52, 211, 153, 0.24);
			color: #abffd8;
		}

		.results-pill.state-empty,
		.results-pill.state-error,
		.results-pill.state-stopped {
			background: rgba(251, 113, 133, 0.1);
			border-color: rgba(251, 113, 133, 0.22);
			color: #ffc4d0;
		}

		.results-empty {
			display: grid;
			grid-template-columns: auto 1fr;
			gap: 18px;
			align-items: center;
			padding: 24px;
			margin-top: 22px;
			margin-bottom: 18px;
			border-radius: 24px;
			border: 1px dashed rgba(144, 180, 212, 0.22);
			background: rgba(255, 255, 255, 0.025);
		}

		.results-filters[hidden],
		.filter-panel[hidden],
		.export-toast[hidden],
		.filter-empty[hidden] {
			display: none;
		}

		.results-filters {
			display: grid;
			gap: 12px;
			margin-top: 22px;
			margin-bottom: 18px;
		}

		.filter-toggle {
			display: flex;
			align-items: center;
			justify-content: space-between;
			gap: 12px;
			width: 100%;
			min-height: 44px;
			padding: 10px 14px;
			border-radius: 18px;
			border: 1px solid rgba(255, 255, 255, 0.1);
			background: rgba(255, 255, 255, 0.04);
			color: var(--text-soft);
			font-weight: 800;
			cursor: pointer;
			text-align: left;
		}

		.filter-toggle:hover {
			border-color: rgba(97, 219, 255, 0.28);
			background: rgba(97, 219, 255, 0.08);
			color: #ffffff;
		}

		.filter-toggle-icon {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			width: 18px;
			height: 18px;
			flex: none;
		}

		.filter-toggle-icon svg {
			display: block;
			width: 12px;
			height: 12px;
			overflow: visible;
			transform-origin: 50% 50%;
			transition: transform 0.2s ease;
		}

		.filter-toggle[aria-expanded='true'] .filter-toggle-icon svg {
			transform: rotate(180deg);
		}

		.filter-panel {
			display: grid;
			gap: 12px;
		}

		.filter-row {
			display: grid;
			grid-template-columns: max-content minmax(0, 1fr);
			gap: 10px;
			align-items: start;
		}

		.filter-row-label {
			color: var(--muted);
			font-size: 0.84rem;
			font-weight: 700;
			letter-spacing: 0.04em;
			line-height: 40px;
			white-space: nowrap;
		}

		.filter-options {
			display: flex;
			flex-wrap: wrap;
			gap: 10px;
			min-width: 0;
		}

		.filter-chip {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			min-height: 40px;
			padding: 9px 14px;
			border-radius: 999px;
			border: 1px solid rgba(255, 255, 255, 0.1);
			background: rgba(255, 255, 255, 0.04);
			color: var(--text-soft);
			font-size: 0.86rem;
			font-weight: 700;
			white-space: nowrap;
			cursor: pointer;
		}

		.filter-chip:hover {
			border-color: rgba(97, 219, 255, 0.28);
			background: rgba(97, 219, 255, 0.1);
			color: #ffffff;
		}

		.filter-chip.is-active {
			border-color: rgba(97, 219, 255, 0.46);
			background: linear-gradient(135deg, rgba(97, 219, 255, 0.22), rgba(52, 211, 153, 0.14));
			color: #ffffff;
			box-shadow: inset 0 0 0 1px rgba(97, 219, 255, 0.12);
		}

		.filter-chip-risk,
		.meta-chip-risk {
			border-color: var(--risk-border);
			background: var(--risk-bg);
			color: var(--risk-color);
		}

		.filter-chip-risk:hover,
		.filter-chip-risk.is-active {
			border-color: var(--risk-active-border);
			background: var(--risk-active-bg);
			color: var(--risk-active-color);
			box-shadow: inset 0 0 0 1px var(--risk-shadow);
		}

		.filter-chip-risk.risk-verylow,
		.meta-chip-risk.risk-verylow {
			--risk-border: rgba(16, 185, 129, 0.3);
			--risk-bg: rgba(16, 185, 129, 0.12);
			--risk-color: #7ef0c4;
			--risk-active-border: rgba(16, 185, 129, 0.58);
			--risk-active-bg: linear-gradient(135deg, rgba(16, 185, 129, 0.34), rgba(52, 211, 153, 0.2));
			--risk-active-color: #ffffff;
			--risk-shadow: rgba(16, 185, 129, 0.18);
		}

		.filter-chip-risk.risk-low,
		.meta-chip-risk.risk-low {
			--risk-border: rgba(45, 212, 191, 0.28);
			--risk-bg: rgba(45, 212, 191, 0.1);
			--risk-color: #99f6e4;
			--risk-active-border: rgba(45, 212, 191, 0.54);
			--risk-active-bg: linear-gradient(135deg, rgba(45, 212, 191, 0.3), rgba(14, 165, 233, 0.16));
			--risk-active-color: #ffffff;
			--risk-shadow: rgba(45, 212, 191, 0.16);
		}

		.filter-chip-risk.risk-elevated,
		.meta-chip-risk.risk-elevated {
			--risk-border: rgba(234, 179, 8, 0.34);
			--risk-bg: rgba(234, 179, 8, 0.12);
			--risk-color: #fde68a;
			--risk-active-border: rgba(234, 179, 8, 0.62);
			--risk-active-bg: linear-gradient(135deg, rgba(234, 179, 8, 0.36), rgba(245, 158, 11, 0.2));
			--risk-active-color: #fffbe6;
			--risk-shadow: rgba(234, 179, 8, 0.18);
		}

		.filter-chip-risk.risk-high,
		.meta-chip-risk.risk-high {
			--risk-border: rgba(249, 115, 22, 0.38);
			--risk-bg: rgba(249, 115, 22, 0.14);
			--risk-color: #fed7aa;
			--risk-active-border: rgba(249, 115, 22, 0.66);
			--risk-active-bg: linear-gradient(135deg, rgba(249, 115, 22, 0.42), rgba(239, 68, 68, 0.22));
			--risk-active-color: #ffffff;
			--risk-shadow: rgba(249, 115, 22, 0.18);
		}

		.filter-chip-risk.risk-critical,
		.meta-chip-risk.risk-critical {
			--risk-border: rgba(239, 68, 68, 0.42);
			--risk-bg: rgba(239, 68, 68, 0.16);
			--risk-color: #fecaca;
			--risk-active-border: rgba(239, 68, 68, 0.72);
			--risk-active-bg: linear-gradient(135deg, rgba(239, 68, 68, 0.48), rgba(190, 18, 60, 0.28));
			--risk-active-color: #ffffff;
			--risk-shadow: rgba(239, 68, 68, 0.2);
		}

		.export-chip {
			border-color: rgba(251, 191, 36, 0.28);
			background: linear-gradient(135deg, rgba(251, 191, 36, 0.18), rgba(255, 184, 105, 0.12));
			color: #ffe7a7;
		}

		.export-chip:hover {
			border-color: rgba(251, 191, 36, 0.48);
			background: linear-gradient(135deg, rgba(251, 191, 36, 0.26), rgba(255, 184, 105, 0.18));
			color: #fff4cf;
		}

		.filter-chip:disabled,
		.filter-chip.is-disabled {
			border-color: rgba(144, 180, 212, 0.1);
			background: rgba(255, 255, 255, 0.025);
			color: rgba(142, 166, 188, 0.46);
			box-shadow: none;
			cursor: not-allowed;
			opacity: 0.72;
			pointer-events: none;
		}

		.export-toast {
			position: fixed;
			left: 50%;
			bottom: 28px;
			z-index: 10000;
			max-width: min(420px, calc(100vw - 32px));
			padding: 12px 16px;
			border-radius: 999px;
			border: 1px solid rgba(97, 219, 255, 0.26);
			background: rgba(5, 18, 32, 0.94);
			box-shadow: 0 18px 44px rgba(0, 0, 0, 0.34);
			color: #e8fbff;
			font-size: 0.9rem;
			font-weight: 800;
			text-align: center;
			transform: translate(-50%, 12px);
			opacity: 0;
			pointer-events: none;
			transition: opacity 0.22s ease, transform 0.22s ease;
		}

		.export-toast.is-visible {
			opacity: 1;
			transform: translate(-50%, 0);
		}

		.export-toast.is-error {
			border-color: rgba(251, 113, 133, 0.34);
			color: #ffd1d8;
		}

		.filter-empty {
			padding: 16px 18px;
			margin-bottom: 18px;
			border-radius: 18px;
			border: 1px dashed rgba(144, 180, 212, 0.22);
			background: rgba(255, 255, 255, 0.025);
			color: var(--muted);
			font-size: 0.92rem;
			line-height: 1.7;
		}

		.empty-visual {
			position: relative;
			width: 90px;
			height: 90px;
			border-radius: 26px;
			background:
				radial-gradient(circle at 30% 30%, rgba(97, 219, 255, 0.26), transparent 42%),
				linear-gradient(160deg, rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0.015));
			border: 1px solid rgba(255, 255, 255, 0.06);
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
		}

		.empty-visual span {
			position: absolute;
			border-radius: 999px;
		}

		.empty-visual span:nth-child(1) {
			width: 44px;
			height: 44px;
			left: 10px;
			top: 14px;
			background: rgba(97, 219, 255, 0.24);
		}

		.empty-visual span:nth-child(2) {
			width: 18px;
			height: 18px;
			right: 18px;
			top: 18px;
			background: rgba(45, 212, 191, 0.48);
		}

		.empty-visual span:nth-child(3) {
			width: 56px;
			height: 10px;
			left: 18px;
			bottom: 18px;
			background: rgba(255, 255, 255, 0.12);
		}

		.results-list {
			display: grid;
			gap: 16px;
		}

		.result-item {
			position: relative;
			overflow: hidden;
			padding: 20px 22px;
			border-radius: 26px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.03), transparent 38%),
				var(--panel-strong);
			box-shadow: var(--shadow-soft);
		}

		.result-item > * {
			position: relative;
			z-index: 1;
		}

		.result-item::before {
			content: '';
			position: absolute;
			top: 0;
			left: 0;
			bottom: 0;
			width: 4px;
			background: rgba(147, 168, 189, 0.5);
		}

		.result-item.success::before {
			background: linear-gradient(180deg, #34d399, #10b981);
		}

		.result-item.error::before {
			background: linear-gradient(180deg, #fb7185, #ef4444);
		}

		.result-flag-overlay {
			position: absolute;
			top: 58px;
			right: -16px;
			width: 168px;
			height: 112px;
			border-radius: 28px;
			background-position: center;
			background-repeat: no-repeat;
			background-size: cover;
			opacity: 0;
			filter: blur(13px) saturate(1.08);
			transform: rotate(7deg) scale(1.18);
			transform-origin: top right;
			pointer-events: none;
			z-index: 0;
			transition: opacity 0.24s ease;
		}

		.result-item.success.has-flag .result-flag-overlay {
			opacity: 0.22;
		}

		.result-top {
			display: flex;
			justify-content: space-between;
			align-items: flex-start;
			gap: 16px;
		}

		.result-info {
			display: flex;
			flex-direction: column;
			gap: 6px;
			min-width: 0;
		}

		.result-label {
			font-size: 0.74rem;
			letter-spacing: 0.14em;
			text-transform: uppercase;
			color: var(--muted);
		}

		.result-ip {
			font-family: 'Space Grotesk', 'Plus Jakarta Sans', monospace;
			font-size: 1.08rem;
			font-weight: 700;
			word-break: break-word;
		}

		.copy-target {
			align-self: flex-start;
			margin: 0;
			padding: 0;
			border: 0;
			background: transparent;
			color: var(--text);
			text-align: left;
			cursor: pointer;
			transition: color 0.18s ease, text-shadow 0.18s ease;
		}

		.copy-target:hover,
		.copy-target:focus-visible {
			color: #8be9ff;
			text-shadow: 0 0 18px rgba(97, 219, 255, 0.28);
		}

		.copy-target:focus-visible {
			outline: 2px solid rgba(97, 219, 255, 0.48);
			outline-offset: 4px;
			border-radius: 6px;
		}

		.result-detail {
			color: var(--muted);
			font-size: 0.94rem;
			line-height: 1.75;
		}

		.result-detail.is-compact {
			font-size: 0.88rem;
		}

		.status-badge {
			position: relative;
			display: inline-flex;
			align-items: center;
			justify-content: center;
			min-width: 78px;
			padding: 10px 14px;
			border-radius: 999px;
			border: 1px solid rgba(255, 255, 255, 0.1);
			background: rgba(255, 255, 255, 0.04);
			font-size: 0.82rem;
			font-weight: 700;
			color: #eef8ff;
			white-space: nowrap;
		}

		.status-badge[data-tooltip]::before,
		.status-badge[data-tooltip]::after {
			position: absolute;
			right: 0;
			opacity: 0;
			pointer-events: none;
			transform: translateY(-4px);
			transition: opacity 0.18s ease, transform 0.18s ease;
			z-index: 20;
		}

		.status-badge[data-tooltip] {
			cursor: help;
		}

		.status-badge[data-tooltip]::before {
			content: '';
			top: calc(100% + 6px);
			width: 10px;
			height: 10px;
			margin-right: 18px;
			background: rgba(5, 18, 32, 0.96);
			border-left: 1px solid rgba(255, 255, 255, 0.12);
			border-top: 1px solid rgba(255, 255, 255, 0.12);
			transform: translateY(-4px) rotate(45deg);
		}

		.status-badge[data-tooltip]::after {
			content: attr(data-tooltip);
			top: calc(100% + 10px);
			width: max-content;
			max-width: min(320px, calc(100vw - 44px));
			padding: 10px 12px;
			border-radius: 14px;
			border: 1px solid rgba(255, 255, 255, 0.12);
			background: rgba(5, 18, 32, 0.96);
			box-shadow: 0 16px 36px rgba(0, 0, 0, 0.28);
			color: #edf7ff;
			font-size: 0.78rem;
			font-weight: 600;
			line-height: 1.55;
			text-align: left;
			white-space: normal;
		}

		.status-badge[data-tooltip]:hover::before,
		.status-badge[data-tooltip]:hover::after,
		.status-badge[data-tooltip]:focus-visible::before,
		.status-badge[data-tooltip]:focus-visible::after {
			opacity: 1;
		}

		.status-badge[data-tooltip]:hover::before,
		.status-badge[data-tooltip]:focus-visible::before {
			transform: translateY(0) rotate(45deg);
		}

		.status-badge[data-tooltip]:hover::after,
		.status-badge[data-tooltip]:focus-visible::after {
			transform: translateY(0);
		}

		.status-success {
			background: rgba(52, 211, 153, 0.12);
			border-color: rgba(52, 211, 153, 0.24);
			color: #a5f3cf;
		}

		.status-error {
			background: rgba(251, 113, 133, 0.12);
			border-color: rgba(251, 113, 133, 0.24);
			color: #fecdd7;
		}

		.status-pending {
			background: rgba(251, 191, 36, 0.12);
			border-color: rgba(251, 191, 36, 0.22);
			color: #fde68a;
		}

		.result-meta {
			display: flex;
			flex-wrap: wrap;
			gap: 10px;
			margin-top: 14px;
		}

		.meta-chip {
			display: inline-flex;
			align-items: center;
			gap: 8px;
			padding: 8px 12px;
			border-radius: 999px;
			background: rgba(97, 219, 255, 0.07);
			border: 1px solid rgba(97, 219, 255, 0.12);
			color: var(--text-soft);
			font-size: 0.82rem;
		}

		.meta-chip svg {
			width: 14px;
			height: 14px;
			flex: none;
			opacity: 0.92;
		}

		.meta-chip-strong {
			background: rgba(97, 219, 255, 0.12);
			border-color: rgba(97, 219, 255, 0.22);
			color: #dff9ff;
		}

		.meta-chip-danger {
			background: rgba(251, 113, 133, 0.1);
			border-color: rgba(251, 113, 133, 0.22);
			color: #ffd1d8;
		}

		.meta-chip.meta-chip-risk {
			border-color: var(--risk-border);
			background: var(--risk-bg);
			color: var(--risk-color);
		}

		.exit-list {
			display: flex;
			flex-wrap: wrap;
			gap: 10px;
			margin-top: 14px;
			align-items: center;
		}

		.exit-list-label {
			color: var(--muted);
			font-size: 0.84rem;
		}

		.exit-ip-btn {
			border: 1px solid rgba(52, 211, 153, 0.22);
			border-radius: 999px;
			padding: 10px 14px;
			background: linear-gradient(135deg, rgba(52, 211, 153, 0.14), rgba(97, 219, 255, 0.08));
			color: var(--text);
			font-weight: 700;
			cursor: pointer;
			transition: transform 0.2s ease, border-color 0.2s ease, background 0.2s ease;
		}

		.exit-ip-btn:hover {
			transform: translateY(-1px);
			border-color: rgba(97, 219, 255, 0.32);
			background: linear-gradient(135deg, rgba(52, 211, 153, 0.18), rgba(97, 219, 255, 0.12));
		}

		.exit-ip-btn.is-active {
			border-color: rgba(97, 219, 255, 0.52);
			background: linear-gradient(135deg, rgba(97, 219, 255, 0.26), rgba(52, 211, 153, 0.16));
			box-shadow: inset 0 0 0 1px rgba(97, 219, 255, 0.14), 0 0 0 1px rgba(97, 219, 255, 0.1);
		}

		.map-container-wrapper {
			display: none;
			margin-top: 16px;
			border-radius: 22px;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background: rgba(255, 255, 255, 0.03);
			padding: 18px;
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
		}

		.map-detail-map-panel {
			height: 330px;
			border-radius: 18px;
			overflow: hidden;
			border: 1px solid rgba(255, 255, 255, 0.08);
			background: rgba(5, 12, 22, 0.72);
		}

		.map-detail-map-slot {
			width: 100%;
			height: 100%;
		}

		.exit-detail-grid {
			display: grid;
			grid-template-columns: repeat(2, minmax(0, 1fr));
			gap: 16px;
			margin-top: 16px;
		}

		.exit-detail-card {
			min-width: 0;
			padding: 18px;
			border-radius: 18px;
			border: 1px solid rgba(255, 255, 255, 0.07);
			background: linear-gradient(180deg, rgba(12, 26, 42, 0.7), rgba(8, 18, 32, 0.82));
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.035);
		}

		.exit-detail-section-title {
			margin: 0 0 14px;
			font-size: 0.78rem;
			font-weight: 800;
			letter-spacing: 0.12em;
			text-transform: uppercase;
			color: var(--accent-warm);
		}

		.exit-detail-list,
		.exit-detail-security-grid {
			display: grid;
			gap: 0 18px;
		}

		.exit-detail-security-grid {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}

		.exit-detail-item {
			display: flex;
			align-items: flex-start;
			justify-content: space-between;
			gap: 16px;
			padding: 10px 0;
			min-width: 0;
		}

		.exit-detail-item:not(:last-child) {
			border-bottom: 1px dashed rgba(144, 180, 212, 0.14);
		}

		.exit-detail-label {
			flex: 0 0 auto;
			color: var(--muted);
			font-size: 0.84rem;
			font-weight: 600;
		}

		.exit-detail-value {
			min-width: 0;
			color: var(--text);
			font-size: 0.86rem;
			font-weight: 700;
			line-height: 1.6;
			text-align: right;
			word-break: break-word;
		}

		.exit-risk-badge,
		.exit-detail-state {
			display: inline-flex;
			align-items: center;
			justify-content: center;
			padding: 4px 10px;
			border-radius: 999px;
			font-size: 0.76rem;
			font-weight: 800;
			letter-spacing: 0.01em;
			border: 1px solid transparent;
			white-space: nowrap;
		}

		.exit-risk-badge {
			max-width: 100%;
			text-align: center;
			white-space: normal;
		}

		.exit-risk-badge.is-info {
			background: rgba(14, 165, 233, 0.16);
			border-color: rgba(14, 165, 233, 0.26);
			color: #9de2ff;
		}

		.exit-risk-badge.is-critical {
			background: #ef4444;
			color: #ffffff;
		}

		.exit-risk-badge.is-high {
			background: #f97316;
			color: #ffffff;
		}

		.exit-risk-badge.is-elevated {
			background: #eab308;
			color: #2f2403;
		}

		.exit-risk-badge.is-low {
			background: rgba(16, 185, 129, 0.14);
			border-color: rgba(16, 185, 129, 0.3);
			color: #7ef0c4;
		}

		.exit-risk-badge.is-verylow {
			background: #10b981;
			color: #ffffff;
		}

		.exit-detail-state.is-safe {
			color: #7ef0c4;
			background: rgba(16, 185, 129, 0.12);
			border-color: rgba(16, 185, 129, 0.22);
		}

		.exit-detail-state.is-neutral {
			color: var(--text);
			background: rgba(255, 255, 255, 0.04);
			border-color: rgba(255, 255, 255, 0.1);
		}

		.exit-detail-state.is-danger {
			color: #ffd2d8;
			background: rgba(239, 68, 68, 0.12);
			border-color: rgba(239, 68, 68, 0.22);
		}

		.exit-detail-state.is-warn {
			color: #ffd59a;
			background: rgba(245, 158, 11, 0.12);
			border-color: rgba(245, 158, 11, 0.22);
		}

		.exit-detail-state.is-info {
			color: #9de2ff;
			background: rgba(14, 165, 233, 0.12);
			border-color: rgba(14, 165, 233, 0.22);
		}

		#map-template {
			display: none;
		}

		#global-map {
			width: 100%;
			height: 100%;
			background: #09111d;
		}

		#global-map .leaflet-tile-pane {
			filter: invert(1) hue-rotate(180deg) brightness(0.92) contrast(0.96) saturate(0.88);
		}

		.map-popup {
			font-family: 'Plus Jakarta Sans', system-ui, sans-serif;
			font-size: 0.88rem;
			line-height: 1.65;
			color: #10253d;
		}

		.map-popup b {
			color: #081826;
		}

		.red-location-marker {
			background: transparent;
			border: 0;
		}

		.red-location-pin {
			position: absolute;
			left: 50%;
			top: 0;
			width: 28px;
			height: 28px;
			border: 2px solid #ffffff;
			border-radius: 50% 50% 50% 0;
			background: #ef4444;
			box-shadow: 0 10px 24px rgba(127, 29, 29, 0.34);
			transform: translateX(-50%) rotate(-45deg);
		}

		.red-location-pin::after {
			content: '';
			position: absolute;
			width: 9px;
			height: 9px;
			left: 50%;
			top: 50%;
			border-radius: 999px;
			background: #ffffff;
			transform: translate(-50%, -50%);
		}

		.leaflet-control-zoom {
			display: none !important;
		}

		.leaflet-control-attribution {
			display: block !important;
			margin: 0 !important;
			padding: 4px 8px !important;
			border-radius: 12px 0 0 0;
			background: rgba(9, 17, 29, 0.78) !important;
			backdrop-filter: blur(10px);
			box-shadow: 0 10px 24px rgba(3, 7, 18, 0.22);
			color: rgba(223, 240, 255, 0.84) !important;
			font-size: 11px;
			line-height: 1.4;
		}

		.leaflet-control-attribution a {
			color: inherit !important;
		}

		.site-footer {
			padding-top: 22px;
			font-size: 0.9rem;
		}

		.site-footer a,
		#visit-count {
			color: #bff4ff;
			font-family: 'Space Grotesk', 'Plus Jakarta Sans', sans-serif;
			font-weight: 600;
			letter-spacing: -0.02em;
			font-variant-numeric: tabular-nums;
		}

		.site-footer a {
			text-decoration: none;
			border-bottom: 1px solid rgba(191, 244, 255, 0.28);
		}

		.site-footer a:hover {
			color: #ffffff;
			border-bottom-color: rgba(255, 255, 255, 0.42);
		}

		html[data-theme='light'] .brand-chip {
			border-color: rgba(86, 124, 158, 0.18);
			background: rgba(255, 255, 255, 0.76);
			color: #1d5d83;
		}

		html[data-theme='light'] .brand-title {
			color: #10253d;
		}

		html[data-theme='light'] .theme-toggle {
			background: transparent;
			border-color: transparent;
			box-shadow: none;
		}

		html[data-theme='light'] .surface-card {
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(255, 255, 255, 0.72)),
				var(--panel);
		}

		html[data-theme='light'] .section-kicker {
			color: #0f7ab8;
		}

		html[data-theme='light'] .section-kicker::before {
			background: linear-gradient(90deg, transparent, rgba(14, 165, 233, 0.72));
		}

		html[data-theme='light'] .panel-badge {
			background: rgba(14, 165, 233, 0.08);
			border-color: rgba(14, 165, 233, 0.16);
			color: #0f5f8e;
		}

		html[data-theme='light'] .field-label {
			color: #17324a;
		}

		html[data-theme='light'] .input-control {
			background: rgba(255, 255, 255, 0.82);
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.65);
		}

		html[data-theme='light'] .input-control::placeholder {
			color: #7b8fa3;
		}

		html[data-theme='light'] .input-control:focus {
			background: #ffffff;
			border-color: rgba(14, 165, 233, 0.3);
			box-shadow: 0 0 0 4px rgba(14, 165, 233, 0.1);
		}

		html[data-theme='light'] .history-toggle {
			border-color: rgba(95, 123, 150, 0.14);
			background: rgba(255, 255, 255, 0.78);
			color: #5b738b;
		}

		html[data-theme='light'] .history-toggle:hover {
			color: #10253d;
			background: rgba(14, 165, 233, 0.1);
		}

		html[data-theme='light'] .history-dropdown {
			border-color: rgba(95, 123, 150, 0.14);
			background: rgba(255, 255, 255, 0.96);
			box-shadow: 0 20px 36px rgba(43, 67, 91, 0.16);
		}

		html[data-theme='light'] .history-item:hover {
			background: rgba(14, 165, 233, 0.08);
			color: #10253d;
		}

		html[data-theme='light'] .history-item.is-empty {
			color: #7f92a6;
		}

		html[data-theme='light'] .mode-card,
		html[data-theme='light'] .progress-container,
		html[data-theme='light'] .metric-card,
		html[data-theme='light'] .results-empty,
		html[data-theme='light'] .map-container-wrapper {
			background: rgba(255, 255, 255, 0.62);
			border-color: rgba(95, 123, 150, 0.14);
		}

		html[data-theme='light'] .map-detail-map-panel,
		html[data-theme='light'] .exit-detail-card {
			border-color: rgba(95, 123, 150, 0.12);
		}

		html[data-theme='light'] .map-detail-map-panel {
			background: rgba(227, 239, 248, 0.72);
		}

		html[data-theme='light'] .exit-detail-card {
			background: linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(245, 249, 253, 0.92));
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.55);
		}

		html[data-theme='light'] .exit-detail-item:not(:last-child) {
			border-bottom-color: rgba(95, 123, 150, 0.16);
		}

		html[data-theme='light'] .exit-risk-badge.is-info,
		html[data-theme='light'] .exit-detail-state.is-info {
			color: #0c7fb3;
		}

		html[data-theme='light'] .exit-risk-badge.is-low,
		html[data-theme='light'] .exit-detail-state.is-safe {
			color: #047857;
		}

		html[data-theme='light'] .exit-detail-state.is-neutral {
			background: rgba(255, 255, 255, 0.82);
			border-color: rgba(95, 123, 150, 0.16);
			color: #10253d;
		}

		html[data-theme='light'] .exit-detail-state.is-danger {
			color: #be123c;
		}

		html[data-theme='light'] .exit-detail-state.is-warn {
			color: #b45309;
		}

		html[data-theme='light'] .slider {
			background: rgba(14, 165, 233, 0.12);
			border-color: rgba(95, 123, 150, 0.14);
		}

		html[data-theme='light'] .slider::before {
			background: #ffffff;
			box-shadow: 0 6px 14px rgba(43, 67, 91, 0.18);
		}

		html[data-theme='light'] .primary-btn {
			box-shadow: 0 18px 34px rgba(14, 165, 233, 0.18);
		}

		html[data-theme='light'] .primary-btn:hover {
			box-shadow: 0 22px 40px rgba(14, 165, 233, 0.22);
		}

		html[data-theme='light'] .primary-btn.is-stop {
			box-shadow: 0 18px 34px rgba(225, 29, 72, 0.18);
		}

		html[data-theme='light'] .primary-btn.is-stop:hover {
			box-shadow: 0 22px 40px rgba(225, 29, 72, 0.24);
		}

		html[data-theme='light'] .results-pill {
			border-color: rgba(95, 123, 150, 0.16);
			background: rgba(255, 255, 255, 0.72);
			color: #16324a;
		}

		html[data-theme='light'] .results-pill.state-idle {
			color: #365168;
		}

		html[data-theme='light'] .results-pill.state-resolving {
			background: rgba(245, 158, 11, 0.12);
			border-color: rgba(245, 158, 11, 0.18);
			color: #9a6706;
		}

		html[data-theme='light'] .results-pill.state-running {
			background: rgba(14, 165, 233, 0.12);
			border-color: rgba(14, 165, 233, 0.18);
			color: #0f5f8e;
		}

		html[data-theme='light'] .results-pill.state-done {
			background: rgba(5, 150, 105, 0.12);
			border-color: rgba(5, 150, 105, 0.18);
			color: #047857;
		}

		html[data-theme='light'] .results-pill.state-empty,
		html[data-theme='light'] .results-pill.state-error,
		html[data-theme='light'] .results-pill.state-stopped {
			background: rgba(225, 29, 72, 0.1);
			border-color: rgba(225, 29, 72, 0.16);
			color: #be123c;
		}

		html[data-theme='light'] .filter-chip {
			border-color: rgba(95, 123, 150, 0.14);
			background: rgba(255, 255, 255, 0.66);
			color: #365168;
		}

		html[data-theme='light'] .filter-toggle {
			border-color: rgba(95, 123, 150, 0.14);
			background: rgba(255, 255, 255, 0.66);
			color: #23415a;
		}

		html[data-theme='light'] .filter-toggle:hover {
			border-color: rgba(14, 165, 233, 0.24);
			background: rgba(14, 165, 233, 0.08);
			color: #10253d;
		}

		html[data-theme='light'] .filter-chip:hover {
			border-color: rgba(14, 165, 233, 0.24);
			background: rgba(14, 165, 233, 0.08);
			color: #10253d;
		}

		html[data-theme='light'] .filter-chip.is-active {
			border-color: rgba(14, 165, 233, 0.32);
			background: linear-gradient(135deg, rgba(14, 165, 233, 0.16), rgba(5, 150, 105, 0.1));
			color: #0f5f8e;
			box-shadow: inset 0 0 0 1px rgba(14, 165, 233, 0.08);
		}

		html[data-theme='light'] .filter-chip-risk.risk-verylow,
		html[data-theme='light'] .meta-chip-risk.risk-verylow {
			--risk-border: rgba(5, 150, 105, 0.24);
			--risk-bg: rgba(5, 150, 105, 0.08);
			--risk-color: #047857;
			--risk-active-border: rgba(5, 150, 105, 0.42);
			--risk-active-bg: linear-gradient(135deg, rgba(5, 150, 105, 0.18), rgba(16, 185, 129, 0.12));
			--risk-active-color: #065f46;
			--risk-shadow: rgba(5, 150, 105, 0.08);
		}

		html[data-theme='light'] .filter-chip-risk.risk-low,
		html[data-theme='light'] .meta-chip-risk.risk-low {
			--risk-border: rgba(13, 148, 136, 0.22);
			--risk-bg: rgba(13, 148, 136, 0.07);
			--risk-color: #0f766e;
			--risk-active-border: rgba(13, 148, 136, 0.38);
			--risk-active-bg: linear-gradient(135deg, rgba(13, 148, 136, 0.16), rgba(14, 165, 233, 0.1));
			--risk-active-color: #115e59;
			--risk-shadow: rgba(13, 148, 136, 0.08);
		}

		html[data-theme='light'] .filter-chip-risk.risk-elevated,
		html[data-theme='light'] .meta-chip-risk.risk-elevated {
			--risk-border: rgba(202, 138, 4, 0.28);
			--risk-bg: rgba(202, 138, 4, 0.08);
			--risk-color: #92400e;
			--risk-active-border: rgba(202, 138, 4, 0.44);
			--risk-active-bg: linear-gradient(135deg, rgba(202, 138, 4, 0.18), rgba(245, 158, 11, 0.12));
			--risk-active-color: #78350f;
			--risk-shadow: rgba(202, 138, 4, 0.1);
		}

		html[data-theme='light'] .filter-chip-risk.risk-high,
		html[data-theme='light'] .meta-chip-risk.risk-high {
			--risk-border: rgba(234, 88, 12, 0.3);
			--risk-bg: rgba(234, 88, 12, 0.09);
			--risk-color: #9a3412;
			--risk-active-border: rgba(234, 88, 12, 0.46);
			--risk-active-bg: linear-gradient(135deg, rgba(234, 88, 12, 0.2), rgba(239, 68, 68, 0.12));
			--risk-active-color: #7c2d12;
			--risk-shadow: rgba(234, 88, 12, 0.1);
		}

		html[data-theme='light'] .filter-chip-risk.risk-critical,
		html[data-theme='light'] .meta-chip-risk.risk-critical {
			--risk-border: rgba(220, 38, 38, 0.32);
			--risk-bg: rgba(220, 38, 38, 0.1);
			--risk-color: #991b1b;
			--risk-active-border: rgba(220, 38, 38, 0.5);
			--risk-active-bg: linear-gradient(135deg, rgba(220, 38, 38, 0.22), rgba(190, 18, 60, 0.14));
			--risk-active-color: #7f1d1d;
			--risk-shadow: rgba(220, 38, 38, 0.1);
		}

		html[data-theme='light'] .filter-chip-risk:hover,
		html[data-theme='light'] .filter-chip-risk.is-active {
			border-color: var(--risk-active-border);
			background: var(--risk-active-bg);
			color: var(--risk-active-color);
			box-shadow: inset 0 0 0 1px var(--risk-shadow);
		}

		html[data-theme='light'] .export-chip {
			border-color: rgba(245, 158, 11, 0.22);
			background: linear-gradient(135deg, rgba(245, 158, 11, 0.14), rgba(251, 191, 36, 0.12));
			color: #9a6706;
		}

		html[data-theme='light'] .export-chip:hover {
			border-color: rgba(245, 158, 11, 0.34);
			background: linear-gradient(135deg, rgba(245, 158, 11, 0.2), rgba(251, 191, 36, 0.16));
			color: #7c4a03;
		}

		html[data-theme='light'] .filter-chip:disabled,
		html[data-theme='light'] .filter-chip.is-disabled {
			border-color: rgba(95, 123, 150, 0.1);
			background: rgba(255, 255, 255, 0.36);
			color: rgba(91, 115, 139, 0.46);
			box-shadow: none;
		}

		html[data-theme='light'] .export-toast {
			border-color: rgba(14, 165, 233, 0.2);
			background: rgba(255, 255, 255, 0.94);
			box-shadow: 0 18px 44px rgba(15, 23, 42, 0.16);
			color: #075985;
		}

		html[data-theme='light'] .export-toast.is-error {
			border-color: rgba(225, 29, 72, 0.2);
			color: #be123c;
		}

		html[data-theme='light'] .filter-empty {
			border-color: rgba(95, 123, 150, 0.16);
			background: rgba(255, 255, 255, 0.58);
			color: #5b738b;
		}

		html[data-theme='light'] .empty-visual {
			background:
				radial-gradient(circle at 30% 30%, rgba(14, 165, 233, 0.18), transparent 42%),
				linear-gradient(160deg, rgba(255, 255, 255, 0.78), rgba(255, 255, 255, 0.4));
			border-color: rgba(95, 123, 150, 0.14);
			box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.82);
		}

		html[data-theme='light'] .empty-visual span:nth-child(1) {
			background: rgba(14, 165, 233, 0.18);
		}

		html[data-theme='light'] .empty-visual span:nth-child(2) {
			background: rgba(20, 184, 166, 0.28);
		}

		html[data-theme='light'] .empty-visual span:nth-child(3) {
			background: rgba(16, 37, 61, 0.12);
		}

		html[data-theme='light'] .site-footer a,
		html[data-theme='light'] #visit-count {
			color: #0f7ab8;
			border-bottom-color: rgba(14, 165, 233, 0.24);
		}

		html[data-theme='light'] .site-footer a:hover {
			color: #10253d;
			border-bottom-color: rgba(16, 37, 61, 0.2);
		}

		html[data-theme='light'] .result-item {
			border-color: rgba(95, 123, 150, 0.14);
			background:
				linear-gradient(180deg, rgba(255, 255, 255, 0.88), transparent 38%),
				var(--panel-strong);
		}

		html[data-theme='light'] .result-item::before {
			background: rgba(121, 140, 159, 0.38);
		}

		html[data-theme='light'] .status-badge {
			border-color: rgba(95, 123, 150, 0.14);
			background: rgba(255, 255, 255, 0.72);
			color: #16324a;
		}

		html[data-theme='light'] .status-badge[data-tooltip]::before,
		html[data-theme='light'] .status-badge[data-tooltip]::after {
			background: rgba(16, 37, 61, 0.96);
			border-color: rgba(255, 255, 255, 0.18);
			color: #f7fbff;
		}

		html[data-theme='light'] .status-success {
			background: rgba(5, 150, 105, 0.12);
			border-color: rgba(5, 150, 105, 0.16);
			color: #047857;
		}

		html[data-theme='light'] .status-error {
			background: rgba(225, 29, 72, 0.1);
			border-color: rgba(225, 29, 72, 0.16);
			color: #be123c;
		}

		html[data-theme='light'] .status-pending {
			background: rgba(245, 158, 11, 0.12);
			border-color: rgba(245, 158, 11, 0.16);
			color: #9a6706;
		}

		html[data-theme='light'] .meta-chip {
			background: rgba(14, 165, 233, 0.08);
			border-color: rgba(14, 165, 233, 0.12);
			color: #23415a;
		}

		html[data-theme='light'] .meta-chip-strong {
			background: rgba(14, 165, 233, 0.12);
			border-color: rgba(14, 165, 233, 0.18);
			color: #075985;
		}

		html[data-theme='light'] .meta-chip-danger {
			background: rgba(225, 29, 72, 0.08);
			border-color: rgba(225, 29, 72, 0.14);
			color: #be123c;
		}

		html[data-theme='light'] .meta-chip.meta-chip-risk {
			border-color: var(--risk-border);
			background: var(--risk-bg);
			color: var(--risk-color);
		}

		html[data-theme='light'] .exit-ip-btn {
			border-color: rgba(5, 150, 105, 0.18);
			background: linear-gradient(135deg, rgba(5, 150, 105, 0.08), rgba(14, 165, 233, 0.08));
			color: #17324a;
		}

		html[data-theme='light'] .exit-ip-btn:hover {
			border-color: rgba(14, 165, 233, 0.24);
			background: linear-gradient(135deg, rgba(5, 150, 105, 0.12), rgba(14, 165, 233, 0.12));
		}

		html[data-theme='light'] .exit-ip-btn.is-active {
			border-color: rgba(14, 165, 233, 0.32);
			background: linear-gradient(135deg, rgba(14, 165, 233, 0.18), rgba(5, 150, 105, 0.12));
			box-shadow: inset 0 0 0 1px rgba(14, 165, 233, 0.1), 0 0 0 1px rgba(14, 165, 233, 0.08);
		}

		html[data-theme='light'] #global-map {
			background: #dfeaf3;
		}

		html[data-theme='light'] #global-map .leaflet-tile-pane {
			filter: none;
		}

		html[data-theme='light'] .leaflet-control-attribution {
			background: rgba(255, 255, 255, 0.92) !important;
			box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08);
			color: rgba(15, 23, 42, 0.72) !important;
		}

		@media (max-width: 980px) {
			.workspace-grid {
				grid-template-columns: 1fr;
			}

			.header-note {
				text-align: left;
				max-width: none;
			}

		}

		@media (max-width: 720px) {
			.page-shell {
				padding: 22px 14px 32px;
			}

			.header-note {
				flex: none;
			}

			.results-list:not(:empty) {
				margin-top: 18px;
			}

			.site-header,
			.panel-header,
			.results-header,
			.control-row,
			.results-empty,
			.result-top {
				flex-direction: column;
			}

			.site-header,
			.panel-header,
			.results-header,
			.control-row {
				align-items: stretch;
			}

			.control-panel,
			.side-card,
			.results-shell {
				padding: 22px;
			}

			.mode-card {
				min-width: 0;
			}

			.progress-head {
				flex-direction: column;
				align-items: flex-start;
			}

			.exit-detail-grid {
				grid-template-columns: 1fr;
			}

			.map-detail-map-panel {
				height: 280px;
			}

		}

		@media (max-width: 560px) {
			.meta-chip,
			.exit-ip-btn {
				width: 100%;
				justify-content: center;
			}

			.filter-row-label,
			.filter-options {
				width: 100%;
			}

			.filter-chip {
				flex: 1 1 128px;
			}

			.results-empty {
				grid-template-columns: 1fr;
				text-align: center;
			}

			.empty-visual {
				margin: 0 auto;
			}

			.summary-grid {
				grid-template-columns: repeat(2, minmax(0, 1fr));
				gap: 10px;
			}

			.metric-card {
				padding: 14px;
			}

			.map-container-wrapper {
				padding: 14px;
			}

			.map-detail-map-panel {
				height: 240px;
			}

			.exit-detail-grid,
			.exit-detail-security-grid {
				grid-template-columns: 1fr;
			}

			.exit-detail-item {
				flex-direction: column;
				align-items: flex-start;
				gap: 6px;
			}

			.exit-detail-value {
				text-align: left;
			}

		}
	</style>
</head>
<body>
	<div class="page-shell">
		<div class="ambient ambient-one"></div>
		<div class="ambient ambient-two"></div>

		<header class="site-header">
			<div class="brand">
				<div class="brand-title">Check Socks5</div>
				<div class="brand-chip">
					<span class="brand-chip-text">
						<span class="brand-dot"></span>
						<span>Cloudflare Workers Toolkit</span>
					</span>
					<button class="theme-toggle" type="button" id="themeToggle" aria-label="切换日间和夜间模式" title="切换日间和夜间模式">
						<span class="theme-toggle-switch" aria-hidden="true">
							<svg class="theme-toggle-icon theme-toggle-icon-light" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
								<circle cx="12" cy="12" r="4"></circle>
								<path d="M12 2v2"></path>
								<path d="M12 20v2"></path>
								<path d="m4.93 4.93 1.41 1.41"></path>
								<path d="m17.66 17.66 1.41 1.41"></path>
								<path d="M2 12h2"></path>
								<path d="M20 12h2"></path>
								<path d="m6.34 17.66-1.41 1.41"></path>
								<path d="m19.07 4.93-1.41 1.41"></path>
							</svg>
							<span class="theme-toggle-thumb"></span>
							<svg class="theme-toggle-icon theme-toggle-icon-dark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
								<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"></path>
							</svg>
						</span>
					</button>
				</div>
			</div>
			<div class="header-note">基于 Cloudflare Workers 的 SOCKS5 / HTTP / HTTPS / TURN 代理检测工具，支持单个或批量代理解析、可用性验证与出口信息查看。</div>
		</header>

		<main class="site-main">
			<section class="workspace-grid">
				<div class="surface-card control-panel">
					<div class="panel-header">
						<div>
							<p class="section-kicker">Workspace</p>
							<h2 class="panel-title">开始检测</h2>
							<p class="panel-copy">输入单个代理链接、IP:端口、域名:端口或一整段列表，支持 SOCKS5 / HTTP / HTTPS / TURN。缺少协议头时会自动按 socks5:// 处理。</p>
						</div>
						<div class="panel-badge">实时解析与验证</div>
					</div>

					<div class="input-zone">
						<label class="field-label" for="inputList">代理链接 / 域名代理</label>
						<div class="input-wrapper" id="inputContainer">
							<input class="input-control" type="text" id="inputList" placeholder="例如：turn://root:root@203.85.37.38:81">
							<button class="history-toggle" type="button" id="historyBtn" aria-label="查看历史记录">
								<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
									<circle cx="12" cy="12" r="10"></circle>
									<polyline points="12 6 12 12 16 14"></polyline>
								</svg>
							</button>
							<div class="history-dropdown" id="historyDropdown"></div>
						</div>
						<p class="field-hint" id="fieldHint">单条模式支持历史快速回填，按 Enter 可以直接开始检测。</p>
					</div>

					<div class="control-row">
						<div class="mode-card">
							<div class="mode-copy">
								<strong>批量检测</strong>
								<div class="mode-state" id="modeLabel">Single / 单目标</div>
							</div>
							<label class="switch">
								<input type="checkbox" id="batchMode">
								<span class="slider"></span>
							</label>
						</div>

						<button class="primary-btn" id="checkBtn" type="button">
							<span>开始检测</span>
							<small>Resolve + Check</small>
						</button>
					</div>

				</div>

				<aside class="side-column">
					<div class="surface-card side-card">
						<p class="section-kicker">Summary</p>
						<h3 class="summary-title" id="summaryHeadline">等待输入</h3>
						<p class="summary-description" id="summaryDescription">实时统计和检测概览。</p>
						<div id="progressContainer" class="progress-container">
							<div class="progress-head">
								<span>检测进度</span>
								<span id="progressText">尚未开始</span>
							</div>
							<div class="progress-track">
								<div id="progressBar" class="progress-bar"></div>
							</div>
						</div>
						<div class="summary-grid">
							<div class="metric-card">
								<span>目标数</span>
								<strong id="statTotal">0</strong>
							</div>
							<div class="metric-card">
								<span>有效</span>
								<strong id="statSuccess">0</strong>
							</div>
							<div class="metric-card">
								<span>待完成</span>
								<strong id="statPending">0</strong>
							</div>
							<div class="metric-card">
								<span>失败</span>
								<strong id="statFailed">0</strong>
							</div>
						</div>
					</div>
				</aside>
			</section>

			<section class="surface-card results-shell">
				<div class="results-header">
					<div>
						<p class="section-kicker">Results</p>
						<h2 class="results-title">检测结果</h2>
						<p class="results-subtitle" id="resultMeta">结果、落地 IP 和地图会在这里按检测进度逐步展开。</p>
					</div>
					<div class="results-pill state-idle" id="resultPill">Idle</div>
				</div>

				<div class="results-empty" id="resultsEmpty">
					<div class="empty-visual" aria-hidden="true">
						<span></span>
						<span></span>
						<span></span>
					</div>
					<div class="empty-copy">
						<h3 id="emptyStateTitle">等待开始检测</h3>
						<p id="emptyStateDescription">输入目标后，检测结果、出口信息和地图会在这里展示。</p>
					</div>
				</div>

				<div class="results-filters" id="resultsFilters" hidden>
					<button class="filter-toggle" id="filterToggle" type="button" aria-expanded="false">
						<span id="filterToggleText">筛选：全部结果</span>
						<span class="filter-toggle-icon" aria-hidden="true">
							<svg viewBox="0 0 12 12" fill="none">
								<path d="M2.5 4.25L6 7.75L9.5 4.25" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"></path>
							</svg>
						</span>
					</button>
					<div class="filter-panel" id="filterPanel" hidden>
						<div class="filter-row">
							<span class="filter-row-label">风控</span>
							<div class="filter-options" id="primaryFilterGroup" aria-label="风控评级筛选"></div>
						</div>
						<div class="filter-row">
							<span class="filter-row-label">协议</span>
							<div class="filter-options" id="protocolFilterGroup" aria-label="代理协议筛选"></div>
						</div>
						<div class="filter-row">
							<span class="filter-row-label">地区</span>
							<div class="filter-options" id="countryFilterGroup" aria-label="出口地区筛选"></div>
						</div>
						<div class="filter-row">
							<span class="filter-row-label">导出</span>
							<div class="filter-options export-options" id="exportGroup" aria-label="导出当前筛选结果">
								<button class="filter-chip export-chip" type="button" data-export-format="clipboard">粘贴板</button>
								<button class="filter-chip export-chip" type="button" data-export-format="txt">TXT文件</button>
								<button class="filter-chip export-chip" type="button" data-export-format="csv">CSV文件</button>
							</div>
						</div>
					</div>
				</div>
				<div class="filter-empty" id="filterEmpty" hidden>当前筛选没有匹配的检测结果。</div>
				<div id="results" class="results-list"></div>
			</section>

		</main>

		<footer class="site-footer">
			<div>${备案内容}</div>
		</footer>
	</div>

	<div id="map-template">
		<div id="global-map"></div>
	</div>

	<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
	<script>
		const checkBtn = document.getElementById('checkBtn');
		let inputList = document.getElementById('inputList');
		const inputContainer = document.getElementById('inputContainer');
		const batchMode = document.getElementById('batchMode');
		const resultsDiv = document.getElementById('results');
		const progressBar = document.getElementById('progressBar');
		const progressText = document.getElementById('progressText');
		const globalMap = document.getElementById('global-map');
		const historyBtn = document.getElementById('historyBtn');
		const historyDropdown = document.getElementById('historyDropdown');
		const fieldHint = document.getElementById('fieldHint');
		const modeLabel = document.getElementById('modeLabel');
		const summaryHeadline = document.getElementById('summaryHeadline');
		const summaryDescription = document.getElementById('summaryDescription');
		const statTotal = document.getElementById('statTotal');
		const statSuccess = document.getElementById('statSuccess');
		const statPending = document.getElementById('statPending');
		const statFailed = document.getElementById('statFailed');
		const resultMeta = document.getElementById('resultMeta');
		const resultPill = document.getElementById('resultPill');
		const resultsEmpty = document.getElementById('resultsEmpty');
		const emptyStateTitle = document.getElementById('emptyStateTitle');
		const emptyStateDescription = document.getElementById('emptyStateDescription');
		const resultsFilters = document.getElementById('resultsFilters');
		const filterToggle = document.getElementById('filterToggle');
		const filterPanel = document.getElementById('filterPanel');
		const filterToggleText = document.getElementById('filterToggleText');
		const primaryFilterGroup = document.getElementById('primaryFilterGroup');
		const protocolFilterGroup = document.getElementById('protocolFilterGroup');
		const countryFilterGroup = document.getElementById('countryFilterGroup');
		const exportGroup = document.getElementById('exportGroup');
		const filterEmpty = document.getElementById('filterEmpty');
		const themeToggle = document.getElementById('themeToggle');
		const THEME_STORAGE_KEY = 'cf_proxy_theme';
		const systemThemeQuery = window.matchMedia('(prefers-color-scheme: dark)');
		const BASE_MAP_TILE_URL = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';
		const BASE_MAP_TILE_OPTIONS = {
			maxZoom: 19,
			attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer noopener">OpenStreetMap</a> contributors'
		};

		let map = null;
		let mapLayers = [];
		let redLocationIcon = null;
		let mapRenderToken = 0;
		let totalTargets = 0;
		let completedCount = 0;
		let successCount = 0;
		let inputCount = 0;
		let appState = 'idle';
		let activeRun = null;
		const CHECK_CONCURRENCY = 32;
		const RESOLVE_BATCH_SIZE = 50;
		const RESOLVE_BATCH_TIMEOUT_MS = 20000;
		const RESOLVE_BATCH_MAX_ATTEMPTS = 3;
		const RISK_RESULT_FILTERS = [
			{ key: 'verylow', label: '极度纯净' },
			{ key: 'low', label: '纯净' },
			{ key: 'elevated', label: '轻微风险' },
			{ key: 'high', label: '高风险' },
			{ key: 'critical', label: '极度危险' }
		];
		const PRIMARY_RESULT_FILTERS = [
			{ key: 'all', label: '全部' },
			{ key: 'success', label: '有效' },
			{ key: 'failed', label: '失败' },
			...RISK_RESULT_FILTERS
		];
		const PROTOCOL_RESULT_FILTERS = [
			{ key: 'socks5', label: 'SOCKS5' },
			{ key: 'http', label: 'HTTP' },
			{ key: 'https', label: 'HTTPS' },
			{ key: 'turn', label: 'TURN' }
		];
		const EXPORT_CSV_COLUMNS = [
			{ header: 'TYPE', path: 'type' },
			{ header: 'USERNAME', path: 'username' },
			{ header: 'PASSWORD', path: 'password' },
			{ header: 'HOSTNAME', path: 'hostname' },
			{ header: 'PORT', path: 'port' },
			{ header: 'LINK', path: 'link' },
			{ header: 'CONNECT_MS', path: 'responseTime' },
			{ header: 'EXIT_IP', path: 'exit.ip' },
			{ header: 'EXIT_RIR', path: 'exit.rir' },
			{ header: 'EXIT_ELAPSED_MS', path: 'exit.elapsed_ms' },
			{ header: 'EXIT_IS_BOGON', path: 'exit.is_bogon' },
			{ header: 'EXIT_IS_MOBILE', path: 'exit.is_mobile' },
			{ header: 'EXIT_IS_SATELLITE', path: 'exit.is_satellite' },
			{ header: 'EXIT_IS_CRAWLER', path: 'exit.is_crawler' },
			{ header: 'EXIT_IS_DATACENTER', path: 'exit.is_datacenter' },
			{ header: 'EXIT_IS_TOR', path: 'exit.is_tor' },
			{ header: 'EXIT_IS_PROXY', path: 'exit.is_proxy' },
			{ header: 'EXIT_IS_VPN', path: 'exit.is_vpn' },
			{ header: 'EXIT_IS_ABUSER', path: 'exit.is_abuser' },
			{ header: 'EXIT_DATACENTER_NAME', path: 'exit.datacenter.datacenter' },
			{ header: 'EXIT_DATACENTER_DOMAIN', path: 'exit.datacenter.domain' },
			{ header: 'EXIT_DATACENTER_NETWORK', path: 'exit.datacenter.network' },
			{ header: 'EXIT_COMPANY_NAME', path: 'exit.company.name' },
			{ header: 'EXIT_COMPANY_ABUSER_SCORE', path: 'exit.company.abuser_score' },
			{ header: 'EXIT_COMPANY_DOMAIN', path: 'exit.company.domain' },
			{ header: 'EXIT_COMPANY_TYPE', path: 'exit.company.type' },
			{ header: 'EXIT_COMPANY_NETWORK', path: 'exit.company.network' },
			{ header: 'EXIT_COMPANY_WHOIS', path: 'exit.company.whois' },
			{ header: 'EXIT_ASN', path: 'exit.asnInfo.asn' },
			{ header: 'EXIT_ASN_ABUSER_SCORE', path: 'exit.asnInfo.abuser_score' },
			{ header: 'EXIT_ASN_ROUTE', path: 'exit.asnInfo.route' },
			{ header: 'EXIT_ASN_DESCR', path: 'exit.asnInfo.descr' },
			{ header: 'EXIT_ASN_COUNTRY', path: 'exit.asnInfo.country' },
			{ header: 'EXIT_ASN_ACTIVE', path: 'exit.asnInfo.active' },
			{ header: 'EXIT_ASN_ORG', path: 'exit.asnInfo.org' },
			{ header: 'EXIT_ASN_DOMAIN', path: 'exit.asnInfo.domain' },
			{ header: 'EXIT_ASN_ABUSE', path: 'exit.asnInfo.abuse' },
			{ header: 'EXIT_ASN_TYPE', path: 'exit.asnInfo.type' },
			{ header: 'EXIT_ASN_UPDATED', path: 'exit.asnInfo.updated' },
			{ header: 'EXIT_ASN_RIR', path: 'exit.asnInfo.rir' },
			{ header: 'EXIT_ASN_WHOIS', path: 'exit.asnInfo.whois' },
			{ header: 'EXIT_LOCATION_IS_EU_MEMBER', path: 'exit.location.is_eu_member' },
			{ header: 'EXIT_LOCATION_CALLING_CODE', path: 'exit.location.calling_code' },
			{ header: 'EXIT_LOCATION_CURRENCY_CODE', path: 'exit.location.currency_code' },
			{ header: 'EXIT_LOCATION_CONTINENT', path: 'exit.location.continent' },
			{ header: 'EXIT_LOCATION_COUNTRY', path: 'exit.location.country' },
			{ header: 'EXIT_LOCATION_COUNTRY_CODE', path: 'exit.location.country_code' },
			{ header: 'EXIT_LOCATION_STATE', path: 'exit.location.state' },
			{ header: 'EXIT_LOCATION_CITY', path: 'exit.location.city' },
			{ header: 'EXIT_LOCATION_LATITUDE', path: 'exit.location.latitude' },
			{ header: 'EXIT_LOCATION_LONGITUDE', path: 'exit.location.longitude' },
			{ header: 'EXIT_LOCATION_ZIP', path: 'exit.location.zip' },
			{ header: 'EXIT_LOCATION_TIMEZONE', path: 'exit.location.timezone' },
			{ header: 'EXIT_LOCATION_LOCAL_TIME', path: 'exit.location.local_time' },
			{ header: 'EXIT_LOCATION_LOCAL_TIME_UNIX', path: 'exit.location.local_time_unix' },
			{ header: 'EXIT_LOCATION_IS_DST', path: 'exit.location.is_dst' }
		];
		let resultRecords = [];
		let activePrimaryFilter = 'all';
		let activeProtocolFilters = getDefaultProtocolFilters();
		let activeCountryFilter = 'all';
		let isFilterPanelExpanded = false;
		let isCreatingResultBatch = false;
		let exportToastTimer = null;

		function getStoredTheme() {
			try {
				const storedTheme = localStorage.getItem(THEME_STORAGE_KEY);
				return storedTheme === 'light' || storedTheme === 'dark' ? storedTheme : '';
			} catch {
				return '';
			}
		}

		function getSystemTheme() {
			return systemThemeQuery.matches ? 'dark' : 'light';
		}

		function applyTheme(theme, source) {
			const nextTheme = theme === 'light' ? 'light' : 'dark';
			const isDark = nextTheme === 'dark';

			document.documentElement.dataset.theme = nextTheme;
			document.documentElement.style.colorScheme = nextTheme;

			if (!themeToggle) return;

			themeToggle.setAttribute('aria-pressed', String(isDark));
			themeToggle.setAttribute(
				'aria-label',
				isDark
					? '当前为夜间模式，点击切换到日间模式。'
					: '当前为日间模式，点击切换到夜间模式。'
			);
			themeToggle.title = source === 'stored'
				? (isDark ? '夜间模式，已保存到本地' : '日间模式，已保存到本地')
				: (isDark ? '夜间模式，当前跟随系统' : '日间模式，当前跟随系统');
		}

		function initializeTheme() {
			const storedTheme = getStoredTheme();
			applyTheme(storedTheme || getSystemTheme(), storedTheme ? 'stored' : 'system');
		}

		initializeTheme();

		function initMap() {
			if (map) return;
			map = L.map('global-map', {
				zoomControl: false,
				attributionControl: true
			}).setView([20, 0], 2);
			map.attributionControl.setPrefix(false);
			// OpenStreetMap provides broader global coverage than AMap for international checks.
			L.tileLayer(BASE_MAP_TILE_URL, BASE_MAP_TILE_OPTIONS).addTo(map);
		}

		function getRedLocationIcon() {
			if (!redLocationIcon) {
				redLocationIcon = L.divIcon({
					className: 'red-location-marker',
					html: '<span class="red-location-pin" aria-hidden="true"></span>',
					iconSize: [32, 40],
					iconAnchor: [16, 38],
					popupAnchor: [0, -34]
				});
			}
			return redLocationIcon;
		}

		function normalizeColoCode(value) {
			const code = String(value || '').trim().toUpperCase();
			return /^[A-Z0-9]{3,4}$/.test(code) ? code : '';
		}

		function isValidCoordinatePair(value) {
			return Array.isArray(value)
				&& value.length === 2
				&& value.every(function (entry) { return Number.isFinite(entry); })
				&& Math.abs(value[0]) <= 90
				&& Math.abs(value[1]) <= 180;
		}

		function parseCoordinatePair(value) {
			if (typeof value === 'string') {
				const parts = value.split(',').map(function (entry) {
					return Number(entry.trim());
				});
				return isValidCoordinatePair(parts) ? parts : null;
			}

			if (Array.isArray(value)) {
				const parts = value.map(function (entry) {
					return Number(entry);
				});
				return isValidCoordinatePair(parts) ? parts : null;
			}

			return null;
		}

		function clearMapLayers() {
			mapLayers.forEach(function (layer) {
				map.removeLayer(layer);
			});
			mapLayers = [];
		}

		function createExitPopup(exitData) {
			const locationText = formatExitLocation(exitData) || 'Location unknown';
			const networkText = formatExitNetwork(exitData) || 'Network unknown';
			const coloCode = normalizeColoCode(exitData?.colo);
			const coloText = coloCode ? '<br>CF Colo: ' + escapeHtml(coloCode) : '';
			return '<div class="map-popup"><b>Exit IP</b><br>'
				+ escapeHtml(exitData?.ip || 'Unknown')
				+ '<br>' + escapeHtml(locationText)
				+ '<br>' + escapeHtml(networkText)
				+ coloText
				+ '</div>';
		}

		function escapeHtml(value) {
			return String(value ?? '').replace(/[&<>"']/g, function (char) {
				return {
					'&': '&amp;',
					'<': '&lt;',
					'>': '&gt;',
					'"': '&quot;',
					"'": '&#39;'
				}[char];
			});
		}

		function joinNonEmptyValues(values, separator) {
			return values
				.map(function (value) {
					return String(value ?? '').trim();
				})
				.filter(Boolean)
				.join(separator || ' / ');
		}

		function formatExitIpType(type) {
			const text = String(type || '').trim();
			if (!text) return '未知';
			const mapping = {
				isp: '住宅',
				hosting: '机房',
				education: '教育',
				government: '政府',
				business: '商用'
			};
			return mapping[text.toLowerCase()] || text;
		}

		function parseAbuseScore(value) {
			const score = Number.parseFloat(String(value ?? '').trim());
			return Number.isFinite(score) ? score : null;
		}

		function calculateExitRiskScore(exitData) {
			const companyScore = parseAbuseScore(exitData?.company?.abuser_score) || 0;
			const asnScore = parseAbuseScore(exitData?.asnInfo?.abuser_score) || 0;
			const baseScore = ((companyScore + asnScore) / 2) * 5;
			const riskCount = [
				exitData?.is_crawler,
				exitData?.is_proxy,
				exitData?.is_vpn,
				exitData?.is_tor,
				exitData?.is_abuser
			].filter(function (flag) {
				return flag === true;
			}).length;
			let finalScore = baseScore + riskCount * 0.15;
			if (exitData?.is_bogon) finalScore += 1.0;
			if (baseScore === 0 && riskCount === 0 && !exitData?.is_bogon) return null;
			return finalScore;
		}

		function getExitRiskMeta(score) {
			if (score === null || score === undefined) {
				return {
					level: '未知',
					className: 'is-info',
					text: '未知'
				};
			}

			const percentage = score * 100;
			if (percentage >= 100) return { level: '极度危险', className: 'is-critical', text: percentage.toFixed(2) + '% 极度危险' };
			if (percentage >= 20) return { level: '高风险', className: 'is-high', text: percentage.toFixed(2) + '% 高风险' };
			if (percentage >= 5) return { level: '轻微风险', className: 'is-elevated', text: percentage.toFixed(2) + '% 轻微风险' };
			if (percentage >= 0.25) return { level: '纯净', className: 'is-low', text: percentage.toFixed(2) + '% 纯净' };
			return { level: '极度纯净', className: 'is-verylow', text: percentage.toFixed(2) + '% 极度纯净' };
		}

		function formatExitRiskText(exitData) {
			return getExitRiskMeta(calculateExitRiskScore(exitData)).text;
		}

		function buildExitRiskBadge(exitData) {
			const riskMeta = getExitRiskMeta(calculateExitRiskScore(exitData));
			return '<span class="exit-risk-badge ' + riskMeta.className + '">' + escapeHtml(riskMeta.text) + '</span>';
		}

		function buildExitStateBadge(flag, tone) {
			const toneClass = flag ? {
				danger: 'is-danger',
				warn: 'is-warn',
				info: 'is-info',
				bonus: 'is-safe'
			}[tone] || 'is-danger' : (tone === 'bonus' ? 'is-neutral' : 'is-safe');
			return '<span class="exit-detail-state ' + toneClass + '">' + (flag ? '是' : '否') + '</span>';
		}

		function buildExitDetailRow(label, value, allowHtml) {
			const content = allowHtml ? value : escapeHtml(firstNonEmpty(value, '未知'));
			return '<div class="exit-detail-item"><span class="exit-detail-label">' + escapeHtml(label) + '</span><span class="exit-detail-value">' + content + '</span></div>';
		}

		function formatExitLocationDetail(exitData) {
			const countryCode = firstNonEmpty(exitData?.countryCode, exitData?.country_code, exitData?.location?.country_code);
			const countryName = firstNonEmpty(
				exitData?.countryName,
				exitData?.location?.country,
				exitData?.country && exitData?.country !== countryCode ? exitData?.country : ''
			);
			const locationPrefix = joinNonEmptyValues([
				countryCode ? '[' + countryCode + ']' : '',
				countryName || exitData?.country
			], ' ');
			const region = firstNonEmpty(exitData?.region, exitData?.location?.state);
			const city = firstNonEmpty(exitData?.city, exitData?.location?.city);
			const area = joinNonEmptyValues([region, city], ' / ');
			return firstNonEmpty(area ? joinNonEmptyValues([locationPrefix, area], ' / ') : locationPrefix, '未知');
		}

		function formatExitTimeDetail(exitData) {
			const timezone = firstNonEmpty(exitData?.timezone, exitData?.location?.timezone);
			const localTime = String(firstNonEmpty(exitData?.location?.local_time)).replace('T', ' ').trim();
			return firstNonEmpty(joinNonEmptyValues([timezone, localTime], ' / '), '未知');
		}

		function formatExitProviderDetail(exitData) {
			const values = [
				exitData?.company?.name,
				exitData?.datacenter?.datacenter,
				exitData?.asOrganization
			].map(function (value) {
				return String(value ?? '').trim();
			}).filter(Boolean);
			const uniqueValues = values.filter(function (value, index) {
				return values.indexOf(value) === index;
			});
			return firstNonEmpty(uniqueValues.join(' / '), '未知');
		}

		function formatExitAsnDetail(exitData) {
			const asn = firstNonEmpty(exitData?.asn, exitData?.asnInfo?.asn);
			const route = firstNonEmpty(exitData?.asnInfo?.route);
			const org = firstNonEmpty(exitData?.asnInfo?.org, exitData?.asOrganization);
			return firstNonEmpty(
				joinNonEmptyValues([
					asn ? 'AS' + asn : '',
					route || org
				], ' / '),
				'未知'
			);
		}

		function formatExitNetworkRange(exitData) {
			return firstNonEmpty(
				exitData?.company?.network,
				exitData?.datacenter?.network,
				exitData?.asnInfo?.route,
				'未知'
			);
		}

		function formatExitTypeDetail(exitData) {
			const rawCompanyType = firstNonEmpty(exitData?.company?.type);
			const rawAsnType = firstNonEmpty(exitData?.asnInfo?.type);
			if (!rawCompanyType && !rawAsnType) return '未知';
			return joinNonEmptyValues([
				rawCompanyType ? formatExitIpType(rawCompanyType) : '',
				rawAsnType ? formatExitIpType(rawAsnType) : ''
			], ' / ');
		}

		function formatExitRegistryDetail(exitData) {
			return firstNonEmpty(
				joinNonEmptyValues([
					firstNonEmpty(exitData?.rir),
					firstNonEmpty(exitData?.asnInfo?.rir)
				], ' / '),
				'未知'
			);
		}

		function renderExitDetailPanel(container, exitData) {
			const basicCard = container.querySelector('.exit-basic-info-card');
			const securityCard = container.querySelector('.exit-security-info-card');
			if (!basicCard || !securityCard) return;

			basicCard.innerHTML =
				'<h4 class="exit-detail-section-title">基本信息</h4>' +
				'<div class="exit-detail-list">' +
					buildExitDetailRow('地理位置', formatExitLocationDetail(exitData)) +
					buildExitDetailRow('时区 / 当地时间', formatExitTimeDetail(exitData)) +
					buildExitDetailRow('归属 / 机房', formatExitProviderDetail(exitData)) +
					buildExitDetailRow('RIR', formatExitRegistryDetail(exitData)) +
					buildExitDetailRow('ASN / 路由', formatExitAsnDetail(exitData)) +
				'</div>';

			securityCard.innerHTML =
				'<h4 class="exit-detail-section-title">安全检测</h4>' +
				'<div class="exit-detail-security-grid">' +
					buildExitDetailRow('数据中心', buildExitStateBadge(Boolean(exitData?.is_datacenter), 'warn'), true) +
					buildExitDetailRow('代理服务器', buildExitStateBadge(Boolean(exitData?.is_proxy), 'danger'), true) +
					buildExitDetailRow('VPN 连线', buildExitStateBadge(Boolean(exitData?.is_vpn), 'danger'), true) +
					buildExitDetailRow('Tor 网络', buildExitStateBadge(Boolean(exitData?.is_tor), 'danger'), true) +
					buildExitDetailRow('网络爬虫', buildExitStateBadge(Boolean(exitData?.is_crawler), 'danger'), true) +
					buildExitDetailRow('移动网络', buildExitStateBadge(Boolean(exitData?.is_mobile), 'bonus'), true) +
					buildExitDetailRow('卫星网络', buildExitStateBadge(Boolean(exitData?.is_satellite), 'bonus'), true) +
					buildExitDetailRow('已知滥用', buildExitStateBadge(Boolean(exitData?.is_abuser), 'danger'), true) +
					buildExitDetailRow('虚假 IP', buildExitStateBadge(Boolean(exitData?.is_bogon), 'danger'), true) +
				'</div>';
		}

		function getMetaChipIcon(iconName) {
			const icons = {
				prep: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="8"></circle><path d="M12 8v4l3 2"></path></svg>',
				location: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 21s6-4.35 6-10a6 6 0 1 0-12 0c0 5.65 6 10 6 10z"></path><circle cx="12" cy="11" r="2.5"></circle></svg>',
				network: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="6" rx="2"></rect><rect x="3" y="14" width="18" height="6" rx="2"></rect><circle cx="7" cy="7" r="1"></circle><circle cx="7" cy="17" r="1"></circle><path d="M12 10v4"></path></svg>',
				shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 5-3.4 8.74-7 10-3.6-1.26-7-5-7-10V6l7-3z"></path><path d="m9.5 12 1.7 1.7 3.3-3.7"></path></svg>',
				error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="m15 9-6 6"></path><path d="m9 9 6 6"></path></svg>',
				info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="M12 10v5"></path><circle cx="12" cy="7" r="1"></circle></svg>',
				retry: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 5v6h-6"></path><path d="M4 19v-6h6"></path><path d="M7 17a7 7 0 0 0 11-4"></path><path d="M17 7A7 7 0 0 0 6 11"></path></svg>'
			};
			return icons[iconName] || icons.info;
		}

		function buildMetaChip(text, iconName, modifierClass) {
			const className = modifierClass ? 'meta-chip ' + modifierClass : 'meta-chip';
			return '<span class="' + className + '">' + getMetaChipIcon(iconName) + '<span>' + escapeHtml(text) + '</span></span>';
		}

		function buildCopyableTarget(target) {
			const value = String(target || '');
			return '<button class="result-ip copy-target" type="button" data-copy-target="' + escapeHtml(value) + '" title="点击复制候选目标" aria-label="复制候选目标 ' + escapeHtml(value) + '">' + escapeHtml(value) + '</button>';
		}

		function normalizeBatchInputValue(value) {
			const targets = [];
			normalizeDelimitedTargetText(value).split('\\n').forEach(function (line) {
				extractTargetsFromInputLine(line).forEach(function (target) {
					targets.push(target);
				});
			});
			return uniqueTargets(targets).join('\\n');
		}

		function normalizeBatchEditingValue(value) {
			return normalizeDelimitedTargetText(value);
		}

		function stripTargetLabel(value) {
			const normalized = normalizeDelimitedTargetText(value);
			const firstLine = normalized.split('\\n')[0] || '';
			const targets = extractTargetsFromInputLine(firstLine);
			return targets[0] || normalizeProxyInput(stripInlineComment(firstLine), true);
		}

		function normalizeDelimitedTargetText(value) {
			return String(value ?? '')
				.replace(/\\r\\n?/g, '\\n')
				.replace(/[\uFF0C]/g, ',')
				.replace(/([^\\s,\\t|]+)[,\\t ]+\\s*(\\d{1,5})(?=\\s*(?:$|\\n|#|\\/\\/))/g, function (match, host, port) {
					return isValidPortValue(port) ? host + ':' + normalizePortValue(port) : match;
				})
				.replace(/,/g, '\\n')
				.replace(/\\t+/g, ' ');
		}

		function stripInlineComment(value) {
			const text = String(value || '').split('#')[0];
			for (let i = 0; i < text.length - 1; i++) {
				if (text[i] === '/' && text[i + 1] === '/' && text[i - 1] !== ':') {
					return text.slice(0, i).trim();
				}
			}
			return text.trim();
		}

		function isValidPortValue(value) {
			const text = String(value || '').trim();
			if (!/^\\d{1,5}$/.test(text)) return false;
			const port = Number(text);
			return Number.isInteger(port) && port >= 1 && port <= 65535;
		}

		function normalizePortValue(value) {
			return String(Number(String(value || '').trim()));
		}

		function trimTargetToken(value) {
			return String(value || '')
				.trim()
				.replace(/^[<({'"“‘]+/, '')
				.replace(/[>)\\}'"”’。，、；;]+$/g, '');
		}

		function extractTargetsFromInputLine(value) {
			const line = stripInlineComment(String(value || '').replace(/\uFF1A/g, ':'));
			const matches = [];
			const pattern = /[^\\s|,，;；]+/g;
			let match;
			while ((match = pattern.exec(line)) !== null) {
				addTargetMatch(line, matches, match.index, match.index + match[0].length, match[0]);
			}

			return matches
				.sort(function (left, right) { return left.index - right.index; })
				.map(function (match) { return match.target; });
		}

		function collectUrlTargetMatches(line, matches) {
			const pattern = /(?:https?|wss?|tcp|tls|socks5?|turn):\\/\\/[^\\s'"<>|]+/ig;
			let match;
			while ((match = pattern.exec(line)) !== null) {
				addTargetMatch(line, matches, match.index, match.index + match[0].length, match[0]);
			}
		}

		function collectBracketedIPv6TargetMatches(line, matches) {
			const pattern = /\\[[0-9a-fA-F:.]+\\](?::\\d{1,5})?/g;
			let match;
			while ((match = pattern.exec(line)) !== null) {
				addTargetMatch(line, matches, match.index, match.index + match[0].length, match[0]);
			}
		}

		function collectDottedTargetMatches(line, matches) {
			const pattern = /[A-Za-z0-9.-]+(?::\\d{1,5})?/g;
			let match;
			while ((match = pattern.exec(line)) !== null) {
				addTargetMatch(line, matches, match.index, match.index + match[0].length, match[0]);
			}
		}

		function collectRawIPv6TargetMatches(line, matches) {
			const pattern = /[^\\s|,，;；]+/g;
			let match;
			while ((match = pattern.exec(line)) !== null) {
				const token = trimTargetToken(match[0]);
				const colonMatches = token.match(/:/g) || [];
				if (colonMatches.length < 2 || !isClientRawIPv6(token)) continue;

				const offset = match[0].indexOf(token);
				const index = match.index + Math.max(offset, 0);
				addTargetMatch(line, matches, index, index + token.length, token);
			}
		}

		function addTargetMatch(line, matches, index, end, rawTarget) {
			if (hasTargetRangeOverlap(matches, index, end)) return;

			const target = normalizeExtractedTarget(rawTarget);
			if (!target) return;

			matches.push({ index, end, target });
		}

		function hasTargetRangeOverlap(matches, index, end) {
			return matches.some(function (match) {
				return index < match.end && end > match.index;
			});
		}

		function normalizeExtractedTarget(value) {
			return normalizeProxyInput(value, true);
		}

		function normalizeProxyInput(value, loose) {
			let token = trimTargetToken(stripInlineComment(value).replace(/\uFF1A/g, ':'));
			if (!token) return '';
			while (token.charAt(0) === '/') token = token.slice(1);
			if (!/^(?:socks5|http|https|turn):\\/\\//i.test(token)) {
				token = 'socks5://' + token;
			}
			try {
				return parseProxyUrl(token).normalized;
			} catch (error) {
				if (loose) return '';
				throw error;
			}
		}

		function getProxyDefaultPort(scheme) {
			return scheme === 'turn' ? '3478' : (scheme === 'https' ? '443' : (scheme === 'http' ? '80' : '1080'));
		}

		function parseProxyUrl(value) {
			const text = String(value || '').trim();
			const match = text.match(/^(socks5|http|https|turn):\\/\\/(.+)$/i);
			if (!match) throw new Error('只支持 socks5://、http://、https://、turn:// 代理');

			const scheme = match[1].toLowerCase();
			const defaultPort = getProxyDefaultPort(scheme);
			try {
				const parsedUrl = new URL(text);
				let host = parsedUrl.hostname || '';
				const port = parsedUrl.port || defaultPort;
				const auth = parsedUrl.username ? parsedUrl.username + ':' + parsedUrl.password : '';
				if (host.indexOf(':') !== -1 && host.charAt(0) !== '[') host = '[' + host + ']';
				return normalizeParsedProxyParts(scheme, auth, host, port);
			} catch (urlError) {
				if (urlError && /只支持|主机名|端口号/.test(urlError.message || '')) throw urlError;
			}

			let rest = match[2].split(/[/?#]/)[0].trim();
			let auth = '';
			let hostPort = rest;
			const at = rest.lastIndexOf('@');
			if (at !== -1) {
				auth = rest.slice(0, at);
				hostPort = rest.slice(at + 1);
			}

			let host = hostPort;
			let port = defaultPort;
			if (hostPort.charAt(0) === '[') {
				const close = hostPort.indexOf(']');
				if (close === -1) throw new Error('IPv6 地址缺少 ]');
				host = hostPort.slice(0, close + 1);
				if (hostPort.slice(close + 1, close + 2) === ':') port = hostPort.slice(close + 2);
			} else {
				const colonMatches = hostPort.match(/:/g) || [];
				if (colonMatches.length === 1) {
					const index = hostPort.lastIndexOf(':');
					host = hostPort.slice(0, index);
					port = hostPort.slice(index + 1);
				} else if (colonMatches.length > 1) {
					host = '[' + hostPort + ']';
				}
			}

			return normalizeParsedProxyParts(scheme, auth, host, port);
		}

		function normalizeParsedProxyParts(scheme, auth, host, port) {
			let cleanHost = trimTargetToken(host).replace(/^\\[|\\]$/g, '');
			if (!cleanHost) throw new Error('缺少代理主机名');
			if (!isClientIPv4(cleanHost) && !isClientRawIPv6(cleanHost) && !isClientDomain(cleanHost)) {
				throw new Error('代理主机名格式无效');
			}
			if (!isValidPortValue(port)) throw new Error('代理端口号无效');

			const finalHost = isClientRawIPv6(cleanHost) ? '[' + cleanHost + ']' : cleanHost;
			const normalizedPort = normalizePortValue(port);
			const normalized = scheme + '://' + (auth ? auth + '@' : '') + finalHost + ':' + normalizedPort;
			return {
				scheme: scheme,
				auth: auth,
				host: finalHost,
				hostPlain: cleanHost,
				port: normalizedPort,
				normalized: normalized
			};
		}

		function isIPv4LikeTarget(value) {
			return /^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(String(value || ''));
		}

		function isPrivateClientIPv4(value) {
			if (!isClientIPv4(value)) return false;

			const parts = String(value || '').split('.').map(function (part) { return Number(part); });
			return parts[0] === 10
				|| parts[0] === 127
				|| parts[0] === 0
				|| (parts[0] === 169 && parts[1] === 254)
				|| (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
				|| (parts[0] === 192 && parts[1] === 168);
		}

		function isClientDomain(value) {
			const labels = String(value || '').split('.');
			return labels.length >= 2
				&& /[A-Za-z]/.test(labels[labels.length - 1])
				&& labels.every(function (label) {
					return /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label);
				});
		}

		function isClientIPv4(value) {
			const parts = String(value || '').split('.');
			return parts.length === 4 && parts.every(function (part) {
				if (!/^\\d{1,3}$/.test(part)) return false;
				const num = Number(part);
				return num >= 0 && num <= 255;
			});
		}

		function isClientRawIPv6(value) {
			const text = String(value || '');
			const colonMatches = text.match(/:/g) || [];
			return colonMatches.length >= 2 && /^[0-9a-fA-F:]+$/.test(text);
		}

		function isClientIpAddress(value) {
			const host = String(value || '').replace(/^\\[|\\]$/g, '');
			return isClientIPv4(host) || isClientRawIPv6(host);
		}

		function getDirectProxyTarget(input) {
			const parsed = parseProxyUrl(input);
			return isClientIpAddress(parsed.hostPlain) ? parsed.normalized : '';
		}

		function parseResolvedTarget(target) {
			const text = String(target || '').trim();
			if (text.charAt(0) === '[') {
				const close = text.indexOf(']');
				if (close === -1) return { host: text, port: '' };
				return { host: text.slice(0, close + 1), port: text.slice(close + 2).replace(/^:/, '') };
			}
			const index = text.lastIndexOf(':');
			if (index === -1) return { host: text, port: '' };
			return { host: text.slice(0, index), port: text.slice(index + 1) };
		}

		function replaceProxyHost(proxyUrl, resolvedTarget) {
			const parsed = parseProxyUrl(proxyUrl);
			const target = parseResolvedTarget(resolvedTarget);
			return normalizeParsedProxyParts(parsed.scheme, parsed.auth, target.host, target.port || parsed.port).normalized;
		}

		function pushResolvedTargets(targetGroups, output) {
			const seenTargets = new Set();
			targetGroups.forEach(function (group) {
				group.forEach(function (target) {
					if (seenTargets.has(target)) return;
					seenTargets.add(target);
					output.push(target);
				});
			});
		}

		function uniqueTargets(targets) {
			const seenTargets = new Set();
			return targets.filter(function (target) {
				if (seenTargets.has(target)) return false;
				seenTargets.add(target);
				return true;
			});
		}

		function makeAbortError(message) {
			const error = new Error(message || '检测已停止');
			error.name = 'AbortError';
			return error;
		}

		function isRunStopped(run) {
			return !run || run.cancelled || run.controller.signal.aborted || activeRun !== run;
		}

		function throwIfRunStopped(run) {
			if (isRunStopped(run)) throw makeAbortError();
		}

		function setCheckButtonRunning(isRunning) {
			const label = checkBtn.querySelector('span');
			const hint = checkBtn.querySelector('small');
			checkBtn.disabled = false;
			checkBtn.classList.toggle('is-stop', isRunning);
			if (label) label.innerText = isRunning ? '停止检测' : '开始检测';
			if (hint) hint.innerText = isRunning ? 'Stop' : 'Resolve + Check';
		}

		function stopActiveRun() {
			if (!activeRun || isRunStopped(activeRun)) return;
			activeRun.cancelled = true;
			activeRun.controller.abort();
			progressText.innerText = '正在停止检测...';
			setAppState('stopped');
		}

		function splitIntoChunks(items, size) {
			const chunks = [];
			for (let i = 0; i < items.length; i += size) {
				chunks.push(items.slice(i, i + size));
			}
			return chunks;
		}

		async function fetchJsonWithTimeout(resource, options, timeoutMs, signal) {
			const controller = new AbortController();
			const timer = window.setTimeout(function () {
				controller.abort();
			}, timeoutMs);
			const abortFromSignal = function () {
				controller.abort();
			};
			if (signal) {
				if (signal.aborted) controller.abort();
				else signal.addEventListener('abort', abortFromSignal, { once: true });
			}

			try {
				const response = await fetch(resource, Object.assign({}, options || {}, {
					signal: controller.signal
				}));
				let payload = null;
				try {
					payload = await response.json();
				} catch (error) {
					if (response.ok) {
						throw error;
					}
				}
				return { response, payload };
			} finally {
				window.clearTimeout(timer);
				if (signal) signal.removeEventListener('abort', abortFromSignal);
			}
		}

		function updateResolveBatchProgress(batchIndex, totalBatches, attempt) {
			const retryText = attempt > 1
				? '，第 ' + attempt + ' 次尝试'
				: '';
			progressText.innerText = '正在解析目标... 第 ' + batchIndex + ' / ' + totalBatches + ' 批' + retryText;
		}

		function applyResolveBatchPayload(batch, payload) {
			const results = payload && Array.isArray(payload.results) ? payload.results : null;
			if (!results) {
				throw new Error('Invalid resolve batch response');
			}

			results.forEach(function (result, index) {
				const job = batch[index];
				if (!job) return;

				if (result && Array.isArray(result.targets)) {
					result.targets.forEach(function (target) {
						job.group.push(replaceProxyHost(job.line, target));
					});
				}

				if (result && result.error) {
					console.warn('Resolve skipped for', job.line, result.error);
				}
			});
		}

		async function requestResolveBatch(batch, run) {
			throwIfRunStopped(run);
			const payload = {
				targets: batch.map(function (job) { return job.line; })
			};
			const result = await fetchJsonWithTimeout('/resolve-batch', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify(payload)
			}, RESOLVE_BATCH_TIMEOUT_MS, run?.controller.signal);

			if (!result.response.ok) {
				const errorMessage = result.payload && result.payload.error
					? result.payload.error
					: 'Resolve batch failed with status ' + result.response.status;
				throw new Error(errorMessage);
			}

			applyResolveBatchPayload(batch, result.payload);
		}

		async function resolveBatchWithRetry(batch, batchIndex, totalBatches, run) {
			for (let attempt = 1; attempt <= RESOLVE_BATCH_MAX_ATTEMPTS; attempt++) {
				throwIfRunStopped(run);
				updateResolveBatchProgress(batchIndex, totalBatches, attempt);

				try {
					await requestResolveBatch(batch, run);
					return true;
				} catch (error) {
					if (isRunStopped(run)) throw error;
					const label = error && error.name === 'AbortError'
						? 'Resolve batch timeout'
						: 'Resolve batch error';

					if (attempt >= RESOLVE_BATCH_MAX_ATTEMPTS) {
						console.error(label + ', abandoned batch', batch.map(function (job) { return job.line; }), error);
						return false;
					}

					console.warn(label + ', retrying batch', batch.map(function (job) { return job.line; }), error);
				}
			}

			return false;
		}

		async function resolveBatchJobs(resolveJobs, run) {
			const batches = splitIntoChunks(resolveJobs, RESOLVE_BATCH_SIZE);
			let failedBatchCount = 0;

			for (let index = 0; index < batches.length; index++) {
				throwIfRunStopped(run);
				const resolved = await resolveBatchWithRetry(batches[index], index + 1, batches.length, run);
				if (!resolved) {
					failedBatchCount++;
				}
			}

			if (failedBatchCount > 0) {
				console.warn('Resolve batches abandoned:', failedBatchCount);
			}
		}

		async function resolveSingleJob(job, run) {
			for (let attempt = 1; attempt <= RESOLVE_BATCH_MAX_ATTEMPTS; attempt++) {
				throwIfRunStopped(run);
				try {
					const result = await fetchJsonWithTimeout('/resolve?proxyip=' + encodeURIComponent(job.line), {}, RESOLVE_BATCH_TIMEOUT_MS, run?.controller.signal);
					if (!result.response.ok) {
						console.error('Resolve error for', job.line, result.payload || result.response.status);
						return false;
					}

					if (Array.isArray(result.payload)) {
						result.payload.forEach(function (target) {
							job.group.push(replaceProxyHost(job.line, target));
						});
					}
					return true;
				} catch (error) {
					if (isRunStopped(run)) throw error;
					if (attempt >= RESOLVE_BATCH_MAX_ATTEMPTS) {
						console.error('Resolve timeout for', job.line, error);
						return false;
					}
					console.warn('Resolve timeout for ' + job.line + ', retrying', error);
				}
			}

			return false;
		}

		async function runWithConcurrency(items, limit, worker, run) {
			let nextIndex = 0;
			const workerCount = Math.min(Math.max(Number(limit) || 1, 1), items.length);
			const runners = [];

			async function runNext() {
				while (nextIndex < items.length && !isRunStopped(run)) {
					const currentIndex = nextIndex++;
					await worker(items[currentIndex], currentIndex);
				}
			}

			for (let i = 0; i < workerCount; i++) {
				runners.push(runNext());
			}

			await Promise.all(runners);
		}

		function normalizeBatchInputControl(control) {
			if (!control || control.tagName !== 'TEXTAREA') return;

			const rawValue = control.value;
			const nextValue = normalizeBatchEditingValue(rawValue);

			if (nextValue === rawValue) return;

			const selectionStart = control.selectionStart ?? rawValue.length;
			const selectionEnd = control.selectionEnd ?? rawValue.length;
			const nextSelectionStart = normalizeBatchEditingValue(rawValue.slice(0, selectionStart)).length;
			const nextSelectionEnd = normalizeBatchEditingValue(rawValue.slice(0, selectionEnd)).length;

			control.value = nextValue;
			control.setSelectionRange(nextSelectionStart, nextSelectionEnd);
		}

		function bindInputShortcut() {
			inputList.addEventListener('input', function () {
				if (!batchMode.checked) return;
				normalizeBatchInputControl(inputList);
			});

			inputList.addEventListener('keydown', function (event) {
				const shouldRunSingle = !batchMode.checked && event.key === 'Enter';
				const shouldRunBatch = batchMode.checked && event.key === 'Enter' && (event.ctrlKey || event.metaKey);

				if (shouldRunSingle || shouldRunBatch) {
					event.preventDefault();
					if (!activeRun) checkBtn.click();
				}
			});
		}

		function setModeVisuals(isBatch) {
			modeLabel.innerText = isBatch ? 'Batch / 多目标' : 'Single / 单目标';
			fieldHint.innerText = isBatch
				? '批量模式下每行一个目标，按 Ctrl + Enter 可以直接开始检测。'
				: '单条模式支持历史快速回填，按 Enter 可以直接开始检测。';
		}

		function showEmptyState(title, description) {
			emptyStateTitle.innerText = title;
			emptyStateDescription.innerText = description;
			resultsEmpty.style.display = 'grid';
		}

		function hideEmptyState() {
			resultsEmpty.style.display = 'none';
		}

		function setAppState(nextState) {
			appState = nextState;
			renderDashboard();
		}

		function renderDashboard() {
			const failCount = Math.max(completedCount - successCount, 0);
			const pendingCount = Math.max(totalTargets - completedCount, 0);

			statTotal.innerText = String(totalTargets);
			statSuccess.innerText = String(successCount);
			statPending.innerText = String(pendingCount);
			statFailed.innerText = String(failCount);

			let headline = '等待输入';
			let description = '当前阶段、实时统计。';
			let meta = '结果、落地 IP 和地图会在这里按检测进度逐步展开。';
			let pillText = 'Idle';

			if (appState === 'resolving') {
				headline = '正在解析目标';
				description = '已接收 ' + inputCount + ' 条输入，正在展开为可检测地址。';
				meta = '解析阶段进行中，准备把输入转换为候选目标。';
				pillText = 'Resolving';
			} else if (appState === 'running') {
				headline = '正在检测 ' + totalTargets + ' 个目标';
				description = '已完成 ' + completedCount + ' 个，当前有效 ' + successCount + ' 个。';
				meta = completedCount + ' / ' + totalTargets + ' 已完成，结果会持续追加。';
				pillText = 'Running';
			} else if (appState === 'done') {
				headline = '检测完成';
				description = '有效 ' + successCount + ' / ' + totalTargets + '，失败 ' + failCount + '。';
				meta = '本轮检测已结束，点击落地 IP 可展开地图详情。';
				pillText = 'Completed';
			} else if (appState === 'empty') {
				headline = '未解析到可检测目标';
				description = '请检查域名、IP 或端口格式后重新尝试。';
				meta = '这次输入没有得到有效候选目标。';
				pillText = 'Empty';
			} else if (appState === 'error') {
				headline = '检测过程中出现错误';
				description = '请求被中断或远端接口异常，可以稍后再试。';
				meta = '运行中断，结果可能不完整。';
				pillText = 'Error';
			} else if (appState === 'stopped') {
				headline = '检测已停止';
				description = '已完成 ' + completedCount + ' / ' + totalTargets + '，有效 ' + successCount + ' 个。';
				meta = '本轮检测已手动停止，未开始的任务不会继续请求。';
				pillText = 'Stopped';
			}

			summaryHeadline.innerText = headline;
			summaryDescription.innerText = description;
			resultMeta.innerText = meta;
			resultPill.innerText = pillText;
			resultPill.className = 'results-pill state-' + appState;
		}

		function updateProgress() {
			const percent = totalTargets > 0 ? Math.round((completedCount / totalTargets) * 100) : 0;
			progressBar.style.width = percent + '%';
			progressText.innerText = completedCount + ' / ' + totalTargets;
			renderDashboard();
		}

		function resetResultFilters() {
			resultRecords = [];
			activePrimaryFilter = 'all';
			activeProtocolFilters = getDefaultProtocolFilters();
			activeCountryFilter = 'all';
			isFilterPanelExpanded = false;
			updateResultFilters();
		}

		function getDefaultProtocolFilters() {
			return PROTOCOL_RESULT_FILTERS.map(function (filter) {
				return filter.key;
			});
		}

		function normalizeProxyType(value) {
			const type = String(value || '').trim().toLowerCase();
			return type === 'socks5' || type === 'http' || type === 'https' || type === 'turn' ? type : '';
		}

		function getProxyTypeFromTarget(target) {
			try {
				return normalizeProxyType(parseProxyUrl(target).scheme);
			} catch {
				return '';
			}
		}

		function createResultRecord(target, itemObj) {
			const record = {
				target: target,
				el: itemObj.el,
				status: 'pending',
				proxyType: getProxyTypeFromTarget(target),
				riskLevels: [],
				countries: [],
				data: null,
				exitIps: []
			};
			resultRecords.push(record);
			itemObj.record = record;
			if (!isCreatingResultBatch) {
				updateResultFilters();
			}
			return record;
		}

		function normalizeCountryFilterKey(value) {
			const text = String(value || '').trim();
			if (!text) return '';
			return /^[a-z]{2}$/i.test(text) ? text.toUpperCase() : text;
		}

		function getExitCountryFilterKey(exitData) {
			const candidates = [
				exitData?.country,
				exitData?.countryCode,
				exitData?.country_code,
				exitData?.countryIsoCode,
				exitData?.country_iso_code
			];

			for (const candidate of candidates) {
				const normalized = normalizeCountryFilterKey(candidate);
				if (/^[A-Z]{2}$/.test(normalized)) {
					return normalized;
				}
			}

			for (const candidate of candidates) {
				const normalized = normalizeCountryFilterKey(candidate);
				if (normalized) {
					return normalized;
				}
			}

			return '';
		}

		function getCountryFilterKeys(exitIps, stackName) {
			const countries = [];
			exitIps.forEach(function (entry) {
				if (stackName && entry.stack !== stackName) return;
				const country = getExitCountryFilterKey(entry.exitData);
				if (country && !countries.includes(country)) {
					countries.push(country);
				}
			});
			return countries;
		}

		function updateResultRecordAsSuccess(record, data, exitIps) {
			if (!record) return;
			record.status = 'success';
			record.proxyType = normalizeProxyType(data?.type) || getProxyTypeFromTarget(record.target);
			record.riskLevels = getRiskFilterKeys(exitIps);
			record.countries = getCountryFilterKeys(exitIps);
			record.data = data || null;
			record.exitIps = Array.isArray(exitIps) ? exitIps : [];
		}

		function updateResultRecordAsError(record, data) {
			if (!record) return;
			record.status = 'error';
			record.proxyType = normalizeProxyType(data?.type) || getProxyTypeFromTarget(record.target);
			record.riskLevels = [];
			record.countries = [];
			record.data = data || null;
			record.exitIps = [];
		}

		function getRiskFilterByKey(filterKey) {
			return RISK_RESULT_FILTERS.find(function (filter) {
				return filter.key === filterKey;
			}) || null;
		}

		function getRiskFilterKeyFromLevel(level) {
			const filter = RISK_RESULT_FILTERS.find(function (entry) {
				return entry.label === level;
			});
			return filter ? filter.key : '';
		}

		function getExitRiskFilterKey(exitData) {
			return getRiskFilterKeyFromLevel(getExitRiskMeta(calculateExitRiskScore(exitData)).level);
		}

		function getRiskFilterSeverity(filterKey) {
			return RISK_RESULT_FILTERS.findIndex(function (filter) {
				return filter.key === filterKey;
			});
		}

		function getHighestExitRiskChipModifier(exitIps) {
			let highestRiskKey = '';
			(Array.isArray(exitIps) ? exitIps : []).forEach(function (entry) {
				const riskKey = getExitRiskFilterKey(entry?.exitData);
				if (riskKey && getRiskFilterSeverity(riskKey) > getRiskFilterSeverity(highestRiskKey)) {
					highestRiskKey = riskKey;
				}
			});
			return highestRiskKey ? 'meta-chip-risk risk-' + highestRiskKey : 'meta-chip-strong';
		}

		function getRiskFilterKeys(exitIps) {
			const riskLevels = [];
			(Array.isArray(exitIps) ? exitIps : []).forEach(function (entry) {
				const riskKey = getExitRiskFilterKey(entry?.exitData);
				if (riskKey && !riskLevels.includes(riskKey)) {
					riskLevels.push(riskKey);
				}
			});
			return riskLevels;
		}

		function isRiskPrimaryFilter(filterKey) {
			return Boolean(getRiskFilterByKey(filterKey));
		}

		function doesRecordMatchPrimaryFilter(record, filterKey) {
			if (filterKey === 'success') {
				return record.status === 'success';
			}
			if (filterKey === 'failed') {
				return record.status === 'error';
			}
			if (isRiskPrimaryFilter(filterKey)) {
				return record.status === 'success' && record.riskLevels.includes(filterKey);
			}
			return true;
		}

		function getRecordCountryKeys(record, filterKey) {
			if (isRiskPrimaryFilter(filterKey)) {
				const countries = [];
				record.exitIps.forEach(function (entry) {
					if (getExitRiskFilterKey(entry?.exitData) !== filterKey) return;
					const country = getExitCountryFilterKey(entry?.exitData);
					if (country && !countries.includes(country)) {
						countries.push(country);
					}
				});
				return countries;
			}
			return record.countries;
		}

		function doesRecordMatchCountryFilter(record, countryKey, filterKey) {
			return countryKey === 'all' || getRecordCountryKeys(record, filterKey).includes(countryKey);
		}

		function getPrimaryFilteredRecords(filterKey) {
			return resultRecords.filter(function (record) {
				return doesRecordMatchPrimaryFilter(record, filterKey);
			});
		}

		function doesRecordMatchProtocolFilter(record, protocolKey) {
			return record.proxyType === protocolKey;
		}

		function doesRecordMatchProtocolFilters(record) {
			return activeProtocolFilters.includes(record.proxyType);
		}

		function getProtocolFilteredRecords(records) {
			return records.filter(function (record) {
				return doesRecordMatchProtocolFilters(record);
			});
		}

		function toggleProtocolFilter(protocolKey) {
			if (!PROTOCOL_RESULT_FILTERS.some(function (filter) { return filter.key === protocolKey; })) return;
			const nextFilters = activeProtocolFilters.includes(protocolKey)
				? activeProtocolFilters.filter(function (key) { return key !== protocolKey; })
				: activeProtocolFilters.concat(protocolKey);
			activeProtocolFilters = PROTOCOL_RESULT_FILTERS
				.map(function (filter) { return filter.key; })
				.filter(function (key) { return nextFilters.includes(key); });
		}

		function getCountryFilterOptions(baseRecords, filterKey) {
			const countryCounts = new Map();
			baseRecords.forEach(function (record) {
				getRecordCountryKeys(record, filterKey).forEach(function (country) {
					countryCounts.set(country, (countryCounts.get(country) || 0) + 1);
				});
			});

			const options = [{ key: 'all', label: '全部', count: baseRecords.length }];
			Array.from(countryCounts.entries())
				.sort(function (left, right) {
					return right[1] - left[1] || left[0].localeCompare(right[0]);
				})
				.forEach(function (entry) {
					options.push({ key: entry[0], label: entry[0], count: entry[1] });
				});
			return options;
		}

		function getRiskFilterChipClass(filterKey) {
			return isRiskPrimaryFilter(filterKey) ? 'filter-chip-risk risk-' + filterKey : '';
		}

		function renderFilterChip(attributeName, key, label, count, isActive, isDisabled, extraClass) {
			const className = 'filter-chip'
				+ (extraClass ? ' ' + extraClass : '')
				+ (isActive ? ' is-active' : '')
				+ (isDisabled ? ' is-disabled' : '');
			const disabledAttribute = isDisabled ? ' disabled aria-disabled="true"' : '';
			return '<button type="button" class="' + className + '" data-' + attributeName + '="' + escapeHtml(key) + '" aria-pressed="' + String(isActive) + '"' + disabledAttribute + '>'
				+ escapeHtml(label + '(' + count + ')')
				+ '</button>';
		}

		function applyResultFilters() {
			let visibleCount = 0;
			resultRecords.forEach(function (record) {
				const shouldShow = doesRecordMatchPrimaryFilter(record, activePrimaryFilter)
					&& doesRecordMatchProtocolFilters(record)
					&& doesRecordMatchCountryFilter(record, activeCountryFilter, activePrimaryFilter);
				record.el.hidden = !shouldShow;
				if (shouldShow) {
					visibleCount++;
				}
			});
			return visibleCount;
		}

		function getPrimaryFilterLabel(filterKey) {
			const filter = PRIMARY_RESULT_FILTERS.find(function (entry) {
				return entry.key === filterKey;
			});
			return filter ? filter.label : '全部';
		}

		function areAllProtocolFiltersActive() {
			return activeProtocolFilters.length === PROTOCOL_RESULT_FILTERS.length
				&& PROTOCOL_RESULT_FILTERS.every(function (filter) {
					return activeProtocolFilters.includes(filter.key);
				});
		}

		function getProtocolFilterLabel() {
			if (!activeProtocolFilters.length) return '协议：未选择';
			return '协议：' + PROTOCOL_RESULT_FILTERS
				.filter(function (filter) {
					return activeProtocolFilters.includes(filter.key);
				})
				.map(function (filter) {
					return filter.label;
				})
				.join(' / ');
		}

		function getFilterToggleLabel(visibleCount) {
			const activeParts = [];
			if (activePrimaryFilter !== 'all') {
				activeParts.push(getPrimaryFilterLabel(activePrimaryFilter));
			}
			if (!areAllProtocolFiltersActive()) {
				activeParts.push(getProtocolFilterLabel());
			}
			if (activeCountryFilter !== 'all') {
				activeParts.push(activeCountryFilter);
			}

			if (!activeParts.length) {
				return '筛选：全部结果';
			}

			return '筛选：' + activeParts.join(' · ') + ' (' + visibleCount + ')';
		}

		function updateFilterPanelState(visibleCount) {
			if (!filterToggle || !filterPanel || !filterToggleText) return;
			filterPanel.hidden = !isFilterPanelExpanded;
			filterToggle.setAttribute('aria-expanded', String(isFilterPanelExpanded));
			filterToggleText.innerText = getFilterToggleLabel(visibleCount);
		}

		function updateResultFilters() {
			if (!resultsFilters || !filterToggle || !filterPanel || !filterToggleText || !primaryFilterGroup || !protocolFilterGroup || !countryFilterGroup || !filterEmpty) return;

			if (!resultRecords.length) {
				resultsFilters.hidden = true;
				filterPanel.hidden = true;
				filterToggle.setAttribute('aria-expanded', 'false');
				filterToggleText.innerText = '筛选：全部结果';
				filterEmpty.hidden = true;
				return;
			}

			resultsFilters.hidden = false;
			primaryFilterGroup.innerHTML = PRIMARY_RESULT_FILTERS.map(function (filter) {
				const count = getPrimaryFilteredRecords(filter.key).length;
				const isActive = activePrimaryFilter === filter.key;
				return renderFilterChip('primary-filter', filter.key, filter.label, count, isActive, count === 0 && !isActive, getRiskFilterChipClass(filter.key));
			}).join('');

			const primaryRecords = getPrimaryFilteredRecords(activePrimaryFilter);
			protocolFilterGroup.innerHTML = PROTOCOL_RESULT_FILTERS.map(function (filter) {
				const count = primaryRecords.filter(function (record) {
					return doesRecordMatchProtocolFilter(record, filter.key);
				}).length;
				const isActive = activeProtocolFilters.includes(filter.key);
				return renderFilterChip('protocol-filter', filter.key, filter.label, count, isActive, count === 0 && !isActive);
			}).join('');

			const baseRecords = getProtocolFilteredRecords(primaryRecords);
			const countryOptions = getCountryFilterOptions(baseRecords, activePrimaryFilter);
			if (activeCountryFilter !== 'all' && !countryOptions.some(function (option) { return option.key === activeCountryFilter; })) {
				activeCountryFilter = 'all';
			}

			countryFilterGroup.innerHTML = countryOptions.map(function (option) {
				return renderFilterChip('country-filter', option.key, option.label, option.count, activeCountryFilter === option.key);
			}).join('');

			const visibleCount = applyResultFilters();
			updateFilterPanelState(visibleCount);
			filterEmpty.hidden = visibleCount !== 0;
		}

		function getCurrentFilteredRecords() {
			return resultRecords.filter(function (record) {
				return doesRecordMatchPrimaryFilter(record, activePrimaryFilter)
					&& doesRecordMatchProtocolFilters(record)
					&& doesRecordMatchCountryFilter(record, activeCountryFilter, activePrimaryFilter);
			});
		}

		function getExportableRecords() {
			return getCurrentFilteredRecords().filter(function (record) {
				return record.status === 'success' && Boolean(record.data);
			});
		}

		function normalizeExportValue(value) {
			if (value === undefined || value === null) {
				return '';
			}
			return String(value).trim();
		}

		function getNestedExportValue(source, path) {
			const parts = path.split('.');
			let current = source;
			for (const part of parts) {
				if (current === undefined || current === null || !Object.prototype.hasOwnProperty.call(current, part)) {
					return '';
				}
				current = current[part];
			}
			return normalizeExportValue(current);
		}

		function getProbeForTextExport(data, stackName) {
			const probe = data?.probe_results?.[stackName];
			return probe?.ok && probe.exit ? probe : null;
		}

		function getTextExportProbeCandidates(data) {
			return [getProbeForTextExport(data, 'ipv6'), getProbeForTextExport(data, 'ipv4')].filter(Boolean);
		}

		function doesProbeMatchActiveRiskFilter(probe) {
			return !isRiskPrimaryFilter(activePrimaryFilter) || getExitRiskFilterKey(probe.exit) === activePrimaryFilter;
		}

		function doesProbeMatchActiveCountryFilter(probe) {
			return activeCountryFilter === 'all' || getExitCountryFilterKey(probe.exit) === activeCountryFilter;
		}

		function getPreferredTextExportProbe(data) {
			const candidates = getTextExportProbeCandidates(data);
			const exactMatchedProbe = candidates.find(function (probe) {
				return doesProbeMatchActiveRiskFilter(probe) && doesProbeMatchActiveCountryFilter(probe);
			});
			if (exactMatchedProbe) {
				return exactMatchedProbe;
			}
			if (activeCountryFilter !== 'all') {
				const countryMatchedProbe = candidates.find(function (probe) {
					return getExitCountryFilterKey(probe.exit) === activeCountryFilter;
				});
				if (countryMatchedProbe) {
					return countryMatchedProbe;
				}
			}
			if (isRiskPrimaryFilter(activePrimaryFilter)) {
				const riskMatchedProbe = candidates.find(function (probe) {
					return getExitRiskFilterKey(probe.exit) === activePrimaryFilter;
				});
				if (riskMatchedProbe) {
					return riskMatchedProbe;
				}
			}
			return candidates[0] || null;
		}

		function getTextExportTarget(data) {
			const link = normalizeExportValue(data?.link).split('#')[0].trim();
			if (link) return link;

			const proxyIP = normalizeExportValue(data?.proxyIP);
			const portRemote = normalizeExportValue(data?.portRemote);
			if (!proxyIP || !portRemote) {
				return '';
			}

			const type = normalizeProxyType(data?.type) || 'socks5';
			const exportHost = isClientRawIPv6(proxyIP) ? '[' + proxyIP + ']' : proxyIP;
			return type + '://' + exportHost + ':' + portRemote;
		}

		function buildTextExportTypeTag(exitData) {
			const typeParts = [
				exitData?.company?.type,
				exitData?.asnInfo?.type
			].map(function (type) {
				return normalizeExportValue(formatExitIpType(type));
			}).filter(function (type) {
				return type && type !== '未知';
			});
			return typeParts.length ? '[' + typeParts.join('/') + ']' : '';
		}

		function buildTextExportRiskTag(exitData) {
			const riskText = normalizeExportValue(formatExitRiskText(exitData));
			return riskText && riskText !== '未知' ? '[' + riskText + ']' : '';
		}

		function buildTextExportLine(data) {
			const exportTarget = getTextExportTarget(data);
			if (!exportTarget) return '';

			const exitData = getPreferredTextExportProbe(data)?.exit || {};
			const country = normalizeExportValue(exitData.country);
			const city = normalizeExportValue(exitData.city);
			const asn = normalizeExportValue(exitData.asn);
			const asOrganization = normalizeExportValue(exitData.asOrganization);
			const locationSegment = [country, city].filter(Boolean).join(' ') + buildTextExportTypeTag(exitData);
			const networkSegment = [asn ? 'AS' + asn : '', asOrganization].filter(Boolean).join(' ') + buildTextExportRiskTag(exitData);
			const description = [locationSegment, networkSegment].filter(Boolean).join(' ');
			return exportTarget + (description ? '#' + description : '');
		}

		function buildTextExport(records) {
			return records.map(function (record) {
				return buildTextExportLine(record.data);
			}).filter(Boolean).join('\\n');
		}

		function escapeCsvValue(value) {
			const text = normalizeExportValue(value);
			if (!/[",\\r\\n]/.test(text)) {
				return text;
			}
			return '"' + text.replace(/"/g, '""') + '"';
		}

		function buildCsvExport(records) {
			const headerLine = EXPORT_CSV_COLUMNS.map(function (column) {
				return escapeCsvValue(column.header);
			}).join(',');
			const rows = records.map(function (record) {
				return EXPORT_CSV_COLUMNS.map(function (column) {
					return escapeCsvValue(getNestedExportValue(record?.data, column.path));
				}).join(',');
			});
			return [headerLine].concat(rows).join('\\n');
		}

		function padExportDatePart(value) {
			return String(value).padStart(2, '0');
		}

		function formatExportTimestamp(date) {
			const current = date || new Date();
			return current.getFullYear()
				+ '-' + padExportDatePart(current.getMonth() + 1)
				+ '-' + padExportDatePart(current.getDate())
				+ ' ' + padExportDatePart(current.getHours())
				+ padExportDatePart(current.getMinutes())
				+ padExportDatePart(current.getSeconds());
		}

		function getExportFileLabel() {
			const fallbackText = getFilterToggleLabel(getCurrentFilteredRecords().length);
			const rawText = String(filterToggleText?.innerText || fallbackText || '').trim();
			const label = rawText.replace(/^筛选：\\s*/, '').trim() || '全部结果';
			return label.replace(/[\\\\/:*?"<>|]/g, '_').replace(/\\s+/g, ' ').trim() || '全部结果';
		}

		function getExportFileName(extension) {
			return getExportFileLabel() + ' ' + formatExportTimestamp(new Date()) + '.' + extension;
		}

		function downloadTextFile(content, filename, mimeType) {
			const blob = new Blob([content], { type: mimeType + ';charset=utf-8' });
			const url = URL.createObjectURL(blob);
			const link = document.createElement('a');
			link.href = url;
			link.download = filename;
			link.style.display = 'none';
			document.body.appendChild(link);
			link.click();
			link.remove();
			window.setTimeout(function () {
				URL.revokeObjectURL(url);
			}, 1000);
		}

		async function writeTextToClipboard(text) {
			if (navigator.clipboard && window.isSecureContext) {
				await navigator.clipboard.writeText(text);
				return;
			}

			const textArea = document.createElement('textarea');
			textArea.value = text;
			textArea.setAttribute('readonly', '');
			textArea.style.position = 'fixed';
			textArea.style.top = '-1000px';
			textArea.style.left = '-1000px';
			document.body.appendChild(textArea);
			textArea.select();
			const didCopy = document.execCommand('copy');
			textArea.remove();
			if (!didCopy) {
				throw new Error('Clipboard copy command failed');
			}
		}

		function showExportToast(message, tone) {
			let toast = document.getElementById('exportToast');
			if (!toast) {
				toast = document.createElement('div');
				toast.id = 'exportToast';
				toast.className = 'export-toast';
				toast.setAttribute('role', 'status');
				toast.setAttribute('aria-live', 'polite');
				document.body.appendChild(toast);
			}

			toast.hidden = false;
			toast.innerText = message;
			toast.className = tone === 'error' ? 'export-toast is-error is-visible' : 'export-toast is-visible';
			window.clearTimeout(exportToastTimer);
			exportToastTimer = window.setTimeout(function () {
				toast.classList.remove('is-visible');
				window.setTimeout(function () {
					toast.hidden = true;
				}, 240);
			}, 2400);
		}

		function showToast(message, tone) {
			showExportToast(message, tone);
		}

		async function handleCopyTargetClick(event) {
			const button = event.target.closest('[data-copy-target]');
			if (!button || !resultsDiv.contains(button)) return;

			event.preventDefault();
			const target = button.dataset.copyTarget || button.innerText.trim();
			if (!target) return;

			try {
				await writeTextToClipboard(target);
				showToast('已复制候选目标：' + target);
			} catch (error) {
				console.error('Failed to copy candidate target', error);
				showToast('复制失败，请检查浏览器权限', 'error');
			}
		}

		async function handleExport(format) {
			const records = getExportableRecords();
			if (!records.length) {
				showExportToast('当前筛选没有可导出的有效结果', 'error');
				return;
			}

			try {
				if (format === 'csv') {
					downloadTextFile('\\ufeff' + buildCsvExport(records), getExportFileName('csv'), 'text/csv');
					showExportToast('已开始下载 CSV 文件');
					return;
				}

				const textContent = buildTextExport(records);
				if (!textContent) {
					showExportToast('当前筛选没有可导出的 TXT 内容', 'error');
					return;
				}

				if (format === 'clipboard') {
					await writeTextToClipboard(textContent);
					showExportToast('已经将结果导出到了粘贴板');
					return;
				}

				if (format === 'txt') {
					downloadTextFile(textContent, getExportFileName('txt'), 'text/plain');
					showExportToast('已开始下载 TXT 文件');
				}
			} catch (error) {
				console.error('Failed to export results', error);
				showExportToast(format === 'clipboard' ? '粘贴板写入失败，请检查浏览器权限' : '导出失败，请稍后重试', 'error');
			}
		}

		function getHistory() {
			try {
				const parsed = JSON.parse(localStorage.getItem('cf_proxy_history') || '[]');
				return Array.isArray(parsed) ? parsed : [];
			} catch {
				return [];
			}
		}

		function saveHistory(value) {
			if (!value || value.includes('\\n')) return;
			let history = getHistory();
			history = history.filter(function (item) {
				return item !== value;
			});
			history.unshift(value);
			history = history.slice(0, 10);
			localStorage.setItem('cf_proxy_history', JSON.stringify(history));
			renderHistory();
		}

		function selectHistory(value) {
			inputList.value = value;
			historyDropdown.style.display = 'none';
			inputList.focus();
		}

		function renderHistory() {
			const history = getHistory();
			historyDropdown.innerHTML = '';

			if (!history.length) {
				const emptyItem = document.createElement('button');
				emptyItem.type = 'button';
				emptyItem.className = 'history-item is-empty';
				emptyItem.innerText = '暂无历史记录';
				historyDropdown.appendChild(emptyItem);
				return;
			}

			history.forEach(function (item) {
				const button = document.createElement('button');
				button.type = 'button';
				button.className = 'history-item';
				button.innerText = item;
				button.addEventListener('click', function () {
					selectHistory(item);
				});
				historyDropdown.appendChild(button);
			});
		}

		function createInputControl(isBatch, value) {
			let control;

			if (isBatch) {
				control = document.createElement('textarea');
				control.placeholder = '每行一个代理，例如：\\nsocks5://user:pass@proxy.example.com:1080\\nhttp://1.1.1.1:8080\\nturn://45.12.4.226:3478';
			} else {
				control = document.createElement('input');
				control.type = 'text';
				control.placeholder = '例如：turn://45.12.4.226:3478';
			}

			control.id = 'inputList';
			control.className = 'input-control';
			control.value = isBatch ? normalizeBatchInputValue(value || '') : (value || '');
			return control;
		}

		function swapInputMode(isBatch) {
			const currentValue = inputList.value;
			const nextValue = isBatch ? currentValue : currentValue.split('\\n')[0];
			const nextControl = createInputControl(isBatch, nextValue);

			inputContainer.innerHTML = '';
			inputContainer.appendChild(nextControl);

			if (!isBatch) {
				inputContainer.appendChild(historyBtn);
				inputContainer.appendChild(historyDropdown);
			}

			inputList = nextControl;
			historyDropdown.style.display = 'none';
			setModeVisuals(isBatch);
			bindInputShortcut();
		}

		function formatLatency(value) {
			if (value === undefined || value === null || value === '') {
				return '延迟未知';
			}
			const text = String(value);
			return text.includes('ms') ? text : text + ' ms';
		}

		function getLatencyTooltipText(data) {
			const coloCode = normalizeColoCode(data?.colo || data?.exit?.colo);
			const coloText = coloCode ? 'Cloudflare ' + coloCode + ' 机房' : 'Cloudflare 测试机房';
			return '这个延迟不是你到代理的延迟，而是 ' + coloText + ' 到代理的检测延迟。';
		}

		function setLatencyTooltip(badge, data, latencyText) {
			if (!badge) return;
			const tooltipText = getLatencyTooltipText(data);
			badge.dataset.tooltip = tooltipText;
			badge.setAttribute('aria-label', latencyText + '。' + tooltipText);
		}

		function joinUniqueValues(values, fallback) {
			const uniqueValues = Array.from(new Set(values.filter(Boolean)));
			return uniqueValues.length ? uniqueValues.join(' / ') : fallback;
		}

		function formatExitLocation(exitData) {
			const country = String(firstNonEmpty(exitData?.country, exitData?.countryCode, exitData?.country_code, exitData?.countryName, exitData?.location?.country) || '').trim();
			const city = String(firstNonEmpty(exitData?.city, exitData?.location?.city) || '').trim();
			return [country, city].filter(Boolean).join(' · ');
		}

		function formatExitNetwork(exitData) {
			const asn = String(exitData?.asn || '').trim();
			const organization = String(exitData?.asOrganization || '').trim();

			if (asn && organization) {
				return 'AS' + asn + ' · ' + organization;
			}

			if (asn) {
				return 'AS' + asn;
			}

			return organization;
		}

		function getExitCountryCode(exitData) {
			const candidates = [
				exitData?.countryCode,
				exitData?.country_code,
				exitData?.countryIsoCode,
				exitData?.country_iso_code,
				exitData?.country
			];

			for (const candidate of candidates) {
				const normalized = String(candidate || '').trim().toLowerCase();
				if (/^[a-z]{2}$/.test(normalized)) {
					return normalized;
				}
			}

			return '';
		}

		function getFlagUrlFromExitIps(exitIps) {
			for (const entry of exitIps) {
				const countryCode = getExitCountryCode(entry.exitData);
				if (countryCode) {
					return 'https://ipdata.co/flags/' + countryCode + '.png';
				}
			}

			return '';
		}

		function updateResultFlag(itemObj, flagUrl) {
			if (!itemObj?.flag) return;

			if (flagUrl) {
				itemObj.el.classList.add('has-flag');
				itemObj.flag.style.backgroundImage = 'url("' + flagUrl + '")';
				return;
			}

			itemObj.el.classList.remove('has-flag');
			itemObj.flag.style.backgroundImage = '';
		}

		function getExitSelectionKey(exitData, fallbackIp) {
			return [
				String(exitData?.ip || fallbackIp || '').trim(),
				String(exitData?.ipType || '').trim().toLowerCase(),
				normalizeColoCode(exitData?.colo),
				String(exitData?.loc || '').trim()
			].join('|');
		}

		function renderExitList(container, exitIps) {
			container.innerHTML = '';

			if (!exitIps.length) {
				const note = document.createElement('span');
				note.className = 'result-detail is-compact';
				note.innerText = '暂无可展示的出口详情';
				container.appendChild(note);
				return;
			}

			const label = document.createElement('span');
			label.className = 'exit-list-label';
			label.innerText = '落地 IP';
			container.appendChild(label);

			exitIps.forEach(function (entry) {
				const button = document.createElement('button');
				button.type = 'button';
				button.className = 'exit-ip-btn';
				button.innerText = entry.ip;
				button.dataset.exitKey = getExitSelectionKey(entry.exitData, entry.ip);
				button.addEventListener('click', function () {
					showDetails(button, entry.exitData);
				});
				container.appendChild(button);
			});
		}

		function addResultItem(ip) {
			hideEmptyState();
			const div = document.createElement('div');
			div.className = 'result-item';
			div.innerHTML =
				'<div class="result-flag-overlay" aria-hidden="true"></div>' +
				'<div class="result-top">' +
					'<div class="result-info">' +
						'<span class="result-label">候选目标</span>' +
						buildCopyableTarget(ip) +
						'<span class="result-detail">已加入检测队列，正在等待返回结果。</span>' +
					'</div>' +
					'<span class="status-badge status-pending">等待中</span>' +
				'</div>' +
				'<div class="result-meta">' +
					buildMetaChip('准备建立检测请求', 'prep') +
				'</div>' +
				'<div class="exit-list"></div>' +
				'<div class="map-container-wrapper">' +
					'<div class="map-detail-map-panel">' +
						'<div class="map-detail-map-slot"></div>' +
					'</div>' +
					'<div class="exit-detail-grid">' +
						'<div class="exit-detail-card exit-basic-info-card"></div>' +
						'<div class="exit-detail-card exit-security-info-card"></div>' +
					'</div>' +
				'</div>';

			resultsDiv.appendChild(div);

			const itemObj = {
				el: div,
				flag: div.querySelector('.result-flag-overlay'),
				info: div.querySelector('.result-info'),
				badge: div.querySelector('.status-badge'),
				meta: div.querySelector('.result-meta'),
				exitList: div.querySelector('.exit-list'),
				mapContainer: div.querySelector('.map-container-wrapper')
			};
			createResultRecord(ip, itemObj);
			return itemObj;
		}

		function firstNonEmpty() {
			for (let i = 0; i < arguments.length; i++) {
				const value = arguments[i];
				if (value === undefined || value === null) continue;
				const text = String(value).trim();
				if (text) return value;
			}
			return '';
		}

		function normalizeExitData(exit) {
			if (!exit || typeof exit !== 'object') return null;

			const location = exit.location && typeof exit.location === 'object' ? exit.location : {};
			const asnInfo = exit.asn && typeof exit.asn === 'object' ? exit.asn : {};
			const company = exit.company && typeof exit.company === 'object' ? exit.company : {};
			const latitude = firstNonEmpty(exit.latitude, location.latitude);
			const longitude = firstNonEmpty(exit.longitude, location.longitude);
			const loc = firstNonEmpty(
				exit.loc,
				latitude !== '' && longitude !== '' ? String(latitude) + ',' + String(longitude) : ''
			);
			const asn = firstNonEmpty(typeof exit.asn === 'object' ? '' : exit.asn, asnInfo.asn);
			const asOrganization = firstNonEmpty(exit.asOrganization, exit.org, asnInfo.org, asnInfo.descr, company.name);
			let countryCode = firstNonEmpty(exit.countryCode, exit.country_code, location.country_code, asnInfo.country);
			if (/^[a-z]{2}$/i.test(String(countryCode || '').trim())) {
				countryCode = String(countryCode).trim().toUpperCase();
			}
			const countryName = firstNonEmpty(exit.countryName, location.country);
			const ip = firstNonEmpty(exit.ip);

			return Object.assign({}, exit, {
				ip: ip,
				ipType: firstNonEmpty(exit.ipType, ip && String(ip).includes(':') ? 'ipv6' : (ip ? 'ipv4' : '')),
				asn: asn,
				asnInfo: asnInfo,
				asOrganization: asOrganization,
				org: firstNonEmpty(exit.org, asn ? 'AS' + asn + (asOrganization ? ' ' + asOrganization : '') : asOrganization),
				continent: firstNonEmpty(exit.continent, location.continent),
				country: firstNonEmpty(exit.country, countryCode, countryName),
				countryCode: countryCode,
				country_code: countryCode,
				countryName: countryName,
				region: firstNonEmpty(exit.region, exit.regionName, location.state),
				regionCode: firstNonEmpty(exit.regionCode, location.state_code),
				city: firstNonEmpty(exit.city, location.city),
				postalCode: firstNonEmpty(exit.postalCode, location.zip),
				timezone: firstNonEmpty(exit.timezone, location.timezone),
				loc: loc,
				latitude: latitude,
				longitude: longitude
			});
		}

		function normalizeCheckDataForUi(data, target) {
			const source = data || {};
			let parsed = null;
			try {
				parsed = parseProxyUrl(source.link || target);
			} catch (error) {
				parsed = null;
			}

			const exit = normalizeExitData(source.exit);
			const stack = exit && String(exit.ipType || '').toLowerCase() === 'ipv6' ? 'ipv6' : 'ipv4';
			const probeResults = {
				ipv4: { ok: false },
				ipv6: { ok: false }
			};
			if (exit && exit.ip) {
				probeResults[stack] = {
					ok: true,
					connect_ms: source.responseTime,
					exit: exit
				};
			}

			return Object.assign({}, source, {
				type: normalizeProxyType(source.type) || (parsed ? parsed.scheme : ''),
				exit: exit,
				proxyIP: parsed ? parsed.hostPlain : (source.hostname || source.candidate || target),
				portRemote: parsed ? parsed.port : (source.port || ''),
				supports_ipv4: Boolean(probeResults.ipv4.ok),
				supports_ipv6: Boolean(probeResults.ipv6.ok),
				probe_results: probeResults
			});
		}

		function getExitEntriesFromCheckData(data) {
			const exit = data && data.exit ? data.exit : null;
			if (!exit || !exit.ip) return [];
			const stack = String(exit.ipType || '').toLowerCase() === 'ipv6' ? 'ipv6' : 'ipv4';
			return [{ stack: stack, ip: exit.ip, exitData: exit }];
		}

		async function checkIP(target, itemObj, run) {
			if (isRunStopped(run)) return;
			itemObj = itemObj || addResultItem(target);
			const resultRecord = itemObj.record;

			try {
				const result = await fetchJsonWithTimeout('/check?proxy=' + encodeURIComponent(target), {}, 30000, run?.controller.signal);
				const data = normalizeCheckDataForUi(result.payload || {
					success: false,
					error: '检测接口没有返回有效 JSON'
				}, target);
				if (!result.response.ok) {
					data.success = false;
					data.error = data.error || ('HTTP ' + result.response.status);
				}
				completedCount++;

				if (data.success) {
					successCount++;
					itemObj.el.className = 'result-item success';
					const latency = formatLatency(data.responseTime);
					itemObj.badge.className = 'status-badge status-success';
					itemObj.badge.innerText = latency;
					setLatencyTooltip(itemObj.badge, data, latency);

					const exitIps = getExitEntriesFromCheckData(data);
					updateResultRecordAsSuccess(resultRecord, data, exitIps);

					const locations = joinUniqueValues(exitIps.map(function (entry) {
						return formatExitLocation(entry.exitData);
					}), '地区未知');
					const networks = joinUniqueValues(exitIps.map(function (entry) {
						return formatExitNetwork(entry.exitData);
					}), 'ASN / 运营商未知');
					const flagUrl = getFlagUrlFromExitIps(exitIps);

					updateResultFlag(itemObj, flagUrl);

					itemObj.info.innerHTML =
						'<span class="result-label">候选目标</span>' +
						buildCopyableTarget(data.link || target) +
						'<span class="result-detail">代理验证通过，可继续查看出口位置和网络信息。</span>';

					const typeSummary = joinUniqueValues(exitIps.map(function (entry) {
						return formatExitTypeDetail(entry.exitData);
					}), '类型未知');
					const riskSummary = joinUniqueValues(exitIps.map(function (entry) {
						return formatExitRiskText(entry.exitData);
					}), '未知');
					const riskModifier = getHighestExitRiskChipModifier(exitIps);
					const metaParts = [
						buildMetaChip(locations, 'location'),
						buildMetaChip(networks, 'network'),
						buildMetaChip(typeSummary, 'network', 'meta-chip-strong'),
						buildMetaChip(riskSummary, 'shield', riskModifier)
					];
					itemObj.meta.innerHTML = metaParts.join('');

					renderExitList(itemObj.exitList, exitIps);
				} else {
					updateResultRecordAsError(resultRecord, data);
					itemObj.el.className = 'result-item error';
					updateResultFlag(itemObj, '');
					itemObj.badge.className = 'status-badge status-error';
					itemObj.badge.innerText = '不可用';
					itemObj.info.innerHTML =
						'<span class="result-label">候选目标</span>' +
						buildCopyableTarget(target) +
						'<span class="result-detail">无法通过该代理访问 api.ipapi.is，请更换目标后重试。</span>';
					itemObj.meta.innerHTML =
						buildMetaChip('检测未通过', 'error', 'meta-chip-danger') +
						buildMetaChip(data.error || data.message || '远端返回失败结果', 'info');
					itemObj.exitList.innerHTML = '';
				}
			} catch (error) {
				if (isRunStopped(run)) {
					if (resultRecord) resultRecord.status = 'stopped';
					itemObj.badge.className = 'status-badge status-error';
					itemObj.badge.innerText = '已停止';
					itemObj.info.innerHTML =
						'<span class="result-label">候选目标</span>' +
						buildCopyableTarget(target) +
						'<span class="result-detail">检测已手动停止，未继续请求该代理。</span>';
					itemObj.meta.innerHTML = buildMetaChip('已停止', 'info');
					itemObj.exitList.innerHTML = '';
					updateProgress();
					updateResultFilters();
					return;
				}
				completedCount++;
				updateResultRecordAsError(resultRecord, null);
				itemObj.el.className = 'result-item error';
				updateResultFlag(itemObj, '');
				itemObj.badge.className = 'status-badge status-error';
				itemObj.badge.innerText = '失败';
				itemObj.info.innerHTML =
					'<span class="result-label">候选目标</span>' +
					buildCopyableTarget(target) +
					'<span class="result-detail">检测请求执行失败，可能是接口异常或网络中断。</span>';
				itemObj.meta.innerHTML =
					buildMetaChip('请求异常', 'error', 'meta-chip-danger') +
					buildMetaChip(error && error.name === 'AbortError' ? '检测请求超时' : '请稍后重试', 'retry');
				itemObj.exitList.innerHTML = '';
			}

			updateProgress();
			updateResultFilters();
		}

		function showDetails(button, exitData) {
			const item = button.closest('.result-item');
			const container = item.querySelector('.map-container-wrapper');
			const isOpen = container.style.display === 'block';
			const nextSelectionKey = button.dataset.exitKey || getExitSelectionKey(exitData);
			const isSameSelection = isOpen && container.dataset.activeExitKey === nextSelectionKey;
			const currentToken = ++mapRenderToken;

			document.querySelectorAll('.map-container-wrapper').forEach(function (panel) {
				if (panel !== container) {
					panel.style.display = 'none';
					panel.dataset.activeExitKey = '';
				}
			});
			document.querySelectorAll('.exit-ip-btn.is-active').forEach(function (activeButton) {
				activeButton.classList.remove('is-active');
			});

			if (isSameSelection) {
				container.style.display = 'none';
				container.dataset.activeExitKey = '';
				return;
			}

			container.dataset.activeExitKey = nextSelectionKey;
			button.classList.add('is-active');
			renderExitDetailPanel(container, exitData);
			initMap();
			const mapHost = container.querySelector('.map-detail-map-slot');
			if (mapHost) {
				mapHost.appendChild(globalMap);
			}
			container.style.display = 'block';

			setTimeout(async function () {
				if (currentToken !== mapRenderToken || container.style.display !== 'block') {
					return;
				}

				map.invalidateSize();

				const exitLocation = parseCoordinatePair(exitData?.loc);
				const hasExitLocation = isValidCoordinatePair(exitLocation);

				clearMapLayers();

				if (hasExitLocation) {
					const exitMarker = L.marker(exitLocation, {
						icon: getRedLocationIcon(),
						title: exitData?.ip || 'Exit IP'
					}).addTo(map);
					exitMarker.bindPopup(createExitPopup(exitData));
					mapLayers.push(exitMarker);
					map.setView(exitLocation, 6);
					return;
				}

				map.setView([20, 0], 2);
			}, 100);
		}

		batchMode.addEventListener('change', function () {
			swapInputMode(batchMode.checked);
		});

		historyBtn.addEventListener('click', function (event) {
			event.stopPropagation();
			const isVisible = historyDropdown.style.display === 'block';
			historyDropdown.style.display = isVisible ? 'none' : 'block';
		});

		document.addEventListener('click', function (event) {
			if (!inputContainer.contains(event.target)) {
				historyDropdown.style.display = 'none';
			}
		});

		if (themeToggle) {
			themeToggle.addEventListener('click', function () {
				const currentTheme = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
				const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
				try {
					localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
				} catch (error) {
					console.warn('Failed to persist theme preference', error);
				}
				applyTheme(nextTheme, 'stored');
			});
		}

		if (systemThemeQuery.addEventListener) {
			systemThemeQuery.addEventListener('change', function (event) {
				if (getStoredTheme()) return;
				applyTheme(event.matches ? 'dark' : 'light', 'system');
			});
		} else if (systemThemeQuery.addListener) {
			systemThemeQuery.addListener(function (event) {
				if (getStoredTheme()) return;
				applyTheme(event.matches ? 'dark' : 'light', 'system');
			});
		}

		filterToggle.addEventListener('click', function () {
			isFilterPanelExpanded = !isFilterPanelExpanded;
			updateResultFilters();
		});

		primaryFilterGroup.addEventListener('click', function (event) {
			const button = event.target.closest('[data-primary-filter]');
			if (!button || button.disabled) return;

			activePrimaryFilter = button.dataset.primaryFilter || 'all';
			activeCountryFilter = 'all';
			updateResultFilters();
		});

		protocolFilterGroup.addEventListener('click', function (event) {
			const button = event.target.closest('[data-protocol-filter]');
			if (!button || button.disabled) return;

			toggleProtocolFilter(button.dataset.protocolFilter || '');
			activeCountryFilter = 'all';
			updateResultFilters();
		});

		countryFilterGroup.addEventListener('click', function (event) {
			const button = event.target.closest('[data-country-filter]');
			if (!button) return;

			activeCountryFilter = button.dataset.countryFilter || 'all';
			updateResultFilters();
		});

		if (exportGroup) {
			exportGroup.addEventListener('click', function (event) {
				const button = event.target.closest('[data-export-format]');
				if (!button) return;

				handleExport(button.dataset.exportFormat || '');
			});
		}

		resultsDiv.addEventListener('click', handleCopyTargetClick);

		checkBtn.addEventListener('click', async function () {
			if (activeRun) {
				stopActiveRun();
				return;
			}

			const value = batchMode.checked ? normalizeBatchInputValue(inputList.value) : stripTargetLabel(inputList.value);
			if (!value) return;

			const lines = batchMode.checked
				? uniqueTargets(normalizeBatchInputValue(value).split('\\n').map(function (line) { return line.trim(); }).filter(Boolean))
				: [value];

			inputList.value = batchMode.checked ? lines.join('\\n') : value;

			if (!batchMode.checked) {
				saveHistory(value);
			}

			resultsDiv.innerHTML = '';
			resetResultFilters();
			progressBar.style.width = '0%';
			progressText.innerText = '正在解析目标...';
			showEmptyState('正在准备检测', '正在解析你输入的目标，请稍候。');

			completedCount = 0;
			successCount = 0;
			totalTargets = 0;
			inputCount = lines.length;

			const run = {
				controller: new AbortController(),
				cancelled: false
			};
			activeRun = run;
			setCheckButtonRunning(true);
			setAppState('resolving');

			try {
				const resolveJobs = [];
				const targetGroups = lines.map(function (line) {
					const directTarget = getDirectProxyTarget(line);
					if (directTarget) {
						return [directTarget];
					}

					const group = [];
					resolveJobs.push({ line, group });
					return group;
				});

				if (batchMode.checked) {
					await resolveBatchJobs(resolveJobs, run);
				} else {
					for (const job of resolveJobs) {
						await resolveSingleJob(job, run);
					}
				}
				throwIfRunStopped(run);

				const allResolvedTargets = [];
				pushResolvedTargets(targetGroups, allResolvedTargets);

				if (allResolvedTargets.length > 0) {
					totalTargets = allResolvedTargets.length;
					setAppState('running');
					updateProgress();
					throwIfRunStopped(run);

					let checkJobs = [];
					isCreatingResultBatch = true;
					try {
						checkJobs = allResolvedTargets.map(function (target) {
							return {
								target: target,
								itemObj: addResultItem(target)
							};
						});
					} finally {
						isCreatingResultBatch = false;
					}
					updateResultFilters();

					await runWithConcurrency(checkJobs, CHECK_CONCURRENCY, function (job) {
						return checkIP(job.target, job.itemObj, run);
					}, run);
					throwIfRunStopped(run);

					const failCount = Math.max(totalTargets - successCount, 0);
					progressText.innerText = '总计 ' + totalTargets + ' · 有效 ' + successCount + ' · 失败 ' + failCount;
					setAppState('done');
				} else {
					progressText.innerText = '未解析到目标';
					showEmptyState('没有可检测的候选目标', '请检查输入格式，或确认域名是否存在 A / AAAA 记录。');
					setAppState('empty');
				}
			} catch (error) {
				if (isRunStopped(run) || error?.name === 'AbortError') {
					progressText.innerText = '已停止 · 已完成 ' + completedCount + ' / ' + totalTargets + ' · 有效 ' + successCount;
					setAppState('stopped');
				} else {
					console.error(error);
					progressText.innerText = '系统错误';
					showEmptyState('检测流程中断', '请求过程中发生异常，请稍后重试。');
					setAppState('error');
				}
			} finally {
				if (activeRun === run) activeRun = null;
				setCheckButtonRunning(false);
			}
		});

		window.onload = function () {
			renderHistory();
			setModeVisuals(false);
			bindInputShortcut();
			renderDashboard();
			updateResultFilters();

			const path = window.location.pathname.slice(1);
			if (path && path.length > 3) {
				const decodedPath = decodeURIComponent(path);
				if (decodedPath !== 'resolve' && decodedPath !== 'favicon.ico') {
					inputList.value = decodedPath;
					window.history.replaceState({}, '', '/');
					checkBtn.click();
				}
			}
		};
	</script>
</body>
</html>`;
}

////////////////////////////////////////////TLSClient by: @Alexandre_Kojeve////////////////////////////////////////////////
const TLS_VERSION_10 = 769, TLS_VERSION_12 = 771, TLS_VERSION_13 = 772;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20, CONTENT_TYPE_ALERT = 21, CONTENT_TYPE_HANDSHAKE = 22, CONTENT_TYPE_APPLICATION_DATA = 23;
const HANDSHAKE_TYPE_CLIENT_HELLO = 1, HANDSHAKE_TYPE_SERVER_HELLO = 2, HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8, HANDSHAKE_TYPE_CERTIFICATE = 11, HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12, HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13, HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14, HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16, HANDSHAKE_TYPE_FINISHED = 20, HANDSHAKE_TYPE_KEY_UPDATE = 24;
const EXT_SERVER_NAME = 0, EXT_SUPPORTED_GROUPS = 10, EXT_EC_POINT_FORMATS = 11, EXT_SIGNATURE_ALGORITHMS = 13, EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, EXT_SUPPORTED_VERSIONS = 43, EXT_PSK_KEY_EXCHANGE_MODES = 45, EXT_KEY_SHARE = 51;

const ALERT_CLOSE_NOTIFY = 0, ALERT_LEVEL_WARNING = 1, ALERT_UNRECOGNIZED_NAME = 112;
const shouldIgnoreTlsAlert = fragment => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

const CIPHER_SUITES_BY_ID = new Map([
	[4865, { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0 }],
	[4866, { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0 }],
	[4867, { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: !0, chacha: !0 }],
	[49199, { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49200, { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52392, { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }],
	[49195, { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49196, { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52393, { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }]
]);
const GROUPS_BY_ID = new Map([[29, "X25519"], [23, "P-256"]]);
const SUPPORTED_SIGNATURE_ALGORITHMS = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539];

const tlsBytes = (...parts) => {
	const flattenBytes = values => values.flatMap(value => value instanceof Uint8Array ? [...value] : Array.isArray(value) ? flattenBytes(value) : "number" == typeof value ? [value] : []);
	return new Uint8Array(flattenBytes(parts))
};
const uint16be = value => [value >> 8 & 255, 255 & value];
const readUint16 = (buffer, offset) => buffer[offset] << 8 | buffer[offset + 1];
const readUint24 = (buffer, offset) => buffer[offset] << 16 | buffer[offset + 1] << 8 | buffer[offset + 2];
const concatBytes = (...chunks) => {
	const nonEmptyChunks = chunks.filter((chunk => chunk && chunk.length > 0)),
		length = nonEmptyChunks.reduce(((total, chunk) => total + chunk.length), 0),
		result = new Uint8Array(length);
	let offset = 0;
	for (const chunk of nonEmptyChunks) result.set(chunk, offset), offset += chunk.length;
	return result
};
const randomBytes = length => crypto.getRandomValues(new Uint8Array(length));
const constantTimeEqual = (left, right) => {
	if (!left || !right || left.length !== right.length) return !1;
	let diff = 0; for (let index = 0; index < left.length; index++) diff |= left[index] ^ right[index];
	return 0 === diff
};
const hashByteLength = hash => "SHA-512" === hash ? 64 : "SHA-384" === hash ? 48 : 32;
async function hmac(hash, key, data) {
	const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, !1, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data))
}
async function digestBytes(hash, data) { return new Uint8Array(await crypto.subtle.digest(hash, data)) }
async function tls12Prf(secret, label, seed, length, hash = "SHA-256") {
	const labelSeed = concatBytes(textEncoder.encode(label), seed);
	let output = new Uint8Array(0),
		currentA = labelSeed;
	for (; output.length < length;) {
		currentA = await hmac(hash, secret, currentA);
		const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
		output = concatBytes(output, block)
	}
	return output.slice(0, length)
}
async function hkdfExtract(hash, salt, inputKeyMaterial) {
	return salt && salt.length || (salt = new Uint8Array(hashByteLength(hash))), hmac(hash, salt, inputKeyMaterial)
}
async function hkdfExpandLabel(hash, secret, label, context, length) {
	const fullLabel = textEncoder.encode("tls13 " + label);
	return async function (hash, secret, info, length) {
		const hashLen = hashByteLength(hash),
			roundCount = Math.ceil(length / hashLen);
		let output = new Uint8Array(0),
			previousBlock = new Uint8Array(0);
		for (let round = 1; round <= roundCount; round++) previousBlock = await hmac(hash, secret, concatBytes(previousBlock, info, [round])), output = concatBytes(output, previousBlock);
		return output.slice(0, length)
	}(hash, secret, tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context), length)
}
async function generateKeyShare(group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group };
	const keyPair = /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey(algorithm, !0, ["deriveBits"]));
	const publicKeyRaw = /** @type {ArrayBuffer} */ (await crypto.subtle.exportKey("raw", keyPair.publicKey));
	return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) }
}
async function deriveSharedSecret(privateKey, peerPublicKey, group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group },
		peerKey = await crypto.subtle.importKey("raw", peerPublicKey, algorithm, !1, []),
		bits = "P-384" === group ? 384 : "P-521" === group ? 528 : 256;
	return new Uint8Array(await crypto.subtle.deriveBits(/** @type {any} */({ name: algorithm.name, public: peerKey }), privateKey, bits))
}
async function importAesGcmKey(key, usages) { return crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, !1, usages) }
async function aesGcmEncryptWithKey(cryptoKey, initializationVector, plaintext, additionalData) {
	return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, plaintext))
}
async function aesGcmDecryptWithKey(cryptoKey, initializationVector, ciphertext, additionalData) {
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, ciphertext))
}

function rotateLeft32(value, bits) { return (value << bits | value >>> 32 - bits) >>> 0 }

function chachaQuarterRound(state, indexA, indexB, indexC, indexD) {
	state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 16), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 12), state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 8), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 7)
}

function chacha20Block(key, counter, nonce) {
	const state = new Uint32Array(16);
	state[0] = 1634760805, state[1] = 857760878, state[2] = 2036477234, state[3] = 1797285236;
	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let wordIndex = 0; wordIndex < 8; wordIndex++) state[4 + wordIndex] = keyView.getUint32(4 * wordIndex, !0);
	state[12] = counter;
	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	state[13] = nonceView.getUint32(0, !0), state[14] = nonceView.getUint32(4, !0), state[15] = nonceView.getUint32(8, !0);
	const workingState = new Uint32Array(state);
	for (let round = 0; round < 10; round++) chachaQuarterRound(workingState, 0, 4, 8, 12), chachaQuarterRound(workingState, 1, 5, 9, 13), chachaQuarterRound(workingState, 2, 6, 10, 14), chachaQuarterRound(workingState, 3, 7, 11, 15), chachaQuarterRound(workingState, 0, 5, 10, 15), chachaQuarterRound(workingState, 1, 6, 11, 12), chachaQuarterRound(workingState, 2, 7, 8, 13), chachaQuarterRound(workingState, 3, 4, 9, 14);
	for (let wordIndex = 0; wordIndex < 16; wordIndex++) workingState[wordIndex] = workingState[wordIndex] + state[wordIndex] >>> 0;
	return new Uint8Array(workingState.buffer.slice(0))
}

function chacha20Xor(key, nonce, data) {
	const output = new Uint8Array(data.length);
	let counter = 1;
	for (let offset = 0; offset < data.length; offset += 64) {
		const block = chacha20Block(key, counter++, nonce),
			blockLength = Math.min(64, data.length - offset);
		for (let index = 0; index < blockLength; index++) output[offset + index] = data[offset + index] ^ block[index]
	}
	return output
}

function poly1305Mac(key, message) {
	const rKey = function (rBytes) {
		const clamped = new Uint8Array(rBytes);
		return clamped[3] &= 15, clamped[7] &= 15, clamped[11] &= 15, clamped[15] &= 15, clamped[4] &= 252, clamped[8] &= 252, clamped[12] &= 252, clamped
	}(key.slice(0, 16)),
		sKey = key.slice(16, 32);
	let accumulator = [0n, 0n, 0n, 0n, 0n];
	const rLimbs = [0x3ffffffn & BigInt(rKey[0] | rKey[1] << 8 | rKey[2] << 16 | rKey[3] << 24), 0x3ffffffn & BigInt(rKey[3] >> 2 | rKey[4] << 6 | rKey[5] << 14 | rKey[6] << 22), 0x3ffffffn & BigInt(rKey[6] >> 4 | rKey[7] << 4 | rKey[8] << 12 | rKey[9] << 20), 0x3ffffffn & BigInt(rKey[9] >> 6 | rKey[10] << 2 | rKey[11] << 10 | rKey[12] << 18), 0x3ffffffn & BigInt(rKey[13] | rKey[14] << 8 | rKey[15] << 16)];
	for (let offset = 0; offset < message.length; offset += 16) {
		const chunk = message.slice(offset, offset + 16),
			paddedChunk = new Uint8Array(17);
		paddedChunk.set(chunk), paddedChunk[chunk.length] = 1, accumulator[0] += BigInt(paddedChunk[0] | paddedChunk[1] << 8 | paddedChunk[2] << 16 | (3 & paddedChunk[3]) << 24), accumulator[1] += BigInt(paddedChunk[3] >> 2 | paddedChunk[4] << 6 | paddedChunk[5] << 14 | (15 & paddedChunk[6]) << 22), accumulator[2] += BigInt(paddedChunk[6] >> 4 | paddedChunk[7] << 4 | paddedChunk[8] << 12 | (63 & paddedChunk[9]) << 20), accumulator[3] += BigInt(paddedChunk[9] >> 6 | paddedChunk[10] << 2 | paddedChunk[11] << 10 | paddedChunk[12] << 18), accumulator[4] += BigInt(paddedChunk[13] | paddedChunk[14] << 8 | paddedChunk[15] << 16 | paddedChunk[16] << 24);
		const product = [0n, 0n, 0n, 0n, 0n];
		for (let accIndex = 0; accIndex < 5; accIndex++)
			for (let rIndex = 0; rIndex < 5; rIndex++) {
				const limbIndex = accIndex + rIndex;
				limbIndex < 5 ? product[limbIndex] += accumulator[accIndex] * rLimbs[rIndex] : product[limbIndex - 5] += accumulator[accIndex] * rLimbs[rIndex] * 5n
			}
		let carry = 0n;
		for (let index = 0; index < 5; index++) product[index] += carry, accumulator[index] = 0x3ffffffn & product[index], carry = product[index] >> 26n;
		accumulator[0] += 5n * carry, carry = accumulator[0] >> 26n, accumulator[0] &= 0x3ffffffn, accumulator[1] += carry
	}
	let tagValue = accumulator[0] | accumulator[1] << 26n | accumulator[2] << 52n | accumulator[3] << 78n | accumulator[4] << 104n;
	tagValue = tagValue + sKey.reduce(((total, byte, index) => total + (BigInt(byte) << BigInt(8 * index))), 0n) & (1n << 128n) - 1n;
	const tag = new Uint8Array(16);
	for (let index = 0; index < 16; index++) tag[index] = Number(tagValue >> BigInt(8 * index) & 0xffn);
	return tag
}

function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
	const polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		ciphertext = chacha20Xor(key, nonce, plaintext),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - ciphertext.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + ciphertext.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(ciphertext, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + ciphertext.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(ciphertext.length), !0);
	const tag = poly1305Mac(polyKey, macData);
	return concatBytes(ciphertext, tag)
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData) {
	if (ciphertext.length < 16) throw new Error("Ciphertext too short");
	const tag = ciphertext.slice(-16),
		encryptedData = ciphertext.slice(0, -16),
		polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - encryptedData.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + encryptedData.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(encryptedData, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + encryptedData.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(encryptedData.length), !0);
	const expectedTag = poly1305Mac(polyKey, macData);
	let diff = 0;
	for (let index = 0; index < 16; index++) diff |= tag[index] ^ expectedTag[index];
	if (0 !== diff) throw new Error("ChaCha20-Poly1305 authentication failed");
	return chacha20Xor(key, nonce, encryptedData)
}

const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;
function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
	const data = 数据转Uint8Array(fragment);
	const record = new Uint8Array(5 + data.byteLength);
	record[0] = contentType;
	record[1] = version >> 8 & 255;
	record[2] = version & 255;
	record[3] = data.byteLength >> 8 & 255;
	record[4] = data.byteLength & 255;
	record.set(data, 5);
	return record;
}
function buildHandshakeMessage(handshakeType, body) { return tlsBytes(handshakeType, (length => [length >> 16 & 255, length >> 8 & 255, 255 & length])(body.length), body) }
class TlsRecordParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = 数据转Uint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 5) return null;
		const contentType = this.buffer[0],
			version = readUint16(this.buffer, 1),
			length = readUint16(this.buffer, 3);
		if (this.buffer.length < 5 + length) return null;
		const fragment = this.buffer.subarray(5, 5 + length);
		return this.buffer = this.buffer.subarray(5 + length), { type: contentType, version, length, fragment }
	}
}
class TlsHandshakeParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = 数据转Uint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 4) return null;
		const handshakeType = this.buffer[0],
			length = readUint24(this.buffer, 1);
		if (this.buffer.length < 4 + length) return null;
		const body = this.buffer.subarray(4, 4 + length),
			raw = this.buffer.subarray(0, 4 + length);
		return this.buffer = this.buffer.subarray(4 + length), { type: handshakeType, length, body, raw }
	}
}

function parseServerHello(body) {
	let offset = 0;
	const legacyVersion = readUint16(body, offset);
	offset += 2;
	const serverRandom = body.slice(offset, offset + 32);
	offset += 32;
	const sessionIdLength = body[offset++],
		sessionId = body.slice(offset, offset + sessionIdLength);
	offset += sessionIdLength;
	const cipherSuite = readUint16(body, offset);
	offset += 2;
	const compression = body[offset++];
	let selectedVersion = legacyVersion,
		keyShare = null,
		alpn = null;
	if (offset < body.length) {
		const extensionsLength = readUint16(body, offset);
		offset += 2;
		const extensionsEnd = offset + extensionsLength;
		for (; offset + 4 <= extensionsEnd;) {
			const extensionType = readUint16(body, offset);
			offset += 2;
			const extensionLength = readUint16(body, offset);
			offset += 2;
			const extensionData = body.slice(offset, offset + extensionLength);
			if (offset += extensionLength, extensionType === EXT_SUPPORTED_VERSIONS && extensionLength >= 2) selectedVersion = readUint16(extensionData, 0);
			else if (extensionType === EXT_KEY_SHARE && extensionLength >= 4) {
				const group = readUint16(extensionData, 0),
					keyLength = readUint16(extensionData, 2);
				keyShare = { group, key: extensionData.slice(4, 4 + keyLength) }
			} else extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3 && (alpn = textDecoder.decode(extensionData.slice(3, 3 + extensionData[2])))
		}
	}
	const helloRetryRequestRandom = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
	return { version: legacyVersion, serverRandom, sessionId, cipherSuite, compression, selectedVersion, keyShare, alpn, isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom), isTls13: selectedVersion === TLS_VERSION_13 }
}

function parseServerKeyExchange(body) {
	let offset = 1;
	const namedCurve = readUint16(body, offset);
	offset += 2;
	const keyLength = body[offset++];
	return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) }
}

function extractLeafCertificate(body, hasContext = 0) {
	let offset = 0;
	if (hasContext) {
		const contextLength = body[offset++];
		offset += contextLength
	}
	if (offset + 3 > body.length) return null;
	const certificateListLength = readUint24(body, offset);
	if (offset += 3, !certificateListLength || offset + 3 > body.length) return null;
	const certificateLength = readUint24(body, offset);
	return offset += 3, certificateLength ? body.slice(offset, offset + certificateLength) : null
}

function parseEncryptedExtensions(body) {
	const parsed = { alpn: null };
	let offset = 2;
	const extensionsEnd = 2 + readUint16(body, 0);
	for (; offset + 4 <= extensionsEnd;) {
		const extensionType = readUint16(body, offset);
		offset += 2;
		const extensionLength = readUint16(body, offset);
		if (offset += 2, extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3) {
			const protocolLength = body[offset + 2];
			protocolLength > 0 && offset + 3 + protocolLength <= offset + extensionLength && (parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength)))
		}
		offset += extensionLength
	}
	return parsed
}

function buildClientHello(clientRandom, serverName, keyShares, { tls13: enableTls13 = !0, tls12: enableTls12 = !0, alpn = null, chacha = !0 } = {}) {
	const cipherIds = [];
	enableTls13 && cipherIds.push(4865, 4866, ...(chacha ? [4867] : [])), enableTls12 && cipherIds.push(49199, 49200, 49195, 49196, ...(chacha ? [52392, 52393] : []));
	const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be)),
		extensions = [tlsBytes(255, 1, 0, 1, 0)];
	if (serverName) {
		const serverNameBytes = textEncoder.encode(serverName),
			serverNameList = tlsBytes(0, uint16be(serverNameBytes.length), serverNameBytes);
		extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME), uint16be(serverNameList.length + 2), uint16be(serverNameList.length), serverNameList))
	}
	extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0)), extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
	const signatureBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
	extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS), uint16be(signatureBytes.length + 2), uint16be(signatureBytes.length), signatureBytes));
	const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
	if (protocols.length) {
		const alpnBytes = concatBytes(...protocols.map((protocol => { const protocolBytes = textEncoder.encode(protocol); return tlsBytes(protocolBytes.length, protocolBytes) })));
		extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), uint16be(alpnBytes.length + 2), uint16be(alpnBytes.length), alpnBytes))
	}
	if (enableTls13 && keyShares) {
		let keyShareBytes;
		if (extensions.push(enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4)), extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1)), keyShares?.x25519 && keyShares?.p256) keyShareBytes = concatBytes(tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519), tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256));
		else if (keyShares?.x25519) keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
		else if (keyShares?.p256) keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
		else {
			if (!(keyShares instanceof Uint8Array)) throw new Error("Invalid keyShares");
			keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares)
		}
		extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE), uint16be(keyShareBytes.length + 2), uint16be(keyShareBytes.length), keyShareBytes))
	}
	const extensionsBytes = concatBytes(...extensions);
	return buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, tlsBytes(uint16be(TLS_VERSION_12), clientRandom, 0, uint16be(cipherBytes.length), cipherBytes, 1, 0, uint16be(extensionsBytes.length), extensionsBytes))
}
const uint64be = sequenceNumber => { const bytes = new Uint8Array(8); return new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, !1), bytes },
	xorSequenceIntoIv = (initializationVector, sequenceNumber) => {
		const nonce = initializationVector.slice(),
			sequenceBytes = uint64be(sequenceNumber);
		for (let index = 0; index < 8; index++) nonce[nonce.length - 8 + index] ^= sequenceBytes[index];
		return nonce
	},
	deriveTrafficKeys = (hash, secret, keyLen, ivLen) => Promise.all([hkdfExpandLabel(hash, secret, "key", EMPTY_BYTES, keyLen), hkdfExpandLabel(hash, secret, "iv", EMPTY_BYTES, ivLen)]);
class TlsClient {
	constructor(socket, options = {}) {
		if (this.socket = socket, this.serverName = options.serverName || "", this.supportTls13 = !1 !== options.tls13, this.supportTls12 = !1 !== options.tls12, !this.supportTls13 && !this.supportTls12) throw new Error("At least one TLS version must be enabled");
		this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null, this.allowChacha = options.allowChacha !== false, this.timeout = options.timeout ?? 3e4, this.clientRandom = randomBytes(32), this.serverRandom = null, this.handshakeChunks = [], this.handshakeComplete = !1, this.negotiatedAlpn = null, this.cipherSuite = null, this.cipherConfig = null, this.isTls13 = !1, this.masterSecret = null, this.handshakeSecret = null, this.clientWriteKey = null, this.serverWriteKey = null, this.clientWriteIv = null, this.serverWriteIv = null, this.clientHandshakeKey = null, this.serverHandshakeKey = null, this.clientHandshakeIv = null, this.serverHandshakeIv = null, this.clientAppKey = null, this.serverAppKey = null, this.clientAppIv = null, this.serverAppIv = null, this.clientWriteCryptoKey = null, this.serverWriteCryptoKey = null, this.clientHandshakeCryptoKey = null, this.serverHandshakeCryptoKey = null, this.clientAppCryptoKey = null, this.serverAppCryptoKey = null, this.clientSeqNum = 0n, this.serverSeqNum = 0n, this.recordParser = new TlsRecordParser, this.handshakeParser = new TlsHandshakeParser, this.keyPairs = new Map, this.ecdhKeyPair = null, this.sawCert = !1
	}
	recordHandshake(chunk) { this.handshakeChunks.push(chunk) }
	transcript() { return 1 === this.handshakeChunks.length ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks) }
	getCipherConfig(cipherSuite) { return CIPHER_SUITES_BY_ID.get(cipherSuite) || null }
	async readChunk(reader) { return this.timeout ? Promise.race([reader.read(), new Promise(((resolve, reject) => setTimeout((() => reject(new Error("TLS read timeout"))), this.timeout)))]) : reader.read() }
	async readRecordsUntil(reader, predicate, closedError) {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();)
				if (await predicate(record)) return;
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error(closedError);
			this.recordParser.feed(value)
		}
	}
	async readHandshakeUntil(reader, predicate, closedError) {
		for (let message; message = this.handshakeParser.next();)
			if (await predicate(message)) return;
		return this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(record.fragment);
				for (let message; message = this.handshakeParser.next();)
					if (await predicate(message)) return 1
			}
		}), closedError)
	}
	async acceptCertificate(certificate) { if (!certificate?.length) throw new Error("Empty certificate"); this.sawCert = !0 }
	async handshake() {
		const [p256Share, x25519Share] = await Promise.all([generateKeyShare("P-256"), generateKeyShare("X25519")]);
		this.keyPairs = new Map([[23, p256Share], [29, x25519Share]]), this.ecdhKeyPair = p256Share.keyPair;
		const reader = this.socket.readable.getReader(),
			writer = this.socket.writable.getWriter();
		try {
			const clientHello = buildClientHello(this.clientRandom, this.serverName, { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw }, { tls13: this.supportTls13, tls12: this.supportTls12, alpn: this.alpnProtocols, chacha: this.allowChacha });
			this.recordHandshake(clientHello), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
			const serverHello = await this.receiveServerHello(reader);
			if (serverHello.isHRR) throw new Error("HelloRetryRequest is not supported by TLSClientMini");
			if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
				const selectedKeyPair = this.keyPairs.get(serverHello.keyShare.group);
				this.ecdhKeyPair = selectedKeyPair.keyPair
			}
			serverHello.isTls13 ? await this.handshakeTls13(reader, writer, serverHello) : await this.handshakeTls12(reader, writer), this.handshakeComplete = !0
		} finally {
			reader.releaseLock(), writer.releaseLock()
		}
	}
	async receiveServerHello(reader) {
		for (; ;) {
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error("Connection closed waiting for ServerHello");
			let record;
			for (this.recordParser.feed(value); record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (shouldIgnoreTlsAlert(record.fragment)) continue;
					throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
				}
				if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(record.fragment); message = this.handshakeParser.next();) {
					if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
					this.recordHandshake(message.raw);
					const serverHello = parseServerHello(message.body);
					if (this.serverRandom = serverHello.serverRandom, this.cipherSuite = serverHello.cipherSuite, this.cipherConfig = this.getCipherConfig(serverHello.cipherSuite), this.isTls13 = serverHello.isTls13, this.negotiatedAlpn = serverHello.alpn || null, !this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
					return serverHello
				}
			}
		}
	}
	async handshakeTls12(reader, writer) {
		/** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */
		let serverKeyExchange = null;
		let sawServerHelloDone = !1;
		if (await this.readHandshakeUntil(reader, (async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_CERTIFICATE: {
					this.recordHandshake(message.raw);
					const certificate = extractLeafCertificate(message.body, 1);
					if (!certificate) throw new Error("Missing TLS 1.2 certificate");
					await this.acceptCertificate(certificate);
					break
				}
				case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
					this.recordHandshake(message.raw), serverKeyExchange = parseServerKeyExchange(message.body);
					break;
				case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
					return this.recordHandshake(message.raw), sawServerHelloDone = !0, 1;
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					throw new Error("Client certificate is not supported");
				default:
					this.recordHandshake(message.raw)
			}
		}), "Connection closed during TLS 1.2 handshake"), !this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
		const serverKeyExchangeData = /** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */ (serverKeyExchange);
		if (!serverKeyExchangeData) throw new Error("Missing TLS 1.2 ServerKeyExchange");
		const curveName = GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
		if (!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const keyShare = this.keyPairs.get(serverKeyExchangeData.namedCurve);
		if (!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const preMasterSecret = await deriveSharedSecret(keyShare.keyPair.privateKey, serverKeyExchangeData.serverPublicKey, curveName),
			clientKeyExchange = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw));
		this.recordHandshake(clientKeyExchange);
		const hashName = this.cipherConfig.hash;
		this.masterSecret = await tls12Prf(preMasterSecret, "master secret", concatBytes(this.clientRandom, this.serverRandom), 48, hashName);
		const keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			keyBlock = await tls12Prf(this.masterSecret, "key expansion", concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hashName);
		this.clientWriteKey = keyBlock.slice(0, keyLen), this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen), this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen), this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
		if (!this.cipherConfig.chacha) [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([importAesGcmKey(this.clientWriteKey, ["encrypt"]), importAesGcmKey(this.serverWriteKey, ["decrypt"])]);
		await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange)), await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
		const clientVerifyData = await tls12Prf(this.masterSecret, "client finished", await digestBytes(hashName, this.transcript()), 12, hashName),
			finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
		this.recordHandshake(finishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)));
		let sawChangeCipherSpec = !1;
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void (sawChangeCipherSpec = !0);
			if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
			const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
			if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
			const verifyLength = readUint24(decrypted, 1),
				verifyData = decrypted.slice(4, 4 + verifyLength),
				expectedVerifyData = await tls12Prf(this.masterSecret, "server finished", await digestBytes(hashName, this.transcript()), 12, hashName);
			if (!constantTimeEqual(verifyData, expectedVerifyData)) throw new Error("TLS 1.2 server Finished verify failed");
			return 1
		}), "Connection closed waiting for TLS 1.2 Finished")
	}
	async handshakeTls13(reader, writer, serverHello) {
		const groupName = GROUPS_BY_ID.get(serverHello.keyShare?.group);
		if (!groupName || !serverHello.keyShare?.key?.length) throw new Error("Missing TLS 1.3 key_share");
		const hashName = this.cipherConfig.hash,
			hashLen = hashByteLength(hashName),
			keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, groupName),
			earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen)),
			derivedSecret = await hkdfExpandLabel(hashName, earlySecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen);
		this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
		const transcriptHash = await digestBytes(hashName, this.transcript()),
			clientHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "c hs traffic", transcriptHash, hashLen),
			serverHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "s hs traffic", transcriptHash, hashLen);
		[this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hashName, clientHandshakeTrafficSecret, keyLen, ivLen), [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hashName, serverHandshakeTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([importAesGcmKey(this.clientHandshakeKey, ["encrypt"]), importAesGcmKey(this.serverHandshakeKey, ["decrypt"])]);
		const serverFinishedKey = await hkdfExpandLabel(hashName, serverHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen);
		let serverFinishedReceived = !1;
		const handleHandshakeMessage = async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
					const encryptedExtensions = parseEncryptedExtensions(message.body);
					encryptedExtensions.alpn && (this.negotiatedAlpn = encryptedExtensions.alpn), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE: {
					const certificate = extractLeafCertificate(message.body);
					if (!certificate) throw new Error("Missing TLS 1.3 certificate");
					await this.acceptCertificate(certificate), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					throw new Error("Client certificate is not supported");
				case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
					this.recordHandshake(message.raw);
					break;
				case HANDSHAKE_TYPE_FINISHED: {
					const expectedVerifyData = await hmac(hashName, serverFinishedKey, await digestBytes(hashName, this.transcript()));
					if (!constantTimeEqual(expectedVerifyData, message.body)) throw new Error("TLS 1.3 server Finished verify failed");
					this.recordHandshake(message.raw), serverFinishedReceived = !0;
					break
				}
				default:
					this.recordHandshake(message.raw)
			}
		};
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
			const decrypted = await this.decryptTls13Handshake(record.fragment),
				innerType = decrypted[decrypted.length - 1],
				plaintext = decrypted.slice(0, -1);
			if (innerType === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(plaintext);
				for (let message; message = this.handshakeParser.next();)
					if (await handleHandshakeMessage(message), serverFinishedReceived) return 1
			}
		}), "Connection closed during TLS 1.3 handshake");
		const applicationTranscriptHash = await digestBytes(hashName, this.transcript()),
			masterDerivedSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen),
			masterSecret = await hkdfExtract(hashName, masterDerivedSecret, new Uint8Array(hashLen)),
			clientAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "c ap traffic", applicationTranscriptHash, hashLen),
			serverAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "s ap traffic", applicationTranscriptHash, hashLen);
		[this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hashName, clientAppTrafficSecret, keyLen, ivLen), [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hashName, serverAppTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([importAesGcmKey(this.clientAppKey, ["encrypt"]), importAesGcmKey(this.serverAppKey, ["decrypt"])]);
		const clientFinishedKey = await hkdfExpandLabel(hashName, clientHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen),
			clientFinishedVerifyData = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript())),
			clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientFinishedVerifyData);
		this.recordHandshake(clientFinishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, await this.encryptTls13Handshake(concatBytes(clientFinishedMessage, [CONTENT_TYPE_HANDSHAKE])))), this.clientSeqNum = 0n, this.serverSeqNum = 0n
	}
	async encryptTls12(plaintext, contentType) {
		const sequenceNumber = this.clientSeqNum++,
			sequenceBytes = uint64be(sequenceNumber),
			additionalData = concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(plaintext.length));
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.clientWriteIv, sequenceNumber);
			return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, additionalData)
		}
		const explicitNonce = randomBytes(8);
		if (!this.clientWriteCryptoKey) this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
		return concatBytes(explicitNonce, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBytes(this.clientWriteIv, explicitNonce), plaintext, additionalData))
	}
	async decryptTls12(ciphertext, contentType) {
		const sequenceNumber = this.serverSeqNum++,
			sequenceBytes = uint64be(sequenceNumber);
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.serverWriteIv, sequenceNumber);
			return chacha20Poly1305Decrypt(this.serverWriteKey, nonce, ciphertext, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(ciphertext.length - 16)))
		}
		const explicitNonce = ciphertext.subarray(0, 8),
			encryptedData = ciphertext.subarray(8);
		if (!this.serverWriteCryptoKey) this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
		return aesGcmDecryptWithKey(this.serverWriteCryptoKey, concatBytes(this.serverWriteIv, explicitNonce), encryptedData, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(encryptedData.length - 16)))
	}
	async encryptTls13Handshake(plaintext) {
		const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, additionalData);
		if (!this.clientHandshakeCryptoKey) this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13Handshake(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
		const decrypted = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey || (this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = decrypted.length - 1;
		for (; innerTypeIndex >= 0 && !decrypted[innerTypeIndex];) innerTypeIndex--;
		return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1)
	}
	async encryptTls13(data) {
		const plaintext = concatBytes(data, [CONTENT_TYPE_APPLICATION_DATA]),
			nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, additionalData);
		if (!this.clientAppCryptoKey) this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length)),
			plaintext = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverAppCryptoKey || (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = plaintext.length - 1;
		for (; innerTypeIndex >= 0 && !plaintext[innerTypeIndex];) innerTypeIndex--;
		if (innerTypeIndex < 0) return {
			data: EMPTY_BYTES,
			type: 0
		};
		return {
			data: plaintext.slice(0, innerTypeIndex),
			type: plaintext[innerTypeIndex]
		}
	}
	async write(data) {
		if (!this.handshakeComplete) throw new Error("Handshake not complete");
		const plaintext = 数据转Uint8Array(data);
		if (!plaintext.byteLength) return;
		const writer = this.socket.writable.getWriter();
		try {
			const records = [];
			for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
				const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
				const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
				records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
			}
			await writer.write(records.length === 1 ? records[0] : concatBytes(...records))
		} finally {
			writer.releaseLock()
		}
	}
	async read() {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${record.fragment[1]}`)
				}
				if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
				if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
				const { data, type } = await this.decryptTls13(record.fragment);
				if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
				if (type === CONTENT_TYPE_ALERT) {
					if (data[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${data[1]}`)
				}
				if (type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(data); message = this.handshakeParser.next();)
					if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE) throw new Error("TLS 1.3 KeyUpdate is not supported by TLSClientMini")
			}
			const reader = this.socket.readable.getReader();
			try {
				const { value, done } = await this.readChunk(reader);
				if (done) return null;
				this.recordParser.feed(value)
			} finally {
				reader.releaseLock()
			}
		}
	}
	close() { this.socket.close() }
}
