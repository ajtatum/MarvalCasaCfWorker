export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);

		// Handle the cache clearing endpoint
		if (url.pathname === '/clear-cache') {
			return await clearCache(request, env);
		}

		return await handleRequest(request, env, ctx);
	}
}

// Function to handle the cache clearing endpoint
async function clearCache(request, env) {
	const url = new URL(request.url);
	const subdomain = url.searchParams.get('subdomain');

	if (!subdomain) {
		return new Response('Subdomain is required', {
			status: 400
		});
	}

	if (!url.searchParams.get('token') || url.searchParams.get('token') !== `${env.CLEAR_CACHE_TOKEN}`) {
		return new Response('Unauthorized', {
			status: 401
		});
	}

	const cache = caches.default;
	const cacheKeys = await cache.keys();

	// Filter and delete cached items related to the specific subdomain
	for (const cacheKey of cacheKeys) {
		const cacheUrl = new URL(cacheKey.url);
		if (cacheUrl.hostname === `${subdomain}.marvel.casa`) {
			await cache.delete(cacheKey);
		}
	}

	return new Response(`Cache cleared for ${subdomain}.marvel.casa`, {
		status: 200
	});
}

// Main function to handle regular requests
async function handleRequest(request, env, ctx) {
	const url = new URL(request.url);

	// Handle WebSocket Upgrade
	if (request.headers.get('Upgrade') === 'websocket') {
		return handleWebSocket(request);
	}

	// Implement rate limiting using Cloudflare D1
	const rateLimitResponse = await applyRateLimit(request, env);
	if (rateLimitResponse) {
		return rateLimitResponse;
	}

	// Skip Cloudflare caching for the auth.marvel.casa domain
	if (url.hostname === 'auth.marvel.casa') {
		let response = await fetch(request);
		response = await handleCacheTTL(response, url.pathname);
		return await compressResponse(request, response);
	}

	// Continue with caching logic for other domains
	const cache = caches.default;
	let response = await cache.match(request);
	if (response) {
		console.log(`Cache hit for ${request.url}`);
		return response;
	}

	response = await fetch(request);
	ctx.waitUntil(cache.put(request, response.clone()));

	// Apply custom error pages for errors in the 400–599 range
	response = await handleErrorResponse(response, request);

	// Apply caching TTL and compression before returning the response
	response = await handleCacheTTL(response, url.pathname);
	return await compressResponse(request, response);
}

// Function to handle caching TTL (edge and browser) considering Cache-Control header
async function handleCacheTTL(response, url) {
	const responseHeaders = new Headers(response.headers);

	// Set default cache options
	let cacheOptions = {
		edgeTTL: 86400, // Default to 1 day
		browserTTL: 3600 // Default to 1 hour
	};

	// set static cache options
	let staticCacheOptions = {
		edgeTTL: 604800, // 1 week
		browserTTL: 86400 // 1 day
	};

	// Dynamic content handling (assuming dynamic content can be identified by URL patterns or query params)
	if (url.searchParams.has("nocache") || pathname.includes("/dynamic/")) {
		// Bypass cache for dynamic content
		cacheOptions.edgeTTL = 0;
		cacheOptions.browserTTL = 0;
	}

	const originCacheControl = responseHeaders.get("Cache-Control");

	if (originCacheControl) {
		// Parse Cache-Control header from the origin
		const cacheControlDirectives = originCacheControl.split(',').map(directive => directive.trim());

		if (cacheControlDirectives.includes("no-store")) {
			// Do not cache at all
			responseHeaders.set('Cache-Control', 'no-store');
			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: responseHeaders,
			});
		}

		if (cacheControlDirectives.includes("no-cache") || cacheControlDirectives.includes("private")) {
			// Cache only at the edge, not in the browser
			cacheOptions.edgeTTL = 0;
			cacheOptions.browserTTL = 0;
		}

		// Check for max-age directive
		const maxAgeDirective = cacheControlDirectives.find(directive => directive.startsWith("max-age="));
		if (maxAgeDirective) {
			const maxAge = parseInt(maxAgeDirective.split("=")[1], 10);
			cacheOptions.browserTTL = maxAge; // Use max-age from the origin for browser TTL
			cacheOptions.edgeTTL = Math.max(cacheOptions.edgeTTL, maxAge); // Use max-age from the origin if longer than the default edge TTL
		}
	} else {
		const pathname = url.pathname;

		// Determine TTL based on the type of content if no Cache-Control header is present
		if (pathname.endsWith(".html")) {
			cacheOptions.edgeTTL = 3600; // Cache HTML for 1 hour at the edge
			cacheOptions.browserTTL = 1800; // Cache HTML for 30 minutes in the browser
		} else if (pathname.endsWith(".css")) {
			cacheOptions.edgeTTL = staticCacheOptions.edgeTTL;
			cacheOptions.browserTTL = staticCacheOptions.browserTTL;
		} else if (pathname.endsWith(".js")) {
			cacheOptions.edgeTTL = staticCacheOptions.edgeTTL;
			cacheOptions.browserTTL = staticCacheOptions.browserTTL;
		} else if (pathname.endsWith(".png") || pathname.endsWith(".jpg") || pathname.endsWith(".jpeg") || pathname.endsWith(".gif") || pathname.endsWith(".webp")) {
			cacheOptions.edgeTTL = staticCacheOptions.edgeTTL;
			cacheOptions.browserTTL = staticCacheOptions.browserTTL;
		}
	}

	// Set the Cache-Control header for the browser
	responseHeaders.set("Cache-Control", `public, max-age=${cacheOptions.browserTTL}`);
	//responseHeaders.set('Strict-Transport-Security','max-age=31536000; includeSubDomains; preload');
	responseHeaders.set('X-Content-Type-Options', 'nosniff');
	responseHeaders.set('X-Frame-Options', 'DENY');
	//responseHeaders.set('Content-Security-Policy',"default-src 'self'; script-src 'self' https://trusted.cdn.com; style-src 'self' https://trusted.cdn.com; img-src 'self' data:;");
	responseHeaders.set('Referrer-Policy', 'no-referrer-when-downgrade');
	responseHeaders.set("X-XSS-Protection", "1; mode=block");
	responseHeaders.set("Access-Control-Allow-Origin", "*");

	// Set the edge cache TTL using the cf object
	const modifiedResponse = new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: responseHeaders,
	});

	return modifiedResponse;
}

// Function to handle response compression
async function compressResponse(request, response) {
	const acceptEncoding = request.headers.get('Accept-Encoding') || '';
	const contentType = response.headers.get('Content-Type') || '';

	// Determine if we should compress based on Content-Type
	const shouldCompress = contentType.startsWith('text/') ||
		contentType.includes('javascript') ||
		contentType.includes('json') ||
		contentType.includes('css') ||
		contentType.includes('xml');

	if (!shouldCompress) {
		// Skip compression for non-text content like images, videos, etc.
		return response;
	}

	let contentEncoding = '';
	let compressedBody;

	// Apply Brotli compression if supported
	if (acceptEncoding.includes('br')) {
		contentEncoding = 'br';
		compressedBody = await compressWithBrotli(await response.text());
	} else if (acceptEncoding.includes('gzip')) {
		// Apply Gzip compression if supported
		contentEncoding = 'gzip';
		compressedBody = await compressWithGzip(await response.text());
	} else if (acceptEncoding.includes('deflate')) {
		// Apply Deflate compression if supported
		contentEncoding = 'deflate';
		compressedBody = await compressWithDeflate(await response.text());
	} else {
		// No compression supported
		return response;
	}

	// Return compressed response
	return new Response(compressedBody, {
		status: response.status,
		statusText: response.statusText,
		headers: {
			...Object.fromEntries(response.headers),
			'Content-Encoding': contentEncoding,
			'Vary': 'Accept-Encoding', // To ensure correct caching based on encoding
		},
	});
}

// Placeholder functions for compression algorithms (implement as needed)
async function compressWithBrotli(text) {
	// Use a Brotli compression library to compress the text
	// e.g., using zlib in a Node.js environment, or a WebAssembly module for Workers
	// This is a placeholder
	return new TextEncoder().encode(text); // Replace with actual Brotli compression
}

async function compressWithGzip(text) {
	// Use a Gzip compression library to compress the text
	// This is a placeholder
	return new TextEncoder().encode(text); // Replace with actual Gzip compression
}

async function compressWithDeflate(text) {
	// Use a Deflate compression library to compress the text
	// This is a placeholder
	return new TextEncoder().encode(text); // Replace with actual Deflate compression
}

// Handle WebSocket Upgrade
function handleWebSocket(request) {
	const upgradeHeader = request.headers.get('Upgrade');
	if (upgradeHeader !== 'websocket') {
		return new Response('Expected WebSocket upgrade', {
			status: 426
		});
	}

	const [client, server] = new WebSocketPair();
	server.accept();

	// Handle the WebSocket connection on the server side
	server.addEventListener('message', event => {
		server.send(`${event.data}`);
	});

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

// Apply custom error handling for HTTP status codes 400–599
async function handleErrorResponse(response, request) {
	if (response.status >= 400 && response.status < 600) {
		return customErrorPage(response.status, request);
	}
	return response;
}

// Rate Limiting using Cloudflare D1
async function applyRateLimit(request, env) {
	const url = new URL(request.url);

	// Check if the request is from another subdomain of marvel.casa
	const origin = request.headers.get('Origin');
	const referer = request.headers.get('Referer');

	if (origin || referer) {
		const originURL = new URL(origin || referer);
		if (originURL.hostname.endsWith('.marvel.casa') && originURL.hostname !== url.hostname) {
			// Bypass rate limiting for cross-subdomain requests within marvel.casa
			return null;
		}
	}

	let rateLimitKey;
	let limit = 15; // Default rate limit
	const ttl = 60; // Time window in seconds

	// Check if the request has an API key
	const apiKey = request.headers.get('x-api-key');
	if (apiKey) {
		rateLimitKey = `apiKey:${apiKey}`;
	} else {
		// Fallback to IP address
		const ipAddress = request.headers.get('cf-connecting-ip');
		rateLimitKey = `ip:${ipAddress}`;
	}

	if (url.includes("https://metrics.tech.marvel.casa/js/plausible") || url.includes("https://metrics.tech.marvel.casa/api/event")) {
		limit = 100; // Higher rate limit for specific URLs
	} else if (url.includes("auth.marvel.casa")) {
		limit = 10; // Lower rate limit for specific URLs
	}

	// Fetch existing rate limit data from D1
	const result = await env.RATE_LIMIT_DB.prepare(
			'SELECT count, timestamp FROM rate_limit WHERE id = ?'
		)
		.bind(rateLimitKey).first();

	let currentCount = 0;
	const now = Math.floor(Date.now() / 1000);

	if (result) {
		const {
			count,
			timestamp
		} = result;
		if (now - timestamp < ttl) {
			currentCount = count;
		} else {
			currentCount = 0; // Reset count if time window has passed
		}
	}

	if (currentCount >= limit) {
		return new Response('Too many requests. Please wait before trying again.', {
			status: 429,
			headers: {
				'Retry-After': String(ttl)
			},
		});
	}

	// Update or insert the new count in D1
	if (result) {
		await env.RATE_LIMIT_DB.prepare(
				'UPDATE rate_limit SET count = ?, timestamp = ? WHERE id = ?'
			)
			.bind(currentCount + 1, now, rateLimitKey).run();
	} else {
		await env.RATE_LIMIT_DB.prepare(
				'INSERT INTO rate_limit (id, count, timestamp) VALUES (?, ?, ?)'
			)
			.bind(rateLimitKey, 1, now).run();
	}

	// No rate limit exceeded, proceed with request handling
	return null;
}

function customErrorPage(status, request) {
	const errorPages = {
		400: 'Bad Request',
		401: 'Unauthorized',
		403: 'Access Forbidden',
		404: 'Page Not Found',
		429: 'Too Many Requests',
		500: 'Internal Server Error',
		502: 'Bad Gateway',
		503: 'Service Unavailable',
		504: 'Gateway Timeout'
		// Add more custom pages as needed
	};
	const statusTexts = {
		400: "Oops, did you send a jumbled mess? The server is having a meltdown trying to understand it. Maybe try again with some clarity?",
		401: "Hold up! You can't just walk in here. You need the secret handshake (or a login). Come back when you're authorized.",
		403: "Denied! Looks like you don't have the magic key to enter this realm. Permissions, right?",
		404: "Well, this is awkward. The page you're looking for took a detour, or maybe it never existed. Who knows?",
		429: "Whoa there, champ! You're going way too fast. How about a breather before you try again?",
		500: "Looks like the server just had a brain freeze. Give it a sec to reboot its thoughts, and maybe try again later?",
		502: "The server's middleman is acting up. It's like a bad game of telephone. Let's try again in a bit, okay?",
		503: "The server is taking a little 'me time.' It’ll be back once it’s done with its spa day. Please try again later.",
		504: "The server was too slow on the uptake, and now we're all just sitting here awkwardly. Maybe refresh and hope for the best?",
	};

	const message = errorPages[status] || 'Error';
	const statusText = statusTexts[status] || 'An error occurred. Please try again later.';
	const url = request.url;
	const timestamp = new Date().toISOString();
	const userAgent = request.headers.get('User-Agent');
	const referer = request.headers.get('Referer') || 'No referrer';

	// Cloudflare-specific variables
	const ipAddress = request.headers.get('cf-connecting-ip') || 'Unknown IP';
	const country = request.headers.get('cf-ipcountry') || 'Unknown country';
	const rayId = request.headers.get('cf-ray') || 'No Ray ID';
	const tlsVersion = request.cf && request.cf.tlsVersion ? request.cf.tlsVersion : 'Unknown TLS version';
	const httpProtocol = request.headers.get('cf-visitor') ? JSON.parse(request.headers.get('cf-visitor')).scheme : 'Unknown protocol';

	const htmlContent = `
		<!DOCTYPE html>
		<html lang="en">

			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Error ${status}</title>
				<style>
					@import url('https://fonts.googleapis.com/css2?family=PT+Sans:ital,wght@0,400;0,700;1,400;1,700&family=Poppins:wght@500;600;700&display=swap');

					body,
					html {
						margin: 0;
						padding: 0;
						height: 100%;
						background-image: url('https://imagedelivery.net/Px2XuROM7nCrn9B2uj7K4Q/9d20fb62-d108-413e-0615-eeaa84a0da00/3840w');
						background-size: cover;
						background-position: center;
						font-family: "Poppins", sans-serif;
						font-weight: 500;
						overflow: hidden;
						font-size: 16px;
					}

					.container {
						position: absolute;
						top: 50%;
						left: 50%;
						transform: translate(-50%, -50%);
						width: 80%;
						max-width: 50rem;
						background-color: rgba(255, 255, 255, 0.8);
						padding: 20px;
						border-radius: 10px;
						box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
					}

					.error-container {
						text-align: left;
						display: none;
					}

					.message-container {
						text-align: left;
					}

					.message-container .error-message {
						font-size: 1.4rem;
						color: #173F58;
						font-weight: 700;
						text-align: center;
					}

					.message-container .error-details {
						font-size: 1.2rem;
						color: #172839;
						font-weight: 500;
						margin-top: 1em;
						line-height: 2rem;
					}

					.message-container .error-details b {
						color: #173F58;
					}

					.ps {
						color: #461409 !important;
						font-weight: 600;
					}

					.error-container .error-message {
						font-size: 1.4rem;
						color: #173F58;
						font-weight: 700;
						text-align: center;
					}

					.error-container .error-details {
						font-size: 1.2rem;
						color: #172839;
						font-weight: 500;
						margin-top: 1em;
					}

					.error-container .error-details b {
						color: #173F58;
					}

					.toggle-container {
						text-align: center;
					}

					.toggle-button {
						display: inline-block;
						margin-top: 20px;
						padding: 10px 20px;
						background-color: #00438D;
						border: #00438D;
						color: white;
						text-decoration: none;
						border-radius: 5px;
						cursor: pointer;
						font-weight: 600;
						font-family: "Poppins", sans-serif;
					}
				</style>
				<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
			</head>

			<body>
				<div class="container">
					<div class="message-container">
						<div class="error-message">🌀 By the Eye of Agamotto, Something Has Gone Awry 🌀</div>
						<div class="error-details">
							<p><b>Greetings, traveler.</b> It appears the mystical energies of this domain are in flux, causing an unexpected disruption. Fear not, for the Sorcerer Supreme is on the case.</p>
							<p>While I delve into the arcane arts to restore balance, you may wish to seek refuge elsewhere in the multiverse. But worry not—this disturbance is temporary. Soon, all will be as it should.</p>
							<p>Until then, remember: <b><i>reality is often what we make of it.</b></i></p>
							<p>🕸️ Dr. Stephen Strange<br>Master of the Mystic Arts<br><span class="ps">P.S. If the anomaly persists, try a refresh—or summon me again later.</span></p>
						</div>
						<div class="toggle-container">
							<button class="toggle-button" onclick="showErrorDetails()">View Error Details</button>
						</div>
					</div>


					<div class="error-container">
						<div class="error-message">${statusText}</div>
						<div class="error-details"><b>Status:</b> ${status} - ${message}</div>
						<div class="error-details"><b>URL:</b> ${url}</div>
						<div class="error-details"><b>Time:</b> ${timestamp}</div>
						<div class="error-details"><b>User Agent:</b> ${userAgent}</div>
						<div class="error-details"><b>Referrer:</b> ${referer}</div>
						<div class="error-details"><b>IP Address:</b> ${ipAddress}</div>
						<div class="error-details"><b>Country:</b> ${country}</div>
						<div class="error-details"><b>Cloudflare Ray ID:</b> ${rayId}</div>
						<div class="error-details"><b>TLS Version:</b> ${tlsVersion}</div>
						<div class="error-details"><b>HTTP Protocol:</b> ${httpProtocol}</div>
						<div class="toggle-container">
							<button class="toggle-button" onclick="showMessageContainer()">&larr;</button>
					</div>

					</div>
				</div>
				<script>
					function showErrorDetails() {
						$('.message-container').fadeOut(300, function () {
							$('.error-container').fadeIn(300);
						});
					}

					function showMessageContainer() {
						$('.error-container').fadeOut(300, function () {
							$('.message-container').fadeIn(300);
						});
					}
				</script>
			</body>

		</html>
	`;

	return new Response(htmlContent, {
		status: status,
		headers: {
			'Content-Type': 'text/html'
		}
	});
}