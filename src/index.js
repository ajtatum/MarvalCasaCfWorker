addEventListener('fetch', event => {
	event.respondWith(handleRequest(event.request, event));
})

async function handleRequest (request, event) {
	// Implement rate limiting using Cloudflare D1
	const rateLimitResponse = await applyRateLimit(request);
	if (rateLimitResponse) {
		return rateLimitResponse;
	}

	const cache = caches.default;
	let response = await cache.match(request);
	if (response) {
		return response;
	}

	response = await fetch(request)
	const responseClone = response.clone();

	if (!response.ok) {
		return customErrorPage(response.status);
	}

	// Security Headers
	//response.headers.set('Strict-Transport-Security','max-age=31536000; includeSubDomains; preload');
	response.headers.set('X-Content-Type-Options', 'nosniff');
	response.headers.set('X-Frame-Options', 'DENY');
	//response.headers.set('Content-Security-Policy',"default-src 'self'; script-src 'self' https://trusted.cdn.com; style-src 'self' https://trusted.cdn.com; img-src 'self' data:;");
	response.headers.set('Referrer-Policy', 'no-referrer-when-downgrade');
	response.headers.set("X-XSS-Protection", "1; mode=block");
	response.headers.set("Access-Control-Allow-Origin", "*");

	const url = new URL(request.url);
	const pathname = url.pathname;
	let cacheOptions = {
		edgeTTL: 86400, // Default to 1 day TTL
		browserTTL: 3600 // Default to 1 hour TTL
	};

	if (pathname.endsWith(".html")) {
		cacheOptions.edgeTTL = 3600; // Cache for 1 hour at the edge
		cacheOptions.browserTTL = 1800; // Cache for 30 minutes in the browser
	} else if (pathname.endsWith(".css")) {
		cacheOptions.edgeTTL = 604800;
		cacheOptions.browserTTL = 86400;
	} else if (pathname.endsWith(".js")) {
		cacheOptions.edgeTTL = 604800;
		cacheOptions.browserTTL = 86400;
	} else if (pathname.endsWith(".png") || pathname.endsWith(".jpg") || pathname.endsWith(".jpeg") || pathname.endsWith(".gif") || pathname.endsWith(".webp")) {
		cacheOptions.edgeTTL = 604800;
		cacheOptions.browserTTL = 86400;
	}

	// Dynamic content handling (assuming dynamic content can be identified by URL patterns or query params)
	if (url.searchParams.has("nocache") || pathname.includes("/dynamic/")) {
    	// Bypass cache for dynamic content
		cacheOptions.edgeTTL = 0;
		cacheOptions.browserTTL = 0;
	}

	const originCacheControl = responseClone.headers.get('Cache-Control')
	if (originCacheControl) {
		const maxAgeMatch = originCacheControl.match(/max-age=(\d+)/);
		if (maxAgeMatch) {
			cacheOptions.browserTTL = parseInt(maxAgeMatch[1], 10);
		}
		cacheOptions.edgeTTL = cacheOptions.browserTTL > cacheOptions.edgeTTL ? cacheOptions.browserTTL	: cacheOptions.edgeTTL;
	}

	event.waitUntil(cache.put(request, responseClone))
	response = new Response(responseClone.body, responseClone);
	response.headers.set('Cache-Control',`public, max-age=${cacheOptions.browserTTL}`);

	return response;
}

// Rate Limiting using Cloudflare D1
async function applyRateLimit (request) {
	const rateLimitKey = `${request.headers.get('cf-connecting-ip')}:${request.url}`;
	const limit = 15; // Define your rate limit
	const ttl = 60; // Time window in seconds

	const url = request.url;;
	if (url.includes("https://metrics.tech.marvel.casa/js/plausible") || url.includes("https://metrics.tech.marvel.casa/api/event")) {
		limit = 100; // Higher rate limit for specific URLs
	}	

	// Fetch existing rate limit data from D1
	const result = await RATE_LIMIT_DB.prepare(
		'SELECT count, timestamp FROM rate_limit WHERE id = ?'
	)
	.bind(rateLimitKey).first();

	let currentCount = 0;
	const now = Math.floor(Date.now() / 1000);

	if (result) {
		const { count, timestamp } = result;
		if (now - timestamp < ttl) {
			currentCount = count;
		} else {
			currentCount = 0; // Reset count if time window has passed
		}
	}

	if (currentCount >= limit) {
		return new Response('Too many requests', { status: 429 });
	}

	// Update or insert the new count in D1
	if (result) {
		await RATE_LIMIT_DB.prepare(
			'UPDATE rate_limit SET count = ?, timestamp = ? WHERE id = ?'
		)
		.bind(currentCount + 1, now, rateLimitKey).run();
	} else {
		await RATE_LIMIT_DB.prepare(
			'INSERT INTO rate_limit (id, count, timestamp) VALUES (?, ?, ?)'
		)
		.bind(rateLimitKey, 1, now).run();
	}

	// No rate limit exceeded, proceed with request handling
	return null;
}

function customErrorPage (status, request) {
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
						color: #333;
						font-weight: 700;
						text-align: center;
					}

					.error-container .error-details {
						font-size: 1.2rem;
						color: #666;
						font-weight: 500;
						margin-top: 1em;
					}

					.error-container .error-details b {
						color: #333;
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
						<div class="error-details"><b>Status:</b>${status} - ${message}</div>
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
