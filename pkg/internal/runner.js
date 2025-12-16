import EmscriptenModuleFactory from "./wasm-wrapper.js";
import fs from "fs";
import path from "path"; // Added path import
import readline from "readline";
import crypto from "crypto";

const [, , wasmPath] = process.argv;
const keyStr =
	process.env.SECURE_KEY ||
	"wODdrvWqmdP4Zliay-iF3cz3KZcK0ekrial868apg06TXeCo7A1hIQO0ESElHg6D";
const clientVersion = process.env.CLIENT_VERSION || "3.7.1";

if (!keyStr || !clientVersion) {
	console.error(
		"SECURE_KEY and CLIENT_VERSION environment variables must be set."
	);
	process.exit(1);
}

// Ensure WebCrypto polyfill is present for WASM if needed
if (!global.window) global.window = {};
if (!global.window.crypto) {
	global.window.crypto = {
		subtle: crypto.webcrypto.subtle,
		getRandomValues: (arr) => crypto.webcrypto.getRandomValues(arr),
	};
}

// Required shim for Emscripten to access Node modules
function emscriptenRequireShim(id) {
	if (id === 5982) return path;
	if (id === 45742) return fs;
	if (id === 1426) return process;
	if (id === 86433) return crypto;
	return {};
}

async function init() {
	try {
		const wasmBinary = fs.readFileSync(wasmPath);
		const mockExports = {};
		const mockModule = { exports: mockExports };

		// Pass the shim to the factory!
		EmscriptenModuleFactory(mockModule, mockExports, emscriptenRequireShim);
		const factory = mockModule.exports.exports;

		const moduleArg = {
			wasmBinary: wasmBinary,
			locateFile: (p) => p,
		};

		const instance = await factory(moduleArg);
		// Extract required classes
		const { SecureKey, Hmac, Curve25519Key } = instance;
		return { SecureKey, Hmac, Curve25519Key };
	} catch (e) {
		console.error("WASM Init Failed:", e);
		process.exit(1);
	}
}

// Persist the login key so we can derive the confirm hash after LF1
let loginCurveKey = null;

async function run() {
	try {
		const { SecureKey, Hmac, Curve25519Key } = await init();
		const secureKey = SecureKey.loadToken(keyStr);

		// Helper: generate PIN-wrapped secret for loginV2
		const generateLoginSecret = () => {
			const generatePin = () => {
				const limit = 4_294_000_000; // floor(2^32 / 1e6) * 1e6 to avoid modulo bias
				while (true) {
					const n = crypto.randomBytes(4).readUInt32BE(0);
					if (n < limit)
						return String(n % 1_000_000).padStart(6, "0");
				}
			};
			const pin = generatePin();

			loginCurveKey = new Curve25519Key(secureKey);
			const pubRaw = Buffer.from(loginCurveKey.getPublicKey());

			// AES-256-CBC per 16-byte block, zero IV, take first block only (matches LINE extension)
			const aesKey = crypto.createHash("sha256").update(pin).digest();
			const iv = Buffer.alloc(16, 0);
			const encryptBlock = (block) => {
				const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
				const out = Buffer.concat([
					cipher.update(block),
					cipher.final(),
				]);
				return out.subarray(0, 16);
			};
			const secretBytes = Buffer.concat([
				encryptBlock(pubRaw.subarray(0, 16)),
				encryptBlock(pubRaw.subarray(16, 32)),
			]);

			return {
				pin,
				secret: secretBytes.toString("base64"),
				publicKeyHex: pubRaw.toString("hex"),
			};
		};

		// Helper: derive hash key chain for confirmE2EELogin
		const generateHashKeyChain = (serverPubB64, encryptedKeyChainB64) => {
			if (!loginCurveKey) {
				throw new Error("login key not initialized");
			}

			const serverRaw = Buffer.from(serverPubB64, "base64");
			const raw32 =
				serverRaw.length === 32
					? serverRaw
					: serverRaw.length > 32
					? serverRaw.subarray(serverRaw.length - 32)
					: (() => {
							throw new Error("invalid server public key length");
					  })();

			const channel = loginCurveKey.createChannel(raw32);
			const encKeyChain = Buffer.from(encryptedKeyChainB64, "base64");
			const hashBytes =
				channel.generateHashKeyChainToConfirmE2EE(encKeyChain);

			return Buffer.from(hashBytes).toString("base64");
		};

		const rl = readline.createInterface({
			input: process.stdin,
			terminal: false,
		});

		const processQuery = async (queryStr) => {
			let query = {};
			try {
				query = JSON.parse(queryStr);
			} catch (e) {
				console.error("Failed to parse query:", e);
				process.stdout.write(
					JSON.stringify({ error: e.message }) + "\n"
				);
				return;
			}

			const type = query.type || "sign";

			try {
				if (type === "e2ee") {
					const result = generateLoginSecret();
					process.stdout.write(
						JSON.stringify({
							secret: result.secret,
							pin: result.pin,
							publicKeyHex: result.publicKeyHex,
						}) + "\n"
					);
				} else if (type === "confirm_hash") {
					const { serverPublicKey, encryptedKeyChain } = query;
					const hash = generateHashKeyChain(
						serverPublicKey,
						encryptedKeyChain
					);
					process.stdout.write(JSON.stringify({ hash }) + "\n");
				} else if (type === "qr" || type === "qr_secret") {
					const result = generateQrSecret();
					process.stdout.write(
						JSON.stringify({
							secret: result.secret,
							pin: result.pin,
							publicKeyHex: result.publicKeyHex,
						}) + "\n"
					);
				} else if (type === "sign") {
					let { reqPath, body, accessToken } = query;

					if (typeof reqPath !== "string") {
						throw new Error("Invalid sign query format");
					}
					if (typeof body !== "string") {
						body = "";
					}

					accessToken = accessToken || "";
					body = body || "";

					if (!reqPath.startsWith("/")) {
						reqPath = "/" + reqPath;
					}

					const calculateSha256 = async (data) => {
						if (typeof data === "string")
							data = new TextEncoder().encode(data);
						return new Uint8Array(
							await global.window.crypto.subtle.digest(
								"SHA-256",
								data
							)
						);
					};

					const secureKey = SecureKey.loadToken(keyStr);
					const clientVersionHash = await calculateSha256(
						clientVersion
					);
					const accessTokenHash = await calculateSha256(accessToken);

					const derivedKey = secureKey.deriveKey(
						clientVersionHash,
						accessTokenHash
					);
					const hmac = new Hmac(derivedKey);

					const dataToSign = new TextEncoder().encode(reqPath + body);
					const signatureBytes = hmac.digest(dataToSign);

					const signature =
						Buffer.from(signatureBytes).toString("base64");

					process.stdout.write(
						JSON.stringify({
							signature: signature,
						}) + "\n"
					);
				} else {
					throw new Error("Unknown command type: " + type);
				}
			} catch (e) {
				console.error("Error processing request:", e);
				process.stdout.write(
					JSON.stringify({ error: e.message }) + "\n"
				);
			}
		};

		rl.on("line", (line) => {
			if (line.trim()) processQuery(line);
		});
	} catch (e) {
		console.error(e);
		process.exit(1);
	}
}

run();
