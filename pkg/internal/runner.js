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
		const {
			SecureKey,
			Hmac,
			Curve25519Key,
			E2EEKey,
			E2EEChannel,
			E2EEKeychain,
			AesKey,
		} = instance;
		return {
			SecureKey,
			Hmac,
			Curve25519Key,
			E2EEKey,
			E2EEChannel,
			E2EEKeychain,
			AesKey,
		};
	} catch (e) {
		console.error("WASM Init Failed:", e);
		process.exit(1);
	}
}

// Persist the login key so we can derive the confirm hash after LF1
let loginCurveKey = null;

async function run() {
	try {
		const {
			SecureKey,
			Hmac,
			Curve25519Key,
			E2EEKey,
			E2EEChannel,
			E2EEKeychain,
			AesKey,
		} = await init();
		const secureKey = SecureKey.loadToken(keyStr);

		let storageKey = null;
		const keyStore = new Map();
		const channelStore = new Map();
		let nextId = 1;

		const putKey = (key) => {
			const id = nextId++;
			keyStore.set(id, key);
			return id;
		};
		const getKey = (id) => {
			const key = keyStore.get(id);
			if (!key) throw new Error("unknown key");
			return key;
		};
		const putChannel = (chan) => {
			const id = nextId++;
			channelStore.set(id, chan);
			return id;
		};
		const getChannel = (id) => {
			const chan = channelStore.get(id);
			if (!chan) throw new Error("unknown channel");
			return chan;
		};
		const b64ToU8 = (b64) => new Uint8Array(Buffer.from(b64, "base64"));
		const u8ToB64 = (u8) => Buffer.from(u8).toString("base64");
		const ensureStorage = () => {
			if (!storageKey) throw new Error("storage key not initialized");
		};

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
			const toInt = (v) =>
				typeof v === "string" ? Number.parseInt(v, 10) : Number(v);
			const toIntStrict = (name, v) => {
				const n = toInt(v);
				if (!Number.isFinite(n)) {
					throw new Error(`invalid ${name}: ${JSON.stringify(v)}`);
				}
				return Math.trunc(n);
			};

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
				} else if (type === "login_unwrap_keychain") {
					const { serverPublicKey, encryptedKeyChain } = query;
					if (!loginCurveKey) {
						throw new Error("login key not initialized");
					}

					const serverRaw = Buffer.from(serverPublicKey, "base64");
					const raw32 =
						serverRaw.length === 32
							? serverRaw
							: serverRaw.length > 32
							? serverRaw.subarray(serverRaw.length - 32)
							: (() => {
									throw new Error("invalid server public key length");
						  })();

					const channel = loginCurveKey.createChannel(raw32);
					const unwrap = channel.unwrapE2EEKeyChain(
						b64ToU8(encryptedKeyChain)
					);
					const keys = [];
					for (let i = 0; i < unwrap.size(); i++) {
						const k = unwrap.get(i);
						const id = putKey(k);
						keys.push({
							keyId: id,
							exported: u8ToB64(k.exportKey()),
							version: k.getVersion(),
							rawKeyId: k.getKeyId(),
						});
					}
					process.stdout.write(JSON.stringify({ keys }) + "\n");
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
				} else if (type === "storage_init") {
					const { wrappedNonce, kdfParameter1, kdfParameter2 } = query;
					if (!wrappedNonce || !kdfParameter1 || !kdfParameter2) {
						throw new Error("missing storage init params");
					}
					const unwrapped = SecureKey.unwrapKeyFromEncryptedIdentityV3Response(
						b64ToU8(wrappedNonce),
						b64ToU8(kdfParameter1),
						b64ToU8(kdfParameter2)
					);
					storageKey = new AesKey(unwrapped);
					process.stdout.write(JSON.stringify({ ok: true }) + "\n");
				} else if (type === "storage_encrypt") {
					ensureStorage();
					const plaintext = query.plaintext ?? "";
					const ct = storageKey.encrypt(new TextEncoder().encode(plaintext));
					process.stdout.write(
						JSON.stringify({ ciphertext: u8ToB64(ct) }) + "\n"
					);
				} else if (type === "storage_decrypt") {
					ensureStorage();
					const { ciphertext } = query;
					if (!ciphertext) throw new Error("missing ciphertext");
					const pt = storageKey.decrypt(b64ToU8(ciphertext));
					process.stdout.write(
						JSON.stringify({
							plaintext: new TextDecoder().decode(Uint8Array.from(pt).buffer),
						}) + "\n"
					);
				} else if (type === "key_load") {
					const { key } = query;
					if (!key) throw new Error("missing key");
					const k = E2EEKey.loadKey(b64ToU8(key));
					const id = putKey(k);
					process.stdout.write(JSON.stringify({ keyId: id }) + "\n");
				} else if (type === "key_get_public") {
					const { keyId } = query;
					const k = getKey(keyId);
					process.stdout.write(
						JSON.stringify({ publicKey: u8ToB64(k.getPublicKey()) }) + "\n"
					);
				} else if (type === "key_get_id") {
					const { keyId } = query;
					const k = getKey(keyId);
					process.stdout.write(JSON.stringify({ key: k.getKeyId() }) + "\n");
				} else if (type === "channel_create") {
					const { keyId, peerPublicKey } = query;
					const k = getKey(keyId);
					const chan = k.createChannel(b64ToU8(peerPublicKey));
					const chanId = putChannel(chan);
					process.stdout.write(JSON.stringify({ channelId: chanId }) + "\n");
				} else if (type === "channel_unwrap_group_shared_key") {
					const { channelId, encryptedSharedKey } = query;
					const chan = getChannel(toIntStrict("channelId", channelId));
					const unwrappedKey = chan.unwrapGroupSharedKey(b64ToU8(encryptedSharedKey));
					const keyId = putKey(unwrappedKey);
					process.stdout.write(JSON.stringify({ keyId }) + "\n");
				} else if (type === "channel_encrypt_v2") {
					const {
						channelId,
						to,
						from,
						senderKeyId,
						receiverKeyId,
						contentType,
						sequenceNumber,
						plaintext,
					} = query;
					const seq = typeof sequenceNumber === "bigint" ? sequenceNumber : BigInt(sequenceNumber);
					const sKey = toIntStrict("senderKeyId", senderKeyId);
					const rKey = toIntStrict("receiverKeyId", receiverKeyId);
					const cType = toIntStrict("contentType", contentType);
					const chan = getChannel(toIntStrict("channelId", channelId));
					const ct = chan.encryptV2(
						to,
						from,
						sKey,
						rKey,
						cType,
						seq,
						new TextEncoder().encode(plaintext || "")
					);
					process.stdout.write(
						JSON.stringify({ ciphertext: u8ToB64(ct) }) + "\n"
					);
				} else if (type === "channel_decrypt_v2") {
					const {
						channelId,
						to,
						from,
						senderKeyId,
						receiverKeyId,
						contentType,
						ciphertext,
					} = query;
					const chan = getChannel(toIntStrict("channelId", channelId));
					const sKey = toIntStrict("senderKeyId", senderKeyId);
					const rKey = toIntStrict("receiverKeyId", receiverKeyId);
					const cType = toIntStrict("contentType", contentType);
					const pt = chan.decryptV2(
						to,
						from,
						sKey,
						rKey,
						cType,
						b64ToU8(ciphertext)
					);
					const plaintext = new TextDecoder().decode(Uint8Array.from(pt).buffer);
					process.stdout.write(
						JSON.stringify({ plaintext, base64: u8ToB64(pt) }) + "\n"
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
