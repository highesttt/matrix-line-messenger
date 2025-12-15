// internal/runner.js
// const fs = require("fs");
// const path = require("path");
// const crypto = require("crypto");

import fs from "fs";
import path from "path";
import crypto from "crypto";

// ----------------------------------------------------------------------------
// 1. Polyfills (Copied from your file)
// ----------------------------------------------------------------------------
if (!global.window) global.window = {};
if (!global.window.crypto) {
	global.window.crypto = {
		subtle: crypto.webcrypto.subtle,
		getRandomValues: (arr) => crypto.webcrypto.getRandomValues(arr),
	};
}
global.window.location = {
	origin: "chrome-extension://ophjlpahpchlmihnnnihgmmeilfjmjjc",
	search: "",
};
global.self = global.window;
if (!global.TextEncoder) global.TextEncoder = require("util").TextEncoder;
if (!global.TextDecoder) global.TextDecoder = require("util").TextDecoder;

// ----------------------------------------------------------------------------
// 2. Helpers
// ----------------------------------------------------------------------------
function requireFunc(id) {
	if (id === 5982) return path;
	if (id === 45742) return fs;
	if (id === 1426) return process;
	if (id === 86433) return crypto;
	return {};
}

/**
 * ----------------------------------------------------------------------------
 * 3. Emscripten Module Loader
 * ----------------------------------------------------------------------------
 * Extracted logic from ltsm.sandbox.js to load the WASM runtime.
 */
const EmscriptenModuleFactory = (module, exports) => {
	var n = requireFunc(1426),
		i = (() => {
			var e =
				"undefined" !== typeof document && document.currentScript
					? document.currentScript.src
					: void 0;
			return (
				(e = e || "/index.js"),
				function (t) {
					var i,
						o,
						a = "undefined" != typeof (t = t || {}) ? t : {};
					a.ready = new Promise(function (e, t) {
						(i = e), (o = t);
					});
					var s,
						u,
						c,
						l,
						d,
						f,
						h = Object.assign({}, a),
						p = [],
						m = "object" == typeof window,
						g = "function" == typeof importScripts,
						v =
							"object" == typeof n &&
							"object" == typeof n.versions &&
							"string" == typeof n.versions.node,
						y = "";
					v
						? ((y = g ? requireFunc(5982).dirname(y) + "/" : "//"),
						  (f = () => {
								d ||
									((l = requireFunc(45742)),
									(d = requireFunc(5982)));
						  }),
						  (s = function (e, t) {
								return (
									f(),
									(e = d.normalize(e)),
									l.readFileSync(e, t ? void 0 : "utf8")
								);
						  }),
						  (c = (e) => {
								var t = s(e, !0);
								return t.buffer || (t = new Uint8Array(t)), t;
						  }),
						  (u = (e, t, r) => {
								f(),
									(e = d.normalize(e)),
									l.readFile(e, function (e, n) {
										e ? r(e) : t(n.buffer);
									});
						  }),
						  n.argv.length > 1 && n.argv[1].replace(/\\/g, "/"),
						  (p = n.argv.slice(2)),
						  n.on("uncaughtException", function (e) {
								if (!(e instanceof or)) throw e;
						  }),
						  n.on("unhandledRejection", function (e) {
								throw e;
						  }),
						  (e, t) => {
								if (S) throw ((n.exitCode = e), t);
								!(function (e) {
									if (e instanceof or) return;
									w("exiting due to exception: " + e);
								})(t),
									n.exit(e);
						  },
						  (a.inspect = function () {
								return "[Emscripten Module object]";
						  }))
						: (m || g) &&
						  (g
								? (y = self.location.href)
								: "undefined" != typeof document &&
								  document.currentScript &&
								  (y = document.currentScript.src),
						  e && (y = e),
						  (y =
								0 !== y.indexOf("blob:")
									? y.substr(
											0,
											y
												.replace(/[?#].*/, "")
												.lastIndexOf("/") + 1
									  )
									: ""),
						  (s = (e) => {
								var t = new XMLHttpRequest();
								return (
									t.open("GET", e, !1),
									t.send(null),
									t.responseText
								);
						  }),
						  g &&
								(c = (e) => {
									var t = new XMLHttpRequest();
									return (
										t.open("GET", e, !1),
										(t.responseType = "arraybuffer"),
										t.send(null),
										new Uint8Array(t.response)
									);
								}),
						  (u = (e, t, r) => {
								var n = new XMLHttpRequest();
								n.open("GET", e, !0),
									(n.responseType = "arraybuffer"),
									(n.onload = () => {
										200 == n.status ||
										(0 == n.status && n.response)
											? t(n.response)
											: r();
									}),
									(n.onerror = r),
									n.send(null);
						  }));
					var b,
						E = a.print || function () {},
						w = a.printErr || function () {};
					Object.assign(a, h),
						(h = null),
						a.arguments && (p = a.arguments),
						a.thisProgram && a.thisProgram,
						a.quit && a.quit,
						a.wasmBinary && (b = a.wasmBinary);
					var _,
						S = a.noExitRuntime || !0;
					"object" != typeof WebAssembly &&
						oe("no native wasm support detected");
					var A = !1;
					function x(e, t) {
						e || oe(t);
					}
					var T =
						"undefined" != typeof TextDecoder
							? new TextDecoder("utf8")
							: void 0;
					function M(e, t, r) {
						for (var n = t + r, i = t; e[i] && !(i >= n); ) ++i;
						if (i - t > 16 && e.buffer && T)
							return T.decode(e.subarray(t, i));
						for (var o = ""; t < i; ) {
							var a = e[t++];
							if (128 & a) {
								var s = 63 & e[t++];
								if (192 != (224 & a)) {
									var u = 63 & e[t++];
									if (
										(a =
											224 == (240 & a)
												? ((15 & a) << 12) |
												  (s << 6) |
												  u
												: ((7 & a) << 18) |
												  (s << 12) |
												  (u << 6) |
												  (63 & e[t++])) < 65536
									)
										o += String.fromCharCode(a);
									else {
										var c = a - 65536;
										o += String.fromCharCode(
											55296 | (c >> 10),
											56320 | (1023 & c)
										);
									}
								} else
									o += String.fromCharCode(
										((31 & a) << 6) | s
									);
							} else o += String.fromCharCode(a);
						}
						return o;
					}
					function C(e, t) {
						return e ? M(L, e, t) : "";
					}
					function I(e, t, r, n) {
						if (!(n > 0)) return 0;
						for (
							var i = r, o = r + n - 1, a = 0;
							a < e.length;
							++a
						) {
							var s = e.charCodeAt(a);
							if (s >= 55296 && s <= 57343)
								s =
									(65536 + ((1023 & s) << 10)) |
									(1023 & e.charCodeAt(++a));
							if (s <= 127) {
								if (r >= o) break;
								t[r++] = s;
							} else if (s <= 2047) {
								if (r + 1 >= o) break;
								(t[r++] = 192 | (s >> 6)),
									(t[r++] = 128 | (63 & s));
							} else if (s <= 65535) {
								if (r + 2 >= o) break;
								(t[r++] = 224 | (s >> 12)),
									(t[r++] = 128 | ((s >> 6) & 63)),
									(t[r++] = 128 | (63 & s));
							} else {
								if (r + 3 >= o) break;
								(t[r++] = 240 | (s >> 18)),
									(t[r++] = 128 | ((s >> 12) & 63)),
									(t[r++] = 128 | ((s >> 6) & 63)),
									(t[r++] = 128 | (63 & s));
							}
						}
						return (t[r] = 0), r - i;
					}
					function R(e, t, r) {
						return I(e, L, t, r);
					}
					function k(e) {
						for (var t = 0, r = 0; r < e.length; ++r) {
							var n = e.charCodeAt(r);
							n >= 55296 &&
								n <= 57343 &&
								(n =
									(65536 + ((1023 & n) << 10)) |
									(1023 & e.charCodeAt(++r))),
								n <= 127
									? ++t
									: (t += n <= 2047 ? 2 : n <= 65535 ? 3 : 4);
						}
						return t;
					}
					var O,
						N,
						L,
						P,
						D,
						B,
						U,
						j,
						F,
						V,
						q,
						H =
							"undefined" != typeof TextDecoder
								? new TextDecoder("utf-16le")
								: void 0;
					function K(e, t) {
						for (
							var r = e, n = r >> 1, i = n + t / 2;
							!(n >= i) && D[n];

						)
							++n;
						if ((r = n << 1) - e > 32 && H)
							return H.decode(L.subarray(e, r));
						for (var o = "", a = 0; !(a >= t / 2); ++a) {
							var s = P[(e + 2 * a) >> 1];
							if (0 == s) break;
							o += String.fromCharCode(s);
						}
						return o;
					}
					function G(e, t, r) {
						if ((void 0 === r && (r = 2147483647), r < 2)) return 0;
						for (
							var n = t,
								i = (r -= 2) < 2 * e.length ? r / 2 : e.length,
								o = 0;
							o < i;
							++o
						) {
							var a = e.charCodeAt(o);
							(P[t >> 1] = a), (t += 2);
						}
						return (P[t >> 1] = 0), t - n;
					}
					function z(e) {
						return 2 * e.length;
					}
					function W(e, t) {
						for (var r = 0, n = ""; !(r >= t / 4); ) {
							var i = B[(e + 4 * r) >> 2];
							if (0 == i) break;
							if ((++r, i >= 65536)) {
								var o = i - 65536;
								n += String.fromCharCode(
									55296 | (o >> 10),
									56320 | (1023 & o)
								);
							} else n += String.fromCharCode(i);
						}
						return n;
					}
					function $(e, t, r) {
						if ((void 0 === r && (r = 2147483647), r < 4)) return 0;
						for (
							var n = t, i = n + r - 4, o = 0;
							o < e.length;
							++o
						) {
							var a = e.charCodeAt(o);
							if (a >= 55296 && a <= 57343)
								a =
									(65536 + ((1023 & a) << 10)) |
									(1023 & e.charCodeAt(++o));
							if (((B[t >> 2] = a), (t += 4) + 4 > i)) break;
						}
						return (B[t >> 2] = 0), t - n;
					}
					function X(e) {
						for (var t = 0, r = 0; r < e.length; ++r) {
							var n = e.charCodeAt(r);
							n >= 55296 && n <= 57343 && ++r, (t += 4);
						}
						return t;
					}
					a.INITIAL_MEMORY;
					var Y,
						Q = [],
						J = [],
						Z = [];
					var ee = 0,
						te = null,
						re = null;
					function ne(e) {
						ee++,
							a.monitorRunDependencies &&
								a.monitorRunDependencies(ee);
					}
					function ie(e) {
						if (
							(ee--,
							a.monitorRunDependencies &&
								a.monitorRunDependencies(ee),
							0 == ee &&
								(null !== te &&
									(clearInterval(te), (te = null)),
								re))
						) {
							var t = re;
							(re = null), t();
						}
					}
					function oe(e) {
						a.onAbort && a.onAbort(e),
							w((e = "Aborted(" + e + ")")),
							(A = !0),
							1,
							(e += ". Build with -sASSERTIONS for more info.");
						var t = new WebAssembly.RuntimeError(e);
						throw (o(t), t);
					}
					var ae,
						se,
						ue = "data:application/octet-stream;base64,";
					function ce(e) {
						return e.startsWith(ue);
					}
					function le(e) {
						return e.startsWith("file://");
					}
					function de(e) {
						try {
							if (e == ae && b) return new Uint8Array(b);
							if (c) return c(e);
							throw "both async and sync fetching of the wasm failed";
						} catch (w) {
							oe(w);
						}
					}
					ce((ae = "ltsm.wasm")) ||
						((se = ae),
						(ae = a.locateFile ? a.locateFile(se, y) : y + se));
					var fe = {
						1456932: (e, t) => {
							throw C(e) + ": " + C(t);
						},
						1456985: () => {
							if (void 0 === a.getRandomValues)
								try {
									var e =
										"object" === typeof window
											? window
											: self;
									if (
										"function" !==
										typeof (t =
											"undefined" !== typeof e.crypto
												? e.crypto
												: e.msCrypto).getRandomValues
									)
										throw "Crypto.getRandomValues is not a function";
									a.getRandomValues = function (e) {
										t.getRandomValues(e);
									};
								} catch (n) {}
							if (void 0 === a.getRandomValues)
								try {
									var t;
									if (
										"function" !==
										typeof (t = requireFunc(86433))
											.randomFillSync
									)
										throw "crypto.randomFillSync is not a function";
									a.getRandomValues = function (e) {
										t.randomFillSync(e);
									};
								} catch (n) {}
							return void 0 === a.getRandomValues ? 1 : 0;
						},
						1457725: (e, t) => {
							var r = 1,
								n = L.subarray(e, e + t);
							try {
								a.getRandomValues(n), (r = 0);
							} catch (i) {
								r = 1;
							}
							return r;
						},
					};
					function he(e) {
						for (; e.length > 0; ) {
							var t = e.shift();
							if ("function" != typeof t) {
								var r = t.func;
								"number" == typeof r
									? void 0 === t.arg
										? me(r)()
										: me(r)(t.arg)
									: r(void 0 === t.arg ? null : t.arg);
							} else t(a);
						}
					}
					var pe = [];
					function me(e) {
						var t = pe[e];
						return (
							t ||
								(e >= pe.length && (pe.length = e + 1),
								(pe[e] = t = Y.get(e))),
							t
						);
					}
					function ge(e) {
						(this.excPtr = e),
							(this.ptr = e - 24),
							(this.set_type = function (e) {
								U[(this.ptr + 4) >> 2] = e;
							}),
							(this.get_type = function () {
								return U[(this.ptr + 4) >> 2];
							}),
							(this.set_destructor = function (e) {
								U[(this.ptr + 8) >> 2] = e;
							}),
							(this.get_destructor = function () {
								return U[(this.ptr + 8) >> 2];
							}),
							(this.set_refcount = function (e) {
								B[this.ptr >> 2] = e;
							}),
							(this.set_caught = function (e) {
								(e = e ? 1 : 0), (N[(this.ptr + 12) >> 0] = e);
							}),
							(this.get_caught = function () {
								return 0 != N[(this.ptr + 12) >> 0];
							}),
							(this.set_rethrown = function (e) {
								(e = e ? 1 : 0), (N[(this.ptr + 13) >> 0] = e);
							}),
							(this.get_rethrown = function () {
								return 0 != N[(this.ptr + 13) >> 0];
							}),
							(this.init = function (e, t) {
								this.set_adjusted_ptr(0),
									this.set_type(e),
									this.set_destructor(t),
									this.set_refcount(0),
									this.set_caught(!1),
									this.set_rethrown(!1);
							}),
							(this.add_ref = function () {
								var e = B[this.ptr >> 2];
								B[this.ptr >> 2] = e + 1;
							}),
							(this.release_ref = function () {
								var e = B[this.ptr >> 2];
								return (B[this.ptr >> 2] = e - 1), 1 === e;
							}),
							(this.set_adjusted_ptr = function (e) {
								U[(this.ptr + 16) >> 2] = e;
							}),
							(this.get_adjusted_ptr = function () {
								return U[(this.ptr + 16) >> 2];
							}),
							(this.get_exception_ptr = function () {
								if (ir(this.get_type()))
									return U[this.excPtr >> 2];
								var e = this.get_adjusted_ptr();
								return 0 !== e ? e : this.excPtr;
							});
					}
					var ve = {
						isAbs: (e) => "/" === e.charAt(0),
						splitPath: (e) =>
							/^(\/|)([ -￿]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/i
								.exec(e)
								.slice(1),
						normalizeArray: (e, t) => {
							for (var r = 0, n = e.length - 1; n >= 0; n--) {
								var i = e[n];
								"." === i
									? e.splice(n, 1)
									: ".." === i
									? (e.splice(n, 1), r++)
									: r && (e.splice(n, 1), r--);
							}
							if (t) for (; r; r--) e.unshift("..");
							return e;
						},
						normalize: (e) => {
							var t = ve.isAbs(e),
								r = "/" === e.substr(-1);
							return (
								(e = ve
									.normalizeArray(
										e.split("/").filter((e) => !!e),
										!t
									)
									.join("/")) ||
									t ||
									(e = "."),
								e && r && (e += "/"),
								(t ? "/" : "") + e
							);
						},
						dirname: (e) => {
							var t = ve.splitPath(e),
								r = t[0],
								n = t[1];
							return r || n
								? (n && (n = n.substr(0, n.length - 1)), r + n)
								: ".";
						},
						basename: (e) => {
							if ("/" === e) return "/";
							var t = (e = (e = ve.normalize(e)).replace(
								/\$\/$/,
								""
							)).lastIndexOf("/");
							return -1 === t ? e : e.substr(t + 1);
						},
						join: function () {
							var e = Array.prototype.slice.call(arguments, 0);
							return ve.normalize(e.join("/"));
						},
						join2: (e, t) => ve.normalize(e + "/" + t),
					};
					var ye = {
							resolve: function () {
								for (
									var e = "",
										t = !1,
										r = arguments.length - 1;
									r >= -1 && !t;
									r--
								) {
									var n = r >= 0 ? arguments[r] : _e.cwd();
									if ("string" != typeof n)
										throw new TypeError(
											"Arguments to path.resolve must be strings"
										);
									if (!n) return "";
									(e = n + "/" + e), (t = ve.isAbs(n));
								}
								return (
									(t ? "/" : "") +
										(e = ve
											.normalizeArray(
												e.split("/").filter((e) => !!e),
												!t
											)
											.join("/")) || "."
								);
							},
							relative: (e, t) => {
								function r(e) {
									for (
										var t = 0;
										t < e.length && "" === e[t];
										t++
									);
									for (
										var r = e.length - 1;
										r >= 0 && "" === e[r];
										r--
									);
									return t > r ? [] : e.slice(t, r - t + 1);
								}
								(e = ye.resolve(e).substr(1)),
									(t = ye.resolve(t).substr(1));
								for (
									var n = r(e.split("/")),
										i = r(t.split("/")),
										o = Math.min(n.length, i.length),
										a = o,
										s = 0;
									s < o;
									s++
								)
									if (n[s] !== i[s]) {
										a = s;
										break;
									}
								var u = [];
								for (s = a; s < n.length; s++) u.push("..");
								return (u = u.concat(i.slice(a))).join("/");
							},
						},
						be = {
							ttys: [],
							init: function () {},
							shutdown: function () {},
							register: function (e, t) {
								(be.ttys[e] = {
									input: [],
									output: [],
									ops: t,
								}),
									_e.registerDevice(e, be.stream_ops);
							},
							stream_ops: {
								open: function (e) {
									var t = be.ttys[e.node.rdev];
									if (!t) throw new _e.ErrnoError(43);
									(e.tty = t), (e.seekable = !1);
								},
								close: function (e) {
									e.tty.ops.flush(e.tty);
								},
								flush: function (e) {
									e.tty.ops.flush(e.tty);
								},
								read: function (e, t, r, n, i) {
									if (!e.tty || !e.tty.ops.get_char)
										throw new _e.ErrnoError(60);
									for (var o = 0, a = 0; a < n; a++) {
										var s;
										try {
											s = e.tty.ops.get_char(e.tty);
										} catch (u) {
											throw new _e.ErrnoError(29);
										}
										if (void 0 === s && 0 === o)
											throw new _e.ErrnoError(6);
										if (null === s || void 0 === s) break;
										o++, (t[r + a] = s);
									}
									return (
										o && (e.node.timestamp = Date.now()), o
									);
								},
								write: function (e, t, r, n, i) {
									if (!e.tty || !e.tty.ops.put_char)
										throw new _e.ErrnoError(60);
									try {
										for (var o = 0; o < n; o++)
											e.tty.ops.put_char(e.tty, t[r + o]);
									} catch (a) {
										throw new _e.ErrnoError(29);
									}
									return (
										n && (e.node.timestamp = Date.now()), o
									);
								},
							},
							default_tty_ops: {
								get_char: function (e) {
									if (!e.input.length) {
										var t = null;
										if (v) {
											var r = Buffer.alloc(256),
												i = 0;
											try {
												i = l.readSync(
													n.stdin.fd,
													r,
													0,
													256,
													-1
												);
											} catch (o) {
												if (
													!o
														.toString()
														.includes("EOF")
												)
													throw o;
												i = 0;
											}
											t =
												i > 0
													? r
															.slice(0, i)
															.toString("utf-8")
													: null;
										} else
											"undefined" != typeof window &&
											"function" == typeof window.prompt
												? null !==
														(t =
															window.prompt(
																"Input: "
															)) && (t += "\n")
												: "function" ==
														typeof readline &&
												  null !== (t = readline()) &&
												  (t += "\n");
										if (!t) return null;
										e.input = Qt(t, !0);
									}
									return e.input.shift();
								},
								put_char: function (e, t) {
									null === t || 10 === t
										? (E(M(e.output, 0)), (e.output = []))
										: 0 != t && e.output.push(t);
								},
								flush: function (e) {
									e.output &&
										e.output.length > 0 &&
										(E(M(e.output, 0)), (e.output = []));
								},
							},
							default_tty1_ops: {
								put_char: function (e, t) {
									null === t || 10 === t
										? (w(M(e.output, 0)), (e.output = []))
										: 0 != t && e.output.push(t);
								},
								flush: function (e) {
									e.output &&
										e.output.length > 0 &&
										(w(M(e.output, 0)), (e.output = []));
								},
							},
						};
					function Ee(e) {
						oe();
					}
					var we = {
						ops_table: null,
						mount: function (e) {
							return we.createNode(null, "/", 16895, 0);
						},
						createNode: function (e, t, r, n) {
							if (_e.isBlkdev(r) || _e.isFIFO(r))
								throw new _e.ErrnoError(63);
							we.ops_table ||
								(we.ops_table = {
									dir: {
										node: {
											getattr: we.node_ops.getattr,
											setattr: we.node_ops.setattr,
											lookup: we.node_ops.lookup,
											mknod: we.node_ops.mknod,
											rename: we.node_ops.rename,
											unlink: we.node_ops.unlink,
											rmdir: we.node_ops.rmdir,
											readdir: we.node_ops.readdir,
											symlink: we.node_ops.symlink,
										},
										stream: {
											llseek: we.stream_ops.llseek,
										},
									},
									file: {
										node: {
											getattr: we.node_ops.getattr,
											setattr: we.node_ops.setattr,
										},
										stream: {
											llseek: we.stream_ops.llseek,
											read: we.stream_ops.read,
											write: we.stream_ops.write,
											allocate: we.stream_ops.allocate,
											mmap: we.stream_ops.mmap,
											msync: we.stream_ops.msync,
										},
									},
									link: {
										node: {
											getattr: we.node_ops.getattr,
											setattr: we.node_ops.setattr,
											readlink: we.node_ops.readlink,
										},
										stream: {},
									},
									chrdev: {
										node: {
											getattr: we.node_ops.getattr,
											setattr: we.node_ops.setattr,
										},
										stream: _e.chrdev_stream_ops,
									},
								});
							var i = _e.createNode(e, t, r, n);
							return (
								_e.isDir(i.mode)
									? ((i.node_ops = we.ops_table.dir.node),
									  (i.stream_ops = we.ops_table.dir.stream),
									  (i.contents = {}))
									: _e.isFile(i.mode)
									? ((i.node_ops = we.ops_table.file.node),
									  (i.stream_ops = we.ops_table.file.stream),
									  (i.usedBytes = 0),
									  (i.contents = null))
									: _e.isLink(i.mode)
									? ((i.node_ops = we.ops_table.link.node),
									  (i.stream_ops = we.ops_table.link.stream))
									: _e.isChrdev(i.mode) &&
									  ((i.node_ops = we.ops_table.chrdev.node),
									  (i.stream_ops =
											we.ops_table.chrdev.stream)),
								(i.timestamp = Date.now()),
								e &&
									((e.contents[t] = i),
									(e.timestamp = i.timestamp)),
								i
							);
						},
						getFileDataAsTypedArray: function (e) {
							return e.contents
								? e.contents.subarray
									? e.contents.subarray(0, e.usedBytes)
									: new Uint8Array(e.contents)
								: new Uint8Array(0);
						},
						expandFileStorage: function (e, t) {
							var r = e.contents ? e.contents.length : 0;
							if (!(r >= t)) {
								(t = Math.max(
									t,
									(r * (r < 1048576 ? 2 : 1.125)) >>> 0
								)),
									0 != r && (t = Math.max(t, 256));
								var n = e.contents;
								(e.contents = new Uint8Array(t)),
									e.usedBytes > 0 &&
										e.contents.set(
											n.subarray(0, e.usedBytes),
											0
										);
							}
						},
						resizeFileStorage: function (e, t) {
							if (e.usedBytes != t)
								if (0 == t)
									(e.contents = null), (e.usedBytes = 0);
								else {
									var r = e.contents;
									(e.contents = new Uint8Array(t)),
										r &&
											e.contents.set(
												r.subarray(
													0,
													Math.min(t, e.usedBytes)
												)
											),
										(e.usedBytes = t);
								}
						},
						node_ops: {
							getattr: function (e) {
								var t = {};
								return (
									(t.dev = _e.isChrdev(e.mode) ? e.id : 1),
									(t.ino = e.id),
									(t.mode = e.mode),
									(t.nlink = 1),
									(t.uid = 0),
									(t.gid = 0),
									(t.rdev = e.rdev),
									_e.isDir(e.mode)
										? (t.size = 4096)
										: _e.isFile(e.mode)
										? (t.size = e.usedBytes)
										: _e.isLink(e.mode)
										? (t.size = e.link.length)
										: (t.size = 0),
									(t.atime = new Date(e.timestamp)),
									(t.mtime = new Date(e.timestamp)),
									(t.ctime = new Date(e.timestamp)),
									(t.blksize = 4096),
									(t.blocks = Math.ceil(t.size / t.blksize)),
									t
								);
							},
							setattr: function (e, t) {
								void 0 !== t.mode && (e.mode = t.mode),
									void 0 !== t.timestamp &&
										(e.timestamp = t.timestamp),
									void 0 !== t.size &&
										we.resizeFileStorage(e, t.size);
							},
							lookup: function (e, t) {
								throw _e.genericErrors[44];
							},
							mknod: function (e, t, r, n) {
								return we.createNode(e, t, r, n);
							},
							rename: function (e, t, r) {
								if (_e.isDir(e.mode)) {
									var n;
									try {
										n = _e.lookupNode(t, r);
									} catch (o) {}
									if (n)
										for (var i in n.contents)
											throw new _e.ErrnoError(55);
								}
								delete e.parent.contents[e.name],
									(e.parent.timestamp = Date.now()),
									(e.name = r),
									(t.contents[r] = e),
									(t.timestamp = e.parent.timestamp),
									(e.parent = t);
							},
							unlink: function (e, t) {
								delete e.contents[t],
									(e.timestamp = Date.now());
							},
							rmdir: function (e, t) {
								var r = _e.lookupNode(e, t);
								for (var n in r.contents)
									throw new _e.ErrnoError(55);
								delete e.contents[t],
									(e.timestamp = Date.now());
							},
							readdir: function (e) {
								var t = [".", ".."];
								for (var r in e.contents)
									e.contents.hasOwnProperty(r) && t.push(r);
								return t;
							},
							symlink: function (e, t, r) {
								var n = we.createNode(e, t, 41471, 0);
								return (n.link = r), n;
							},
							readlink: function (e) {
								if (!_e.isLink(e.mode))
									throw new _e.ErrnoError(28);
								return e.link;
							},
						},
						stream_ops: {
							read: function (e, t, r, n, i) {
								var o = e.node.contents;
								if (i >= e.node.usedBytes) return 0;
								var a = Math.min(e.node.usedBytes - i, n);
								if (a > 8 && o.subarray)
									t.set(o.subarray(i, i + a), r);
								else
									for (var s = 0; s < a; s++)
										t[r + s] = o[i + s];
								return a;
							},
							write: function (e, t, r, n, i, o) {
								if (!n) return 0;
								var a = e.node;
								if (
									((a.timestamp = Date.now()),
									t.subarray &&
										(!a.contents || a.contents.subarray))
								) {
									if (o)
										return (
											(a.contents = t.subarray(r, r + n)),
											(a.usedBytes = n),
											n
										);
									if (0 === a.usedBytes && 0 === i)
										return (
											(a.contents = t.slice(r, r + n)),
											(a.usedBytes = n),
											n
										);
									if (i + n <= a.usedBytes)
										return (
											a.contents.set(
												t.subarray(r, r + n),
												i
											),
											n
										);
								}
								if (
									(we.expandFileStorage(a, i + n),
									a.contents.subarray && t.subarray)
								)
									a.contents.set(t.subarray(r, r + n), i);
								else
									for (var s = 0; s < n; s++)
										a.contents[i + s] = t[r + s];
								return (
									(a.usedBytes = Math.max(
										a.usedBytes,
										i + n
									)),
									n
								);
							},
							llseek: function (e, t, r) {
								var n = t;
								if (
									(1 === r
										? (n += e.position)
										: 2 === r &&
										  _e.isFile(e.node.mode) &&
										  (n += e.node.usedBytes),
									n < 0)
								)
									throw new _e.ErrnoError(28);
								return n;
							},
							allocate: function (e, t, r) {
								we.expandFileStorage(e.node, t + r),
									(e.node.usedBytes = Math.max(
										e.node.usedBytes,
										t + r
									));
							},
							mmap: function (e, t, r, n, i) {
								if (!_e.isFile(e.node.mode))
									throw new _e.ErrnoError(43);
								var o,
									a,
									s = e.node.contents;
								if (2 & i || s.buffer !== O) {
									if (
										((r > 0 || r + t < s.length) &&
											(s = s.subarray
												? s.subarray(r, r + t)
												: Array.prototype.slice.call(
														s,
														r,
														r + t
												  )),
										(a = !0),
										!(o = Ee()))
									)
										throw new _e.ErrnoError(48);
									N.set(s, o);
								} else (a = !1), (o = s.byteOffset);
								return { ptr: o, allocated: a };
							},
							msync: function (e, t, r, n, i) {
								if (!_e.isFile(e.node.mode))
									throw new _e.ErrnoError(43);
								if (2 & i) return 0;
								we.stream_ops.write(e, t, 0, n, r, !1);
								return 0;
							},
						},
					};
					var _e = {
							root: null,
							mounts: [],
							devices: {},
							streams: [],
							nextInode: 1,
							nameTable: null,
							currentPath: "/",
							initialized: !1,
							ignorePermissions: !0,
							ErrnoError: null,
							genericErrors: {},
							filesystems: null,
							syncFSRequests: 0,
							lookupPath: (e, t = {}) => {
								if (!(e = ye.resolve(_e.cwd(), e)))
									return {
										path: "",
										node: null,
									};
								if (
									(t = Object.assign(
										{
											follow_mount: !0,
											recurse_count: 0,
										},
										t
									)).recurse_count > 8
								)
									throw new _e.ErrnoError(32);
								for (
									var r = ve.normalizeArray(
											e.split("/").filter((e) => !!e),
											!1
										),
										n = _e.root,
										i = "/",
										o = 0;
									o < r.length;
									o++
								) {
									var a = o === r.length - 1;
									if (a && t.parent) break;
									if (
										((n = _e.lookupNode(n, r[o])),
										(i = ve.join2(i, r[o])),
										_e.isMountpoint(n) &&
											(!a || (a && t.follow_mount)) &&
											(n = n.mounted.root),
										!a || t.follow)
									)
										for (var s = 0; _e.isLink(n.mode); ) {
											var u = _e.readlink(i);
											if (
												((i = ye.resolve(
													ve.dirname(i),
													u
												)),
												(n = _e.lookupPath(i, {
													recurse_count:
														t.recurse_count + 1,
												}).node),
												s++ > 40)
											)
												throw new _e.ErrnoError(32);
										}
								}
								return { path: i, node: n };
							},
							getPath: (e) => {
								for (var t; ; ) {
									if (_e.isRoot(e)) {
										var r = e.mount.mountpoint;
										return t
											? "/" !== r[r.length - 1]
												? r + "/" + t
												: r + t
											: r;
									}
									(t = t ? e.name + "/" + t : e.name),
										(e = e.parent);
								}
							},
							hashName: (e, t) => {
								for (var r = 0, n = 0; n < t.length; n++)
									r = ((r << 5) - r + t.charCodeAt(n)) | 0;
								return ((e + r) >>> 0) % _e.nameTable.length;
							},
							hashAddNode: (e) => {
								var t = _e.hashName(e.parent.id, e.name);
								(e.name_next = _e.nameTable[t]),
									(_e.nameTable[t] = e);
							},
							hashRemoveNode: (e) => {
								var t = _e.hashName(e.parent.id, e.name);
								if (_e.nameTable[t] === e)
									_e.nameTable[t] = e.name_next;
								else
									for (var r = _e.nameTable[t]; r; ) {
										if (r.name_next === e) {
											r.name_next = e.name_next;
											break;
										}
										r = r.name_next;
									}
							},
							lookupNode: (e, t) => {
								var r = _e.mayLookup(e);
								if (r) throw new _e.ErrnoError(r, e);
								for (
									var n = _e.hashName(e.id, t),
										i = _e.nameTable[n];
									i;
									i = i.name_next
								) {
									var o = i.name;
									if (i.parent.id === e.id && o === t)
										return i;
								}
								return _e.lookup(e, t);
							},
							createNode: (e, t, r, n) => {
								var i = new _e.FSNode(e, t, r, n);
								return _e.hashAddNode(i), i;
							},
							destroyNode: (e) => {
								_e.hashRemoveNode(e);
							},
							isRoot: (e) => e === e.parent,
							isMountpoint: (e) => !!e.mounted,
							isFile: (e) => 32768 === (61440 & e),
							isDir: (e) => 16384 === (61440 & e),
							isLink: (e) => 40960 === (61440 & e),
							isChrdev: (e) => 8192 === (61440 & e),
							isBlkdev: (e) => 24576 === (61440 & e),
							isFIFO: (e) => 4096 === (61440 & e),
							isSocket: (e) => 49152 === (49152 & e),
							flagModes: {
								r: 0,
								"r+": 2,
								w: 577,
								"w+": 578,
								a: 1089,
								"a+": 1090,
							},
							modeStringToFlags: (e) => {
								var t = _e.flagModes[e];
								if ("undefined" == typeof t)
									throw new Error(
										"Unknown file open mode: " + e
									);
								return t;
							},
							flagsToPermissionString: (e) => {
								var t = ["r", "w", "rw"][3 & e];
								return 512 & e && (t += "w"), t;
							},
							nodePermissions: (e, t) =>
								_e.ignorePermissions ||
								((!t.includes("r") || 292 & e.mode) &&
									(!t.includes("w") || 146 & e.mode) &&
									(!t.includes("x") || 73 & e.mode))
									? 0
									: 2,
							mayLookup: (e) => {
								var t = _e.nodePermissions(e, "x");
								return t || (e.node_ops.lookup ? 0 : 2);
							},
							mayCreate: (e, t) => {
								try {
									_e.lookupNode(e, t);
									return 20;
								} catch (r) {}
								return _e.nodePermissions(e, "wx");
							},
							mayDelete: (e, t, r) => {
								var n;
								try {
									n = _e.lookupNode(e, t);
								} catch (o) {
									return o.errno;
								}
								var i = _e.nodePermissions(e, "wx");
								if (i) return i;
								if (r) {
									if (!_e.isDir(n.mode)) return 54;
									if (
										_e.isRoot(n) ||
										_e.getPath(n) === _e.cwd()
									)
										return 10;
								} else if (_e.isDir(n.mode)) return 31;
								return 0;
							},
							mayOpen: (e, t) =>
								e
									? _e.isLink(e.mode)
										? 32
										: _e.isDir(e.mode) &&
										  ("r" !==
												_e.flagsToPermissionString(t) ||
												512 & t)
										? 31
										: _e.nodePermissions(
												e,
												_e.flagsToPermissionString(t)
										  )
									: 44,
							MAX_OPEN_FDS: 4096,
							nextfd: (e = 0, t = _e.MAX_OPEN_FDS) => {
								for (var r = e; r <= t; r++)
									if (!_e.streams[r]) return r;
								throw new _e.ErrnoError(33);
							},
							getStream: (e) => _e.streams[e],
							createStream: (e, t, r) => {
								_e.FSStream ||
									((_e.FSStream = function () {
										this.shared = {};
									}),
									(_e.FSStream.prototype = {
										object: {
											get: function () {
												return this.node;
											},
											set: function (e) {
												this.node = e;
											},
										},
										isRead: {
											get: function () {
												return (
													1 !== (2097155 & this.flags)
												);
											},
										},
										isWrite: {
											get: function () {
												return (
													0 !== (2097155 & this.flags)
												);
											},
										},
										isAppend: {
											get: function () {
												return 1024 & this.flags;
											},
										},
										flags: {
											get: function () {
												return this.shared.flags;
											},
											set: function (e) {
												this.shared.flags = e;
											},
										},
										position: {
											get function() {
												return this.shared.position;
											},
											set: function (e) {
												this.shared.position = e;
											},
										},
									})),
									(e = Object.assign(new _e.FSStream(), e));
								var n = _e.nextfd(t, r);
								return (e.fd = n), (_e.streams[n] = e), e;
							},
							closeStream: (e) => {
								_e.streams[e] = null;
							},
							chrdev_stream_ops: {
								open: (e) => {
									var t = _e.getDevice(e.node.rdev);
									(e.stream_ops = t.stream_ops),
										e.stream_ops.open &&
											e.stream_ops.open(e);
								},
								llseek: () => {
									throw new _e.ErrnoError(70);
								},
							},
							major: (e) => e >> 8,
							minor: (e) => 255 & e,
							makedev: (e, t) => (e << 8) | t,
							registerDevice: (e, t) => {
								_e.devices[e] = {
									stream_ops: t,
								};
							},
							getDevice: (e) => _e.devices[e],
							getMounts: (e) => {
								for (var t = [], r = [e]; r.length; ) {
									var n = r.pop();
									t.push(n), r.push.apply(r, n.mounts);
								}
								return t;
							},
							syncfs: (e, t) => {
								"function" == typeof e && ((t = e), (e = !1)),
									_e.syncFSRequests++,
									_e.syncFSRequests > 1 &&
										w(
											"warning: " +
												_e.syncFSRequests +
												" FS.syncfs operations in flight at once, probably just doing extra work"
										);
								var r = _e.getMounts(_e.root.mount),
									n = 0;
								function i(e) {
									return _e.syncFSRequests--, t(e);
								}
								function o(e) {
									if (e)
										return o.errored
											? void 0
											: ((o.errored = !0), i(e));
									++n >= r.length && i(null);
								}
								r.forEach((t) => {
									if (!t.type.syncfs) return o(null);
									t.type.syncfs(t, e, o);
								});
							},
							mount: (e, t, r) => {
								var n,
									i = "/" === r,
									o = !r;
								if (i && _e.root) throw new _e.ErrnoError(10);
								if (!i && !o) {
									var a = _e.lookupPath(r, {
										follow_mount: !1,
									});
									if (
										((r = a.path),
										(n = a.node),
										_e.isMountpoint(n))
									)
										throw new _e.ErrnoError(10);
									if (!_e.isDir(n.mode))
										throw new _e.ErrnoError(54);
								}
								var s = {
										type: e,
										opts: t,
										mountpoint: r,
										mounts: [],
									},
									u = e.mount(s);
								return (
									(u.mount = s),
									(s.root = u),
									i
										? (_e.root = u)
										: n &&
										  ((n.mounted = s),
										  n.mount && n.mount.mounts.push(s)),
									u
								);
							},
							unmount: (e) => {
								var t = _e.lookupPath(e, {
									follow_mount: !1,
								});
								if (!_e.isMountpoint(t.node))
									throw new _e.ErrnoError(28);
								var r = t.node,
									n = r.mounted,
									i = _e.getMounts(n);
								Object.keys(_e.nameTable).forEach((e) => {
									for (var t = _e.nameTable[e]; t; ) {
										var r = t.name_next;
										i.includes(t.mount) &&
											_e.destroyNode(t),
											(t = r);
									}
								}),
									(r.mounted = null);
								var o = r.mount.mounts.indexOf(n);
								r.mount.mounts.splice(o, 1);
							},
							lookup: (e, t) => e.node_ops.lookup(e, t),
							mknod: (e, t, r) => {
								var n = _e.lookupPath(e, {
										parent: !0,
									}).node,
									i = ve.basename(e);
								if (!i || "." === i || ".." === i)
									throw new _e.ErrnoError(28);
								var o = _e.mayCreate(n, i);
								if (o) throw new _e.ErrnoError(o);
								if (!n.node_ops.mknod)
									throw new _e.ErrnoError(63);
								return n.node_ops.mknod(n, i, t, r);
							},
							create: (e, t) => (
								(t = void 0 !== t ? t : 438),
								(t &= 4095),
								(t |= 32768),
								_e.mknod(e, t, 0)
							),
							mkdir: (e, t) => (
								(t = void 0 !== t ? t : 511),
								(t &= 1023),
								(t |= 16384),
								_e.mknod(e, t, 0)
							),
							mkdirTree: (e, t) => {
								for (
									var r = e.split("/"), n = "", i = 0;
									i < r.length;
									++i
								)
									if (r[i]) {
										n += "/" + r[i];
										try {
											_e.mkdir(n, t);
										} catch (o) {
											if (20 != o.errno) throw o;
										}
									}
							},
							mkdev: (e, t, r) => (
								"undefined" == typeof r && ((r = t), (t = 438)),
								(t |= 8192),
								_e.mknod(e, t, r)
							),
							symlink: (e, t) => {
								if (!ye.resolve(e)) throw new _e.ErrnoError(44);
								var r = _e.lookupPath(t, {
									parent: !0,
								}).node;
								if (!r) throw new _e.ErrnoError(44);
								var n = ve.basename(t),
									i = _e.mayCreate(r, n);
								if (i) throw new _e.ErrnoError(i);
								if (!r.node_ops.symlink)
									throw new _e.ErrnoError(63);
								return r.node_ops.symlink(r, n, e);
							},
							rename: (e, t) => {
								var r,
									n,
									i = ve.dirname(e),
									o = ve.dirname(t),
									a = ve.basename(e),
									s = ve.basename(t);
								if (
									((r = _e.lookupPath(e, {
										parent: !0,
									}).node),
									(n = _e.lookupPath(t, {
										parent: !0,
									}).node),
									!r || !n)
								)
									throw new _e.ErrnoError(44);
								if (r.mount !== n.mount)
									throw new _e.ErrnoError(75);
								var u,
									c = _e.lookupNode(r, a),
									l = ye.relative(e, o);
								if ("." !== l.charAt(0))
									throw new _e.ErrnoError(28);
								if ("." !== (l = ye.relative(t, i)).charAt(0))
									throw new _e.ErrnoError(55);
								try {
									u = _e.lookupNode(n, s);
								} catch (h) {}
								if (c !== u) {
									var d = _e.isDir(c.mode),
										f = _e.mayDelete(r, a, d);
									if (f) throw new _e.ErrnoError(f);
									if (
										(f = u
											? _e.mayDelete(n, s, d)
											: _e.mayCreate(n, s))
									)
										throw new _e.ErrnoError(f);
									if (!r.node_ops.rename)
										throw new _e.ErrnoError(63);
									if (
										_e.isMountpoint(c) ||
										(u && _e.isMountpoint(u))
									)
										throw new _e.ErrnoError(10);
									if (
										n !== r &&
										(f = _e.nodePermissions(r, "w"))
									)
										throw new _e.ErrnoError(f);
									_e.hashRemoveNode(c);
									try {
										r.node_ops.rename(c, n, s);
									} catch (h) {
										throw h;
									} finally {
										_e.hashAddNode(c);
									}
								}
							},
							rmdir: (e) => {
								var t = _e.lookupPath(e, {
										parent: !0,
									}).node,
									r = ve.basename(e),
									n = _e.lookupNode(t, r),
									i = _e.mayDelete(t, r, !0);
								if (i) throw new _e.ErrnoError(i);
								if (!t.node_ops.rmdir)
									throw new _e.ErrnoError(63);
								if (_e.isMountpoint(n))
									throw new _e.ErrnoError(10);
								t.node_ops.rmdir(t, r), _e.destroyNode(n);
							},
							readdir: (e) => {
								var t = _e.lookupPath(e, {
									follow: !0,
								}).node;
								if (!t.node_ops.readdir)
									throw new _e.ErrnoError(54);
								return t.node_ops.readdir(t);
							},
							unlink: (e) => {
								var t = _e.lookupPath(e, {
									parent: !0,
								}).node;
								if (!t) throw new _e.ErrnoError(44);
								var r = ve.basename(e),
									n = _e.lookupNode(t, r),
									i = _e.mayDelete(t, r, !1);
								if (i) throw new _e.ErrnoError(i);
								if (!t.node_ops.unlink)
									throw new _e.ErrnoError(63);
								if (_e.isMountpoint(n))
									throw new _e.ErrnoError(10);
								t.node_ops.unlink(t, r), _e.destroyNode(n);
							},
							readlink: (e) => {
								var t = _e.lookupPath(e).node;
								if (!t) throw new _e.ErrnoError(44);
								if (!t.node_ops.readlink)
									throw new _e.ErrnoError(28);
								return ye.resolve(
									_e.getPath(t.parent),
									t.node_ops.readlink(t)
								);
							},
							stat: (e, t) => {
								var r = _e.lookupPath(e, {
									follow: !t,
								}).node;
								if (!r) throw new _e.ErrnoError(44);
								if (!r.node_ops.getattr)
									throw new _e.ErrnoError(63);
								return r.node_ops.getattr(r);
							},
							lstat: (e) => _e.stat(e, !0),
							chmod: (e, t, r) => {
								var n;
								"string" == typeof e
									? (n = _e.lookupPath(e, {
											follow: !r,
									  }).node)
									: (n = e);
								if (!n.node_ops.setattr)
									throw new _e.ErrnoError(63);
								n.node_ops.setattr(n, {
									mode: (4095 & t) | (-4096 & n.mode),
									timestamp: Date.now(),
								});
							},
							lchmod: (e, t) => {
								_e.chmod(e, t, !0);
							},
							fchmod: (e, t) => {
								var r = _e.getStream(e);
								if (!r) throw new _e.ErrnoError(8);
								_e.chmod(r.node, t);
							},
							chown: (e, t, r, n) => {
								var i;
								"string" == typeof e
									? (i = _e.lookupPath(e, {
											follow: !n,
									  }).node)
									: (i = e);
								if (!i.node_ops.setattr)
									throw new _e.ErrnoError(63);
								i.node_ops.setattr(i, {
									timestamp: Date.now(),
								});
							},
							lchown: (e, t, r) => {
								_e.chown(e, t, r, !0);
							},
							fchown: (e, t, r) => {
								var n = _e.getStream(e);
								if (!n) throw new _e.ErrnoError(8);
								_e.chown(n.node, t, r);
							},
							truncate: (e, t) => {
								if (t < 0) throw new _e.ErrnoError(28);
								var r;
								"string" == typeof e
									? (r = _e.lookupPath(e, {
											follow: !0,
									  }).node)
									: (r = e);
								if (!r.node_ops.setattr)
									throw new _e.ErrnoError(63);
								if (_e.isDir(r.mode))
									throw new _e.ErrnoError(31);
								if (!_e.isFile(r.mode))
									throw new _e.ErrnoError(28);
								var n = _e.nodePermissions(r, "w");
								if (n) throw new _e.ErrnoError(n);
								r.node_ops.setattr(r, {
									size: t,
									timestamp: Date.now(),
								});
							},
							ftruncate: (e, t) => {
								var r = _e.getStream(e);
								if (!r) throw new _e.ErrnoError(8);
								if (0 === (2097155 & r.flags))
									throw new _e.ErrnoError(28);
								_e.truncate(r.node, t);
							},
							utime: (e, t, r) => {
								var n = _e.lookupPath(e, {
									follow: !0,
								}).node;
								n.node_ops.setattr(n, {
									timestamp: Math.max(t, r),
								});
							},
							open: (e, t, r) => {
								if ("" === e) throw new _e.ErrnoError(44);
								var n;
								if (
									((r = "undefined" == typeof r ? 438 : r),
									(r =
										64 &
										(t =
											"string" == typeof t
												? _e.modeStringToFlags(t)
												: t)
											? (4095 & r) | 32768
											: 0),
									"object" == typeof e)
								)
									n = e;
								else {
									e = ve.normalize(e);
									try {
										n = _e.lookupPath(e, {
											follow: !(131072 & t),
										}).node;
									} catch (u) {}
								}
								var i = !1;
								if (64 & t)
									if (n) {
										if (128 & t)
											throw new _e.ErrnoError(20);
									} else (n = _e.mknod(e, r, 0)), (i = !0);
								if (!n) throw new _e.ErrnoError(44);
								if (
									(_e.isChrdev(n.mode) && (t &= -513),
									65536 & t && !_e.isDir(n.mode))
								)
									throw new _e.ErrnoError(54);
								if (!i) {
									var o = _e.mayOpen(n, t);
									if (o) throw new _e.ErrnoError(o);
								}
								512 & t && !i && _e.truncate(n, 0),
									(t &= -131713);
								var s = _e.createStream({
									node: n,
									path: _e.getPath(n),
									flags: t,
									seekable: !0,
									position: 0,
									stream_ops: n.stream_ops,
									ungotten: [],
									error: !1,
								});
								return (
									s.stream_ops.open && s.stream_ops.open(s),
									!a.logReadFiles ||
										1 & t ||
										(_e.readFiles || (_e.readFiles = {}),
										e in _e.readFiles ||
											(_e.readFiles[e] = 1)),
									s
								);
							},
							close: (e) => {
								if (_e.isClosed(e)) throw new _e.ErrnoError(8);
								e.getdents && (e.getdents = null);
								try {
									e.stream_ops.close && e.stream_ops.close(e);
								} catch (t) {
									throw t;
								} finally {
									_e.closeStream(e.fd);
								}
								e.fd = null;
							},
							isClosed: (e) => null === e.fd,
							llseek: (e, t, r) => {
								if (_e.isClosed(e)) throw new _e.ErrnoError(8);
								if (!e.seekable || !e.stream_ops.llseek)
									throw new _e.ErrnoError(70);
								if (0 != r && 1 != r && 2 != r)
									throw new _e.ErrnoError(28);
								return (
									(e.position = e.stream_ops.llseek(e, t, r)),
									(e.ungotten = []),
									e.position
								);
							},
							read: (e, t, r, n, i) => {
								if (n < 0 || i < 0) throw new _e.ErrnoError(28);
								if (_e.isClosed(e)) throw new _e.ErrnoError(8);
								if (1 === (2097155 & e.flags))
									throw new _e.ErrnoError(8);
								if (_e.isDir(e.node.mode))
									throw new _e.ErrnoError(31);
								if (!e.stream_ops.read)
									throw new _e.ErrnoError(28);
								var o = "undefined" != typeof i;
								if (o) {
									if (!e.seekable)
										throw new _e.ErrnoError(70);
								} else i = e.position;
								var a = e.stream_ops.read(e, t, r, n, i);
								return o || (e.position += a), a;
							},
							write: (e, t, r, n, i, o) => {
								if (n < 0 || i < 0) throw new _e.ErrnoError(28);
								if (_e.isClosed(e)) throw new _e.ErrnoError(8);
								if (0 === (2097155 & e.flags))
									throw new _e.ErrnoError(8);
								if (_e.isDir(e.node.mode))
									throw new _e.ErrnoError(31);
								if (!e.stream_ops.write)
									throw new _e.ErrnoError(28);
								e.seekable &&
									1024 & e.flags &&
									_e.llseek(e, 0, 2);
								var a = "undefined" != typeof i;
								if (a) {
									if (!e.seekable)
										throw new _e.ErrnoError(70);
								} else i = e.position;
								var s = e.stream_ops.write(e, t, r, n, i, o);
								return a || (e.position += s), s;
							},
							allocate: (e, t, r) => {
								if (_e.isClosed(e)) throw new _e.ErrnoError(8);
								if (t < 0 || r <= 0)
									throw new _e.ErrnoError(28);
								if (0 === (2097155 & e.flags))
									throw new _e.ErrnoError(8);
								if (
									!_e.isFile(e.node.mode) &&
									!_e.isDir(e.node.mode)
								)
									throw new _e.ErrnoError(43);
								if (!e.stream_ops.allocate)
									throw new _e.ErrnoError(138);
								e.stream_ops.allocate(e, t, r);
							},
							mmap: (e, t, r, n, i) => {
								if (
									0 !== (2 & n) &&
									0 === (2 & i) &&
									2 !== (2097155 & e.flags)
								)
									throw new _e.ErrnoError(2);
								if (1 === (2097155 & e.flags))
									throw new _e.ErrnoError(2);
								if (!e.stream_ops.mmap)
									throw new _e.ErrnoError(43);
								return e.stream_ops.mmap(e, t, r, n, i);
							},
							msync: (e, t, r, n, i) =>
								e && e.stream_ops.msync
									? e.stream_ops.msync(e, t, r, n, i)
									: 0,
							munmap: (e) => 0,
							ioctl: (e, t, r) => {
								if (!e.stream_ops.ioctl)
									throw new _e.ErrnoError(59);
								return e.stream_ops.ioctl(e, t, r);
							},
							readFile: (e, t = {}) => {
								if (
									((t.flags = t.flags || 0),
									(t.encoding = t.encoding || "binary"),
									"utf8" !== t.encoding &&
										"binary" !== t.encoding)
								)
									throw new Error(
										'Invalid encoding type "' +
											t.encoding +
											'"'
									);
								var r,
									n = _e.open(e, t.flags),
									i = _e.stat(e).size,
									o = new Uint8Array(i);
								return (
									_e.read(n, o, 0, i, 0),
									"utf8" === t.encoding
										? (r = M(o, 0))
										: "binary" === t.encoding && (r = o),
									_e.close(n),
									r
								);
							},
							writeFile: (e, t, r = {}) => {
								r.flags = r.flags || 577;
								var n = _e.open(e, r.flags, r.mode);
								if ("string" == typeof t) {
									var i = new Uint8Array(k(t) + 1),
										o = I(t, i, 0, i.length);
									_e.write(n, i, 0, o, void 0, r.canOwn);
								} else {
									if (!ArrayBuffer.isView(t))
										throw new Error(
											"Unsupported data type"
										);
									_e.write(
										n,
										t,
										0,
										t.byteLength,
										void 0,
										r.canOwn
									);
								}
								_e.close(n);
							},
							cwd: () => _e.currentPath,
							chdir: (e) => {
								var t = _e.lookupPath(e, {
									follow: !0,
								});
								if (null === t.node)
									throw new _e.ErrnoError(44);
								if (!_e.isDir(t.node.mode))
									throw new _e.ErrnoError(54);
								var r = _e.nodePermissions(t.node, "x");
								if (r) throw new _e.ErrnoError(r);
								_e.currentPath = t.path;
							},
							createDefaultDirectories: () => {
								_e.mkdir("/tmp"),
									_e.mkdir("/home"),
									_e.mkdir("/home/web_user");
							},
							createDefaultDevices: () => {
								_e.mkdir("/dev"),
									_e.registerDevice(_e.makedev(1, 3), {
										read: () => 0,
										write: (e, t, r, n, i) => n,
									}),
									_e.mkdev("/dev/null", _e.makedev(1, 3)),
									be.register(
										_e.makedev(5, 0),
										be.default_tty_ops
									),
									be.register(
										_e.makedev(6, 0),
										be.default_tty1_ops
									),
									_e.mkdev("/dev/tty", _e.makedev(5, 0)),
									_e.mkdev("/dev/tty1", _e.makedev(6, 0));
								var e = (function () {
									if (
										"object" == typeof crypto &&
										"function" ==
											typeof crypto.getRandomValues
									) {
										var e = new Uint8Array(1);
										return function () {
											return (
												crypto.getRandomValues(e), e[0]
											);
										};
									}
									if (v)
										try {
											var t = requireFunc(86433);
											return function () {
												return t.randomBytes(1)[0];
											};
										} catch (n) {}
									return function () {
										oe("randomDevice");
									};
								})();
								_e.createDevice("/dev", "random", e),
									_e.createDevice("/dev", "urandom", e),
									_e.mkdir("/dev/shm"),
									_e.mkdir("/dev/shm/tmp");
							},
							createSpecialDirectories: () => {
								_e.mkdir("/proc");
								var e = _e.mkdir("/proc/self");
								_e.mkdir("/proc/self/fd"),
									_e.mount(
										{
											mount: () => {
												var t = _e.createNode(
													e,
													"fd",
													16895,
													73
												);
												return (
													(t.node_ops = {
														lookup: (e, t) => {
															var r = +t,
																n =
																	_e.getStream(
																		r
																	);
															if (!n)
																throw new _e.ErrnoError(
																	8
																);
															var i = {
																parent: null,
																mount: {
																	mountpoint:
																		"fake",
																},
																node_ops: {
																	readlink:
																		() =>
																			n.path,
																},
															};
															return (
																(i.parent = i),
																i
															);
														},
													}),
													t
												);
											},
										},
										{},
										"/proc/self/fd"
									);
							},
							createStandardStreams: () => {
								a.stdin
									? _e.createDevice("/dev", "stdin", a.stdin)
									: _e.symlink("/dev/tty", "/dev/stdin"),
									a.stdout
										? _e.createDevice(
												"/dev",
												"stdout",
												null,
												a.stdout
										  )
										: _e.symlink("/dev/tty", "/dev/stdout"),
									a.stderr
										? _e.createDevice(
												"/dev",
												"stderr",
												null,
												a.stderr
										  )
										: _e.symlink(
												"/dev/tty1",
												"/dev/stderr"
										  );
								_e.open("/dev/stdin", 0),
									_e.open("/dev/stdout", 1),
									_e.open("/dev/stderr", 1);
							},
							ensureErrnoError: () => {
								_e.ErrnoError ||
									((_e.ErrnoError = function (e, t) {
										(this.node = t),
											(this.setErrno = function (e) {
												this.errno = e;
											}),
											this.setErrno(e),
											(this.message = "FS error");
									}),
									(_e.ErrnoError.prototype = new Error()),
									(_e.ErrnoError.prototype.constructor =
										_e.ErrnoError),
									[44].forEach((e) => {
										(_e.genericErrors[e] =
											new _e.ErrnoError(e)),
											(_e.genericErrors[e].stack =
												"<generic error, no stack>");
									}));
							},
							staticInit: () => {
								_e.ensureErrnoError(),
									(_e.nameTable = new Array(4096)),
									_e.mount(we, {}, "/"),
									_e.createDefaultDirectories(),
									_e.createDefaultDevices(),
									_e.createSpecialDirectories(),
									(_e.filesystems = {
										MEMFS: we,
									});
							},
							init: (e, t, r) => {
								(_e.init.initialized = !0),
									_e.ensureErrnoError(),
									(a.stdin = e || a.stdin),
									(a.stdout = t || a.stdout),
									(a.stderr = r || a.stderr),
									_e.createStandardStreams();
							},
							quit: () => {
								_e.init.initialized = !1;
								for (var e = 0; e < _e.streams.length; e++) {
									var t = _e.streams[e];
									t && _e.close(t);
								}
							},
							getMode: (e, t) => {
								var r = 0;
								return e && (r |= 365), t && (r |= 146), r;
							},
							findObject: (e, t) => {
								var r = _e.analyzePath(e, t);
								return r.exists ? r.object : null;
							},
							analyzePath: (e, t) => {
								try {
									e = (n = _e.lookupPath(e, {
										follow: !t,
									})).path;
								} catch (i) {}
								var r = {
									isRoot: !1,
									exists: !1,
									error: 0,
									name: null,
									path: null,
									object: null,
									parentExists: !1,
									parentPath: null,
									parentObject: null,
								};
								try {
									var n = _e.lookupPath(e, {
										parent: !0,
									});
									(r.parentExists = !0),
										(r.parentPath = n.path),
										(r.parentObject = n.node),
										(r.name = ve.basename(e)),
										(n = _e.lookupPath(e, {
											follow: !t,
										})),
										(r.exists = !0),
										(r.path = n.path),
										(r.object = n.node),
										(r.name = n.node.name),
										(r.isRoot = "/" === n.path);
								} catch (i) {
									r.error = i.errno;
								}
								return r;
							},
							createPath: (e, t, r, n) => {
								e = "string" == typeof e ? e : _e.getPath(e);
								for (
									var i = t.split("/").reverse();
									i.length;

								) {
									var o = i.pop();
									if (o) {
										var a = ve.join2(e, o);
										try {
											_e.mkdir(a);
										} catch (s) {}
										e = a;
									}
								}
								return a;
							},
							createFile: (e, t, r, n, i) => {
								var o = ve.join2(
										"string" == typeof e
											? e
											: _e.getPath(e),
										t
									),
									a = _e.getMode(n, i);
								return _e.create(o, a);
							},
							createDataFile: (e, t, r, n, i, o) => {
								var a = t;
								e &&
									((e =
										"string" == typeof e
											? e
											: _e.getPath(e)),
									(a = t ? ve.join2(e, t) : e));
								var s = _e.getMode(n, i),
									u = _e.create(a, s);
								if (r) {
									if ("string" == typeof r) {
										for (
											var c = new Array(r.length),
												l = 0,
												d = r.length;
											l < d;
											++l
										)
											c[l] = r.charCodeAt(l);
										r = c;
									}
									_e.chmod(u, 146 | s);
									var f = _e.open(u, 577);
									_e.write(f, r, 0, r.length, 0, o),
										_e.close(f),
										_e.chmod(u, s);
								}
								return u;
							},
							createDevice: (e, t, r, n) => {
								var i = ve.join2(
										"string" == typeof e
											? e
											: _e.getPath(e),
										t
									),
									o = _e.getMode(!!r, !!n);
								_e.createDevice.major ||
									(_e.createDevice.major = 64);
								var a = _e.makedev(_e.createDevice.major++, 0);
								return (
									_e.registerDevice(a, {
										open: (e) => {
											e.seekable = !1;
										},
										close: (e) => {
											n &&
												n.buffer &&
												n.buffer.length &&
												n(10);
										},
										read: (e, t, n, i, o) => {
											for (var a = 0, s = 0; s < i; s++) {
												var u;
												try {
													u = r();
												} catch (c) {
													throw new _e.ErrnoError(29);
												}
												if (void 0 === u && 0 === a)
													throw new _e.ErrnoError(6);
												if (null === u || void 0 === u)
													break;
												a++, (t[n + s] = u);
											}
											return (
												a &&
													(e.node.timestamp =
														Date.now()),
												a
											);
										},
										write: (e, t, r, i, o) => {
											for (var a = 0; a < i; a++)
												try {
													n(t[r + a]);
												} catch (s) {
													throw new _e.ErrnoError(29);
												}
											return (
												i &&
													(e.node.timestamp =
														Date.now()),
												a
											);
										},
									}),
									_e.mkdev(i, o, a)
								);
							},
							forceLoadFile: (e) => {
								if (
									e.isDevice ||
									e.isFolder ||
									e.link ||
									e.contents
								)
									return !0;
								if ("undefined" != typeof XMLHttpRequest)
									throw new Error(
										"Lazy loading should have been performed (contents set) in createLazyFile, but it was not. Lazy loading only works in web workers. Use --embed-file or --preload-file in emcc on the main thread."
									);
								if (!s)
									throw new Error(
										"Cannot load without read() or XMLHttpRequest."
									);
								try {
									(e.contents = Qt(s(e.url), !0)),
										(e.usedBytes = e.contents.length);
								} catch (t) {
									throw new _e.ErrnoError(29);
								}
							},
							createLazyFile: (e, t, r, n, i) => {
								function o() {
									(this.lengthKnown = !1), (this.chunks = []);
								}
								if (
									((o.prototype.get = function (e) {
										if (!(e > this.length - 1 || e < 0)) {
											var t = e % this.chunkSize,
												r = (e / this.chunkSize) | 0;
											return this.getter(r)[t];
										}
									}),
									(o.prototype.setDataGetter = function (e) {
										this.getter = e;
									}),
									(o.prototype.cacheLength = function () {
										var e = new XMLHttpRequest();
										if (
											(e.open("HEAD", r, !1),
											e.send(null),
											!(
												(e.status >= 200 &&
													e.status < 300) ||
												304 === e.status
											))
										)
											throw new Error(
												"Couldn't load " +
													r +
													". Status: " +
													e.status
											);
										var t,
											n = Number(
												e.getResponseHeader(
													"Content-length"
												)
											),
											i =
												(t =
													e.getResponseHeader(
														"Accept-Ranges"
													)) && "bytes" === t,
											o =
												(t =
													e.getResponseHeader(
														"Content-Encoding"
													)) && "gzip" === t,
											a = 1048576;
										i || (a = n);
										var s = this;
										s.setDataGetter((e) => {
											var t = e * a,
												i = (e + 1) * a - 1;
											if (
												((i = Math.min(i, n - 1)),
												"undefined" ==
													typeof s.chunks[e] &&
													(s.chunks[e] = ((e, t) => {
														if (e > t)
															throw new Error(
																"invalid range (" +
																	e +
																	", " +
																	t +
																	") or no bytes requested!"
															);
														if (t > n - 1)
															throw new Error(
																"only " +
																	n +
																	" bytes available! programmer error!"
															);
														var i =
															new XMLHttpRequest();
														if (
															(i.open(
																"GET",
																r,
																!1
															),
															n !== a &&
																i.setRequestHeader(
																	"Range",
																	"bytes=" +
																		e +
																		"-" +
																		t
																),
															(i.responseType =
																"arraybuffer"),
															i.overrideMimeType &&
																i.overrideMimeType(
																	"text/plain; charset=x-user-defined"
																),
															i.send(null),
															!(
																(i.status >=
																	200 &&
																	i.status <
																		300) ||
																304 === i.status
															))
														)
															throw new Error(
																"Couldn't load " +
																	r +
																	". Status: " +
																	i.status
															);
														return void 0 !==
															i.response
															? new Uint8Array(
																	i.response ||
																		[]
															  )
															: Qt(
																	i.responseText ||
																		"",
																	!0
															  );
													})(t, i)),
												"undefined" ==
													typeof s.chunks[e])
											)
												throw new Error(
													"doXHR failed!"
												);
											return s.chunks[e];
										}),
											(!o && n) ||
												((a = n = 1),
												(n = this.getter(0).length),
												(a = n),
												E(
													"LazyFiles on gzip forces download of the whole file when length is accessed"
												)),
											(this._length = n),
											(this._chunkSize = a),
											(this.lengthKnown = !0);
									}),
									"undefined" != typeof XMLHttpRequest)
								) {
									if (!g)
										throw "Cannot do synchronous binary XHRs outside webworkers in modern browsers. Use --embed-file or --preload-file in emcc";
									var a = new o();
									Object.defineProperties(a, {
										length: {
											get: function () {
												return (
													this.lengthKnown ||
														this.cacheLength(),
													this._length
												);
											},
										},
										chunkSize: {
											get: function () {
												return (
													this.lengthKnown ||
														this.cacheLength(),
													this._chunkSize
												);
											},
										},
									});
									var s = {
										isDevice: !1,
										contents: a,
									};
								} else
									s = {
										isDevice: !1,
										url: r,
									};
								var u = _e.createFile(e, t, s, n, i);
								s.contents
									? (u.contents = s.contents)
									: s.url &&
									  ((u.contents = null), (u.url = s.url)),
									Object.defineProperties(u, {
										usedBytes: {
											get: function () {
												return this.contents.length;
											},
										},
									});
								var c = {};
								function l(e, t, r, n, i) {
									var o = e.node.contents;
									if (i >= o.length) return 0;
									var a = Math.min(o.length - i, n);
									if (o.slice)
										for (var s = 0; s < a; s++)
											t[r + s] = o[i + s];
									else
										for (s = 0; s < a; s++)
											t[r + s] = o.get(i + s);
									return a;
								}
								return (
									Object.keys(u.stream_ops).forEach((e) => {
										var t = u.stream_ops[e];
										c[e] = function () {
											return (
												_e.forceLoadFile(u),
												t.apply(null, arguments)
											);
										};
									}),
									(c.read = (e, t, r, n, i) => (
										_e.forceLoadFile(u), l(e, t, r, n, i)
									)),
									(c.mmap = (e, t, r, n, i) => {
										_e.forceLoadFile(u);
										var o = Ee();
										if (!o) throw new _e.ErrnoError(48);
										return (
											l(e, N, o, t, r),
											{
												ptr: o,
												allocated: !0,
											}
										);
									}),
									(u.stream_ops = c),
									u
								);
							},
							createPreloadedFile: (
								e,
								t,
								r,
								n,
								i,
								o,
								a,
								s,
								c,
								l
							) => {
								var d = t ? ye.resolve(ve.join2(e, t)) : e;
								function f(r) {
									function u(r) {
										l && l(),
											s ||
												_e.createDataFile(
													e,
													t,
													r,
													n,
													i,
													c
												),
											o && o(),
											ie();
									}
									Browser.handledByPreloadPlugin(
										r,
										d,
										u,
										() => {
											a && a(), ie();
										}
									) || u(r);
								}
								ne(),
									"string" == typeof r
										? (function (e, t, r, n) {
												var i = n ? "" : "al " + e;
												u(
													e,
													function (r) {
														x(
															r,
															'Loading data file "' +
																e +
																'" failed (no arrayBuffer).'
														),
															t(
																new Uint8Array(
																	r
																)
															),
															i && ie();
													},
													function (t) {
														if (!r)
															throw (
																'Loading data file "' +
																e +
																'" failed.'
															);
														r();
													}
												),
													i && ne();
										  })(r, (e) => f(e), a)
										: f(r);
							},
							indexedDB: () =>
								window.indexedDB ||
								window.mozIndexedDB ||
								window.webkitIndexedDB ||
								window.msIndexedDB,
							DB_NAME: () => "EM_FS_" + window.location.pathname,
							DB_VERSION: 20,
							DB_STORE_NAME: "FILE_DATA",
							saveFilesToDB: (e, t, r) => {
								(t = t || (() => {})), (r = r || (() => {}));
								var n = _e.indexedDB();
								try {
									var i = n.open(_e.DB_NAME(), _e.DB_VERSION);
								} catch (o) {
									return r(o);
								}
								(i.onupgradeneeded = () => {
									E("creating db"),
										i.result.createObjectStore(
											_e.DB_STORE_NAME
										);
								}),
									(i.onsuccess = () => {
										var n = i.result.transaction(
												[_e.DB_STORE_NAME],
												"readwrite"
											),
											o = n.objectStore(_e.DB_STORE_NAME),
											a = 0,
											s = 0,
											u = e.length;
										function c() {
											0 == s ? t() : r();
										}
										e.forEach((e) => {
											var t = o.put(
												_e.analyzePath(e).object
													.contents,
												e
											);
											(t.onsuccess = () => {
												++a + s == u && c();
											}),
												(t.onerror = () => {
													s++, a + s == u && c();
												});
										}),
											(n.onerror = r);
									}),
									(i.onerror = r);
							},
							loadFilesFromDB: (e, t, r) => {
								(t = t || (() => {})), (r = r || (() => {}));
								var n = _e.indexedDB();
								try {
									var i = n.open(_e.DB_NAME(), _e.DB_VERSION);
								} catch (o) {
									return r(o);
								}
								(i.onupgradeneeded = r),
									(i.onsuccess = () => {
										var n = i.result;
										try {
											var a = n.transaction(
												[_e.DB_STORE_NAME],
												"readonly"
											);
										} catch (o) {
											return void r(o);
										}
										var s = a.objectStore(_e.DB_STORE_NAME),
											u = 0,
											c = 0,
											l = e.length;
										function d() {
											0 == c ? t() : r();
										}
										e.forEach((e) => {
											var t = s.get(e);
											(t.onsuccess = () => {
												_e.analyzePath(e).exists &&
													_e.unlink(e),
													_e.createDataFile(
														ve.dirname(e),
														ve.basename(e),
														t.result,
														!0,
														!0,
														!0
													),
													++u + c == l && d();
											}),
												(t.onerror = () => {
													c++, u + c == l && d();
												});
										}),
											(a.onerror = r);
									}),
									(i.onerror = r);
							},
						},
						Se = {
							DEFAULT_POLLMASK: 5,
							calculateAt: function (e, t, r) {
								if (ve.isAbs(t)) return t;
								var n;
								if (-100 === e) n = _e.cwd();
								else {
									var i = _e.getStream(e);
									if (!i) throw new _e.ErrnoError(8);
									n = i.path;
								}
								if (0 == t.length) {
									if (!r) throw new _e.ErrnoError(44);
									return n;
								}
								return ve.join2(n, t);
							},
							doStat: function (e, t, r) {
								try {
									var n = e(t);
								} catch (i) {
									if (
										i &&
										i.node &&
										ve.normalize(t) !==
											ve.normalize(_e.getPath(i.node))
									)
										return -54;
									throw i;
								}
								return (
									(B[r >> 2] = n.dev),
									(B[(r + 4) >> 2] = 0),
									(B[(r + 8) >> 2] = n.ino),
									(B[(r + 12) >> 2] = n.mode),
									(B[(r + 16) >> 2] = n.nlink),
									(B[(r + 20) >> 2] = n.uid),
									(B[(r + 24) >> 2] = n.gid),
									(B[(r + 28) >> 2] = n.rdev),
									(B[(r + 32) >> 2] = 0),
									(F[(r + 40) >> 3] = BigInt(n.size)),
									(B[(r + 48) >> 2] = 4096),
									(B[(r + 52) >> 2] = n.blocks),
									(B[(r + 56) >> 2] =
										(n.atime.getTime() / 1e3) | 0),
									(B[(r + 60) >> 2] = 0),
									(B[(r + 64) >> 2] =
										(n.mtime.getTime() / 1e3) | 0),
									(B[(r + 68) >> 2] = 0),
									(B[(r + 72) >> 2] =
										(n.ctime.getTime() / 1e3) | 0),
									(B[(r + 76) >> 2] = 0),
									(F[(r + 80) >> 3] = BigInt(n.ino)),
									0
								);
							},
							doMsync: function (e, t, r, n, i) {
								var o = L.slice(e, e + r);
								_e.msync(t, o, i, r, n);
							},
							varargs: void 0,
							get: function () {
								return (
									(Se.varargs += 4), B[(Se.varargs - 4) >> 2]
								);
							},
							getStr: function (e) {
								return C(e);
							},
							getStreamFromFD: function (e) {
								var t = _e.getStream(e);
								if (!t) throw new _e.ErrnoError(8);
								return t;
							},
						};
					function Ae(e) {
						if (null === e) return "null";
						var t = typeof e;
						return "object" === t ||
							"array" === t ||
							"function" === t
							? e.toString()
							: "" + e;
					}
					var xe = void 0;
					function Te(e) {
						for (var t = "", r = e; L[r]; ) t += xe[L[r++]];
						return t;
					}
					var Me = {},
						Ce = {},
						Ie = {},
						Re = 48,
						ke = 57;
					function Oe(e) {
						if (void 0 === e) return "_unknown";
						var t = (e = e.replace(
							/[^a-zA-Z0-9_]/g,
							"$"
						)).charCodeAt(0);
						return t >= Re && t <= ke ? "_" + e : e;
					}
					function Ne(e, t) {
						return (
							(e = Oe(e)),
							function () {
								return t.apply(this, arguments);
							}
						);
					}
					function Le(e, t) {
						var r = Ne(t, function (e) {
							(this.name = t), (this.message = e);
							var r = new Error(e).stack;
							void 0 !== r &&
								(this.stack =
									this.toString() +
									"\n" +
									r.replace(/^Error(:[^\n]*)?\n/, ""));
						});
						return (
							(r.prototype = Object.create(e.prototype)),
							(r.prototype.constructor = r),
							(r.prototype.toString = function () {
								return void 0 === this.message
									? this.name
									: this.name + ": " + this.message;
							}),
							r
						);
					}
					var Pe = void 0;
					function De(e) {
						throw new Pe(e);
					}
					var Be = void 0;
					function Ue(e) {
						throw new Be(e);
					}
					function je(e, t, r) {
						function n(t) {
							var n = r(t);
							n.length !== e.length &&
								Ue("Mismatched type converter count");
							for (var i = 0; i < e.length; ++i) Fe(e[i], n[i]);
						}
						e.forEach(function (e) {
							Ie[e] = t;
						});
						var i = new Array(t.length),
							o = [],
							a = 0;
						t.forEach((e, t) => {
							Ce.hasOwnProperty(e)
								? (i[t] = Ce[e])
								: (o.push(e),
								  Me.hasOwnProperty(e) || (Me[e] = []),
								  Me[e].push(() => {
										(i[t] = Ce[e]),
											++a === o.length && n(i);
								  }));
						}),
							0 === o.length && n(i);
					}
					function Fe(e, t, r = {}) {
						if (!("argPackAdvance" in t))
							throw new TypeError(
								"registerType registeredInstance requires argPackAdvance"
							);
						var n = t.name;
						if (
							(e ||
								De(
									'type "' +
										n +
										'" must have a positive integer typeid pointer'
								)) &&
							Ce.hasOwnProperty(e)
						) {
							if (r.ignoreDuplicateRegistrations) return;
							De("Cannot register type '" + n + "' twice");
						}
						if (((Ce[e] = t), delete Ie[e], Me.hasOwnProperty(e))) {
							var i = Me[e];
							delete Me[e], i.forEach((e) => e());
						}
					}
					function Ve(e, t, r) {
						switch (t) {
							case 0:
								return r
									? function (e) {
											return N[e];
									  }
									: function (e) {
											return L[e];
									  };
							case 1:
								return r
									? function (e) {
											return P[e >> 1];
									  }
									: function (e) {
											return D[e >> 1];
									  };
							case 2:
								return r
									? function (e) {
											return B[e >> 2];
									  }
									: function (e) {
											return U[e >> 2];
									  };
							case 3:
								return r
									? function (e) {
											return F[e >> 3];
									  }
									: function (e) {
											return V[e >> 3];
									  };
							default:
								throw new TypeError(
									"Unknown integer type: " + e
								);
						}
					}
					function qe(e) {
						switch (e) {
							case 1:
								return 0;
							case 2:
								return 1;
							case 4:
								return 2;
							case 8:
								return 3;
							default:
								throw new TypeError("Unknown type size: " + e);
						}
					}
					function He(e) {
						if (!(this instanceof ft)) return !1;
						if (!(e instanceof ft)) return !1;
						for (
							var t = this.$$.ptrType.registeredClass,
								r = this.$$.ptr,
								n = e.$$.ptrType.registeredClass,
								i = e.$$.ptr;
							t.baseClass;

						)
							(r = t.upcast(r)), (t = t.baseClass);
						for (; n.baseClass; )
							(i = n.upcast(i)), (n = n.baseClass);
						return t === n && r === i;
					}
					function Ke(e) {
						return {
							count: e.count,
							deleteScheduled: e.deleteScheduled,
							preservePointerOnDelete: e.preservePointerOnDelete,
							ptr: e.ptr,
							ptrType: e.ptrType,
							smartPtr: e.smartPtr,
							smartPtrType: e.smartPtrType,
						};
					}
					function Ge(e) {
						De(
							e.$$.ptrType.registeredClass.name +
								" instance already deleted"
						);
					}
					var ze = !1;
					function We(e) {}
					function $e(e) {
						(e.count.value -= 1),
							0 === e.count.value &&
								(function (e) {
									e.smartPtr
										? e.smartPtrType.rawDestructor(
												e.smartPtr
										  )
										: e.ptrType.registeredClass.rawDestructor(
												e.ptr
										  );
								})(e);
					}
					function Xe(e, t, r) {
						if (t === r) return e;
						if (void 0 === r.baseClass) return null;
						var n = Xe(e, t, r.baseClass);
						return null === n ? null : r.downcast(n);
					}
					var Ye = {};
					function Qe() {
						return Object.keys(nt).length;
					}
					function Je() {
						var e = [];
						for (var t in nt) nt.hasOwnProperty(t) && e.push(nt[t]);
						return e;
					}
					var Ze = [];
					function et() {
						for (; Ze.length; ) {
							var e = Ze.pop();
							(e.$$.deleteScheduled = !1), e.delete();
						}
					}
					var tt = void 0;
					function rt(e) {
						(tt = e), Ze.length && tt && tt(et);
					}
					var nt = {};
					function it(e, t) {
						return (
							(t = (function (e, t) {
								for (
									void 0 === t &&
									De("ptr should not be undefined");
									e.baseClass;

								)
									(t = e.upcast(t)), (e = e.baseClass);
								return t;
							})(e, t)),
							nt[t]
						);
					}
					function ot(e, t) {
						return (
							(t.ptrType && t.ptr) ||
								Ue("makeClassHandle requires ptr and ptrType"),
							!!t.smartPtrType !== !!t.smartPtr &&
								Ue(
									"Both smartPtrType and smartPtr must be specified"
								),
							(t.count = { value: 1 }),
							st(
								Object.create(e, {
									$$: { value: t },
								})
							)
						);
					}
					function at(e) {
						var t = this.getPointee(e);
						if (!t) return this.destructor(e), null;
						var r = it(this.registeredClass, t);
						if (void 0 !== r) {
							if (0 === r.$$.count.value)
								return (
									(r.$$.ptr = t),
									(r.$$.smartPtr = e),
									r.clone()
								);
							var n = r.clone();
							return this.destructor(e), n;
						}
						function i() {
							return this.isSmartPointer
								? ot(this.registeredClass.instancePrototype, {
										ptrType: this.pointeeType,
										ptr: t,
										smartPtrType: this,
										smartPtr: e,
								  })
								: ot(this.registeredClass.instancePrototype, {
										ptrType: this,
										ptr: e,
								  });
						}
						var o,
							a = this.registeredClass.getActualType(t),
							s = Ye[a];
						if (!s) return i.call(this);
						o = this.isConst ? s.constPointerType : s.pointerType;
						var u = Xe(t, this.registeredClass, o.registeredClass);
						return null === u
							? i.call(this)
							: this.isSmartPointer
							? ot(o.registeredClass.instancePrototype, {
									ptrType: o,
									ptr: u,
									smartPtrType: this,
									smartPtr: e,
							  })
							: ot(o.registeredClass.instancePrototype, {
									ptrType: o,
									ptr: u,
							  });
					}
					function st(e) {
						return "undefined" === typeof FinalizationRegistry
							? ((st = (e) => e), e)
							: ((ze = new FinalizationRegistry((e) => {
									$e(e.$$);
							  })),
							  (st = (e) => {
									var t = e.$$;
									if (!!t.smartPtr) {
										var r = { $$: t };
										ze.register(e, r, e);
									}
									return e;
							  }),
							  (We = (e) => ze.unregister(e)),
							  st(e));
					}
					function ut() {
						if (
							(this.$$.ptr || Ge(this),
							this.$$.preservePointerOnDelete)
						)
							return (this.$$.count.value += 1), this;
						var e = st(
							Object.create(Object.getPrototypeOf(this), {
								$$: { value: Ke(this.$$) },
							})
						);
						return (
							(e.$$.count.value += 1),
							(e.$$.deleteScheduled = !1),
							e
						);
					}
					function ct() {
						this.$$.ptr || Ge(this),
							this.$$.deleteScheduled &&
								!this.$$.preservePointerOnDelete &&
								De("Object already scheduled for deletion"),
							We(this),
							$e(this.$$),
							this.$$.preservePointerOnDelete ||
								((this.$$.smartPtr = void 0),
								(this.$$.ptr = void 0));
					}
					function lt() {
						return !this.$$.ptr;
					}
					function dt() {
						return (
							this.$$.ptr || Ge(this),
							this.$$.deleteScheduled &&
								!this.$$.preservePointerOnDelete &&
								De("Object already scheduled for deletion"),
							Ze.push(this),
							1 === Ze.length && tt && tt(et),
							(this.$$.deleteScheduled = !0),
							this
						);
					}
					function ft() {}
					function ht(e, t, r) {
						if (void 0 === e[t].overloadTable) {
							var n = e[t];
							(e[t] = function () {
								return (
									e[t].overloadTable.hasOwnProperty(
										arguments.length
									) ||
										De(
											"Function '" +
												r +
												"' called with an invalid number of arguments (" +
												arguments.length +
												") - expects one of (" +
												e[t].overloadTable +
												")!"
										),
									e[t].overloadTable[arguments.length].apply(
										this,
										arguments
									)
								);
							}),
								(e[t].overloadTable = []),
								(e[t].overloadTable[n.argCount] = n);
						}
					}
					function pt(e, t, r) {
						a.hasOwnProperty(e)
							? ((void 0 === r ||
									(void 0 !== a[e].overloadTable &&
										void 0 !== a[e].overloadTable[r])) &&
									De(
										"Cannot register public name '" +
											e +
											"' twice"
									),
							  ht(a, e, e),
							  a.hasOwnProperty(r) &&
									De(
										"Cannot register multiple overloads of a function with the same number of arguments (" +
											r +
											")!"
									),
							  (a[e].overloadTable[r] = t))
							: ((a[e] = t),
							  void 0 !== r && (a[e].numArguments = r));
					}
					function mt(e, t, r, n, i, o, a, s) {
						(this.name = e),
							(this.constructor = t),
							(this.instancePrototype = r),
							(this.rawDestructor = n),
							(this.baseClass = i),
							(this.getActualType = o),
							(this.upcast = a),
							(this.downcast = s),
							(this.pureVirtualFunctions = []);
					}
					function gt(e, t, r) {
						for (; t !== r; )
							t.upcast ||
								De(
									"Expected null or instance of " +
										r.name +
										", got an instance of " +
										t.name
								),
								(e = t.upcast(e)),
								(t = t.baseClass);
						return e;
					}
					function vt(e, t) {
						if (null === t)
							return (
								this.isReference &&
									De("null is not a valid " + this.name),
								0
							);
						t.$$ ||
							De('Cannot pass "' + Ae(t) + '" as a ' + this.name),
							t.$$.ptr ||
								De(
									"Cannot pass deleted object as a pointer of type " +
										this.name
								);
						var r = t.$$.ptrType.registeredClass;
						return gt(t.$$.ptr, r, this.registeredClass);
					}
					function yt(e, t) {
						var r;
						if (null === t)
							return (
								this.isReference &&
									De("null is not a valid " + this.name),
								this.isSmartPointer
									? ((r = this.rawConstructor()),
									  null !== e &&
											e.push(this.rawDestructor, r),
									  r)
									: 0
							);
						t.$$ ||
							De('Cannot pass "' + Ae(t) + '" as a ' + this.name),
							t.$$.ptr ||
								De(
									"Cannot pass deleted object as a pointer of type " +
										this.name
								);
						!this.isConst &&
							t.$$.ptrType.isConst &&
							De(
								"Cannot convert argument of type " +
									(t.$$.smartPtrType
										? t.$$.smartPtrType.name
										: t.$$.ptrType.name) +
									" to parameter type " +
									this.name
							);
						var n = t.$$.ptrType.registeredClass;
						if (
							((r = gt(t.$$.ptr, n, this.registeredClass)),
							this.isSmartPointer)
						)
							switch (
								(void 0 === t.$$.smartPtr &&
									De(
										"Passing raw pointer to smart pointer is illegal"
									),
								this.sharingPolicy)
							) {
								case 0:
									t.$$.smartPtrType === this
										? (r = t.$$.smartPtr)
										: De(
												"Cannot convert argument of type " +
													(t.$$.smartPtrType
														? t.$$.smartPtrType.name
														: t.$$.ptrType.name) +
													" to parameter type " +
													this.name
										  );
									break;
								case 1:
									r = t.$$.smartPtr;
									break;
								case 2:
									if (t.$$.smartPtrType === this)
										r = t.$$.smartPtr;
									else {
										var i = t.clone();
										(r = this.rawShare(
											r,
											Ut.toHandle(function () {
												i.delete();
											})
										)),
											null !== e &&
												e.push(this.rawDestructor, r);
									}
									break;
								default:
									De("Unsupporting sharing policy");
							}
						return r;
					}
					function bt(e, t) {
						if (null === t)
							return (
								this.isReference &&
									De("null is not a valid " + this.name),
								0
							);
						t.$$ ||
							De('Cannot pass "' + Ae(t) + '" as a ' + this.name),
							t.$$.ptr ||
								De(
									"Cannot pass deleted object as a pointer of type " +
										this.name
								);
						t.$$.ptrType.isConst &&
							De(
								"Cannot convert argument of type " +
									t.$$.ptrType.name +
									" to parameter type " +
									this.name
							);
						var r = t.$$.ptrType.registeredClass;
						return gt(t.$$.ptr, r, this.registeredClass);
					}
					function Et(e) {
						return this.fromWireType(U[e >> 2]);
					}
					function wt(e) {
						return (
							this.rawGetPointee && (e = this.rawGetPointee(e)), e
						);
					}
					function _t(e) {
						this.rawDestructor && this.rawDestructor(e);
					}
					function St(e) {
						null !== e && e.delete();
					}
					function At(e, t, r, n, i, o, a, s, u, c, l) {
						(this.name = e),
							(this.registeredClass = t),
							(this.isReference = r),
							(this.isConst = n),
							(this.isSmartPointer = i),
							(this.pointeeType = o),
							(this.sharingPolicy = a),
							(this.rawGetPointee = s),
							(this.rawConstructor = u),
							(this.rawShare = c),
							(this.rawDestructor = l),
							i || void 0 !== t.baseClass
								? (this.toWireType = yt)
								: n
								? ((this.toWireType = vt),
								  (this.destructorFunction = null))
								: ((this.toWireType = bt),
								  (this.destructorFunction = null));
					}
					function xt(e, t, r) {
						a.hasOwnProperty(e) ||
							Ue("Replacing nonexistant public symbol"),
							void 0 !== a[e].overloadTable && void 0 !== r
								? (a[e].overloadTable[r] = t)
								: ((a[e] = t), (a[e].argCount = r));
					}
					function Tt(e, t) {
						e = Te(e);
						var r = me(t);
						return (
							"function" != typeof r &&
								De(
									"unknown function pointer with signature " +
										e +
										": " +
										t
								),
							r
						);
					}
					var Mt = void 0;
					function Ct(e) {
						var t = tr(e),
							r = Te(t);
						return er(t), r;
					}
					function It(e, t) {
						var r = [],
							n = {};
						throw (
							(t.forEach(function e(t) {
								n[t] ||
									Ce[t] ||
									(Ie[t]
										? Ie[t].forEach(e)
										: (r.push(t), (n[t] = !0)));
							}),
							new Mt(e + ": " + r.map(Ct).join([", "])))
						);
					}
					function Rt(e) {
						for (; e.length; ) {
							var t = e.pop();
							e.pop()(t);
						}
					}
					function kt(e, t, r, n, i) {
						var o = t.length;
						o < 2 &&
							De(
								"argTypes array size mismatch! Must at least get return value and 'this' types!"
							);
						for (
							var a = null !== t[1] && null !== r, s = !1, u = 1;
							u < t.length;
							++u
						)
							if (
								null !== t[u] &&
								void 0 === t[u].destructorFunction
							) {
								s = !0;
								break;
							}
						var c = "void" !== t[0].name,
							l = o - 2,
							d = new Array(l),
							f = [],
							h = [];
						return function () {
							var r;
							arguments.length !== l &&
								De(
									"function " +
										e +
										" called with " +
										arguments.length +
										" arguments, expected " +
										l +
										" args!"
								),
								(h.length = 0),
								(f.length = a ? 2 : 1),
								(f[0] = i),
								a &&
									((r = t[1].toWireType(h, this)),
									(f[1] = r));
							for (var o = 0; o < l; ++o)
								(d[o] = t[o + 2].toWireType(h, arguments[o])),
									f.push(d[o]);
							return (function (e) {
								if (s) Rt(h);
								else
									for (var n = a ? 1 : 2; n < t.length; n++) {
										var i = 1 === n ? r : d[n - 2];
										null !== t[n].destructorFunction &&
											t[n].destructorFunction(i);
									}
								if (c) return t[0].fromWireType(e);
							})(n.apply(null, f));
						};
					}
					function Ot(e, t) {
						for (var r = [], n = 0; n < e; n++)
							r.push(B[(t >> 2) + n]);
						return r;
					}
					var Nt = [],
						Lt = [
							{},
							{ value: void 0 },
							{ value: null },
							{ value: !0 },
							{ value: !1 },
						];
					function Pt(e) {
						e > 4 &&
							0 === --Lt[e].refcount &&
							((Lt[e] = void 0), Nt.push(e));
					}
					function Dt() {
						for (var e = 0, t = 5; t < Lt.length; ++t)
							void 0 !== Lt[t] && ++e;
						return e;
					}
					function Bt() {
						for (var e = 5; e < Lt.length; ++e)
							if (void 0 !== Lt[e]) return Lt[e];
						return null;
					}
					var Ut = {
						toValue: (e) => (
							e || De("Cannot use deleted val. handle = " + e),
							Lt[e].value
						),
						toHandle: (e) => {
							switch (e) {
								case void 0:
									return 1;
								case null:
									return 2;
								case !0:
									return 3;
								case !1:
									return 4;
								default:
									var t = Nt.length ? Nt.pop() : Lt.length;
									return (
										(Lt[t] = {
											refcount: 1,
											value: e,
										}),
										t
									);
							}
						},
					};
					function jt(e, t) {
						switch (t) {
							case 2:
								return function (e) {
									return this.fromWireType(j[e >> 2]);
								};
							case 3:
								return function (e) {
									return this.fromWireType(q[e >> 3]);
								};
							default:
								throw new TypeError("Unknown float type: " + e);
						}
					}
					function Ft(e, t) {
						var r = Ce[e];
						return (
							void 0 === r &&
								De(t + " has unknown type " + Ct(e)),
							r
						);
					}
					var Vt = {};
					function qt(e) {
						var t = Vt[e];
						return void 0 === t ? Te(e) : t;
					}
					function Ht() {
						if ("object" == typeof globalThis) return globalThis;
						function e(e) {
							e.$$$embind_global$$$ = e;
							var t =
								"object" == typeof $$$embind_global$$$ &&
								e.$$$embind_global$$$ == e;
							return t || delete e.$$$embind_global$$$, t;
						}
						if ("object" == typeof $$$embind_global$$$)
							return $$$embind_global$$$;
						if (
							("object" == typeof r.g && e(r.g)
								? ($$$embind_global$$$ = r.g)
								: "object" == typeof self &&
								  e(self) &&
								  ($$$embind_global$$$ = self),
							"object" == typeof $$$embind_global$$$)
						)
							return $$$embind_global$$$;
						throw Error("unable to get global object.");
					}
					var Kt = {};
					var Gt = [];
					var zt = 9007199254740992,
						Wt = -9007199254740992;
					var $t = function (e, t, r, n) {
							e || (e = this),
								(this.parent = e),
								(this.mount = e.mount),
								(this.mounted = null),
								(this.id = _e.nextInode++),
								(this.name = t),
								(this.mode = r),
								(this.node_ops = {}),
								(this.stream_ops = {}),
								(this.rdev = n);
						},
						Xt = 365,
						Yt = 146;
					function Qt(e, t, r) {
						var n = r > 0 ? r : k(e) + 1,
							i = new Array(n),
							o = I(e, i, 0, i.length);
						return t && (i.length = o), i;
					}
					Object.defineProperties($t.prototype, {
						read: {
							get: function () {
								return (this.mode & Xt) === Xt;
							},
							set: function (e) {
								e ? (this.mode |= Xt) : (this.mode &= -366);
							},
						},
						write: {
							get: function () {
								return (this.mode & Yt) === Yt;
							},
							set: function (e) {
								e ? (this.mode |= Yt) : (this.mode &= -147);
							},
						},
						isFolder: {
							get: function () {
								return _e.isDir(this.mode);
							},
						},
						isDevice: {
							get: function () {
								return _e.isChrdev(this.mode);
							},
						},
					}),
						(_e.FSNode = $t),
						_e.staticInit(),
						(function () {
							for (var e = new Array(256), t = 0; t < 256; ++t)
								e[t] = String.fromCharCode(t);
							xe = e;
						})(),
						(Pe = a.BindingError = Le(Error, "BindingError")),
						(Be = a.InternalError = Le(Error, "InternalError")),
						(ft.prototype.isAliasOf = He),
						(ft.prototype.clone = ut),
						(ft.prototype.delete = ct),
						(ft.prototype.isDeleted = lt),
						(ft.prototype.deleteLater = dt),
						(a.getInheritedInstanceCount = Qe),
						(a.getLiveInheritedInstances = Je),
						(a.flushPendingDeletes = et),
						(a.setDelayFunction = rt),
						(At.prototype.getPointee = wt),
						(At.prototype.destructor = _t),
						(At.prototype.argPackAdvance = 8),
						(At.prototype.readValueFromPointer = Et),
						(At.prototype.deleteObject = St),
						(At.prototype.fromWireType = at),
						(Mt = a.UnboundTypeError =
							Le(Error, "UnboundTypeError")),
						(a.count_emval_handles = Dt),
						(a.get_first_emval = Bt);
					var Jt,
						Zt = {
							p: function (e) {
								return nr(e + 24) + 24;
							},
							B: function (e, t, r) {
								throw (new ge(e).init(t, r), e, e);
							},
							s: function (e, t, r) {
								Se.varargs = r;
								try {
									var n = Se.getStreamFromFD(e);
									switch (t) {
										case 0:
											return (i = Se.get()) < 0
												? -28
												: _e.createStream(n, i).fd;
										case 1:
										case 2:
										case 6:
										case 7:
											return 0;
										case 3:
											return n.flags;
										case 4:
											var i = Se.get();
											return (n.flags |= i), 0;
										case 5:
											i = Se.get();
											return (P[(i + 0) >> 1] = 2), 0;
										case 16:
										case 8:
										default:
											return -28;
										case 9:
											return (
												(o = 28), (B[rr() >> 2] = o), -1
											);
									}
								} catch (a) {
									if (
										"undefined" == typeof _e ||
										!(a instanceof _e.ErrnoError)
									)
										throw a;
									return -a.errno;
								}
								var o;
							},
							F: function (e, t, r) {
								Se.varargs = r;
								try {
									var n = Se.getStreamFromFD(e);
									switch (t) {
										case 21509:
										case 21505:
										case 21510:
										case 21511:
										case 21512:
										case 21506:
										case 21507:
										case 21508:
										case 21523:
										case 21524:
											return n.tty ? 0 : -59;
										case 21519:
											if (!n.tty) return -59;
											var i = Se.get();
											return (B[i >> 2] = 0), 0;
										case 21520:
											return n.tty ? -28 : -59;
										case 21531:
											i = Se.get();
											return _e.ioctl(n, t, i);
										default:
											oe("bad ioctl syscall " + t);
									}
								} catch (o) {
									if (
										"undefined" == typeof _e ||
										!(o instanceof _e.ErrnoError)
									)
										throw o;
									return -o.errno;
								}
							},
							G: function (e, t, r, n) {
								Se.varargs = n;
								try {
									(t = Se.getStr(t)),
										(t = Se.calculateAt(e, t));
									var i = n ? Se.get() : 0;
									return _e.open(t, r, i).fd;
								} catch (o) {
									if (
										"undefined" == typeof _e ||
										!(o instanceof _e.ErrnoError)
									)
										throw o;
									return -o.errno;
								}
							},
							v: function (e, t, r, n, i) {
								t = Te(t);
								var o = qe(r),
									a = -1 != t.indexOf("u");
								a && (i = (1n << 64n) - 1n),
									Fe(e, {
										name: t,
										fromWireType: function (e) {
											return e;
										},
										toWireType: function (e, r) {
											if ("bigint" != typeof r)
												throw new TypeError(
													'Cannot convert "' +
														Ae(r) +
														'" to ' +
														this.name
												);
											if (r < n || r > i)
												throw new TypeError(
													'Passing a number "' +
														Ae(r) +
														'" from JS side to C/C++ side to an argument of type "' +
														t +
														'", which is outside the valid range [' +
														n +
														", " +
														i +
														"]!"
												);
											return r;
										},
										argPackAdvance: 8,
										readValueFromPointer: Ve(t, o, !a),
										destructorFunction: null,
									});
							},
							J: function (e, t, r, n, i) {
								var o = qe(r);
								Fe(e, {
									name: (t = Te(t)),
									fromWireType: function (e) {
										return !!e;
									},
									toWireType: function (e, t) {
										return t ? n : i;
									},
									argPackAdvance: 8,
									readValueFromPointer: function (e) {
										var n;
										if (1 === r) n = N;
										else if (2 === r) n = P;
										else {
											if (4 !== r)
												throw new TypeError(
													"Unknown boolean type size: " +
														t
												);
											n = B;
										}
										return this.fromWireType(n[e >> o]);
									},
									destructorFunction: null,
								});
							},
							i: function (
								e,
								t,
								r,
								n,
								i,
								o,
								a,
								s,
								u,
								c,
								l,
								d,
								f
							) {
								(l = Te(l)),
									(o = Tt(i, o)),
									s && (s = Tt(a, s)),
									c && (c = Tt(u, c)),
									(f = Tt(d, f));
								var h = Oe(l);
								pt(h, function () {
									It(
										"Cannot construct " +
											l +
											" due to unbound types",
										[n]
									);
								}),
									je([e, t, r], n ? [n] : [], function (t) {
										var r, i;
										(t = t[0]),
											(i = n
												? (r = t.registeredClass)
														.instancePrototype
												: ft.prototype);
										var a = Ne(h, function () {
												if (
													Object.getPrototypeOf(
														this
													) !== u
												)
													throw new Pe(
														"Use 'new' to construct " +
															l
													);
												if (
													void 0 ===
													d.constructor_body
												)
													throw new Pe(
														l +
															" has no accessible constructor"
													);
												var e =
													d.constructor_body[
														arguments.length
													];
												if (void 0 === e)
													throw new Pe(
														"Tried to invoke ctor of " +
															l +
															" with invalid number of parameters (" +
															arguments.length +
															") - expected (" +
															Object.keys(
																d.constructor_body
															).toString() +
															") parameters instead!"
													);
												return e.apply(this, arguments);
											}),
											u = Object.create(i, {
												constructor: {
													value: a,
												},
											});
										a.prototype = u;
										var d = new mt(l, a, u, f, r, o, s, c),
											p = new At(l, d, !0, !1, !1),
											m = new At(l + "*", d, !1, !1, !1),
											g = new At(
												l + " const*",
												d,
												!1,
												!0,
												!1
											);
										return (
											(Ye[e] = {
												pointerType: m,
												constPointerType: g,
											}),
											xt(h, a),
											[p, m, g]
										);
									});
							},
							g: function (e, t, r, n, i, o, a) {
								var s = Ot(r, n);
								(t = Te(t)),
									(o = Tt(i, o)),
									je([], [e], function (e) {
										var n = (e = e[0]).name + "." + t;
										function i() {
											It(
												"Cannot call " +
													n +
													" due to unbound types",
												s
											);
										}
										t.startsWith("@@") &&
											(t = Symbol[t.substring(2)]);
										var u = e.registeredClass.constructor;
										return (
											void 0 === u[t]
												? ((i.argCount = r - 1),
												  (u[t] = i))
												: (ht(u, t, n),
												  (u[t].overloadTable[r - 1] =
														i)),
											je([], s, function (e) {
												var i = [e[0], null].concat(
														e.slice(1)
													),
													s = kt(n, i, null, o, a);
												return (
													void 0 ===
													u[t].overloadTable
														? ((s.argCount = r - 1),
														  (u[t] = s))
														: (u[t].overloadTable[
																r - 1
														  ] = s),
													[]
												);
											}),
											[]
										);
									});
							},
							k: function (e, t, r, n, i, o) {
								x(t > 0);
								var a = Ot(t, r);
								(i = Tt(n, i)),
									je([], [e], function (e) {
										var r =
											"constructor " + (e = e[0]).name;
										if (
											(void 0 ===
												e.registeredClass
													.constructor_body &&
												(e.registeredClass.constructor_body =
													[]),
											void 0 !==
												e.registeredClass
													.constructor_body[t - 1])
										)
											throw new Pe(
												"Cannot register multiple constructors with identical number of parameters (" +
													(t - 1) +
													") for class '" +
													e.name +
													"'! Overload resolution is currently only performed using the parameter count, not actual type info!"
											);
										return (
											(e.registeredClass.constructor_body[
												t - 1
											] = () => {
												It(
													"Cannot construct " +
														e.name +
														" due to unbound types",
													a
												);
											}),
											je([], a, function (n) {
												return (
													n.splice(1, 0, null),
													(e.registeredClass.constructor_body[
														t - 1
													] = kt(r, n, null, i, o)),
													[]
												);
											}),
											[]
										);
									});
							},
							b: function (e, t, r, n, i, o, a, s) {
								var u = Ot(r, n);
								(t = Te(t)),
									(o = Tt(i, o)),
									je([], [e], function (e) {
										var n = (e = e[0]).name + "." + t;
										function i() {
											It(
												"Cannot call " +
													n +
													" due to unbound types",
												u
											);
										}
										t.startsWith("@@") &&
											(t = Symbol[t.substring(2)]),
											s &&
												e.registeredClass.pureVirtualFunctions.push(
													t
												);
										var c =
												e.registeredClass
													.instancePrototype,
											l = c[t];
										return (
											void 0 === l ||
											(void 0 === l.overloadTable &&
												l.className !== e.name &&
												l.argCount === r - 2)
												? ((i.argCount = r - 2),
												  (i.className = e.name),
												  (c[t] = i))
												: (ht(c, t, n),
												  (c[t].overloadTable[r - 2] =
														i)),
											je([], u, function (i) {
												var s = kt(n, i, e, o, a);
												return (
													void 0 ===
													c[t].overloadTable
														? ((s.argCount = r - 2),
														  (c[t] = s))
														: (c[t].overloadTable[
																r - 2
														  ] = s),
													[]
												);
											}),
											[]
										);
									});
							},
							c: function (e, t, r) {
								(e = Te(e)),
									je([], [t], function (t) {
										return (
											(t = t[0]),
											(a[e] = t.fromWireType(r)),
											[]
										);
									});
							},
							I: function (e, t) {
								Fe(e, {
									name: (t = Te(t)),
									fromWireType: function (e) {
										var t = Ut.toValue(e);
										return Pt(e), t;
									},
									toWireType: function (e, t) {
										return Ut.toHandle(t);
									},
									argPackAdvance: 8,
									readValueFromPointer: Et,
									destructorFunction: null,
								});
							},
							u: function (e, t, r) {
								var n = qe(r);
								Fe(e, {
									name: (t = Te(t)),
									fromWireType: function (e) {
										return e;
									},
									toWireType: function (e, t) {
										return t;
									},
									argPackAdvance: 8,
									readValueFromPointer: jt(t, n),
									destructorFunction: null,
								});
							},
							N: function (e, t, r, n, i, o) {
								var a = Ot(t, r);
								(e = Te(e)),
									(i = Tt(n, i)),
									pt(
										e,
										function () {
											It(
												"Cannot call " +
													e +
													" due to unbound types",
												a
											);
										},
										t - 1
									),
									je([], a, function (r) {
										var n = [r[0], null].concat(r.slice(1));
										return (
											xt(e, kt(e, n, null, i, o), t - 1),
											[]
										);
									});
							},
							h: function (e, t, r, n, i) {
								(t = Te(t)), -1 === i && (i = 4294967295);
								var o = qe(r),
									a = (e) => e;
								if (0 === n) {
									var s = 32 - 8 * r;
									a = (e) => (e << s) >>> s;
								}
								var u = t.includes("unsigned");
								Fe(e, {
									name: t,
									fromWireType: a,
									toWireType: u
										? function (e, t) {
												return this.name, t >>> 0;
										  }
										: function (e, t) {
												return this.name, t;
										  },
									argPackAdvance: 8,
									readValueFromPointer: Ve(t, o, 0 !== n),
									destructorFunction: null,
								});
							},
							d: function (e, t, r) {
								var n = [
									Int8Array,
									Uint8Array,
									Int16Array,
									Uint16Array,
									Int32Array,
									Uint32Array,
									Float32Array,
									Float64Array,
									BigInt64Array,
									BigUint64Array,
								][t];
								function i(e) {
									var t = U,
										r = t[(e >>= 2)],
										i = t[e + 1];
									return new n(O, i, r);
								}
								Fe(
									e,
									{
										name: (r = Te(r)),
										fromWireType: i,
										argPackAdvance: 8,
										readValueFromPointer: i,
									},
									{
										ignoreDuplicateRegistrations: !0,
									}
								);
							},
							t: function (e, t) {
								var r = "std::string" === (t = Te(t));
								Fe(e, {
									name: t,
									fromWireType: function (e) {
										var t,
											n = U[e >> 2];
										if (r)
											for (
												var i = e + 4, o = 0;
												o <= n;
												++o
											) {
												var a = e + 4 + o;
												if (o == n || 0 == L[a]) {
													var s = C(i, a - i);
													void 0 === t
														? (t = s)
														: ((t +=
																String.fromCharCode(
																	0
																)),
														  (t += s)),
														(i = a + 1);
												}
											}
										else {
											var u = new Array(n);
											for (o = 0; o < n; ++o)
												u[o] = String.fromCharCode(
													L[e + 4 + o]
												);
											t = u.join("");
										}
										return er(e), t;
									},
									toWireType: function (e, t) {
										t instanceof ArrayBuffer &&
											(t = new Uint8Array(t));
										var n = "string" == typeof t;
										n ||
											t instanceof Uint8Array ||
											t instanceof Uint8ClampedArray ||
											t instanceof Int8Array ||
											De(
												"Cannot pass non-string to std::string"
											);
										var i = (
												r && n
													? () => k(t)
													: () => t.length
											)(),
											o = nr(4 + i + 1);
										if (((U[o >> 2] = i), r && n))
											R(t, o + 4, i + 1);
										else if (n)
											for (var a = 0; a < i; ++a) {
												var s = t.charCodeAt(a);
												s > 255 &&
													(er(o),
													De(
														"String has UTF-16 code units that do not fit in 8 bits"
													)),
													(L[o + 4 + a] = s);
											}
										else
											for (a = 0; a < i; ++a)
												L[o + 4 + a] = t[a];
										return null !== e && e.push(er, o), o;
									},
									argPackAdvance: 8,
									readValueFromPointer: Et,
									destructorFunction: function (e) {
										er(e);
									},
								});
							},
							n: function (e, t, r) {
								var n, i, o, a, s;
								(r = Te(r)),
									2 === t
										? ((n = K),
										  (i = G),
										  (a = z),
										  (o = () => D),
										  (s = 1))
										: 4 === t &&
										  ((n = W),
										  (i = $),
										  (a = X),
										  (o = () => U),
										  (s = 2)),
									Fe(e, {
										name: r,
										fromWireType: function (e) {
											for (
												var r,
													i = U[e >> 2],
													a = o(),
													u = e + 4,
													c = 0;
												c <= i;
												++c
											) {
												var l = e + 4 + c * t;
												if (c == i || 0 == a[l >> s]) {
													var d = n(u, l - u);
													void 0 === r
														? (r = d)
														: ((r +=
																String.fromCharCode(
																	0
																)),
														  (r += d)),
														(u = l + t);
												}
											}
											return er(e), r;
										},
										toWireType: function (e, n) {
											"string" != typeof n &&
												De(
													"Cannot pass non-string to C++ string type " +
														r
												);
											var o = a(n),
												u = nr(4 + o + t);
											return (
												(U[u >> 2] = o >> s),
												i(n, u + 4, o + t),
												null !== e && e.push(er, u),
												u
											);
										},
										argPackAdvance: 8,
										readValueFromPointer: Et,
										destructorFunction: function (e) {
											er(e);
										},
									});
							},
							K: function (e, t) {
								Fe(e, {
									isVoid: !0,
									name: (t = Te(t)),
									argPackAdvance: 0,
									fromWireType: function () {},
									toWireType: function (e, t) {},
								});
							},
							z: function (e, t, r) {
								(e = Ut.toValue(e)), (t = Ft(t, "emval::as"));
								var n = [],
									i = Ut.toHandle(n);
								return (B[r >> 2] = i), t.toWireType(n, e);
							},
							a: Pt,
							f: function (e) {
								return 0 === e
									? Ut.toHandle(Ht())
									: ((e = qt(e)), Ut.toHandle(Ht()[e]));
							},
							A: function (e, t) {
								return (
									(e = Ut.toValue(e)),
									(t = Ut.toValue(t)),
									Ut.toHandle(e[t])
								);
							},
							j: function (e) {
								e > 4 && (Lt[e].refcount += 1);
							},
							e: function (e, t, r, n) {
								e = Ut.toValue(e);
								var i = Kt[t];
								return (
									i ||
										((i = (function (e) {
											var t = new Array(e + 1);
											return function (r, n, i) {
												t[0] = r;
												for (var o = 0; o < e; ++o) {
													var a = Ft(
														B[(n >> 2) + o],
														"parameter " + o
													);
													(t[o + 1] =
														a.readValueFromPointer(
															i
														)),
														(i += a.argPackAdvance);
												}
												var s = new (r.bind.apply(
													r,
													t
												))();
												return Ut.toHandle(s);
											};
										})(t)),
										(Kt[t] = i)),
									i(e, r, n)
								);
							},
							x: function () {
								return Ut.toHandle([]);
							},
							M: function (e) {
								return Ut.toHandle(qt(e));
							},
							y: function (e) {
								Rt(Ut.toValue(e)), Pt(e);
							},
							L: function (e, t, r) {
								(e = Ut.toValue(e)),
									(t = Ut.toValue(t)),
									(r = Ut.toValue(r)),
									(e[t] = r);
							},
							l: function (e, t) {
								var r = (e = Ft(
									e,
									"_emval_take_value"
								)).readValueFromPointer(t);
								return Ut.toHandle(r);
							},
							m: function () {
								oe("");
							},
							o: function (e, t, r) {
								var n = (function (e, t) {
									var r;
									for (Gt.length = 0, t >>= 2; (r = L[e++]); )
										(t += (105 != r) & t),
											Gt.push(
												105 == r
													? B[t]
													: (106 == r ? F : q)[
															t++ >> 1
													  ]
											),
											++t;
									return Gt;
								})(t, r);
								return fe[e].apply(null, n);
							},
							H: function (e, t, r) {
								L.copyWithin(e, t, t + r);
							},
							C: function (e) {
								return L.length, !1;
							},
							q: function (e) {
								try {
									var t = Se.getStreamFromFD(e);
									return _e.close(t), 0;
								} catch (r) {
									if (
										"undefined" == typeof _e ||
										!(r instanceof _e.ErrnoError)
									)
										throw r;
									return r.errno;
								}
							},
							E: function (e, t, r, n) {
								try {
									var i = (function (e, t, r, n) {
										for (var i = 0, o = 0; o < r; o++) {
											var a = U[t >> 2],
												s = U[(t + 4) >> 2];
											t += 8;
											var u = _e.read(e, N, a, s, n);
											if (u < 0) return -1;
											if (((i += u), u < s)) break;
										}
										return i;
									})(Se.getStreamFromFD(e), t, r);
									return (B[n >> 2] = i), 0;
								} catch (o) {
									if (
										"undefined" == typeof _e ||
										!(o instanceof _e.ErrnoError)
									)
										throw o;
									return o.errno;
								}
							},
							D: function (e, t, r, n) {
								try {
									if (
										((t =
											(o = t) < Wt || o > zt
												? NaN
												: Number(o)),
										isNaN(t))
									)
										return 61;
									var i = Se.getStreamFromFD(e);
									return (
										_e.llseek(i, t, r),
										(F[n >> 3] = BigInt(i.position)),
										i.getdents &&
											0 === t &&
											0 === r &&
											(i.getdents = null),
										0
									);
								} catch (a) {
									if (
										"undefined" == typeof _e ||
										!(a instanceof _e.ErrnoError)
									)
										throw a;
									return a.errno;
								}
								var o;
							},
							r: function (e, t, r, n) {
								try {
									var i = (function (e, t, r, n) {
										for (var i = 0, o = 0; o < r; o++) {
											var a = U[t >> 2],
												s = U[(t + 4) >> 2];
											t += 8;
											var u = _e.write(e, N, a, s, n);
											if (u < 0) return -1;
											i += u;
										}
										return i;
									})(Se.getStreamFromFD(e), t, r);
									return (U[n >> 2] = i), 0;
								} catch (o) {
									if (
										"undefined" == typeof _e ||
										!(o instanceof _e.ErrnoError)
									)
										throw o;
									return o.errno;
								}
							},
							w: function () {
								var e = window.location.origin,
									t = k(e) + 1,
									r = nr(t);
								return R(e, r, t), r;
							},
						},
						er =
							((function () {
								var e = { a: Zt };
								function t(e, t) {
									var r,
										n,
										i = e.exports;
									(a.asm = i),
										(_ = a.asm.O),
										(r = _.buffer),
										(O = r),
										(a.HEAP8 = N = new Int8Array(r)),
										(a.HEAP16 = P = new Int16Array(r)),
										(a.HEAP32 = B = new Int32Array(r)),
										(a.HEAPU8 = L = new Uint8Array(r)),
										(a.HEAPU16 = D = new Uint16Array(r)),
										(a.HEAPU32 = U = new Uint32Array(r)),
										(a.HEAPF32 = j = new Float32Array(r)),
										(a.HEAPF64 = q = new Float64Array(r)),
										(a.HEAP64 = F = new BigInt64Array(r)),
										(a.HEAPU64 = V = new BigUint64Array(r)),
										(Y = a.asm.Q),
										(n = a.asm.P),
										J.unshift(n),
										ie();
								}
								function r(e) {
									t(e.instance);
								}
								function n(t) {
									return (function () {
										if (!b && (m || g)) {
											if (
												"function" == typeof fetch &&
												!le(ae)
											)
												return fetch(ae, {
													credentials: "same-origin",
												})
													.then(function (e) {
														if (!e.ok)
															throw (
																"failed to load wasm binary file at '" +
																ae +
																"'"
															);
														return e.arrayBuffer();
													})
													.catch(function () {
														return de(ae);
													});
											if (u)
												return new Promise(function (
													e,
													t
												) {
													u(
														ae,
														function (t) {
															e(
																new Uint8Array(
																	t
																)
															);
														},
														t
													);
												});
										}
										return Promise.resolve().then(
											function () {
												return de(ae);
											}
										);
									})()
										.then(function (t) {
											return WebAssembly.instantiate(
												t,
												e
											);
										})
										.then(function (e) {
											return e;
										})
										.then(t, function (e) {
											w(
												"failed to asynchronously prepare wasm: " +
													e
											),
												oe(e);
										});
								}
								if ((ne(), a.instantiateWasm))
									try {
										return a.instantiateWasm(e, t);
									} catch (i) {
										return (
											w(
												"Module.instantiateWasm callback failed with error: " +
													i
											),
											!1
										);
									}
								(b ||
								"function" !=
									typeof WebAssembly.instantiateStreaming ||
								ce(ae) ||
								le(ae) ||
								v ||
								"function" != typeof fetch
									? n(r)
									: fetch(ae, {
											credentials: "same-origin",
									  }).then(function (t) {
											return WebAssembly.instantiateStreaming(
												t,
												e
											).then(r, function (e) {
												return (
													w(
														"wasm streaming compile failed: " +
															e
													),
													w(
														"falling back to ArrayBuffer instantiation"
													),
													n(r)
												);
											});
									  })
								).catch(o);
							})(),
							(a.___wasm_call_ctors = function () {
								return (a.___wasm_call_ctors = a.asm.P).apply(
									null,
									arguments
								);
							}),
							(a._free = function () {
								return (er = a._free = a.asm.R).apply(
									null,
									arguments
								);
							})),
						tr = (a.___getTypeName = function () {
							return (tr = a.___getTypeName = a.asm.S).apply(
								null,
								arguments
							);
						}),
						rr =
							((a.___embind_register_native_and_builtin_types =
								function () {
									return (a.___embind_register_native_and_builtin_types =
										a.asm.T).apply(null, arguments);
								}),
							(a.___errno_location = function () {
								return (rr = a.___errno_location =
									a.asm.U).apply(null, arguments);
							})),
						nr = (a._malloc = function () {
							return (nr = a._malloc = a.asm.V).apply(
								null,
								arguments
							);
						}),
						ir = (a.___cxa_is_pointer_type = function () {
							return (ir = a.___cxa_is_pointer_type =
								a.asm.W).apply(null, arguments);
						});
					function or(e) {
						(this.name = "ExitStatus"),
							(this.message =
								"Program terminated with exit(" + e + ")"),
							(this.status = e);
					}
					function ar(e) {
						function t() {
							Jt ||
								((Jt = !0),
								(a.calledRun = !0),
								A ||
									(!0,
									a.noFSInit ||
										_e.init.initialized ||
										_e.init(),
									(_e.ignorePermissions = !1),
									be.init(),
									he(J),
									i(a),
									a.onRuntimeInitialized &&
										a.onRuntimeInitialized(),
									(function () {
										if (a.postRun)
											for (
												"function" ==
													typeof a.postRun &&
												(a.postRun = [a.postRun]);
												a.postRun.length;

											)
												(e = a.postRun.shift()),
													Z.unshift(e);
										var e;
										he(Z);
									})()));
						}
						(e = e || p),
							ee > 0 ||
								(!(function () {
									if (a.preRun)
										for (
											"function" == typeof a.preRun &&
											(a.preRun = [a.preRun]);
											a.preRun.length;

										)
											(e = a.preRun.shift()),
												Q.unshift(e);
									var e;
									he(Q);
								})(),
								ee > 0 ||
									(a.setStatus
										? (a.setStatus("Running..."),
										  setTimeout(function () {
												setTimeout(function () {
													a.setStatus("");
												}, 1),
													t();
										  }, 1))
										: t()));
					}
					if (
						((re = function e() {
							Jt || ar(), Jt || (re = e);
						}),
						(a.run = ar),
						a.preInit)
					)
						for (
							"function" == typeof a.preInit &&
							(a.preInit = [a.preInit]);
							a.preInit.length > 0;

						)
							a.preInit.pop()();
					return ar(), t.ready;
				}
			);
		})();
	exports.exports = i;
};

export default EmscriptenModuleFactory;