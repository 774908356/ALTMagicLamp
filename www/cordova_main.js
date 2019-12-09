(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __extends = undefined && undefined.__extends || function () {
    var extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function (d, b) {
        d.__proto__ = b;
    } || function (d, b) {
        for (var p in b) {
            if (b.hasOwnProperty(p)) d[p] = b[p];
        }
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() {
            this.constructor = d;
        }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
}();
(function iife() {
    var platformExportObj = function detectPlatformExportObj() {
        if (typeof module !== 'undefined' && module.exports) {
            return module.exports; // node
        } else if (typeof window !== 'undefined') {
            return window; // browser
        }
        throw new Error('Could not detect platform global object (no window or module.exports)');
    }();
    /* tslint:disable */
    var isBrowser = typeof window !== 'undefined';
    var b64Encode = isBrowser ? btoa : require('base-64').encode;
    var b64Decode = isBrowser ? atob : require('base-64').decode;
    var URL = isBrowser ? window.URL : require('url').URL;
    var punycode = isBrowser ? window.punycode : require('punycode');
    if (!punycode) {
        throw new Error("Could not find punycode. Did you forget to add e.g.\n  <script src=\"bower_components/punycode/punycode.min.js\"></script>?");
    }
    /* tslint:enable */
    // Custom error base class
    var ShadowsocksConfigError = /** @class */function (_super) {
        __extends(ShadowsocksConfigError, _super);
        function ShadowsocksConfigError(message) {
            var _newTarget = this.constructor;
            var _this = _super.call(this, message) || this;
            Object.setPrototypeOf(_this, _newTarget.prototype); // restore prototype chain
            _this.name = _newTarget.name;
            return _this;
        }
        return ShadowsocksConfigError;
    }(Error);
    platformExportObj.ShadowsocksConfigError = ShadowsocksConfigError;
    var InvalidConfigField = /** @class */function (_super) {
        __extends(InvalidConfigField, _super);
        function InvalidConfigField() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        return InvalidConfigField;
    }(ShadowsocksConfigError);
    platformExportObj.InvalidConfigField = InvalidConfigField;
    var InvalidUri = /** @class */function (_super) {
        __extends(InvalidUri, _super);
        function InvalidUri() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        return InvalidUri;
    }(ShadowsocksConfigError);
    platformExportObj.InvalidUri = InvalidUri;
    // Self-validating/normalizing config data types implement this ValidatedConfigField interface.
    // Constructors take some data, validate, normalize, and store if valid, or throw otherwise.
    var ValidatedConfigField = /** @class */function () {
        function ValidatedConfigField() {}
        return ValidatedConfigField;
    }();
    platformExportObj.ValidatedConfigField = ValidatedConfigField;
    function throwErrorForInvalidField(name, value, reason) {
        throw new InvalidConfigField("Invalid " + name + ": " + value + " " + (reason || ''));
    }
    var Host = /** @class */function (_super) {
        __extends(Host, _super);
        function Host(host) {
            var _this = _super.call(this) || this;
            if (!host) {
                throwErrorForInvalidField('host', host);
            }
            if (host instanceof Host) {
                host = host.data;
            }
            host = punycode.toASCII(host);
            _this.isIPv4 = Host.IPV4_PATTERN.test(host);
            _this.isIPv6 = _this.isIPv4 ? false : Host.IPV6_PATTERN.test(host);
            _this.isHostname = _this.isIPv4 || _this.isIPv6 ? false : Host.HOSTNAME_PATTERN.test(host);
            if (!(_this.isIPv4 || _this.isIPv6 || _this.isHostname)) {
                throwErrorForInvalidField('host', host);
            }
            _this.data = host;
            return _this;
        }
        Host.IPV4_PATTERN = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        Host.IPV6_PATTERN = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
        Host.HOSTNAME_PATTERN = /^[A-z0-9]+[A-z0-9_.-]*$/;
        return Host;
    }(ValidatedConfigField);
    platformExportObj.Host = Host;
    var Port = /** @class */function (_super) {
        __extends(Port, _super);
        function Port(port) {
            var _this = _super.call(this) || this;
            if (port instanceof Port) {
                port = port.data;
            }
            if (typeof port === 'number') {
                // Stringify in case negative or floating point -> the regex test below will catch.
                port = port.toString();
            }
            if (!Port.PATTERN.test(port)) {
                throwErrorForInvalidField('port', port);
            }
            // Could exceed the maximum port number, so convert to Number to check. Could also have leading
            // zeros. Converting to Number drops those, so we get normalization for free. :)
            port = Number(port);
            if (port > 65535) {
                throwErrorForInvalidField('port', port);
            }
            _this.data = port;
            return _this;
        }
        Port.PATTERN = /^[0-9]{1,5}$/;
        return Port;
    }(ValidatedConfigField);
    platformExportObj.Port = Port;
    // A method value must exactly match an element in the set of known ciphers.
    // ref: https://github.com/shadowsocks/shadowsocks-libev/blob/10a2d3e3/completions/bash/ss-redir#L5
    platformExportObj.METHODS = new Set(['rc4-md5', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb', 'bf-cfb', 'chacha20-ietf-poly1305', 'salsa20', 'chacha20', 'chacha20-ietf', 'xchacha20-ietf-poly1305']);
    var Method = /** @class */function (_super) {
        __extends(Method, _super);
        function Method(method) {
            var _this = _super.call(this) || this;
            if (method instanceof Method) {
                method = method.data;
            }
            if (!platformExportObj.METHODS.has(method)) {
                throwErrorForInvalidField('method', method);
            }
            _this.data = method;
            return _this;
        }
        return Method;
    }(ValidatedConfigField);
    platformExportObj.Method = Method;
    var Password = /** @class */function (_super) {
        __extends(Password, _super);
        function Password(password) {
            var _this = _super.call(this) || this;
            _this.data = password instanceof Password ? password.data : password;
            return _this;
        }
        return Password;
    }(ValidatedConfigField);
    platformExportObj.Password = Password;
    var Tag = /** @class */function (_super) {
        __extends(Tag, _super);
        function Tag(tag) {
            if (tag === void 0) {
                tag = '';
            }
            var _this = _super.call(this) || this;
            _this.data = tag instanceof Tag ? tag.data : tag;
            return _this;
        }
        return Tag;
    }(ValidatedConfigField);
    platformExportObj.Tag = Tag;
    // tslint:disable-next-line:no-any
    function makeConfig(input) {
        // Use "!" for the required fields to tell tsc that we handle undefined in the
        // ValidatedConfigFields we call; tsc can't figure that out otherwise.
        var config = {
            host: new Host(input.host),
            port: new Port(input.port),
            method: new Method(input.method),
            password: new Password(input.password),
            tag: new Tag(input.tag),
            extra: {}
        };
        // Put any remaining fields in `input` into `config.extra`.
        for (var _i = 0, _a = Object.keys(input); _i < _a.length; _i++) {
            var key = _a[_i];
            if (!/^(host|port|method|password|tag)$/.test(key)) {
                config.extra[key] = input[key] && input[key].toString();
            }
        }
        return config;
    }
    platformExportObj.makeConfig = makeConfig;
    platformExportObj.SHADOWSOCKS_URI = {
        PROTOCOL: 'ss:',
        getUriFormattedHost: function getUriFormattedHost(host) {
            return host.isIPv6 ? "[" + host.data + "]" : host.data;
        },
        getHash: function getHash(tag) {
            return tag.data ? "#" + encodeURIComponent(tag.data) : '';
        },
        validateProtocol: function validateProtocol(uri) {
            if (!uri.startsWith(platformExportObj.SHADOWSOCKS_URI.PROTOCOL)) {
                throw new InvalidUri("URI must start with \"" + platformExportObj.SHADOWSOCKS_URI.PROTOCOL + "\"");
            }
        },
        parse: function parse(uri) {
            var error;
            for (var _i = 0, _a = [platformExportObj.SIP002_URI, platformExportObj.LEGACY_BASE64_URI]; _i < _a.length; _i++) {
                var uriType = _a[_i];
                try {
                    return uriType.parse(uri);
                } catch (e) {
                    error = e;
                }
            }
            if (!(error instanceof InvalidUri)) {
                var originalErrorName = error.name || '(Unnamed Error)';
                var originalErrorMessage = error.message || '(no error message provided)';
                var originalErrorString = originalErrorName + ": " + originalErrorMessage;
                var newErrorMessage = "Invalid input: " + originalErrorString;
                error = new InvalidUri(newErrorMessage);
            }
            throw error;
        }
    };
    // Ref: https://shadowsocks.org/en/config/quick-guide.html
    platformExportObj.LEGACY_BASE64_URI = {
        parse: function parse(uri) {
            platformExportObj.SHADOWSOCKS_URI.validateProtocol(uri);
            var hashIndex = uri.indexOf('#');
            var hasTag = hashIndex !== -1;
            var b64EndIndex = hasTag ? hashIndex : uri.length;
            var tagStartIndex = hasTag ? hashIndex + 1 : uri.length;
            var tag = new Tag(decodeURIComponent(uri.substring(tagStartIndex)));
            var b64EncodedData = uri.substring('ss://'.length, b64EndIndex);
            var b64DecodedData = b64Decode(b64EncodedData);
            var atSignIndex = b64DecodedData.lastIndexOf('@');
            if (atSignIndex === -1) {
                throw new InvalidUri("Missing \"@\"");
            }
            var methodAndPassword = b64DecodedData.substring(0, atSignIndex);
            var methodEndIndex = methodAndPassword.indexOf(':');
            if (methodEndIndex === -1) {
                throw new InvalidUri("Missing password");
            }
            var methodString = methodAndPassword.substring(0, methodEndIndex);
            var method = new Method(methodString);
            var passwordStartIndex = methodEndIndex + 1;
            var passwordString = methodAndPassword.substring(passwordStartIndex);
            var password = new Password(passwordString);
            var hostStartIndex = atSignIndex + 1;
            var hostAndPort = b64DecodedData.substring(hostStartIndex);
            var hostEndIndex = hostAndPort.lastIndexOf(':');
            if (hostEndIndex === -1) {
                throw new InvalidUri("Missing port");
            }
            var uriFormattedHost = hostAndPort.substring(0, hostEndIndex);
            var host;
            try {
                host = new Host(uriFormattedHost);
            } catch (_) {
                // Could be IPv6 host formatted with surrounding brackets, so try stripping first and last
                // characters. If this throws, give up and let the exception propagate.
                host = new Host(uriFormattedHost.substring(1, uriFormattedHost.length - 1));
            }
            var portStartIndex = hostEndIndex + 1;
            var portString = hostAndPort.substring(portStartIndex);
            var port = new Port(portString);
            var extra = {}; // empty because LegacyBase64Uri can't hold extra
            return { method: method, password: password, host: host, port: port, tag: tag, extra: extra };
        },
        stringify: function stringify(config) {
            var host = config.host,
                port = config.port,
                method = config.method,
                password = config.password,
                tag = config.tag;
            var hash = platformExportObj.SHADOWSOCKS_URI.getHash(tag);
            var b64EncodedData = b64Encode(method.data + ":" + password.data + "@" + host.data + ":" + port.data);
            var dataLength = b64EncodedData.length;
            var paddingLength = 0;
            for (; b64EncodedData[dataLength - 1 - paddingLength] === '='; paddingLength++) {}
            b64EncodedData = paddingLength === 0 ? b64EncodedData : b64EncodedData.substring(0, dataLength - paddingLength);
            return "ss://" + b64EncodedData + hash;
        }
    };
    // Ref: https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html
    platformExportObj.SIP002_URI = {
        parse: function parse(uri) {
            platformExportObj.SHADOWSOCKS_URI.validateProtocol(uri);
            // Can use built-in URL parser for expedience. Just have to replace "ss" with "http" to ensure
            // correct results, otherwise browsers like Safari fail to parse it.
            var inputForUrlParser = "http" + uri.substring(2);
            // The built-in URL parser throws as desired when given URIs with invalid syntax.
            var urlParserResult = new URL(inputForUrlParser);
            var uriFormattedHost = urlParserResult.hostname;
            // URI-formatted IPv6 hostnames have surrounding brackets.
            var last = uriFormattedHost.length - 1;
            var brackets = uriFormattedHost[0] === '[' && uriFormattedHost[last] === ']';
            var hostString = brackets ? uriFormattedHost.substring(1, last) : uriFormattedHost;
            var host = new Host(hostString);
            var parsedPort = urlParserResult.port;
            if (!parsedPort && uri.match(/:80($|\/)/g)) {
                // The default URL parser fails to recognize the default port (80) when the URI being parsed
                // is HTTP. Check if the port is present at the end of the string or before the parameters.
                parsedPort = 80;
            }
            var port = new Port(parsedPort);
            var tag = new Tag(decodeURIComponent(urlParserResult.hash.substring(1)));
            var b64EncodedUserInfo = urlParserResult.username.replace(/%3D/g, '=');
            // base64.decode throws as desired when given invalid base64 input.
            var b64DecodedUserInfo = b64Decode(b64EncodedUserInfo);
            var colonIdx = b64DecodedUserInfo.indexOf(':');
            if (colonIdx === -1) {
                throw new InvalidUri("Missing password");
            }
            var methodString = b64DecodedUserInfo.substring(0, colonIdx);
            var method = new Method(methodString);
            var passwordString = b64DecodedUserInfo.substring(colonIdx + 1);
            var password = new Password(passwordString);
            var queryParams = urlParserResult.search.substring(1).split('&');
            var extra = {};
            for (var _i = 0, queryParams_1 = queryParams; _i < queryParams_1.length; _i++) {
                var pair = queryParams_1[_i];
                var _a = pair.split('=', 2),
                    key = _a[0],
                    value = _a[1];
                if (!key) continue;
                extra[key] = decodeURIComponent(value || '');
            }
            return { method: method, password: password, host: host, port: port, tag: tag, extra: extra };
        },
        stringify: function stringify(config) {
            var host = config.host,
                port = config.port,
                method = config.method,
                password = config.password,
                tag = config.tag,
                extra = config.extra;
            var userInfo = b64Encode(method.data + ":" + password.data);
            var uriHost = platformExportObj.SHADOWSOCKS_URI.getUriFormattedHost(host);
            var hash = platformExportObj.SHADOWSOCKS_URI.getHash(tag);
            var queryString = '';
            for (var key in extra) {
                if (!key) continue;
                queryString += (queryString ? '&' : '?') + (key + "=" + encodeURIComponent(extra[key]));
            }
            return "ss://" + userInfo + "@" + uriHost + ":" + port.data + "/" + queryString + hash;
        }
    };
})();

},{"base-64":2,"punycode":3,"url":15}],2:[function(require,module,exports){
(function (global){
'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

/*! http://mths.be/base64 v0.1.0 by @mathias | MIT license */
;(function (root) {

	// Detect free variables `exports`.
	var freeExports = (typeof exports === 'undefined' ? 'undefined' : _typeof(exports)) == 'object' && exports;

	// Detect free variable `module`.
	var freeModule = (typeof module === 'undefined' ? 'undefined' : _typeof(module)) == 'object' && module && module.exports == freeExports && module;

	// Detect free variable `global`, from Node.js or Browserified code, and use
	// it as `root`.
	var freeGlobal = (typeof global === 'undefined' ? 'undefined' : _typeof(global)) == 'object' && global;
	if (freeGlobal.global === freeGlobal || freeGlobal.window === freeGlobal) {
		root = freeGlobal;
	}

	/*--------------------------------------------------------------------------*/

	var InvalidCharacterError = function InvalidCharacterError(message) {
		this.message = message;
	};
	InvalidCharacterError.prototype = new Error();
	InvalidCharacterError.prototype.name = 'InvalidCharacterError';

	var error = function error(message) {
		// Note: the error messages used throughout this file match those used by
		// the native `atob`/`btoa` implementation in Chromium.
		throw new InvalidCharacterError(message);
	};

	var TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	// http://whatwg.org/html/common-microsyntaxes.html#space-character
	var REGEX_SPACE_CHARACTERS = /[\t\n\f\r ]/g;

	// `decode` is designed to be fully compatible with `atob` as described in the
	// HTML Standard. http://whatwg.org/html/webappapis.html#dom-windowbase64-atob
	// The optimized base64-decoding algorithm used is based on @atk’s excellent
	// implementation. https://gist.github.com/atk/1020396
	var decode = function decode(input) {
		input = String(input).replace(REGEX_SPACE_CHARACTERS, '');
		var length = input.length;
		if (length % 4 == 0) {
			input = input.replace(/==?$/, '');
			length = input.length;
		}
		if (length % 4 == 1 ||
		// http://whatwg.org/C#alphanumeric-ascii-characters
		/[^+a-zA-Z0-9/]/.test(input)) {
			error('Invalid character: the string to be decoded is not correctly encoded.');
		}
		var bitCounter = 0;
		var bitStorage;
		var buffer;
		var output = '';
		var position = -1;
		while (++position < length) {
			buffer = TABLE.indexOf(input.charAt(position));
			bitStorage = bitCounter % 4 ? bitStorage * 64 + buffer : buffer;
			// Unless this is the first of a group of 4 characters…
			if (bitCounter++ % 4) {
				// …convert the first 8 bits to a single ASCII character.
				output += String.fromCharCode(0xFF & bitStorage >> (-2 * bitCounter & 6));
			}
		}
		return output;
	};

	// `encode` is designed to be fully compatible with `btoa` as described in the
	// HTML Standard: http://whatwg.org/html/webappapis.html#dom-windowbase64-btoa
	var encode = function encode(input) {
		input = String(input);
		if (/[^\0-\xFF]/.test(input)) {
			// Note: no need to special-case astral symbols here, as surrogates are
			// matched, and the input is supposed to only contain ASCII anyway.
			error('The string to be encoded contains characters outside of the ' + 'Latin1 range.');
		}
		var padding = input.length % 3;
		var output = '';
		var position = -1;
		var a;
		var b;
		var c;
		var d;
		var buffer;
		// Make sure any padding is handled outside of the loop.
		var length = input.length - padding;

		while (++position < length) {
			// Read three bytes, i.e. 24 bits.
			a = input.charCodeAt(position) << 16;
			b = input.charCodeAt(++position) << 8;
			c = input.charCodeAt(++position);
			buffer = a + b + c;
			// Turn the 24 bits into four chunks of 6 bits each, and append the
			// matching character for each of them to the output.
			output += TABLE.charAt(buffer >> 18 & 0x3F) + TABLE.charAt(buffer >> 12 & 0x3F) + TABLE.charAt(buffer >> 6 & 0x3F) + TABLE.charAt(buffer & 0x3F);
		}

		if (padding == 2) {
			a = input.charCodeAt(position) << 8;
			b = input.charCodeAt(++position);
			buffer = a + b;
			output += TABLE.charAt(buffer >> 10) + TABLE.charAt(buffer >> 4 & 0x3F) + TABLE.charAt(buffer << 2 & 0x3F) + '=';
		} else if (padding == 1) {
			buffer = input.charCodeAt(position);
			output += TABLE.charAt(buffer >> 2) + TABLE.charAt(buffer << 4 & 0x3F) + '==';
		}

		return output;
	};

	var base64 = {
		'encode': encode,
		'decode': decode,
		'version': '0.1.0'
	};

	// Some AMD build optimizers, like r.js, check for specific condition patterns
	// like the following:
	if (typeof define == 'function' && _typeof(define.amd) == 'object' && define.amd) {
		define(function () {
			return base64;
		});
	} else if (freeExports && !freeExports.nodeType) {
		if (freeModule) {
			// in Node.js or RingoJS v0.8.0+
			freeModule.exports = base64;
		} else {
			// in Narwhal or RingoJS v0.7.0-
			for (var key in base64) {
				base64.hasOwnProperty(key) && (freeExports[key] = base64[key]);
			}
		}
	} else {
		// in Rhino or a web browser
		root.base64 = base64;
	}
})(undefined);

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}],3:[function(require,module,exports){
(function (global){
'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

/*! https://mths.be/punycode v1.4.1 by @mathias */
;(function (root) {

	/** Detect free variables */
	var freeExports = (typeof exports === 'undefined' ? 'undefined' : _typeof(exports)) == 'object' && exports && !exports.nodeType && exports;
	var freeModule = (typeof module === 'undefined' ? 'undefined' : _typeof(module)) == 'object' && module && !module.nodeType && module;
	var freeGlobal = (typeof global === 'undefined' ? 'undefined' : _typeof(global)) == 'object' && global;
	if (freeGlobal.global === freeGlobal || freeGlobal.window === freeGlobal || freeGlobal.self === freeGlobal) {
		root = freeGlobal;
	}

	/**
  * The `punycode` object.
  * @name punycode
  * @type Object
  */
	var punycode,


	/** Highest positive signed 32-bit float value */
	maxInt = 2147483647,
	    // aka. 0x7FFFFFFF or 2^31-1

	/** Bootstring parameters */
	base = 36,
	    tMin = 1,
	    tMax = 26,
	    skew = 38,
	    damp = 700,
	    initialBias = 72,
	    initialN = 128,
	    // 0x80
	delimiter = '-',
	    // '\x2D'

	/** Regular expressions */
	regexPunycode = /^xn--/,
	    regexNonASCII = /[^\x20-\x7E]/,
	    // unprintable ASCII chars + non-ASCII chars
	regexSeparators = /[\x2E\u3002\uFF0E\uFF61]/g,
	    // RFC 3490 separators

	/** Error messages */
	errors = {
		'overflow': 'Overflow: input needs wider integers to process',
		'not-basic': 'Illegal input >= 0x80 (not a basic code point)',
		'invalid-input': 'Invalid input'
	},


	/** Convenience shortcuts */
	baseMinusTMin = base - tMin,
	    floor = Math.floor,
	    stringFromCharCode = String.fromCharCode,


	/** Temporary variable */
	key;

	/*--------------------------------------------------------------------------*/

	/**
  * A generic error utility function.
  * @private
  * @param {String} type The error type.
  * @returns {Error} Throws a `RangeError` with the applicable error message.
  */
	function error(type) {
		throw new RangeError(errors[type]);
	}

	/**
  * A generic `Array#map` utility function.
  * @private
  * @param {Array} array The array to iterate over.
  * @param {Function} callback The function that gets called for every array
  * item.
  * @returns {Array} A new array of values returned by the callback function.
  */
	function map(array, fn) {
		var length = array.length;
		var result = [];
		while (length--) {
			result[length] = fn(array[length]);
		}
		return result;
	}

	/**
  * A simple `Array#map`-like wrapper to work with domain name strings or email
  * addresses.
  * @private
  * @param {String} domain The domain name or email address.
  * @param {Function} callback The function that gets called for every
  * character.
  * @returns {Array} A new string of characters returned by the callback
  * function.
  */
	function mapDomain(string, fn) {
		var parts = string.split('@');
		var result = '';
		if (parts.length > 1) {
			// In email addresses, only the domain name should be punycoded. Leave
			// the local part (i.e. everything up to `@`) intact.
			result = parts[0] + '@';
			string = parts[1];
		}
		// Avoid `split(regex)` for IE8 compatibility. See #17.
		string = string.replace(regexSeparators, '\x2E');
		var labels = string.split('.');
		var encoded = map(labels, fn).join('.');
		return result + encoded;
	}

	/**
  * Creates an array containing the numeric code points of each Unicode
  * character in the string. While JavaScript uses UCS-2 internally,
  * this function will convert a pair of surrogate halves (each of which
  * UCS-2 exposes as separate characters) into a single code point,
  * matching UTF-16.
  * @see `punycode.ucs2.encode`
  * @see <https://mathiasbynens.be/notes/javascript-encoding>
  * @memberOf punycode.ucs2
  * @name decode
  * @param {String} string The Unicode input string (UCS-2).
  * @returns {Array} The new array of code points.
  */
	function ucs2decode(string) {
		var output = [],
		    counter = 0,
		    length = string.length,
		    value,
		    extra;
		while (counter < length) {
			value = string.charCodeAt(counter++);
			if (value >= 0xD800 && value <= 0xDBFF && counter < length) {
				// high surrogate, and there is a next character
				extra = string.charCodeAt(counter++);
				if ((extra & 0xFC00) == 0xDC00) {
					// low surrogate
					output.push(((value & 0x3FF) << 10) + (extra & 0x3FF) + 0x10000);
				} else {
					// unmatched surrogate; only append this code unit, in case the next
					// code unit is the high surrogate of a surrogate pair
					output.push(value);
					counter--;
				}
			} else {
				output.push(value);
			}
		}
		return output;
	}

	/**
  * Creates a string based on an array of numeric code points.
  * @see `punycode.ucs2.decode`
  * @memberOf punycode.ucs2
  * @name encode
  * @param {Array} codePoints The array of numeric code points.
  * @returns {String} The new Unicode string (UCS-2).
  */
	function ucs2encode(array) {
		return map(array, function (value) {
			var output = '';
			if (value > 0xFFFF) {
				value -= 0x10000;
				output += stringFromCharCode(value >>> 10 & 0x3FF | 0xD800);
				value = 0xDC00 | value & 0x3FF;
			}
			output += stringFromCharCode(value);
			return output;
		}).join('');
	}

	/**
  * Converts a basic code point into a digit/integer.
  * @see `digitToBasic()`
  * @private
  * @param {Number} codePoint The basic numeric code point value.
  * @returns {Number} The numeric value of a basic code point (for use in
  * representing integers) in the range `0` to `base - 1`, or `base` if
  * the code point does not represent a value.
  */
	function basicToDigit(codePoint) {
		if (codePoint - 48 < 10) {
			return codePoint - 22;
		}
		if (codePoint - 65 < 26) {
			return codePoint - 65;
		}
		if (codePoint - 97 < 26) {
			return codePoint - 97;
		}
		return base;
	}

	/**
  * Converts a digit/integer into a basic code point.
  * @see `basicToDigit()`
  * @private
  * @param {Number} digit The numeric value of a basic code point.
  * @returns {Number} The basic code point whose value (when used for
  * representing integers) is `digit`, which needs to be in the range
  * `0` to `base - 1`. If `flag` is non-zero, the uppercase form is
  * used; else, the lowercase form is used. The behavior is undefined
  * if `flag` is non-zero and `digit` has no uppercase form.
  */
	function digitToBasic(digit, flag) {
		//  0..25 map to ASCII a..z or A..Z
		// 26..35 map to ASCII 0..9
		return digit + 22 + 75 * (digit < 26) - ((flag != 0) << 5);
	}

	/**
  * Bias adaptation function as per section 3.4 of RFC 3492.
  * https://tools.ietf.org/html/rfc3492#section-3.4
  * @private
  */
	function adapt(delta, numPoints, firstTime) {
		var k = 0;
		delta = firstTime ? floor(delta / damp) : delta >> 1;
		delta += floor(delta / numPoints);
		for (; /* no initialization */delta > baseMinusTMin * tMax >> 1; k += base) {
			delta = floor(delta / baseMinusTMin);
		}
		return floor(k + (baseMinusTMin + 1) * delta / (delta + skew));
	}

	/**
  * Converts a Punycode string of ASCII-only symbols to a string of Unicode
  * symbols.
  * @memberOf punycode
  * @param {String} input The Punycode string of ASCII-only symbols.
  * @returns {String} The resulting string of Unicode symbols.
  */
	function decode(input) {
		// Don't use UCS-2
		var output = [],
		    inputLength = input.length,
		    out,
		    i = 0,
		    n = initialN,
		    bias = initialBias,
		    basic,
		    j,
		    index,
		    oldi,
		    w,
		    k,
		    digit,
		    t,

		/** Cached calculation results */
		baseMinusT;

		// Handle the basic code points: let `basic` be the number of input code
		// points before the last delimiter, or `0` if there is none, then copy
		// the first basic code points to the output.

		basic = input.lastIndexOf(delimiter);
		if (basic < 0) {
			basic = 0;
		}

		for (j = 0; j < basic; ++j) {
			// if it's not a basic code point
			if (input.charCodeAt(j) >= 0x80) {
				error('not-basic');
			}
			output.push(input.charCodeAt(j));
		}

		// Main decoding loop: start just after the last delimiter if any basic code
		// points were copied; start at the beginning otherwise.

		for (index = basic > 0 ? basic + 1 : 0; index < inputLength;) /* no final expression */{

			// `index` is the index of the next character to be consumed.
			// Decode a generalized variable-length integer into `delta`,
			// which gets added to `i`. The overflow checking is easier
			// if we increase `i` as we go, then subtract off its starting
			// value at the end to obtain `delta`.
			for (oldi = i, w = 1, k = base;; /* no condition */k += base) {

				if (index >= inputLength) {
					error('invalid-input');
				}

				digit = basicToDigit(input.charCodeAt(index++));

				if (digit >= base || digit > floor((maxInt - i) / w)) {
					error('overflow');
				}

				i += digit * w;
				t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;

				if (digit < t) {
					break;
				}

				baseMinusT = base - t;
				if (w > floor(maxInt / baseMinusT)) {
					error('overflow');
				}

				w *= baseMinusT;
			}

			out = output.length + 1;
			bias = adapt(i - oldi, out, oldi == 0);

			// `i` was supposed to wrap around from `out` to `0`,
			// incrementing `n` each time, so we'll fix that now:
			if (floor(i / out) > maxInt - n) {
				error('overflow');
			}

			n += floor(i / out);
			i %= out;

			// Insert `n` at position `i` of the output
			output.splice(i++, 0, n);
		}

		return ucs2encode(output);
	}

	/**
  * Converts a string of Unicode symbols (e.g. a domain name label) to a
  * Punycode string of ASCII-only symbols.
  * @memberOf punycode
  * @param {String} input The string of Unicode symbols.
  * @returns {String} The resulting Punycode string of ASCII-only symbols.
  */
	function encode(input) {
		var n,
		    delta,
		    handledCPCount,
		    basicLength,
		    bias,
		    j,
		    m,
		    q,
		    k,
		    t,
		    currentValue,
		    output = [],

		/** `inputLength` will hold the number of code points in `input`. */
		inputLength,

		/** Cached calculation results */
		handledCPCountPlusOne,
		    baseMinusT,
		    qMinusT;

		// Convert the input in UCS-2 to Unicode
		input = ucs2decode(input);

		// Cache the length
		inputLength = input.length;

		// Initialize the state
		n = initialN;
		delta = 0;
		bias = initialBias;

		// Handle the basic code points
		for (j = 0; j < inputLength; ++j) {
			currentValue = input[j];
			if (currentValue < 0x80) {
				output.push(stringFromCharCode(currentValue));
			}
		}

		handledCPCount = basicLength = output.length;

		// `handledCPCount` is the number of code points that have been handled;
		// `basicLength` is the number of basic code points.

		// Finish the basic string - if it is not empty - with a delimiter
		if (basicLength) {
			output.push(delimiter);
		}

		// Main encoding loop:
		while (handledCPCount < inputLength) {

			// All non-basic code points < n have been handled already. Find the next
			// larger one:
			for (m = maxInt, j = 0; j < inputLength; ++j) {
				currentValue = input[j];
				if (currentValue >= n && currentValue < m) {
					m = currentValue;
				}
			}

			// Increase `delta` enough to advance the decoder's <n,i> state to <m,0>,
			// but guard against overflow
			handledCPCountPlusOne = handledCPCount + 1;
			if (m - n > floor((maxInt - delta) / handledCPCountPlusOne)) {
				error('overflow');
			}

			delta += (m - n) * handledCPCountPlusOne;
			n = m;

			for (j = 0; j < inputLength; ++j) {
				currentValue = input[j];

				if (currentValue < n && ++delta > maxInt) {
					error('overflow');
				}

				if (currentValue == n) {
					// Represent delta as a generalized variable-length integer
					for (q = delta, k = base;; /* no condition */k += base) {
						t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
						if (q < t) {
							break;
						}
						qMinusT = q - t;
						baseMinusT = base - t;
						output.push(stringFromCharCode(digitToBasic(t + qMinusT % baseMinusT, 0)));
						q = floor(qMinusT / baseMinusT);
					}

					output.push(stringFromCharCode(digitToBasic(q, 0)));
					bias = adapt(delta, handledCPCountPlusOne, handledCPCount == basicLength);
					delta = 0;
					++handledCPCount;
				}
			}

			++delta;
			++n;
		}
		return output.join('');
	}

	/**
  * Converts a Punycode string representing a domain name or an email address
  * to Unicode. Only the Punycoded parts of the input will be converted, i.e.
  * it doesn't matter if you call it on a string that has already been
  * converted to Unicode.
  * @memberOf punycode
  * @param {String} input The Punycoded domain name or email address to
  * convert to Unicode.
  * @returns {String} The Unicode representation of the given Punycode
  * string.
  */
	function toUnicode(input) {
		return mapDomain(input, function (string) {
			return regexPunycode.test(string) ? decode(string.slice(4).toLowerCase()) : string;
		});
	}

	/**
  * Converts a Unicode string representing a domain name or an email address to
  * Punycode. Only the non-ASCII parts of the domain name will be converted,
  * i.e. it doesn't matter if you call it with a domain that's already in
  * ASCII.
  * @memberOf punycode
  * @param {String} input The domain name or email address to convert, as a
  * Unicode string.
  * @returns {String} The Punycode representation of the given domain name or
  * email address.
  */
	function toASCII(input) {
		return mapDomain(input, function (string) {
			return regexNonASCII.test(string) ? 'xn--' + encode(string) : string;
		});
	}

	/*--------------------------------------------------------------------------*/

	/** Define the public API */
	punycode = {
		/**
   * A string representing the current Punycode.js version number.
   * @memberOf punycode
   * @type String
   */
		'version': '1.4.1',
		/**
   * An object of methods to convert from JavaScript's internal character
   * representation (UCS-2) to Unicode code points, and back.
   * @see <https://mathiasbynens.be/notes/javascript-encoding>
   * @memberOf punycode
   * @type Object
   */
		'ucs2': {
			'decode': ucs2decode,
			'encode': ucs2encode
		},
		'decode': decode,
		'encode': encode,
		'toASCII': toASCII,
		'toUnicode': toUnicode
	};

	/** Expose `punycode` */
	// Some AMD build optimizers, like r.js, check for specific condition patterns
	// like the following:
	if (typeof define == 'function' && _typeof(define.amd) == 'object' && define.amd) {
		define('punycode', function () {
			return punycode;
		});
	} else if (freeExports && freeModule) {
		if (module.exports == freeExports) {
			// in Node.js, io.js, or RingoJS v0.8.0+
			freeModule.exports = punycode;
		} else {
			// in Narwhal or RingoJS v0.7.0-
			for (key in punycode) {
				punycode.hasOwnProperty(key) && (freeExports[key] = punycode[key]);
			}
		}
	} else {
		// in Rhino or a web browser
		root.punycode = punycode;
	}
})(undefined);

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}],4:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

// If obj.hasOwnProperty has been overridden, then calling
// obj.hasOwnProperty(prop) will break.
// See: https://github.com/joyent/node/issues/1707

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

module.exports = function (qs, sep, eq, options) {
  sep = sep || '&';
  eq = eq || '=';
  var obj = {};

  if (typeof qs !== 'string' || qs.length === 0) {
    return obj;
  }

  var regexp = /\+/g;
  qs = qs.split(sep);

  var maxKeys = 1000;
  if (options && typeof options.maxKeys === 'number') {
    maxKeys = options.maxKeys;
  }

  var len = qs.length;
  // maxKeys <= 0 means that we should not limit keys count
  if (maxKeys > 0 && len > maxKeys) {
    len = maxKeys;
  }

  for (var i = 0; i < len; ++i) {
    var x = qs[i].replace(regexp, '%20'),
        idx = x.indexOf(eq),
        kstr,
        vstr,
        k,
        v;

    if (idx >= 0) {
      kstr = x.substr(0, idx);
      vstr = x.substr(idx + 1);
    } else {
      kstr = x;
      vstr = '';
    }

    k = decodeURIComponent(kstr);
    v = decodeURIComponent(vstr);

    if (!hasOwnProperty(obj, k)) {
      obj[k] = v;
    } else if (isArray(obj[k])) {
      obj[k].push(v);
    } else {
      obj[k] = [obj[k], v];
    }
  }

  return obj;
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

},{}],5:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var stringifyPrimitive = function stringifyPrimitive(v) {
  switch (typeof v === 'undefined' ? 'undefined' : _typeof(v)) {
    case 'string':
      return v;

    case 'boolean':
      return v ? 'true' : 'false';

    case 'number':
      return isFinite(v) ? v : '';

    default:
      return '';
  }
};

module.exports = function (obj, sep, eq, name) {
  sep = sep || '&';
  eq = eq || '=';
  if (obj === null) {
    obj = undefined;
  }

  if ((typeof obj === 'undefined' ? 'undefined' : _typeof(obj)) === 'object') {
    return map(objectKeys(obj), function (k) {
      var ks = encodeURIComponent(stringifyPrimitive(k)) + eq;
      if (isArray(obj[k])) {
        return map(obj[k], function (v) {
          return ks + encodeURIComponent(stringifyPrimitive(v));
        }).join(sep);
      } else {
        return ks + encodeURIComponent(stringifyPrimitive(obj[k]));
      }
    }).join(sep);
  }

  if (!name) return '';
  return encodeURIComponent(stringifyPrimitive(name)) + eq + encodeURIComponent(stringifyPrimitive(obj));
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

function map(xs, f) {
  if (xs.map) return xs.map(f);
  var res = [];
  for (var i = 0; i < xs.length; i++) {
    res.push(f(xs[i], i));
  }
  return res;
}

var objectKeys = Object.keys || function (obj) {
  var res = [];
  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) res.push(key);
  }
  return res;
};

},{}],6:[function(require,module,exports){
'use strict';

exports.decode = exports.parse = require('./decode');
exports.encode = exports.stringify = require('./encode');

},{"./decode":4,"./encode":5}],7:[function(require,module,exports){
'use strict';

function RavenConfigError(message) {
  this.name = 'RavenConfigError';
  this.message = message;
}
RavenConfigError.prototype = new Error();
RavenConfigError.prototype.constructor = RavenConfigError;

module.exports = RavenConfigError;

},{}],8:[function(require,module,exports){
'use strict';

var utils = require('./utils');

var wrapMethod = function wrapMethod(console, level, callback) {
  var originalConsoleLevel = console[level];
  var originalConsole = console;

  if (!(level in console)) {
    return;
  }

  var sentryLevel = level === 'warn' ? 'warning' : level;

  console[level] = function () {
    var args = [].slice.call(arguments);

    var msg = utils.safeJoin(args, ' ');
    var data = { level: sentryLevel, logger: 'console', extra: { arguments: args } };

    if (level === 'assert') {
      if (args[0] === false) {
        // Default browsers message
        msg = 'Assertion failed: ' + (utils.safeJoin(args.slice(1), ' ') || 'console.assert');
        data.extra.arguments = args.slice(1);
        callback && callback(msg, data);
      }
    } else {
      callback && callback(msg, data);
    }

    // this fails for some browsers. :(
    if (originalConsoleLevel) {
      // IE9 doesn't allow calling apply on console functions directly
      // See: https://stackoverflow.com/questions/5472938/does-ie9-support-console-log-and-is-it-a-real-function#answer-5473193
      Function.prototype.apply.call(originalConsoleLevel, originalConsole, args);
    }
  };
};

module.exports = {
  wrapMethod: wrapMethod
};

},{"./utils":11}],9:[function(require,module,exports){
(function (global){
'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

/*global XDomainRequest:false */

var TraceKit = require('../vendor/TraceKit/tracekit');
var stringify = require('../vendor/json-stringify-safe/stringify');
var md5 = require('../vendor/md5/md5');
var RavenConfigError = require('./configError');

var utils = require('./utils');
var isErrorEvent = utils.isErrorEvent;
var isDOMError = utils.isDOMError;
var isDOMException = utils.isDOMException;
var isError = utils.isError;
var isObject = utils.isObject;
var isPlainObject = utils.isPlainObject;
var isUndefined = utils.isUndefined;
var isFunction = utils.isFunction;
var isString = utils.isString;
var isArray = utils.isArray;
var isEmptyObject = utils.isEmptyObject;
var each = utils.each;
var objectMerge = utils.objectMerge;
var truncate = utils.truncate;
var objectFrozen = utils.objectFrozen;
var hasKey = utils.hasKey;
var joinRegExp = utils.joinRegExp;
var urlencode = utils.urlencode;
var uuid4 = utils.uuid4;
var htmlTreeAsString = utils.htmlTreeAsString;
var isSameException = utils.isSameException;
var isSameStacktrace = utils.isSameStacktrace;
var parseUrl = utils.parseUrl;
var fill = utils.fill;
var supportsFetch = utils.supportsFetch;
var supportsReferrerPolicy = utils.supportsReferrerPolicy;
var serializeKeysForMessage = utils.serializeKeysForMessage;
var serializeException = utils.serializeException;
var sanitize = utils.sanitize;

var wrapConsoleMethod = require('./console').wrapMethod;

var dsnKeys = 'source protocol user pass host port path'.split(' '),
    dsnPattern = /^(?:(\w+):)?\/\/(?:(\w+)(:\w+)?@)?([\w\.-]+)(?::(\d+))?(\/.*)/;

function now() {
  return +new Date();
}

// This is to be defensive in environments where window does not exist (see https://github.com/getsentry/raven-js/pull/785)
var _window = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};
var _document = _window.document;
var _navigator = _window.navigator;

function keepOriginalCallback(original, callback) {
  return isFunction(callback) ? function (data) {
    return callback(data, original);
  } : callback;
}

// First, check for JSON support
// If there is no JSON, we no-op the core features of Raven
// since JSON is required to encode the payload
function Raven() {
  this._hasJSON = !!((typeof JSON === 'undefined' ? 'undefined' : _typeof(JSON)) === 'object' && JSON.stringify);
  // Raven can run in contexts where there's no document (react-native)
  this._hasDocument = !isUndefined(_document);
  this._hasNavigator = !isUndefined(_navigator);
  this._lastCapturedException = null;
  this._lastData = null;
  this._lastEventId = null;
  this._globalServer = null;
  this._globalKey = null;
  this._globalProject = null;
  this._globalContext = {};
  this._globalOptions = {
    // SENTRY_RELEASE can be injected by https://github.com/getsentry/sentry-webpack-plugin
    release: _window.SENTRY_RELEASE && _window.SENTRY_RELEASE.id,
    logger: 'javascript',
    ignoreErrors: [],
    ignoreUrls: [],
    whitelistUrls: [],
    includePaths: [],
    headers: null,
    collectWindowErrors: true,
    captureUnhandledRejections: true,
    maxMessageLength: 0,
    // By default, truncates URL values to 250 chars
    maxUrlLength: 250,
    stackTraceLimit: 50,
    autoBreadcrumbs: true,
    instrument: true,
    sampleRate: 1,
    sanitizeKeys: []
  };
  this._fetchDefaults = {
    method: 'POST',
    // Despite all stars in the sky saying that Edge supports old draft syntax, aka 'never', 'always', 'origin' and 'default
    // https://caniuse.com/#feat=referrer-policy
    // It doesn't. And it throw exception instead of ignoring this parameter...
    // REF: https://github.com/getsentry/raven-js/issues/1233
    referrerPolicy: supportsReferrerPolicy() ? 'origin' : ''
  };
  this._ignoreOnError = 0;
  this._isRavenInstalled = false;
  this._originalErrorStackTraceLimit = Error.stackTraceLimit;
  // capture references to window.console *and* all its methods first
  // before the console plugin has a chance to monkey patch
  this._originalConsole = _window.console || {};
  this._originalConsoleMethods = {};
  this._plugins = [];
  this._startTime = now();
  this._wrappedBuiltIns = [];
  this._breadcrumbs = [];
  this._lastCapturedEvent = null;
  this._keypressTimeout;
  this._location = _window.location;
  this._lastHref = this._location && this._location.href;
  this._resetBackoff();

  // eslint-disable-next-line guard-for-in
  for (var method in this._originalConsole) {
    this._originalConsoleMethods[method] = this._originalConsole[method];
  }
}

/*
 * The core Raven singleton
 *
 * @this {Raven}
 */

Raven.prototype = {
  // Hardcode version string so that raven source can be loaded directly via
  // webpack (using a build step causes webpack #1617). Grunt verifies that
  // this value matches package.json during build.
  //   See: https://github.com/getsentry/raven-js/issues/465
  VERSION: '3.27.2',

  debug: false,

  TraceKit: TraceKit, // alias to TraceKit

  /*
     * Configure Raven with a DSN and extra options
     *
     * @param {string} dsn The public Sentry DSN
     * @param {object} options Set of global options [optional]
     * @return {Raven}
     */
  config: function config(dsn, options) {
    var self = this;

    if (self._globalServer) {
      this._logDebug('error', 'Error: Raven has already been configured');
      return self;
    }
    if (!dsn) return self;

    var globalOptions = self._globalOptions;

    // merge in options
    if (options) {
      each(options, function (key, value) {
        // tags and extra are special and need to be put into context
        if (key === 'tags' || key === 'extra' || key === 'user') {
          self._globalContext[key] = value;
        } else {
          globalOptions[key] = value;
        }
      });
    }

    self.setDSN(dsn);

    // "Script error." is hard coded into browsers for errors that it can't read.
    // this is the result of a script being pulled in from an external domain and CORS.
    globalOptions.ignoreErrors.push(/^Script error\.?$/);
    globalOptions.ignoreErrors.push(/^Javascript error: Script error\.? on line 0$/);

    // join regexp rules into one big rule
    globalOptions.ignoreErrors = joinRegExp(globalOptions.ignoreErrors);
    globalOptions.ignoreUrls = globalOptions.ignoreUrls.length ? joinRegExp(globalOptions.ignoreUrls) : false;
    globalOptions.whitelistUrls = globalOptions.whitelistUrls.length ? joinRegExp(globalOptions.whitelistUrls) : false;
    globalOptions.includePaths = joinRegExp(globalOptions.includePaths);
    globalOptions.maxBreadcrumbs = Math.max(0, Math.min(globalOptions.maxBreadcrumbs || 100, 100)); // default and hard limit is 100

    var autoBreadcrumbDefaults = {
      xhr: true,
      console: true,
      dom: true,
      location: true,
      sentry: true
    };

    var autoBreadcrumbs = globalOptions.autoBreadcrumbs;
    if ({}.toString.call(autoBreadcrumbs) === '[object Object]') {
      autoBreadcrumbs = objectMerge(autoBreadcrumbDefaults, autoBreadcrumbs);
    } else if (autoBreadcrumbs !== false) {
      autoBreadcrumbs = autoBreadcrumbDefaults;
    }
    globalOptions.autoBreadcrumbs = autoBreadcrumbs;

    var instrumentDefaults = {
      tryCatch: true
    };

    var instrument = globalOptions.instrument;
    if ({}.toString.call(instrument) === '[object Object]') {
      instrument = objectMerge(instrumentDefaults, instrument);
    } else if (instrument !== false) {
      instrument = instrumentDefaults;
    }
    globalOptions.instrument = instrument;

    TraceKit.collectWindowErrors = !!globalOptions.collectWindowErrors;

    // return for chaining
    return self;
  },

  /*
     * Installs a global window.onerror error handler
     * to capture and report uncaught exceptions.
     * At this point, install() is required to be called due
     * to the way TraceKit is set up.
     *
     * @return {Raven}
     */
  install: function install() {
    var self = this;
    if (self.isSetup() && !self._isRavenInstalled) {
      TraceKit.report.subscribe(function () {
        self._handleOnErrorStackInfo.apply(self, arguments);
      });

      if (self._globalOptions.captureUnhandledRejections) {
        self._attachPromiseRejectionHandler();
      }

      self._patchFunctionToString();

      if (self._globalOptions.instrument && self._globalOptions.instrument.tryCatch) {
        self._instrumentTryCatch();
      }

      if (self._globalOptions.autoBreadcrumbs) self._instrumentBreadcrumbs();

      // Install all of the plugins
      self._drainPlugins();

      self._isRavenInstalled = true;
    }

    Error.stackTraceLimit = self._globalOptions.stackTraceLimit;
    return this;
  },

  /*
     * Set the DSN (can be called multiple time unlike config)
     *
     * @param {string} dsn The public Sentry DSN
     */
  setDSN: function setDSN(dsn) {
    var self = this,
        uri = self._parseDSN(dsn),
        lastSlash = uri.path.lastIndexOf('/'),
        path = uri.path.substr(1, lastSlash);

    self._dsn = dsn;
    self._globalKey = uri.user;
    self._globalSecret = uri.pass && uri.pass.substr(1);
    self._globalProject = uri.path.substr(lastSlash + 1);

    self._globalServer = self._getGlobalServer(uri);

    self._globalEndpoint = self._globalServer + '/' + path + 'api/' + self._globalProject + '/store/';

    // Reset backoff state since we may be pointing at a
    // new project/server
    this._resetBackoff();
  },

  /*
     * Wrap code within a context so Raven can capture errors
     * reliably across domains that is executed immediately.
     *
     * @param {object} options A specific set of options for this context [optional]
     * @param {function} func The callback to be immediately executed within the context
     * @param {array} args An array of arguments to be called with the callback [optional]
     */
  context: function context(options, func, args) {
    if (isFunction(options)) {
      args = func || [];
      func = options;
      options = {};
    }

    return this.wrap(options, func).apply(this, args);
  },

  /*
     * Wrap code within a context and returns back a new function to be executed
     *
     * @param {object} options A specific set of options for this context [optional]
     * @param {function} func The function to be wrapped in a new context
     * @param {function} _before A function to call before the try/catch wrapper [optional, private]
     * @return {function} The newly wrapped functions with a context
     */
  wrap: function wrap(options, func, _before) {
    var self = this;
    // 1 argument has been passed, and it's not a function
    // so just return it
    if (isUndefined(func) && !isFunction(options)) {
      return options;
    }

    // options is optional
    if (isFunction(options)) {
      func = options;
      options = undefined;
    }

    // At this point, we've passed along 2 arguments, and the second one
    // is not a function either, so we'll just return the second argument.
    if (!isFunction(func)) {
      return func;
    }

    // We don't wanna wrap it twice!
    try {
      if (func.__raven__) {
        return func;
      }

      // If this has already been wrapped in the past, return that
      if (func.__raven_wrapper__) {
        return func.__raven_wrapper__;
      }
    } catch (e) {
      // Just accessing custom props in some Selenium environments
      // can cause a "Permission denied" exception (see raven-js#495).
      // Bail on wrapping and return the function as-is (defers to window.onerror).
      return func;
    }

    function wrapped() {
      var args = [],
          i = arguments.length,
          deep = !options || options && options.deep !== false;

      if (_before && isFunction(_before)) {
        _before.apply(this, arguments);
      }

      // Recursively wrap all of a function's arguments that are
      // functions themselves.
      while (i--) {
        args[i] = deep ? self.wrap(options, arguments[i]) : arguments[i];
      }try {
        // Attempt to invoke user-land function
        // NOTE: If you are a Sentry user, and you are seeing this stack frame, it
        //       means Raven caught an error invoking your application code. This is
        //       expected behavior and NOT indicative of a bug with Raven.js.
        return func.apply(this, args);
      } catch (e) {
        self._ignoreNextOnError();
        self.captureException(e, options);
        throw e;
      }
    }

    // copy over properties of the old function
    for (var property in func) {
      if (hasKey(func, property)) {
        wrapped[property] = func[property];
      }
    }
    wrapped.prototype = func.prototype;

    func.__raven_wrapper__ = wrapped;
    // Signal that this function has been wrapped/filled already
    // for both debugging and to prevent it to being wrapped/filled twice
    wrapped.__raven__ = true;
    wrapped.__orig__ = func;

    return wrapped;
  },

  /**
   * Uninstalls the global error handler.
   *
   * @return {Raven}
   */
  uninstall: function uninstall() {
    TraceKit.report.uninstall();

    this._detachPromiseRejectionHandler();
    this._unpatchFunctionToString();
    this._restoreBuiltIns();
    this._restoreConsole();

    Error.stackTraceLimit = this._originalErrorStackTraceLimit;
    this._isRavenInstalled = false;

    return this;
  },

  /**
   * Callback used for `unhandledrejection` event
   *
   * @param {PromiseRejectionEvent} event An object containing
   *   promise: the Promise that was rejected
   *   reason: the value with which the Promise was rejected
   * @return void
   */
  _promiseRejectionHandler: function _promiseRejectionHandler(event) {
    this._logDebug('debug', 'Raven caught unhandled promise rejection:', event);
    this.captureException(event.reason, {
      mechanism: {
        type: 'onunhandledrejection',
        handled: false
      }
    });
  },

  /**
   * Installs the global promise rejection handler.
   *
   * @return {raven}
   */
  _attachPromiseRejectionHandler: function _attachPromiseRejectionHandler() {
    this._promiseRejectionHandler = this._promiseRejectionHandler.bind(this);
    _window.addEventListener && _window.addEventListener('unhandledrejection', this._promiseRejectionHandler);
    return this;
  },

  /**
   * Uninstalls the global promise rejection handler.
   *
   * @return {raven}
   */
  _detachPromiseRejectionHandler: function _detachPromiseRejectionHandler() {
    _window.removeEventListener && _window.removeEventListener('unhandledrejection', this._promiseRejectionHandler);
    return this;
  },

  /**
   * Manually capture an exception and send it over to Sentry
   *
   * @param {error} ex An exception to be logged
   * @param {object} options A specific set of options for this error [optional]
   * @return {Raven}
   */
  captureException: function captureException(ex, options) {
    options = objectMerge({ trimHeadFrames: 0 }, options ? options : {});

    if (isErrorEvent(ex) && ex.error) {
      // If it is an ErrorEvent with `error` property, extract it to get actual Error
      ex = ex.error;
    } else if (isDOMError(ex) || isDOMException(ex)) {
      // If it is a DOMError or DOMException (which are legacy APIs, but still supported in some browsers)
      // then we just extract the name and message, as they don't provide anything else
      // https://developer.mozilla.org/en-US/docs/Web/API/DOMError
      // https://developer.mozilla.org/en-US/docs/Web/API/DOMException
      var name = ex.name || (isDOMError(ex) ? 'DOMError' : 'DOMException');
      var message = ex.message ? name + ': ' + ex.message : name;

      return this.captureMessage(message, objectMerge(options, {
        // neither DOMError or DOMException provide stack trace and we most likely wont get it this way as well
        // but it's barely any overhead so we may at least try
        stacktrace: true,
        trimHeadFrames: options.trimHeadFrames + 1
      }));
    } else if (isError(ex)) {
      // we have a real Error object
      ex = ex;
    } else if (isPlainObject(ex)) {
      // If it is plain Object, serialize it manually and extract options
      // This will allow us to group events based on top-level keys
      // which is much better than creating new group when any key/value change
      options = this._getCaptureExceptionOptionsFromPlainObject(options, ex);
      ex = new Error(options.message);
    } else {
      // If none of previous checks were valid, then it means that
      // it's not a DOMError/DOMException
      // it's not a plain Object
      // it's not a valid ErrorEvent (one with an error property)
      // it's not an Error
      // So bail out and capture it as a simple message:
      return this.captureMessage(ex, objectMerge(options, {
        stacktrace: true, // if we fall back to captureMessage, default to attempting a new trace
        trimHeadFrames: options.trimHeadFrames + 1
      }));
    }

    // Store the raw exception object for potential debugging and introspection
    this._lastCapturedException = ex;

    // TraceKit.report will re-raise any exception passed to it,
    // which means you have to wrap it in try/catch. Instead, we
    // can wrap it here and only re-raise if TraceKit.report
    // raises an exception different from the one we asked to
    // report on.
    try {
      var stack = TraceKit.computeStackTrace(ex);
      this._handleStackInfo(stack, options);
    } catch (ex1) {
      if (ex !== ex1) {
        throw ex1;
      }
    }

    return this;
  },

  _getCaptureExceptionOptionsFromPlainObject: function _getCaptureExceptionOptionsFromPlainObject(currentOptions, ex) {
    var exKeys = Object.keys(ex).sort();
    var options = objectMerge(currentOptions, {
      message: 'Non-Error exception captured with keys: ' + serializeKeysForMessage(exKeys),
      fingerprint: [md5(exKeys)],
      extra: currentOptions.extra || {}
    });
    options.extra.__serialized__ = serializeException(ex);

    return options;
  },

  /*
     * Manually send a message to Sentry
     *
     * @param {string} msg A plain message to be captured in Sentry
     * @param {object} options A specific set of options for this message [optional]
     * @return {Raven}
     */
  captureMessage: function captureMessage(msg, options) {
    // config() automagically converts ignoreErrors from a list to a RegExp so we need to test for an
    // early call; we'll error on the side of logging anything called before configuration since it's
    // probably something you should see:
    if (!!this._globalOptions.ignoreErrors.test && this._globalOptions.ignoreErrors.test(msg)) {
      return;
    }

    options = options || {};
    msg = msg + ''; // Make sure it's actually a string

    var data = objectMerge({
      message: msg
    }, options);

    var ex;
    // Generate a "synthetic" stack trace from this point.
    // NOTE: If you are a Sentry user, and you are seeing this stack frame, it is NOT indicative
    //       of a bug with Raven.js. Sentry generates synthetic traces either by configuration,
    //       or if it catches a thrown object without a "stack" property.
    try {
      throw new Error(msg);
    } catch (ex1) {
      ex = ex1;
    }

    // null exception name so `Error` isn't prefixed to msg
    ex.name = null;
    var stack = TraceKit.computeStackTrace(ex);

    // stack[0] is `throw new Error(msg)` call itself, we are interested in the frame that was just before that, stack[1]
    var initialCall = isArray(stack.stack) && stack.stack[1];

    // if stack[1] is `Raven.captureException`, it means that someone passed a string to it and we redirected that call
    // to be handled by `captureMessage`, thus `initialCall` is the 3rd one, not 2nd
    // initialCall => captureException(string) => captureMessage(string)
    if (initialCall && initialCall.func === 'Raven.captureException') {
      initialCall = stack.stack[2];
    }

    var fileurl = initialCall && initialCall.url || '';

    if (!!this._globalOptions.ignoreUrls.test && this._globalOptions.ignoreUrls.test(fileurl)) {
      return;
    }

    if (!!this._globalOptions.whitelistUrls.test && !this._globalOptions.whitelistUrls.test(fileurl)) {
      return;
    }

    // Always attempt to get stacktrace if message is empty.
    // It's the only way to provide any helpful information to the user.
    if (this._globalOptions.stacktrace || options.stacktrace || data.message === '') {
      // fingerprint on msg, not stack trace (legacy behavior, could be revisited)
      data.fingerprint = data.fingerprint == null ? msg : data.fingerprint;

      options = objectMerge({
        trimHeadFrames: 0
      }, options);
      // Since we know this is a synthetic trace, the top frame (this function call)
      // MUST be from Raven.js, so mark it for trimming
      // We add to the trim counter so that callers can choose to trim extra frames, such
      // as utility functions.
      options.trimHeadFrames += 1;

      var frames = this._prepareFrames(stack, options);
      data.stacktrace = {
        // Sentry expects frames oldest to newest
        frames: frames.reverse()
      };
    }

    // Make sure that fingerprint is always wrapped in an array
    if (data.fingerprint) {
      data.fingerprint = isArray(data.fingerprint) ? data.fingerprint : [data.fingerprint];
    }

    // Fire away!
    this._send(data);

    return this;
  },

  captureBreadcrumb: function captureBreadcrumb(obj) {
    var crumb = objectMerge({
      timestamp: now() / 1000
    }, obj);

    if (isFunction(this._globalOptions.breadcrumbCallback)) {
      var result = this._globalOptions.breadcrumbCallback(crumb);

      if (isObject(result) && !isEmptyObject(result)) {
        crumb = result;
      } else if (result === false) {
        return this;
      }
    }

    this._breadcrumbs.push(crumb);
    if (this._breadcrumbs.length > this._globalOptions.maxBreadcrumbs) {
      this._breadcrumbs.shift();
    }
    return this;
  },

  addPlugin: function addPlugin(plugin /*arg1, arg2, ... argN*/) {
    var pluginArgs = [].slice.call(arguments, 1);

    this._plugins.push([plugin, pluginArgs]);
    if (this._isRavenInstalled) {
      this._drainPlugins();
    }

    return this;
  },

  /*
     * Set/clear a user to be sent along with the payload.
     *
     * @param {object} user An object representing user data [optional]
     * @return {Raven}
     */
  setUserContext: function setUserContext(user) {
    // Intentionally do not merge here since that's an unexpected behavior.
    this._globalContext.user = user;

    return this;
  },

  /*
     * Merge extra attributes to be sent along with the payload.
     *
     * @param {object} extra An object representing extra data [optional]
     * @return {Raven}
     */
  setExtraContext: function setExtraContext(extra) {
    this._mergeContext('extra', extra);

    return this;
  },

  /*
     * Merge tags to be sent along with the payload.
     *
     * @param {object} tags An object representing tags [optional]
     * @return {Raven}
     */
  setTagsContext: function setTagsContext(tags) {
    this._mergeContext('tags', tags);

    return this;
  },

  /*
     * Clear all of the context.
     *
     * @return {Raven}
     */
  clearContext: function clearContext() {
    this._globalContext = {};

    return this;
  },

  /*
     * Get a copy of the current context. This cannot be mutated.
     *
     * @return {object} copy of context
     */
  getContext: function getContext() {
    // lol javascript
    return JSON.parse(stringify(this._globalContext));
  },

  /*
     * Set environment of application
     *
     * @param {string} environment Typically something like 'production'.
     * @return {Raven}
     */
  setEnvironment: function setEnvironment(environment) {
    this._globalOptions.environment = environment;

    return this;
  },

  /*
     * Set release version of application
     *
     * @param {string} release Typically something like a git SHA to identify version
     * @return {Raven}
     */
  setRelease: function setRelease(release) {
    this._globalOptions.release = release;

    return this;
  },

  /*
     * Set the dataCallback option
     *
     * @param {function} callback The callback to run which allows the
     *                            data blob to be mutated before sending
     * @return {Raven}
     */
  setDataCallback: function setDataCallback(callback) {
    var original = this._globalOptions.dataCallback;
    this._globalOptions.dataCallback = keepOriginalCallback(original, callback);
    return this;
  },

  /*
     * Set the breadcrumbCallback option
     *
     * @param {function} callback The callback to run which allows filtering
     *                            or mutating breadcrumbs
     * @return {Raven}
     */
  setBreadcrumbCallback: function setBreadcrumbCallback(callback) {
    var original = this._globalOptions.breadcrumbCallback;
    this._globalOptions.breadcrumbCallback = keepOriginalCallback(original, callback);
    return this;
  },

  /*
     * Set the shouldSendCallback option
     *
     * @param {function} callback The callback to run which allows
     *                            introspecting the blob before sending
     * @return {Raven}
     */
  setShouldSendCallback: function setShouldSendCallback(callback) {
    var original = this._globalOptions.shouldSendCallback;
    this._globalOptions.shouldSendCallback = keepOriginalCallback(original, callback);
    return this;
  },

  /**
   * Override the default HTTP transport mechanism that transmits data
   * to the Sentry server.
   *
   * @param {function} transport Function invoked instead of the default
   *                             `makeRequest` handler.
   *
   * @return {Raven}
   */
  setTransport: function setTransport(transport) {
    this._globalOptions.transport = transport;

    return this;
  },

  /*
     * Get the latest raw exception that was captured by Raven.
     *
     * @return {error}
     */
  lastException: function lastException() {
    return this._lastCapturedException;
  },

  /*
     * Get the last event id
     *
     * @return {string}
     */
  lastEventId: function lastEventId() {
    return this._lastEventId;
  },

  /*
     * Determine if Raven is setup and ready to go.
     *
     * @return {boolean}
     */
  isSetup: function isSetup() {
    if (!this._hasJSON) return false; // needs JSON support
    if (!this._globalServer) {
      if (!this.ravenNotConfiguredError) {
        this.ravenNotConfiguredError = true;
        this._logDebug('error', 'Error: Raven has not been configured.');
      }
      return false;
    }
    return true;
  },

  afterLoad: function afterLoad() {
    // TODO: remove window dependence?

    // Attempt to initialize Raven on load
    var RavenConfig = _window.RavenConfig;
    if (RavenConfig) {
      this.config(RavenConfig.dsn, RavenConfig.config).install();
    }
  },

  showReportDialog: function showReportDialog(options) {
    if (!_document // doesn't work without a document (React native)
    ) return;

    options = objectMerge({
      eventId: this.lastEventId(),
      dsn: this._dsn,
      user: this._globalContext.user || {}
    }, options);

    if (!options.eventId) {
      throw new RavenConfigError('Missing eventId');
    }

    if (!options.dsn) {
      throw new RavenConfigError('Missing DSN');
    }

    var encode = encodeURIComponent;
    var encodedOptions = [];

    for (var key in options) {
      if (key === 'user') {
        var user = options.user;
        if (user.name) encodedOptions.push('name=' + encode(user.name));
        if (user.email) encodedOptions.push('email=' + encode(user.email));
      } else {
        encodedOptions.push(encode(key) + '=' + encode(options[key]));
      }
    }
    var globalServer = this._getGlobalServer(this._parseDSN(options.dsn));

    var script = _document.createElement('script');
    script.async = true;
    script.src = globalServer + '/api/embed/error-page/?' + encodedOptions.join('&');
    (_document.head || _document.body).appendChild(script);
  },

  /**** Private functions ****/
  _ignoreNextOnError: function _ignoreNextOnError() {
    var self = this;
    this._ignoreOnError += 1;
    setTimeout(function () {
      // onerror should trigger before setTimeout
      self._ignoreOnError -= 1;
    });
  },

  _triggerEvent: function _triggerEvent(eventType, options) {
    // NOTE: `event` is a native browser thing, so let's avoid conflicting wiht it
    var evt, key;

    if (!this._hasDocument) return;

    options = options || {};

    eventType = 'raven' + eventType.substr(0, 1).toUpperCase() + eventType.substr(1);

    if (_document.createEvent) {
      evt = _document.createEvent('HTMLEvents');
      evt.initEvent(eventType, true, true);
    } else {
      evt = _document.createEventObject();
      evt.eventType = eventType;
    }

    for (key in options) {
      if (hasKey(options, key)) {
        evt[key] = options[key];
      }
    }if (_document.createEvent) {
      // IE9 if standards
      _document.dispatchEvent(evt);
    } else {
      // IE8 regardless of Quirks or Standards
      // IE9 if quirks
      try {
        _document.fireEvent('on' + evt.eventType.toLowerCase(), evt);
      } catch (e) {
        // Do nothing
      }
    }
  },

  /**
   * Wraps addEventListener to capture UI breadcrumbs
   * @param evtName the event name (e.g. "click")
   * @returns {Function}
   * @private
   */
  _breadcrumbEventHandler: function _breadcrumbEventHandler(evtName) {
    var self = this;
    return function (evt) {
      // reset keypress timeout; e.g. triggering a 'click' after
      // a 'keypress' will reset the keypress debounce so that a new
      // set of keypresses can be recorded
      self._keypressTimeout = null;

      // It's possible this handler might trigger multiple times for the same
      // event (e.g. event propagation through node ancestors). Ignore if we've
      // already captured the event.
      if (self._lastCapturedEvent === evt) return;

      self._lastCapturedEvent = evt;

      // try/catch both:
      // - accessing evt.target (see getsentry/raven-js#838, #768)
      // - `htmlTreeAsString` because it's complex, and just accessing the DOM incorrectly
      //   can throw an exception in some circumstances.
      var target;
      try {
        target = htmlTreeAsString(evt.target);
      } catch (e) {
        target = '<unknown>';
      }

      self.captureBreadcrumb({
        category: 'ui.' + evtName, // e.g. ui.click, ui.input
        message: target
      });
    };
  },

  /**
   * Wraps addEventListener to capture keypress UI events
   * @returns {Function}
   * @private
   */
  _keypressEventHandler: function _keypressEventHandler() {
    var self = this,
        debounceDuration = 1000; // milliseconds

    // TODO: if somehow user switches keypress target before
    //       debounce timeout is triggered, we will only capture
    //       a single breadcrumb from the FIRST target (acceptable?)
    return function (evt) {
      var target;
      try {
        target = evt.target;
      } catch (e) {
        // just accessing event properties can throw an exception in some rare circumstances
        // see: https://github.com/getsentry/raven-js/issues/838
        return;
      }
      var tagName = target && target.tagName;

      // only consider keypress events on actual input elements
      // this will disregard keypresses targeting body (e.g. tabbing
      // through elements, hotkeys, etc)
      if (!tagName || tagName !== 'INPUT' && tagName !== 'TEXTAREA' && !target.isContentEditable) return;

      // record first keypress in a series, but ignore subsequent
      // keypresses until debounce clears
      var timeout = self._keypressTimeout;
      if (!timeout) {
        self._breadcrumbEventHandler('input')(evt);
      }
      clearTimeout(timeout);
      self._keypressTimeout = setTimeout(function () {
        self._keypressTimeout = null;
      }, debounceDuration);
    };
  },

  /**
   * Captures a breadcrumb of type "navigation", normalizing input URLs
   * @param to the originating URL
   * @param from the target URL
   * @private
   */
  _captureUrlChange: function _captureUrlChange(from, to) {
    var parsedLoc = parseUrl(this._location.href);
    var parsedTo = parseUrl(to);
    var parsedFrom = parseUrl(from);

    // because onpopstate only tells you the "new" (to) value of location.href, and
    // not the previous (from) value, we need to track the value of the current URL
    // state ourselves
    this._lastHref = to;

    // Use only the path component of the URL if the URL matches the current
    // document (almost all the time when using pushState)
    if (parsedLoc.protocol === parsedTo.protocol && parsedLoc.host === parsedTo.host) to = parsedTo.relative;
    if (parsedLoc.protocol === parsedFrom.protocol && parsedLoc.host === parsedFrom.host) from = parsedFrom.relative;

    this.captureBreadcrumb({
      category: 'navigation',
      data: {
        to: to,
        from: from
      }
    });
  },

  _patchFunctionToString: function _patchFunctionToString() {
    var self = this;
    self._originalFunctionToString = Function.prototype.toString;
    // eslint-disable-next-line no-extend-native
    Function.prototype.toString = function () {
      if (typeof this === 'function' && this.__raven__) {
        return self._originalFunctionToString.apply(this.__orig__, arguments);
      }
      return self._originalFunctionToString.apply(this, arguments);
    };
  },

  _unpatchFunctionToString: function _unpatchFunctionToString() {
    if (this._originalFunctionToString) {
      // eslint-disable-next-line no-extend-native
      Function.prototype.toString = this._originalFunctionToString;
    }
  },

  /**
   * Wrap timer functions and event targets to catch errors and provide
   * better metadata.
   */
  _instrumentTryCatch: function _instrumentTryCatch() {
    var self = this;

    var wrappedBuiltIns = self._wrappedBuiltIns;

    function wrapTimeFn(orig) {
      return function (fn, t) {
        // preserve arity
        // Make a copy of the arguments to prevent deoptimization
        // https://github.com/petkaantonov/bluebird/wiki/Optimization-killers#32-leaking-arguments
        var args = new Array(arguments.length);
        for (var i = 0; i < args.length; ++i) {
          args[i] = arguments[i];
        }
        var originalCallback = args[0];
        if (isFunction(originalCallback)) {
          args[0] = self.wrap({
            mechanism: {
              type: 'instrument',
              data: { function: orig.name || '<anonymous>' }
            }
          }, originalCallback);
        }

        // IE < 9 doesn't support .call/.apply on setInterval/setTimeout, but it
        // also supports only two arguments and doesn't care what this is, so we
        // can just call the original function directly.
        if (orig.apply) {
          return orig.apply(this, args);
        } else {
          return orig(args[0], args[1]);
        }
      };
    }

    var autoBreadcrumbs = this._globalOptions.autoBreadcrumbs;

    function wrapEventTarget(global) {
      var proto = _window[global] && _window[global].prototype;
      if (proto && proto.hasOwnProperty && proto.hasOwnProperty('addEventListener')) {
        fill(proto, 'addEventListener', function (orig) {
          return function (evtName, fn, capture, secure) {
            // preserve arity
            try {
              if (fn && fn.handleEvent) {
                fn.handleEvent = self.wrap({
                  mechanism: {
                    type: 'instrument',
                    data: {
                      target: global,
                      function: 'handleEvent',
                      handler: fn && fn.name || '<anonymous>'
                    }
                  }
                }, fn.handleEvent);
              }
            } catch (err) {}
            // can sometimes get 'Permission denied to access property "handle Event'


            // More breadcrumb DOM capture ... done here and not in `_instrumentBreadcrumbs`
            // so that we don't have more than one wrapper function
            var before, clickHandler, keypressHandler;

            if (autoBreadcrumbs && autoBreadcrumbs.dom && (global === 'EventTarget' || global === 'Node')) {
              // NOTE: generating multiple handlers per addEventListener invocation, should
              //       revisit and verify we can just use one (almost certainly)
              clickHandler = self._breadcrumbEventHandler('click');
              keypressHandler = self._keypressEventHandler();
              before = function before(evt) {
                // need to intercept every DOM event in `before` argument, in case that
                // same wrapped method is re-used for different events (e.g. mousemove THEN click)
                // see #724
                if (!evt) return;

                var eventType;
                try {
                  eventType = evt.type;
                } catch (e) {
                  // just accessing event properties can throw an exception in some rare circumstances
                  // see: https://github.com/getsentry/raven-js/issues/838
                  return;
                }
                if (eventType === 'click') return clickHandler(evt);else if (eventType === 'keypress') return keypressHandler(evt);
              };
            }
            return orig.call(this, evtName, self.wrap({
              mechanism: {
                type: 'instrument',
                data: {
                  target: global,
                  function: 'addEventListener',
                  handler: fn && fn.name || '<anonymous>'
                }
              }
            }, fn, before), capture, secure);
          };
        }, wrappedBuiltIns);
        fill(proto, 'removeEventListener', function (orig) {
          return function (evt, fn, capture, secure) {
            try {
              fn = fn && (fn.__raven_wrapper__ ? fn.__raven_wrapper__ : fn);
            } catch (e) {
              // ignore, accessing __raven_wrapper__ will throw in some Selenium environments
            }
            return orig.call(this, evt, fn, capture, secure);
          };
        }, wrappedBuiltIns);
      }
    }

    fill(_window, 'setTimeout', wrapTimeFn, wrappedBuiltIns);
    fill(_window, 'setInterval', wrapTimeFn, wrappedBuiltIns);
    if (_window.requestAnimationFrame) {
      fill(_window, 'requestAnimationFrame', function (orig) {
        return function (cb) {
          return orig(self.wrap({
            mechanism: {
              type: 'instrument',
              data: {
                function: 'requestAnimationFrame',
                handler: orig && orig.name || '<anonymous>'
              }
            }
          }, cb));
        };
      }, wrappedBuiltIns);
    }

    // event targets borrowed from bugsnag-js:
    // https://github.com/bugsnag/bugsnag-js/blob/master/src/bugsnag.js#L666
    var eventTargets = ['EventTarget', 'Window', 'Node', 'ApplicationCache', 'AudioTrackList', 'ChannelMergerNode', 'CryptoOperation', 'EventSource', 'FileReader', 'HTMLUnknownElement', 'IDBDatabase', 'IDBRequest', 'IDBTransaction', 'KeyOperation', 'MediaController', 'MessagePort', 'ModalWindow', 'Notification', 'SVGElementInstance', 'Screen', 'TextTrack', 'TextTrackCue', 'TextTrackList', 'WebSocket', 'WebSocketWorker', 'Worker', 'XMLHttpRequest', 'XMLHttpRequestEventTarget', 'XMLHttpRequestUpload'];
    for (var i = 0; i < eventTargets.length; i++) {
      wrapEventTarget(eventTargets[i]);
    }
  },

  /**
   * Instrument browser built-ins w/ breadcrumb capturing
   *  - XMLHttpRequests
   *  - DOM interactions (click/typing)
   *  - window.location changes
   *  - console
   *
   * Can be disabled or individually configured via the `autoBreadcrumbs` config option
   */
  _instrumentBreadcrumbs: function _instrumentBreadcrumbs() {
    var self = this;
    var autoBreadcrumbs = this._globalOptions.autoBreadcrumbs;

    var wrappedBuiltIns = self._wrappedBuiltIns;

    function wrapProp(prop, xhr) {
      if (prop in xhr && isFunction(xhr[prop])) {
        fill(xhr, prop, function (orig) {
          return self.wrap({
            mechanism: {
              type: 'instrument',
              data: { function: prop, handler: orig && orig.name || '<anonymous>' }
            }
          }, orig);
        }); // intentionally don't track filled methods on XHR instances
      }
    }

    if (autoBreadcrumbs.xhr && 'XMLHttpRequest' in _window) {
      var xhrproto = _window.XMLHttpRequest && _window.XMLHttpRequest.prototype;
      fill(xhrproto, 'open', function (origOpen) {
        return function (method, url) {
          // preserve arity

          // if Sentry key appears in URL, don't capture
          if (isString(url) && url.indexOf(self._globalKey) === -1) {
            this.__raven_xhr = {
              method: method,
              url: url,
              status_code: null
            };
          }

          return origOpen.apply(this, arguments);
        };
      }, wrappedBuiltIns);

      fill(xhrproto, 'send', function (origSend) {
        return function () {
          // preserve arity
          var xhr = this;

          function onreadystatechangeHandler() {
            if (xhr.__raven_xhr && xhr.readyState === 4) {
              try {
                // touching statusCode in some platforms throws
                // an exception
                xhr.__raven_xhr.status_code = xhr.status;
              } catch (e) {
                /* do nothing */
              }

              self.captureBreadcrumb({
                type: 'http',
                category: 'xhr',
                data: xhr.__raven_xhr
              });
            }
          }

          var props = ['onload', 'onerror', 'onprogress'];
          for (var j = 0; j < props.length; j++) {
            wrapProp(props[j], xhr);
          }

          if ('onreadystatechange' in xhr && isFunction(xhr.onreadystatechange)) {
            fill(xhr, 'onreadystatechange', function (orig) {
              return self.wrap({
                mechanism: {
                  type: 'instrument',
                  data: {
                    function: 'onreadystatechange',
                    handler: orig && orig.name || '<anonymous>'
                  }
                }
              }, orig, onreadystatechangeHandler);
            } /* intentionally don't track this instrumentation */
            );
          } else {
            // if onreadystatechange wasn't actually set by the page on this xhr, we
            // are free to set our own and capture the breadcrumb
            xhr.onreadystatechange = onreadystatechangeHandler;
          }

          return origSend.apply(this, arguments);
        };
      }, wrappedBuiltIns);
    }

    if (autoBreadcrumbs.xhr && supportsFetch()) {
      fill(_window, 'fetch', function (origFetch) {
        return function () {
          // preserve arity
          // Make a copy of the arguments to prevent deoptimization
          // https://github.com/petkaantonov/bluebird/wiki/Optimization-killers#32-leaking-arguments
          var args = new Array(arguments.length);
          for (var i = 0; i < args.length; ++i) {
            args[i] = arguments[i];
          }

          var fetchInput = args[0];
          var method = 'GET';
          var url;

          if (typeof fetchInput === 'string') {
            url = fetchInput;
          } else if ('Request' in _window && fetchInput instanceof _window.Request) {
            url = fetchInput.url;
            if (fetchInput.method) {
              method = fetchInput.method;
            }
          } else {
            url = '' + fetchInput;
          }

          // if Sentry key appears in URL, don't capture, as it's our own request
          if (url.indexOf(self._globalKey) !== -1) {
            return origFetch.apply(this, args);
          }

          if (args[1] && args[1].method) {
            method = args[1].method;
          }

          var fetchData = {
            method: method,
            url: url,
            status_code: null
          };

          return origFetch.apply(this, args).then(function (response) {
            fetchData.status_code = response.status;

            self.captureBreadcrumb({
              type: 'http',
              category: 'fetch',
              data: fetchData
            });

            return response;
          })['catch'](function (err) {
            // if there is an error performing the request
            self.captureBreadcrumb({
              type: 'http',
              category: 'fetch',
              data: fetchData,
              level: 'error'
            });

            throw err;
          });
        };
      }, wrappedBuiltIns);
    }

    // Capture breadcrumbs from any click that is unhandled / bubbled up all the way
    // to the document. Do this before we instrument addEventListener.
    if (autoBreadcrumbs.dom && this._hasDocument) {
      if (_document.addEventListener) {
        _document.addEventListener('click', self._breadcrumbEventHandler('click'), false);
        _document.addEventListener('keypress', self._keypressEventHandler(), false);
      } else if (_document.attachEvent) {
        // IE8 Compatibility
        _document.attachEvent('onclick', self._breadcrumbEventHandler('click'));
        _document.attachEvent('onkeypress', self._keypressEventHandler());
      }
    }

    // record navigation (URL) changes
    // NOTE: in Chrome App environment, touching history.pushState, *even inside
    //       a try/catch block*, will cause Chrome to output an error to console.error
    // borrowed from: https://github.com/angular/angular.js/pull/13945/files
    var chrome = _window.chrome;
    var isChromePackagedApp = chrome && chrome.app && chrome.app.runtime;
    var hasPushAndReplaceState = !isChromePackagedApp && _window.history && _window.history.pushState && _window.history.replaceState;
    if (autoBreadcrumbs.location && hasPushAndReplaceState) {
      // TODO: remove onpopstate handler on uninstall()
      var oldOnPopState = _window.onpopstate;
      _window.onpopstate = function () {
        var currentHref = self._location.href;
        self._captureUrlChange(self._lastHref, currentHref);

        if (oldOnPopState) {
          return oldOnPopState.apply(this, arguments);
        }
      };

      var historyReplacementFunction = function historyReplacementFunction(origHistFunction) {
        // note history.pushState.length is 0; intentionally not declaring
        // params to preserve 0 arity
        return function () /* state, title, url */{
          var url = arguments.length > 2 ? arguments[2] : undefined;

          // url argument is optional
          if (url) {
            // coerce to string (this is what pushState does)
            self._captureUrlChange(self._lastHref, url + '');
          }

          return origHistFunction.apply(this, arguments);
        };
      };

      fill(_window.history, 'pushState', historyReplacementFunction, wrappedBuiltIns);
      fill(_window.history, 'replaceState', historyReplacementFunction, wrappedBuiltIns);
    }

    if (autoBreadcrumbs.console && 'console' in _window && console.log) {
      // console
      var consoleMethodCallback = function consoleMethodCallback(msg, data) {
        self.captureBreadcrumb({
          message: msg,
          level: data.level,
          category: 'console'
        });
      };

      each(['debug', 'info', 'warn', 'error', 'log'], function (_, level) {
        wrapConsoleMethod(console, level, consoleMethodCallback);
      });
    }
  },

  _restoreBuiltIns: function _restoreBuiltIns() {
    // restore any wrapped builtins
    var builtin;
    while (this._wrappedBuiltIns.length) {
      builtin = this._wrappedBuiltIns.shift();

      var obj = builtin[0],
          name = builtin[1],
          orig = builtin[2];

      obj[name] = orig;
    }
  },

  _restoreConsole: function _restoreConsole() {
    // eslint-disable-next-line guard-for-in
    for (var method in this._originalConsoleMethods) {
      this._originalConsole[method] = this._originalConsoleMethods[method];
    }
  },

  _drainPlugins: function _drainPlugins() {
    var self = this;

    // FIX ME TODO
    each(this._plugins, function (_, plugin) {
      var installer = plugin[0];
      var args = plugin[1];
      installer.apply(self, [self].concat(args));
    });
  },

  _parseDSN: function _parseDSN(str) {
    var m = dsnPattern.exec(str),
        dsn = {},
        i = 7;

    try {
      while (i--) {
        dsn[dsnKeys[i]] = m[i] || '';
      }
    } catch (e) {
      throw new RavenConfigError('Invalid DSN: ' + str);
    }

    if (dsn.pass && !this._globalOptions.allowSecretKey) {
      throw new RavenConfigError('Do not specify your secret key in the DSN. See: http://bit.ly/raven-secret-key');
    }

    return dsn;
  },

  _getGlobalServer: function _getGlobalServer(uri) {
    // assemble the endpoint from the uri pieces
    var globalServer = '//' + uri.host + (uri.port ? ':' + uri.port : '');

    if (uri.protocol) {
      globalServer = uri.protocol + ':' + globalServer;
    }
    return globalServer;
  },

  _handleOnErrorStackInfo: function _handleOnErrorStackInfo(stackInfo, options) {
    options = options || {};
    options.mechanism = options.mechanism || {
      type: 'onerror',
      handled: false
    };

    // if we are intentionally ignoring errors via onerror, bail out
    if (!this._ignoreOnError) {
      this._handleStackInfo(stackInfo, options);
    }
  },

  _handleStackInfo: function _handleStackInfo(stackInfo, options) {
    var frames = this._prepareFrames(stackInfo, options);

    this._triggerEvent('handle', {
      stackInfo: stackInfo,
      options: options
    });

    this._processException(stackInfo.name, stackInfo.message, stackInfo.url, stackInfo.lineno, frames, options);
  },

  _prepareFrames: function _prepareFrames(stackInfo, options) {
    var self = this;
    var frames = [];
    if (stackInfo.stack && stackInfo.stack.length) {
      each(stackInfo.stack, function (i, stack) {
        var frame = self._normalizeFrame(stack, stackInfo.url);
        if (frame) {
          frames.push(frame);
        }
      });

      // e.g. frames captured via captureMessage throw
      if (options && options.trimHeadFrames) {
        for (var j = 0; j < options.trimHeadFrames && j < frames.length; j++) {
          frames[j].in_app = false;
        }
      }
    }
    frames = frames.slice(0, this._globalOptions.stackTraceLimit);
    return frames;
  },

  _normalizeFrame: function _normalizeFrame(frame, stackInfoUrl) {
    // normalize the frames data
    var normalized = {
      filename: frame.url,
      lineno: frame.line,
      colno: frame.column,
      function: frame.func || '?'
    };

    // Case when we don't have any information about the error
    // E.g. throwing a string or raw object, instead of an `Error` in Firefox
    // Generating synthetic error doesn't add any value here
    //
    // We should probably somehow let a user know that they should fix their code
    if (!frame.url) {
      normalized.filename = stackInfoUrl; // fallback to whole stacks url from onerror handler
    }

    normalized.in_app = !( // determine if an exception came from outside of our app
    // first we check the global includePaths list.
    !!this._globalOptions.includePaths.test && !this._globalOptions.includePaths.test(normalized.filename) ||
    // Now we check for fun, if the function name is Raven or TraceKit
    /(Raven|TraceKit)\./.test(normalized['function']) ||
    // finally, we do a last ditch effort and check for raven.min.js
    /raven\.(min\.)?js$/.test(normalized.filename));

    return normalized;
  },

  _processException: function _processException(type, message, fileurl, lineno, frames, options) {
    var prefixedMessage = (type ? type + ': ' : '') + (message || '');
    if (!!this._globalOptions.ignoreErrors.test && (this._globalOptions.ignoreErrors.test(message) || this._globalOptions.ignoreErrors.test(prefixedMessage))) {
      return;
    }

    var stacktrace;

    if (frames && frames.length) {
      fileurl = frames[0].filename || fileurl;
      // Sentry expects frames oldest to newest
      // and JS sends them as newest to oldest
      frames.reverse();
      stacktrace = { frames: frames };
    } else if (fileurl) {
      stacktrace = {
        frames: [{
          filename: fileurl,
          lineno: lineno,
          in_app: true
        }]
      };
    }

    if (!!this._globalOptions.ignoreUrls.test && this._globalOptions.ignoreUrls.test(fileurl)) {
      return;
    }

    if (!!this._globalOptions.whitelistUrls.test && !this._globalOptions.whitelistUrls.test(fileurl)) {
      return;
    }

    var data = objectMerge({
      // sentry.interfaces.Exception
      exception: {
        values: [{
          type: type,
          value: message,
          stacktrace: stacktrace
        }]
      },
      transaction: fileurl
    }, options);

    var ex = data.exception.values[0];
    if (ex.type == null && ex.value === '') {
      ex.value = 'Unrecoverable error caught';
    }

    // Move mechanism from options to exception interface
    // We do this, as requiring user to pass `{exception:{mechanism:{ ... }}}` would be
    // too much
    if (!data.exception.mechanism && data.mechanism) {
      data.exception.mechanism = data.mechanism;
      delete data.mechanism;
    }

    data.exception.mechanism = objectMerge({
      type: 'generic',
      handled: true
    }, data.exception.mechanism || {});

    // Fire away!
    this._send(data);
  },

  _trimPacket: function _trimPacket(data) {
    // For now, we only want to truncate the two different messages
    // but this could/should be expanded to just trim everything
    var max = this._globalOptions.maxMessageLength;
    if (data.message) {
      data.message = truncate(data.message, max);
    }
    if (data.exception) {
      var exception = data.exception.values[0];
      exception.value = truncate(exception.value, max);
    }

    var request = data.request;
    if (request) {
      if (request.url) {
        request.url = truncate(request.url, this._globalOptions.maxUrlLength);
      }
      if (request.Referer) {
        request.Referer = truncate(request.Referer, this._globalOptions.maxUrlLength);
      }
    }

    if (data.breadcrumbs && data.breadcrumbs.values) this._trimBreadcrumbs(data.breadcrumbs);

    return data;
  },

  /**
   * Truncate breadcrumb values (right now just URLs)
   */
  _trimBreadcrumbs: function _trimBreadcrumbs(breadcrumbs) {
    // known breadcrumb properties with urls
    // TODO: also consider arbitrary prop values that start with (https?)?://
    var urlProps = ['to', 'from', 'url'],
        urlProp,
        crumb,
        data;

    for (var i = 0; i < breadcrumbs.values.length; ++i) {
      crumb = breadcrumbs.values[i];
      if (!crumb.hasOwnProperty('data') || !isObject(crumb.data) || objectFrozen(crumb.data)) continue;

      data = objectMerge({}, crumb.data);
      for (var j = 0; j < urlProps.length; ++j) {
        urlProp = urlProps[j];
        if (data.hasOwnProperty(urlProp) && data[urlProp]) {
          data[urlProp] = truncate(data[urlProp], this._globalOptions.maxUrlLength);
        }
      }
      breadcrumbs.values[i].data = data;
    }
  },

  _getHttpData: function _getHttpData() {
    if (!this._hasNavigator && !this._hasDocument) return;
    var httpData = {};

    if (this._hasNavigator && _navigator.userAgent) {
      httpData.headers = {
        'User-Agent': _navigator.userAgent
      };
    }

    // Check in `window` instead of `document`, as we may be in ServiceWorker environment
    if (_window.location && _window.location.href) {
      httpData.url = _window.location.href;
    }

    if (this._hasDocument && _document.referrer) {
      if (!httpData.headers) httpData.headers = {};
      httpData.headers.Referer = _document.referrer;
    }

    return httpData;
  },

  _resetBackoff: function _resetBackoff() {
    this._backoffDuration = 0;
    this._backoffStart = null;
  },

  _shouldBackoff: function _shouldBackoff() {
    return this._backoffDuration && now() - this._backoffStart < this._backoffDuration;
  },

  /**
   * Returns true if the in-process data payload matches the signature
   * of the previously-sent data
   *
   * NOTE: This has to be done at this level because TraceKit can generate
   *       data from window.onerror WITHOUT an exception object (IE8, IE9,
   *       other old browsers). This can take the form of an "exception"
   *       data object with a single frame (derived from the onerror args).
   */
  _isRepeatData: function _isRepeatData(current) {
    var last = this._lastData;

    if (!last || current.message !== last.message || // defined for captureMessage
    current.transaction !== last.transaction // defined for captureException/onerror
    ) return false;

    // Stacktrace interface (i.e. from captureMessage)
    if (current.stacktrace || last.stacktrace) {
      return isSameStacktrace(current.stacktrace, last.stacktrace);
    } else if (current.exception || last.exception) {
      // Exception interface (i.e. from captureException/onerror)
      return isSameException(current.exception, last.exception);
    } else if (current.fingerprint || last.fingerprint) {
      return Boolean(current.fingerprint && last.fingerprint) && JSON.stringify(current.fingerprint) === JSON.stringify(last.fingerprint);
    }

    return true;
  },

  _setBackoffState: function _setBackoffState(request) {
    // If we are already in a backoff state, don't change anything
    if (this._shouldBackoff()) {
      return;
    }

    var status = request.status;

    // 400 - project_id doesn't exist or some other fatal
    // 401 - invalid/revoked dsn
    // 429 - too many requests
    if (!(status === 400 || status === 401 || status === 429)) return;

    var retry;
    try {
      // If Retry-After is not in Access-Control-Expose-Headers, most
      // browsers will throw an exception trying to access it
      if (supportsFetch()) {
        retry = request.headers.get('Retry-After');
      } else {
        retry = request.getResponseHeader('Retry-After');
      }

      // Retry-After is returned in seconds
      retry = parseInt(retry, 10) * 1000;
    } catch (e) {
      /* eslint no-empty:0 */
    }

    this._backoffDuration = retry ? // If Sentry server returned a Retry-After value, use it
    retry : // Otherwise, double the last backoff duration (starts at 1 sec)
    this._backoffDuration * 2 || 1000;

    this._backoffStart = now();
  },

  _send: function _send(data) {
    var globalOptions = this._globalOptions;

    var baseData = {
      project: this._globalProject,
      logger: globalOptions.logger,
      platform: 'javascript'
    },
        httpData = this._getHttpData();

    if (httpData) {
      baseData.request = httpData;
    }

    // HACK: delete `trimHeadFrames` to prevent from appearing in outbound payload
    if (data.trimHeadFrames) delete data.trimHeadFrames;

    data = objectMerge(baseData, data);

    // Merge in the tags and extra separately since objectMerge doesn't handle a deep merge
    data.tags = objectMerge(objectMerge({}, this._globalContext.tags), data.tags);
    data.extra = objectMerge(objectMerge({}, this._globalContext.extra), data.extra);

    // Send along our own collected metadata with extra
    data.extra['session:duration'] = now() - this._startTime;

    if (this._breadcrumbs && this._breadcrumbs.length > 0) {
      // intentionally make shallow copy so that additions
      // to breadcrumbs aren't accidentally sent in this request
      data.breadcrumbs = {
        values: [].slice.call(this._breadcrumbs, 0)
      };
    }

    if (this._globalContext.user) {
      // sentry.interfaces.User
      data.user = this._globalContext.user;
    }

    // Include the environment if it's defined in globalOptions
    if (globalOptions.environment) data.environment = globalOptions.environment;

    // Include the release if it's defined in globalOptions
    if (globalOptions.release) data.release = globalOptions.release;

    // Include server_name if it's defined in globalOptions
    if (globalOptions.serverName) data.server_name = globalOptions.serverName;

    data = this._sanitizeData(data);

    // Cleanup empty properties before sending them to the server
    Object.keys(data).forEach(function (key) {
      if (data[key] == null || data[key] === '' || isEmptyObject(data[key])) {
        delete data[key];
      }
    });

    if (isFunction(globalOptions.dataCallback)) {
      data = globalOptions.dataCallback(data) || data;
    }

    // Why??????????
    if (!data || isEmptyObject(data)) {
      return;
    }

    // Check if the request should be filtered or not
    if (isFunction(globalOptions.shouldSendCallback) && !globalOptions.shouldSendCallback(data)) {
      return;
    }

    // Backoff state: Sentry server previously responded w/ an error (e.g. 429 - too many requests),
    // so drop requests until "cool-off" period has elapsed.
    if (this._shouldBackoff()) {
      this._logDebug('warn', 'Raven dropped error due to backoff: ', data);
      return;
    }

    if (typeof globalOptions.sampleRate === 'number') {
      if (Math.random() < globalOptions.sampleRate) {
        this._sendProcessedPayload(data);
      }
    } else {
      this._sendProcessedPayload(data);
    }
  },

  _sanitizeData: function _sanitizeData(data) {
    return sanitize(data, this._globalOptions.sanitizeKeys);
  },

  _getUuid: function _getUuid() {
    return uuid4();
  },

  _sendProcessedPayload: function _sendProcessedPayload(data, callback) {
    var self = this;
    var globalOptions = this._globalOptions;

    if (!this.isSetup()) return;

    // Try and clean up the packet before sending by truncating long values
    data = this._trimPacket(data);

    // ideally duplicate error testing should occur *before* dataCallback/shouldSendCallback,
    // but this would require copying an un-truncated copy of the data packet, which can be
    // arbitrarily deep (extra_data) -- could be worthwhile? will revisit
    if (!this._globalOptions.allowDuplicates && this._isRepeatData(data)) {
      this._logDebug('warn', 'Raven dropped repeat event: ', data);
      return;
    }

    // Send along an event_id if not explicitly passed.
    // This event_id can be used to reference the error within Sentry itself.
    // Set lastEventId after we know the error should actually be sent
    this._lastEventId = data.event_id || (data.event_id = this._getUuid());

    // Store outbound payload after trim
    this._lastData = data;

    this._logDebug('debug', 'Raven about to send:', data);

    var auth = {
      sentry_version: '7',
      sentry_client: 'raven-js/' + this.VERSION,
      sentry_key: this._globalKey
    };

    if (this._globalSecret) {
      auth.sentry_secret = this._globalSecret;
    }

    var exception = data.exception && data.exception.values[0];

    // only capture 'sentry' breadcrumb is autoBreadcrumbs is truthy
    if (this._globalOptions.autoBreadcrumbs && this._globalOptions.autoBreadcrumbs.sentry) {
      this.captureBreadcrumb({
        category: 'sentry',
        message: exception ? (exception.type ? exception.type + ': ' : '') + exception.value : data.message,
        event_id: data.event_id,
        level: data.level || 'error' // presume error unless specified
      });
    }

    var url = this._globalEndpoint;
    (globalOptions.transport || this._makeRequest).call(this, {
      url: url,
      auth: auth,
      data: data,
      options: globalOptions,
      onSuccess: function success() {
        self._resetBackoff();

        self._triggerEvent('success', {
          data: data,
          src: url
        });
        callback && callback();
      },
      onError: function failure(error) {
        self._logDebug('error', 'Raven transport failed to send: ', error);

        if (error.request) {
          self._setBackoffState(error.request);
        }

        self._triggerEvent('failure', {
          data: data,
          src: url
        });
        error = error || new Error('Raven send failed (no additional details provided)');
        callback && callback(error);
      }
    });
  },

  _makeRequest: function _makeRequest(opts) {
    // Auth is intentionally sent as part of query string (NOT as custom HTTP header) to avoid preflight CORS requests
    var url = opts.url + '?' + urlencode(opts.auth);

    var evaluatedHeaders = null;
    var evaluatedFetchParameters = {};

    if (opts.options.headers) {
      evaluatedHeaders = this._evaluateHash(opts.options.headers);
    }

    if (opts.options.fetchParameters) {
      evaluatedFetchParameters = this._evaluateHash(opts.options.fetchParameters);
    }

    if (supportsFetch()) {
      evaluatedFetchParameters.body = stringify(opts.data);

      var defaultFetchOptions = objectMerge({}, this._fetchDefaults);
      var fetchOptions = objectMerge(defaultFetchOptions, evaluatedFetchParameters);

      if (evaluatedHeaders) {
        fetchOptions.headers = evaluatedHeaders;
      }

      return _window.fetch(url, fetchOptions).then(function (response) {
        if (response.ok) {
          opts.onSuccess && opts.onSuccess();
        } else {
          var error = new Error('Sentry error code: ' + response.status);
          // It's called request only to keep compatibility with XHR interface
          // and not add more redundant checks in setBackoffState method
          error.request = response;
          opts.onError && opts.onError(error);
        }
      })['catch'](function () {
        opts.onError && opts.onError(new Error('Sentry error code: network unavailable'));
      });
    }

    var request = _window.XMLHttpRequest && new _window.XMLHttpRequest();
    if (!request) return;

    // if browser doesn't support CORS (e.g. IE7), we are out of luck
    var hasCORS = 'withCredentials' in request || typeof XDomainRequest !== 'undefined';

    if (!hasCORS) return;

    if ('withCredentials' in request) {
      request.onreadystatechange = function () {
        if (request.readyState !== 4) {
          return;
        } else if (request.status === 200) {
          opts.onSuccess && opts.onSuccess();
        } else if (opts.onError) {
          var err = new Error('Sentry error code: ' + request.status);
          err.request = request;
          opts.onError(err);
        }
      };
    } else {
      request = new XDomainRequest();
      // xdomainrequest cannot go http -> https (or vice versa),
      // so always use protocol relative
      url = url.replace(/^https?:/, '');

      // onreadystatechange not supported by XDomainRequest
      if (opts.onSuccess) {
        request.onload = opts.onSuccess;
      }
      if (opts.onError) {
        request.onerror = function () {
          var err = new Error('Sentry error code: XDomainRequest');
          err.request = request;
          opts.onError(err);
        };
      }
    }

    request.open('POST', url);

    if (evaluatedHeaders) {
      each(evaluatedHeaders, function (key, value) {
        request.setRequestHeader(key, value);
      });
    }

    request.send(stringify(opts.data));
  },

  _evaluateHash: function _evaluateHash(hash) {
    var evaluated = {};

    for (var key in hash) {
      if (hash.hasOwnProperty(key)) {
        var value = hash[key];
        evaluated[key] = typeof value === 'function' ? value() : value;
      }
    }

    return evaluated;
  },

  _logDebug: function _logDebug(level) {
    // We allow `Raven.debug` and `Raven.config(DSN, { debug: true })` to not make backward incompatible API change
    if (this._originalConsoleMethods[level] && (this.debug || this._globalOptions.debug)) {
      // In IE<10 console methods do not have their own 'apply' method
      Function.prototype.apply.call(this._originalConsoleMethods[level], this._originalConsole, [].slice.call(arguments, 1));
    }
  },

  _mergeContext: function _mergeContext(key, context) {
    if (isUndefined(context)) {
      delete this._globalContext[key];
    } else {
      this._globalContext[key] = objectMerge(this._globalContext[key] || {}, context);
    }
  }
};

// Deprecations
Raven.prototype.setUser = Raven.prototype.setUserContext;
Raven.prototype.setReleaseContext = Raven.prototype.setRelease;

module.exports = Raven;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"../vendor/TraceKit/tracekit":12,"../vendor/json-stringify-safe/stringify":13,"../vendor/md5/md5":14,"./configError":7,"./console":8,"./utils":11}],10:[function(require,module,exports){
(function (global){
'use strict';

/**
 * Enforces a single instance of the Raven client, and the
 * main entry point for Raven. If you are a consumer of the
 * Raven library, you SHOULD load this file (vs raven.js).
 **/

var RavenConstructor = require('./raven');

// This is to be defensive in environments where window does not exist (see https://github.com/getsentry/raven-js/pull/785)
var _window = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};
var _Raven = _window.Raven;

var Raven = new RavenConstructor();

/*
 * Allow multiple versions of Raven to be installed.
 * Strip Raven from the global context and returns the instance.
 *
 * @return {Raven}
 */
Raven.noConflict = function () {
  _window.Raven = _Raven;
  return Raven;
};

Raven.afterLoad();

module.exports = Raven;

/**
 * DISCLAIMER:
 *
 * Expose `Client` constructor for cases where user want to track multiple "sub-applications" in one larger app.
 * It's not meant to be used by a wide audience, so pleaaase make sure that you know what you're doing before using it.
 * Accidentally calling `install` multiple times, may result in an unexpected behavior that's very hard to debug.
 *
 * It's called `Client' to be in-line with Raven Node implementation.
 *
 * HOWTO:
 *
 * import Raven from 'raven-js';
 *
 * const someAppReporter = new Raven.Client();
 * const someOtherAppReporter = new Raven.Client();
 *
 * someAppReporter.config('__DSN__', {
 *   ...config goes here
 * });
 *
 * someOtherAppReporter.config('__OTHER_DSN__', {
 *   ...config goes here
 * });
 *
 * someAppReporter.captureMessage(...);
 * someAppReporter.captureException(...);
 * someAppReporter.captureBreadcrumb(...);
 *
 * someOtherAppReporter.captureMessage(...);
 * someOtherAppReporter.captureException(...);
 * someOtherAppReporter.captureBreadcrumb(...);
 *
 * It should "just work".
 */
module.exports.Client = RavenConstructor;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"./raven":9}],11:[function(require,module,exports){
(function (global){
'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var stringify = require('../vendor/json-stringify-safe/stringify');

var _window = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

function isObject(what) {
  return (typeof what === 'undefined' ? 'undefined' : _typeof(what)) === 'object' && what !== null;
}

// Yanked from https://git.io/vS8DV re-used under CC0
// with some tiny modifications
function isError(value) {
  switch (Object.prototype.toString.call(value)) {
    case '[object Error]':
      return true;
    case '[object Exception]':
      return true;
    case '[object DOMException]':
      return true;
    default:
      return value instanceof Error;
  }
}

function isErrorEvent(value) {
  return Object.prototype.toString.call(value) === '[object ErrorEvent]';
}

function isDOMError(value) {
  return Object.prototype.toString.call(value) === '[object DOMError]';
}

function isDOMException(value) {
  return Object.prototype.toString.call(value) === '[object DOMException]';
}

function isUndefined(what) {
  return what === void 0;
}

function isFunction(what) {
  return typeof what === 'function';
}

function isPlainObject(what) {
  return Object.prototype.toString.call(what) === '[object Object]';
}

function isString(what) {
  return Object.prototype.toString.call(what) === '[object String]';
}

function isArray(what) {
  return Object.prototype.toString.call(what) === '[object Array]';
}

function isEmptyObject(what) {
  if (!isPlainObject(what)) return false;

  for (var _ in what) {
    if (what.hasOwnProperty(_)) {
      return false;
    }
  }
  return true;
}

function supportsErrorEvent() {
  try {
    new ErrorEvent(''); // eslint-disable-line no-new
    return true;
  } catch (e) {
    return false;
  }
}

function supportsDOMError() {
  try {
    new DOMError(''); // eslint-disable-line no-new
    return true;
  } catch (e) {
    return false;
  }
}

function supportsDOMException() {
  try {
    new DOMException(''); // eslint-disable-line no-new
    return true;
  } catch (e) {
    return false;
  }
}

function supportsFetch() {
  if (!('fetch' in _window)) return false;

  try {
    new Headers(); // eslint-disable-line no-new
    new Request(''); // eslint-disable-line no-new
    new Response(); // eslint-disable-line no-new
    return true;
  } catch (e) {
    return false;
  }
}

// Despite all stars in the sky saying that Edge supports old draft syntax, aka 'never', 'always', 'origin' and 'default
// https://caniuse.com/#feat=referrer-policy
// It doesn't. And it throw exception instead of ignoring this parameter...
// REF: https://github.com/getsentry/raven-js/issues/1233
function supportsReferrerPolicy() {
  if (!supportsFetch()) return false;

  try {
    // eslint-disable-next-line no-new
    new Request('pickleRick', {
      referrerPolicy: 'origin'
    });
    return true;
  } catch (e) {
    return false;
  }
}

function supportsPromiseRejectionEvent() {
  return typeof PromiseRejectionEvent === 'function';
}

function wrappedCallback(callback) {
  function dataCallback(data, original) {
    var normalizedData = callback(data) || data;
    if (original) {
      return original(normalizedData) || normalizedData;
    }
    return normalizedData;
  }

  return dataCallback;
}

function each(obj, callback) {
  var i, j;

  if (isUndefined(obj.length)) {
    for (i in obj) {
      if (hasKey(obj, i)) {
        callback.call(null, i, obj[i]);
      }
    }
  } else {
    j = obj.length;
    if (j) {
      for (i = 0; i < j; i++) {
        callback.call(null, i, obj[i]);
      }
    }
  }
}

function objectMerge(obj1, obj2) {
  if (!obj2) {
    return obj1;
  }
  each(obj2, function (key, value) {
    obj1[key] = value;
  });
  return obj1;
}

/**
 * This function is only used for react-native.
 * react-native freezes object that have already been sent over the
 * js bridge. We need this function in order to check if the object is frozen.
 * So it's ok that objectFrozen returns false if Object.isFrozen is not
 * supported because it's not relevant for other "platforms". See related issue:
 * https://github.com/getsentry/react-native-sentry/issues/57
 */
function objectFrozen(obj) {
  if (!Object.isFrozen) {
    return false;
  }
  return Object.isFrozen(obj);
}

function truncate(str, max) {
  if (typeof max !== 'number') {
    throw new Error('2nd argument to `truncate` function should be a number');
  }
  if (typeof str !== 'string' || max === 0) {
    return str;
  }
  return str.length <= max ? str : str.substr(0, max) + '\u2026';
}

/**
 * hasKey, a better form of hasOwnProperty
 * Example: hasKey(MainHostObject, property) === true/false
 *
 * @param {Object} host object to check property
 * @param {string} key to check
 */
function hasKey(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function joinRegExp(patterns) {
  // Combine an array of regular expressions and strings into one large regexp
  // Be mad.
  var sources = [],
      i = 0,
      len = patterns.length,
      pattern;

  for (; i < len; i++) {
    pattern = patterns[i];
    if (isString(pattern)) {
      // If it's a string, we need to escape it
      // Taken from: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions
      sources.push(pattern.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, '\\$1'));
    } else if (pattern && pattern.source) {
      // If it's a regexp already, we want to extract the source
      sources.push(pattern.source);
    }
    // Intentionally skip other cases
  }
  return new RegExp(sources.join('|'), 'i');
}

function urlencode(o) {
  var pairs = [];
  each(o, function (key, value) {
    pairs.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
  });
  return pairs.join('&');
}

// borrowed from https://tools.ietf.org/html/rfc3986#appendix-B
// intentionally using regex and not <a/> href parsing trick because React Native and other
// environments where DOM might not be available
function parseUrl(url) {
  if (typeof url !== 'string') return {};
  var match = url.match(/^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?$/);

  // coerce to undefined values to empty string so we don't get 'undefined'
  var query = match[6] || '';
  var fragment = match[8] || '';
  return {
    protocol: match[2],
    host: match[4],
    path: match[5],
    relative: match[5] + query + fragment // everything minus origin
  };
}
function uuid4() {
  var crypto = _window.crypto || _window.msCrypto;

  if (!isUndefined(crypto) && crypto.getRandomValues) {
    // Use window.crypto API if available
    // eslint-disable-next-line no-undef
    var arr = new Uint16Array(8);
    crypto.getRandomValues(arr);

    // set 4 in byte 7
    arr[3] = arr[3] & 0xfff | 0x4000;
    // set 2 most significant bits of byte 9 to '10'
    arr[4] = arr[4] & 0x3fff | 0x8000;

    var pad = function pad(num) {
      var v = num.toString(16);
      while (v.length < 4) {
        v = '0' + v;
      }
      return v;
    };

    return pad(arr[0]) + pad(arr[1]) + pad(arr[2]) + pad(arr[3]) + pad(arr[4]) + pad(arr[5]) + pad(arr[6]) + pad(arr[7]);
  } else {
    // http://stackoverflow.com/questions/105034/how-to-create-a-guid-uuid-in-javascript/2117523#2117523
    return 'xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0,
          v = c === 'x' ? r : r & 0x3 | 0x8;
      return v.toString(16);
    });
  }
}

/**
 * Given a child DOM element, returns a query-selector statement describing that
 * and its ancestors
 * e.g. [HTMLElement] => body > div > input#foo.btn[name=baz]
 * @param elem
 * @returns {string}
 */
function htmlTreeAsString(elem) {
  /* eslint no-extra-parens:0*/
  var MAX_TRAVERSE_HEIGHT = 5,
      MAX_OUTPUT_LEN = 80,
      out = [],
      height = 0,
      len = 0,
      separator = ' > ',
      sepLength = separator.length,
      nextStr;

  while (elem && height++ < MAX_TRAVERSE_HEIGHT) {
    nextStr = htmlElementAsString(elem);
    // bail out if
    // - nextStr is the 'html' element
    // - the length of the string that would be created exceeds MAX_OUTPUT_LEN
    //   (ignore this limit if we are on the first iteration)
    if (nextStr === 'html' || height > 1 && len + out.length * sepLength + nextStr.length >= MAX_OUTPUT_LEN) {
      break;
    }

    out.push(nextStr);

    len += nextStr.length;
    elem = elem.parentNode;
  }

  return out.reverse().join(separator);
}

/**
 * Returns a simple, query-selector representation of a DOM element
 * e.g. [HTMLElement] => input#foo.btn[name=baz]
 * @param HTMLElement
 * @returns {string}
 */
function htmlElementAsString(elem) {
  var out = [],
      className,
      classes,
      key,
      attr,
      i;

  if (!elem || !elem.tagName) {
    return '';
  }

  out.push(elem.tagName.toLowerCase());
  if (elem.id) {
    out.push('#' + elem.id);
  }

  className = elem.className;
  if (className && isString(className)) {
    classes = className.split(/\s+/);
    for (i = 0; i < classes.length; i++) {
      out.push('.' + classes[i]);
    }
  }
  var attrWhitelist = ['type', 'name', 'title', 'alt'];
  for (i = 0; i < attrWhitelist.length; i++) {
    key = attrWhitelist[i];
    attr = elem.getAttribute(key);
    if (attr) {
      out.push('[' + key + '="' + attr + '"]');
    }
  }
  return out.join('');
}

/**
 * Returns true if either a OR b is truthy, but not both
 */
function isOnlyOneTruthy(a, b) {
  return !!(!!a ^ !!b);
}

/**
 * Returns true if both parameters are undefined
 */
function isBothUndefined(a, b) {
  return isUndefined(a) && isUndefined(b);
}

/**
 * Returns true if the two input exception interfaces have the same content
 */
function isSameException(ex1, ex2) {
  if (isOnlyOneTruthy(ex1, ex2)) return false;

  ex1 = ex1.values[0];
  ex2 = ex2.values[0];

  if (ex1.type !== ex2.type || ex1.value !== ex2.value) return false;

  // in case both stacktraces are undefined, we can't decide so default to false
  if (isBothUndefined(ex1.stacktrace, ex2.stacktrace)) return false;

  return isSameStacktrace(ex1.stacktrace, ex2.stacktrace);
}

/**
 * Returns true if the two input stack trace interfaces have the same content
 */
function isSameStacktrace(stack1, stack2) {
  if (isOnlyOneTruthy(stack1, stack2)) return false;

  var frames1 = stack1.frames;
  var frames2 = stack2.frames;

  // Exit early if stacktrace is malformed
  if (frames1 === undefined || frames2 === undefined) return false;

  // Exit early if frame count differs
  if (frames1.length !== frames2.length) return false;

  // Iterate through every frame; bail out if anything differs
  var a, b;
  for (var i = 0; i < frames1.length; i++) {
    a = frames1[i];
    b = frames2[i];
    if (a.filename !== b.filename || a.lineno !== b.lineno || a.colno !== b.colno || a['function'] !== b['function']) return false;
  }
  return true;
}

/**
 * Polyfill a method
 * @param obj object e.g. `document`
 * @param name method name present on object e.g. `addEventListener`
 * @param replacement replacement function
 * @param track {optional} record instrumentation to an array
 */
function fill(obj, name, replacement, track) {
  if (obj == null) return;
  var orig = obj[name];
  obj[name] = replacement(orig);
  obj[name].__raven__ = true;
  obj[name].__orig__ = orig;
  if (track) {
    track.push([obj, name, orig]);
  }
}

/**
 * Join values in array
 * @param input array of values to be joined together
 * @param delimiter string to be placed in-between values
 * @returns {string}
 */
function safeJoin(input, delimiter) {
  if (!isArray(input)) return '';

  var output = [];

  for (var i = 0; i < input.length; i++) {
    try {
      output.push(String(input[i]));
    } catch (e) {
      output.push('[value cannot be serialized]');
    }
  }

  return output.join(delimiter);
}

// Default Node.js REPL depth
var MAX_SERIALIZE_EXCEPTION_DEPTH = 3;
// 50kB, as 100kB is max payload size, so half sounds reasonable
var MAX_SERIALIZE_EXCEPTION_SIZE = 50 * 1024;
var MAX_SERIALIZE_KEYS_LENGTH = 40;

function utf8Length(value) {
  return ~-encodeURI(value).split(/%..|./).length;
}

function jsonSize(value) {
  return utf8Length(JSON.stringify(value));
}

function serializeValue(value) {
  if (typeof value === 'string') {
    var maxLength = 40;
    return truncate(value, maxLength);
  } else if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'undefined') {
    return value;
  }

  var type = Object.prototype.toString.call(value);

  // Node.js REPL notation
  if (type === '[object Object]') return '[Object]';
  if (type === '[object Array]') return '[Array]';
  if (type === '[object Function]') return value.name ? '[Function: ' + value.name + ']' : '[Function]';

  return value;
}

function serializeObject(value, depth) {
  if (depth === 0) return serializeValue(value);

  if (isPlainObject(value)) {
    return Object.keys(value).reduce(function (acc, key) {
      acc[key] = serializeObject(value[key], depth - 1);
      return acc;
    }, {});
  } else if (Array.isArray(value)) {
    return value.map(function (val) {
      return serializeObject(val, depth - 1);
    });
  }

  return serializeValue(value);
}

function serializeException(ex, depth, maxSize) {
  if (!isPlainObject(ex)) return ex;

  depth = typeof depth !== 'number' ? MAX_SERIALIZE_EXCEPTION_DEPTH : depth;
  maxSize = typeof depth !== 'number' ? MAX_SERIALIZE_EXCEPTION_SIZE : maxSize;

  var serialized = serializeObject(ex, depth);

  if (jsonSize(stringify(serialized)) > maxSize) {
    return serializeException(ex, depth - 1);
  }

  return serialized;
}

function serializeKeysForMessage(keys, maxLength) {
  if (typeof keys === 'number' || typeof keys === 'string') return keys.toString();
  if (!Array.isArray(keys)) return '';

  keys = keys.filter(function (key) {
    return typeof key === 'string';
  });
  if (keys.length === 0) return '[object has no keys]';

  maxLength = typeof maxLength !== 'number' ? MAX_SERIALIZE_KEYS_LENGTH : maxLength;
  if (keys[0].length >= maxLength) return keys[0];

  for (var usedKeys = keys.length; usedKeys > 0; usedKeys--) {
    var serialized = keys.slice(0, usedKeys).join(', ');
    if (serialized.length > maxLength) continue;
    if (usedKeys === keys.length) return serialized;
    return serialized + '\u2026';
  }

  return '';
}

function sanitize(input, sanitizeKeys) {
  if (!isArray(sanitizeKeys) || isArray(sanitizeKeys) && sanitizeKeys.length === 0) return input;

  var sanitizeRegExp = joinRegExp(sanitizeKeys);
  var sanitizeMask = '********';
  var safeInput;

  try {
    safeInput = JSON.parse(stringify(input));
  } catch (o_O) {
    return input;
  }

  function sanitizeWorker(workerInput) {
    if (isArray(workerInput)) {
      return workerInput.map(function (val) {
        return sanitizeWorker(val);
      });
    }

    if (isPlainObject(workerInput)) {
      return Object.keys(workerInput).reduce(function (acc, k) {
        if (sanitizeRegExp.test(k)) {
          acc[k] = sanitizeMask;
        } else {
          acc[k] = sanitizeWorker(workerInput[k]);
        }
        return acc;
      }, {});
    }

    return workerInput;
  }

  return sanitizeWorker(safeInput);
}

module.exports = {
  isObject: isObject,
  isError: isError,
  isErrorEvent: isErrorEvent,
  isDOMError: isDOMError,
  isDOMException: isDOMException,
  isUndefined: isUndefined,
  isFunction: isFunction,
  isPlainObject: isPlainObject,
  isString: isString,
  isArray: isArray,
  isEmptyObject: isEmptyObject,
  supportsErrorEvent: supportsErrorEvent,
  supportsDOMError: supportsDOMError,
  supportsDOMException: supportsDOMException,
  supportsFetch: supportsFetch,
  supportsReferrerPolicy: supportsReferrerPolicy,
  supportsPromiseRejectionEvent: supportsPromiseRejectionEvent,
  wrappedCallback: wrappedCallback,
  each: each,
  objectMerge: objectMerge,
  truncate: truncate,
  objectFrozen: objectFrozen,
  hasKey: hasKey,
  joinRegExp: joinRegExp,
  urlencode: urlencode,
  uuid4: uuid4,
  htmlTreeAsString: htmlTreeAsString,
  htmlElementAsString: htmlElementAsString,
  isSameException: isSameException,
  isSameStacktrace: isSameStacktrace,
  parseUrl: parseUrl,
  fill: fill,
  safeJoin: safeJoin,
  serializeException: serializeException,
  serializeKeysForMessage: serializeKeysForMessage,
  sanitize: sanitize
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"../vendor/json-stringify-safe/stringify":13}],12:[function(require,module,exports){
(function (global){
'use strict';

var utils = require('../../src/utils');

/*
 TraceKit - Cross brower stack traces

 This was originally forked from github.com/occ/TraceKit, but has since been
 largely re-written and is now maintained as part of raven-js.  Tests for
 this are in test/vendor.

 MIT license
*/

var TraceKit = {
  collectWindowErrors: true,
  debug: false
};

// This is to be defensive in environments where window does not exist (see https://github.com/getsentry/raven-js/pull/785)
var _window = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

// global reference to slice
var _slice = [].slice;
var UNKNOWN_FUNCTION = '?';

// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error#Error_types
var ERROR_TYPES_RE = /^(?:[Uu]ncaught (?:exception: )?)?(?:((?:Eval|Internal|Range|Reference|Syntax|Type|URI|)Error): )?(.*)$/;

function getLocationHref() {
  if (typeof document === 'undefined' || document.location == null) return '';
  return document.location.href;
}

function getLocationOrigin() {
  if (typeof document === 'undefined' || document.location == null) return '';

  // Oh dear IE10...
  if (!document.location.origin) {
    return document.location.protocol + '//' + document.location.hostname + (document.location.port ? ':' + document.location.port : '');
  }

  return document.location.origin;
}

/**
 * TraceKit.report: cross-browser processing of unhandled exceptions
 *
 * Syntax:
 *   TraceKit.report.subscribe(function(stackInfo) { ... })
 *   TraceKit.report.unsubscribe(function(stackInfo) { ... })
 *   TraceKit.report(exception)
 *   try { ...code... } catch(ex) { TraceKit.report(ex); }
 *
 * Supports:
 *   - Firefox: full stack trace with line numbers, plus column number
 *              on top frame; column number is not guaranteed
 *   - Opera:   full stack trace with line and column numbers
 *   - Chrome:  full stack trace with line and column numbers
 *   - Safari:  line and column number for the top frame only; some frames
 *              may be missing, and column number is not guaranteed
 *   - IE:      line and column number for the top frame only; some frames
 *              may be missing, and column number is not guaranteed
 *
 * In theory, TraceKit should work on all of the following versions:
 *   - IE5.5+ (only 8.0 tested)
 *   - Firefox 0.9+ (only 3.5+ tested)
 *   - Opera 7+ (only 10.50 tested; versions 9 and earlier may require
 *     Exceptions Have Stacktrace to be enabled in opera:config)
 *   - Safari 3+ (only 4+ tested)
 *   - Chrome 1+ (only 5+ tested)
 *   - Konqueror 3.5+ (untested)
 *
 * Requires TraceKit.computeStackTrace.
 *
 * Tries to catch all unhandled exceptions and report them to the
 * subscribed handlers. Please note that TraceKit.report will rethrow the
 * exception. This is REQUIRED in order to get a useful stack trace in IE.
 * If the exception does not reach the top of the browser, you will only
 * get a stack trace from the point where TraceKit.report was called.
 *
 * Handlers receive a stackInfo object as described in the
 * TraceKit.computeStackTrace docs.
 */
TraceKit.report = function reportModuleWrapper() {
  var handlers = [],
      lastArgs = null,
      lastException = null,
      lastExceptionStack = null;

  /**
   * Add a crash handler.
   * @param {Function} handler
   */
  function subscribe(handler) {
    installGlobalHandler();
    handlers.push(handler);
  }

  /**
   * Remove a crash handler.
   * @param {Function} handler
   */
  function unsubscribe(handler) {
    for (var i = handlers.length - 1; i >= 0; --i) {
      if (handlers[i] === handler) {
        handlers.splice(i, 1);
      }
    }
  }

  /**
   * Remove all crash handlers.
   */
  function unsubscribeAll() {
    uninstallGlobalHandler();
    handlers = [];
  }

  /**
   * Dispatch stack information to all handlers.
   * @param {Object.<string, *>} stack
   */
  function notifyHandlers(stack, isWindowError) {
    var exception = null;
    if (isWindowError && !TraceKit.collectWindowErrors) {
      return;
    }
    for (var i in handlers) {
      if (handlers.hasOwnProperty(i)) {
        try {
          handlers[i].apply(null, [stack].concat(_slice.call(arguments, 2)));
        } catch (inner) {
          exception = inner;
        }
      }
    }

    if (exception) {
      throw exception;
    }
  }

  var _oldOnerrorHandler, _onErrorHandlerInstalled;

  /**
   * Ensures all global unhandled exceptions are recorded.
   * Supported by Gecko and IE.
   * @param {string} msg Error message.
   * @param {string} url URL of script that generated the exception.
   * @param {(number|string)} lineNo The line number at which the error
   * occurred.
   * @param {?(number|string)} colNo The column number at which the error
   * occurred.
   * @param {?Error} ex The actual Error object.
   */
  function traceKitWindowOnError(msg, url, lineNo, colNo, ex) {
    var stack = null;
    // If 'ex' is ErrorEvent, get real Error from inside
    var exception = utils.isErrorEvent(ex) ? ex.error : ex;
    // If 'msg' is ErrorEvent, get real message from inside
    var message = utils.isErrorEvent(msg) ? msg.message : msg;

    if (lastExceptionStack) {
      TraceKit.computeStackTrace.augmentStackTraceWithInitialElement(lastExceptionStack, url, lineNo, message);
      processLastException();
    } else if (exception && utils.isError(exception)) {
      // non-string `exception` arg; attempt to extract stack trace

      // New chrome and blink send along a real error object
      // Let's just report that like a normal error.
      // See: https://mikewest.org/2013/08/debugging-runtime-errors-with-window-onerror
      stack = TraceKit.computeStackTrace(exception);
      notifyHandlers(stack, true);
    } else {
      var location = {
        url: url,
        line: lineNo,
        column: colNo
      };

      var name = undefined;
      var groups;

      if ({}.toString.call(message) === '[object String]') {
        var groups = message.match(ERROR_TYPES_RE);
        if (groups) {
          name = groups[1];
          message = groups[2];
        }
      }

      location.func = UNKNOWN_FUNCTION;

      stack = {
        name: name,
        message: message,
        url: getLocationHref(),
        stack: [location]
      };
      notifyHandlers(stack, true);
    }

    if (_oldOnerrorHandler) {
      return _oldOnerrorHandler.apply(this, arguments);
    }

    return false;
  }

  function installGlobalHandler() {
    if (_onErrorHandlerInstalled) {
      return;
    }
    _oldOnerrorHandler = _window.onerror;
    _window.onerror = traceKitWindowOnError;
    _onErrorHandlerInstalled = true;
  }

  function uninstallGlobalHandler() {
    if (!_onErrorHandlerInstalled) {
      return;
    }
    _window.onerror = _oldOnerrorHandler;
    _onErrorHandlerInstalled = false;
    _oldOnerrorHandler = undefined;
  }

  function processLastException() {
    var _lastExceptionStack = lastExceptionStack,
        _lastArgs = lastArgs;
    lastArgs = null;
    lastExceptionStack = null;
    lastException = null;
    notifyHandlers.apply(null, [_lastExceptionStack, false].concat(_lastArgs));
  }

  /**
   * Reports an unhandled Error to TraceKit.
   * @param {Error} ex
   * @param {?boolean} rethrow If false, do not re-throw the exception.
   * Only used for window.onerror to not cause an infinite loop of
   * rethrowing.
   */
  function report(ex, rethrow) {
    var args = _slice.call(arguments, 1);
    if (lastExceptionStack) {
      if (lastException === ex) {
        return; // already caught by an inner catch block, ignore
      } else {
        processLastException();
      }
    }

    var stack = TraceKit.computeStackTrace(ex);
    lastExceptionStack = stack;
    lastException = ex;
    lastArgs = args;

    // If the stack trace is incomplete, wait for 2 seconds for
    // slow slow IE to see if onerror occurs or not before reporting
    // this exception; otherwise, we will end up with an incomplete
    // stack trace
    setTimeout(function () {
      if (lastException === ex) {
        processLastException();
      }
    }, stack.incomplete ? 2000 : 0);

    if (rethrow !== false) {
      throw ex; // re-throw to propagate to the top level (and cause window.onerror)
    }
  }

  report.subscribe = subscribe;
  report.unsubscribe = unsubscribe;
  report.uninstall = unsubscribeAll;
  return report;
}();

/**
 * TraceKit.computeStackTrace: cross-browser stack traces in JavaScript
 *
 * Syntax:
 *   s = TraceKit.computeStackTrace(exception) // consider using TraceKit.report instead (see below)
 * Returns:
 *   s.name              - exception name
 *   s.message           - exception message
 *   s.stack[i].url      - JavaScript or HTML file URL
 *   s.stack[i].func     - function name, or empty for anonymous functions (if guessing did not work)
 *   s.stack[i].args     - arguments passed to the function, if known
 *   s.stack[i].line     - line number, if known
 *   s.stack[i].column   - column number, if known
 *
 * Supports:
 *   - Firefox:  full stack trace with line numbers and unreliable column
 *               number on top frame
 *   - Opera 10: full stack trace with line and column numbers
 *   - Opera 9-: full stack trace with line numbers
 *   - Chrome:   full stack trace with line and column numbers
 *   - Safari:   line and column number for the topmost stacktrace element
 *               only
 *   - IE:       no line numbers whatsoever
 *
 * Tries to guess names of anonymous functions by looking for assignments
 * in the source code. In IE and Safari, we have to guess source file names
 * by searching for function bodies inside all page scripts. This will not
 * work for scripts that are loaded cross-domain.
 * Here be dragons: some function names may be guessed incorrectly, and
 * duplicate functions may be mismatched.
 *
 * TraceKit.computeStackTrace should only be used for tracing purposes.
 * Logging of unhandled exceptions should be done with TraceKit.report,
 * which builds on top of TraceKit.computeStackTrace and provides better
 * IE support by utilizing the window.onerror event to retrieve information
 * about the top of the stack.
 *
 * Note: In IE and Safari, no stack trace is recorded on the Error object,
 * so computeStackTrace instead walks its *own* chain of callers.
 * This means that:
 *  * in Safari, some methods may be missing from the stack trace;
 *  * in IE, the topmost function in the stack trace will always be the
 *    caller of computeStackTrace.
 *
 * This is okay for tracing (because you are likely to be calling
 * computeStackTrace from the function you want to be the topmost element
 * of the stack trace anyway), but not okay for logging unhandled
 * exceptions (because your catch block will likely be far away from the
 * inner function that actually caused the exception).
 *
 */
TraceKit.computeStackTrace = function computeStackTraceWrapper() {
  // Contents of Exception in various browsers.
  //
  // SAFARI:
  // ex.message = Can't find variable: qq
  // ex.line = 59
  // ex.sourceId = 580238192
  // ex.sourceURL = http://...
  // ex.expressionBeginOffset = 96
  // ex.expressionCaretOffset = 98
  // ex.expressionEndOffset = 98
  // ex.name = ReferenceError
  //
  // FIREFOX:
  // ex.message = qq is not defined
  // ex.fileName = http://...
  // ex.lineNumber = 59
  // ex.columnNumber = 69
  // ex.stack = ...stack trace... (see the example below)
  // ex.name = ReferenceError
  //
  // CHROME:
  // ex.message = qq is not defined
  // ex.name = ReferenceError
  // ex.type = not_defined
  // ex.arguments = ['aa']
  // ex.stack = ...stack trace...
  //
  // INTERNET EXPLORER:
  // ex.message = ...
  // ex.name = ReferenceError
  //
  // OPERA:
  // ex.message = ...message... (see the example below)
  // ex.name = ReferenceError
  // ex.opera#sourceloc = 11  (pretty much useless, duplicates the info in ex.message)
  // ex.stacktrace = n/a; see 'opera:config#UserPrefs|Exceptions Have Stacktrace'

  /**
   * Computes stack trace information from the stack property.
   * Chrome and Gecko use this property.
   * @param {Error} ex
   * @return {?Object.<string, *>} Stack trace information.
   */
  function computeStackTraceFromStackProp(ex) {
    if (typeof ex.stack === 'undefined' || !ex.stack) return;

    var chrome = /^\s*at (?:(.*?) ?\()?((?:file|https?|blob|chrome-extension|native|eval|webpack|<anonymous>|[a-z]:|\/).*?)(?::(\d+))?(?::(\d+))?\)?\s*$/i;
    var winjs = /^\s*at (?:((?:\[object object\])?.+) )?\(?((?:file|ms-appx(?:-web)|https?|webpack|blob):.*?):(\d+)(?::(\d+))?\)?\s*$/i;
    // NOTE: blob urls are now supposed to always have an origin, therefore it's format
    // which is `blob:http://url/path/with-some-uuid`, is matched by `blob.*?:\/` as well
    var gecko = /^\s*(.*?)(?:\((.*?)\))?(?:^|@)((?:file|https?|blob|chrome|webpack|resource|moz-extension).*?:\/.*?|\[native code\]|[^@]*(?:bundle|\d+\.js))(?::(\d+))?(?::(\d+))?\s*$/i;
    // Used to additionally parse URL/line/column from eval frames
    var geckoEval = /(\S+) line (\d+)(?: > eval line \d+)* > eval/i;
    var chromeEval = /\((\S*)(?::(\d+))(?::(\d+))\)/;
    var lines = ex.stack.split('\n');
    var stack = [];
    var submatch;
    var parts;
    var element;
    var reference = /^(.*) is undefined$/.exec(ex.message);

    for (var i = 0, j = lines.length; i < j; ++i) {
      if (parts = chrome.exec(lines[i])) {
        var isNative = parts[2] && parts[2].indexOf('native') === 0; // start of line
        var isEval = parts[2] && parts[2].indexOf('eval') === 0; // start of line
        if (isEval && (submatch = chromeEval.exec(parts[2]))) {
          // throw out eval line/column and use top-most line/column number
          parts[2] = submatch[1]; // url
          parts[3] = submatch[2]; // line
          parts[4] = submatch[3]; // column
        }
        element = {
          url: !isNative ? parts[2] : null,
          func: parts[1] || UNKNOWN_FUNCTION,
          args: isNative ? [parts[2]] : [],
          line: parts[3] ? +parts[3] : null,
          column: parts[4] ? +parts[4] : null
        };
      } else if (parts = winjs.exec(lines[i])) {
        element = {
          url: parts[2],
          func: parts[1] || UNKNOWN_FUNCTION,
          args: [],
          line: +parts[3],
          column: parts[4] ? +parts[4] : null
        };
      } else if (parts = gecko.exec(lines[i])) {
        var isEval = parts[3] && parts[3].indexOf(' > eval') > -1;
        if (isEval && (submatch = geckoEval.exec(parts[3]))) {
          // throw out eval line/column and use top-most line number
          parts[3] = submatch[1];
          parts[4] = submatch[2];
          parts[5] = null; // no column when eval
        } else if (i === 0 && !parts[5] && typeof ex.columnNumber !== 'undefined') {
          // FireFox uses this awesome columnNumber property for its top frame
          // Also note, Firefox's column number is 0-based and everything else expects 1-based,
          // so adding 1
          // NOTE: this hack doesn't work if top-most frame is eval
          stack[0].column = ex.columnNumber + 1;
        }
        element = {
          url: parts[3],
          func: parts[1] || UNKNOWN_FUNCTION,
          args: parts[2] ? parts[2].split(',') : [],
          line: parts[4] ? +parts[4] : null,
          column: parts[5] ? +parts[5] : null
        };
      } else {
        continue;
      }

      if (!element.func && element.line) {
        element.func = UNKNOWN_FUNCTION;
      }

      if (element.url && element.url.substr(0, 5) === 'blob:') {
        // Special case for handling JavaScript loaded into a blob.
        // We use a synchronous AJAX request here as a blob is already in
        // memory - it's not making a network request.  This will generate a warning
        // in the browser console, but there has already been an error so that's not
        // that much of an issue.
        var xhr = new XMLHttpRequest();
        xhr.open('GET', element.url, false);
        xhr.send(null);

        // If we failed to download the source, skip this patch
        if (xhr.status === 200) {
          var source = xhr.responseText || '';

          // We trim the source down to the last 300 characters as sourceMappingURL is always at the end of the file.
          // Why 300? To be in line with: https://github.com/getsentry/sentry/blob/4af29e8f2350e20c28a6933354e4f42437b4ba42/src/sentry/lang/javascript/processor.py#L164-L175
          source = source.slice(-300);

          // Now we dig out the source map URL
          var sourceMaps = source.match(/\/\/# sourceMappingURL=(.*)$/);

          // If we don't find a source map comment or we find more than one, continue on to the next element.
          if (sourceMaps) {
            var sourceMapAddress = sourceMaps[1];

            // Now we check to see if it's a relative URL.
            // If it is, convert it to an absolute one.
            if (sourceMapAddress.charAt(0) === '~') {
              sourceMapAddress = getLocationOrigin() + sourceMapAddress.slice(1);
            }

            // Now we strip the '.map' off of the end of the URL and update the
            // element so that Sentry can match the map to the blob.
            element.url = sourceMapAddress.slice(0, -4);
          }
        }
      }

      stack.push(element);
    }

    if (!stack.length) {
      return null;
    }

    return {
      name: ex.name,
      message: ex.message,
      url: getLocationHref(),
      stack: stack
    };
  }

  /**
   * Adds information about the first frame to incomplete stack traces.
   * Safari and IE require this to get complete data on the first frame.
   * @param {Object.<string, *>} stackInfo Stack trace information from
   * one of the compute* methods.
   * @param {string} url The URL of the script that caused an error.
   * @param {(number|string)} lineNo The line number of the script that
   * caused an error.
   * @param {string=} message The error generated by the browser, which
   * hopefully contains the name of the object that caused the error.
   * @return {boolean} Whether or not the stack information was
   * augmented.
   */
  function augmentStackTraceWithInitialElement(stackInfo, url, lineNo, message) {
    var initial = {
      url: url,
      line: lineNo
    };

    if (initial.url && initial.line) {
      stackInfo.incomplete = false;

      if (!initial.func) {
        initial.func = UNKNOWN_FUNCTION;
      }

      if (stackInfo.stack.length > 0) {
        if (stackInfo.stack[0].url === initial.url) {
          if (stackInfo.stack[0].line === initial.line) {
            return false; // already in stack trace
          } else if (!stackInfo.stack[0].line && stackInfo.stack[0].func === initial.func) {
            stackInfo.stack[0].line = initial.line;
            return false;
          }
        }
      }

      stackInfo.stack.unshift(initial);
      stackInfo.partial = true;
      return true;
    } else {
      stackInfo.incomplete = true;
    }

    return false;
  }

  /**
   * Computes stack trace information by walking the arguments.caller
   * chain at the time the exception occurred. This will cause earlier
   * frames to be missed but is the only way to get any stack trace in
   * Safari and IE. The top frame is restored by
   * {@link augmentStackTraceWithInitialElement}.
   * @param {Error} ex
   * @return {?Object.<string, *>} Stack trace information.
   */
  function computeStackTraceByWalkingCallerChain(ex, depth) {
    var functionName = /function\s+([_$a-zA-Z\xA0-\uFFFF][_$a-zA-Z0-9\xA0-\uFFFF]*)?\s*\(/i,
        stack = [],
        funcs = {},
        recursion = false,
        parts,
        item,
        source;

    for (var curr = computeStackTraceByWalkingCallerChain.caller; curr && !recursion; curr = curr.caller) {
      if (curr === computeStackTrace || curr === TraceKit.report) {
        // console.log('skipping internal function');
        continue;
      }

      item = {
        url: null,
        func: UNKNOWN_FUNCTION,
        line: null,
        column: null
      };

      if (curr.name) {
        item.func = curr.name;
      } else if (parts = functionName.exec(curr.toString())) {
        item.func = parts[1];
      }

      if (typeof item.func === 'undefined') {
        try {
          item.func = parts.input.substring(0, parts.input.indexOf('{'));
        } catch (e) {}
      }

      if (funcs['' + curr]) {
        recursion = true;
      } else {
        funcs['' + curr] = true;
      }

      stack.push(item);
    }

    if (depth) {
      // console.log('depth is ' + depth);
      // console.log('stack is ' + stack.length);
      stack.splice(0, depth);
    }

    var result = {
      name: ex.name,
      message: ex.message,
      url: getLocationHref(),
      stack: stack
    };
    augmentStackTraceWithInitialElement(result, ex.sourceURL || ex.fileName, ex.line || ex.lineNumber, ex.message || ex.description);
    return result;
  }

  /**
   * Computes a stack trace for an exception.
   * @param {Error} ex
   * @param {(string|number)=} depth
   */
  function computeStackTrace(ex, depth) {
    var stack = null;
    depth = depth == null ? 0 : +depth;

    try {
      stack = computeStackTraceFromStackProp(ex);
      if (stack) {
        return stack;
      }
    } catch (e) {
      if (TraceKit.debug) {
        throw e;
      }
    }

    try {
      stack = computeStackTraceByWalkingCallerChain(ex, depth + 1);
      if (stack) {
        return stack;
      }
    } catch (e) {
      if (TraceKit.debug) {
        throw e;
      }
    }
    return {
      name: ex.name,
      message: ex.message,
      url: getLocationHref()
    };
  }

  computeStackTrace.augmentStackTraceWithInitialElement = augmentStackTraceWithInitialElement;
  computeStackTrace.computeStackTraceFromStackProp = computeStackTraceFromStackProp;

  return computeStackTrace;
}();

module.exports = TraceKit;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"../../src/utils":11}],13:[function(require,module,exports){
'use strict';

/*
 json-stringify-safe
 Like JSON.stringify, but doesn't throw on circular references.

 Originally forked from https://github.com/isaacs/json-stringify-safe
 version 5.0.1 on 3/8/2017 and modified to handle Errors serialization
 and IE8 compatibility. Tests for this are in test/vendor.

 ISC license: https://github.com/isaacs/json-stringify-safe/blob/master/LICENSE
*/

exports = module.exports = stringify;
exports.getSerialize = serializer;

function indexOf(haystack, needle) {
  for (var i = 0; i < haystack.length; ++i) {
    if (haystack[i] === needle) return i;
  }
  return -1;
}

function stringify(obj, replacer, spaces, cycleReplacer) {
  return JSON.stringify(obj, serializer(replacer, cycleReplacer), spaces);
}

// https://github.com/ftlabs/js-abbreviate/blob/fa709e5f139e7770a71827b1893f22418097fbda/index.js#L95-L106
function stringifyError(value) {
  var err = {
    // These properties are implemented as magical getters and don't show up in for in
    stack: value.stack,
    message: value.message,
    name: value.name
  };

  for (var i in value) {
    if (Object.prototype.hasOwnProperty.call(value, i)) {
      err[i] = value[i];
    }
  }

  return err;
}

function serializer(replacer, cycleReplacer) {
  var stack = [];
  var keys = [];

  if (cycleReplacer == null) {
    cycleReplacer = function cycleReplacer(key, value) {
      if (stack[0] === value) {
        return '[Circular ~]';
      }
      return '[Circular ~.' + keys.slice(0, indexOf(stack, value)).join('.') + ']';
    };
  }

  return function (key, value) {
    if (stack.length > 0) {
      var thisPos = indexOf(stack, this);
      ~thisPos ? stack.splice(thisPos + 1) : stack.push(this);
      ~thisPos ? keys.splice(thisPos, Infinity, key) : keys.push(key);

      if (~indexOf(stack, value)) {
        value = cycleReplacer.call(this, key, value);
      }
    } else {
      stack.push(value);
    }

    return replacer == null ? value instanceof Error ? stringifyError(value) : value : replacer.call(this, key, value);
  };
}

},{}],14:[function(require,module,exports){
'use strict';

/*
 * JavaScript MD5
 * https://github.com/blueimp/JavaScript-MD5
 *
 * Copyright 2011, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * https://opensource.org/licenses/MIT
 *
 * Based on
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*
* Add integers, wrapping at 2^32. This uses 16-bit operations internally
* to work around bugs in some JS interpreters.
*/
function safeAdd(x, y) {
  var lsw = (x & 0xffff) + (y & 0xffff);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return msw << 16 | lsw & 0xffff;
}

/*
* Bitwise rotate a 32-bit number to the left.
*/
function bitRotateLeft(num, cnt) {
  return num << cnt | num >>> 32 - cnt;
}

/*
* These functions implement the four basic operations the algorithm uses.
*/
function md5cmn(q, a, b, x, s, t) {
  return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
}
function md5ff(a, b, c, d, x, s, t) {
  return md5cmn(b & c | ~b & d, a, b, x, s, t);
}
function md5gg(a, b, c, d, x, s, t) {
  return md5cmn(b & d | c & ~d, a, b, x, s, t);
}
function md5hh(a, b, c, d, x, s, t) {
  return md5cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5ii(a, b, c, d, x, s, t) {
  return md5cmn(c ^ (b | ~d), a, b, x, s, t);
}

/*
* Calculate the MD5 of an array of little-endian words, and a bit length.
*/
function binlMD5(x, len) {
  /* append padding */
  x[len >> 5] |= 0x80 << len % 32;
  x[(len + 64 >>> 9 << 4) + 14] = len;

  var i;
  var olda;
  var oldb;
  var oldc;
  var oldd;
  var a = 1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d = 271733878;

  for (i = 0; i < x.length; i += 16) {
    olda = a;
    oldb = b;
    oldc = c;
    oldd = d;

    a = md5ff(a, b, c, d, x[i], 7, -680876936);
    d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
    c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
    b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
    a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
    d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
    c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
    b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
    a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
    d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
    c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
    b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
    a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
    d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
    c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
    b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);

    a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
    d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
    c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
    b = md5gg(b, c, d, a, x[i], 20, -373897302);
    a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
    d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
    c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
    b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
    a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
    d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
    c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
    b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
    a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
    d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
    c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
    b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);

    a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
    d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
    c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
    b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
    a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
    d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
    c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
    b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
    a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
    d = md5hh(d, a, b, c, x[i], 11, -358537222);
    c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
    b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
    a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
    d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
    c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
    b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);

    a = md5ii(a, b, c, d, x[i], 6, -198630844);
    d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
    c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
    b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
    a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
    d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
    c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
    b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
    a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
    d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
    c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
    b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
    a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
    d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
    c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
    b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);

    a = safeAdd(a, olda);
    b = safeAdd(b, oldb);
    c = safeAdd(c, oldc);
    d = safeAdd(d, oldd);
  }
  return [a, b, c, d];
}

/*
* Convert an array of little-endian words to a string
*/
function binl2rstr(input) {
  var i;
  var output = '';
  var length32 = input.length * 32;
  for (i = 0; i < length32; i += 8) {
    output += String.fromCharCode(input[i >> 5] >>> i % 32 & 0xff);
  }
  return output;
}

/*
* Convert a raw string to an array of little-endian words
* Characters >255 have their high-byte silently ignored.
*/
function rstr2binl(input) {
  var i;
  var output = [];
  output[(input.length >> 2) - 1] = undefined;
  for (i = 0; i < output.length; i += 1) {
    output[i] = 0;
  }
  var length8 = input.length * 8;
  for (i = 0; i < length8; i += 8) {
    output[i >> 5] |= (input.charCodeAt(i / 8) & 0xff) << i % 32;
  }
  return output;
}

/*
* Calculate the MD5 of a raw string
*/
function rstrMD5(s) {
  return binl2rstr(binlMD5(rstr2binl(s), s.length * 8));
}

/*
* Calculate the HMAC-MD5, of a key and some data (raw strings)
*/
function rstrHMACMD5(key, data) {
  var i;
  var bkey = rstr2binl(key);
  var ipad = [];
  var opad = [];
  var hash;
  ipad[15] = opad[15] = undefined;
  if (bkey.length > 16) {
    bkey = binlMD5(bkey, key.length * 8);
  }
  for (i = 0; i < 16; i += 1) {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5c5c5c5c;
  }
  hash = binlMD5(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
  return binl2rstr(binlMD5(opad.concat(hash), 512 + 128));
}

/*
* Convert a raw string to a hex string
*/
function rstr2hex(input) {
  var hexTab = '0123456789abcdef';
  var output = '';
  var x;
  var i;
  for (i = 0; i < input.length; i += 1) {
    x = input.charCodeAt(i);
    output += hexTab.charAt(x >>> 4 & 0x0f) + hexTab.charAt(x & 0x0f);
  }
  return output;
}

/*
* Encode a string as utf-8
*/
function str2rstrUTF8(input) {
  return unescape(encodeURIComponent(input));
}

/*
* Take string arguments and return either raw or hex encoded strings
*/
function rawMD5(s) {
  return rstrMD5(str2rstrUTF8(s));
}
function hexMD5(s) {
  return rstr2hex(rawMD5(s));
}
function rawHMACMD5(k, d) {
  return rstrHMACMD5(str2rstrUTF8(k), str2rstrUTF8(d));
}
function hexHMACMD5(k, d) {
  return rstr2hex(rawHMACMD5(k, d));
}

function md5(string, key, raw) {
  if (!key) {
    if (!raw) {
      return hexMD5(string);
    }
    return rawMD5(string);
  }
  if (!raw) {
    return hexHMACMD5(key, string);
  }
  return rawHMACMD5(key, string);
}

module.exports = md5;

},{}],15:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var punycode = require('punycode');
var util = require('./util');

exports.parse = urlParse;
exports.resolve = urlResolve;
exports.resolveObject = urlResolveObject;
exports.format = urlFormat;

exports.Url = Url;

function Url() {
  this.protocol = null;
  this.slashes = null;
  this.auth = null;
  this.host = null;
  this.port = null;
  this.hostname = null;
  this.hash = null;
  this.search = null;
  this.query = null;
  this.pathname = null;
  this.path = null;
  this.href = null;
}

// Reference: RFC 3986, RFC 1808, RFC 2396

// define these here so at least they only have to be
// compiled once on the first module load.
var protocolPattern = /^([a-z0-9.+-]+:)/i,
    portPattern = /:[0-9]*$/,


// Special case for a simple path URL
simplePathPattern = /^(\/\/?(?!\/)[^\?\s]*)(\?[^\s]*)?$/,


// RFC 2396: characters reserved for delimiting URLs.
// We actually just auto-escape these.
delims = ['<', '>', '"', '`', ' ', '\r', '\n', '\t'],


// RFC 2396: characters not allowed for various reasons.
unwise = ['{', '}', '|', '\\', '^', '`'].concat(delims),


// Allowed by RFCs, but cause of XSS attacks.  Always escape these.
autoEscape = ['\''].concat(unwise),

// Characters that are never ever allowed in a hostname.
// Note that any invalid chars are also handled, but these
// are the ones that are *expected* to be seen, so we fast-path
// them.
nonHostChars = ['%', '/', '?', ';', '#'].concat(autoEscape),
    hostEndingChars = ['/', '?', '#'],
    hostnameMaxLen = 255,
    hostnamePartPattern = /^[+a-z0-9A-Z_-]{0,63}$/,
    hostnamePartStart = /^([+a-z0-9A-Z_-]{0,63})(.*)$/,

// protocols that can allow "unsafe" and "unwise" chars.
unsafeProtocol = {
  'javascript': true,
  'javascript:': true
},

// protocols that never have a hostname.
hostlessProtocol = {
  'javascript': true,
  'javascript:': true
},

// protocols that always contain a // bit.
slashedProtocol = {
  'http': true,
  'https': true,
  'ftp': true,
  'gopher': true,
  'file': true,
  'http:': true,
  'https:': true,
  'ftp:': true,
  'gopher:': true,
  'file:': true
},
    querystring = require('querystring');

function urlParse(url, parseQueryString, slashesDenoteHost) {
  if (url && util.isObject(url) && url instanceof Url) return url;

  var u = new Url();
  u.parse(url, parseQueryString, slashesDenoteHost);
  return u;
}

Url.prototype.parse = function (url, parseQueryString, slashesDenoteHost) {
  if (!util.isString(url)) {
    throw new TypeError("Parameter 'url' must be a string, not " + (typeof url === 'undefined' ? 'undefined' : _typeof(url)));
  }

  // Copy chrome, IE, opera backslash-handling behavior.
  // Back slashes before the query string get converted to forward slashes
  // See: https://code.google.com/p/chromium/issues/detail?id=25916
  var queryIndex = url.indexOf('?'),
      splitter = queryIndex !== -1 && queryIndex < url.indexOf('#') ? '?' : '#',
      uSplit = url.split(splitter),
      slashRegex = /\\/g;
  uSplit[0] = uSplit[0].replace(slashRegex, '/');
  url = uSplit.join(splitter);

  var rest = url;

  // trim before proceeding.
  // This is to support parse stuff like "  http://foo.com  \n"
  rest = rest.trim();

  if (!slashesDenoteHost && url.split('#').length === 1) {
    // Try fast path regexp
    var simplePath = simplePathPattern.exec(rest);
    if (simplePath) {
      this.path = rest;
      this.href = rest;
      this.pathname = simplePath[1];
      if (simplePath[2]) {
        this.search = simplePath[2];
        if (parseQueryString) {
          this.query = querystring.parse(this.search.substr(1));
        } else {
          this.query = this.search.substr(1);
        }
      } else if (parseQueryString) {
        this.search = '';
        this.query = {};
      }
      return this;
    }
  }

  var proto = protocolPattern.exec(rest);
  if (proto) {
    proto = proto[0];
    var lowerProto = proto.toLowerCase();
    this.protocol = lowerProto;
    rest = rest.substr(proto.length);
  }

  // figure out if it's got a host
  // user@server is *always* interpreted as a hostname, and url
  // resolution will treat //foo/bar as host=foo,path=bar because that's
  // how the browser resolves relative URLs.
  if (slashesDenoteHost || proto || rest.match(/^\/\/[^@\/]+@[^@\/]+/)) {
    var slashes = rest.substr(0, 2) === '//';
    if (slashes && !(proto && hostlessProtocol[proto])) {
      rest = rest.substr(2);
      this.slashes = true;
    }
  }

  if (!hostlessProtocol[proto] && (slashes || proto && !slashedProtocol[proto])) {

    // there's a hostname.
    // the first instance of /, ?, ;, or # ends the host.
    //
    // If there is an @ in the hostname, then non-host chars *are* allowed
    // to the left of the last @ sign, unless some host-ending character
    // comes *before* the @-sign.
    // URLs are obnoxious.
    //
    // ex:
    // http://a@b@c/ => user:a@b host:c
    // http://a@b?@c => user:a host:c path:/?@c

    // v0.12 TODO(isaacs): This is not quite how Chrome does things.
    // Review our test case against browsers more comprehensively.

    // find the first instance of any hostEndingChars
    var hostEnd = -1;
    for (var i = 0; i < hostEndingChars.length; i++) {
      var hec = rest.indexOf(hostEndingChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd)) hostEnd = hec;
    }

    // at this point, either we have an explicit point where the
    // auth portion cannot go past, or the last @ char is the decider.
    var auth, atSign;
    if (hostEnd === -1) {
      // atSign can be anywhere.
      atSign = rest.lastIndexOf('@');
    } else {
      // atSign must be in auth portion.
      // http://a@b/c@d => host:b auth:a path:/c@d
      atSign = rest.lastIndexOf('@', hostEnd);
    }

    // Now we have a portion which is definitely the auth.
    // Pull that off.
    if (atSign !== -1) {
      auth = rest.slice(0, atSign);
      rest = rest.slice(atSign + 1);
      this.auth = decodeURIComponent(auth);
    }

    // the host is the remaining to the left of the first non-host char
    hostEnd = -1;
    for (var i = 0; i < nonHostChars.length; i++) {
      var hec = rest.indexOf(nonHostChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd)) hostEnd = hec;
    }
    // if we still have not hit it, then the entire thing is a host.
    if (hostEnd === -1) hostEnd = rest.length;

    this.host = rest.slice(0, hostEnd);
    rest = rest.slice(hostEnd);

    // pull out port.
    this.parseHost();

    // we've indicated that there is a hostname,
    // so even if it's empty, it has to be present.
    this.hostname = this.hostname || '';

    // if hostname begins with [ and ends with ]
    // assume that it's an IPv6 address.
    var ipv6Hostname = this.hostname[0] === '[' && this.hostname[this.hostname.length - 1] === ']';

    // validate a little.
    if (!ipv6Hostname) {
      var hostparts = this.hostname.split(/\./);
      for (var i = 0, l = hostparts.length; i < l; i++) {
        var part = hostparts[i];
        if (!part) continue;
        if (!part.match(hostnamePartPattern)) {
          var newpart = '';
          for (var j = 0, k = part.length; j < k; j++) {
            if (part.charCodeAt(j) > 127) {
              // we replace non-ASCII char with a temporary placeholder
              // we need this to make sure size of hostname is not
              // broken by replacing non-ASCII by nothing
              newpart += 'x';
            } else {
              newpart += part[j];
            }
          }
          // we test again with ASCII char only
          if (!newpart.match(hostnamePartPattern)) {
            var validParts = hostparts.slice(0, i);
            var notHost = hostparts.slice(i + 1);
            var bit = part.match(hostnamePartStart);
            if (bit) {
              validParts.push(bit[1]);
              notHost.unshift(bit[2]);
            }
            if (notHost.length) {
              rest = '/' + notHost.join('.') + rest;
            }
            this.hostname = validParts.join('.');
            break;
          }
        }
      }
    }

    if (this.hostname.length > hostnameMaxLen) {
      this.hostname = '';
    } else {
      // hostnames are always lower case.
      this.hostname = this.hostname.toLowerCase();
    }

    if (!ipv6Hostname) {
      // IDNA Support: Returns a punycoded representation of "domain".
      // It only converts parts of the domain name that
      // have non-ASCII characters, i.e. it doesn't matter if
      // you call it with a domain that already is ASCII-only.
      this.hostname = punycode.toASCII(this.hostname);
    }

    var p = this.port ? ':' + this.port : '';
    var h = this.hostname || '';
    this.host = h + p;
    this.href += this.host;

    // strip [ and ] from the hostname
    // the host field still retains them, though
    if (ipv6Hostname) {
      this.hostname = this.hostname.substr(1, this.hostname.length - 2);
      if (rest[0] !== '/') {
        rest = '/' + rest;
      }
    }
  }

  // now rest is set to the post-host stuff.
  // chop off any delim chars.
  if (!unsafeProtocol[lowerProto]) {

    // First, make 100% sure that any "autoEscape" chars get
    // escaped, even if encodeURIComponent doesn't think they
    // need to be.
    for (var i = 0, l = autoEscape.length; i < l; i++) {
      var ae = autoEscape[i];
      if (rest.indexOf(ae) === -1) continue;
      var esc = encodeURIComponent(ae);
      if (esc === ae) {
        esc = escape(ae);
      }
      rest = rest.split(ae).join(esc);
    }
  }

  // chop off from the tail first.
  var hash = rest.indexOf('#');
  if (hash !== -1) {
    // got a fragment string.
    this.hash = rest.substr(hash);
    rest = rest.slice(0, hash);
  }
  var qm = rest.indexOf('?');
  if (qm !== -1) {
    this.search = rest.substr(qm);
    this.query = rest.substr(qm + 1);
    if (parseQueryString) {
      this.query = querystring.parse(this.query);
    }
    rest = rest.slice(0, qm);
  } else if (parseQueryString) {
    // no query string, but parseQueryString still requested
    this.search = '';
    this.query = {};
  }
  if (rest) this.pathname = rest;
  if (slashedProtocol[lowerProto] && this.hostname && !this.pathname) {
    this.pathname = '/';
  }

  //to support http.request
  if (this.pathname || this.search) {
    var p = this.pathname || '';
    var s = this.search || '';
    this.path = p + s;
  }

  // finally, reconstruct the href based on what has been validated.
  this.href = this.format();
  return this;
};

// format a parsed object into a url string
function urlFormat(obj) {
  // ensure it's an object, and not a string url.
  // If it's an obj, this is a no-op.
  // this way, you can call url_format() on strings
  // to clean up potentially wonky urls.
  if (util.isString(obj)) obj = urlParse(obj);
  if (!(obj instanceof Url)) return Url.prototype.format.call(obj);
  return obj.format();
}

Url.prototype.format = function () {
  var auth = this.auth || '';
  if (auth) {
    auth = encodeURIComponent(auth);
    auth = auth.replace(/%3A/i, ':');
    auth += '@';
  }

  var protocol = this.protocol || '',
      pathname = this.pathname || '',
      hash = this.hash || '',
      host = false,
      query = '';

  if (this.host) {
    host = auth + this.host;
  } else if (this.hostname) {
    host = auth + (this.hostname.indexOf(':') === -1 ? this.hostname : '[' + this.hostname + ']');
    if (this.port) {
      host += ':' + this.port;
    }
  }

  if (this.query && util.isObject(this.query) && Object.keys(this.query).length) {
    query = querystring.stringify(this.query);
  }

  var search = this.search || query && '?' + query || '';

  if (protocol && protocol.substr(-1) !== ':') protocol += ':';

  // only the slashedProtocols get the //.  Not mailto:, xmpp:, etc.
  // unless they had them to begin with.
  if (this.slashes || (!protocol || slashedProtocol[protocol]) && host !== false) {
    host = '//' + (host || '');
    if (pathname && pathname.charAt(0) !== '/') pathname = '/' + pathname;
  } else if (!host) {
    host = '';
  }

  if (hash && hash.charAt(0) !== '#') hash = '#' + hash;
  if (search && search.charAt(0) !== '?') search = '?' + search;

  pathname = pathname.replace(/[?#]/g, function (match) {
    return encodeURIComponent(match);
  });
  search = search.replace('#', '%23');

  return protocol + host + pathname + search + hash;
};

function urlResolve(source, relative) {
  return urlParse(source, false, true).resolve(relative);
}

Url.prototype.resolve = function (relative) {
  return this.resolveObject(urlParse(relative, false, true)).format();
};

function urlResolveObject(source, relative) {
  if (!source) return relative;
  return urlParse(source, false, true).resolveObject(relative);
}

Url.prototype.resolveObject = function (relative) {
  if (util.isString(relative)) {
    var rel = new Url();
    rel.parse(relative, false, true);
    relative = rel;
  }

  var result = new Url();
  var tkeys = Object.keys(this);
  for (var tk = 0; tk < tkeys.length; tk++) {
    var tkey = tkeys[tk];
    result[tkey] = this[tkey];
  }

  // hash is always overridden, no matter what.
  // even href="" will remove it.
  result.hash = relative.hash;

  // if the relative url is empty, then there's nothing left to do here.
  if (relative.href === '') {
    result.href = result.format();
    return result;
  }

  // hrefs like //foo/bar always cut to the protocol.
  if (relative.slashes && !relative.protocol) {
    // take everything except the protocol from relative
    var rkeys = Object.keys(relative);
    for (var rk = 0; rk < rkeys.length; rk++) {
      var rkey = rkeys[rk];
      if (rkey !== 'protocol') result[rkey] = relative[rkey];
    }

    //urlParse appends trailing / to urls like http://www.example.com
    if (slashedProtocol[result.protocol] && result.hostname && !result.pathname) {
      result.path = result.pathname = '/';
    }

    result.href = result.format();
    return result;
  }

  if (relative.protocol && relative.protocol !== result.protocol) {
    // if it's a known url protocol, then changing
    // the protocol does weird things
    // first, if it's not file:, then we MUST have a host,
    // and if there was a path
    // to begin with, then we MUST have a path.
    // if it is file:, then the host is dropped,
    // because that's known to be hostless.
    // anything else is assumed to be absolute.
    if (!slashedProtocol[relative.protocol]) {
      var keys = Object.keys(relative);
      for (var v = 0; v < keys.length; v++) {
        var k = keys[v];
        result[k] = relative[k];
      }
      result.href = result.format();
      return result;
    }

    result.protocol = relative.protocol;
    if (!relative.host && !hostlessProtocol[relative.protocol]) {
      var relPath = (relative.pathname || '').split('/');
      while (relPath.length && !(relative.host = relPath.shift())) {}
      if (!relative.host) relative.host = '';
      if (!relative.hostname) relative.hostname = '';
      if (relPath[0] !== '') relPath.unshift('');
      if (relPath.length < 2) relPath.unshift('');
      result.pathname = relPath.join('/');
    } else {
      result.pathname = relative.pathname;
    }
    result.search = relative.search;
    result.query = relative.query;
    result.host = relative.host || '';
    result.auth = relative.auth;
    result.hostname = relative.hostname || relative.host;
    result.port = relative.port;
    // to support http.request
    if (result.pathname || result.search) {
      var p = result.pathname || '';
      var s = result.search || '';
      result.path = p + s;
    }
    result.slashes = result.slashes || relative.slashes;
    result.href = result.format();
    return result;
  }

  var isSourceAbs = result.pathname && result.pathname.charAt(0) === '/',
      isRelAbs = relative.host || relative.pathname && relative.pathname.charAt(0) === '/',
      mustEndAbs = isRelAbs || isSourceAbs || result.host && relative.pathname,
      removeAllDots = mustEndAbs,
      srcPath = result.pathname && result.pathname.split('/') || [],
      relPath = relative.pathname && relative.pathname.split('/') || [],
      psychotic = result.protocol && !slashedProtocol[result.protocol];

  // if the url is a non-slashed url, then relative
  // links like ../.. should be able
  // to crawl up to the hostname, as well.  This is strange.
  // result.protocol has already been set by now.
  // Later on, put the first path part into the host field.
  if (psychotic) {
    result.hostname = '';
    result.port = null;
    if (result.host) {
      if (srcPath[0] === '') srcPath[0] = result.host;else srcPath.unshift(result.host);
    }
    result.host = '';
    if (relative.protocol) {
      relative.hostname = null;
      relative.port = null;
      if (relative.host) {
        if (relPath[0] === '') relPath[0] = relative.host;else relPath.unshift(relative.host);
      }
      relative.host = null;
    }
    mustEndAbs = mustEndAbs && (relPath[0] === '' || srcPath[0] === '');
  }

  if (isRelAbs) {
    // it's absolute.
    result.host = relative.host || relative.host === '' ? relative.host : result.host;
    result.hostname = relative.hostname || relative.hostname === '' ? relative.hostname : result.hostname;
    result.search = relative.search;
    result.query = relative.query;
    srcPath = relPath;
    // fall through to the dot-handling below.
  } else if (relPath.length) {
    // it's relative
    // throw away the existing file, and take the new path instead.
    if (!srcPath) srcPath = [];
    srcPath.pop();
    srcPath = srcPath.concat(relPath);
    result.search = relative.search;
    result.query = relative.query;
  } else if (!util.isNullOrUndefined(relative.search)) {
    // just pull out the search.
    // like href='?foo'.
    // Put this after the other two cases because it simplifies the booleans
    if (psychotic) {
      result.hostname = result.host = srcPath.shift();
      //occationaly the auth can get stuck only in host
      //this especially happens in cases like
      //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
      var authInHost = result.host && result.host.indexOf('@') > 0 ? result.host.split('@') : false;
      if (authInHost) {
        result.auth = authInHost.shift();
        result.host = result.hostname = authInHost.shift();
      }
    }
    result.search = relative.search;
    result.query = relative.query;
    //to support http.request
    if (!util.isNull(result.pathname) || !util.isNull(result.search)) {
      result.path = (result.pathname ? result.pathname : '') + (result.search ? result.search : '');
    }
    result.href = result.format();
    return result;
  }

  if (!srcPath.length) {
    // no path at all.  easy.
    // we've already handled the other stuff above.
    result.pathname = null;
    //to support http.request
    if (result.search) {
      result.path = '/' + result.search;
    } else {
      result.path = null;
    }
    result.href = result.format();
    return result;
  }

  // if a url ENDs in . or .., then it must get a trailing slash.
  // however, if it ends in anything else non-slashy,
  // then it must NOT get a trailing slash.
  var last = srcPath.slice(-1)[0];
  var hasTrailingSlash = (result.host || relative.host || srcPath.length > 1) && (last === '.' || last === '..') || last === '';

  // strip single dots, resolve double dots to parent dir
  // if the path tries to go above the root, `up` ends up > 0
  var up = 0;
  for (var i = srcPath.length; i >= 0; i--) {
    last = srcPath[i];
    if (last === '.') {
      srcPath.splice(i, 1);
    } else if (last === '..') {
      srcPath.splice(i, 1);
      up++;
    } else if (up) {
      srcPath.splice(i, 1);
      up--;
    }
  }

  // if the path is allowed to go above the root, restore leading ..s
  if (!mustEndAbs && !removeAllDots) {
    for (; up--; up) {
      srcPath.unshift('..');
    }
  }

  if (mustEndAbs && srcPath[0] !== '' && (!srcPath[0] || srcPath[0].charAt(0) !== '/')) {
    srcPath.unshift('');
  }

  if (hasTrailingSlash && srcPath.join('/').substr(-1) !== '/') {
    srcPath.push('');
  }

  var isAbsolute = srcPath[0] === '' || srcPath[0] && srcPath[0].charAt(0) === '/';

  // put the host back
  if (psychotic) {
    result.hostname = result.host = isAbsolute ? '' : srcPath.length ? srcPath.shift() : '';
    //occationaly the auth can get stuck only in host
    //this especially happens in cases like
    //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
    var authInHost = result.host && result.host.indexOf('@') > 0 ? result.host.split('@') : false;
    if (authInHost) {
      result.auth = authInHost.shift();
      result.host = result.hostname = authInHost.shift();
    }
  }

  mustEndAbs = mustEndAbs || result.host && srcPath.length;

  if (mustEndAbs && !isAbsolute) {
    srcPath.unshift('');
  }

  if (!srcPath.length) {
    result.pathname = null;
    result.path = null;
  } else {
    result.pathname = srcPath.join('/');
  }

  //to support request.http
  if (!util.isNull(result.pathname) || !util.isNull(result.search)) {
    result.path = (result.pathname ? result.pathname : '') + (result.search ? result.search : '');
  }
  result.auth = relative.auth || result.auth;
  result.slashes = result.slashes || relative.slashes;
  result.href = result.format();
  return result;
};

Url.prototype.parseHost = function () {
  var host = this.host;
  var port = portPattern.exec(host);
  if (port) {
    port = port[0];
    if (port !== ':') {
      this.port = port.substr(1);
    }
    host = host.substr(0, host.length - port.length);
  }
  if (host) this.hostname = host;
};

},{"./util":16,"punycode":3,"querystring":6}],16:[function(require,module,exports){
'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

module.exports = {
  isString: function isString(arg) {
    return typeof arg === 'string';
  },
  isObject: function isObject(arg) {
    return (typeof arg === 'undefined' ? 'undefined' : _typeof(arg)) === 'object' && arg !== null;
  },
  isNull: function isNull(arg) {
    return arg === null;
  },
  isNullOrUndefined: function isNullOrUndefined(arg) {
    return arg == null;
  }
};

},{}],17:[function(require,module,exports){
'use strict';

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
var byteToHex = [];
for (var i = 0; i < 256; ++i) {
  byteToHex[i] = (i + 0x100).toString(16).substr(1);
}

function bytesToUuid(buf, offset) {
  var i = offset || 0;
  var bth = byteToHex;
  // join used to fix memory issue caused by concatenation: https://bugs.chromium.org/p/v8/issues/detail?id=3175#c4
  return [bth[buf[i++]], bth[buf[i++]], bth[buf[i++]], bth[buf[i++]], '-', bth[buf[i++]], bth[buf[i++]], '-', bth[buf[i++]], bth[buf[i++]], '-', bth[buf[i++]], bth[buf[i++]], '-', bth[buf[i++]], bth[buf[i++]], bth[buf[i++]], bth[buf[i++]], bth[buf[i++]], bth[buf[i++]]].join('');
}

module.exports = bytesToUuid;

},{}],18:[function(require,module,exports){
'use strict';

// Unique ID creation requires a high quality random # generator.  In the
// browser this is a little complicated due to unknown quality of Math.random()
// and inconsistent support for the `crypto` API.  We do the best we can via
// feature-detection

// getRandomValues needs to be invoked in a context where "this" is a Crypto
// implementation. Also, find the complete implementation of crypto on IE11.
var getRandomValues = typeof crypto != 'undefined' && crypto.getRandomValues && crypto.getRandomValues.bind(crypto) || typeof msCrypto != 'undefined' && typeof window.msCrypto.getRandomValues == 'function' && msCrypto.getRandomValues.bind(msCrypto);

if (getRandomValues) {
  // WHATWG crypto RNG - http://wiki.whatwg.org/wiki/Crypto
  var rnds8 = new Uint8Array(16); // eslint-disable-line no-undef

  module.exports = function whatwgRNG() {
    getRandomValues(rnds8);
    return rnds8;
  };
} else {
  // Math.random()-based (RNG)
  //
  // If all else fails, use Math.random().  It's fast, but is of unspecified
  // quality.
  var rnds = new Array(16);

  module.exports = function mathRNG() {
    for (var i = 0, r; i < 16; i++) {
      if ((i & 0x03) === 0) r = Math.random() * 0x100000000;
      rnds[i] = r >>> ((i & 0x03) << 3) & 0xff;
    }

    return rnds;
  };
}

},{}],19:[function(require,module,exports){
// Adapted from Chris Veness' SHA1 code at
// http://www.movable-type.co.uk/scripts/sha1.html
'use strict';

function f(s, x, y, z) {
  switch (s) {
    case 0:
      return x & y ^ ~x & z;
    case 1:
      return x ^ y ^ z;
    case 2:
      return x & y ^ x & z ^ y & z;
    case 3:
      return x ^ y ^ z;
  }
}

function ROTL(x, n) {
  return x << n | x >>> 32 - n;
}

function sha1(bytes) {
  var K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
  var H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

  if (typeof bytes == 'string') {
    var msg = unescape(encodeURIComponent(bytes)); // UTF8 escape
    bytes = new Array(msg.length);
    for (var i = 0; i < msg.length; i++) {
      bytes[i] = msg.charCodeAt(i);
    }
  }

  bytes.push(0x80);

  var l = bytes.length / 4 + 2;
  var N = Math.ceil(l / 16);
  var M = new Array(N);

  for (var i = 0; i < N; i++) {
    M[i] = new Array(16);
    for (var j = 0; j < 16; j++) {
      M[i][j] = bytes[i * 64 + j * 4] << 24 | bytes[i * 64 + j * 4 + 1] << 16 | bytes[i * 64 + j * 4 + 2] << 8 | bytes[i * 64 + j * 4 + 3];
    }
  }

  M[N - 1][14] = (bytes.length - 1) * 8 / Math.pow(2, 32);M[N - 1][14] = Math.floor(M[N - 1][14]);
  M[N - 1][15] = (bytes.length - 1) * 8 & 0xffffffff;

  for (var i = 0; i < N; i++) {
    var W = new Array(80);

    for (var t = 0; t < 16; t++) {
      W[t] = M[i][t];
    }for (var t = 16; t < 80; t++) {
      W[t] = ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    var a = H[0];
    var b = H[1];
    var c = H[2];
    var d = H[3];
    var e = H[4];

    for (var t = 0; t < 80; t++) {
      var s = Math.floor(t / 20);
      var T = ROTL(a, 5) + f(s, b, c, d) + e + K[s] + W[t] >>> 0;
      e = d;
      d = c;
      c = ROTL(b, 30) >>> 0;
      b = a;
      a = T;
    }

    H[0] = H[0] + a >>> 0;
    H[1] = H[1] + b >>> 0;
    H[2] = H[2] + c >>> 0;
    H[3] = H[3] + d >>> 0;
    H[4] = H[4] + e >>> 0;
  }

  return [H[0] >> 24 & 0xff, H[0] >> 16 & 0xff, H[0] >> 8 & 0xff, H[0] & 0xff, H[1] >> 24 & 0xff, H[1] >> 16 & 0xff, H[1] >> 8 & 0xff, H[1] & 0xff, H[2] >> 24 & 0xff, H[2] >> 16 & 0xff, H[2] >> 8 & 0xff, H[2] & 0xff, H[3] >> 24 & 0xff, H[3] >> 16 & 0xff, H[3] >> 8 & 0xff, H[3] & 0xff, H[4] >> 24 & 0xff, H[4] >> 16 & 0xff, H[4] >> 8 & 0xff, H[4] & 0xff];
}

module.exports = sha1;

},{}],20:[function(require,module,exports){
'use strict';

var bytesToUuid = require('./bytesToUuid');

function uuidToBytes(uuid) {
  // Note: We assume we're being passed a valid uuid string
  var bytes = [];
  uuid.replace(/[a-fA-F0-9]{2}/g, function (hex) {
    bytes.push(parseInt(hex, 16));
  });

  return bytes;
}

function stringToBytes(str) {
  str = unescape(encodeURIComponent(str)); // UTF8 escape
  var bytes = new Array(str.length);
  for (var i = 0; i < str.length; i++) {
    bytes[i] = str.charCodeAt(i);
  }
  return bytes;
}

module.exports = function (name, version, hashfunc) {
  var generateUUID = function generateUUID(value, namespace, buf, offset) {
    var off = buf && offset || 0;

    if (typeof value == 'string') value = stringToBytes(value);
    if (typeof namespace == 'string') namespace = uuidToBytes(namespace);

    if (!Array.isArray(value)) throw TypeError('value must be an array of bytes');
    if (!Array.isArray(namespace) || namespace.length !== 16) throw TypeError('namespace must be uuid string or an Array of 16 byte values');

    // Per 4.3
    var bytes = hashfunc(namespace.concat(value));
    bytes[6] = bytes[6] & 0x0f | version;
    bytes[8] = bytes[8] & 0x3f | 0x80;

    if (buf) {
      for (var idx = 0; idx < 16; ++idx) {
        buf[off + idx] = bytes[idx];
      }
    }

    return buf || bytesToUuid(bytes);
  };

  // Function#name is not settable on some platforms (#270)
  try {
    generateUUID.name = name;
  } catch (err) {}

  // Pre-defined namespaces, per Appendix C
  generateUUID.DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
  generateUUID.URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';

  return generateUUID;
};

},{"./bytesToUuid":17}],21:[function(require,module,exports){
'use strict';

var rng = require('./lib/rng');
var bytesToUuid = require('./lib/bytesToUuid');

function v4(options, buf, offset) {
  var i = buf && offset || 0;

  if (typeof options == 'string') {
    buf = options === 'binary' ? new Array(16) : null;
    options = null;
  }
  options = options || {};

  var rnds = options.random || (options.rng || rng)();

  // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`
  rnds[6] = rnds[6] & 0x0f | 0x40;
  rnds[8] = rnds[8] & 0x3f | 0x80;

  // Copy bytes to buffer, if provided
  if (buf) {
    for (var ii = 0; ii < 16; ++ii) {
      buf[i + ii] = rnds[ii];
    }
  }

  return buf || bytesToUuid(rnds);
}

module.exports = v4;

},{"./lib/bytesToUuid":17,"./lib/rng":18}],22:[function(require,module,exports){
'use strict';

var v35 = require('./lib/v35.js');
var sha1 = require('./lib/sha1');
module.exports = v35('v5', 0x50, sha1);

},{"./lib/sha1":19,"./lib/v35.js":20}],23:[function(require,module,exports){
'use strict';

var v4 = require('uuid/v4'),
    v5 = require('uuid/v5');

var uuidv4 = function uuidv4() {
  return v4();
};

uuidv4.regex = {
  v4: /^([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})|(0{8}-0{4}-0{4}-0{4}-0{12})$/,
  v5: /^([a-f0-9]{8}-[a-f0-9]{4}-5[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})|(0{8}-0{4}-0{4}-0{4}-0{12})$/
};

uuidv4.is = function (value) {
  if (!value) {
    return false;
  }

  return uuidv4.regex.v4.test(value) || uuidv4.regex.v5.test(value);
};

uuidv4.empty = function () {
  return '00000000-0000-0000-0000-000000000000';
};

uuidv4.fromString = function (text) {
  if (!text) {
    throw new Error('Text is missing.');
  }

  var namespace = 'bb5d0ffa-9a4c-4d7c-8fc2-0a7d2220ba45';

  var uuidFromString = v5(text, namespace);

  return uuidFromString;
};

module.exports = uuidv4;

},{"uuid/v4":21,"uuid/v5":22}],24:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __read = undefined && undefined.__read || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o),
        r,
        ar = [],
        e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) {
            ar.push(r.value);
        }
    } catch (error) {
        e = { error: error };
    } finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        } finally {
            if (e) throw e.error;
        }
    }
    return ar;
};
var __spread = undefined && undefined.__spread || function () {
    for (var ar = [], i = 0; i < arguments.length; i++) {
        ar = ar.concat(__read(arguments[i]));
    }return ar;
};
var __values = undefined && undefined.__values || function (o) {
    var s = typeof Symbol === "function" && Symbol.iterator,
        m = s && o[s],
        i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function next() {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
};
Object.defineProperty(exports, "__esModule", { value: true });
var shadowsocks_config_1 = require("ShadowsocksConfig/shadowsocks_config");
var errors = require("../model/errors");
var events = require("../model/events");
var settings_1 = require("./settings");
// If s is a URL whose fragment contains a Shadowsocks URL then return that Shadowsocks URL,
// otherwise return s.
function unwrapInvite(s) {
    try {
        var url = new URL(s);
        if (url.hash) {
            var decodedFragment = decodeURIComponent(url.hash);
            // Search in the fragment for ss:// for two reasons:
            //  - URL.hash includes the leading # (what).
            //  - When a user opens invite.html#ENCODEDSSURL in their browser, the website (currently)
            //    redirects to invite.html#/en/invite/ENCODEDSSURL. Since copying that redirected URL
            //    seems like a reasonable thing to do, let's support those URLs too.
            var possibleShadowsocksUrl = decodedFragment.substring(decodedFragment.indexOf('ss://'));
            if (new URL(possibleShadowsocksUrl).protocol === 'ss:') {
                return possibleShadowsocksUrl;
            }
        }
    } catch (e) {
        // Something wasn't a URL, or it couldn't be decoded - no problem, people put all kinds of
        // crazy things in the clipboard.
    }
    return s;
}
exports.unwrapInvite = unwrapInvite;
var App = /** @class */function () {
    function App(eventQueue, serverRepo, rootEl, debugMode, urlInterceptor, clipboard, errorReporter, settings, environmentVars, updater, quitApplication, document) {
        if (document === void 0) {
            document = window.document;
        }
        this.eventQueue = eventQueue;
        this.serverRepo = serverRepo;
        this.rootEl = rootEl;
        this.debugMode = debugMode;
        this.clipboard = clipboard;
        this.errorReporter = errorReporter;
        this.settings = settings;
        this.environmentVars = environmentVars;
        this.updater = updater;
        this.quitApplication = quitApplication;
        this.ignoredAccessKeys = {};
        this.serverListEl = rootEl.$.serversView.$.serverList;
        this.feedbackViewEl = rootEl.$.feedbackView;
        this.syncServersToUI();
        this.syncConnectivityStateToServerCards();
        rootEl.$.aboutView.version = environmentVars.APP_VERSION;
        this.localize = this.rootEl.localize.bind(this.rootEl);
        if (urlInterceptor) {
            this.registerUrlInterceptionListener(urlInterceptor);
        } else {
            console.warn('no urlInterceptor, ss:// urls will not be intercepted');
        }
        this.clipboard.setListener(this.handleClipboardText.bind(this));
        this.updater.setListener(this.updateDownloaded.bind(this));
        // Register Cordova mobile foreground event to sync server connectivity.
        document.addEventListener('resume', this.syncConnectivityStateToServerCards.bind(this));
        // Register handlers for events fired by Polymer components.
        this.rootEl.addEventListener('PromptAddServerRequested', this.requestPromptAddServer.bind(this));
        this.rootEl.addEventListener('AddServerConfirmationRequested', this.requestAddServerConfirmation.bind(this));
        this.rootEl.addEventListener('AddServerRequested', this.requestAddServer.bind(this));
        this.rootEl.addEventListener('IgnoreServerRequested', this.requestIgnoreServer.bind(this));
        this.rootEl.addEventListener('ConnectPressed', this.connectServer.bind(this));
        this.rootEl.addEventListener('DisconnectPressed', this.disconnectServer.bind(this));
        this.rootEl.addEventListener('ForgetPressed', this.forgetServer.bind(this));
        this.rootEl.addEventListener('RenameRequested', this.renameServer.bind(this));
        this.rootEl.addEventListener('QuitPressed', this.quitApplication.bind(this));
        this.rootEl.addEventListener('AutoConnectDialogDismissed', this.autoConnectDialogDismissed.bind(this));
        this.rootEl.addEventListener('ShowServerRename', this.rootEl.showServerRename.bind(this.rootEl));
        this.feedbackViewEl.$.submitButton.addEventListener('tap', this.submitFeedback.bind(this));
        this.rootEl.addEventListener('PrivacyTermsAcked', this.ackPrivacyTerms.bind(this));
        // Register handlers for events published to our event queue.
        this.eventQueue.subscribe(events.ServerAdded, this.showServerAdded.bind(this));
        this.eventQueue.subscribe(events.ServerForgotten, this.showServerForgotten.bind(this));
        this.eventQueue.subscribe(events.ServerRenamed, this.showServerRenamed.bind(this));
        this.eventQueue.subscribe(events.ServerForgetUndone, this.showServerForgetUndone.bind(this));
        this.eventQueue.subscribe(events.ServerConnected, this.showServerConnected.bind(this));
        this.eventQueue.subscribe(events.ServerDisconnected, this.showServerDisconnected.bind(this));
        this.eventQueue.subscribe(events.ServerReconnecting, this.showServerReconnecting.bind(this));
        this.eventQueue.startPublishing();
        if (!this.arePrivacyTermsAcked()) {
            this.displayPrivacyView();
        }
        this.displayZeroStateUi();
        this.pullClipboardText();
    }
    App.prototype.showLocalizedError = function (e, toastDuration) {
        var _this = this;
        if (toastDuration === void 0) {
            toastDuration = 10000;
        }
        var messageKey;
        var messageParams;
        var buttonKey;
        var buttonHandler;
        var buttonLink;
        if (e instanceof errors.VpnPermissionNotGranted) {
            messageKey = 'outline-plugin-error-vpn-permission-not-granted';
        } else if (e instanceof errors.InvalidServerCredentials) {
            messageKey = 'outline-plugin-error-invalid-server-credentials';
        } else if (e instanceof errors.RemoteUdpForwardingDisabled) {
            messageKey = 'outline-plugin-error-udp-forwarding-not-enabled';
        } else if (e instanceof errors.ServerUnreachable) {
            messageKey = 'outline-plugin-error-server-unreachable';
        } else if (e instanceof errors.FeedbackSubmissionError) {
            messageKey = 'error-feedback-submission';
        } else if (e instanceof errors.ServerUrlInvalid) {
            messageKey = 'error-invalid-access-key';
        } else if (e instanceof errors.ServerIncompatible) {
            messageKey = 'error-server-incompatible';
        } else if (e instanceof errors.OperationTimedOut) {
            messageKey = 'error-timeout';
        } else if (e instanceof errors.ShadowsocksStartFailure && this.isWindows()) {
            // Fall through to `error-unexpected` for other platforms.
            messageKey = 'outline-plugin-error-antivirus';
            buttonKey = 'fix-this';
            buttonLink = 'https://s3.amazonaws.com/outline-vpn/index.html#/en/support/antivirusBlock';
        } else if (e instanceof errors.ConfigureSystemProxyFailure) {
            messageKey = 'outline-plugin-error-routing-tables';
            buttonKey = 'feedback-page-title';
            buttonHandler = function buttonHandler() {
                // TODO: Drop-down has no selected item, why not?
                _this.rootEl.changePage('feedback');
            };
        } else if (e instanceof errors.NoAdminPermissions) {
            messageKey = 'outline-plugin-error-admin-permissions';
        } else if (e instanceof errors.UnsupportedRoutingTable) {
            messageKey = 'outline-plugin-error-unsupported-routing-table';
        } else if (e instanceof errors.ServerAlreadyAdded) {
            messageKey = 'error-server-already-added';
            messageParams = ['serverName', e.server.name];
        } else if (e instanceof errors.SystemConfigurationException) {
            messageKey = 'outline-plugin-error-system-configuration';
        } else {
            messageKey = 'error-unexpected';
        }
        var message = messageParams ? this.localize.apply(this, __spread([messageKey], messageParams)) : this.localize(messageKey);
        // Defer by 500ms so that this toast is shown after any toasts that get shown when any
        // currently-in-flight domain events land (e.g. fake servers added).
        if (this.rootEl && this.rootEl.async) {
            this.rootEl.async(function () {
                _this.rootEl.showToast(message, toastDuration, buttonKey ? _this.localize(buttonKey) : undefined, buttonHandler, buttonLink);
            }, 500);
        }
    };
    App.prototype.pullClipboardText = function () {
        var _this = this;
        this.clipboard.getContents().then(function (text) {
            _this.handleClipboardText(text);
        }, function (e) {
            console.warn('cannot read clipboard, system may lack clipboard support');
        });
    };
    App.prototype.showServerConnected = function (event) {
        console.debug("server " + event.server.id + " connected");
        var card = this.serverListEl.getServerCard(event.server.id);
        card.state = 'CONNECTED';
    };
    App.prototype.showServerDisconnected = function (event) {
        console.debug("server " + event.server.id + " disconnected");
        try {
            this.serverListEl.getServerCard(event.server.id).state = 'DISCONNECTED';
        } catch (e) {
            console.warn('server card not found after disconnection event, assuming forgotten');
        }
    };
    App.prototype.showServerReconnecting = function (event) {
        console.debug("server " + event.server.id + " reconnecting");
        var card = this.serverListEl.getServerCard(event.server.id);
        card.state = 'RECONNECTING';
    };
    App.prototype.displayZeroStateUi = function () {
        if (this.rootEl.$.serversView.shouldShowZeroState) {
            this.rootEl.$.addServerView.openAddServerSheet();
        }
    };
    App.prototype.arePrivacyTermsAcked = function () {
        try {
            return this.settings.get(settings_1.SettingsKey.PRIVACY_ACK) === 'true';
        } catch (e) {
            console.error("could not read privacy acknowledgement setting, assuming not acknowledged");
        }
        return false;
    };
    App.prototype.displayPrivacyView = function () {
        this.rootEl.$.serversView.hidden = true;
        this.rootEl.$.privacyView.hidden = false;
    };
    App.prototype.ackPrivacyTerms = function () {
        this.rootEl.$.serversView.hidden = false;
        this.rootEl.$.privacyView.hidden = true;
        this.settings.set(settings_1.SettingsKey.PRIVACY_ACK, 'true');
    };
    App.prototype.handleClipboardText = function (text) {
        // Shorten, sanitise.
        // Note that we always check the text, even if the contents are same as last time, because we
        // keep an in-memory cache of user-ignored access keys.
        text = text.substring(0, 1000).trim();
        try {
            this.confirmAddServer(text, true);
        } catch (err) {
            // Don't alert the user; high false positive rate.
        }
    };
    App.prototype.updateDownloaded = function () {
        this.rootEl.showToast(this.localize('update-downloaded'), 60000);
    };
    App.prototype.requestPromptAddServer = function () {
        this.rootEl.promptAddServer();
    };
    // Caches an ignored server access key so we don't prompt the user to add it again.
    App.prototype.requestIgnoreServer = function (event) {
        var accessKey = event.detail.accessKey;
        this.ignoredAccessKeys[accessKey] = true;
    };
    App.prototype.requestAddServer = function (event) {
        try {
            this.serverRepo.add(event.detail.serverConfig);
        } catch (err) {
            this.changeToDefaultPage();
            this.showLocalizedError(err);
        }
    };
    App.prototype.requestAddServerConfirmation = function (event) {
        var accessKey = event.detail.accessKey;
        console.debug('Got add server confirmation request from UI');
        try {
            this.confirmAddServer(accessKey);
        } catch (err) {
            console.error('Failed to confirm add sever.', err);
            var addServerView = this.rootEl.$.addServerView;
            addServerView.$.accessKeyInput.invalid = true;
        }
    };
    App.prototype.confirmAddServer = function (accessKey, fromClipboard) {
        if (fromClipboard === void 0) {
            fromClipboard = false;
        }
        var addServerView = this.rootEl.$.addServerView;
        accessKey = unwrapInvite(accessKey);
        if (fromClipboard && accessKey in this.ignoredAccessKeys) {
            return console.debug('Ignoring access key');
        } else if (fromClipboard && addServerView.isAddingServer()) {
            return console.debug('Already adding a server');
        }
        // Expect SHADOWSOCKS_URI.parse to throw on invalid access key; propagate any exception.
        var shadowsocksConfig = null;
        try {
            shadowsocksConfig = shadowsocks_config_1.SHADOWSOCKS_URI.parse(accessKey);
        } catch (error) {
            var message = !!error.message ? error.message : 'Failed to parse access key';
            throw new errors.ServerUrlInvalid(message);
        }
        if (shadowsocksConfig.host.isIPv6) {
            throw new errors.ServerIncompatible('Only IPv4 addresses are currently supported');
        }
        var name = shadowsocksConfig.extra.outline ? this.localize('server-default-name-outline') : shadowsocksConfig.tag.data ? shadowsocksConfig.tag.data : this.localize('server-default-name');
        var serverConfig = {
            host: shadowsocksConfig.host.data,
            port: shadowsocksConfig.port.data,
            method: shadowsocksConfig.method.data,
            password: shadowsocksConfig.password.data,
            name: name
        };
        if (!this.serverRepo.containsServer(serverConfig)) {
            // Only prompt the user to add new servers.
            try {
                addServerView.openAddServerConfirmationSheet(accessKey, serverConfig);
            } catch (err) {
                console.error('Failed to open add sever confirmation sheet:', err.message);
                if (!fromClipboard) this.showLocalizedError();
            }
        } else if (!fromClipboard) {
            // Display error message if this is not a clipboard add.
            addServerView.close();
            this.showLocalizedError(new errors.ServerAlreadyAdded(this.serverRepo.createServer('', serverConfig, this.eventQueue)));
        }
    };
    App.prototype.forgetServer = function (event) {
        var _this = this;
        var serverId = event.detail.serverId;
        var server = this.serverRepo.getById(serverId);
        if (!server) {
            console.error("No server with id " + serverId);
            return this.showLocalizedError();
        }
        var onceNotRunning = server.checkRunning().then(function (isRunning) {
            return isRunning ? _this.disconnectServer(event) : Promise.resolve();
        });
        onceNotRunning.then(function () {
            _this.serverRepo.forget(serverId);
        });
    };
    App.prototype.renameServer = function (event) {
        var serverId = event.detail.serverId;
        var newName = event.detail.newName;
        this.serverRepo.rename(serverId, newName);
    };
    App.prototype.connectServer = function (event) {
        var _this = this;
        var serverId = event.detail.serverId;
        if (!serverId) {
            throw new Error("connectServer event had no server ID");
        }
        var server = this.getServerByServerId(serverId);
        var card = this.getCardByServerId(serverId);
        console.log("connecting to server connecting to server" + serverId);
        card.state = 'CONNECTING';
        server.connect().then(function () {
            card.state = 'CONNECTED';
            console.log("connected to server " + serverId);
            _this.rootEl.showToast(_this.localize('server-connected', 'serverName', server.name));
            _this.maybeShowAutoConnectDialog();
        }, function (e) {
            card.state = 'DISCONNECTED';
            _this.showLocalizedError(e);
            console.error("could not connect to server " + serverId + ": " + e.name);
            if (!(e instanceof errors.RegularNativeError)) {
                _this.errorReporter.report("connection failure: " + e.name, 'connection-failure');
            }
        });
    };
    App.prototype.maybeShowAutoConnectDialog = function () {
        var dismissed = false;
        try {
            dismissed = this.settings.get(settings_1.SettingsKey.AUTO_CONNECT_DIALOG_DISMISSED) === 'true';
        } catch (e) {
            console.error("Failed to read auto-connect dialog status, assuming not dismissed: " + e);
        }
        if (!dismissed) {
            this.rootEl.$.serversView.$.autoConnectDialog.show();
        }
    };
    App.prototype.autoConnectDialogDismissed = function () {
        this.settings.set(settings_1.SettingsKey.AUTO_CONNECT_DIALOG_DISMISSED, 'true');
    };
    App.prototype.disconnectServer = function (event) {
        var _this = this;
        var serverId = event.detail.serverId;
        if (!serverId) {
            throw new Error("disconnectServer event had no server ID");
        }
        var server = this.getServerByServerId(serverId);
        var card = this.getCardByServerId(serverId);
        console.log("disconnecting from server " + serverId);
        card.state = 'DISCONNECTING';
        server.disconnect().then(function () {
            card.state = 'DISCONNECTED';
            console.log("disconnected from server " + serverId);
            _this.rootEl.showToast(_this.localize('server-disconnected', 'serverName', server.name));
        }, function (e) {
            card.state = 'CONNECTED';
            _this.showLocalizedError(e);
            console.warn("could not disconnect from server " + serverId + ": " + e.name);
        });
    };
    App.prototype.submitFeedback = function (event) {
        var _this = this;
        var formData = this.feedbackViewEl.getValidatedFormData();
        if (!formData) {
            return;
        }
        var feedback = formData.feedback,
            category = formData.category,
            email = formData.email;
        this.rootEl.$.feedbackView.submitting = true;
        this.errorReporter.report(feedback, category, email).then(function () {
            _this.rootEl.$.feedbackView.submitting = false;
            _this.rootEl.$.feedbackView.resetForm();
            _this.changeToDefaultPage();
            _this.rootEl.showToast(_this.rootEl.localize('feedback-thanks'));
        }, function (err) {
            _this.rootEl.$.feedbackView.submitting = false;
            _this.showLocalizedError(new errors.FeedbackSubmissionError());
        });
    };
    // EventQueue event handlers:
    App.prototype.showServerAdded = function (event) {
        var server = event.server;
        console.debug('Server added');
        this.syncServersToUI();
        this.syncServerConnectivityState(server);
        this.changeToDefaultPage();
        this.rootEl.showToast(this.localize('server-added', 'serverName', server.name));
    };
    App.prototype.showServerForgotten = function (event) {
        var _this = this;
        var server = event.server;
        console.debug('Server forgotten');
        this.syncServersToUI();
        this.rootEl.showToast(this.localize('server-forgotten', 'serverName', server.name), 10000, this.localize('undo-button-label'), function () {
            _this.serverRepo.undoForget(server.id);
        });
    };
    App.prototype.showServerForgetUndone = function (event) {
        this.syncServersToUI();
        var server = event.server;
        this.rootEl.showToast(this.localize('server-forgotten-undo', 'serverName', server.name));
    };
    App.prototype.showServerRenamed = function (event) {
        var server = event.server;
        console.debug('Server renamed');
        this.serverListEl.getServerCard(server.id).serverName = server.name;
        this.rootEl.showToast(this.localize('server-rename-complete'));
    };
    // Helpers:
    App.prototype.syncServersToUI = function () {
        this.rootEl.servers = this.serverRepo.getAll();
    };
    App.prototype.syncConnectivityStateToServerCards = function () {
        var e_1, _a;
        try {
            for (var _b = __values(this.serverRepo.getAll()), _c = _b.next(); !_c.done; _c = _b.next()) {
                var server = _c.value;
                this.syncServerConnectivityState(server);
            }
        } catch (e_1_1) {
            e_1 = { error: e_1_1 };
        } finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
            } finally {
                if (e_1) throw e_1.error;
            }
        }
    };
    App.prototype.syncServerConnectivityState = function (server) {
        var _this = this;
        server.checkRunning().then(function (isRunning) {
            var card = _this.serverListEl.getServerCard(server.id);
            if (!isRunning) {
                card.state = 'DISCONNECTED';
                return;
            }
            server.checkReachable().then(function (isReachable) {
                if (isReachable) {
                    card.state = 'CONNECTED';
                } else {
                    console.log("Server " + server.id + " reconnecting");
                    card.state = 'RECONNECTING';
                }
            });
        }).catch(function (e) {
            console.error('Failed to sync server connectivity state', e);
        });
    };
    App.prototype.registerUrlInterceptionListener = function (urlInterceptor) {
        var _this = this;
        urlInterceptor.registerListener(function (url) {
            if (!url || !unwrapInvite(url).startsWith('ss://')) {
                // This check is necessary to ignore empty and malformed install-referrer URLs in Android
                // while allowing ss:// and invite URLs.
                // TODO: Stop receiving install referrer intents so we can remove this.
                return console.debug("Ignoring intercepted non-shadowsocks url");
            }
            try {
                _this.confirmAddServer(url);
            } catch (err) {
                _this.showLocalizedErrorInDefaultPage(err);
            }
        });
    };
    App.prototype.changeToDefaultPage = function () {
        this.rootEl.changePage(this.rootEl.DEFAULT_PAGE);
    };
    // Returns the server having serverId, throws if the server cannot be found.
    App.prototype.getServerByServerId = function (serverId) {
        var server = this.serverRepo.getById(serverId);
        if (!server) {
            throw new Error("could not find server with ID " + serverId);
        }
        return server;
    };
    // Returns the card associated with serverId, throws if no such card exists.
    // See server-list.html.
    App.prototype.getCardByServerId = function (serverId) {
        return this.serverListEl.getServerCard(serverId);
    };
    App.prototype.showLocalizedErrorInDefaultPage = function (err) {
        this.changeToDefaultPage();
        this.showLocalizedError(err);
    };
    App.prototype.isWindows = function () {
        return !('cordova' in window);
    };
    return App;
}();
exports.App = App;

},{"../model/errors":36,"../model/events":37,"./settings":33,"ShadowsocksConfig/shadowsocks_config":1}],25:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
// Generic clipboard. Implementations should only have to implement getContents().
var AbstractClipboard = /** @class */function () {
    function AbstractClipboard() {
        this.listener = null;
    }
    AbstractClipboard.prototype.getContents = function () {
        return Promise.reject(new Error('unimplemented skeleton method'));
    };
    AbstractClipboard.prototype.setListener = function (listener) {
        this.listener = listener;
    };
    AbstractClipboard.prototype.emitEvent = function () {
        if (this.listener) {
            this.getContents().then(this.listener);
        }
    };
    return AbstractClipboard;
}();
exports.AbstractClipboard = AbstractClipboard;

},{}],26:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __extends = undefined && undefined.__extends || function () {
    var _extendStatics = function extendStatics(d, b) {
        _extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function (d, b) {
            d.__proto__ = b;
        } || function (d, b) {
            for (var p in b) {
                if (b.hasOwnProperty(p)) d[p] = b[p];
            }
        };
        return _extendStatics(d, b);
    };
    return function (d, b) {
        _extendStatics(d, b);
        function __() {
            this.constructor = d;
        }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
}();
Object.defineProperty(exports, "__esModule", { value: true });
/// <reference path='../../types/ambient/outlinePlugin.d.ts'/>
/// <reference path='../../types/ambient/webintents.d.ts'/>
var Raven = require("raven-js");
var clipboard_1 = require("./clipboard");
var error_reporter_1 = require("./error_reporter");
var fake_connection_1 = require("./fake_connection");
var main_1 = require("./main");
var outline_server_1 = require("./outline_server");
var updater_1 = require("./updater");
var interceptors = require("./url_interceptor");
// Pushes a clipboard event whenever the app is brought to the foreground.
var CordovaClipboard = /** @class */function (_super) {
    __extends(CordovaClipboard, _super);
    function CordovaClipboard() {
        var _this = _super.call(this) || this;
        document.addEventListener('resume', _this.emitEvent.bind(_this));
        return _this;
    }
    CordovaClipboard.prototype.getContents = function () {
        return new Promise(function (resolve, reject) {
            cordova.plugins.clipboard.paste(resolve, reject);
        });
    };
    return CordovaClipboard;
}(clipboard_1.AbstractClipboard);
// Adds reports from the (native) Cordova plugin.
var CordovaErrorReporter = /** @class */function (_super) {
    __extends(CordovaErrorReporter, _super);
    function CordovaErrorReporter(appVersion, appBuildNumber, dsn, nativeDsn) {
        var _this = _super.call(this, appVersion, dsn, { 'build.number': appBuildNumber }) || this;
        cordova.plugins.outline.log.initialize(nativeDsn).catch(console.error);
        return _this;
    }
    CordovaErrorReporter.prototype.report = function (userFeedback, feedbackCategory, userEmail) {
        return _super.prototype.report.call(this, userFeedback, feedbackCategory, userEmail).then(function () {
            return cordova.plugins.outline.log.send(Raven.lastEventId());
        });
    };
    return CordovaErrorReporter;
}(error_reporter_1.SentryErrorReporter);
exports.CordovaErrorReporter = CordovaErrorReporter;
// This class should only be instantiated after Cordova fires the deviceready event.
var CordovaPlatform = /** @class */function () {
    function CordovaPlatform() {}
    CordovaPlatform.isBrowser = function () {
        return device.platform === 'browser';
    };
    CordovaPlatform.prototype.hasDeviceSupport = function () {
        return !CordovaPlatform.isBrowser();
    };
    CordovaPlatform.prototype.getPersistentServerFactory = function () {
        var _this = this;
        return function (serverId, config, eventQueue) {
            return new outline_server_1.OutlineServer(serverId, config, _this.hasDeviceSupport() ? new cordova.plugins.outline.Connection(config, serverId) : new fake_connection_1.FakeOutlineConnection(config, serverId), eventQueue);
        };
    };
    CordovaPlatform.prototype.getUrlInterceptor = function () {
        if (device.platform === 'iOS' || device.platform === 'Mac OS X') {
            return new interceptors.AppleUrlInterceptor(appleLaunchUrl);
        } else if (device.platform === 'Android') {
            return new interceptors.AndroidUrlInterceptor();
        }
        console.warn('no intent interceptor available');
        return new interceptors.UrlInterceptor();
    };
    CordovaPlatform.prototype.getClipboard = function () {
        return new CordovaClipboard();
    };
    CordovaPlatform.prototype.getErrorReporter = function (env) {
        return this.hasDeviceSupport() ? new CordovaErrorReporter(env.APP_VERSION, env.APP_BUILD_NUMBER, env.SENTRY_DSN, env.SENTRY_NATIVE_DSN) : new error_reporter_1.SentryErrorReporter(env.APP_VERSION, env.SENTRY_DSN, {});
    };
    CordovaPlatform.prototype.getUpdater = function () {
        return new updater_1.AbstractUpdater();
    };
    CordovaPlatform.prototype.quitApplication = function () {
        // Only used in macOS because menu bar apps provide no alternative way of quitting.
        cordova.plugins.outline.quitApplication();
    };
    return CordovaPlatform;
}();
// https://cordova.apache.org/docs/en/latest/cordova/events/events.html#deviceready
var onceDeviceReady = new Promise(function (resolve) {
    document.addEventListener('deviceready', resolve);
});
// cordova-[ios|osx] call a global function with this signature when a URL is
// intercepted. We handle URL interceptions with an intent interceptor; however,
// when the app is launched via URL our start up sequence misses the call due to
// a race. Define the function temporarily here, and set a global variable.
var appleLaunchUrl;
window.handleOpenURL = function (url) {
    appleLaunchUrl = url;
};
onceDeviceReady.then(function () {
    main_1.main(new CordovaPlatform());
});

},{"./clipboard":25,"./error_reporter":28,"./fake_connection":29,"./main":30,"./outline_server":31,"./updater":34,"./url_interceptor":35,"raven-js":10}],27:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
// Keep these in sync with the EnvironmentVariables interface above.
var ENV_KEYS = {
    APP_VERSION: 'APP_VERSION',
    APP_BUILD_NUMBER: 'APP_BUILD_NUMBER',
    SENTRY_DSN: 'SENTRY_DSN',
    SENTRY_NATIVE_DSN: 'SENTRY_NATIVE_DSN'
};
function validateEnvVars(json) {
    for (var key in ENV_KEYS) {
        if (!json.hasOwnProperty(key)) {
            throw new Error("Missing environment variable: " + key);
        }
    }
}
// According to http://caniuse.com/#feat=fetch fetch didn't hit iOS Safari
// until v10.3 released 3/26/17, so use XMLHttpRequest instead.
exports.onceEnvVars = new Promise(function (resolve, reject) {
    var xhr = new XMLHttpRequest();
    xhr.onload = function () {
        try {
            var json = JSON.parse(xhr.responseText);
            validateEnvVars(json);
            console.debug('Resolving with envVars:', json);
            resolve(json);
        } catch (err) {
            reject(err);
        }
    };
    xhr.open('GET', 'environment.json', true);
    xhr.send();
});

},{}],28:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
var Raven = require("raven-js");
var SentryErrorReporter = /** @class */function () {
    function SentryErrorReporter(appVersion, dsn, tags) {
        Raven.config(dsn, { release: appVersion, 'tags': tags }).install();
        this.setUpUnhandledRejectionListener();
    }
    SentryErrorReporter.prototype.report = function (userFeedback, feedbackCategory, userEmail) {
        Raven.setUserContext({ email: userEmail || '' });
        Raven.captureMessage(userFeedback, { tags: { category: feedbackCategory } });
        Raven.setUserContext(); // Reset the user context, don't cache the email
        return Promise.resolve();
    };
    SentryErrorReporter.prototype.setUpUnhandledRejectionListener = function () {
        // Chrome is the only browser that supports the unhandledrejection event.
        // This is fine for Android, but will not work in iOS.
        var unhandledRejection = 'unhandledrejection';
        window.addEventListener(unhandledRejection, function (event) {
            var reason = event.reason;
            var msg = reason.stack ? reason.stack : reason;
            Raven.captureBreadcrumb({ message: msg, category: unhandledRejection });
        });
    };
    return SentryErrorReporter;
}();
exports.SentryErrorReporter = SentryErrorReporter;

},{"raven-js":10}],29:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
/// <reference path='../../types/ambient/outlinePlugin.d.ts'/>
var errors = require("../model/errors");
// Note that because this implementation does not emit disconnection events, "switching" between
// servers in the server list will not work as expected.
var FakeOutlineConnection = /** @class */function () {
    function FakeOutlineConnection(config, id) {
        this.config = config;
        this.id = id;
        this.running = false;
    }
    FakeOutlineConnection.prototype.playBroken = function () {
        return this.config.name && this.config.name.toLowerCase().includes('broken');
    };
    FakeOutlineConnection.prototype.playUnreachable = function () {
        return !(this.config.name && this.config.name.toLowerCase().includes('unreachable'));
    };
    FakeOutlineConnection.prototype.start = function () {
        if (this.running) {
            return Promise.resolve();
        }
        if (!this.playUnreachable()) {
            return Promise.reject(new errors.OutlinePluginError(5 /* SERVER_UNREACHABLE */));
        } else if (this.playBroken()) {
            return Promise.reject(new errors.OutlinePluginError(8 /* SHADOWSOCKS_START_FAILURE */));
        } else {
            this.running = true;
            return Promise.resolve();
        }
    };
    FakeOutlineConnection.prototype.stop = function () {
        if (!this.running) {
            return Promise.resolve();
        }
        this.running = false;
        return Promise.resolve();
    };
    FakeOutlineConnection.prototype.isRunning = function () {
        return Promise.resolve(this.running);
    };
    FakeOutlineConnection.prototype.isReachable = function () {
        return Promise.resolve(!this.playUnreachable());
    };
    FakeOutlineConnection.prototype.onStatusChange = function (listener) {
        // NOOP
    };
    return FakeOutlineConnection;
}();
exports.FakeOutlineConnection = FakeOutlineConnection;

},{"../model/errors":36}],30:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __read = undefined && undefined.__read || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o),
        r,
        ar = [],
        e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) {
            ar.push(r.value);
        }
    } catch (error) {
        e = { error: error };
    } finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        } finally {
            if (e) throw e.error;
        }
    }
    return ar;
};
Object.defineProperty(exports, "__esModule", { value: true });
var url = require("url");
var events_1 = require("../model/events");
var app_1 = require("./app");
var environment_1 = require("./environment");
var persistent_server_1 = require("./persistent_server");
var settings_1 = require("./settings");
// Used to determine whether to use Polymer functionality on app initialization failure.
var webComponentsAreReady = false;
document.addEventListener('WebComponentsReady', function () {
    console.debug('received WebComponentsReady event');
    webComponentsAreReady = true;
});
// Used to delay loading the app until (translation) resources have been loaded. This can happen a
// little later than WebComponentsReady.
var oncePolymerIsReady = new Promise(function (resolve) {
    document.addEventListener('app-localize-resources-loaded', function () {
        console.debug('received app-localize-resources-loaded event');
        resolve();
    });
});
// Helpers
// Do not call until WebComponentsReady has fired!
function getRootEl() {
    return document.querySelector('app-root');
}
function createServerRepo(eventQueue, storage, deviceSupport, connectionType) {
    var repo = new persistent_server_1.PersistentServerRepository(connectionType, eventQueue, storage);
    if (!deviceSupport) {
        console.debug('Detected development environment, using fake servers.');
        if (repo.getAll().length === 0) {
            repo.add({ name: 'Fake Working Server', host: '127.0.0.1', port: 123 });
            repo.add({ name: 'Fake Broken Server', host: '192.0.2.1', port: 123 });
            repo.add({ name: 'Fake Unreachable Server', host: '10.0.0.24', port: 123 });
        }
    }
    return repo;
}
function main(platform) {
    return Promise.all([environment_1.onceEnvVars, oncePolymerIsReady]).then(function (_a) {
        var _b = __read(_a, 1),
            environmentVars = _b[0];
        console.debug('running main() function');
        var queryParams = url.parse(document.URL, true).query;
        var debugMode = queryParams.debug === 'true';
        var eventQueue = new events_1.EventQueue();
        var serverRepo = createServerRepo(eventQueue, window.localStorage, platform.hasDeviceSupport(), platform.getPersistentServerFactory());
        var settings = new settings_1.Settings();
        var app = new app_1.App(eventQueue, serverRepo, getRootEl(), debugMode, platform.getUrlInterceptor(), platform.getClipboard(), platform.getErrorReporter(environmentVars), settings, environmentVars, platform.getUpdater(), platform.quitApplication);
    }, function (e) {
        onUnexpectedError(e);
        throw e;
    });
}
exports.main = main;
function onUnexpectedError(error) {
    var rootEl = getRootEl();
    if (webComponentsAreReady && rootEl && rootEl.localize) {
        var localize = rootEl.localize.bind(rootEl);
        rootEl.showToast(localize('error-unexpected'), 120000);
    } else {
        // Something went terribly wrong (i.e. Polymer failed to initialize). Provide some messaging to
        // the user, even if we are not able to display it in a toast or localize it.
        // TODO: provide an help email once we have a domain.
        alert("An unexpected error occurred.");
    }
    console.error(error);
}
// Returns Polymer's localization function. Must be called after WebComponentsReady has fired.
function getLocalizationFunction() {
    var rootEl = getRootEl();
    if (!rootEl) {
        return null;
    }
    return rootEl.localize;
}
exports.getLocalizationFunction = getLocalizationFunction;

},{"../model/events":37,"./app":24,"./environment":27,"./persistent_server":32,"./settings":33,"url":15}],31:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
/// <reference path='../../types/ambient/outlinePlugin.d.ts'/>
var errors = require("../model/errors");
var events = require("../model/events");
var OutlineServer = /** @class */function () {
    function OutlineServer(id, config, connection, eventQueue) {
        var _this = this;
        this.id = id;
        this.config = config;
        this.connection = connection;
        this.eventQueue = eventQueue;
        this.connection.onStatusChange(function (status) {
            var statusEvent;
            switch (status) {
                case 0 /* CONNECTED */:
                    statusEvent = new events.ServerConnected(_this);
                    break;
                case 1 /* DISCONNECTED */:
                    statusEvent = new events.ServerDisconnected(_this);
                    break;
                case 2 /* RECONNECTING */:
                    statusEvent = new events.ServerReconnecting(_this);
                    break;
                default:
                    console.warn("Received unknown connection status " + status);
                    return;
            }
            eventQueue.enqueue(statusEvent);
        });
    }
    Object.defineProperty(OutlineServer.prototype, "name", {
        get: function get() {
            return this.config.name || this.config.host || '';
        },
        set: function set(newName) {
            this.config.name = newName;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(OutlineServer.prototype, "host", {
        get: function get() {
            return this.config.host;
        },
        enumerable: true,
        configurable: true
    });
    OutlineServer.prototype.connect = function () {
        return this.connection.start().catch(function (e) {
            // e originates in "native" code: either Cordova or Electron's main process.
            // Because of this, we cannot assume "instanceof OutlinePluginError" will work.
            if (e.errorCode) {
                throw errors.fromErrorCode(e.errorCode);
            }
            throw e;
        });
    };
    OutlineServer.prototype.disconnect = function () {
        return this.connection.stop().catch(function (e) {
            // TODO: None of the plugins currently return an ErrorCode on disconnection.
            throw new errors.RegularNativeError();
        });
    };
    OutlineServer.prototype.checkRunning = function () {
        return this.connection.isRunning();
    };
    OutlineServer.prototype.checkReachable = function () {
        return this.connection.isReachable();
    };
    return OutlineServer;
}();
exports.OutlineServer = OutlineServer;

},{"../model/errors":36,"../model/events":37}],32:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __values = undefined && undefined.__values || function (o) {
    var s = typeof Symbol === "function" && Symbol.iterator,
        m = s && o[s],
        i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function next() {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
};
Object.defineProperty(exports, "__esModule", { value: true });
var uuidv4 = require("uuidv4");
var errors_1 = require("../model/errors");
var events = require("../model/events");
// Maintains a persisted set of servers and liaises with the core.
var PersistentServerRepository = /** @class */function () {
    function PersistentServerRepository(createServer, eventQueue, storage) {
        this.createServer = createServer;
        this.eventQueue = eventQueue;
        this.storage = storage;
        this.lastForgottenServer = null;
        this.loadServers();
    }
    PersistentServerRepository.prototype.getAll = function () {
        return Array.from(this.serverById.values());
    };
    PersistentServerRepository.prototype.getById = function (serverId) {
        return this.serverById.get(serverId);
    };
    PersistentServerRepository.prototype.add = function (serverConfig) {
        var alreadyAddedServer = this.serverFromConfig(serverConfig);
        if (alreadyAddedServer) {
            throw new errors_1.ServerAlreadyAdded(alreadyAddedServer);
        }
        var server = this.createServer(uuidv4(), serverConfig, this.eventQueue);
        this.serverById.set(server.id, server);
        this.storeServers();
        this.eventQueue.enqueue(new events.ServerAdded(server));
    };
    PersistentServerRepository.prototype.rename = function (serverId, newName) {
        var server = this.serverById.get(serverId);
        if (!server) {
            console.warn("Cannot rename nonexistent server " + serverId);
            return;
        }
        server.name = newName;
        this.storeServers();
        this.eventQueue.enqueue(new events.ServerRenamed(server));
    };
    PersistentServerRepository.prototype.forget = function (serverId) {
        var server = this.serverById.get(serverId);
        if (!server) {
            console.warn("Cannot remove nonexistent server " + serverId);
            return;
        }
        this.serverById.delete(serverId);
        this.lastForgottenServer = server;
        this.storeServers();
        this.eventQueue.enqueue(new events.ServerForgotten(server));
    };
    PersistentServerRepository.prototype.undoForget = function (serverId) {
        if (!this.lastForgottenServer) {
            console.warn('No forgotten server to unforget');
            return;
        } else if (this.lastForgottenServer.id !== serverId) {
            console.warn('id of forgotten server', this.lastForgottenServer, 'does not match', serverId);
            return;
        }
        this.serverById.set(this.lastForgottenServer.id, this.lastForgottenServer);
        this.storeServers();
        this.eventQueue.enqueue(new events.ServerForgetUndone(this.lastForgottenServer));
        this.lastForgottenServer = null;
    };
    PersistentServerRepository.prototype.containsServer = function (config) {
        return !!this.serverFromConfig(config);
    };
    PersistentServerRepository.prototype.serverFromConfig = function (config) {
        var e_1, _a;
        try {
            for (var _b = __values(this.getAll()), _c = _b.next(); !_c.done; _c = _b.next()) {
                var server = _c.value;
                if (configsMatch(server.config, config)) {
                    return server;
                }
            }
        } catch (e_1_1) {
            e_1 = { error: e_1_1 };
        } finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
            } finally {
                if (e_1) throw e_1.error;
            }
        }
    };
    PersistentServerRepository.prototype.storeServers = function () {
        var e_2, _a;
        var configById = {};
        try {
            for (var _b = __values(this.serverById.values()), _c = _b.next(); !_c.done; _c = _b.next()) {
                var server = _c.value;
                configById[server.id] = server.config;
            }
        } catch (e_2_1) {
            e_2 = { error: e_2_1 };
        } finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
            } finally {
                if (e_2) throw e_2.error;
            }
        }
        var json = JSON.stringify(configById);
        this.storage.setItem(PersistentServerRepository.SERVERS_STORAGE_KEY, json);
    };
    // Loads servers from storage,
    // raising an error if there is any problem loading.
    PersistentServerRepository.prototype.loadServers = function () {
        this.serverById = new Map();
        var serversJson = this.storage.getItem(PersistentServerRepository.SERVERS_STORAGE_KEY);
        if (!serversJson) {
            console.debug("no servers found in storage");
            return;
        }
        var configById = {};
        try {
            configById = JSON.parse(serversJson);
        } catch (e) {
            throw new Error("could not parse saved servers: " + e.message);
        }
        for (var serverId in configById) {
            if (configById.hasOwnProperty(serverId)) {
                var config = configById[serverId];
                try {
                    var server = this.createServer(serverId, config, this.eventQueue);
                    this.serverById.set(serverId, server);
                } catch (e) {
                    // Don't propagate so other stored servers can be created.
                    console.error(e);
                }
            }
        }
    };
    // Name by which servers are saved to storage.
    PersistentServerRepository.SERVERS_STORAGE_KEY = 'servers';
    return PersistentServerRepository;
}();
exports.PersistentServerRepository = PersistentServerRepository;
function configsMatch(left, right) {
    return left.host === right.host && left.port === right.port && left.method === right.method && left.password === right.password;
}

},{"../model/errors":36,"../model/events":37,"uuidv4":23}],33:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __values = undefined && undefined.__values || function (o) {
    var s = typeof Symbol === "function" && Symbol.iterator,
        m = s && o[s],
        i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function next() {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
};
var __read = undefined && undefined.__read || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o),
        r,
        ar = [],
        e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) {
            ar.push(r.value);
        }
    } catch (error) {
        e = { error: error };
    } finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        } finally {
            if (e) throw e.error;
        }
    }
    return ar;
};
Object.defineProperty(exports, "__esModule", { value: true });
// Setting keys supported by the `Settings` class.
var SettingsKey;
(function (SettingsKey) {
    SettingsKey["VPN_WARNING_DISMISSED"] = "vpn-warning-dismissed";
    SettingsKey["AUTO_CONNECT_DIALOG_DISMISSED"] = "auto-connect-dialog-dismissed";
    SettingsKey["PRIVACY_ACK"] = "privacy-ack";
})(SettingsKey = exports.SettingsKey || (exports.SettingsKey = {}));
// Persistent storage for user settings that supports a limited set of keys.
var Settings = /** @class */function () {
    function Settings(storage, validKeys) {
        if (storage === void 0) {
            storage = window.localStorage;
        }
        if (validKeys === void 0) {
            validKeys = Object.values(SettingsKey);
        }
        this.storage = storage;
        this.validKeys = validKeys;
        this.settings = new Map();
        this.loadSettings();
    }
    Settings.prototype.get = function (key) {
        return this.settings.get(key);
    };
    Settings.prototype.set = function (key, value) {
        if (!this.isValidSetting(key)) {
            throw new Error("Cannot set invalid key " + key);
        }
        this.settings.set(key, value);
        this.storeSettings();
    };
    Settings.prototype.remove = function (key) {
        this.settings.delete(key);
        this.storeSettings();
    };
    Settings.prototype.isValidSetting = function (key) {
        return this.validKeys.includes(key);
    };
    Settings.prototype.loadSettings = function () {
        var settingsJson = this.storage.getItem(Settings.STORAGE_KEY);
        if (!settingsJson) {
            console.debug("No settings found in storage");
            return;
        }
        var storageSettings = JSON.parse(settingsJson);
        for (var key in storageSettings) {
            if (storageSettings.hasOwnProperty(key)) {
                this.settings.set(key, storageSettings[key]);
            }
        }
    };
    Settings.prototype.storeSettings = function () {
        var e_1, _a;
        var storageSettings = {};
        try {
            for (var _b = __values(this.settings), _c = _b.next(); !_c.done; _c = _b.next()) {
                var _d = __read(_c.value, 2),
                    key = _d[0],
                    value = _d[1];
                storageSettings[key] = value;
            }
        } catch (e_1_1) {
            e_1 = { error: e_1_1 };
        } finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
            } finally {
                if (e_1) throw e_1.error;
            }
        }
        var storageSettingsJson = JSON.stringify(storageSettings);
        this.storage.setItem(Settings.STORAGE_KEY, storageSettingsJson);
    };
    Settings.STORAGE_KEY = 'settings';
    return Settings;
}();
exports.Settings = Settings;

},{}],34:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

Object.defineProperty(exports, "__esModule", { value: true });
var AbstractUpdater = /** @class */function () {
    function AbstractUpdater() {
        this.listener = null;
    }
    AbstractUpdater.prototype.setListener = function (listener) {
        this.listener = listener;
    };
    AbstractUpdater.prototype.emitEvent = function () {
        if (this.listener) {
            this.listener();
        }
    };
    return AbstractUpdater;
}();
exports.AbstractUpdater = AbstractUpdater;

},{}],35:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __extends = undefined && undefined.__extends || function () {
    var _extendStatics = function extendStatics(d, b) {
        _extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function (d, b) {
            d.__proto__ = b;
        } || function (d, b) {
            for (var p in b) {
                if (b.hasOwnProperty(p)) d[p] = b[p];
            }
        };
        return _extendStatics(d, b);
    };
    return function (d, b) {
        _extendStatics(d, b);
        function __() {
            this.constructor = d;
        }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
}();
var __values = undefined && undefined.__values || function (o) {
    var s = typeof Symbol === "function" && Symbol.iterator,
        m = s && o[s],
        i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function next() {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
};
Object.defineProperty(exports, "__esModule", { value: true });
/// <reference path='../../types/ambient/webintents.d.ts'/>
var UrlInterceptor = /** @class */function () {
    function UrlInterceptor() {
        this.listeners = [];
    }
    UrlInterceptor.prototype.registerListener = function (listener) {
        this.listeners.push(listener);
        if (this.launchUrl) {
            listener(this.launchUrl);
            this.launchUrl = undefined;
        }
    };
    UrlInterceptor.prototype.executeListeners = function (url) {
        var e_1, _a;
        if (!url) {
            return;
        }
        if (!this.listeners.length) {
            console.log('no listeners have been added, delaying intent firing');
            this.launchUrl = url;
            return;
        }
        try {
            for (var _b = __values(this.listeners), _c = _b.next(); !_c.done; _c = _b.next()) {
                var listener = _c.value;
                listener(url);
            }
        } catch (e_1_1) {
            e_1 = { error: e_1_1 };
        } finally {
            try {
                if (_c && !_c.done && (_a = _b.return)) _a.call(_b);
            } finally {
                if (e_1) throw e_1.error;
            }
        }
    };
    return UrlInterceptor;
}();
exports.UrlInterceptor = UrlInterceptor;
var AndroidUrlInterceptor = /** @class */function (_super) {
    __extends(AndroidUrlInterceptor, _super);
    function AndroidUrlInterceptor() {
        var _this = _super.call(this) || this;
        window.webintent.getUri(function (launchUrl) {
            window.webintent.onNewIntent(_this.executeListeners.bind(_this));
            _this.executeListeners(launchUrl);
        });
        return _this;
    }
    return AndroidUrlInterceptor;
}(UrlInterceptor);
exports.AndroidUrlInterceptor = AndroidUrlInterceptor;
var AppleUrlInterceptor = /** @class */function (_super) {
    __extends(AppleUrlInterceptor, _super);
    function AppleUrlInterceptor(launchUrl) {
        var _this = _super.call(this) || this;
        // cordova-[ios|osx] call a global function with this signature when a URL is intercepted.
        // We define it in |cordova_main|, redefine it to use this interceptor.
        window.handleOpenURL = function (url) {
            _this.executeListeners(url);
        };
        if (launchUrl) {
            _this.executeListeners(launchUrl);
        }
        return _this;
    }
    return AppleUrlInterceptor;
}(UrlInterceptor);
exports.AppleUrlInterceptor = AppleUrlInterceptor;

},{}],36:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __extends = undefined && undefined.__extends || function () {
    var _extendStatics = function extendStatics(d, b) {
        _extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function (d, b) {
            d.__proto__ = b;
        } || function (d, b) {
            for (var p in b) {
                if (b.hasOwnProperty(p)) d[p] = b[p];
            }
        };
        return _extendStatics(d, b);
    };
    return function (d, b) {
        _extendStatics(d, b);
        function __() {
            this.constructor = d;
        }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
}();
Object.defineProperty(exports, "__esModule", { value: true });
var OutlineError = /** @class */function (_super) {
    __extends(OutlineError, _super);
    function OutlineError(message) {
        var _newTarget = this.constructor;
        var _this =
        // ref:
        // https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-2.html#support-for-newtarget
        _super.call(this, message) || this;
        Object.setPrototypeOf(_this, _newTarget.prototype); // restore prototype chain
        _this.name = _newTarget.name;
        return _this;
    }
    return OutlineError;
}(Error);
exports.OutlineError = OutlineError;
var ServerAlreadyAdded = /** @class */function (_super) {
    __extends(ServerAlreadyAdded, _super);
    function ServerAlreadyAdded(server) {
        var _this = _super.call(this) || this;
        _this.server = server;
        return _this;
    }
    return ServerAlreadyAdded;
}(OutlineError);
exports.ServerAlreadyAdded = ServerAlreadyAdded;
var ServerIncompatible = /** @class */function (_super) {
    __extends(ServerIncompatible, _super);
    function ServerIncompatible(message) {
        return _super.call(this, message) || this;
    }
    return ServerIncompatible;
}(OutlineError);
exports.ServerIncompatible = ServerIncompatible;
var ServerUrlInvalid = /** @class */function (_super) {
    __extends(ServerUrlInvalid, _super);
    function ServerUrlInvalid(message) {
        return _super.call(this, message) || this;
    }
    return ServerUrlInvalid;
}(OutlineError);
exports.ServerUrlInvalid = ServerUrlInvalid;
var OperationTimedOut = /** @class */function (_super) {
    __extends(OperationTimedOut, _super);
    function OperationTimedOut(timeoutMs, operationName) {
        var _this = _super.call(this) || this;
        _this.timeoutMs = timeoutMs;
        _this.operationName = operationName;
        return _this;
    }
    return OperationTimedOut;
}(OutlineError);
exports.OperationTimedOut = OperationTimedOut;
var FeedbackSubmissionError = /** @class */function (_super) {
    __extends(FeedbackSubmissionError, _super);
    function FeedbackSubmissionError() {
        return _super.call(this) || this;
    }
    return FeedbackSubmissionError;
}(OutlineError);
exports.FeedbackSubmissionError = FeedbackSubmissionError;
// Error thrown by "native" code.
//
// Must be kept in sync with its Cordova doppelganger:
//   cordova-plugin-outline/outlinePlugin.js
//
// TODO: Rename this class, "plugin" is a poor name since the Electron apps do not have plugins.
var OutlinePluginError = /** @class */function (_super) {
    __extends(OutlinePluginError, _super);
    function OutlinePluginError(errorCode) {
        var _this = _super.call(this) || this;
        _this.errorCode = errorCode;
        return _this;
    }
    return OutlinePluginError;
}(OutlineError);
exports.OutlinePluginError = OutlinePluginError;
// Marker class for errors originating in native code.
// Bifurcates into two subclasses:
//  - "expected" errors originating in native code, e.g. incorrect password
//  - "unexpected" errors originating in native code, e.g. unhandled routing table
var NativeError = /** @class */function (_super) {
    __extends(NativeError, _super);
    function NativeError() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return NativeError;
}(OutlineError);
exports.NativeError = NativeError;
var RegularNativeError = /** @class */function (_super) {
    __extends(RegularNativeError, _super);
    function RegularNativeError() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return RegularNativeError;
}(NativeError);
exports.RegularNativeError = RegularNativeError;
var RedFlagNativeError = /** @class */function (_super) {
    __extends(RedFlagNativeError, _super);
    function RedFlagNativeError() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return RedFlagNativeError;
}(NativeError);
exports.RedFlagNativeError = RedFlagNativeError;
//////
// "Expected" errors.
//////
var UnexpectedPluginError = /** @class */function (_super) {
    __extends(UnexpectedPluginError, _super);
    function UnexpectedPluginError() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return UnexpectedPluginError;
}(RegularNativeError);
exports.UnexpectedPluginError = UnexpectedPluginError;
var VpnPermissionNotGranted = /** @class */function (_super) {
    __extends(VpnPermissionNotGranted, _super);
    function VpnPermissionNotGranted() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return VpnPermissionNotGranted;
}(RegularNativeError);
exports.VpnPermissionNotGranted = VpnPermissionNotGranted;
var InvalidServerCredentials = /** @class */function (_super) {
    __extends(InvalidServerCredentials, _super);
    function InvalidServerCredentials() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return InvalidServerCredentials;
}(RegularNativeError);
exports.InvalidServerCredentials = InvalidServerCredentials;
var RemoteUdpForwardingDisabled = /** @class */function (_super) {
    __extends(RemoteUdpForwardingDisabled, _super);
    function RemoteUdpForwardingDisabled() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return RemoteUdpForwardingDisabled;
}(RegularNativeError);
exports.RemoteUdpForwardingDisabled = RemoteUdpForwardingDisabled;
var ServerUnreachable = /** @class */function (_super) {
    __extends(ServerUnreachable, _super);
    function ServerUnreachable() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return ServerUnreachable;
}(RegularNativeError);
exports.ServerUnreachable = ServerUnreachable;
var IllegalServerConfiguration = /** @class */function (_super) {
    __extends(IllegalServerConfiguration, _super);
    function IllegalServerConfiguration() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return IllegalServerConfiguration;
}(RegularNativeError);
exports.IllegalServerConfiguration = IllegalServerConfiguration;
var NoAdminPermissions = /** @class */function (_super) {
    __extends(NoAdminPermissions, _super);
    function NoAdminPermissions() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return NoAdminPermissions;
}(RegularNativeError);
exports.NoAdminPermissions = NoAdminPermissions;
var SystemConfigurationException = /** @class */function (_super) {
    __extends(SystemConfigurationException, _super);
    function SystemConfigurationException() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return SystemConfigurationException;
}(RegularNativeError);
exports.SystemConfigurationException = SystemConfigurationException;
//////
// Now, "unexpected" errors.
// Use these sparingly because each occurrence triggers a Sentry report.
//////
// Windows.
var ShadowsocksStartFailure = /** @class */function (_super) {
    __extends(ShadowsocksStartFailure, _super);
    function ShadowsocksStartFailure() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return ShadowsocksStartFailure;
}(RedFlagNativeError);
exports.ShadowsocksStartFailure = ShadowsocksStartFailure;
var ConfigureSystemProxyFailure = /** @class */function (_super) {
    __extends(ConfigureSystemProxyFailure, _super);
    function ConfigureSystemProxyFailure() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return ConfigureSystemProxyFailure;
}(RedFlagNativeError);
exports.ConfigureSystemProxyFailure = ConfigureSystemProxyFailure;
var UnsupportedRoutingTable = /** @class */function (_super) {
    __extends(UnsupportedRoutingTable, _super);
    function UnsupportedRoutingTable() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return UnsupportedRoutingTable;
}(RedFlagNativeError);
exports.UnsupportedRoutingTable = UnsupportedRoutingTable;
// Used on Android and Apple to indicate that the plugin failed to establish the VPN tunnel.
var VpnStartFailure = /** @class */function (_super) {
    __extends(VpnStartFailure, _super);
    function VpnStartFailure() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return VpnStartFailure;
}(RedFlagNativeError);
exports.VpnStartFailure = VpnStartFailure;
// Converts an ErrorCode - originating in "native" code - to an instance of the relevant
// OutlineError subclass.
// Throws if the error code is not one defined in ErrorCode or is ErrorCode.NO_ERROR.
function fromErrorCode(errorCode) {
    switch (errorCode) {
        case 1 /* UNEXPECTED */:
            return new UnexpectedPluginError();
        case 2 /* VPN_PERMISSION_NOT_GRANTED */:
            return new VpnPermissionNotGranted();
        case 3 /* INVALID_SERVER_CREDENTIALS */:
            return new InvalidServerCredentials();
        case 4 /* UDP_RELAY_NOT_ENABLED */:
            return new RemoteUdpForwardingDisabled();
        case 5 /* SERVER_UNREACHABLE */:
            return new ServerUnreachable();
        case 6 /* VPN_START_FAILURE */:
            return new VpnStartFailure();
        case 7 /* ILLEGAL_SERVER_CONFIGURATION */:
            return new IllegalServerConfiguration();
        case 8 /* SHADOWSOCKS_START_FAILURE */:
            return new ShadowsocksStartFailure();
        case 9 /* CONFIGURE_SYSTEM_PROXY_FAILURE */:
            return new ConfigureSystemProxyFailure();
        case 10 /* NO_ADMIN_PERMISSIONS */:
            return new NoAdminPermissions();
        case 11 /* UNSUPPORTED_ROUTING_TABLE */:
            return new UnsupportedRoutingTable();
        case 12 /* SYSTEM_MISCONFIGURED */:
            return new SystemConfigurationException();
        default:
            throw new Error("unknown ErrorCode " + errorCode);
    }
}
exports.fromErrorCode = fromErrorCode;
// Converts a NativeError to an ErrorCode.
// Throws if the error is not a subclass of NativeError.
function toErrorCode(e) {
    if (e instanceof UnexpectedPluginError) {
        return 1 /* UNEXPECTED */;
    } else if (e instanceof VpnPermissionNotGranted) {
        return 2 /* VPN_PERMISSION_NOT_GRANTED */;
    } else if (e instanceof InvalidServerCredentials) {
        return 3 /* INVALID_SERVER_CREDENTIALS */;
    } else if (e instanceof RemoteUdpForwardingDisabled) {
        return 4 /* UDP_RELAY_NOT_ENABLED */;
    } else if (e instanceof ServerUnreachable) {
        return 5 /* SERVER_UNREACHABLE */;
    } else if (e instanceof VpnStartFailure) {
        return 6 /* VPN_START_FAILURE */;
    } else if (e instanceof IllegalServerConfiguration) {
        return 7 /* ILLEGAL_SERVER_CONFIGURATION */;
    } else if (e instanceof ShadowsocksStartFailure) {
        return 8 /* SHADOWSOCKS_START_FAILURE */;
    } else if (e instanceof ConfigureSystemProxyFailure) {
        return 9 /* CONFIGURE_SYSTEM_PROXY_FAILURE */;
    } else if (e instanceof UnsupportedRoutingTable) {
        return 11 /* UNSUPPORTED_ROUTING_TABLE */;
    } else if (e instanceof NoAdminPermissions) {
        return 10 /* NO_ADMIN_PERMISSIONS */;
    } else if (e instanceof SystemConfigurationException) {
        return 12 /* SYSTEM_MISCONFIGURED */;
    }
    throw new Error("unknown NativeError " + e.name);
}
exports.toErrorCode = toErrorCode;

},{}],37:[function(require,module,exports){
"use strict";
// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var __values = undefined && undefined.__values || function (o) {
    var s = typeof Symbol === "function" && Symbol.iterator,
        m = s && o[s],
        i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function next() {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
};
Object.defineProperty(exports, "__esModule", { value: true });
var ServerAdded = /** @class */function () {
    function ServerAdded(server) {
        this.server = server;
    }
    return ServerAdded;
}();
exports.ServerAdded = ServerAdded;
var ServerForgotten = /** @class */function () {
    function ServerForgotten(server) {
        this.server = server;
    }
    return ServerForgotten;
}();
exports.ServerForgotten = ServerForgotten;
var ServerForgetUndone = /** @class */function () {
    function ServerForgetUndone(server) {
        this.server = server;
    }
    return ServerForgetUndone;
}();
exports.ServerForgetUndone = ServerForgetUndone;
var ServerRenamed = /** @class */function () {
    function ServerRenamed(server) {
        this.server = server;
    }
    return ServerRenamed;
}();
exports.ServerRenamed = ServerRenamed;
var ServerConnected = /** @class */function () {
    function ServerConnected(server) {
        this.server = server;
    }
    return ServerConnected;
}();
exports.ServerConnected = ServerConnected;
var ServerDisconnected = /** @class */function () {
    function ServerDisconnected(server) {
        this.server = server;
    }
    return ServerDisconnected;
}();
exports.ServerDisconnected = ServerDisconnected;
var ServerReconnecting = /** @class */function () {
    function ServerReconnecting(server) {
        this.server = server;
    }
    return ServerReconnecting;
}();
exports.ServerReconnecting = ServerReconnecting;
// Simple publisher-subscriber queue.
var EventQueue = /** @class */function () {
    function EventQueue() {
        this.queuedEvents = [];
        // tslint:disable-next-line: no-any
        this.listenersByEventType = new Map();
        this.isStarted = false;
        this.isPublishing = false;
    }
    EventQueue.prototype.startPublishing = function () {
        this.isStarted = true;
        this.publishQueuedEvents();
    };
    // Registers a listener for events of the type of the given constructor.
    EventQueue.prototype.subscribe = function (
    // tslint:disable-next-line: no-any
    eventConstructor, listener) {
        var listeners = this.listenersByEventType.get(eventConstructor.name);
        if (!listeners) {
            listeners = [];
            this.listenersByEventType.set(eventConstructor.name, listeners);
        }
        listeners.push(listener);
    };
    // Enqueues the given event for publishing and publishes all queued events if
    // publishing is not already happening.
    //
    // The enqueue method is reentrant: it may be called by an event listener
    // during the publishing of the events. In that case the method adds the event
    // to the end of the queue and returns immediately.
    //
    // This guarantees that events are published and handled in the order that
    // they are queued.
    //
    // There's no guarantee that the subscribers for the event have been called by
    // the time this function returns.
    EventQueue.prototype.enqueue = function (event) {
        this.queuedEvents.push(event);
        if (this.isStarted) {
            this.publishQueuedEvents();
        }
    };
    // Triggers the subscribers for all the enqueued events.
    EventQueue.prototype.publishQueuedEvents = function () {
        var e_1, _a;
        if (this.isPublishing) return;
        this.isPublishing = true;
        while (this.queuedEvents.length > 0) {
            var event_1 = this.queuedEvents.shift();
            var listeners = this.listenersByEventType.get(event_1.constructor.name);
            if (!listeners) {
                console.warn('Dropping event with no listeners:', event_1);
                continue;
            }
            try {
                for (var listeners_1 = (e_1 = void 0, __values(listeners)), listeners_1_1 = listeners_1.next(); !listeners_1_1.done; listeners_1_1 = listeners_1.next()) {
                    var listener = listeners_1_1.value;
                    listener(event_1);
                }
            } catch (e_1_1) {
                e_1 = { error: e_1_1 };
            } finally {
                try {
                    if (listeners_1_1 && !listeners_1_1.done && (_a = listeners_1.return)) _a.call(listeners_1);
                } finally {
                    if (e_1) throw e_1.error;
                }
            }
        }
        this.isPublishing = false;
    };
    return EventQueue;
}();
exports.EventQueue = EventQueue;

},{}]},{},[26])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJub2RlX21vZHVsZXMvU2hhZG93c29ja3NDb25maWcvc2hhZG93c29ja3NfY29uZmlnLnRzIiwibm9kZV9tb2R1bGVzL2Jhc2UtNjQvYmFzZTY0LmpzIiwibm9kZV9tb2R1bGVzL3B1bnljb2RlL3B1bnljb2RlLmpzIiwibm9kZV9tb2R1bGVzL3F1ZXJ5c3RyaW5nLWVzMy9kZWNvZGUuanMiLCJub2RlX21vZHVsZXMvcXVlcnlzdHJpbmctZXMzL2VuY29kZS5qcyIsIm5vZGVfbW9kdWxlcy9xdWVyeXN0cmluZy1lczMvaW5kZXguanMiLCJub2RlX21vZHVsZXMvcmF2ZW4tanMvc3JjL2NvbmZpZ0Vycm9yLmpzIiwibm9kZV9tb2R1bGVzL3JhdmVuLWpzL3NyYy9jb25zb2xlLmpzIiwibm9kZV9tb2R1bGVzL3JhdmVuLWpzL3NyYy9yYXZlbi5qcyIsIm5vZGVfbW9kdWxlcy9yYXZlbi1qcy9zcmMvc2luZ2xldG9uLmpzIiwibm9kZV9tb2R1bGVzL3JhdmVuLWpzL3NyYy91dGlscy5qcyIsIm5vZGVfbW9kdWxlcy9yYXZlbi1qcy92ZW5kb3IvVHJhY2VLaXQvdHJhY2VraXQuanMiLCJub2RlX21vZHVsZXMvcmF2ZW4tanMvdmVuZG9yL2pzb24tc3RyaW5naWZ5LXNhZmUvc3RyaW5naWZ5LmpzIiwibm9kZV9tb2R1bGVzL3JhdmVuLWpzL3ZlbmRvci9tZDUvbWQ1LmpzIiwibm9kZV9tb2R1bGVzL3VybC91cmwuanMiLCJub2RlX21vZHVsZXMvdXJsL3V0aWwuanMiLCJub2RlX21vZHVsZXMvdXVpZC9saWIvYnl0ZXNUb1V1aWQuanMiLCJub2RlX21vZHVsZXMvdXVpZC9saWIvcm5nLWJyb3dzZXIuanMiLCJub2RlX21vZHVsZXMvdXVpZC9saWIvc2hhMS1icm93c2VyLmpzIiwibm9kZV9tb2R1bGVzL3V1aWQvbGliL3YzNS5qcyIsIm5vZGVfbW9kdWxlcy91dWlkL3Y0LmpzIiwibm9kZV9tb2R1bGVzL3V1aWQvdjUuanMiLCJub2RlX21vZHVsZXMvdXVpZHY0L2xpYi91dWlkdjQuanMiLCJ3d3cvYXBwL2FwcC5qcyIsInd3dy9hcHAvY2xpcGJvYXJkLmpzIiwid3d3L2FwcC9jb3Jkb3ZhX21haW4uanMiLCJ3d3cvYXBwL2Vudmlyb25tZW50LmpzIiwid3d3L2FwcC9lcnJvcl9yZXBvcnRlci5qcyIsInd3dy9hcHAvZmFrZV9jb25uZWN0aW9uLmpzIiwid3d3L2FwcC9tYWluLmpzIiwid3d3L2FwcC9vdXRsaW5lX3NlcnZlci5qcyIsInd3dy9hcHAvcGVyc2lzdGVudF9zZXJ2ZXIuanMiLCJ3d3cvYXBwL3NldHRpbmdzLmpzIiwid3d3L2FwcC91cGRhdGVyLmpzIiwid3d3L2FwcC91cmxfaW50ZXJjZXB0b3IuanMiLCJ3d3cvbW9kZWwvZXJyb3JzLmpzIiwid3d3L21vZGVsL2V2ZW50cy5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7QUNBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUVBLFFBQUEsb0JBQW9CLFNBQUEsdUJBQUEsR0FBQTtBQUNkLFlBQUEsT0FBUyxNQUFULEtBQW1CLFdBQW5CLElBQThCLE9BQVksT0FBMUMsRUFBMEM7QUFDMUMsbUJBQVMsT0FBRyxPQUFaLENBRDBDLENBQ2xCO0FBQ3hCLFNBRkEsTUFFQSxJQUFTLE9BQUcsTUFBSCxLQUFvQixXQUE3QixFQUF1QztBQUN2QyxtQkFBTSxNQUFOLENBRHVDLENBQ3JCO0FBQ2xCO0FBQ0YsY0FBQyxJQUFTLEtBQVQsQ0FBVyx1RUFBWCxDQUFEO0FBQ0YsS0FQa0IsRUFBcEI7QUFTQTtBQUNBLFFBQUEsWUFBQSxPQUFtQixNQUFuQixLQUFtQixXQUFuQjtBQUVBLFFBQUEsWUFBQSxZQUEwQixJQUExQixHQUEwQixRQUFBLFNBQUEsRUFBQSxNQUExQjtBQUNBLFFBQUEsWUFBQSxZQUFBLElBQUEsR0FBQSxRQUFB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LGFBQUssWUFBTCxHQUFvQixJQUFwQjtBQUNBLGVBQU8sS0FBSyxZQUFMLENBQWtCLE1BQWxCLEdBQTJCLENBQWxDLEVBQXFDO0FBQ2pDLGdCQUFJLFVBQVUsS0FBSyxZQUFMLENBQWtCLEtBQWxCLEVBQWQ7QUFDQSxnQkFBSSxZQUFZLEtBQUssb0JBQUwsQ0FBMEIsR0FBMUIsQ0FBOEIsUUFBUSxXQUFSLENBQW9CLElBQWxELENBQWhCO0FBQ0EsZ0JBQUksQ0FBQyxTQUFMLEVBQWdCO0FBQ1osd0JBQVEsSUFBUixDQUFhLG1DQUFiLEVBQWtELE9BQWxEO0FBQ0E7QUFDSDtBQUNELGdCQUFJO0FBQ0EscUJBQUssSUFBSSxlQUFlLE1BQU0sS0FBSyxDQUFYLEVBQWMsU0FBUyxTQUFULENBQTdCLENBQUosRUFBdUQsZ0JBQWdCLFlBQVksSUFBWixFQUE1RSxFQUFnRyxDQUFDLGNBQWMsSUFBL0csRUFBcUgsZ0JBQWdCLFlBQVksSUFBWixFQUFySSxFQUF5SjtBQUNySix3QkFBSSxXQUFXLGNBQWMsS0FBN0I7QUFDQSw2QkFBUyxPQUFUO0FBQ0g7QUFDSixhQUxELENBTUEsT0FBTyxLQUFQLEVBQWM7QUFBRSxzQkFBTSxFQUFFLE9BQU8sS0FBVCxFQUFOO0FBQXlCLGFBTnpDLFNBT1E7QUFDSixvQkFBSTtBQUNBLHdCQUFJLGlCQUFpQixDQUFDLGNBQWMsSUFBaEMsS0FBeUMsS0FBSyxZQUFZLE1BQTFELENBQUosRUFBdUUsR0FBRyxJQUFILENBQVEsV0FBUjtBQUMxRSxpQkFGRCxTQUdRO0FBQUUsd0JBQUksR0FBSixFQUFTLE1BQU0sSUFBSSxLQUFWO0FBQWtCO0FBQ3hDO0FBQ0o7QUFDRCxhQUFLLFlBQUwsR0FBb0IsS0FBcEI7QUFDSCxLQTNCRDtBQTRCQSxXQUFPLFVBQVA7QUFDSCxDQXZFK0IsRUFBaEM7QUF3RUEsUUFBUSxVQUFSLEdBQXFCLFVBQXJCIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzQ29udGVudCI6WyIoZnVuY3Rpb24oKXtmdW5jdGlvbiByKGUsbix0KXtmdW5jdGlvbiBvKGksZil7aWYoIW5baV0pe2lmKCFlW2ldKXt2YXIgYz1cImZ1bmN0aW9uXCI9PXR5cGVvZiByZXF1aXJlJiZyZXF1aXJlO2lmKCFmJiZjKXJldHVybiBjKGksITApO2lmKHUpcmV0dXJuIHUoaSwhMCk7dmFyIGE9bmV3IEVycm9yKFwiQ2Fubm90IGZpbmQgbW9kdWxlICdcIitpK1wiJ1wiKTt0aHJvdyBhLmNvZGU9XCJNT0RVTEVfTk9UX0ZPVU5EXCIsYX12YXIgcD1uW2ldPXtleHBvcnRzOnt9fTtlW2ldWzBdLmNhbGwocC5leHBvcnRzLGZ1bmN0aW9uKHIpe3ZhciBuPWVbaV1bMV1bcl07cmV0dXJuIG8obnx8cil9LHAscC5leHBvcnRzLHIsZSxuLHQpfXJldHVybiBuW2ldLmV4cG9ydHN9Zm9yKHZhciB1PVwiZnVuY3Rpb25cIj09dHlwZW9mIHJlcXVpcmUmJnJlcXVpcmUsaT0wO2k8dC5sZW5ndGg7aSsrKW8odFtpXSk7cmV0dXJuIG99cmV0dXJuIHJ9KSgpIiwiLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG5cbi8qIHRzbGludDpkaXNhYmxlICovXG5jb25zdCBpc0Jyb3dzZXIgPSB0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJztcbmNvbnN0IGI2NEVuY29kZSA9IGlzQnJvd3NlciA/IGJ0b2EgOiByZXF1aXJlKCdiYXNlLTY0JykuZW5jb2RlO1xuY29uc3QgYjY0RGVjb2RlID0gaXNCcm93c2VyID8gYXRvYiA6IHJlcXVpcmUoJ2Jhc2UtNjQnKS5kZWNvZGU7XG5jb25zdCBVUkwgPSBpc0Jyb3dzZXIgPyB3aW5kb3cuVVJMIDogcmVxdWlyZSgndXJsJykuVVJMO1xuY29uc3QgcHVueWNvZGUgPSBpc0Jyb3dzZXIgPyAod2luZG93IGFzIGFueSkucHVueWNvZGUgOiByZXF1aXJlKCdwdW55Y29kZScpO1xuaWYgKCFwdW55Y29kZSkge1xuICB0aHJvdyBuZXcgRXJyb3IoYENvdWxkIG5vdCBmaW5kIHB1bnljb2RlLiBEaWQgeW91IGZvcmdldCB0byBhZGQgZS5nLlxuICA8c2NyaXB0IHNyYz1cImJvd2VyX2NvbXBvbmVudHMvcHVueWNvZGUvcHVueWNvZGUubWluLmpzXCI+PC9zY3JpcHQ+P2ApO1xufVxuLyogdHNsaW50OmVuYWJsZSAqL1xuXG4vLyBDdXN0b20gZXJyb3IgYmFzZSBjbGFzc1xuZXhwb3J0IGNsYXNzIFNoYWRvd3NvY2tzQ29uZmlnRXJyb3IgZXh0ZW5kcyBFcnJvciB7XG4gIGNvbnN0cnVjdG9yKG1lc3NhZ2U6IHN0cmluZykge1xuICAgIHN1cGVyKG1lc3NhZ2UpOyAgLy8gJ0Vycm9yJyBicmVha3MgcHJvdG90eXBlIGNoYWluIGhlcmUgaWYgdGhpcyBpcyB0cmFuc3BpbGVkIHRvIGVzNVxuICAgIE9iamVjdC5zZXRQcm90b3R5cGVPZih0aGlzLCBuZXcudGFyZ2V0LnByb3RvdHlwZSk7ICAvLyByZXN0b3JlIHByb3RvdHlwZSBjaGFpblxuICAgIHRoaXMubmFtZSA9IG5ldy50YXJnZXQubmFtZTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgSW52YWxpZENvbmZpZ0ZpZWxkIGV4dGVuZHMgU2hhZG93c29ja3NDb25maWdFcnJvciB7fVxuXG5leHBvcnQgY2xhc3MgSW52YWxpZFVyaSBleHRlbmRzIFNoYWRvd3NvY2tzQ29uZmlnRXJyb3Ige31cblxuLy8gU2VsZi12YWxpZGF0aW5nL25vcm1hbGl6aW5nIGNvbmZpZyBkYXRhIHR5cGVzIGltcGxlbWVudCB0aGlzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIGludGVyZmFjZS5cbi8vIENvbnN0cnVjdG9ycyB0YWtlIHNvbWUgZGF0YSwgdmFsaWRhdGUsIG5vcm1hbGl6ZSwgYW5kIHN0b3JlIGlmIHZhbGlkLCBvciB0aHJvdyBvdGhlcndpc2UuXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgVmFsaWRhdGVkQ29uZmlnRmllbGQge31cblxuZnVuY3Rpb24gdGhyb3dFcnJvckZvckludmFsaWRGaWVsZChuYW1lOiBzdHJpbmcsIHZhbHVlOiB7fSwgcmVhc29uPzogc3RyaW5nKSB7XG4gIHRocm93IG5ldyBJbnZhbGlkQ29uZmlnRmllbGQoYEludmFsaWQgJHtuYW1lfTogJHt2YWx1ZX0gJHtyZWFzb24gfHwgJyd9YCk7XG59XG5cbmV4cG9ydCBjbGFzcyBIb3N0IGV4dGVuZHMgVmFsaWRhdGVkQ29uZmlnRmllbGQge1xuICBwdWJsaWMgc3RhdGljIElQVjRfUEFUVEVSTiA9IC9eKD86WzAtOV17MSwzfVxcLil7M31bMC05XXsxLDN9JC87XG4gIHB1YmxpYyBzdGF0aWMgSVBWNl9QQVRURVJOID0gL14oPzpbQS1GMC05XXsxLDR9Oil7N31bQS1GMC05XXsxLDR9JC9pO1xuICBwdWJsaWMgc3RhdGljIEhPU1ROQU1FX1BBVFRFUk4gPSAvXltBLXowLTldK1tBLXowLTlfLi1dKiQvO1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogc3RyaW5nO1xuICBwdWJsaWMgcmVhZG9ubHkgaXNJUHY0OiBib29sZWFuO1xuICBwdWJsaWMgcmVhZG9ubHkgaXNJUHY2OiBib29sZWFuO1xuICBwdWJsaWMgcmVhZG9ubHkgaXNIb3N0bmFtZTogYm9vbGVhbjtcblxuICBjb25zdHJ1Y3Rvcihob3N0OiBIb3N0IHwgc3RyaW5nKSB7XG4gICAgc3VwZXIoKTtcbiAgICBpZiAoIWhvc3QpIHtcbiAgICAgIHRocm93RXJyb3JGb3JJbnZhbGlkRmllbGQoJ2hvc3QnLCBob3N0KTtcbiAgICB9XG4gICAgaWYgKGhvc3QgaW5zdGFuY2VvZiBIb3N0KSB7XG4gICAgICBob3N0ID0gaG9zdC5kYXRhO1xuICAgIH1cbiAgICBob3N0ID0gcHVueWNvZGUudG9BU0NJSShob3N0KSBhcyBzdHJpbmc7XG4gICAgdGhpcy5pc0lQdjQgPSBIb3N0LklQVjRfUEFUVEVSTi50ZXN0KGhvc3QpO1xuICAgIHRoaXMuaXNJUHY2ID0gdGhpcy5pc0lQdjQgPyBmYWxzZSA6IEhvc3QuSVBWNl9QQVRURVJOLnRlc3QoaG9zdCk7XG4gICAgdGhpcy5pc0hvc3RuYW1lID0gdGhpcy5pc0lQdjQgfHwgdGhpcy5pc0lQdjYgPyBmYWxzZSA6IEhvc3QuSE9TVE5BTUVfUEFUVEVSTi50ZXN0KGhvc3QpO1xuICAgIGlmICghKHRoaXMuaXNJUHY0IHx8IHRoaXMuaXNJUHY2IHx8IHRoaXMuaXNIb3N0bmFtZSkpIHtcbiAgICAgIHRocm93RXJyb3JGb3JJbnZhbGlkRmllbGQoJ2hvc3QnLCBob3N0KTtcbiAgICB9XG4gICAgdGhpcy5kYXRhID0gaG9zdDtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgUG9ydCBleHRlbmRzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIHtcbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBQQVRURVJOID0gL15bMC05XXsxLDV9JC87XG4gIHB1YmxpYyByZWFkb25seSBkYXRhOiBudW1iZXI7XG5cbiAgY29uc3RydWN0b3IocG9ydDogUG9ydCB8IHN0cmluZyB8IG51bWJlcikge1xuICAgIHN1cGVyKCk7XG4gICAgaWYgKHBvcnQgaW5zdGFuY2VvZiBQb3J0KSB7XG4gICAgICBwb3J0ID0gcG9ydC5kYXRhO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIHBvcnQgPT09ICdudW1iZXInKSB7XG4gICAgICAvLyBTdHJpbmdpZnkgaW4gY2FzZSBuZWdhdGl2ZSBvciBmbG9hdGluZyBwb2ludCAtPiB0aGUgcmVnZXggdGVzdCBiZWxvdyB3aWxsIGNhdGNoLlxuICAgICAgcG9ydCA9IHBvcnQudG9TdHJpbmcoKTtcbiAgICB9XG4gICAgaWYgKCFQb3J0LlBBVFRFUk4udGVzdChwb3J0KSkge1xuICAgICAgdGhyb3dFcnJvckZvckludmFsaWRGaWVsZCgncG9ydCcsIHBvcnQpO1xuICAgIH1cbiAgICAvLyBDb3VsZCBleGNlZWQgdGhlIG1heGltdW0gcG9ydCBudW1iZXIsIHNvIGNvbnZlcnQgdG8gTnVtYmVyIHRvIGNoZWNrLiBDb3VsZCBhbHNvIGhhdmUgbGVhZGluZ1xuICAgIC8vIHplcm9zLiBDb252ZXJ0aW5nIHRvIE51bWJlciBkcm9wcyB0aG9zZSwgc28gd2UgZ2V0IG5vcm1hbGl6YXRpb24gZm9yIGZyZWUuIDopXG4gICAgcG9ydCA9IE51bWJlcihwb3J0KTtcbiAgICBpZiAocG9ydCA+IDY1NTM1KSB7XG4gICAgICB0aHJvd0Vycm9yRm9ySW52YWxpZEZpZWxkKCdwb3J0JywgcG9ydCk7XG4gICAgfVxuICAgIHRoaXMuZGF0YSA9IHBvcnQ7XG4gIH1cbn1cblxuLy8gQSBtZXRob2QgdmFsdWUgbXVzdCBleGFjdGx5IG1hdGNoIGFuIGVsZW1lbnQgaW4gdGhlIHNldCBvZiBrbm93biBjaXBoZXJzLlxuLy8gcmVmOiBodHRwczovL2dpdGh1Yi5jb20vc2hhZG93c29ja3Mvc2hhZG93c29ja3MtbGliZXYvYmxvYi8xMGEyZDNlMy9jb21wbGV0aW9ucy9iYXNoL3NzLXJlZGlyI0w1XG5leHBvcnQgY29uc3QgTUVUSE9EUyA9IG5ldyBTZXQoW1xuICAncmM0LW1kNScsXG4gICdhZXMtMTI4LWdjbScsXG4gICdhZXMtMTkyLWdjbScsXG4gICdhZXMtMjU2LWdjbScsXG4gICdhZXMtMTI4LWNmYicsXG4gICdhZXMtMTkyLWNmYicsXG4gICdhZXMtMjU2LWNmYicsXG4gICdhZXMtMTI4LWN0cicsXG4gICdhZXMtMTkyLWN0cicsXG4gICdhZXMtMjU2LWN0cicsXG4gICdjYW1lbGxpYS0xMjgtY2ZiJyxcbiAgJ2NhbWVsbGlhLTE5Mi1jZmInLFxuICAnY2FtZWxsaWEtMjU2LWNmYicsXG4gICdiZi1jZmInLFxuICAnY2hhY2hhMjAtaWV0Zi1wb2x5MTMwNScsXG4gICdzYWxzYTIwJyxcbiAgJ2NoYWNoYTIwJyxcbiAgJ2NoYWNoYTIwLWlldGYnLFxuICAneGNoYWNoYTIwLWlldGYtcG9seTEzMDUnLFxuXSk7XG5cbmV4cG9ydCBjbGFzcyBNZXRob2QgZXh0ZW5kcyBWYWxpZGF0ZWRDb25maWdGaWVsZCB7XG4gIHB1YmxpYyByZWFkb25seSBkYXRhOiBzdHJpbmc7XG4gIGNvbnN0cnVjdG9yKG1ldGhvZDogTWV0aG9kIHwgc3RyaW5nKSB7XG4gICAgc3VwZXIoKTtcbiAgICBpZiAobWV0aG9kIGluc3RhbmNlb2YgTWV0aG9kKSB7XG4gICAgICBtZXRob2QgPSBtZXRob2QuZGF0YTtcbiAgICB9XG4gICAgaWYgKCFNRVRIT0RTLmhhcyhtZXRob2QpKSB7XG4gICAgICB0aHJvd0Vycm9yRm9ySW52YWxpZEZpZWxkKCdtZXRob2QnLCBtZXRob2QpO1xuICAgIH1cbiAgICB0aGlzLmRhdGEgPSBtZXRob2Q7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFBhc3N3b3JkIGV4dGVuZHMgVmFsaWRhdGVkQ29uZmlnRmllbGQge1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogc3RyaW5nO1xuXG4gIGNvbnN0cnVjdG9yKHBhc3N3b3JkOiBQYXNzd29yZCB8IHN0cmluZykge1xuICAgIHN1cGVyKCk7XG4gICAgdGhpcy5kYXRhID0gcGFzc3dvcmQgaW5zdGFuY2VvZiBQYXNzd29yZCA/IHBhc3N3b3JkLmRhdGEgOiBwYXNzd29yZDtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgVGFnIGV4dGVuZHMgVmFsaWRhdGVkQ29uZmlnRmllbGQge1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogc3RyaW5nO1xuXG4gIGNvbnN0cnVjdG9yKHRhZzogVGFnIHwgc3RyaW5nID0gJycpIHtcbiAgICBzdXBlcigpO1xuICAgIHRoaXMuZGF0YSA9IHRhZyBpbnN0YW5jZW9mIFRhZyA/IHRhZy5kYXRhIDogdGFnO1xuICB9XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ29uZmlnIHtcbiAgaG9zdDogSG9zdDtcbiAgcG9ydDogUG9ydDtcbiAgbWV0aG9kOiBNZXRob2Q7XG4gIHBhc3N3b3JkOiBQYXNzd29yZDtcbiAgdGFnOiBUYWc7XG4gIC8vIEFueSBhZGRpdGlvbmFsIGNvbmZpZ3VyYXRpb24gKGUuZy4gYHRpbWVvdXRgLCBTSVAwMDMgYHBsdWdpbmAsIGV0Yy4pIG1heSBiZSBzdG9yZWQgaGVyZS5cbiAgZXh0cmE6IHtba2V5OiBzdHJpbmddOiBzdHJpbmd9O1xufVxuXG4vLyB0c2xpbnQ6ZGlzYWJsZS1uZXh0LWxpbmU6bm8tYW55XG5leHBvcnQgZnVuY3Rpb24gbWFrZUNvbmZpZyhpbnB1dDoge1trZXk6IHN0cmluZ106IGFueX0pOiBDb25maWcge1xuICAvLyBVc2UgXCIhXCIgZm9yIHRoZSByZXF1aXJlZCBmaWVsZHMgdG8gdGVsbCB0c2MgdGhhdCB3ZSBoYW5kbGUgdW5kZWZpbmVkIGluIHRoZVxuICAvLyBWYWxpZGF0ZWRDb25maWdGaWVsZHMgd2UgY2FsbDsgdHNjIGNhbid0IGZpZ3VyZSB0aGF0IG91dCBvdGhlcndpc2UuXG4gIGNvbnN0IGNvbmZpZyA9IHtcbiAgICBob3N0OiBuZXcgSG9zdChpbnB1dC5ob3N0ISksXG4gICAgcG9ydDogbmV3IFBvcnQoaW5wdXQucG9ydCEpLFxuICAgIG1ldGhvZDogbmV3IE1ldGhvZChpbnB1dC5tZXRob2QhKSxcbiAgICBwYXNzd29yZDogbmV3IFBhc3N3b3JkKGlucHV0LnBhc3N3b3JkISksXG4gICAgdGFnOiBuZXcgVGFnKGlucHV0LnRhZyksICAvLyBpbnB1dC50YWcgbWlnaHQgYmUgdW5kZWZpbmVkIGJ1dCBUYWcoKSBoYW5kbGVzIHRoYXQgZmluZS5cbiAgICBleHRyYToge30gYXMge1trZXk6IHN0cmluZ106IHN0cmluZ30sXG4gIH07XG4gIC8vIFB1dCBhbnkgcmVtYWluaW5nIGZpZWxkcyBpbiBgaW5wdXRgIGludG8gYGNvbmZpZy5leHRyYWAuXG4gIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKGlucHV0KSkge1xuICAgIGlmICghL14oaG9zdHxwb3J0fG1ldGhvZHxwYXNzd29yZHx0YWcpJC8udGVzdChrZXkpKSB7XG4gICAgICBjb25maWcuZXh0cmFba2V5XSA9IGlucHV0W2tleV0gJiYgaW5wdXRba2V5XS50b1N0cmluZygpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gY29uZmlnO1xufVxuXG5leHBvcnQgY29uc3QgU0hBRE9XU09DS1NfVVJJID0ge1xuICBQUk9UT0NPTDogJ3NzOicsXG5cbiAgZ2V0VXJpRm9ybWF0dGVkSG9zdDogKGhvc3Q6IEhvc3QpID0+IHtcbiAgICByZXR1cm4gaG9zdC5pc0lQdjYgPyBgWyR7aG9zdC5kYXRhfV1gIDogaG9zdC5kYXRhO1xuICB9LFxuXG4gIGdldEhhc2g6ICh0YWc6IFRhZykgPT4ge1xuICAgIHJldHVybiB0YWcuZGF0YSA/IGAjJHtlbmNvZGVVUklDb21wb25lbnQodGFnLmRhdGEpfWAgOiAnJztcbiAgfSxcblxuICB2YWxpZGF0ZVByb3RvY29sOiAodXJpOiBzdHJpbmcpID0+IHtcbiAgICBpZiAoIXVyaS5zdGFydHNXaXRoKFNIQURPV1NPQ0tTX1VSSS5QUk9UT0NPTCkpIHtcbiAgICAgIHRocm93IG5ldyBJbnZhbGlkVXJpKGBVUkkgbXVzdCBzdGFydCB3aXRoIFwiJHtTSEFET1dTT0NLU19VUkkuUFJPVE9DT0x9XCJgKTtcbiAgICB9XG4gIH0sXG5cbiAgcGFyc2U6ICh1cmk6IHN0cmluZyk6IENvbmZpZyA9PiB7XG4gICAgbGV0IGVycm9yOiBFcnJvciB8IHVuZGVmaW5lZDtcbiAgICBmb3IgKGNvbnN0IHVyaVR5cGUgb2YgW1NJUDAwMl9VUkksIExFR0FDWV9CQVNFNjRfVVJJXSkge1xuICAgICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIHVyaVR5cGUucGFyc2UodXJpKTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgZXJyb3IgPSBlO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAoIShlcnJvciBpbnN0YW5jZW9mIEludmFsaWRVcmkpKSB7XG4gICAgICBjb25zdCBvcmlnaW5hbEVycm9yTmFtZSA9IGVycm9yIS5uYW1lISB8fCAnKFVubmFtZWQgRXJyb3IpJztcbiAgICAgIGNvbnN0IG9yaWdpbmFsRXJyb3JNZXNzYWdlID0gZXJyb3IhLm1lc3NhZ2UhIHx8ICcobm8gZXJyb3IgbWVzc2FnZSBwcm92aWRlZCknO1xuICAgICAgY29uc3Qgb3JpZ2luYWxFcnJvclN0cmluZyA9IGAke29yaWdpbmFsRXJyb3JOYW1lfTogJHtvcmlnaW5hbEVycm9yTWVzc2FnZX1gO1xuICAgICAgY29uc3QgbmV3RXJyb3JNZXNzYWdlID0gYEludmFsaWQgaW5wdXQ6ICR7b3JpZ2luYWxFcnJvclN0cmluZ31gO1xuICAgICAgZXJyb3IgPSBuZXcgSW52YWxpZFVyaShuZXdFcnJvck1lc3NhZ2UpO1xuICAgIH1cbiAgICB0aHJvdyBlcnJvcjtcbiAgfSxcbn07XG5cbi8vIFJlZjogaHR0cHM6Ly9zaGFkb3dzb2Nrcy5vcmcvZW4vY29uZmlnL3F1aWNrLWd1aWRlLmh0bWxcbmV4cG9ydCBjb25zdCBMRUdBQ1lfQkFTRTY0X1VSSSA9IHtcbiAgcGFyc2U6ICh1cmk6IHN0cmluZyk6IENvbmZpZyA9PiB7XG4gICAgU0hBRE9XU09DS1NfVVJJLnZhbGlkYXRlUHJvdG9jb2wodXJpKTtcbiAgICBjb25zdCBoYXNoSW5kZXggPSB1cmkuaW5kZXhPZignIycpO1xuICAgIGNvbnN0IGhhc1RhZyA9IGhhc2hJbmRleCAhPT0gLTE7XG4gICAgY29uc3QgYjY0RW5kSW5kZXggPSBoYXNUYWcgPyBoYXNoSW5kZXggOiB1cmkubGVuZ3RoO1xuICAgIGNvbnN0IHRhZ1N0YXJ0SW5kZXggPSBoYXNUYWcgPyBoYXNoSW5kZXggKyAxIDogdXJpLmxlbmd0aDtcbiAgICBjb25zdCB0YWcgPSBuZXcgVGFnKGRlY29kZVVSSUNvbXBvbmVudCh1cmkuc3Vic3RyaW5nKHRhZ1N0YXJ0SW5kZXgpKSk7XG4gICAgY29uc3QgYjY0RW5jb2RlZERhdGEgPSB1cmkuc3Vic3RyaW5nKCdzczovLycubGVuZ3RoLCBiNjRFbmRJbmRleCk7XG4gICAgY29uc3QgYjY0RGVjb2RlZERhdGEgPSBiNjREZWNvZGUoYjY0RW5jb2RlZERhdGEpO1xuICAgIGNvbnN0IGF0U2lnbkluZGV4ID0gYjY0RGVjb2RlZERhdGEubGFzdEluZGV4T2YoJ0AnKTtcbiAgICBpZiAoYXRTaWduSW5kZXggPT09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgTWlzc2luZyBcIkBcImApO1xuICAgIH1cbiAgICBjb25zdCBtZXRob2RBbmRQYXNzd29yZCA9IGI2NERlY29kZWREYXRhLnN1YnN0cmluZygwLCBhdFNpZ25JbmRleCk7XG4gICAgY29uc3QgbWV0aG9kRW5kSW5kZXggPSBtZXRob2RBbmRQYXNzd29yZC5pbmRleE9mKCc6Jyk7XG4gICAgaWYgKG1ldGhvZEVuZEluZGV4ID09PSAtMSkge1xuICAgICAgdGhyb3cgbmV3IEludmFsaWRVcmkoYE1pc3NpbmcgcGFzc3dvcmRgKTtcbiAgICB9XG4gICAgY29uc3QgbWV0aG9kU3RyaW5nID0gbWV0aG9kQW5kUGFzc3dvcmQuc3Vic3RyaW5nKDAsIG1ldGhvZEVuZEluZGV4KTtcbiAgICBjb25zdCBtZXRob2QgPSBuZXcgTWV0aG9kKG1ldGhvZFN0cmluZyk7XG4gICAgY29uc3QgcGFzc3dvcmRTdGFydEluZGV4ID0gbWV0aG9kRW5kSW5kZXggKyAxO1xuICAgIGNvbnN0IHBhc3N3b3JkU3RyaW5nID0gbWV0aG9kQW5kUGFzc3dvcmQuc3Vic3RyaW5nKHBhc3N3b3JkU3RhcnRJbmRleCk7XG4gICAgY29uc3QgcGFzc3dvcmQgPSBuZXcgUGFzc3dvcmQocGFzc3dvcmRTdHJpbmcpO1xuICAgIGNvbnN0IGhvc3RTdGFydEluZGV4ID0gYXRTaWduSW5kZXggKyAxO1xuICAgIGNvbnN0IGhvc3RBbmRQb3J0ID0gYjY0RGVjb2RlZERhdGEuc3Vic3RyaW5nKGhvc3RTdGFydEluZGV4KTtcbiAgICBjb25zdCBob3N0RW5kSW5kZXggPSBob3N0QW5kUG9ydC5sYXN0SW5kZXhPZignOicpO1xuICAgIGlmIChob3N0RW5kSW5kZXggPT09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgTWlzc2luZyBwb3J0YCk7XG4gICAgfVxuICAgIGNvbnN0IHVyaUZvcm1hdHRlZEhvc3QgPSBob3N0QW5kUG9ydC5zdWJzdHJpbmcoMCwgaG9zdEVuZEluZGV4KTtcbiAgICBsZXQgaG9zdDogSG9zdDtcbiAgICB0cnkge1xuICAgICAgaG9zdCA9IG5ldyBIb3N0KHVyaUZvcm1hdHRlZEhvc3QpO1xuICAgIH0gY2F0Y2ggKF8pIHtcbiAgICAgIC8vIENvdWxkIGJlIElQdjYgaG9zdCBmb3JtYXR0ZWQgd2l0aCBzdXJyb3VuZGluZyBicmFja2V0cywgc28gdHJ5IHN0cmlwcGluZyBmaXJzdCBhbmQgbGFzdFxuICAgICAgLy8gY2hhcmFjdGVycy4gSWYgdGhpcyB0aHJvd3MsIGdpdmUgdXAgYW5kIGxldCB0aGUgZXhjZXB0aW9uIHByb3BhZ2F0ZS5cbiAgICAgIGhvc3QgPSBuZXcgSG9zdCh1cmlGb3JtYXR0ZWRIb3N0LnN1YnN0cmluZygxLCB1cmlGb3JtYXR0ZWRIb3N0Lmxlbmd0aCAtIDEpKTtcbiAgICB9XG4gICAgY29uc3QgcG9ydFN0YXJ0SW5kZXggPSBob3N0RW5kSW5kZXggKyAxO1xuICAgIGNvbnN0IHBvcnRTdHJpbmcgPSBob3N0QW5kUG9ydC5zdWJzdHJpbmcocG9ydFN0YXJ0SW5kZXgpO1xuICAgIGNvbnN0IHBvcnQgPSBuZXcgUG9ydChwb3J0U3RyaW5nKTtcbiAgICBjb25zdCBleHRyYSA9IHt9IGFzIHtba2V5OiBzdHJpbmddOiBzdHJpbmd9OyAgLy8gZW1wdHkgYmVjYXVzZSBMZWdhY3lCYXNlNjRVcmkgY2FuJ3QgaG9sZCBleHRyYVxuICAgIHJldHVybiB7bWV0aG9kLCBwYXNzd29yZCwgaG9zdCwgcG9ydCwgdGFnLCBleHRyYX07XG4gIH0sXG5cbiAgc3RyaW5naWZ5OiAoY29uZmlnOiBDb25maWcpID0+IHtcbiAgICBjb25zdCB7aG9zdCwgcG9ydCwgbWV0aG9kLCBwYXNzd29yZCwgdGFnfSA9IGNvbmZpZztcbiAgICBjb25zdCBoYXNoID0gU0hBRE9XU09DS1NfVVJJLmdldEhhc2godGFnKTtcbiAgICBsZXQgYjY0RW5jb2RlZERhdGEgPSBiNjRFbmNvZGUoYCR7bWV0aG9kLmRhdGF9OiR7cGFzc3dvcmQuZGF0YX1AJHtob3N0LmRhdGF9OiR7cG9ydC5kYXRhfWApO1xuICAgIGNvbnN0IGRhdGFMZW5ndGggPSBiNjRFbmNvZGVkRGF0YS5sZW5ndGg7XG4gICAgbGV0IHBhZGRpbmdMZW5ndGggPSAwO1xuICAgIGZvciAoOyBiNjRFbmNvZGVkRGF0YVtkYXRhTGVuZ3RoIC0gMSAtIHBhZGRpbmdMZW5ndGhdID09PSAnPSc7IHBhZGRpbmdMZW5ndGgrKyk7XG4gICAgYjY0RW5jb2RlZERhdGEgPSBwYWRkaW5nTGVuZ3RoID09PSAwID8gYjY0RW5jb2RlZERhdGEgOlxuICAgICAgICBiNjRFbmNvZGVkRGF0YS5zdWJzdHJpbmcoMCwgZGF0YUxlbmd0aCAtIHBhZGRpbmdMZW5ndGgpO1xuICAgIHJldHVybiBgc3M6Ly8ke2I2NEVuY29kZWREYXRhfSR7aGFzaH1gO1xuICB9LFxufTtcblxuLy8gUmVmOiBodHRwczovL3NoYWRvd3NvY2tzLm9yZy9lbi9zcGVjL1NJUDAwMi1VUkktU2NoZW1lLmh0bWxcbmV4cG9ydCBjb25zdCBTSVAwMDJfVVJJID0ge1xuICBwYXJzZTogKHVyaTogc3RyaW5nKTogQ29uZmlnID0+IHtcbiAgICBTSEFET1dTT0NLU19VUkkudmFsaWRhdGVQcm90b2NvbCh1cmkpO1xuICAgIC8vIENhbiB1c2UgYnVpbHQtaW4gVVJMIHBhcnNlciBmb3IgZXhwZWRpZW5jZS4gSnVzdCBoYXZlIHRvIHJlcGxhY2UgXCJzc1wiIHdpdGggXCJodHRwXCIgdG8gZW5zdXJlXG4gICAgLy8gY29ycmVjdCByZXN1bHRzLCBvdGhlcndpc2UgYnJvd3NlcnMgbGlrZSBTYWZhcmkgZmFpbCB0byBwYXJzZSBpdC5cbiAgICBjb25zdCBpbnB1dEZvclVybFBhcnNlciA9IGBodHRwJHt1cmkuc3Vic3RyaW5nKDIpfWA7XG4gICAgLy8gVGhlIGJ1aWx0LWluIFVSTCBwYXJzZXIgdGhyb3dzIGFzIGRlc2lyZWQgd2hlbiBnaXZlbiBVUklzIHdpdGggaW52YWxpZCBzeW50YXguXG4gICAgY29uc3QgdXJsUGFyc2VyUmVzdWx0ID0gbmV3IFVSTChpbnB1dEZvclVybFBhcnNlcik7XG4gICAgY29uc3QgdXJpRm9ybWF0dGVkSG9zdCA9IHVybFBhcnNlclJlc3VsdC5ob3N0bmFtZTtcbiAgICAvLyBVUkktZm9ybWF0dGVkIElQdjYgaG9zdG5hbWVzIGhhdmUgc3Vycm91bmRpbmcgYnJhY2tldHMuXG4gICAgY29uc3QgbGFzdCA9IHVyaUZvcm1hdHRlZEhvc3QubGVuZ3RoIC0gMTtcbiAgICBjb25zdCBicmFja2V0cyA9IHVyaUZvcm1hdHRlZEhvc3RbMF0gPT09ICdbJyAmJiB1cmlGb3JtYXR0ZWRIb3N0W2xhc3RdID09PSAnXSc7XG4gICAgY29uc3QgaG9zdFN0cmluZyA9IGJyYWNrZXRzID8gdXJpRm9ybWF0dGVkSG9zdC5zdWJzdHJpbmcoMSwgbGFzdCkgOiB1cmlGb3JtYXR0ZWRIb3N0O1xuICAgIGNvbnN0IGhvc3QgPSBuZXcgSG9zdChob3N0U3RyaW5nKTtcbiAgICBsZXQgcGFyc2VkUG9ydCA9IHVybFBhcnNlclJlc3VsdC5wb3J0O1xuICAgIGlmICghcGFyc2VkUG9ydCAmJiB1cmkubWF0Y2goLzo4MCgkfFxcLykvZykpIHtcbiAgICAgIC8vIFRoZSBkZWZhdWx0IFVSTCBwYXJzZXIgZmFpbHMgdG8gcmVjb2duaXplIHRoZSBkZWZhdWx0IHBvcnQgKDgwKSB3aGVuIHRoZSBVUkkgYmVpbmcgcGFyc2VkXG4gICAgICAvLyBpcyBIVFRQLiBDaGVjayBpZiB0aGUgcG9ydCBpcyBwcmVzZW50IGF0IHRoZSBlbmQgb2YgdGhlIHN0cmluZyBvciBiZWZvcmUgdGhlIHBhcmFtZXRlcnMuXG4gICAgICBwYXJzZWRQb3J0ID0gODA7XG4gICAgfVxuICAgIGNvbnN0IHBvcnQgPSBuZXcgUG9ydChwYXJzZWRQb3J0KTtcbiAgICBjb25zdCB0YWcgPSBuZXcgVGFnKGRlY29kZVVSSUNvbXBvbmVudCh1cmxQYXJzZXJSZXN1bHQuaGFzaC5zdWJzdHJpbmcoMSkpKTtcbiAgICBjb25zdCBiNjRFbmNvZGVkVXNlckluZm8gPSB1cmxQYXJzZXJSZXN1bHQudXNlcm5hbWUucmVwbGFjZSgvJTNEL2csICc9Jyk7XG4gICAgLy8gYmFzZTY0LmRlY29kZSB0aHJvd3MgYXMgZGVzaXJlZCB3aGVuIGdpdmVuIGludmFsaWQgYmFzZTY0IGlucHV0LlxuICAgIGNvbnN0IGI2NERlY29kZWRVc2VySW5mbyA9IGI2NERlY29kZShiNjRFbmNvZGVkVXNlckluZm8pO1xuICAgIGNvbnN0IGNvbG9uSWR4ID0gYjY0RGVjb2RlZFVzZXJJbmZvLmluZGV4T2YoJzonKTtcbiAgICBpZiAoY29sb25JZHggPT09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgTWlzc2luZyBwYXNzd29yZGApO1xuICAgIH1cbiAgICBjb25zdCBtZXRob2RTdHJpbmcgPSBiNjREZWNvZGVkVXNlckluZm8uc3Vic3RyaW5nKDAsIGNvbG9uSWR4KTtcbiAgICBjb25zdCBtZXRob2QgPSBuZXcgTWV0aG9kKG1ldGhvZFN0cmluZyk7XG4gICAgY29uc3QgcGFzc3dvcmRTdHJpbmcgPSBiNjREZWNvZGVkVXNlckluZm8uc3Vic3RyaW5nKGNvbG9uSWR4ICsgMSk7XG4gICAgY29uc3QgcGFzc3dvcmQgPSBuZXcgUGFzc3dvcmQocGFzc3dvcmRTdHJpbmcpO1xuICAgIGNvbnN0IHF1ZXJ5UGFyYW1zID0gdXJsUGFyc2VyUmVzdWx0LnNlYXJjaC5zdWJzdHJpbmcoMSkuc3BsaXQoJyYnKTtcbiAgICBjb25zdCBleHRyYSA9IHt9IGFzIHtba2V5OiBzdHJpbmddOiBzdHJpbmd9O1xuICAgIGZvciAoY29uc3QgcGFpciBvZiBxdWVyeVBhcmFtcykge1xuICAgICAgY29uc3QgW2tleSwgdmFsdWVdID0gcGFpci5zcGxpdCgnPScsIDIpO1xuICAgICAgaWYgKCFrZXkpIGNvbnRpbnVlO1xuICAgICAgZXh0cmFba2V5XSA9IGRlY29kZVVSSUNvbXBvbmVudCh2YWx1ZSB8fCAnJyk7XG4gICAgfVxuICAgIHJldHVybiB7bWV0aG9kLCBwYXNzd29yZCwgaG9zdCwgcG9ydCwgdGFnLCBleHRyYX07XG4gIH0sXG5cbiAgc3RyaW5naWZ5OiAoY29uZmlnOiBDb25maWcpID0+IHtcbiAgICBjb25zdCB7aG9zdCwgcG9ydCwgbWV0aG9kLCBwYXNzd29yZCwgdGFnLCBleHRyYX0gPSBjb25maWc7XG4gICAgY29uc3QgdXNlckluZm8gPSBiNjRFbmNvZGUoYCR7bWV0aG9kLmRhdGF9OiR7cGFzc3dvcmQuZGF0YX1gKTtcbiAgICBjb25zdCB1cmlIb3N0ID0gU0hBRE9XU09DS1NfVVJJLmdldFVyaUZvcm1hdHRlZEhvc3QoaG9zdCk7XG4gICAgY29uc3QgaGFzaCA9IFNIQURPV1NPQ0tTX1VSSS5nZXRIYXNoKHRhZyk7XG4gICAgbGV0IHF1ZXJ5U3RyaW5nID0gJyc7XG4gICAgZm9yIChjb25zdCBrZXkgaW4gZXh0cmEpIHtcbiAgICAgIGlmICgha2V5KSBjb250aW51ZTtcbiAgICAgIHF1ZXJ5U3RyaW5nICs9IChxdWVyeVN0cmluZyA/ICcmJyA6ICc/JykgKyBgJHtrZXl9PSR7ZW5jb2RlVVJJQ29tcG9uZW50KGV4dHJhW2tleV0pfWA7XG4gICAgfVxuICAgIHJldHVybiBgc3M6Ly8ke3VzZXJJbmZvfUAke3VyaUhvc3R9OiR7cG9ydC5kYXRhfS8ke3F1ZXJ5U3RyaW5nfSR7aGFzaH1gO1xuICB9LFxufTtcbiIsIi8qISBodHRwOi8vbXRocy5iZS9iYXNlNjQgdjAuMS4wIGJ5IEBtYXRoaWFzIHwgTUlUIGxpY2Vuc2UgKi9cbjsoZnVuY3Rpb24ocm9vdCkge1xuXG5cdC8vIERldGVjdCBmcmVlIHZhcmlhYmxlcyBgZXhwb3J0c2AuXG5cdHZhciBmcmVlRXhwb3J0cyA9IHR5cGVvZiBleHBvcnRzID09ICdvYmplY3QnICYmIGV4cG9ydHM7XG5cblx0Ly8gRGV0ZWN0IGZyZWUgdmFyaWFibGUgYG1vZHVsZWAuXG5cdHZhciBmcmVlTW9kdWxlID0gdHlwZW9mIG1vZHVsZSA9PSAnb2JqZWN0JyAmJiBtb2R1bGUgJiZcblx0XHRtb2R1bGUuZXhwb3J0cyA9PSBmcmVlRXhwb3J0cyAmJiBtb2R1bGU7XG5cblx0Ly8gRGV0ZWN0IGZyZWUgdmFyaWFibGUgYGdsb2JhbGAsIGZyb20gTm9kZS5qcyBvciBCcm93c2VyaWZpZWQgY29kZSwgYW5kIHVzZVxuXHQvLyBpdCBhcyBgcm9vdGAuXG5cdHZhciBmcmVlR2xvYmFsID0gdHlwZW9mIGdsb2JhbCA9PSAnb2JqZWN0JyAmJiBnbG9iYWw7XG5cdGlmIChmcmVlR2xvYmFsLmdsb2JhbCA9PT0gZnJlZUdsb2JhbCB8fCBmcmVlR2xvYmFsLndpbmRvdyA9PT0gZnJlZUdsb2JhbCkge1xuXHRcdHJvb3QgPSBmcmVlR2xvYmFsO1xuXHR9XG5cblx0LyotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSovXG5cblx0dmFyIEludmFsaWRDaGFyYWN0ZXJFcnJvciA9IGZ1bmN0aW9uKG1lc3NhZ2UpIHtcblx0XHR0aGlzLm1lc3NhZ2UgPSBtZXNzYWdlO1xuXHR9O1xuXHRJbnZhbGlkQ2hhcmFjdGVyRXJyb3IucHJvdG90eXBlID0gbmV3IEVycm9yO1xuXHRJbnZhbGlkQ2hhcmFjdGVyRXJyb3IucHJvdG90eXBlLm5hbWUgPSAnSW52YWxpZENoYXJhY3RlckVycm9yJztcblxuXHR2YXIgZXJyb3IgPSBmdW5jdGlvbihtZXNzYWdlKSB7XG5cdFx0Ly8gTm90ZTogdGhlIGVycm9yIG1lc3NhZ2VzIHVzZWQgdGhyb3VnaG91dCB0aGlzIGZpbGUgbWF0Y2ggdGhvc2UgdXNlZCBieVxuXHRcdC8vIHRoZSBuYXRpdmUgYGF0b2JgL2BidG9hYCBpbXBsZW1lbnRhdGlvbiBpbiBDaHJvbWl1bS5cblx0XHR0aHJvdyBuZXcgSW52YWxpZENoYXJhY3RlckVycm9yKG1lc3NhZ2UpO1xuXHR9O1xuXG5cdHZhciBUQUJMRSA9ICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvJztcblx0Ly8gaHR0cDovL3doYXR3Zy5vcmcvaHRtbC9jb21tb24tbWljcm9zeW50YXhlcy5odG1sI3NwYWNlLWNoYXJhY3RlclxuXHR2YXIgUkVHRVhfU1BBQ0VfQ0hBUkFDVEVSUyA9IC9bXFx0XFxuXFxmXFxyIF0vZztcblxuXHQvLyBgZGVjb2RlYCBpcyBkZXNpZ25lZCB0byBiZSBmdWxseSBjb21wYXRpYmxlIHdpdGggYGF0b2JgIGFzIGRlc2NyaWJlZCBpbiB0aGVcblx0Ly8gSFRNTCBTdGFuZGFyZC4gaHR0cDovL3doYXR3Zy5vcmcvaHRtbC93ZWJhcHBhcGlzLmh0bWwjZG9tLXdpbmRvd2Jhc2U2NC1hdG9iXG5cdC8vIFRoZSBvcHRpbWl6ZWQgYmFzZTY0LWRlY29kaW5nIGFsZ29yaXRobSB1c2VkIGlzIGJhc2VkIG9uIEBhdGvigJlzIGV4Y2VsbGVudFxuXHQvLyBpbXBsZW1lbnRhdGlvbi4gaHR0cHM6Ly9naXN0LmdpdGh1Yi5jb20vYXRrLzEwMjAzOTZcblx0dmFyIGRlY29kZSA9IGZ1bmN0aW9uKGlucHV0KSB7XG5cdFx0aW5wdXQgPSBTdHJpbmcoaW5wdXQpXG5cdFx0XHQucmVwbGFjZShSRUdFWF9TUEFDRV9DSEFSQUNURVJTLCAnJyk7XG5cdFx0dmFyIGxlbmd0aCA9IGlucHV0Lmxlbmd0aDtcblx0XHRpZiAobGVuZ3RoICUgNCA9PSAwKSB7XG5cdFx0XHRpbnB1dCA9IGlucHV0LnJlcGxhY2UoLz09PyQvLCAnJyk7XG5cdFx0XHRsZW5ndGggPSBpbnB1dC5sZW5ndGg7XG5cdFx0fVxuXHRcdGlmIChcblx0XHRcdGxlbmd0aCAlIDQgPT0gMSB8fFxuXHRcdFx0Ly8gaHR0cDovL3doYXR3Zy5vcmcvQyNhbHBoYW51bWVyaWMtYXNjaWktY2hhcmFjdGVyc1xuXHRcdFx0L1teK2EtekEtWjAtOS9dLy50ZXN0KGlucHV0KVxuXHRcdCkge1xuXHRcdFx0ZXJyb3IoXG5cdFx0XHRcdCdJbnZhbGlkIGNoYXJhY3RlcjogdGhlIHN0cmluZyB0byBiZSBkZWNvZGVkIGlzIG5vdCBjb3JyZWN0bHkgZW5jb2RlZC4nXG5cdFx0XHQpO1xuXHRcdH1cblx0XHR2YXIgYml0Q291bnRlciA9IDA7XG5cdFx0dmFyIGJpdFN0b3JhZ2U7XG5cdFx0dmFyIGJ1ZmZlcjtcblx0XHR2YXIgb3V0cHV0ID0gJyc7XG5cdFx0dmFyIHBvc2l0aW9uID0gLTE7XG5cdFx0d2hpbGUgKCsrcG9zaXRpb24gPCBsZW5ndGgpIHtcblx0XHRcdGJ1ZmZlciA9IFRBQkxFLmluZGV4T2YoaW5wdXQuY2hhckF0KHBvc2l0aW9uKSk7XG5cdFx0XHRiaXRTdG9yYWdlID0gYml0Q291bnRlciAlIDQgPyBiaXRTdG9yYWdlICogNjQgKyBidWZmZXIgOiBidWZmZXI7XG5cdFx0XHQvLyBVbmxlc3MgdGhpcyBpcyB0aGUgZmlyc3Qgb2YgYSBncm91cCBvZiA0IGNoYXJhY3RlcnPigKZcblx0XHRcdGlmIChiaXRDb3VudGVyKysgJSA0KSB7XG5cdFx0XHRcdC8vIOKApmNvbnZlcnQgdGhlIGZpcnN0IDggYml0cyB0byBhIHNpbmdsZSBBU0NJSSBjaGFyYWN0ZXIuXG5cdFx0XHRcdG91dHB1dCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKFxuXHRcdFx0XHRcdDB4RkYgJiBiaXRTdG9yYWdlID4+ICgtMiAqIGJpdENvdW50ZXIgJiA2KVxuXHRcdFx0XHQpO1xuXHRcdFx0fVxuXHRcdH1cblx0XHRyZXR1cm4gb3V0cHV0O1xuXHR9O1xuXG5cdC8vIGBlbmNvZGVgIGlzIGRlc2lnbmVkIHRvIGJlIGZ1bGx5IGNvbXBhdGlibGUgd2l0aCBgYnRvYWAgYXMgZGVzY3JpYmVkIGluIHRoZVxuXHQvLyBIVE1MIFN0YW5kYXJkOiBodHRwOi8vd2hhdHdnLm9yZy9odG1sL3dlYmFwcGFwaXMuaHRtbCNkb20td2luZG93YmFzZTY0LWJ0b2Fcblx0dmFyIGVuY29kZSA9IGZ1bmN0aW9uKGlucHV0KSB7XG5cdFx0aW5wdXQgPSBTdHJpbmcoaW5wdXQpO1xuXHRcdGlmICgvW15cXDAtXFx4RkZdLy50ZXN0KGlucHV0KSkge1xuXHRcdFx0Ly8gTm90ZTogbm8gbmVlZCB0byBzcGVjaWFsLWNhc2UgYXN0cmFsIHN5bWJvbHMgaGVyZSwgYXMgc3Vycm9nYXRlcyBhcmVcblx0XHRcdC8vIG1hdGNoZWQsIGFuZCB0aGUgaW5wdXQgaXMgc3VwcG9zZWQgdG8gb25seSBjb250YWluIEFTQ0lJIGFueXdheS5cblx0XHRcdGVycm9yKFxuXHRcdFx0XHQnVGhlIHN0cmluZyB0byBiZSBlbmNvZGVkIGNvbnRhaW5zIGNoYXJhY3RlcnMgb3V0c2lkZSBvZiB0aGUgJyArXG5cdFx0XHRcdCdMYXRpbjEgcmFuZ2UuJ1xuXHRcdFx0KTtcblx0XHR9XG5cdFx0dmFyIHBhZGRpbmcgPSBpbnB1dC5sZW5ndGggJSAzO1xuXHRcdHZhciBvdXRwdXQgPSAnJztcblx0XHR2YXIgcG9zaXRpb24gPSAtMTtcblx0XHR2YXIgYTtcblx0XHR2YXIgYjtcblx0XHR2YXIgYztcblx0XHR2YXIgZDtcblx0XHR2YXIgYnVmZmVyO1xuXHRcdC8vIE1ha2Ugc3VyZSBhbnkgcGFkZGluZyBpcyBoYW5kbGVkIG91dHNpZGUgb2YgdGhlIGxvb3AuXG5cdFx0dmFyIGxlbmd0aCA9IGlucHV0Lmxlbmd0aCAtIHBhZGRpbmc7XG5cblx0XHR3aGlsZSAoKytwb3NpdGlvbiA8IGxlbmd0aCkge1xuXHRcdFx0Ly8gUmVhZCB0aHJlZSBieXRlcywgaS5lLiAyNCBiaXRzLlxuXHRcdFx0YSA9IGlucHV0LmNoYXJDb2RlQXQocG9zaXRpb24pIDw8IDE2O1xuXHRcdFx0YiA9IGlucHV0LmNoYXJDb2RlQXQoKytwb3NpdGlvbikgPDwgODtcblx0XHRcdGMgPSBpbnB1dC5jaGFyQ29kZUF0KCsrcG9zaXRpb24pO1xuXHRcdFx0YnVmZmVyID0gYSArIGIgKyBjO1xuXHRcdFx0Ly8gVHVybiB0aGUgMjQgYml0cyBpbnRvIGZvdXIgY2h1bmtzIG9mIDYgYml0cyBlYWNoLCBhbmQgYXBwZW5kIHRoZVxuXHRcdFx0Ly8gbWF0Y2hpbmcgY2hhcmFjdGVyIGZvciBlYWNoIG9mIHRoZW0gdG8gdGhlIG91dHB1dC5cblx0XHRcdG91dHB1dCArPSAoXG5cdFx0XHRcdFRBQkxFLmNoYXJBdChidWZmZXIgPj4gMTggJiAweDNGKSArXG5cdFx0XHRcdFRBQkxFLmNoYXJBdChidWZmZXIgPj4gMTIgJiAweDNGKSArXG5cdFx0XHRcdFRBQkxFLmNoYXJBdChidWZmZXIgPj4gNiAmIDB4M0YpICtcblx0XHRcdFx0VEFCTEUuY2hhckF0KGJ1ZmZlciAmIDB4M0YpXG5cdFx0XHQpO1xuXHRcdH1cblxuXHRcdGlmIChwYWRkaW5nID09IDIpIHtcblx0XHRcdGEgPSBpbnB1dC5jaGFyQ29kZUF0KHBvc2l0aW9uKSA8PCA4O1xuXHRcdFx0YiA9IGlucHV0LmNoYXJDb2RlQXQoKytwb3NpdGlvbik7XG5cdFx0XHRidWZmZXIgPSBhICsgYjtcblx0XHRcdG91dHB1dCArPSAoXG5cdFx0XHRcdFRBQkxFLmNoYXJBdChidWZmZXIgPj4gMTApICtcblx0XHRcdFx0VEFCTEUuY2hhckF0KChidWZmZXIgPj4gNCkgJiAweDNGKSArXG5cdFx0XHRcdFRBQkxFLmNoYXJBdCgoYnVmZmVyIDw8IDIpICYgMHgzRikgK1xuXHRcdFx0XHQnPSdcblx0XHRcdCk7XG5cdFx0fSBlbHNlIGlmIChwYWRkaW5nID09IDEpIHtcblx0XHRcdGJ1ZmZlciA9IGlucHV0LmNoYXJDb2RlQXQocG9zaXRpb24pO1xuXHRcdFx0b3V0cHV0ICs9IChcblx0XHRcdFx0VEFCTEUuY2hhckF0KGJ1ZmZlciA+PiAyKSArXG5cdFx0XHRcdFRBQkxFLmNoYXJBdCgoYnVmZmVyIDw8IDQpICYgMHgzRikgK1xuXHRcdFx0XHQnPT0nXG5cdFx0XHQpO1xuXHRcdH1cblxuXHRcdHJldHVybiBvdXRwdXQ7XG5cdH07XG5cblx0dmFyIGJhc2U2NCA9IHtcblx0XHQnZW5jb2RlJzogZW5jb2RlLFxuXHRcdCdkZWNvZGUnOiBkZWNvZGUsXG5cdFx0J3ZlcnNpb24nOiAnMC4xLjAnXG5cdH07XG5cblx0Ly8gU29tZSBBTUQgYnVpbGQgb3B0aW1pemVycywgbGlrZSByLmpzLCBjaGVjayBmb3Igc3BlY2lmaWMgY29uZGl0aW9uIHBhdHRlcm5zXG5cdC8vIGxpa2UgdGhlIGZvbGxvd2luZzpcblx0aWYgKFxuXHRcdHR5cGVvZiBkZWZpbmUgPT0gJ2Z1bmN0aW9uJyAmJlxuXHRcdHR5cGVvZiBkZWZpbmUuYW1kID09ICdvYmplY3QnICYmXG5cdFx0ZGVmaW5lLmFtZFxuXHQpIHtcblx0XHRkZWZpbmUoZnVuY3Rpb24oKSB7XG5cdFx0XHRyZXR1cm4gYmFzZTY0O1xuXHRcdH0pO1xuXHR9XHRlbHNlIGlmIChmcmVlRXhwb3J0cyAmJiAhZnJlZUV4cG9ydHMubm9kZVR5cGUpIHtcblx0XHRpZiAoZnJlZU1vZHVsZSkgeyAvLyBpbiBOb2RlLmpzIG9yIFJpbmdvSlMgdjAuOC4wK1xuXHRcdFx0ZnJlZU1vZHVsZS5leHBvcnRzID0gYmFzZTY0O1xuXHRcdH0gZWxzZSB7IC8vIGluIE5hcndoYWwgb3IgUmluZ29KUyB2MC43LjAtXG5cdFx0XHRmb3IgKHZhciBrZXkgaW4gYmFzZTY0KSB7XG5cdFx0XHRcdGJhc2U2NC5oYXNPd25Qcm9wZXJ0eShrZXkpICYmIChmcmVlRXhwb3J0c1trZXldID0gYmFzZTY0W2tleV0pO1xuXHRcdFx0fVxuXHRcdH1cblx0fSBlbHNlIHsgLy8gaW4gUmhpbm8gb3IgYSB3ZWIgYnJvd3NlclxuXHRcdHJvb3QuYmFzZTY0ID0gYmFzZTY0O1xuXHR9XG5cbn0odGhpcykpO1xuIiwiLyohIGh0dHBzOi8vbXRocy5iZS9wdW55Y29kZSB2MS40LjEgYnkgQG1hdGhpYXMgKi9cbjsoZnVuY3Rpb24ocm9vdCkge1xuXG5cdC8qKiBEZXRlY3QgZnJlZSB2YXJpYWJsZXMgKi9cblx0dmFyIGZyZWVFeHBvcnRzID0gdHlwZW9mIGV4cG9ydHMgPT0gJ29iamVjdCcgJiYgZXhwb3J0cyAmJlxuXHRcdCFleHBvcnRzLm5vZGVUeXBlICYmIGV4cG9ydHM7XG5cdHZhciBmcmVlTW9kdWxlID0gdHlwZW9mIG1vZHVsZSA9PSAnb2JqZWN0JyAmJiBtb2R1bGUgJiZcblx0XHQhbW9kdWxlLm5vZGVUeXBlICYmIG1vZHVsZTtcblx0dmFyIGZyZWVHbG9iYWwgPSB0eXBlb2YgZ2xvYmFsID09ICdvYmplY3QnICYmIGdsb2JhbDtcblx0aWYgKFxuXHRcdGZyZWVHbG9iYWwuZ2xvYmFsID09PSBmcmVlR2xvYmFsIHx8XG5cdFx0ZnJlZUdsb2JhbC53aW5kb3cgPT09IGZyZWVHbG9iYWwgfHxcblx0XHRmcmVlR2xvYmFsLnNlbGYgPT09IGZyZWVHbG9iYWxcblx0KSB7XG5cdFx0cm9vdCA9IGZyZWVHbG9iYWw7XG5cdH1cblxuXHQvKipcblx0ICogVGhlIGBwdW55Y29kZWAgb2JqZWN0LlxuXHQgKiBAbmFtZSBwdW55Y29kZVxuXHQgKiBAdHlwZSBPYmplY3Rcblx0ICovXG5cdHZhciBwdW55Y29kZSxcblxuXHQvKiogSGlnaGVzdCBwb3NpdGl2ZSBzaWduZWQgMzItYml0IGZsb2F0IHZhbHVlICovXG5cdG1heEludCA9IDIxNDc0ODM2NDcsIC8vIGFrYS4gMHg3RkZGRkZGRiBvciAyXjMxLTFcblxuXHQvKiogQm9vdHN0cmluZyBwYXJhbWV0ZXJzICovXG5cdGJhc2UgPSAzNixcblx0dE1pbiA9IDEsXG5cdHRNYXggPSAyNixcblx0c2tldyA9IDM4LFxuXHRkYW1wID0gNzAwLFxuXHRpbml0aWFsQmlhcyA9IDcyLFxuXHRpbml0aWFsTiA9IDEyOCwgLy8gMHg4MFxuXHRkZWxpbWl0ZXIgPSAnLScsIC8vICdcXHgyRCdcblxuXHQvKiogUmVndWxhciBleHByZXNzaW9ucyAqL1xuXHRyZWdleFB1bnljb2RlID0gL154bi0tLyxcblx0cmVnZXhOb25BU0NJSSA9IC9bXlxceDIwLVxceDdFXS8sIC8vIHVucHJpbnRhYmxlIEFTQ0lJIGNoYXJzICsgbm9uLUFTQ0lJIGNoYXJzXG5cdHJlZ2V4U2VwYXJhdG9ycyA9IC9bXFx4MkVcXHUzMDAyXFx1RkYwRVxcdUZGNjFdL2csIC8vIFJGQyAzNDkwIHNlcGFyYXRvcnNcblxuXHQvKiogRXJyb3IgbWVzc2FnZXMgKi9cblx0ZXJyb3JzID0ge1xuXHRcdCdvdmVyZmxvdyc6ICdPdmVyZmxvdzogaW5wdXQgbmVlZHMgd2lkZXIgaW50ZWdlcnMgdG8gcHJvY2VzcycsXG5cdFx0J25vdC1iYXNpYyc6ICdJbGxlZ2FsIGlucHV0ID49IDB4ODAgKG5vdCBhIGJhc2ljIGNvZGUgcG9pbnQpJyxcblx0XHQnaW52YWxpZC1pbnB1dCc6ICdJbnZhbGlkIGlucHV0J1xuXHR9LFxuXG5cdC8qKiBDb252ZW5pZW5jZSBzaG9ydGN1dHMgKi9cblx0YmFzZU1pbnVzVE1pbiA9IGJhc2UgLSB0TWluLFxuXHRmbG9vciA9IE1hdGguZmxvb3IsXG5cdHN0cmluZ0Zyb21DaGFyQ29kZSA9IFN0cmluZy5mcm9tQ2hhckNvZGUsXG5cblx0LyoqIFRlbXBvcmFyeSB2YXJpYWJsZSAqL1xuXHRrZXk7XG5cblx0LyotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSovXG5cblx0LyoqXG5cdCAqIEEgZ2VuZXJpYyBlcnJvciB1dGlsaXR5IGZ1bmN0aW9uLlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gdHlwZSBUaGUgZXJyb3IgdHlwZS5cblx0ICogQHJldHVybnMge0Vycm9yfSBUaHJvd3MgYSBgUmFuZ2VFcnJvcmAgd2l0aCB0aGUgYXBwbGljYWJsZSBlcnJvciBtZXNzYWdlLlxuXHQgKi9cblx0ZnVuY3Rpb24gZXJyb3IodHlwZSkge1xuXHRcdHRocm93IG5ldyBSYW5nZUVycm9yKGVycm9yc1t0eXBlXSk7XG5cdH1cblxuXHQvKipcblx0ICogQSBnZW5lcmljIGBBcnJheSNtYXBgIHV0aWxpdHkgZnVuY3Rpb24uXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7QXJyYXl9IGFycmF5IFRoZSBhcnJheSB0byBpdGVyYXRlIG92ZXIuXG5cdCAqIEBwYXJhbSB7RnVuY3Rpb259IGNhbGxiYWNrIFRoZSBmdW5jdGlvbiB0aGF0IGdldHMgY2FsbGVkIGZvciBldmVyeSBhcnJheVxuXHQgKiBpdGVtLlxuXHQgKiBAcmV0dXJucyB7QXJyYXl9IEEgbmV3IGFycmF5IG9mIHZhbHVlcyByZXR1cm5lZCBieSB0aGUgY2FsbGJhY2sgZnVuY3Rpb24uXG5cdCAqL1xuXHRmdW5jdGlvbiBtYXAoYXJyYXksIGZuKSB7XG5cdFx0dmFyIGxlbmd0aCA9IGFycmF5Lmxlbmd0aDtcblx0XHR2YXIgcmVzdWx0ID0gW107XG5cdFx0d2hpbGUgKGxlbmd0aC0tKSB7XG5cdFx0XHRyZXN1bHRbbGVuZ3RoXSA9IGZuKGFycmF5W2xlbmd0aF0pO1xuXHRcdH1cblx0XHRyZXR1cm4gcmVzdWx0O1xuXHR9XG5cblx0LyoqXG5cdCAqIEEgc2ltcGxlIGBBcnJheSNtYXBgLWxpa2Ugd3JhcHBlciB0byB3b3JrIHdpdGggZG9tYWluIG5hbWUgc3RyaW5ncyBvciBlbWFpbFxuXHQgKiBhZGRyZXNzZXMuXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBkb21haW4gVGhlIGRvbWFpbiBuYW1lIG9yIGVtYWlsIGFkZHJlc3MuXG5cdCAqIEBwYXJhbSB7RnVuY3Rpb259IGNhbGxiYWNrIFRoZSBmdW5jdGlvbiB0aGF0IGdldHMgY2FsbGVkIGZvciBldmVyeVxuXHQgKiBjaGFyYWN0ZXIuXG5cdCAqIEByZXR1cm5zIHtBcnJheX0gQSBuZXcgc3RyaW5nIG9mIGNoYXJhY3RlcnMgcmV0dXJuZWQgYnkgdGhlIGNhbGxiYWNrXG5cdCAqIGZ1bmN0aW9uLlxuXHQgKi9cblx0ZnVuY3Rpb24gbWFwRG9tYWluKHN0cmluZywgZm4pIHtcblx0XHR2YXIgcGFydHMgPSBzdHJpbmcuc3BsaXQoJ0AnKTtcblx0XHR2YXIgcmVzdWx0ID0gJyc7XG5cdFx0aWYgKHBhcnRzLmxlbmd0aCA+IDEpIHtcblx0XHRcdC8vIEluIGVtYWlsIGFkZHJlc3Nlcywgb25seSB0aGUgZG9tYWluIG5hbWUgc2hvdWxkIGJlIHB1bnljb2RlZC4gTGVhdmVcblx0XHRcdC8vIHRoZSBsb2NhbCBwYXJ0IChpLmUuIGV2ZXJ5dGhpbmcgdXAgdG8gYEBgKSBpbnRhY3QuXG5cdFx0XHRyZXN1bHQgPSBwYXJ0c1swXSArICdAJztcblx0XHRcdHN0cmluZyA9IHBhcnRzWzFdO1xuXHRcdH1cblx0XHQvLyBBdm9pZCBgc3BsaXQocmVnZXgpYCBmb3IgSUU4IGNvbXBhdGliaWxpdHkuIFNlZSAjMTcuXG5cdFx0c3RyaW5nID0gc3RyaW5nLnJlcGxhY2UocmVnZXhTZXBhcmF0b3JzLCAnXFx4MkUnKTtcblx0XHR2YXIgbGFiZWxzID0gc3RyaW5nLnNwbGl0KCcuJyk7XG5cdFx0dmFyIGVuY29kZWQgPSBtYXAobGFiZWxzLCBmbikuam9pbignLicpO1xuXHRcdHJldHVybiByZXN1bHQgKyBlbmNvZGVkO1xuXHR9XG5cblx0LyoqXG5cdCAqIENyZWF0ZXMgYW4gYXJyYXkgY29udGFpbmluZyB0aGUgbnVtZXJpYyBjb2RlIHBvaW50cyBvZiBlYWNoIFVuaWNvZGVcblx0ICogY2hhcmFjdGVyIGluIHRoZSBzdHJpbmcuIFdoaWxlIEphdmFTY3JpcHQgdXNlcyBVQ1MtMiBpbnRlcm5hbGx5LFxuXHQgKiB0aGlzIGZ1bmN0aW9uIHdpbGwgY29udmVydCBhIHBhaXIgb2Ygc3Vycm9nYXRlIGhhbHZlcyAoZWFjaCBvZiB3aGljaFxuXHQgKiBVQ1MtMiBleHBvc2VzIGFzIHNlcGFyYXRlIGNoYXJhY3RlcnMpIGludG8gYSBzaW5nbGUgY29kZSBwb2ludCxcblx0ICogbWF0Y2hpbmcgVVRGLTE2LlxuXHQgKiBAc2VlIGBwdW55Y29kZS51Y3MyLmVuY29kZWBcblx0ICogQHNlZSA8aHR0cHM6Ly9tYXRoaWFzYnluZW5zLmJlL25vdGVzL2phdmFzY3JpcHQtZW5jb2Rpbmc+XG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZS51Y3MyXG5cdCAqIEBuYW1lIGRlY29kZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gc3RyaW5nIFRoZSBVbmljb2RlIGlucHV0IHN0cmluZyAoVUNTLTIpLlxuXHQgKiBAcmV0dXJucyB7QXJyYXl9IFRoZSBuZXcgYXJyYXkgb2YgY29kZSBwb2ludHMuXG5cdCAqL1xuXHRmdW5jdGlvbiB1Y3MyZGVjb2RlKHN0cmluZykge1xuXHRcdHZhciBvdXRwdXQgPSBbXSxcblx0XHQgICAgY291bnRlciA9IDAsXG5cdFx0ICAgIGxlbmd0aCA9IHN0cmluZy5sZW5ndGgsXG5cdFx0ICAgIHZhbHVlLFxuXHRcdCAgICBleHRyYTtcblx0XHR3aGlsZSAoY291bnRlciA8IGxlbmd0aCkge1xuXHRcdFx0dmFsdWUgPSBzdHJpbmcuY2hhckNvZGVBdChjb3VudGVyKyspO1xuXHRcdFx0aWYgKHZhbHVlID49IDB4RDgwMCAmJiB2YWx1ZSA8PSAweERCRkYgJiYgY291bnRlciA8IGxlbmd0aCkge1xuXHRcdFx0XHQvLyBoaWdoIHN1cnJvZ2F0ZSwgYW5kIHRoZXJlIGlzIGEgbmV4dCBjaGFyYWN0ZXJcblx0XHRcdFx0ZXh0cmEgPSBzdHJpbmcuY2hhckNvZGVBdChjb3VudGVyKyspO1xuXHRcdFx0XHRpZiAoKGV4dHJhICYgMHhGQzAwKSA9PSAweERDMDApIHsgLy8gbG93IHN1cnJvZ2F0ZVxuXHRcdFx0XHRcdG91dHB1dC5wdXNoKCgodmFsdWUgJiAweDNGRikgPDwgMTApICsgKGV4dHJhICYgMHgzRkYpICsgMHgxMDAwMCk7XG5cdFx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdFx0Ly8gdW5tYXRjaGVkIHN1cnJvZ2F0ZTsgb25seSBhcHBlbmQgdGhpcyBjb2RlIHVuaXQsIGluIGNhc2UgdGhlIG5leHRcblx0XHRcdFx0XHQvLyBjb2RlIHVuaXQgaXMgdGhlIGhpZ2ggc3Vycm9nYXRlIG9mIGEgc3Vycm9nYXRlIHBhaXJcblx0XHRcdFx0XHRvdXRwdXQucHVzaCh2YWx1ZSk7XG5cdFx0XHRcdFx0Y291bnRlci0tO1xuXHRcdFx0XHR9XG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRvdXRwdXQucHVzaCh2YWx1ZSk7XG5cdFx0XHR9XG5cdFx0fVxuXHRcdHJldHVybiBvdXRwdXQ7XG5cdH1cblxuXHQvKipcblx0ICogQ3JlYXRlcyBhIHN0cmluZyBiYXNlZCBvbiBhbiBhcnJheSBvZiBudW1lcmljIGNvZGUgcG9pbnRzLlxuXHQgKiBAc2VlIGBwdW55Y29kZS51Y3MyLmRlY29kZWBcblx0ICogQG1lbWJlck9mIHB1bnljb2RlLnVjczJcblx0ICogQG5hbWUgZW5jb2RlXG5cdCAqIEBwYXJhbSB7QXJyYXl9IGNvZGVQb2ludHMgVGhlIGFycmF5IG9mIG51bWVyaWMgY29kZSBwb2ludHMuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSBuZXcgVW5pY29kZSBzdHJpbmcgKFVDUy0yKS5cblx0ICovXG5cdGZ1bmN0aW9uIHVjczJlbmNvZGUoYXJyYXkpIHtcblx0XHRyZXR1cm4gbWFwKGFycmF5LCBmdW5jdGlvbih2YWx1ZSkge1xuXHRcdFx0dmFyIG91dHB1dCA9ICcnO1xuXHRcdFx0aWYgKHZhbHVlID4gMHhGRkZGKSB7XG5cdFx0XHRcdHZhbHVlIC09IDB4MTAwMDA7XG5cdFx0XHRcdG91dHB1dCArPSBzdHJpbmdGcm9tQ2hhckNvZGUodmFsdWUgPj4+IDEwICYgMHgzRkYgfCAweEQ4MDApO1xuXHRcdFx0XHR2YWx1ZSA9IDB4REMwMCB8IHZhbHVlICYgMHgzRkY7XG5cdFx0XHR9XG5cdFx0XHRvdXRwdXQgKz0gc3RyaW5nRnJvbUNoYXJDb2RlKHZhbHVlKTtcblx0XHRcdHJldHVybiBvdXRwdXQ7XG5cdFx0fSkuam9pbignJyk7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBiYXNpYyBjb2RlIHBvaW50IGludG8gYSBkaWdpdC9pbnRlZ2VyLlxuXHQgKiBAc2VlIGBkaWdpdFRvQmFzaWMoKWBcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IGNvZGVQb2ludCBUaGUgYmFzaWMgbnVtZXJpYyBjb2RlIHBvaW50IHZhbHVlLlxuXHQgKiBAcmV0dXJucyB7TnVtYmVyfSBUaGUgbnVtZXJpYyB2YWx1ZSBvZiBhIGJhc2ljIGNvZGUgcG9pbnQgKGZvciB1c2UgaW5cblx0ICogcmVwcmVzZW50aW5nIGludGVnZXJzKSBpbiB0aGUgcmFuZ2UgYDBgIHRvIGBiYXNlIC0gMWAsIG9yIGBiYXNlYCBpZlxuXHQgKiB0aGUgY29kZSBwb2ludCBkb2VzIG5vdCByZXByZXNlbnQgYSB2YWx1ZS5cblx0ICovXG5cdGZ1bmN0aW9uIGJhc2ljVG9EaWdpdChjb2RlUG9pbnQpIHtcblx0XHRpZiAoY29kZVBvaW50IC0gNDggPCAxMCkge1xuXHRcdFx0cmV0dXJuIGNvZGVQb2ludCAtIDIyO1xuXHRcdH1cblx0XHRpZiAoY29kZVBvaW50IC0gNjUgPCAyNikge1xuXHRcdFx0cmV0dXJuIGNvZGVQb2ludCAtIDY1O1xuXHRcdH1cblx0XHRpZiAoY29kZVBvaW50IC0gOTcgPCAyNikge1xuXHRcdFx0cmV0dXJuIGNvZGVQb2ludCAtIDk3O1xuXHRcdH1cblx0XHRyZXR1cm4gYmFzZTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyBhIGRpZ2l0L2ludGVnZXIgaW50byBhIGJhc2ljIGNvZGUgcG9pbnQuXG5cdCAqIEBzZWUgYGJhc2ljVG9EaWdpdCgpYFxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0gZGlnaXQgVGhlIG51bWVyaWMgdmFsdWUgb2YgYSBiYXNpYyBjb2RlIHBvaW50LlxuXHQgKiBAcmV0dXJucyB7TnVtYmVyfSBUaGUgYmFzaWMgY29kZSBwb2ludCB3aG9zZSB2YWx1ZSAod2hlbiB1c2VkIGZvclxuXHQgKiByZXByZXNlbnRpbmcgaW50ZWdlcnMpIGlzIGBkaWdpdGAsIHdoaWNoIG5lZWRzIHRvIGJlIGluIHRoZSByYW5nZVxuXHQgKiBgMGAgdG8gYGJhc2UgLSAxYC4gSWYgYGZsYWdgIGlzIG5vbi16ZXJvLCB0aGUgdXBwZXJjYXNlIGZvcm0gaXNcblx0ICogdXNlZDsgZWxzZSwgdGhlIGxvd2VyY2FzZSBmb3JtIGlzIHVzZWQuIFRoZSBiZWhhdmlvciBpcyB1bmRlZmluZWRcblx0ICogaWYgYGZsYWdgIGlzIG5vbi16ZXJvIGFuZCBgZGlnaXRgIGhhcyBubyB1cHBlcmNhc2UgZm9ybS5cblx0ICovXG5cdGZ1bmN0aW9uIGRpZ2l0VG9CYXNpYyhkaWdpdCwgZmxhZykge1xuXHRcdC8vICAwLi4yNSBtYXAgdG8gQVNDSUkgYS4ueiBvciBBLi5aXG5cdFx0Ly8gMjYuLjM1IG1hcCB0byBBU0NJSSAwLi45XG5cdFx0cmV0dXJuIGRpZ2l0ICsgMjIgKyA3NSAqIChkaWdpdCA8IDI2KSAtICgoZmxhZyAhPSAwKSA8PCA1KTtcblx0fVxuXG5cdC8qKlxuXHQgKiBCaWFzIGFkYXB0YXRpb24gZnVuY3Rpb24gYXMgcGVyIHNlY3Rpb24gMy40IG9mIFJGQyAzNDkyLlxuXHQgKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjMzQ5MiNzZWN0aW9uLTMuNFxuXHQgKiBAcHJpdmF0ZVxuXHQgKi9cblx0ZnVuY3Rpb24gYWRhcHQoZGVsdGEsIG51bVBvaW50cywgZmlyc3RUaW1lKSB7XG5cdFx0dmFyIGsgPSAwO1xuXHRcdGRlbHRhID0gZmlyc3RUaW1lID8gZmxvb3IoZGVsdGEgLyBkYW1wKSA6IGRlbHRhID4+IDE7XG5cdFx0ZGVsdGEgKz0gZmxvb3IoZGVsdGEgLyBudW1Qb2ludHMpO1xuXHRcdGZvciAoLyogbm8gaW5pdGlhbGl6YXRpb24gKi87IGRlbHRhID4gYmFzZU1pbnVzVE1pbiAqIHRNYXggPj4gMTsgayArPSBiYXNlKSB7XG5cdFx0XHRkZWx0YSA9IGZsb29yKGRlbHRhIC8gYmFzZU1pbnVzVE1pbik7XG5cdFx0fVxuXHRcdHJldHVybiBmbG9vcihrICsgKGJhc2VNaW51c1RNaW4gKyAxKSAqIGRlbHRhIC8gKGRlbHRhICsgc2tldykpO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgUHVueWNvZGUgc3RyaW5nIG9mIEFTQ0lJLW9ubHkgc3ltYm9scyB0byBhIHN0cmluZyBvZiBVbmljb2RlXG5cdCAqIHN5bWJvbHMuXG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgVGhlIFB1bnljb2RlIHN0cmluZyBvZiBBU0NJSS1vbmx5IHN5bWJvbHMuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSByZXN1bHRpbmcgc3RyaW5nIG9mIFVuaWNvZGUgc3ltYm9scy5cblx0ICovXG5cdGZ1bmN0aW9uIGRlY29kZShpbnB1dCkge1xuXHRcdC8vIERvbid0IHVzZSBVQ1MtMlxuXHRcdHZhciBvdXRwdXQgPSBbXSxcblx0XHQgICAgaW5wdXRMZW5ndGggPSBpbnB1dC5sZW5ndGgsXG5cdFx0ICAgIG91dCxcblx0XHQgICAgaSA9IDAsXG5cdFx0ICAgIG4gPSBpbml0aWFsTixcblx0XHQgICAgYmlhcyA9IGluaXRpYWxCaWFzLFxuXHRcdCAgICBiYXNpYyxcblx0XHQgICAgaixcblx0XHQgICAgaW5kZXgsXG5cdFx0ICAgIG9sZGksXG5cdFx0ICAgIHcsXG5cdFx0ICAgIGssXG5cdFx0ICAgIGRpZ2l0LFxuXHRcdCAgICB0LFxuXHRcdCAgICAvKiogQ2FjaGVkIGNhbGN1bGF0aW9uIHJlc3VsdHMgKi9cblx0XHQgICAgYmFzZU1pbnVzVDtcblxuXHRcdC8vIEhhbmRsZSB0aGUgYmFzaWMgY29kZSBwb2ludHM6IGxldCBgYmFzaWNgIGJlIHRoZSBudW1iZXIgb2YgaW5wdXQgY29kZVxuXHRcdC8vIHBvaW50cyBiZWZvcmUgdGhlIGxhc3QgZGVsaW1pdGVyLCBvciBgMGAgaWYgdGhlcmUgaXMgbm9uZSwgdGhlbiBjb3B5XG5cdFx0Ly8gdGhlIGZpcnN0IGJhc2ljIGNvZGUgcG9pbnRzIHRvIHRoZSBvdXRwdXQuXG5cblx0XHRiYXNpYyA9IGlucHV0Lmxhc3RJbmRleE9mKGRlbGltaXRlcik7XG5cdFx0aWYgKGJhc2ljIDwgMCkge1xuXHRcdFx0YmFzaWMgPSAwO1xuXHRcdH1cblxuXHRcdGZvciAoaiA9IDA7IGogPCBiYXNpYzsgKytqKSB7XG5cdFx0XHQvLyBpZiBpdCdzIG5vdCBhIGJhc2ljIGNvZGUgcG9pbnRcblx0XHRcdGlmIChpbnB1dC5jaGFyQ29kZUF0KGopID49IDB4ODApIHtcblx0XHRcdFx0ZXJyb3IoJ25vdC1iYXNpYycpO1xuXHRcdFx0fVxuXHRcdFx0b3V0cHV0LnB1c2goaW5wdXQuY2hhckNvZGVBdChqKSk7XG5cdFx0fVxuXG5cdFx0Ly8gTWFpbiBkZWNvZGluZyBsb29wOiBzdGFydCBqdXN0IGFmdGVyIHRoZSBsYXN0IGRlbGltaXRlciBpZiBhbnkgYmFzaWMgY29kZVxuXHRcdC8vIHBvaW50cyB3ZXJlIGNvcGllZDsgc3RhcnQgYXQgdGhlIGJlZ2lubmluZyBvdGhlcndpc2UuXG5cblx0XHRmb3IgKGluZGV4ID0gYmFzaWMgPiAwID8gYmFzaWMgKyAxIDogMDsgaW5kZXggPCBpbnB1dExlbmd0aDsgLyogbm8gZmluYWwgZXhwcmVzc2lvbiAqLykge1xuXG5cdFx0XHQvLyBgaW5kZXhgIGlzIHRoZSBpbmRleCBvZiB0aGUgbmV4dCBjaGFyYWN0ZXIgdG8gYmUgY29uc3VtZWQuXG5cdFx0XHQvLyBEZWNvZGUgYSBnZW5lcmFsaXplZCB2YXJpYWJsZS1sZW5ndGggaW50ZWdlciBpbnRvIGBkZWx0YWAsXG5cdFx0XHQvLyB3aGljaCBnZXRzIGFkZGVkIHRvIGBpYC4gVGhlIG92ZXJmbG93IGNoZWNraW5nIGlzIGVhc2llclxuXHRcdFx0Ly8gaWYgd2UgaW5jcmVhc2UgYGlgIGFzIHdlIGdvLCB0aGVuIHN1YnRyYWN0IG9mZiBpdHMgc3RhcnRpbmdcblx0XHRcdC8vIHZhbHVlIGF0IHRoZSBlbmQgdG8gb2J0YWluIGBkZWx0YWAuXG5cdFx0XHRmb3IgKG9sZGkgPSBpLCB3ID0gMSwgayA9IGJhc2U7IC8qIG5vIGNvbmRpdGlvbiAqLzsgayArPSBiYXNlKSB7XG5cblx0XHRcdFx0aWYgKGluZGV4ID49IGlucHV0TGVuZ3RoKSB7XG5cdFx0XHRcdFx0ZXJyb3IoJ2ludmFsaWQtaW5wdXQnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGRpZ2l0ID0gYmFzaWNUb0RpZ2l0KGlucHV0LmNoYXJDb2RlQXQoaW5kZXgrKykpO1xuXG5cdFx0XHRcdGlmIChkaWdpdCA+PSBiYXNlIHx8IGRpZ2l0ID4gZmxvb3IoKG1heEludCAtIGkpIC8gdykpIHtcblx0XHRcdFx0XHRlcnJvcignb3ZlcmZsb3cnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGkgKz0gZGlnaXQgKiB3O1xuXHRcdFx0XHR0ID0gayA8PSBiaWFzID8gdE1pbiA6IChrID49IGJpYXMgKyB0TWF4ID8gdE1heCA6IGsgLSBiaWFzKTtcblxuXHRcdFx0XHRpZiAoZGlnaXQgPCB0KSB7XG5cdFx0XHRcdFx0YnJlYWs7XG5cdFx0XHRcdH1cblxuXHRcdFx0XHRiYXNlTWludXNUID0gYmFzZSAtIHQ7XG5cdFx0XHRcdGlmICh3ID4gZmxvb3IobWF4SW50IC8gYmFzZU1pbnVzVCkpIHtcblx0XHRcdFx0XHRlcnJvcignb3ZlcmZsb3cnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdHcgKj0gYmFzZU1pbnVzVDtcblxuXHRcdFx0fVxuXG5cdFx0XHRvdXQgPSBvdXRwdXQubGVuZ3RoICsgMTtcblx0XHRcdGJpYXMgPSBhZGFwdChpIC0gb2xkaSwgb3V0LCBvbGRpID09IDApO1xuXG5cdFx0XHQvLyBgaWAgd2FzIHN1cHBvc2VkIHRvIHdyYXAgYXJvdW5kIGZyb20gYG91dGAgdG8gYDBgLFxuXHRcdFx0Ly8gaW5jcmVtZW50aW5nIGBuYCBlYWNoIHRpbWUsIHNvIHdlJ2xsIGZpeCB0aGF0IG5vdzpcblx0XHRcdGlmIChmbG9vcihpIC8gb3V0KSA+IG1heEludCAtIG4pIHtcblx0XHRcdFx0ZXJyb3IoJ292ZXJmbG93Jyk7XG5cdFx0XHR9XG5cblx0XHRcdG4gKz0gZmxvb3IoaSAvIG91dCk7XG5cdFx0XHRpICU9IG91dDtcblxuXHRcdFx0Ly8gSW5zZXJ0IGBuYCBhdCBwb3NpdGlvbiBgaWAgb2YgdGhlIG91dHB1dFxuXHRcdFx0b3V0cHV0LnNwbGljZShpKyssIDAsIG4pO1xuXG5cdFx0fVxuXG5cdFx0cmV0dXJuIHVjczJlbmNvZGUob3V0cHV0KTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyBhIHN0cmluZyBvZiBVbmljb2RlIHN5bWJvbHMgKGUuZy4gYSBkb21haW4gbmFtZSBsYWJlbCkgdG8gYVxuXHQgKiBQdW55Y29kZSBzdHJpbmcgb2YgQVNDSUktb25seSBzeW1ib2xzLlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0IFRoZSBzdHJpbmcgb2YgVW5pY29kZSBzeW1ib2xzLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgcmVzdWx0aW5nIFB1bnljb2RlIHN0cmluZyBvZiBBU0NJSS1vbmx5IHN5bWJvbHMuXG5cdCAqL1xuXHRmdW5jdGlvbiBlbmNvZGUoaW5wdXQpIHtcblx0XHR2YXIgbixcblx0XHQgICAgZGVsdGEsXG5cdFx0ICAgIGhhbmRsZWRDUENvdW50LFxuXHRcdCAgICBiYXNpY0xlbmd0aCxcblx0XHQgICAgYmlhcyxcblx0XHQgICAgaixcblx0XHQgICAgbSxcblx0XHQgICAgcSxcblx0XHQgICAgayxcblx0XHQgICAgdCxcblx0XHQgICAgY3VycmVudFZhbHVlLFxuXHRcdCAgICBvdXRwdXQgPSBbXSxcblx0XHQgICAgLyoqIGBpbnB1dExlbmd0aGAgd2lsbCBob2xkIHRoZSBudW1iZXIgb2YgY29kZSBwb2ludHMgaW4gYGlucHV0YC4gKi9cblx0XHQgICAgaW5wdXRMZW5ndGgsXG5cdFx0ICAgIC8qKiBDYWNoZWQgY2FsY3VsYXRpb24gcmVzdWx0cyAqL1xuXHRcdCAgICBoYW5kbGVkQ1BDb3VudFBsdXNPbmUsXG5cdFx0ICAgIGJhc2VNaW51c1QsXG5cdFx0ICAgIHFNaW51c1Q7XG5cblx0XHQvLyBDb252ZXJ0IHRoZSBpbnB1dCBpbiBVQ1MtMiB0byBVbmljb2RlXG5cdFx0aW5wdXQgPSB1Y3MyZGVjb2RlKGlucHV0KTtcblxuXHRcdC8vIENhY2hlIHRoZSBsZW5ndGhcblx0XHRpbnB1dExlbmd0aCA9IGlucHV0Lmxlbmd0aDtcblxuXHRcdC8vIEluaXRpYWxpemUgdGhlIHN0YXRlXG5cdFx0biA9IGluaXRpYWxOO1xuXHRcdGRlbHRhID0gMDtcblx0XHRiaWFzID0gaW5pdGlhbEJpYXM7XG5cblx0XHQvLyBIYW5kbGUgdGhlIGJhc2ljIGNvZGUgcG9pbnRzXG5cdFx0Zm9yIChqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdGN1cnJlbnRWYWx1ZSA9IGlucHV0W2pdO1xuXHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA8IDB4ODApIHtcblx0XHRcdFx0b3V0cHV0LnB1c2goc3RyaW5nRnJvbUNoYXJDb2RlKGN1cnJlbnRWYWx1ZSkpO1xuXHRcdFx0fVxuXHRcdH1cblxuXHRcdGhhbmRsZWRDUENvdW50ID0gYmFzaWNMZW5ndGggPSBvdXRwdXQubGVuZ3RoO1xuXG5cdFx0Ly8gYGhhbmRsZWRDUENvdW50YCBpcyB0aGUgbnVtYmVyIG9mIGNvZGUgcG9pbnRzIHRoYXQgaGF2ZSBiZWVuIGhhbmRsZWQ7XG5cdFx0Ly8gYGJhc2ljTGVuZ3RoYCBpcyB0aGUgbnVtYmVyIG9mIGJhc2ljIGNvZGUgcG9pbnRzLlxuXG5cdFx0Ly8gRmluaXNoIHRoZSBiYXNpYyBzdHJpbmcgLSBpZiBpdCBpcyBub3QgZW1wdHkgLSB3aXRoIGEgZGVsaW1pdGVyXG5cdFx0aWYgKGJhc2ljTGVuZ3RoKSB7XG5cdFx0XHRvdXRwdXQucHVzaChkZWxpbWl0ZXIpO1xuXHRcdH1cblxuXHRcdC8vIE1haW4gZW5jb2RpbmcgbG9vcDpcblx0XHR3aGlsZSAoaGFuZGxlZENQQ291bnQgPCBpbnB1dExlbmd0aCkge1xuXG5cdFx0XHQvLyBBbGwgbm9uLWJhc2ljIGNvZGUgcG9pbnRzIDwgbiBoYXZlIGJlZW4gaGFuZGxlZCBhbHJlYWR5LiBGaW5kIHRoZSBuZXh0XG5cdFx0XHQvLyBsYXJnZXIgb25lOlxuXHRcdFx0Zm9yIChtID0gbWF4SW50LCBqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdFx0Y3VycmVudFZhbHVlID0gaW5wdXRbal07XG5cdFx0XHRcdGlmIChjdXJyZW50VmFsdWUgPj0gbiAmJiBjdXJyZW50VmFsdWUgPCBtKSB7XG5cdFx0XHRcdFx0bSA9IGN1cnJlbnRWYWx1ZTtcblx0XHRcdFx0fVxuXHRcdFx0fVxuXG5cdFx0XHQvLyBJbmNyZWFzZSBgZGVsdGFgIGVub3VnaCB0byBhZHZhbmNlIHRoZSBkZWNvZGVyJ3MgPG4saT4gc3RhdGUgdG8gPG0sMD4sXG5cdFx0XHQvLyBidXQgZ3VhcmQgYWdhaW5zdCBvdmVyZmxvd1xuXHRcdFx0aGFuZGxlZENQQ291bnRQbHVzT25lID0gaGFuZGxlZENQQ291bnQgKyAxO1xuXHRcdFx0aWYgKG0gLSBuID4gZmxvb3IoKG1heEludCAtIGRlbHRhKSAvIGhhbmRsZWRDUENvdW50UGx1c09uZSkpIHtcblx0XHRcdFx0ZXJyb3IoJ292ZXJmbG93Jyk7XG5cdFx0XHR9XG5cblx0XHRcdGRlbHRhICs9IChtIC0gbikgKiBoYW5kbGVkQ1BDb3VudFBsdXNPbmU7XG5cdFx0XHRuID0gbTtcblxuXHRcdFx0Zm9yIChqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdFx0Y3VycmVudFZhbHVlID0gaW5wdXRbal07XG5cblx0XHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA8IG4gJiYgKytkZWx0YSA+IG1heEludCkge1xuXHRcdFx0XHRcdGVycm9yKCdvdmVyZmxvdycpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA9PSBuKSB7XG5cdFx0XHRcdFx0Ly8gUmVwcmVzZW50IGRlbHRhIGFzIGEgZ2VuZXJhbGl6ZWQgdmFyaWFibGUtbGVuZ3RoIGludGVnZXJcblx0XHRcdFx0XHRmb3IgKHEgPSBkZWx0YSwgayA9IGJhc2U7IC8qIG5vIGNvbmRpdGlvbiAqLzsgayArPSBiYXNlKSB7XG5cdFx0XHRcdFx0XHR0ID0gayA8PSBiaWFzID8gdE1pbiA6IChrID49IGJpYXMgKyB0TWF4ID8gdE1heCA6IGsgLSBiaWFzKTtcblx0XHRcdFx0XHRcdGlmIChxIDwgdCkge1xuXHRcdFx0XHRcdFx0XHRicmVhaztcblx0XHRcdFx0XHRcdH1cblx0XHRcdFx0XHRcdHFNaW51c1QgPSBxIC0gdDtcblx0XHRcdFx0XHRcdGJhc2VNaW51c1QgPSBiYXNlIC0gdDtcblx0XHRcdFx0XHRcdG91dHB1dC5wdXNoKFxuXHRcdFx0XHRcdFx0XHRzdHJpbmdGcm9tQ2hhckNvZGUoZGlnaXRUb0Jhc2ljKHQgKyBxTWludXNUICUgYmFzZU1pbnVzVCwgMCkpXG5cdFx0XHRcdFx0XHQpO1xuXHRcdFx0XHRcdFx0cSA9IGZsb29yKHFNaW51c1QgLyBiYXNlTWludXNUKTtcblx0XHRcdFx0XHR9XG5cblx0XHRcdFx0XHRvdXRwdXQucHVzaChzdHJpbmdGcm9tQ2hhckNvZGUoZGlnaXRUb0Jhc2ljKHEsIDApKSk7XG5cdFx0XHRcdFx0YmlhcyA9IGFkYXB0KGRlbHRhLCBoYW5kbGVkQ1BDb3VudFBsdXNPbmUsIGhhbmRsZWRDUENvdW50ID09IGJhc2ljTGVuZ3RoKTtcblx0XHRcdFx0XHRkZWx0YSA9IDA7XG5cdFx0XHRcdFx0KytoYW5kbGVkQ1BDb3VudDtcblx0XHRcdFx0fVxuXHRcdFx0fVxuXG5cdFx0XHQrK2RlbHRhO1xuXHRcdFx0KytuO1xuXG5cdFx0fVxuXHRcdHJldHVybiBvdXRwdXQuam9pbignJyk7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBQdW55Y29kZSBzdHJpbmcgcmVwcmVzZW50aW5nIGEgZG9tYWluIG5hbWUgb3IgYW4gZW1haWwgYWRkcmVzc1xuXHQgKiB0byBVbmljb2RlLiBPbmx5IHRoZSBQdW55Y29kZWQgcGFydHMgb2YgdGhlIGlucHV0IHdpbGwgYmUgY29udmVydGVkLCBpLmUuXG5cdCAqIGl0IGRvZXNuJ3QgbWF0dGVyIGlmIHlvdSBjYWxsIGl0IG9uIGEgc3RyaW5nIHRoYXQgaGFzIGFscmVhZHkgYmVlblxuXHQgKiBjb252ZXJ0ZWQgdG8gVW5pY29kZS5cblx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBUaGUgUHVueWNvZGVkIGRvbWFpbiBuYW1lIG9yIGVtYWlsIGFkZHJlc3MgdG9cblx0ICogY29udmVydCB0byBVbmljb2RlLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgVW5pY29kZSByZXByZXNlbnRhdGlvbiBvZiB0aGUgZ2l2ZW4gUHVueWNvZGVcblx0ICogc3RyaW5nLlxuXHQgKi9cblx0ZnVuY3Rpb24gdG9Vbmljb2RlKGlucHV0KSB7XG5cdFx0cmV0dXJuIG1hcERvbWFpbihpbnB1dCwgZnVuY3Rpb24oc3RyaW5nKSB7XG5cdFx0XHRyZXR1cm4gcmVnZXhQdW55Y29kZS50ZXN0KHN0cmluZylcblx0XHRcdFx0PyBkZWNvZGUoc3RyaW5nLnNsaWNlKDQpLnRvTG93ZXJDYXNlKCkpXG5cdFx0XHRcdDogc3RyaW5nO1xuXHRcdH0pO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgVW5pY29kZSBzdHJpbmcgcmVwcmVzZW50aW5nIGEgZG9tYWluIG5hbWUgb3IgYW4gZW1haWwgYWRkcmVzcyB0b1xuXHQgKiBQdW55Y29kZS4gT25seSB0aGUgbm9uLUFTQ0lJIHBhcnRzIG9mIHRoZSBkb21haW4gbmFtZSB3aWxsIGJlIGNvbnZlcnRlZCxcblx0ICogaS5lLiBpdCBkb2Vzbid0IG1hdHRlciBpZiB5b3UgY2FsbCBpdCB3aXRoIGEgZG9tYWluIHRoYXQncyBhbHJlYWR5IGluXG5cdCAqIEFTQ0lJLlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0IFRoZSBkb21haW4gbmFtZSBvciBlbWFpbCBhZGRyZXNzIHRvIGNvbnZlcnQsIGFzIGFcblx0ICogVW5pY29kZSBzdHJpbmcuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSBQdW55Y29kZSByZXByZXNlbnRhdGlvbiBvZiB0aGUgZ2l2ZW4gZG9tYWluIG5hbWUgb3Jcblx0ICogZW1haWwgYWRkcmVzcy5cblx0ICovXG5cdGZ1bmN0aW9uIHRvQVNDSUkoaW5wdXQpIHtcblx0XHRyZXR1cm4gbWFwRG9tYWluKGlucHV0LCBmdW5jdGlvbihzdHJpbmcpIHtcblx0XHRcdHJldHVybiByZWdleE5vbkFTQ0lJLnRlc3Qoc3RyaW5nKVxuXHRcdFx0XHQ/ICd4bi0tJyArIGVuY29kZShzdHJpbmcpXG5cdFx0XHRcdDogc3RyaW5nO1xuXHRcdH0pO1xuXHR9XG5cblx0LyotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSovXG5cblx0LyoqIERlZmluZSB0aGUgcHVibGljIEFQSSAqL1xuXHRwdW55Y29kZSA9IHtcblx0XHQvKipcblx0XHQgKiBBIHN0cmluZyByZXByZXNlbnRpbmcgdGhlIGN1cnJlbnQgUHVueWNvZGUuanMgdmVyc2lvbiBudW1iZXIuXG5cdFx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdFx0ICogQHR5cGUgU3RyaW5nXG5cdFx0ICovXG5cdFx0J3ZlcnNpb24nOiAnMS40LjEnLFxuXHRcdC8qKlxuXHRcdCAqIEFuIG9iamVjdCBvZiBtZXRob2RzIHRvIGNvbnZlcnQgZnJvbSBKYXZhU2NyaXB0J3MgaW50ZXJuYWwgY2hhcmFjdGVyXG5cdFx0ICogcmVwcmVzZW50YXRpb24gKFVDUy0yKSB0byBVbmljb2RlIGNvZGUgcG9pbnRzLCBhbmQgYmFjay5cblx0XHQgKiBAc2VlIDxodHRwczovL21hdGhpYXNieW5lbnMuYmUvbm90ZXMvamF2YXNjcmlwdC1lbmNvZGluZz5cblx0XHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0XHQgKiBAdHlwZSBPYmplY3Rcblx0XHQgKi9cblx0XHQndWNzMic6IHtcblx0XHRcdCdkZWNvZGUnOiB1Y3MyZGVjb2RlLFxuXHRcdFx0J2VuY29kZSc6IHVjczJlbmNvZGVcblx0XHR9LFxuXHRcdCdkZWNvZGUnOiBkZWNvZGUsXG5cdFx0J2VuY29kZSc6IGVuY29kZSxcblx0XHQndG9BU0NJSSc6IHRvQVNDSUksXG5cdFx0J3RvVW5pY29kZSc6IHRvVW5pY29kZVxuXHR9O1xuXG5cdC8qKiBFeHBvc2UgYHB1bnljb2RlYCAqL1xuXHQvLyBTb21lIEFNRCBidWlsZCBvcHRpbWl6ZXJzLCBsaWtlIHIuanMsIGNoZWNrIGZvciBzcGVjaWZpYyBjb25kaXRpb24gcGF0dGVybnNcblx0Ly8gbGlrZSB0aGUgZm9sbG93aW5nOlxuXHRpZiAoXG5cdFx0dHlwZW9mIGRlZmluZSA9PSAnZnVuY3Rpb24nICYmXG5cdFx0dHlwZW9mIGRlZmluZS5hbWQgPT0gJ29iamVjdCcgJiZcblx0XHRkZWZpbmUuYW1kXG5cdCkge1xuXHRcdGRlZmluZSgncHVueWNvZGUnLCBmdW5jdGlvbigpIHtcblx0XHRcdHJldHVybiBwdW55Y29kZTtcblx0XHR9KTtcblx0fSBlbHNlIGlmIChmcmVlRXhwb3J0cyAmJiBmcmVlTW9kdWxlKSB7XG5cdFx0aWYgKG1vZHVsZS5leHBvcnRzID09IGZyZWVFeHBvcnRzKSB7XG5cdFx0XHQvLyBpbiBOb2RlLmpzLCBpby5qcywgb3IgUmluZ29KUyB2MC44LjArXG5cdFx0XHRmcmVlTW9kdWxlLmV4cG9ydHMgPSBwdW55Y29kZTtcblx0XHR9IGVsc2Uge1xuXHRcdFx0Ly8gaW4gTmFyd2hhbCBvciBSaW5nb0pTIHYwLjcuMC1cblx0XHRcdGZvciAoa2V5IGluIHB1bnljb2RlKSB7XG5cdFx0XHRcdHB1bnljb2RlLmhhc093blByb3BlcnR5KGtleSkgJiYgKGZyZWVFeHBvcnRzW2tleV0gPSBwdW55Y29kZVtrZXldKTtcblx0XHRcdH1cblx0XHR9XG5cdH0gZWxzZSB7XG5cdFx0Ly8gaW4gUmhpbm8gb3IgYSB3ZWIgYnJvd3NlclxuXHRcdHJvb3QucHVueWNvZGUgPSBwdW55Y29kZTtcblx0fVxuXG59KHRoaXMpKTtcbiIsIi8vIENvcHlyaWdodCBKb3llbnQsIEluYy4gYW5kIG90aGVyIE5vZGUgY29udHJpYnV0b3JzLlxuLy9cbi8vIFBlcm1pc3Npb24gaXMgaGVyZWJ5IGdyYW50ZWQsIGZyZWUgb2YgY2hhcmdlLCB0byBhbnkgcGVyc29uIG9idGFpbmluZyBhXG4vLyBjb3B5IG9mIHRoaXMgc29mdHdhcmUgYW5kIGFzc29jaWF0ZWQgZG9jdW1lbnRhdGlvbiBmaWxlcyAodGhlXG4vLyBcIlNvZnR3YXJlXCIpLCB0byBkZWFsIGluIHRoZSBTb2Z0d2FyZSB3aXRob3V0IHJlc3RyaWN0aW9uLCBpbmNsdWRpbmdcbi8vIHdpdGhvdXQgbGltaXRhdGlvbiB0aGUgcmlnaHRzIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBtZXJnZSwgcHVibGlzaCxcbi8vIGRpc3RyaWJ1dGUsIHN1YmxpY2Vuc2UsIGFuZC9vciBzZWxsIGNvcGllcyBvZiB0aGUgU29mdHdhcmUsIGFuZCB0byBwZXJtaXRcbi8vIHBlcnNvbnMgdG8gd2hvbSB0aGUgU29mdHdhcmUgaXMgZnVybmlzaGVkIHRvIGRvIHNvLCBzdWJqZWN0IHRvIHRoZVxuLy8gZm9sbG93aW5nIGNvbmRpdGlvbnM6XG4vL1xuLy8gVGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2Ugc2hhbGwgYmUgaW5jbHVkZWRcbi8vIGluIGFsbCBjb3BpZXMgb3Igc3Vic3RhbnRpYWwgcG9ydGlvbnMgb2YgdGhlIFNvZnR3YXJlLlxuLy9cbi8vIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIsIFdJVEhPVVQgV0FSUkFOVFkgT0YgQU5ZIEtJTkQsIEVYUFJFU1Ncbi8vIE9SIElNUExJRUQsIElOQ0xVRElORyBCVVQgTk9UIExJTUlURUQgVE8gVEhFIFdBUlJBTlRJRVMgT0Zcbi8vIE1FUkNIQU5UQUJJTElUWSwgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UgQU5EIE5PTklORlJJTkdFTUVOVC4gSU5cbi8vIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1JTIE9SIENPUFlSSUdIVCBIT0xERVJTIEJFIExJQUJMRSBGT1IgQU5ZIENMQUlNLFxuLy8gREFNQUdFUyBPUiBPVEhFUiBMSUFCSUxJVFksIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBUT1JUIE9SXG4vLyBPVEhFUldJU0UsIEFSSVNJTkcgRlJPTSwgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgU09GVFdBUkUgT1IgVEhFXG4vLyBVU0UgT1IgT1RIRVIgREVBTElOR1MgSU4gVEhFIFNPRlRXQVJFLlxuXG4ndXNlIHN0cmljdCc7XG5cbi8vIElmIG9iai5oYXNPd25Qcm9wZXJ0eSBoYXMgYmVlbiBvdmVycmlkZGVuLCB0aGVuIGNhbGxpbmdcbi8vIG9iai5oYXNPd25Qcm9wZXJ0eShwcm9wKSB3aWxsIGJyZWFrLlxuLy8gU2VlOiBodHRwczovL2dpdGh1Yi5jb20vam95ZW50L25vZGUvaXNzdWVzLzE3MDdcbmZ1bmN0aW9uIGhhc093blByb3BlcnR5KG9iaiwgcHJvcCkge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCk7XG59XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24ocXMsIHNlcCwgZXEsIG9wdGlvbnMpIHtcbiAgc2VwID0gc2VwIHx8ICcmJztcbiAgZXEgPSBlcSB8fCAnPSc7XG4gIHZhciBvYmogPSB7fTtcblxuICBpZiAodHlwZW9mIHFzICE9PSAnc3RyaW5nJyB8fCBxcy5sZW5ndGggPT09IDApIHtcbiAgICByZXR1cm4gb2JqO1xuICB9XG5cbiAgdmFyIHJlZ2V4cCA9IC9cXCsvZztcbiAgcXMgPSBxcy5zcGxpdChzZXApO1xuXG4gIHZhciBtYXhLZXlzID0gMTAwMDtcbiAgaWYgKG9wdGlvbnMgJiYgdHlwZW9mIG9wdGlvbnMubWF4S2V5cyA9PT0gJ251bWJlcicpIHtcbiAgICBtYXhLZXlzID0gb3B0aW9ucy5tYXhLZXlzO1xuICB9XG5cbiAgdmFyIGxlbiA9IHFzLmxlbmd0aDtcbiAgLy8gbWF4S2V5cyA8PSAwIG1lYW5zIHRoYXQgd2Ugc2hvdWxkIG5vdCBsaW1pdCBrZXlzIGNvdW50XG4gIGlmIChtYXhLZXlzID4gMCAmJiBsZW4gPiBtYXhLZXlzKSB7XG4gICAgbGVuID0gbWF4S2V5cztcbiAgfVxuXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuOyArK2kpIHtcbiAgICB2YXIgeCA9IHFzW2ldLnJlcGxhY2UocmVnZXhwLCAnJTIwJyksXG4gICAgICAgIGlkeCA9IHguaW5kZXhPZihlcSksXG4gICAgICAgIGtzdHIsIHZzdHIsIGssIHY7XG5cbiAgICBpZiAoaWR4ID49IDApIHtcbiAgICAgIGtzdHIgPSB4LnN1YnN0cigwLCBpZHgpO1xuICAgICAgdnN0ciA9IHguc3Vic3RyKGlkeCArIDEpO1xuICAgIH0gZWxzZSB7XG4gICAgICBrc3RyID0geDtcbiAgICAgIHZzdHIgPSAnJztcbiAgICB9XG5cbiAgICBrID0gZGVjb2RlVVJJQ29tcG9uZW50KGtzdHIpO1xuICAgIHYgPSBkZWNvZGVVUklDb21wb25lbnQodnN0cik7XG5cbiAgICBpZiAoIWhhc093blByb3BlcnR5KG9iaiwgaykpIHtcbiAgICAgIG9ialtrXSA9IHY7XG4gICAgfSBlbHNlIGlmIChpc0FycmF5KG9ialtrXSkpIHtcbiAgICAgIG9ialtrXS5wdXNoKHYpO1xuICAgIH0gZWxzZSB7XG4gICAgICBvYmpba10gPSBbb2JqW2tdLCB2XTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gb2JqO1xufTtcblxudmFyIGlzQXJyYXkgPSBBcnJheS5pc0FycmF5IHx8IGZ1bmN0aW9uICh4cykge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHhzKSA9PT0gJ1tvYmplY3QgQXJyYXldJztcbn07XG4iLCIvLyBDb3B5cmlnaHQgSm95ZW50LCBJbmMuIGFuZCBvdGhlciBOb2RlIGNvbnRyaWJ1dG9ycy5cbi8vXG4vLyBQZXJtaXNzaW9uIGlzIGhlcmVieSBncmFudGVkLCBmcmVlIG9mIGNoYXJnZSwgdG8gYW55IHBlcnNvbiBvYnRhaW5pbmcgYVxuLy8gY29weSBvZiB0aGlzIHNvZnR3YXJlIGFuZCBhc3NvY2lhdGVkIGRvY3VtZW50YXRpb24gZmlsZXMgKHRoZVxuLy8gXCJTb2Z0d2FyZVwiKSwgdG8gZGVhbCBpbiB0aGUgU29mdHdhcmUgd2l0aG91dCByZXN0cmljdGlvbiwgaW5jbHVkaW5nXG4vLyB3aXRob3V0IGxpbWl0YXRpb24gdGhlIHJpZ2h0cyB0byB1c2UsIGNvcHksIG1vZGlmeSwgbWVyZ2UsIHB1Ymxpc2gsXG4vLyBkaXN0cmlidXRlLCBzdWJsaWNlbnNlLCBhbmQvb3Igc2VsbCBjb3BpZXMgb2YgdGhlIFNvZnR3YXJlLCBhbmQgdG8gcGVybWl0XG4vLyBwZXJzb25zIHRvIHdob20gdGhlIFNvZnR3YXJlIGlzIGZ1cm5pc2hlZCB0byBkbyBzbywgc3ViamVjdCB0byB0aGVcbi8vIGZvbGxvd2luZyBjb25kaXRpb25zOlxuLy9cbi8vIFRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIHNoYWxsIGJlIGluY2x1ZGVkXG4vLyBpbiBhbGwgY29waWVzIG9yIHN1YnN0YW50aWFsIHBvcnRpb25zIG9mIHRoZSBTb2Z0d2FyZS5cbi8vXG4vLyBUSEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiLCBXSVRIT1VUIFdBUlJBTlRZIE9GIEFOWSBLSU5ELCBFWFBSRVNTXG4vLyBPUiBJTVBMSUVELCBJTkNMVURJTkcgQlVUIE5PVCBMSU1JVEVEIFRPIFRIRSBXQVJSQU5USUVTIE9GXG4vLyBNRVJDSEFOVEFCSUxJVFksIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFIEFORCBOT05JTkZSSU5HRU1FTlQuIElOXG4vLyBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SUyBPUiBDT1BZUklHSFQgSE9MREVSUyBCRSBMSUFCTEUgRk9SIEFOWSBDTEFJTSxcbi8vIERBTUFHRVMgT1IgT1RIRVIgTElBQklMSVRZLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgVE9SVCBPUlxuLy8gT1RIRVJXSVNFLCBBUklTSU5HIEZST00sIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFNPRlRXQVJFIE9SIFRIRVxuLy8gVVNFIE9SIE9USEVSIERFQUxJTkdTIElOIFRIRSBTT0ZUV0FSRS5cblxuJ3VzZSBzdHJpY3QnO1xuXG52YXIgc3RyaW5naWZ5UHJpbWl0aXZlID0gZnVuY3Rpb24odikge1xuICBzd2l0Y2ggKHR5cGVvZiB2KSB7XG4gICAgY2FzZSAnc3RyaW5nJzpcbiAgICAgIHJldHVybiB2O1xuXG4gICAgY2FzZSAnYm9vbGVhbic6XG4gICAgICByZXR1cm4gdiA/ICd0cnVlJyA6ICdmYWxzZSc7XG5cbiAgICBjYXNlICdudW1iZXInOlxuICAgICAgcmV0dXJuIGlzRmluaXRlKHYpID8gdiA6ICcnO1xuXG4gICAgZGVmYXVsdDpcbiAgICAgIHJldHVybiAnJztcbiAgfVxufTtcblxubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbihvYmosIHNlcCwgZXEsIG5hbWUpIHtcbiAgc2VwID0gc2VwIHx8ICcmJztcbiAgZXEgPSBlcSB8fCAnPSc7XG4gIGlmIChvYmogPT09IG51bGwpIHtcbiAgICBvYmogPSB1bmRlZmluZWQ7XG4gIH1cblxuICBpZiAodHlwZW9mIG9iaiA9PT0gJ29iamVjdCcpIHtcbiAgICByZXR1cm4gbWFwKG9iamVjdEtleXMob2JqKSwgZnVuY3Rpb24oaykge1xuICAgICAgdmFyIGtzID0gZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZShrKSkgKyBlcTtcbiAgICAgIGlmIChpc0FycmF5KG9ialtrXSkpIHtcbiAgICAgICAgcmV0dXJuIG1hcChvYmpba10sIGZ1bmN0aW9uKHYpIHtcbiAgICAgICAgICByZXR1cm4ga3MgKyBlbmNvZGVVUklDb21wb25lbnQoc3RyaW5naWZ5UHJpbWl0aXZlKHYpKTtcbiAgICAgICAgfSkuam9pbihzZXApO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIGtzICsgZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZShvYmpba10pKTtcbiAgICAgIH1cbiAgICB9KS5qb2luKHNlcCk7XG5cbiAgfVxuXG4gIGlmICghbmFtZSkgcmV0dXJuICcnO1xuICByZXR1cm4gZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZShuYW1lKSkgKyBlcSArXG4gICAgICAgICBlbmNvZGVVUklDb21wb25lbnQoc3RyaW5naWZ5UHJpbWl0aXZlKG9iaikpO1xufTtcblxudmFyIGlzQXJyYXkgPSBBcnJheS5pc0FycmF5IHx8IGZ1bmN0aW9uICh4cykge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHhzKSA9PT0gJ1tvYmplY3QgQXJyYXldJztcbn07XG5cbmZ1bmN0aW9uIG1hcCAoeHMsIGYpIHtcbiAgaWYgKHhzLm1hcCkgcmV0dXJuIHhzLm1hcChmKTtcbiAgdmFyIHJlcyA9IFtdO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IHhzLmxlbmd0aDsgaSsrKSB7XG4gICAgcmVzLnB1c2goZih4c1tpXSwgaSkpO1xuICB9XG4gIHJldHVybiByZXM7XG59XG5cbnZhciBvYmplY3RLZXlzID0gT2JqZWN0LmtleXMgfHwgZnVuY3Rpb24gKG9iaikge1xuICB2YXIgcmVzID0gW107XG4gIGZvciAodmFyIGtleSBpbiBvYmopIHtcbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwga2V5KSkgcmVzLnB1c2goa2V5KTtcbiAgfVxuICByZXR1cm4gcmVzO1xufTtcbiIsIid1c2Ugc3RyaWN0JztcblxuZXhwb3J0cy5kZWNvZGUgPSBleHBvcnRzLnBhcnNlID0gcmVxdWlyZSgnLi9kZWNvZGUnKTtcbmV4cG9ydHMuZW5jb2RlID0gZXhwb3J0cy5zdHJpbmdpZnkgPSByZXF1aXJlKCcuL2VuY29kZScpO1xuIiwiZnVuY3Rpb24gUmF2ZW5Db25maWdFcnJvcihtZXNzYWdlKSB7XG4gIHRoaXMubmFtZSA9ICdSYXZlbkNvbmZpZ0Vycm9yJztcbiAgdGhpcy5tZXNzYWdlID0gbWVzc2FnZTtcbn1cblJhdmVuQ29uZmlnRXJyb3IucHJvdG90eXBlID0gbmV3IEVycm9yKCk7XG5SYXZlbkNvbmZpZ0Vycm9yLnByb3RvdHlwZS5jb25zdHJ1Y3RvciA9IFJhdmVuQ29uZmlnRXJyb3I7XG5cbm1vZHVsZS5leHBvcnRzID0gUmF2ZW5Db25maWdFcnJvcjtcbiIsInZhciB1dGlscyA9IHJlcXVpcmUoJy4vdXRpbHMnKTtcblxudmFyIHdyYXBNZXRob2QgPSBmdW5jdGlvbihjb25zb2xlLCBsZXZlbCwgY2FsbGJhY2spIHtcbiAgdmFyIG9yaWdpbmFsQ29uc29sZUxldmVsID0gY29uc29sZVtsZXZlbF07XG4gIHZhciBvcmlnaW5hbENvbnNvbGUgPSBjb25zb2xlO1xuXG4gIGlmICghKGxldmVsIGluIGNvbnNvbGUpKSB7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgdmFyIHNlbnRyeUxldmVsID0gbGV2ZWwgPT09ICd3YXJuJyA/ICd3YXJuaW5nJyA6IGxldmVsO1xuXG4gIGNvbnNvbGVbbGV2ZWxdID0gZnVuY3Rpb24oKSB7XG4gICAgdmFyIGFyZ3MgPSBbXS5zbGljZS5jYWxsKGFyZ3VtZW50cyk7XG5cbiAgICB2YXIgbXNnID0gdXRpbHMuc2FmZUpvaW4oYXJncywgJyAnKTtcbiAgICB2YXIgZGF0YSA9IHtsZXZlbDogc2VudHJ5TGV2ZWwsIGxvZ2dlcjogJ2NvbnNvbGUnLCBleHRyYToge2FyZ3VtZW50czogYXJnc319O1xuXG4gICAgaWYgKGxldmVsID09PSAnYXNzZXJ0Jykge1xuICAgICAgaWYgKGFyZ3NbMF0gPT09IGZhbHNlKSB7XG4gICAgICAgIC8vIERlZmF1bHQgYnJvd3NlcnMgbWVzc2FnZVxuICAgICAgICBtc2cgPVxuICAgICAgICAgICdBc3NlcnRpb24gZmFpbGVkOiAnICsgKHV0aWxzLnNhZmVKb2luKGFyZ3Muc2xpY2UoMSksICcgJykgfHwgJ2NvbnNvbGUuYXNzZXJ0Jyk7XG4gICAgICAgIGRhdGEuZXh0cmEuYXJndW1lbnRzID0gYXJncy5zbGljZSgxKTtcbiAgICAgICAgY2FsbGJhY2sgJiYgY2FsbGJhY2sobXNnLCBkYXRhKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgY2FsbGJhY2sgJiYgY2FsbGJhY2sobXNnLCBkYXRhKTtcbiAgICB9XG5cbiAgICAvLyB0aGlzIGZhaWxzIGZvciBzb21lIGJyb3dzZXJzLiA6KFxuICAgIGlmIChvcmlnaW5hbENvbnNvbGVMZXZlbCkge1xuICAgICAgLy8gSUU5IGRvZXNuJ3QgYWxsb3cgY2FsbGluZyBhcHBseSBvbiBjb25zb2xlIGZ1bmN0aW9ucyBkaXJlY3RseVxuICAgICAgLy8gU2VlOiBodHRwczovL3N0YWNrb3ZlcmZsb3cuY29tL3F1ZXN0aW9ucy81NDcyOTM4L2RvZXMtaWU5LXN1cHBvcnQtY29uc29sZS1sb2ctYW5kLWlzLWl0LWEtcmVhbC1mdW5jdGlvbiNhbnN3ZXItNTQ3MzE5M1xuICAgICAgRnVuY3Rpb24ucHJvdG90eXBlLmFwcGx5LmNhbGwob3JpZ2luYWxDb25zb2xlTGV2ZWwsIG9yaWdpbmFsQ29uc29sZSwgYXJncyk7XG4gICAgfVxuICB9O1xufTtcblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gIHdyYXBNZXRob2Q6IHdyYXBNZXRob2Rcbn07XG4iLCIvKmdsb2JhbCBYRG9tYWluUmVxdWVzdDpmYWxzZSAqL1xuXG52YXIgVHJhY2VLaXQgPSByZXF1aXJlKCcuLi92ZW5kb3IvVHJhY2VLaXQvdHJhY2VraXQnKTtcbnZhciBzdHJpbmdpZnkgPSByZXF1aXJlKCcuLi92ZW5kb3IvanNvbi1zdHJpbmdpZnktc2FmZS9zdHJpbmdpZnknKTtcbnZhciBtZDUgPSByZXF1aXJlKCcuLi92ZW5kb3IvbWQ1L21kNScpO1xudmFyIFJhdmVuQ29uZmlnRXJyb3IgPSByZXF1aXJlKCcuL2NvbmZpZ0Vycm9yJyk7XG5cbnZhciB1dGlscyA9IHJlcXVpcmUoJy4vdXRpbHMnKTtcbnZhciBpc0Vycm9yRXZlbnQgPSB1dGlscy5pc0Vycm9yRXZlbnQ7XG52YXIgaXNET01FcnJvciA9IHV0aWxzLmlzRE9NRXJyb3I7XG52YXIgaXNET01FeGNlcHRpb24gPSB1dGlscy5pc0RPTUV4Y2VwdGlvbjtcbnZhciBpc0Vycm9yID0gdXRpbHMuaXNFcnJvcjtcbnZhciBpc09iamVjdCA9IHV0aWxzLmlzT2JqZWN0O1xudmFyIGlzUGxhaW5PYmplY3QgPSB1dGlscy5pc1BsYWluT2JqZWN0O1xudmFyIGlzVW5kZWZpbmVkID0gdXRpbHMuaXNVbmRlZmluZWQ7XG52YXIgaXNGdW5jdGlvbiA9IHV0aWxzLmlzRnVuY3Rpb247XG52YXIgaXNTdHJpbmcgPSB1dGlscy5pc1N0cmluZztcbnZhciBpc0FycmF5ID0gdXRpbHMuaXNBcnJheTtcbnZhciBpc0VtcHR5T2JqZWN0ID0gdXRpbHMuaXNFbXB0eU9iamVjdDtcbnZhciBlYWNoID0gdXRpbHMuZWFjaDtcbnZhciBvYmplY3RNZXJnZSA9IHV0aWxzLm9iamVjdE1lcmdlO1xudmFyIHRydW5jYXRlID0gdXRpbHMudHJ1bmNhdGU7XG52YXIgb2JqZWN0RnJvemVuID0gdXRpbHMub2JqZWN0RnJvemVuO1xudmFyIGhhc0tleSA9IHV0aWxzLmhhc0tleTtcbnZhciBqb2luUmVnRXhwID0gdXRpbHMuam9pblJlZ0V4cDtcbnZhciB1cmxlbmNvZGUgPSB1dGlscy51cmxlbmNvZGU7XG52YXIgdXVpZDQgPSB1dGlscy51dWlkNDtcbnZhciBodG1sVHJlZUFzU3RyaW5nID0gdXRpbHMuaHRtbFRyZWVBc1N0cmluZztcbnZhciBpc1NhbWVFeGNlcHRpb24gPSB1dGlscy5pc1NhbWVFeGNlcHRpb247XG52YXIgaXNTYW1lU3RhY2t0cmFjZSA9IHV0aWxzLmlzU2FtZVN0YWNrdHJhY2U7XG52YXIgcGFyc2VVcmwgPSB1dGlscy5wYXJzZVVybDtcbnZhciBmaWxsID0gdXRpbHMuZmlsbDtcbnZhciBzdXBwb3J0c0ZldGNoID0gdXRpbHMuc3VwcG9ydHNGZXRjaDtcbnZhciBzdXBwb3J0c1JlZmVycmVyUG9saWN5ID0gdXRpbHMuc3VwcG9ydHNSZWZlcnJlclBvbGljeTtcbnZhciBzZXJpYWxpemVLZXlzRm9yTWVzc2FnZSA9IHV0aWxzLnNlcmlhbGl6ZUtleXNGb3JNZXNzYWdlO1xudmFyIHNlcmlhbGl6ZUV4Y2VwdGlvbiA9IHV0aWxzLnNlcmlhbGl6ZUV4Y2VwdGlvbjtcbnZhciBzYW5pdGl6ZSA9IHV0aWxzLnNhbml0aXplO1xuXG52YXIgd3JhcENvbnNvbGVNZXRob2QgPSByZXF1aXJlKCcuL2NvbnNvbGUnKS53cmFwTWV0aG9kO1xuXG52YXIgZHNuS2V5cyA9ICdzb3VyY2UgcHJvdG9jb2wgdXNlciBwYXNzIGhvc3QgcG9ydCBwYXRoJy5zcGxpdCgnICcpLFxuICBkc25QYXR0ZXJuID0gL14oPzooXFx3Kyk6KT9cXC9cXC8oPzooXFx3KykoOlxcdyspP0ApPyhbXFx3XFwuLV0rKSg/OjooXFxkKykpPyhcXC8uKikvO1xuXG5mdW5jdGlvbiBub3coKSB7XG4gIHJldHVybiArbmV3IERhdGUoKTtcbn1cblxuLy8gVGhpcyBpcyB0byBiZSBkZWZlbnNpdmUgaW4gZW52aXJvbm1lbnRzIHdoZXJlIHdpbmRvdyBkb2VzIG5vdCBleGlzdCAoc2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9nZXRzZW50cnkvcmF2ZW4tanMvcHVsbC83ODUpXG52YXIgX3dpbmRvdyA9XG4gIHR5cGVvZiB3aW5kb3cgIT09ICd1bmRlZmluZWQnXG4gICAgPyB3aW5kb3dcbiAgICA6IHR5cGVvZiBnbG9iYWwgIT09ICd1bmRlZmluZWQnID8gZ2xvYmFsIDogdHlwZW9mIHNlbGYgIT09ICd1bmRlZmluZWQnID8gc2VsZiA6IHt9O1xudmFyIF9kb2N1bWVudCA9IF93aW5kb3cuZG9jdW1lbnQ7XG52YXIgX25hdmlnYXRvciA9IF93aW5kb3cubmF2aWdhdG9yO1xuXG5mdW5jdGlvbiBrZWVwT3JpZ2luYWxDYWxsYmFjayhvcmlnaW5hbCwgY2FsbGJhY2spIHtcbiAgcmV0dXJuIGlzRnVuY3Rpb24oY2FsbGJhY2spXG4gICAgPyBmdW5jdGlvbihkYXRhKSB7XG4gICAgICAgIHJldHVybiBjYWxsYmFjayhkYXRhLCBvcmlnaW5hbCk7XG4gICAgICB9XG4gICAgOiBjYWxsYmFjaztcbn1cblxuLy8gRmlyc3QsIGNoZWNrIGZvciBKU09OIHN1cHBvcnRcbi8vIElmIHRoZXJlIGlzIG5vIEpTT04sIHdlIG5vLW9wIHRoZSBjb3JlIGZlYXR1cmVzIG9mIFJhdmVuXG4vLyBzaW5jZSBKU09OIGlzIHJlcXVpcmVkIHRvIGVuY29kZSB0aGUgcGF5bG9hZFxuZnVuY3Rpb24gUmF2ZW4oKSB7XG4gIHRoaXMuX2hhc0pTT04gPSAhISh0eXBlb2YgSlNPTiA9PT0gJ29iamVjdCcgJiYgSlNPTi5zdHJpbmdpZnkpO1xuICAvLyBSYXZlbiBjYW4gcnVuIGluIGNvbnRleHRzIHdoZXJlIHRoZXJlJ3Mgbm8gZG9jdW1lbnQgKHJlYWN0LW5hdGl2ZSlcbiAgdGhpcy5faGFzRG9jdW1lbnQgPSAhaXNVbmRlZmluZWQoX2RvY3VtZW50KTtcbiAgdGhpcy5faGFzTmF2aWdhdG9yID0gIWlzVW5kZWZpbmVkKF9uYXZpZ2F0b3IpO1xuICB0aGlzLl9sYXN0Q2FwdHVyZWRFeGNlcHRpb24gPSBudWxsO1xuICB0aGlzLl9sYXN0RGF0YSA9IG51bGw7XG4gIHRoaXMuX2xhc3RFdmVudElkID0gbnVsbDtcbiAgdGhpcy5fZ2xvYmFsU2VydmVyID0gbnVsbDtcbiAgdGhpcy5fZ2xvYmFsS2V5ID0gbnVsbDtcbiAgdGhpcy5fZ2xvYmFsUHJvamVjdCA9IG51bGw7XG4gIHRoaXMuX2dsb2JhbENvbnRleHQgPSB7fTtcbiAgdGhpcy5fZ2xvYmFsT3B0aW9ucyA9IHtcbiAgICAvLyBTRU5UUllfUkVMRUFTRSBjYW4gYmUgaW5qZWN0ZWQgYnkgaHR0cHM6Ly9naXRodWIuY29tL2dldHNlbnRyeS9zZW50cnktd2VicGFjay1wbHVnaW5cbiAgICByZWxlYXNlOiBfd2luZG93LlNFTlRSWV9SRUxFQVNFICYmIF93aW5kb3cuU0VOVFJZX1JFTEVBU0UuaWQsXG4gICAgbG9nZ2VyOiAnamF2YXNjcmlwdCcsXG4gICAgaWdub3JlRXJyb3JzOiBbXSxcbiAgICBpZ25vcmVVcmxzOiBbXSxcbiAgICB3aGl0ZWxpc3RVcmxzOiBbXSxcbiAgICBpbmNsdWRlUGF0aHM6IFtdLFxuICAgIGhlYWRlcnM6IG51bGwsXG4gICAgY29sbGVjdFdpbmRvd0Vycm9yczogdHJ1ZSxcbiAgICBjYXB0dXJlVW5oYW5kbGVkUmVqZWN0aW9uczogdHJ1ZSxcbiAgICBtYXhNZXNzYWdlTGVuZ3RoOiAwLFxuICAgIC8vIEJ5IGRlZmF1bHQsIHRydW5jYXRlcyBVUkwgdmFsdWVzIHRvIDI1MCBjaGFyc1xuICAgIG1heFVybExlbmd0aDogMjUwLFxuICAgIHN0YWNrVHJhY2VMaW1pdDogNTAsXG4gICAgYXV0b0JyZWFkY3J1bWJzOiB0cnVlLFxuICAgIGluc3RydW1lbnQ6IHRydWUsXG4gICAgc2FtcGxlUmF0ZTogMSxcbiAgICBzYW5pdGl6ZUtleXM6IFtdXG4gIH07XG4gIHRoaXMuX2ZldGNoRGVmYXVsdHMgPSB7XG4gICAgbWV0aG9kOiAnUE9TVCcsXG4gICAgLy8gRGVzcGl0ZSBhbGwgc3RhcnMgaW4gdGhlIHNreSBzYXlpbmcgdGhhdCBFZGdlIHN1cHBvcnRzIG9sZCBkcmFmdCBzeW50YXgsIGFrYSAnbmV2ZXInLCAnYWx3YXlzJywgJ29yaWdpbicgYW5kICdkZWZhdWx0XG4gICAgLy8gaHR0cHM6Ly9jYW5pdXNlLmNvbS8jZmVhdD1yZWZlcnJlci1wb2xpY3lcbiAgICAvLyBJdCBkb2Vzbid0LiBBbmQgaXQgdGhyb3cgZXhjZXB0aW9uIGluc3RlYWQgb2YgaWdub3JpbmcgdGhpcyBwYXJhbWV0ZXIuLi5cbiAgICAvLyBSRUY6IGh0dHBzOi8vZ2l0aHViLmNvbS9nZXRzZW50cnkvcmF2ZW4tanMvaXNzdWVzLzEyMzNcbiAgICByZWZlcnJlclBvbGljeTogc3VwcG9ydHNSZWZlcnJlclBvbGljeSgpID8gJ29yaWdpbicgOiAnJ1xuICB9O1xuICB0aGlzLl9pZ25vcmVPbkVycm9yID0gMDtcbiAgdGhpcy5faXNSYXZlbkluc3RhbGxlZCA9IGZhbHNlO1xuICB0aGlzLl9vcmlnaW5hbEVycm9yU3RhY2tUcmFjZUxpbWl0ID0gRXJyb3Iuc3RhY2tUcmFjZUxpbWl0O1xuICAvLyBjYXB0dXJlIHJlZmVyZW5jZXMgdG8gd2luZG93LmNvbnNvbGUgKmFuZCogYWxsIGl0cyBtZXRob2RzIGZpcnN0XG4gIC8vIGJlZm9yZSB0aGUgY29uc29sZSBwbHVnaW4gaGFzIGEgY2hhbmNlIHRvIG1vbmtleSBwYXRjaFxuICB0aGlzLl9vcmlnaW5hbENvbnNvbGUgPSBfd2luZG93LmNvbnNvbGUgfHwge307XG4gIHRoaXMuX29yaWdpbmFsQ29uc29sZU1ldGhvZHMgPSB7fTtcbiAgdGhpcy5fcGx1Z2lucyA9IFtdO1xuICB0aGlzLl9zdGFydFRpbWUgPSBub3coKTtcbiAgdGhpcy5fd3JhcHBlZEJ1aWx0SW5zID0gW107XG4gIHRoaXMuX2JyZWFkY3J1bWJzID0gW107XG4gIHRoaXMuX2xhc3RDYXB0dXJlZEV2ZW50ID0gbnVsbDtcbiAgdGhpcy5fa2V5cHJlc3NUaW1lb3V0O1xuICB0aGlzLl9sb2NhdGlvbiA9IF93aW5kb3cubG9jYXRpb247XG4gIHRoaXMuX2xhc3RIcmVmID0gdGhpcy5fbG9jYXRpb24gJiYgdGhpcy5fbG9jYXRpb24uaHJlZjtcbiAgdGhpcy5fcmVzZXRCYWNrb2ZmKCk7XG5cbiAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIGd1YXJkLWZvci1pblxuICBmb3IgKHZhciBtZXRob2QgaW4gdGhpcy5fb3JpZ2luYWxDb25zb2xlKSB7XG4gICAgdGhpcy5fb3JpZ2luYWxDb25zb2xlTWV0aG9kc1ttZXRob2RdID0gdGhpcy5fb3JpZ2luYWxDb25zb2xlW21ldGhvZF07XG4gIH1cbn1cblxuLypcbiAqIFRoZSBjb3JlIFJhdmVuIHNpbmdsZXRvblxuICpcbiAqIEB0aGlzIHtSYXZlbn1cbiAqL1xuXG5SYXZlbi5wcm90b3R5cGUgPSB7XG4gIC8vIEhhcmRjb2RlIHZlcnNpb24gc3RyaW5nIHNvIHRoYXQgcmF2ZW4gc291cmNlIGNhbiBiZSBsb2FkZWQgZGlyZWN0bHkgdmlhXG4gIC8vIHdlYnBhY2sgKHVzaW5nIGEgYnVpbGQgc3RlcCBjYXVzZXMgd2VicGFjayAjMTYxNykuIEdydW50IHZlcmlmaWVzIHRoYXRcbiAgLy8gdGhpcyB2YWx1ZSBtYXRjaGVzIHBhY2thZ2UuanNvbiBkdXJpbmcgYnVpbGQuXG4gIC8vICAgU2VlOiBodHRwczovL2dpdGh1Yi5jb20vZ2V0c2VudHJ5L3JhdmVuLWpzL2lzc3Vlcy80NjVcbiAgVkVSU0lPTjogJzMuMjcuMicsXG5cbiAgZGVidWc6IGZhbHNlLFxuXG4gIFRyYWNlS2l0OiBUcmFjZUtpdCwgLy8gYWxpYXMgdG8gVHJhY2VLaXRcblxuICAvKlxuICAgICAqIENvbmZpZ3VyZSBSYXZlbiB3aXRoIGEgRFNOIGFuZCBleHRyYSBvcHRpb25zXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge3N0cmluZ30gZHNuIFRoZSBwdWJsaWMgU2VudHJ5IERTTlxuICAgICAqIEBwYXJhbSB7b2JqZWN0fSBvcHRpb25zIFNldCBvZiBnbG9iYWwgb3B0aW9ucyBbb3B0aW9uYWxdXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIGNvbmZpZzogZnVuY3Rpb24oZHNuLCBvcHRpb25zKSB7XG4gICAgdmFyIHNlbGYgPSB0aGlzO1xuXG4gICAgaWYgKHNlbGYuX2dsb2JhbFNlcnZlcikge1xuICAgICAgdGhpcy5fbG9nRGVidWcoJ2Vycm9yJywgJ0Vycm9yOiBSYXZlbiBoYXMgYWxyZWFkeSBiZWVuIGNvbmZpZ3VyZWQnKTtcbiAgICAgIHJldHVybiBzZWxmO1xuICAgIH1cbiAgICBpZiAoIWRzbikgcmV0dXJuIHNlbGY7XG5cbiAgICB2YXIgZ2xvYmFsT3B0aW9ucyA9IHNlbGYuX2dsb2JhbE9wdGlvbnM7XG5cbiAgICAvLyBtZXJnZSBpbiBvcHRpb25zXG4gICAgaWYgKG9wdGlvbnMpIHtcbiAgICAgIGVhY2gob3B0aW9ucywgZnVuY3Rpb24oa2V5LCB2YWx1ZSkge1xuICAgICAgICAvLyB0YWdzIGFuZCBleHRyYSBhcmUgc3BlY2lhbCBhbmQgbmVlZCB0byBiZSBwdXQgaW50byBjb250ZXh0XG4gICAgICAgIGlmIChrZXkgPT09ICd0YWdzJyB8fCBrZXkgPT09ICdleHRyYScgfHwga2V5ID09PSAndXNlcicpIHtcbiAgICAgICAgICBzZWxmLl9nbG9iYWxDb250ZXh0W2tleV0gPSB2YWx1ZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBnbG9iYWxPcHRpb25zW2tleV0gPSB2YWx1ZTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgc2VsZi5zZXREU04oZHNuKTtcblxuICAgIC8vIFwiU2NyaXB0IGVycm9yLlwiIGlzIGhhcmQgY29kZWQgaW50byBicm93c2VycyBmb3IgZXJyb3JzIHRoYXQgaXQgY2FuJ3QgcmVhZC5cbiAgICAvLyB0aGlzIGlzIHRoZSByZXN1bHQgb2YgYSBzY3JpcHQgYmVpbmcgcHVsbGVkIGluIGZyb20gYW4gZXh0ZXJuYWwgZG9tYWluIGFuZCBDT1JTLlxuICAgIGdsb2JhbE9wdGlvbnMuaWdub3JlRXJyb3JzLnB1c2goL15TY3JpcHQgZXJyb3JcXC4/JC8pO1xuICAgIGdsb2JhbE9wdGlvbnMuaWdub3JlRXJyb3JzLnB1c2goL15KYXZhc2NyaXB0IGVycm9yOiBTY3JpcHQgZXJyb3JcXC4/IG9uIGxpbmUgMCQvKTtcblxuICAgIC8vIGpvaW4gcmVnZXhwIHJ1bGVzIGludG8gb25lIGJpZyBydWxlXG4gICAgZ2xvYmFsT3B0aW9ucy5pZ25vcmVFcnJvcnMgPSBqb2luUmVnRXhwKGdsb2JhbE9wdGlvbnMuaWdub3JlRXJyb3JzKTtcbiAgICBnbG9iYWxPcHRpb25zLmlnbm9yZVVybHMgPSBnbG9iYWxPcHRpb25zLmlnbm9yZVVybHMubGVuZ3RoXG4gICAgICA/IGpvaW5SZWdFeHAoZ2xvYmFsT3B0aW9ucy5pZ25vcmVVcmxzKVxuICAgICAgOiBmYWxzZTtcbiAgICBnbG9iYWxPcHRpb25zLndoaXRlbGlzdFVybHMgPSBnbG9iYWxPcHRpb25zLndoaXRlbGlzdFVybHMubGVuZ3RoXG4gICAgICA/IGpvaW5SZWdFeHAoZ2xvYmFsT3B0aW9ucy53aGl0ZWxpc3RVcmxzKVxuICAgICAgOiBmYWxzZTtcbiAgICBnbG9iYWxPcHRpb25zLmluY2x1ZGVQYXRocyA9IGpvaW5SZWdFeHAoZ2xvYmFsT3B0aW9ucy5pbmNsdWRlUGF0aHMpO1xuICAgIGdsb2JhbE9wdGlvbnMubWF4QnJlYWRjcnVtYnMgPSBNYXRoLm1heChcbiAgICAgIDAsXG4gICAgICBNYXRoLm1pbihnbG9iYWxPcHRpb25zLm1heEJyZWFkY3J1bWJzIHx8IDEwMCwgMTAwKVxuICAgICk7IC8vIGRlZmF1bHQgYW5kIGhhcmQgbGltaXQgaXMgMTAwXG5cbiAgICB2YXIgYXV0b0JyZWFkY3J1bWJEZWZhdWx0cyA9IHtcbiAgICAgIHhocjogdHJ1ZSxcbiAgICAgIGNvbnNvbGU6IHRydWUsXG4gICAgICBkb206IHRydWUsXG4gICAgICBsb2NhdGlvbjogdHJ1ZSxcbiAgICAgIHNlbnRyeTogdHJ1ZVxuICAgIH07XG5cbiAgICB2YXIgYXV0b0JyZWFkY3J1bWJzID0gZ2xvYmFsT3B0aW9ucy5hdXRvQnJlYWRjcnVtYnM7XG4gICAgaWYgKHt9LnRvU3RyaW5nLmNhbGwoYXV0b0JyZWFkY3J1bWJzKSA9PT0gJ1tvYmplY3QgT2JqZWN0XScpIHtcbiAgICAgIGF1dG9CcmVhZGNydW1icyA9IG9iamVjdE1lcmdlKGF1dG9CcmVhZGNydW1iRGVmYXVsdHMsIGF1dG9CcmVhZGNydW1icyk7XG4gICAgfSBlbHNlIGlmIChhdXRvQnJlYWRjcnVtYnMgIT09IGZhbHNlKSB7XG4gICAgICBhdXRvQnJlYWRjcnVtYnMgPSBhdXRvQnJlYWRjcnVtYkRlZmF1bHRzO1xuICAgIH1cbiAgICBnbG9iYWxPcHRpb25zLmF1dG9CcmVhZGNydW1icyA9IGF1dG9CcmVhZGNydW1icztcblxuICAgIHZhciBpbnN0cnVtZW50RGVmYXVsdHMgPSB7XG4gICAgICB0cnlDYXRjaDogdHJ1ZVxuICAgIH07XG5cbiAgICB2YXIgaW5zdHJ1bWVudCA9IGdsb2JhbE9wdGlvbnMuaW5zdHJ1bWVudDtcbiAgICBpZiAoe30udG9TdHJpbmcuY2FsbChpbnN0cnVtZW50KSA9PT0gJ1tvYmplY3QgT2JqZWN0XScpIHtcbiAgICAgIGluc3RydW1lbnQgPSBvYmplY3RNZXJnZShpbnN0cnVtZW50RGVmYXVsdHMsIGluc3RydW1lbnQpO1xuICAgIH0gZWxzZSBpZiAoaW5zdHJ1bWVudCAhPT0gZmFsc2UpIHtcbiAgICAgIGluc3RydW1lbnQgPSBpbnN0cnVtZW50RGVmYXVsdHM7XG4gICAgfVxuICAgIGdsb2JhbE9wdGlvbnMuaW5zdHJ1bWVudCA9IGluc3RydW1lbnQ7XG5cbiAgICBUcmFjZUtpdC5jb2xsZWN0V2luZG93RXJyb3JzID0gISFnbG9iYWxPcHRpb25zLmNvbGxlY3RXaW5kb3dFcnJvcnM7XG5cbiAgICAvLyByZXR1cm4gZm9yIGNoYWluaW5nXG4gICAgcmV0dXJuIHNlbGY7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBJbnN0YWxscyBhIGdsb2JhbCB3aW5kb3cub25lcnJvciBlcnJvciBoYW5kbGVyXG4gICAgICogdG8gY2FwdHVyZSBhbmQgcmVwb3J0IHVuY2F1Z2h0IGV4Y2VwdGlvbnMuXG4gICAgICogQXQgdGhpcyBwb2ludCwgaW5zdGFsbCgpIGlzIHJlcXVpcmVkIHRvIGJlIGNhbGxlZCBkdWVcbiAgICAgKiB0byB0aGUgd2F5IFRyYWNlS2l0IGlzIHNldCB1cC5cbiAgICAgKlxuICAgICAqIEByZXR1cm4ge1JhdmVufVxuICAgICAqL1xuICBpbnN0YWxsOiBmdW5jdGlvbigpIHtcbiAgICB2YXIgc2VsZiA9IHRoaXM7XG4gICAgaWYgKHNlbGYuaXNTZXR1cCgpICYmICFzZWxmLl9pc1JhdmVuSW5zdGFsbGVkKSB7XG4gICAgICBUcmFjZUtpdC5yZXBvcnQuc3Vic2NyaWJlKGZ1bmN0aW9uKCkge1xuICAgICAgICBzZWxmLl9oYW5kbGVPbkVycm9yU3RhY2tJbmZvLmFwcGx5KHNlbGYsIGFyZ3VtZW50cyk7XG4gICAgICB9KTtcblxuICAgICAgaWYgKHNlbGYuX2dsb2JhbE9wdGlvbnMuY2FwdHVyZVVuaGFuZGxlZFJlamVjdGlvbnMpIHtcbiAgICAgICAgc2VsZi5fYXR0YWNoUHJvbWlzZVJlamVjdGlvbkhhbmRsZXIoKTtcbiAgICAgIH1cblxuICAgICAgc2VsZi5fcGF0Y2hGdW5jdGlvblRvU3RyaW5nKCk7XG5cbiAgICAgIGlmIChzZWxmLl9nbG9iYWxPcHRpb25zLmluc3RydW1lbnQgJiYgc2VsZi5fZ2xvYmFsT3B0aW9ucy5pbnN0cnVtZW50LnRyeUNhdGNoKSB7XG4gICAgICAgIHNlbGYuX2luc3RydW1lbnRUcnlDYXRjaCgpO1xuICAgICAgfVxuXG4gICAgICBpZiAoc2VsZi5fZ2xvYmFsT3B0aW9ucy5hdXRvQnJlYWRjcnVtYnMpIHNlbGYuX2luc3RydW1lbnRCcmVhZGNydW1icygpO1xuXG4gICAgICAvLyBJbnN0YWxsIGFsbCBvZiB0aGUgcGx1Z2luc1xuICAgICAgc2VsZi5fZHJhaW5QbHVnaW5zKCk7XG5cbiAgICAgIHNlbGYuX2lzUmF2ZW5JbnN0YWxsZWQgPSB0cnVlO1xuICAgIH1cblxuICAgIEVycm9yLnN0YWNrVHJhY2VMaW1pdCA9IHNlbGYuX2dsb2JhbE9wdGlvbnMuc3RhY2tUcmFjZUxpbWl0O1xuICAgIHJldHVybiB0aGlzO1xuICB9LFxuXG4gIC8qXG4gICAgICogU2V0IHRoZSBEU04gKGNhbiBiZSBjYWxsZWQgbXVsdGlwbGUgdGltZSB1bmxpa2UgY29uZmlnKVxuICAgICAqXG4gICAgICogQHBhcmFtIHtzdHJpbmd9IGRzbiBUaGUgcHVibGljIFNlbnRyeSBEU05cbiAgICAgKi9cbiAgc2V0RFNOOiBmdW5jdGlvbihkc24pIHtcbiAgICB2YXIgc2VsZiA9IHRoaXMsXG4gICAgICB1cmkgPSBzZWxmLl9wYXJzZURTTihkc24pLFxuICAgICAgbGFzdFNsYXNoID0gdXJpLnBhdGgubGFzdEluZGV4T2YoJy8nKSxcbiAgICAgIHBhdGggPSB1cmkucGF0aC5zdWJzdHIoMSwgbGFzdFNsYXNoKTtcblxuICAgIHNlbGYuX2RzbiA9IGRzbjtcbiAgICBzZWxmLl9nbG9iYWxLZXkgPSB1cmkudXNlcjtcbiAgICBzZWxmLl9nbG9iYWxTZWNyZXQgPSB1cmkucGFzcyAmJiB1cmkucGFzcy5zdWJzdHIoMSk7XG4gICAgc2VsZi5fZ2xvYmFsUHJvamVjdCA9IHVyaS5wYXRoLnN1YnN0cihsYXN0U2xhc2ggKyAxKTtcblxuICAgIHNlbGYuX2dsb2JhbFNlcnZlciA9IHNlbGYuX2dldEdsb2JhbFNlcnZlcih1cmkpO1xuXG4gICAgc2VsZi5fZ2xvYmFsRW5kcG9pbnQgPVxuICAgICAgc2VsZi5fZ2xvYmFsU2VydmVyICsgJy8nICsgcGF0aCArICdhcGkvJyArIHNlbGYuX2dsb2JhbFByb2plY3QgKyAnL3N0b3JlLyc7XG5cbiAgICAvLyBSZXNldCBiYWNrb2ZmIHN0YXRlIHNpbmNlIHdlIG1heSBiZSBwb2ludGluZyBhdCBhXG4gICAgLy8gbmV3IHByb2plY3Qvc2VydmVyXG4gICAgdGhpcy5fcmVzZXRCYWNrb2ZmKCk7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBXcmFwIGNvZGUgd2l0aGluIGEgY29udGV4dCBzbyBSYXZlbiBjYW4gY2FwdHVyZSBlcnJvcnNcbiAgICAgKiByZWxpYWJseSBhY3Jvc3MgZG9tYWlucyB0aGF0IGlzIGV4ZWN1dGVkIGltbWVkaWF0ZWx5LlxuICAgICAqXG4gICAgICogQHBhcmFtIHtvYmplY3R9IG9wdGlvbnMgQSBzcGVjaWZpYyBzZXQgb2Ygb3B0aW9ucyBmb3IgdGhpcyBjb250ZXh0IFtvcHRpb25hbF1cbiAgICAgKiBAcGFyYW0ge2Z1bmN0aW9ufSBmdW5jIFRoZSBjYWxsYmFjayB0byBiZSBpbW1lZGlhdGVseSBleGVjdXRlZCB3aXRoaW4gdGhlIGNvbnRleHRcbiAgICAgKiBAcGFyYW0ge2FycmF5fSBhcmdzIEFuIGFycmF5IG9mIGFyZ3VtZW50cyB0byBiZSBjYWxsZWQgd2l0aCB0aGUgY2FsbGJhY2sgW29wdGlvbmFsXVxuICAgICAqL1xuICBjb250ZXh0OiBmdW5jdGlvbihvcHRpb25zLCBmdW5jLCBhcmdzKSB7XG4gICAgaWYgKGlzRnVuY3Rpb24ob3B0aW9ucykpIHtcbiAgICAgIGFyZ3MgPSBmdW5jIHx8IFtdO1xuICAgICAgZnVuYyA9IG9wdGlvbnM7XG4gICAgICBvcHRpb25zID0ge307XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMud3JhcChvcHRpb25zLCBmdW5jKS5hcHBseSh0aGlzLCBhcmdzKTtcbiAgfSxcblxuICAvKlxuICAgICAqIFdyYXAgY29kZSB3aXRoaW4gYSBjb250ZXh0IGFuZCByZXR1cm5zIGJhY2sgYSBuZXcgZnVuY3Rpb24gdG8gYmUgZXhlY3V0ZWRcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7b2JqZWN0fSBvcHRpb25zIEEgc3BlY2lmaWMgc2V0IG9mIG9wdGlvbnMgZm9yIHRoaXMgY29udGV4dCBbb3B0aW9uYWxdXG4gICAgICogQHBhcmFtIHtmdW5jdGlvbn0gZnVuYyBUaGUgZnVuY3Rpb24gdG8gYmUgd3JhcHBlZCBpbiBhIG5ldyBjb250ZXh0XG4gICAgICogQHBhcmFtIHtmdW5jdGlvbn0gX2JlZm9yZSBBIGZ1bmN0aW9uIHRvIGNhbGwgYmVmb3JlIHRoZSB0cnkvY2F0Y2ggd3JhcHBlciBbb3B0aW9uYWwsIHByaXZhdGVdXG4gICAgICogQHJldHVybiB7ZnVuY3Rpb259IFRoZSBuZXdseSB3cmFwcGVkIGZ1bmN0aW9ucyB3aXRoIGEgY29udGV4dFxuICAgICAqL1xuICB3cmFwOiBmdW5jdGlvbihvcHRpb25zLCBmdW5jLCBfYmVmb3JlKSB7XG4gICAgdmFyIHNlbGYgPSB0aGlzO1xuICAgIC8vIDEgYXJndW1lbnQgaGFzIGJlZW4gcGFzc2VkLCBhbmQgaXQncyBub3QgYSBmdW5jdGlvblxuICAgIC8vIHNvIGp1c3QgcmV0dXJuIGl0XG4gICAgaWYgKGlzVW5kZWZpbmVkKGZ1bmMpICYmICFpc0Z1bmN0aW9uKG9wdGlvbnMpKSB7XG4gICAgICByZXR1cm4gb3B0aW9ucztcbiAgICB9XG5cbiAgICAvLyBvcHRpb25zIGlzIG9wdGlvbmFsXG4gICAgaWYgKGlzRnVuY3Rpb24ob3B0aW9ucykpIHtcbiAgICAgIGZ1bmMgPSBvcHRpb25zO1xuICAgICAgb3B0aW9ucyA9IHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICAvLyBBdCB0aGlzIHBvaW50LCB3ZSd2ZSBwYXNzZWQgYWxvbmcgMiBhcmd1bWVudHMsIGFuZCB0aGUgc2Vjb25kIG9uZVxuICAgIC8vIGlzIG5vdCBhIGZ1bmN0aW9uIGVpdGhlciwgc28gd2UnbGwganVzdCByZXR1cm4gdGhlIHNlY29uZCBhcmd1bWVudC5cbiAgICBpZiAoIWlzRnVuY3Rpb24oZnVuYykpIHtcbiAgICAgIHJldHVybiBmdW5jO1xuICAgIH1cblxuICAgIC8vIFdlIGRvbid0IHdhbm5hIHdyYXAgaXQgdHdpY2UhXG4gICAgdHJ5IHtcbiAgICAgIGlmIChmdW5jLl9fcmF2ZW5fXykge1xuICAgICAgICByZXR1cm4gZnVuYztcbiAgICAgIH1cblxuICAgICAgLy8gSWYgdGhpcyBoYXMgYWxyZWFkeSBiZWVuIHdyYXBwZWQgaW4gdGhlIHBhc3QsIHJldHVybiB0aGF0XG4gICAgICBpZiAoZnVuYy5fX3JhdmVuX3dyYXBwZXJfXykge1xuICAgICAgICByZXR1cm4gZnVuYy5fX3JhdmVuX3dyYXBwZXJfXztcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAvLyBKdXN0IGFjY2Vzc2luZyBjdXN0b20gcHJvcHMgaW4gc29tZSBTZWxlbml1bSBlbnZpcm9ubWVudHNcbiAgICAgIC8vIGNhbiBjYXVzZSBhIFwiUGVybWlzc2lvbiBkZW5pZWRcIiBleGNlcHRpb24gKHNlZSByYXZlbi1qcyM0OTUpLlxuICAgICAgLy8gQmFpbCBvbiB3cmFwcGluZyBhbmQgcmV0dXJuIHRoZSBmdW5jdGlvbiBhcy1pcyAoZGVmZXJzIHRvIHdpbmRvdy5vbmVycm9yKS5cbiAgICAgIHJldHVybiBmdW5jO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHdyYXBwZWQoKSB7XG4gICAgICB2YXIgYXJncyA9IFtdLFxuICAgICAgICBpID0gYXJndW1lbnRzLmxlbmd0aCxcbiAgICAgICAgZGVlcCA9ICFvcHRpb25zIHx8IChvcHRpb25zICYmIG9wdGlvbnMuZGVlcCAhPT0gZmFsc2UpO1xuXG4gICAgICBpZiAoX2JlZm9yZSAmJiBpc0Z1bmN0aW9uKF9iZWZvcmUpKSB7XG4gICAgICAgIF9iZWZvcmUuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcbiAgICAgIH1cblxuICAgICAgLy8gUmVjdXJzaXZlbHkgd3JhcCBhbGwgb2YgYSBmdW5jdGlvbidzIGFyZ3VtZW50cyB0aGF0IGFyZVxuICAgICAgLy8gZnVuY3Rpb25zIHRoZW1zZWx2ZXMuXG4gICAgICB3aGlsZSAoaS0tKSBhcmdzW2ldID0gZGVlcCA/IHNlbGYud3JhcChvcHRpb25zLCBhcmd1bWVudHNbaV0pIDogYXJndW1lbnRzW2ldO1xuXG4gICAgICB0cnkge1xuICAgICAgICAvLyBBdHRlbXB0IHRvIGludm9rZSB1c2VyLWxhbmQgZnVuY3Rpb25cbiAgICAgICAgLy8gTk9URTogSWYgeW91IGFyZSBhIFNlbnRyeSB1c2VyLCBhbmQgeW91IGFyZSBzZWVpbmcgdGhpcyBzdGFjayBmcmFtZSwgaXRcbiAgICAgICAgLy8gICAgICAgbWVhbnMgUmF2ZW4gY2F1Z2h0IGFuIGVycm9yIGludm9raW5nIHlvdXIgYXBwbGljYXRpb24gY29kZS4gVGhpcyBpc1xuICAgICAgICAvLyAgICAgICBleHBlY3RlZCBiZWhhdmlvciBhbmQgTk9UIGluZGljYXRpdmUgb2YgYSBidWcgd2l0aCBSYXZlbi5qcy5cbiAgICAgICAgcmV0dXJuIGZ1bmMuYXBwbHkodGhpcywgYXJncyk7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHNlbGYuX2lnbm9yZU5leHRPbkVycm9yKCk7XG4gICAgICAgIHNlbGYuY2FwdHVyZUV4Y2VwdGlvbihlLCBvcHRpb25zKTtcbiAgICAgICAgdGhyb3cgZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBjb3B5IG92ZXIgcHJvcGVydGllcyBvZiB0aGUgb2xkIGZ1bmN0aW9uXG4gICAgZm9yICh2YXIgcHJvcGVydHkgaW4gZnVuYykge1xuICAgICAgaWYgKGhhc0tleShmdW5jLCBwcm9wZXJ0eSkpIHtcbiAgICAgICAgd3JhcHBlZFtwcm9wZXJ0eV0gPSBmdW5jW3Byb3BlcnR5XTtcbiAgICAgIH1cbiAgICB9XG4gICAgd3JhcHBlZC5wcm90b3R5cGUgPSBmdW5jLnByb3RvdHlwZTtcblxuICAgIGZ1bmMuX19yYXZlbl93cmFwcGVyX18gPSB3cmFwcGVkO1xuICAgIC8vIFNpZ25hbCB0aGF0IHRoaXMgZnVuY3Rpb24gaGFzIGJlZW4gd3JhcHBlZC9maWxsZWQgYWxyZWFkeVxuICAgIC8vIGZvciBib3RoIGRlYnVnZ2luZyBhbmQgdG8gcHJldmVudCBpdCB0byBiZWluZyB3cmFwcGVkL2ZpbGxlZCB0d2ljZVxuICAgIHdyYXBwZWQuX19yYXZlbl9fID0gdHJ1ZTtcbiAgICB3cmFwcGVkLl9fb3JpZ19fID0gZnVuYztcblxuICAgIHJldHVybiB3cmFwcGVkO1xuICB9LFxuXG4gIC8qKlxuICAgKiBVbmluc3RhbGxzIHRoZSBnbG9iYWwgZXJyb3IgaGFuZGxlci5cbiAgICpcbiAgICogQHJldHVybiB7UmF2ZW59XG4gICAqL1xuICB1bmluc3RhbGw6IGZ1bmN0aW9uKCkge1xuICAgIFRyYWNlS2l0LnJlcG9ydC51bmluc3RhbGwoKTtcblxuICAgIHRoaXMuX2RldGFjaFByb21pc2VSZWplY3Rpb25IYW5kbGVyKCk7XG4gICAgdGhpcy5fdW5wYXRjaEZ1bmN0aW9uVG9TdHJpbmcoKTtcbiAgICB0aGlzLl9yZXN0b3JlQnVpbHRJbnMoKTtcbiAgICB0aGlzLl9yZXN0b3JlQ29uc29sZSgpO1xuXG4gICAgRXJyb3Iuc3RhY2tUcmFjZUxpbWl0ID0gdGhpcy5fb3JpZ2luYWxFcnJvclN0YWNrVHJhY2VMaW1pdDtcbiAgICB0aGlzLl9pc1JhdmVuSW5zdGFsbGVkID0gZmFsc2U7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfSxcblxuICAvKipcbiAgICogQ2FsbGJhY2sgdXNlZCBmb3IgYHVuaGFuZGxlZHJlamVjdGlvbmAgZXZlbnRcbiAgICpcbiAgICogQHBhcmFtIHtQcm9taXNlUmVqZWN0aW9uRXZlbnR9IGV2ZW50IEFuIG9iamVjdCBjb250YWluaW5nXG4gICAqICAgcHJvbWlzZTogdGhlIFByb21pc2UgdGhhdCB3YXMgcmVqZWN0ZWRcbiAgICogICByZWFzb246IHRoZSB2YWx1ZSB3aXRoIHdoaWNoIHRoZSBQcm9taXNlIHdhcyByZWplY3RlZFxuICAgKiBAcmV0dXJuIHZvaWRcbiAgICovXG4gIF9wcm9taXNlUmVqZWN0aW9uSGFuZGxlcjogZnVuY3Rpb24oZXZlbnQpIHtcbiAgICB0aGlzLl9sb2dEZWJ1ZygnZGVidWcnLCAnUmF2ZW4gY2F1Z2h0IHVuaGFuZGxlZCBwcm9taXNlIHJlamVjdGlvbjonLCBldmVudCk7XG4gICAgdGhpcy5jYXB0dXJlRXhjZXB0aW9uKGV2ZW50LnJlYXNvbiwge1xuICAgICAgbWVjaGFuaXNtOiB7XG4gICAgICAgIHR5cGU6ICdvbnVuaGFuZGxlZHJlamVjdGlvbicsXG4gICAgICAgIGhhbmRsZWQ6IGZhbHNlXG4gICAgICB9XG4gICAgfSk7XG4gIH0sXG5cbiAgLyoqXG4gICAqIEluc3RhbGxzIHRoZSBnbG9iYWwgcHJvbWlzZSByZWplY3Rpb24gaGFuZGxlci5cbiAgICpcbiAgICogQHJldHVybiB7cmF2ZW59XG4gICAqL1xuICBfYXR0YWNoUHJvbWlzZVJlamVjdGlvbkhhbmRsZXI6IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMuX3Byb21pc2VSZWplY3Rpb25IYW5kbGVyID0gdGhpcy5fcHJvbWlzZVJlamVjdGlvbkhhbmRsZXIuYmluZCh0aGlzKTtcbiAgICBfd2luZG93LmFkZEV2ZW50TGlzdGVuZXIgJiZcbiAgICAgIF93aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigndW5oYW5kbGVkcmVqZWN0aW9uJywgdGhpcy5fcHJvbWlzZVJlamVjdGlvbkhhbmRsZXIpO1xuICAgIHJldHVybiB0aGlzO1xuICB9LFxuXG4gIC8qKlxuICAgKiBVbmluc3RhbGxzIHRoZSBnbG9iYWwgcHJvbWlzZSByZWplY3Rpb24gaGFuZGxlci5cbiAgICpcbiAgICogQHJldHVybiB7cmF2ZW59XG4gICAqL1xuICBfZGV0YWNoUHJvbWlzZVJlamVjdGlvbkhhbmRsZXI6IGZ1bmN0aW9uKCkge1xuICAgIF93aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lciAmJlxuICAgICAgX3dpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCd1bmhhbmRsZWRyZWplY3Rpb24nLCB0aGlzLl9wcm9taXNlUmVqZWN0aW9uSGFuZGxlcik7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLyoqXG4gICAqIE1hbnVhbGx5IGNhcHR1cmUgYW4gZXhjZXB0aW9uIGFuZCBzZW5kIGl0IG92ZXIgdG8gU2VudHJ5XG4gICAqXG4gICAqIEBwYXJhbSB7ZXJyb3J9IGV4IEFuIGV4Y2VwdGlvbiB0byBiZSBsb2dnZWRcbiAgICogQHBhcmFtIHtvYmplY3R9IG9wdGlvbnMgQSBzcGVjaWZpYyBzZXQgb2Ygb3B0aW9ucyBmb3IgdGhpcyBlcnJvciBbb3B0aW9uYWxdXG4gICAqIEByZXR1cm4ge1JhdmVufVxuICAgKi9cbiAgY2FwdHVyZUV4Y2VwdGlvbjogZnVuY3Rpb24oZXgsIG9wdGlvbnMpIHtcbiAgICBvcHRpb25zID0gb2JqZWN0TWVyZ2Uoe3RyaW1IZWFkRnJhbWVzOiAwfSwgb3B0aW9ucyA/IG9wdGlvbnMgOiB7fSk7XG5cbiAgICBpZiAoaXNFcnJvckV2ZW50KGV4KSAmJiBleC5lcnJvcikge1xuICAgICAgLy8gSWYgaXQgaXMgYW4gRXJyb3JFdmVudCB3aXRoIGBlcnJvcmAgcHJvcGVydHksIGV4dHJhY3QgaXQgdG8gZ2V0IGFjdHVhbCBFcnJvclxuICAgICAgZXggPSBleC5lcnJvcjtcbiAgICB9IGVsc2UgaWYgKGlzRE9NRXJyb3IoZXgpIHx8IGlzRE9NRXhjZXB0aW9uKGV4KSkge1xuICAgICAgLy8gSWYgaXQgaXMgYSBET01FcnJvciBvciBET01FeGNlcHRpb24gKHdoaWNoIGFyZSBsZWdhY3kgQVBJcywgYnV0IHN0aWxsIHN1cHBvcnRlZCBpbiBzb21lIGJyb3dzZXJzKVxuICAgICAgLy8gdGhlbiB3ZSBqdXN0IGV4dHJhY3QgdGhlIG5hbWUgYW5kIG1lc3NhZ2UsIGFzIHRoZXkgZG9uJ3QgcHJvdmlkZSBhbnl0aGluZyBlbHNlXG4gICAgICAvLyBodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9BUEkvRE9NRXJyb3JcbiAgICAgIC8vIGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0FQSS9ET01FeGNlcHRpb25cbiAgICAgIHZhciBuYW1lID0gZXgubmFtZSB8fCAoaXNET01FcnJvcihleCkgPyAnRE9NRXJyb3InIDogJ0RPTUV4Y2VwdGlvbicpO1xuICAgICAgdmFyIG1lc3NhZ2UgPSBleC5tZXNzYWdlID8gbmFtZSArICc6ICcgKyBleC5tZXNzYWdlIDogbmFtZTtcblxuICAgICAgcmV0dXJuIHRoaXMuY2FwdHVyZU1lc3NhZ2UoXG4gICAgICAgIG1lc3NhZ2UsXG4gICAgICAgIG9iamVjdE1lcmdlKG9wdGlvbnMsIHtcbiAgICAgICAgICAvLyBuZWl0aGVyIERPTUVycm9yIG9yIERPTUV4Y2VwdGlvbiBwcm92aWRlIHN0YWNrIHRyYWNlIGFuZCB3ZSBtb3N0IGxpa2VseSB3b250IGdldCBpdCB0aGlzIHdheSBhcyB3ZWxsXG4gICAgICAgICAgLy8gYnV0IGl0J3MgYmFyZWx5IGFueSBvdmVyaGVhZCBzbyB3ZSBtYXkgYXQgbGVhc3QgdHJ5XG4gICAgICAgICAgc3RhY2t0cmFjZTogdHJ1ZSxcbiAgICAgICAgICB0cmltSGVhZEZyYW1lczogb3B0aW9ucy50cmltSGVhZEZyYW1lcyArIDFcbiAgICAgICAgfSlcbiAgICAgICk7XG4gICAgfSBlbHNlIGlmIChpc0Vycm9yKGV4KSkge1xuICAgICAgLy8gd2UgaGF2ZSBhIHJlYWwgRXJyb3Igb2JqZWN0XG4gICAgICBleCA9IGV4O1xuICAgIH0gZWxzZSBpZiAoaXNQbGFpbk9iamVjdChleCkpIHtcbiAgICAgIC8vIElmIGl0IGlzIHBsYWluIE9iamVjdCwgc2VyaWFsaXplIGl0IG1hbnVhbGx5IGFuZCBleHRyYWN0IG9wdGlvbnNcbiAgICAgIC8vIFRoaXMgd2lsbCBhbGxvdyB1cyB0byBncm91cCBldmVudHMgYmFzZWQgb24gdG9wLWxldmVsIGtleXNcbiAgICAgIC8vIHdoaWNoIGlzIG11Y2ggYmV0dGVyIHRoYW4gY3JlYXRpbmcgbmV3IGdyb3VwIHdoZW4gYW55IGtleS92YWx1ZSBjaGFuZ2VcbiAgICAgIG9wdGlvbnMgPSB0aGlzLl9nZXRDYXB0dXJlRXhjZXB0aW9uT3B0aW9uc0Zyb21QbGFpbk9iamVjdChvcHRpb25zLCBleCk7XG4gICAgICBleCA9IG5ldyBFcnJvcihvcHRpb25zLm1lc3NhZ2UpO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBJZiBub25lIG9mIHByZXZpb3VzIGNoZWNrcyB3ZXJlIHZhbGlkLCB0aGVuIGl0IG1lYW5zIHRoYXRcbiAgICAgIC8vIGl0J3Mgbm90IGEgRE9NRXJyb3IvRE9NRXhjZXB0aW9uXG4gICAgICAvLyBpdCdzIG5vdCBhIHBsYWluIE9iamVjdFxuICAgICAgLy8gaXQncyBub3QgYSB2YWxpZCBFcnJvckV2ZW50IChvbmUgd2l0aCBhbiBlcnJvciBwcm9wZXJ0eSlcbiAgICAgIC8vIGl0J3Mgbm90IGFuIEVycm9yXG4gICAgICAvLyBTbyBiYWlsIG91dCBhbmQgY2FwdHVyZSBpdCBhcyBhIHNpbXBsZSBtZXNzYWdlOlxuICAgICAgcmV0dXJuIHRoaXMuY2FwdHVyZU1lc3NhZ2UoXG4gICAgICAgIGV4LFxuICAgICAgICBvYmplY3RNZXJnZShvcHRpb25zLCB7XG4gICAgICAgICAgc3RhY2t0cmFjZTogdHJ1ZSwgLy8gaWYgd2UgZmFsbCBiYWNrIHRvIGNhcHR1cmVNZXNzYWdlLCBkZWZhdWx0IHRvIGF0dGVtcHRpbmcgYSBuZXcgdHJhY2VcbiAgICAgICAgICB0cmltSGVhZEZyYW1lczogb3B0aW9ucy50cmltSGVhZEZyYW1lcyArIDFcbiAgICAgICAgfSlcbiAgICAgICk7XG4gICAgfVxuXG4gICAgLy8gU3RvcmUgdGhlIHJhdyBleGNlcHRpb24gb2JqZWN0IGZvciBwb3RlbnRpYWwgZGVidWdnaW5nIGFuZCBpbnRyb3NwZWN0aW9uXG4gICAgdGhpcy5fbGFzdENhcHR1cmVkRXhjZXB0aW9uID0gZXg7XG5cbiAgICAvLyBUcmFjZUtpdC5yZXBvcnQgd2lsbCByZS1yYWlzZSBhbnkgZXhjZXB0aW9uIHBhc3NlZCB0byBpdCxcbiAgICAvLyB3aGljaCBtZWFucyB5b3UgaGF2ZSB0byB3cmFwIGl0IGluIHRyeS9jYXRjaC4gSW5zdGVhZCwgd2VcbiAgICAvLyBjYW4gd3JhcCBpdCBoZXJlIGFuZCBvbmx5IHJlLXJhaXNlIGlmIFRyYWNlS2l0LnJlcG9ydFxuICAgIC8vIHJhaXNlcyBhbiBleGNlcHRpb24gZGlmZmVyZW50IGZyb20gdGhlIG9uZSB3ZSBhc2tlZCB0b1xuICAgIC8vIHJlcG9ydCBvbi5cbiAgICB0cnkge1xuICAgICAgdmFyIHN0YWNrID0gVHJhY2VLaXQuY29tcHV0ZVN0YWNrVHJhY2UoZXgpO1xuICAgICAgdGhpcy5faGFuZGxlU3RhY2tJbmZvKHN0YWNrLCBvcHRpb25zKTtcbiAgICB9IGNhdGNoIChleDEpIHtcbiAgICAgIGlmIChleCAhPT0gZXgxKSB7XG4gICAgICAgIHRocm93IGV4MTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfSxcblxuICBfZ2V0Q2FwdHVyZUV4Y2VwdGlvbk9wdGlvbnNGcm9tUGxhaW5PYmplY3Q6IGZ1bmN0aW9uKGN1cnJlbnRPcHRpb25zLCBleCkge1xuICAgIHZhciBleEtleXMgPSBPYmplY3Qua2V5cyhleCkuc29ydCgpO1xuICAgIHZhciBvcHRpb25zID0gb2JqZWN0TWVyZ2UoY3VycmVudE9wdGlvbnMsIHtcbiAgICAgIG1lc3NhZ2U6XG4gICAgICAgICdOb24tRXJyb3IgZXhjZXB0aW9uIGNhcHR1cmVkIHdpdGgga2V5czogJyArIHNlcmlhbGl6ZUtleXNGb3JNZXNzYWdlKGV4S2V5cyksXG4gICAgICBmaW5nZXJwcmludDogW21kNShleEtleXMpXSxcbiAgICAgIGV4dHJhOiBjdXJyZW50T3B0aW9ucy5leHRyYSB8fCB7fVxuICAgIH0pO1xuICAgIG9wdGlvbnMuZXh0cmEuX19zZXJpYWxpemVkX18gPSBzZXJpYWxpemVFeGNlcHRpb24oZXgpO1xuXG4gICAgcmV0dXJuIG9wdGlvbnM7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBNYW51YWxseSBzZW5kIGEgbWVzc2FnZSB0byBTZW50cnlcbiAgICAgKlxuICAgICAqIEBwYXJhbSB7c3RyaW5nfSBtc2cgQSBwbGFpbiBtZXNzYWdlIHRvIGJlIGNhcHR1cmVkIGluIFNlbnRyeVxuICAgICAqIEBwYXJhbSB7b2JqZWN0fSBvcHRpb25zIEEgc3BlY2lmaWMgc2V0IG9mIG9wdGlvbnMgZm9yIHRoaXMgbWVzc2FnZSBbb3B0aW9uYWxdXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIGNhcHR1cmVNZXNzYWdlOiBmdW5jdGlvbihtc2csIG9wdGlvbnMpIHtcbiAgICAvLyBjb25maWcoKSBhdXRvbWFnaWNhbGx5IGNvbnZlcnRzIGlnbm9yZUVycm9ycyBmcm9tIGEgbGlzdCB0byBhIFJlZ0V4cCBzbyB3ZSBuZWVkIHRvIHRlc3QgZm9yIGFuXG4gICAgLy8gZWFybHkgY2FsbDsgd2UnbGwgZXJyb3Igb24gdGhlIHNpZGUgb2YgbG9nZ2luZyBhbnl0aGluZyBjYWxsZWQgYmVmb3JlIGNvbmZpZ3VyYXRpb24gc2luY2UgaXQnc1xuICAgIC8vIHByb2JhYmx5IHNvbWV0aGluZyB5b3Ugc2hvdWxkIHNlZTpcbiAgICBpZiAoXG4gICAgICAhIXRoaXMuX2dsb2JhbE9wdGlvbnMuaWdub3JlRXJyb3JzLnRlc3QgJiZcbiAgICAgIHRoaXMuX2dsb2JhbE9wdGlvbnMuaWdub3JlRXJyb3JzLnRlc3QobXNnKVxuICAgICkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuICAgIG1zZyA9IG1zZyArICcnOyAvLyBNYWtlIHN1cmUgaXQncyBhY3R1YWxseSBhIHN0cmluZ1xuXG4gICAgdmFyIGRhdGEgPSBvYmplY3RNZXJnZShcbiAgICAgIHtcbiAgICAgICAgbWVzc2FnZTogbXNnXG4gICAgICB9LFxuICAgICAgb3B0aW9uc1xuICAgICk7XG5cbiAgICB2YXIgZXg7XG4gICAgLy8gR2VuZXJhdGUgYSBcInN5bnRoZXRpY1wiIHN0YWNrIHRyYWNlIGZyb20gdGhpcyBwb2ludC5cbiAgICAvLyBOT1RFOiBJZiB5b3UgYXJlIGEgU2VudHJ5IHVzZXIsIGFuZCB5b3UgYXJlIHNlZWluZyB0aGlzIHN0YWNrIGZyYW1lLCBpdCBpcyBOT1QgaW5kaWNhdGl2ZVxuICAgIC8vICAgICAgIG9mIGEgYnVnIHdpdGggUmF2ZW4uanMuIFNlbnRyeSBnZW5lcmF0ZXMgc3ludGhldGljIHRyYWNlcyBlaXRoZXIgYnkgY29uZmlndXJhdGlvbixcbiAgICAvLyAgICAgICBvciBpZiBpdCBjYXRjaGVzIGEgdGhyb3duIG9iamVjdCB3aXRob3V0IGEgXCJzdGFja1wiIHByb3BlcnR5LlxuICAgIHRyeSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IobXNnKTtcbiAgICB9IGNhdGNoIChleDEpIHtcbiAgICAgIGV4ID0gZXgxO1xuICAgIH1cblxuICAgIC8vIG51bGwgZXhjZXB0aW9uIG5hbWUgc28gYEVycm9yYCBpc24ndCBwcmVmaXhlZCB0byBtc2dcbiAgICBleC5uYW1lID0gbnVsbDtcbiAgICB2YXIgc3RhY2sgPSBUcmFjZUtpdC5jb21wdXRlU3RhY2tUcmFjZShleCk7XG5cbiAgICAvLyBzdGFja1swXSBpcyBgdGhyb3cgbmV3IEVycm9yKG1zZylgIGNhbGwgaXRzZWxmLCB3ZSBhcmUgaW50ZXJlc3RlZCBpbiB0aGUgZnJhbWUgdGhhdCB3YXMganVzdCBiZWZvcmUgdGhhdCwgc3RhY2tbMV1cbiAgICB2YXIgaW5pdGlhbENhbGwgPSBpc0FycmF5KHN0YWNrLnN0YWNrKSAmJiBzdGFjay5zdGFja1sxXTtcblxuICAgIC8vIGlmIHN0YWNrWzFdIGlzIGBSYXZlbi5jYXB0dXJlRXhjZXB0aW9uYCwgaXQgbWVhbnMgdGhhdCBzb21lb25lIHBhc3NlZCBhIHN0cmluZyB0byBpdCBhbmQgd2UgcmVkaXJlY3RlZCB0aGF0IGNhbGxcbiAgICAvLyB0byBiZSBoYW5kbGVkIGJ5IGBjYXB0dXJlTWVzc2FnZWAsIHRodXMgYGluaXRpYWxDYWxsYCBpcyB0aGUgM3JkIG9uZSwgbm90IDJuZFxuICAgIC8vIGluaXRpYWxDYWxsID0+IGNhcHR1cmVFeGNlcHRpb24oc3RyaW5nKSA9PiBjYXB0dXJlTWVzc2FnZShzdHJpbmcpXG4gICAgaWYgKGluaXRpYWxDYWxsICYmIGluaXRpYWxDYWxsLmZ1bmMgPT09ICdSYXZlbi5jYXB0dXJlRXhjZXB0aW9uJykge1xuICAgICAgaW5pdGlhbENhbGwgPSBzdGFjay5zdGFja1syXTtcbiAgICB9XG5cbiAgICB2YXIgZmlsZXVybCA9IChpbml0aWFsQ2FsbCAmJiBpbml0aWFsQ2FsbC51cmwpIHx8ICcnO1xuXG4gICAgaWYgKFxuICAgICAgISF0aGlzLl9nbG9iYWxPcHRpb25zLmlnbm9yZVVybHMudGVzdCAmJlxuICAgICAgdGhpcy5fZ2xvYmFsT3B0aW9ucy5pZ25vcmVVcmxzLnRlc3QoZmlsZXVybClcbiAgICApIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBpZiAoXG4gICAgICAhIXRoaXMuX2dsb2JhbE9wdGlvbnMud2hpdGVsaXN0VXJscy50ZXN0ICYmXG4gICAgICAhdGhpcy5fZ2xvYmFsT3B0aW9ucy53aGl0ZWxpc3RVcmxzLnRlc3QoZmlsZXVybClcbiAgICApIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyBBbHdheXMgYXR0ZW1wdCB0byBnZXQgc3RhY2t0cmFjZSBpZiBtZXNzYWdlIGlzIGVtcHR5LlxuICAgIC8vIEl0J3MgdGhlIG9ubHkgd2F5IHRvIHByb3ZpZGUgYW55IGhlbHBmdWwgaW5mb3JtYXRpb24gdG8gdGhlIHVzZXIuXG4gICAgaWYgKHRoaXMuX2dsb2JhbE9wdGlvbnMuc3RhY2t0cmFjZSB8fCBvcHRpb25zLnN0YWNrdHJhY2UgfHwgZGF0YS5tZXNzYWdlID09PSAnJykge1xuICAgICAgLy8gZmluZ2VycHJpbnQgb24gbXNnLCBub3Qgc3RhY2sgdHJhY2UgKGxlZ2FjeSBiZWhhdmlvciwgY291bGQgYmUgcmV2aXNpdGVkKVxuICAgICAgZGF0YS5maW5nZXJwcmludCA9IGRhdGEuZmluZ2VycHJpbnQgPT0gbnVsbCA/IG1zZyA6IGRhdGEuZmluZ2VycHJpbnQ7XG5cbiAgICAgIG9wdGlvbnMgPSBvYmplY3RNZXJnZShcbiAgICAgICAge1xuICAgICAgICAgIHRyaW1IZWFkRnJhbWVzOiAwXG4gICAgICAgIH0sXG4gICAgICAgIG9wdGlvbnNcbiAgICAgICk7XG4gICAgICAvLyBTaW5jZSB3ZSBrbm93IHRoaXMgaXMgYSBzeW50aGV0aWMgdHJhY2UsIHRoZSB0b3AgZnJhbWUgKHRoaXMgZnVuY3Rpb24gY2FsbClcbiAgICAgIC8vIE1VU1QgYmUgZnJvbSBSYXZlbi5qcywgc28gbWFyayBpdCBmb3IgdHJpbW1pbmdcbiAgICAgIC8vIFdlIGFkZCB0byB0aGUgdHJpbSBjb3VudGVyIHNvIHRoYXQgY2FsbGVycyBjYW4gY2hvb3NlIHRvIHRyaW0gZXh0cmEgZnJhbWVzLCBzdWNoXG4gICAgICAvLyBhcyB1dGlsaXR5IGZ1bmN0aW9ucy5cbiAgICAgIG9wdGlvbnMudHJpbUhlYWRGcmFtZXMgKz0gMTtcblxuICAgICAgdmFyIGZyYW1lcyA9IHRoaXMuX3ByZXBhcmVGcmFtZXMoc3RhY2ssIG9wdGlvbnMpO1xuICAgICAgZGF0YS5zdGFja3RyYWNlID0ge1xuICAgICAgICAvLyBTZW50cnkgZXhwZWN0cyBmcmFtZXMgb2xkZXN0IHRvIG5ld2VzdFxuICAgICAgICBmcmFtZXM6IGZyYW1lcy5yZXZlcnNlKClcbiAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gTWFrZSBzdXJlIHRoYXQgZmluZ2VycHJpbnQgaXMgYWx3YXlzIHdyYXBwZWQgaW4gYW4gYXJyYXlcbiAgICBpZiAoZGF0YS5maW5nZXJwcmludCkge1xuICAgICAgZGF0YS5maW5nZXJwcmludCA9IGlzQXJyYXkoZGF0YS5maW5nZXJwcmludClcbiAgICAgICAgPyBkYXRhLmZpbmdlcnByaW50XG4gICAgICAgIDogW2RhdGEuZmluZ2VycHJpbnRdO1xuICAgIH1cblxuICAgIC8vIEZpcmUgYXdheSFcbiAgICB0aGlzLl9zZW5kKGRhdGEpO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgY2FwdHVyZUJyZWFkY3J1bWI6IGZ1bmN0aW9uKG9iaikge1xuICAgIHZhciBjcnVtYiA9IG9iamVjdE1lcmdlKFxuICAgICAge1xuICAgICAgICB0aW1lc3RhbXA6IG5vdygpIC8gMTAwMFxuICAgICAgfSxcbiAgICAgIG9ialxuICAgICk7XG5cbiAgICBpZiAoaXNGdW5jdGlvbih0aGlzLl9nbG9iYWxPcHRpb25zLmJyZWFkY3J1bWJDYWxsYmFjaykpIHtcbiAgICAgIHZhciByZXN1bHQgPSB0aGlzLl9nbG9iYWxPcHRpb25zLmJyZWFkY3J1bWJDYWxsYmFjayhjcnVtYik7XG5cbiAgICAgIGlmIChpc09iamVjdChyZXN1bHQpICYmICFpc0VtcHR5T2JqZWN0KHJlc3VsdCkpIHtcbiAgICAgICAgY3J1bWIgPSByZXN1bHQ7XG4gICAgICB9IGVsc2UgaWYgKHJlc3VsdCA9PT0gZmFsc2UpIHtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdGhpcy5fYnJlYWRjcnVtYnMucHVzaChjcnVtYik7XG4gICAgaWYgKHRoaXMuX2JyZWFkY3J1bWJzLmxlbmd0aCA+IHRoaXMuX2dsb2JhbE9wdGlvbnMubWF4QnJlYWRjcnVtYnMpIHtcbiAgICAgIHRoaXMuX2JyZWFkY3J1bWJzLnNoaWZ0KCk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzO1xuICB9LFxuXG4gIGFkZFBsdWdpbjogZnVuY3Rpb24ocGx1Z2luIC8qYXJnMSwgYXJnMiwgLi4uIGFyZ04qLykge1xuICAgIHZhciBwbHVnaW5BcmdzID0gW10uc2xpY2UuY2FsbChhcmd1bWVudHMsIDEpO1xuXG4gICAgdGhpcy5fcGx1Z2lucy5wdXNoKFtwbHVnaW4sIHBsdWdpbkFyZ3NdKTtcbiAgICBpZiAodGhpcy5faXNSYXZlbkluc3RhbGxlZCkge1xuICAgICAgdGhpcy5fZHJhaW5QbHVnaW5zKCk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBTZXQvY2xlYXIgYSB1c2VyIHRvIGJlIHNlbnQgYWxvbmcgd2l0aCB0aGUgcGF5bG9hZC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7b2JqZWN0fSB1c2VyIEFuIG9iamVjdCByZXByZXNlbnRpbmcgdXNlciBkYXRhIFtvcHRpb25hbF1cbiAgICAgKiBAcmV0dXJuIHtSYXZlbn1cbiAgICAgKi9cbiAgc2V0VXNlckNvbnRleHQ6IGZ1bmN0aW9uKHVzZXIpIHtcbiAgICAvLyBJbnRlbnRpb25hbGx5IGRvIG5vdCBtZXJnZSBoZXJlIHNpbmNlIHRoYXQncyBhbiB1bmV4cGVjdGVkIGJlaGF2aW9yLlxuICAgIHRoaXMuX2dsb2JhbENvbnRleHQudXNlciA9IHVzZXI7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfSxcblxuICAvKlxuICAgICAqIE1lcmdlIGV4dHJhIGF0dHJpYnV0ZXMgdG8gYmUgc2VudCBhbG9uZyB3aXRoIHRoZSBwYXlsb2FkLlxuICAgICAqXG4gICAgICogQHBhcmFtIHtvYmplY3R9IGV4dHJhIEFuIG9iamVjdCByZXByZXNlbnRpbmcgZXh0cmEgZGF0YSBbb3B0aW9uYWxdXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIHNldEV4dHJhQ29udGV4dDogZnVuY3Rpb24oZXh0cmEpIHtcbiAgICB0aGlzLl9tZXJnZUNvbnRleHQoJ2V4dHJhJywgZXh0cmEpO1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBNZXJnZSB0YWdzIHRvIGJlIHNlbnQgYWxvbmcgd2l0aCB0aGUgcGF5bG9hZC5cbiAgICAgKlxuICAgICAqIEBwYXJhbSB7b2JqZWN0fSB0YWdzIEFuIG9iamVjdCByZXByZXNlbnRpbmcgdGFncyBbb3B0aW9uYWxdXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIHNldFRhZ3NDb250ZXh0OiBmdW5jdGlvbih0YWdzKSB7XG4gICAgdGhpcy5fbWVyZ2VDb250ZXh0KCd0YWdzJywgdGFncyk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfSxcblxuICAvKlxuICAgICAqIENsZWFyIGFsbCBvZiB0aGUgY29udGV4dC5cbiAgICAgKlxuICAgICAqIEByZXR1cm4ge1JhdmVufVxuICAgICAqL1xuICBjbGVhckNvbnRleHQ6IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMuX2dsb2JhbENvbnRleHQgPSB7fTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9LFxuXG4gIC8qXG4gICAgICogR2V0IGEgY29weSBvZiB0aGUgY3VycmVudCBjb250ZXh0LiBUaGlzIGNhbm5vdCBiZSBtdXRhdGVkLlxuICAgICAqXG4gICAgICogQHJldHVybiB7b2JqZWN0fSBjb3B5IG9mIGNvbnRleHRcbiAgICAgKi9cbiAgZ2V0Q29udGV4dDogZnVuY3Rpb24oKSB7XG4gICAgLy8gbG9sIGphdmFzY3JpcHRcbiAgICByZXR1cm4gSlNPTi5wYXJzZShzdHJpbmdpZnkodGhpcy5fZ2xvYmFsQ29udGV4dCkpO1xuICB9LFxuXG4gIC8qXG4gICAgICogU2V0IGVudmlyb25tZW50IG9mIGFwcGxpY2F0aW9uXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge3N0cmluZ30gZW52aXJvbm1lbnQgVHlwaWNhbGx5IHNvbWV0aGluZyBsaWtlICdwcm9kdWN0aW9uJy5cbiAgICAgKiBAcmV0dXJuIHtSYXZlbn1cbiAgICAgKi9cbiAgc2V0RW52aXJvbm1lbnQ6IGZ1bmN0aW9uKGVudmlyb25tZW50KSB7XG4gICAgdGhpcy5fZ2xvYmFsT3B0aW9ucy5lbnZpcm9ubWVudCA9IGVudmlyb25tZW50O1xuXG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBTZXQgcmVsZWFzZSB2ZXJzaW9uIG9mIGFwcGxpY2F0aW9uXG4gICAgICpcbiAgICAgKiBAcGFyYW0ge3N0cmluZ30gcmVsZWFzZSBUeXBpY2FsbHkgc29tZXRoaW5nIGxpa2UgYSBnaXQgU0hBIHRvIGlkZW50aWZ5IHZlcnNpb25cbiAgICAgKiBAcmV0dXJuIHtSYXZlbn1cbiAgICAgKi9cbiAgc2V0UmVsZWFzZTogZnVuY3Rpb24ocmVsZWFzZSkge1xuICAgIHRoaXMuX2dsb2JhbE9wdGlvbnMucmVsZWFzZSA9IHJlbGVhc2U7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfSxcblxuICAvKlxuICAgICAqIFNldCB0aGUgZGF0YUNhbGxiYWNrIG9wdGlvblxuICAgICAqXG4gICAgICogQHBhcmFtIHtmdW5jdGlvbn0gY2FsbGJhY2sgVGhlIGNhbGxiYWNrIHRvIHJ1biB3aGljaCBhbGxvd3MgdGhlXG4gICAgICogICAgICAgICAgICAgICAgICAgICAgICAgICAgZGF0YSBibG9iIHRvIGJlIG11dGF0ZWQgYmVmb3JlIHNlbmRpbmdcbiAgICAgKiBAcmV0dXJuIHtSYXZlbn1cbiAgICAgKi9cbiAgc2V0RGF0YUNhbGxiYWNrOiBmdW5jdGlvbihjYWxsYmFjaykge1xuICAgIHZhciBvcmlnaW5hbCA9IHRoaXMuX2dsb2JhbE9wdGlvbnMuZGF0YUNhbGxiYWNrO1xuICAgIHRoaXMuX2dsb2JhbE9wdGlvbnMuZGF0YUNhbGxiYWNrID0ga2VlcE9yaWdpbmFsQ2FsbGJhY2sob3JpZ2luYWwsIGNhbGxiYWNrKTtcbiAgICByZXR1cm4gdGhpcztcbiAgfSxcblxuICAvKlxuICAgICAqIFNldCB0aGUgYnJlYWRjcnVtYkNhbGxiYWNrIG9wdGlvblxuICAgICAqXG4gICAgICogQHBhcmFtIHtmdW5jdGlvbn0gY2FsbGJhY2sgVGhlIGNhbGxiYWNrIHRvIHJ1biB3aGljaCBhbGxvd3MgZmlsdGVyaW5nXG4gICAgICogICAgICAgICAgICAgICAgICAgICAgICAgICAgb3IgbXV0YXRpbmcgYnJlYWRjcnVtYnNcbiAgICAgKiBAcmV0dXJuIHtSYXZlbn1cbiAgICAgKi9cbiAgc2V0QnJlYWRjcnVtYkNhbGxiYWNrOiBmdW5jdGlvbihjYWxsYmFjaykge1xuICAgIHZhciBvcmlnaW5hbCA9IHRoaXMuX2dsb2JhbE9wdGlvbnMuYnJlYWRjcnVtYkNhbGxiYWNrO1xuICAgIHRoaXMuX2dsb2JhbE9wdGlvbnMuYnJlYWRjcnVtYkNhbGxiYWNrID0ga2VlcE9yaWdpbmFsQ2FsbGJhY2sob3JpZ2luYWwsIGNhbGxiYWNrKTtcbiAgICByZXR1cm4gdGhpcztcbiAgfSxcblxuICAvKlxuICAgICAqIFNldCB0aGUgc2hvdWxkU2VuZENhbGxiYWNrIG9wdGlvblxuICAgICAqXG4gICAgICogQHBhcmFtIHtmdW5jdGlvbn0gY2FsbGJhY2sgVGhlIGNhbGxiYWNrIHRvIHJ1biB3aGljaCBhbGxvd3NcbiAgICAgKiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbnRyb3NwZWN0aW5nIHRoZSBibG9iIGJlZm9yZSBzZW5kaW5nXG4gICAgICogQHJldHVybiB7UmF2ZW59XG4gICAgICovXG4gIHNldFNob3VsZFNlbmRDYWxsYmFjazogZnVuY3Rpb24oY2FsbGJhY2spIHtcbiAgICB2YXIgb3JpZ2luYWwgPSB0aGlzLl9nbG9iYWxPcHRpb25zLnNob3VsZFNlbmRDYWxsYmFjaztcbiAgICB0aGlzLl9nbG9iYWxPcHRpb25zLnNob3VsZFNlbmRDYWxsYmFjayA9IGtlZXBPcmlnaW5hbENhbGxiYWNrKG9yaWdpbmFsLCBjYWxsYmFjayk7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH0sXG5cbiAgLyoqXG4gICAqIE92ZXJyaWRlIHRoZSBkZWZhdWx0IEhUVFAgdHJhbnNwb3J0IG1lY2hhbmlzbSB0aGF0IHRyYW5zbWl0cyBkYXRhXG4gICAqIHRvIHRoZSBTZW50cnkgc2VydmVyLlxuICAgKlxuICAgKiBAcGFyYW0ge2Z1bmN0aW9ufSB0cmFuc3BvcnQgRnVuY3Rpb24gaW52b2tlZCBpbnN0ZWFkIG9mIHRoZSBkZWZhdWx0XG4gICAqICAgICAgICAgICAgICAgICAgICAgICAgICAgICBgbWFrZVJlcXVlc3RgIGhhbmRsZXIuXG4gICAqXG4gICAqIEByZXR1cm4ge1JhdmVufVxuICAgKi9cbiAgc2V0VHJhbnNwb3J0OiBmdW5jdGlvbih0cmFuc3BvcnQpIHtcbiAgICB0aGlzLl9nbG9iYWxPcHRpb25zLnRyYW5zcG9ydCA9IHRyYW5zcG9ydDtcblxuICAgIHJldHVybiB0aGlzO1xuICB9LFxuXG4gIC8qXG4gICAgICogR2V0IHRoZSBsYXRlc3QgcmF3IGV4Y2VwdGlvbiB0aGF0IHdhcyBjYXB0dXJlZCBieSBSYXZlbi5cbiAgICAgKlxuICAgICAqIEByZXR1cm4ge2Vycm9yfVxuICAgICAqL1xuICBsYXN0RXhjZXB0aW9uOiBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5fbGFzdENhcHR1cmVkRXhjZXB0aW9uO1xuICB9LFxuXG4gIC8qXG4gICAgICogR2V0IHRoZSBsYXN0IGV2ZW50IGlkXG4gICAgICpcbiAgICAgKiBAcmV0dXJuIHtzdHJpbmd9XG4gICAgICovXG4gIGxhc3RFdmVudElkOiBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5fbGFzdEV2ZW50SWQ7XG4gIH0sXG5cbiAgLypcbiAgICAgKiBEZXRlcm1pbmUgaWYgUmF2ZW4gaXMgc2V0dXAgYW5kIHJlYWR5IHRvIGdvLlxuICAgICAqXG4gICAgICogQHJldHVybiB7Ym9vbGVhbn1cbiAgICAgKi9cbiAgaXNTZXR1cDogZnVuY3Rpb24oKSB7XG4gICAgaWYgKCF0aGlzLl9oYXNKU09OKSByZXR1cm4gZmFsc2U7IC8vIG5lZWRzIEpTT04gc3VwcG9ydFxuICAgIGlmICghdGhpcy5fZ2xvYmFsU2VydmVyKSB7XG4gICAgICBpZiAoIXRoaXMucmF2ZW5Ob3RDb25maWd1cmVkRXJyb3IpIHtcbiAgICAgICAgdGhpcy5yYXZlbk5vdENvbmZpZ3VyZWRFcnJvciA9IHRydWU7XG4gICAgICAgIHRoaXMuX2xvZ0RlYnVnKCdlcnJvcicsICdFcnJvcjogUmF2ZW4gaGFzIG5vdCBiZWVuIGNvbmZpZ3VyZWQuJyk7XG4gICAgICB9XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIHJldHVybiB0cnVlO1xuICB9LFxuXG4gIGFmdGVyTG9hZDogZnVuY3Rpb24oKSB7XG4gICAgLy8gVE9ETzogcmVtb3ZlIHdpbmRvdyBkZXBlbmRlbmNlP1xuXG4gICAgLy8gQXR0ZW1wdCB0byBpbml0aWFsaXplIFJhdmVuIG9uIGxvYWRcbiAgICB2YXIgUmF2ZW5Db25maWcgPSBfd2luZG93LlJhdmVuQ29uZmlnO1xuICAgIGlmIChSYXZlbkNvbmZpZykge1xuICAgICAgdGhpcy5jb25maWcoUmF2ZW5Db25maWcuZHNuLCBSYXZlbkNvbmZpZy5jb25maWcpLmluc3RhbGwoKTtcbiAgICB9XG4gIH0sXG5cbiAgc2hvd1JlcG9ydERpYWxvZzogZnVuY3Rpb24ob3B0aW9ucykge1xuICAgIGlmIChcbiAgICAgICFfZG9jdW1lbnQgLy8gZG9lc24ndCB3b3JrIHdpdGhvdXQgYSBkb2N1bWVudCAoUmVhY3QgbmF0aXZlKVxuICAgIClcbiAgICAgIHJldHVybjtcblxuICAgIG9wdGlvbnMgPSBvYmplY3RNZXJnZShcbiAgICAgIHtcbiAgICAgICAgZXZlbnRJZDogdGhpcy5sYXN0RXZlbnRJZCgpLFxuICAgICAgICBkc246IHRoaXMuX2RzbixcbiAgICAgICAgdXNlcjogdGhpcy5fZ2xvYmFsQ29udGV4dC51c2VyIHx8IHt9XG4gICAgICB9LFxuICAgICAgb3B0aW9uc1xuICAgICk7XG5cbiAgICBpZiAoIW9wdGlvbnMuZXZlbnRJZCkge1xuICAgICAgdGhyb3cgbmV3IFJhdmVuQ29uZmlnRXJyb3IoJ01pc3NpbmcgZXZlbnRJZCcpO1xuICAgIH1cblxuICAgIGlmICghb3B0aW9ucy5kc24pIHtcbiAgICAgIHRocm93IG5ldyBSYXZlbkNvbmZpZ0Vycm9yKCdNaXNzaW5nIERTTicpO1xuICAgIH1cblxuICAgIHZhciBlbmNvZGUgPSBlbmNvZGVVUklDb21wb25lbnQ7XG4gICAgdmFyIGVuY29kZWRPcHRpb25zID0gW107XG5cbiAgICBmb3IgKHZhciBrZXkgaW4gb3B0aW9ucykge1xuICAgICAgaWYgKGtleSA9PT0gJ3VzZXInKSB7XG4gICAgICAgIHZhciB1c2VyID0gb3B0aW9ucy51c2VyO1xuICAgICAgICBpZiAodXNlci5uYW1lKSBlbmNvZGVkT3B0aW9ucy5wdXNoKCduYW1lPScgKyBlbmNvZGUodXNlci5uYW1lKSk7XG4gICAgICAgIGlmICh1c2VyLmVtYWlsKSBlbmNvZGVkT3B0aW9ucy5wdXNoKCdlbWFpbD0nICsgZW5jb2RlKHVzZXIuZW1haWwpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGVuY29kZWRPcHRpb25zLnB1c2goZW5jb2RlKGtleSkgKyAnPScgKyBlbmNvZGUob3B0aW9uc1trZXldKSk7XG4gICAgICB9XG4gICAgfVxuICAgIHZhciBnbG9iYWxTZXJ2ZXIgPSB0aGlzLl9nZXRHbG9iYWxTZXJ2ZXIodGhpcy5fcGFyc2VEU04ob3B0aW9ucy5kc24pKTtcblxuICAgIHZhciBzY3JpcHQgPSBfZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7XG4gICAgc2NyaXB0LmFzeW5jID0gdHJ1ZTtcbiAgICBzY3JpcHQuc3JjID0gZ2xvYmFsU2VydmVyICsgJy9hcGkvZW1iZWQvZXJyb3ItcGFnZS8/JyArIGVuY29kZWRPcHRpb25zLmpvaW4oJyYnKTtcbiAgICAoX2RvY3VtZW50LmhlYWQgfHwgX2RvY3VtZW50LmJvZHkpLmFwcGVuZENoaWxkKHNjcmlwdCk7XG4gIH0sXG5cbiAgLyoqKiogUHJpdmF0ZSBmdW5jdGlvbnMgKioqKi9cbiAgX2lnbm9yZU5leHRPbkVycm9yOiBmdW5jdGlvbigpIHtcbiAgICB2YXIgc2VsZiA9IHRoaXM7XG4gICAgdGhpcy5faWdub3JlT25FcnJvciArPSAxO1xuICAgIHNldFRpbWVvdXQoZnVuY3Rpb24oKSB7XG4gICAgICAvLyBvbmVycm9yIHNob3VsZCB0cmlnZ2VyIGJlZm9yZSBzZXRUaW1lb3V0XG4gICAgICBzZWxmLl9pZ25vcmVPbkVycm9yIC09IDE7XG4gICAgfSk7XG4gIH0sXG5cbiAgX3RyaWdnZXJFdmVudDogZnVuY3Rpb24oZXZlbnRUeXBlLCBvcHRpb25zKSB7XG4gICAgLy8gTk9URTogYGV2ZW50YCBpcyBhIG5hdGl2ZSBicm93c2VyIHRoaW5nLCBzbyBsZXQncyBhdm9pZCBjb25mbGljdGluZyB3aWh0IGl0XG4gICAgdmFyIGV2dCwga2V5O1xuXG4gICAgaWYgKCF0aGlzLl9oYXNEb2N1bWVudCkgcmV0dXJuO1xuXG4gICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG5cbiAgICBldmVudFR5cGUgPSAncmF2ZW4nICsgZXZlbnRUeXBlLnN1YnN0cigwLCAxKS50b1VwcGVyQ2FzZSgpICsgZXZlbnRUeXBlLnN1YnN0cigxKTtcblxuICAgIGlmIChfZG9jdW1lbnQuY3JlYXRlRXZlbnQpIHtcbiAgICAgIGV2dCA9IF9kb2N1bWVudC5jcmVhdGVFdmVudCgnSFRNTEV2ZW50cycpO1xuICAgICAgZXZ0LmluaXRFdmVudChldmVudFR5cGUsIHRydWUsIHRydWUpO1xuICAgIH0gZWxzZSB7XG4gICAgICBldnQgPSBfZG9jdW1lbnQuY3JlYXRlRXZlbnRPYmplY3QoKTtcbiAgICAgIGV2dC5ldmVudFR5cGUgPSBldmVudFR5cGU7XG4gICAgfVxuXG4gICAgZm9yIChrZXkgaW4gb3B0aW9ucylcbiAgICAgIGlmIChoYXNLZXkob3B0aW9ucywga2V5KSkge1xuICAgICAgICBldnRba2V5XSA9IG9wdGlvbnNba2V5XTtcbiAgICAgIH1cblxuICAgIGlmIChfZG9jdW1lbnQuY3JlYXRlRXZlbnQpIHtcbiAgICAgIC8vIElFOSBpZiBzdGFuZGFyZHNcbiAgICAgIF9kb2N1bWVudC5kaXNwYXRjaEV2ZW50KGV2dCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIElFOCByZWdhcmRsZXNzIG9mIFF1aXJrcyBvciBTdGFuZGFyZHNcbiAgICAgIC8vIElFOSBpZiBxdWlya3NcbiAgICAgIHRyeSB7XG4gICAgICAgIF9kb2N1bWVudC5maXJlRXZlbnQoJ29uJyArIGV2dC5ldmVudFR5cGUudG9Mb3dlckNhc2UoKSwgZXZ0KTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgLy8gRG8gbm90aGluZ1xuICAgICAgfVxuICAgIH1cbiAgfSxcblxuICAvKipcbiAgICogV3JhcHMgYWRkRXZlbnRMaXN0ZW5lciB0byBjYXB0dXJlIFVJIGJyZWFkY3J1bWJzXG4gICAqIEBwYXJhbSBldnROYW1lIHRoZSBldmVudCBuYW1lIChlLmcuIFwiY2xpY2tcIilcbiAgICogQHJldHVybnMge0Z1bmN0aW9ufVxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgX2JyZWFkY3J1bWJFdmVudEhhbmRsZXI6IGZ1bmN0aW9uKGV2dE5hbWUpIHtcbiAgICB2YXIgc2VsZiA9IHRoaXM7XG4gICAgcmV0dXJuIGZ1bmN0aW9uKGV2dCkge1xuICAgICAgLy8gcmVzZXQga2V5cHJlc3MgdGltZW91dDsgZS5nLiB0cmlnZ2VyaW5nIGEgJ2NsaWNrJyBhZnRlclxuICAgICAgLy8gYSAna2V5cHJlc3MnIHdpbGwgcmVzZXQgdGhlIGtleXByZXNzIGRlYm91bmNlIHNvIHRoYXQgYSBuZXdcbiAgICAgIC8vIHNldCBvZiBrZXlwcmVzc2VzIGNhbiBiZSByZWNvcmRlZFxuICAgICAgc2VsZi5fa2V5cHJlc3NUaW1lb3V0ID0gbnVsbDtcblxuICAgICAgLy8gSXQncyBwb3NzaWJsZSB0aGlzIGhhbmRsZXIgbWlnaHQgdHJpZ2dlciBtdWx0aXBsZSB0aW1lcyBmb3IgdGhlIHNhbWVcbiAgICAgIC8vIGV2ZW50IChlLmcuIGV2ZW50IHByb3BhZ2F0aW9uIHRocm91Z2ggbm9kZSBhbmNlc3RvcnMpLiBJZ25vcmUgaWYgd2UndmVcbiAgICAgIC8vIGFscmVhZHkgY2FwdHVyZWQgdGhlIGV2ZW50LlxuICAgICAgaWYgKHNlbGYuX2xhc3RDYXB0dXJlZEV2ZW50ID09PSBldnQpIHJldHVybjtcblxuICAgICAgc2VsZi5fbGFzdENhcHR1cmVkRXZlbnQgPSBldnQ7XG5cbiAgICAgIC8vIHRyeS9jYXRjaCBib3RoOlxuICAgICAgLy8gLSBhY2Nlc3NpbmcgZXZ0LnRhcmdldCAoc2VlIGdldHNlbnRyeS9yYXZlbi1qcyM4MzgsICM3NjgpXG4gICAgICAvLyAtIGBodG1sVHJlZUFzU3RyaW5nYCBiZWNhdXNlIGl0J3MgY29tcGxleCwgYW5kIGp1c3QgYWNjZXNzaW5nIHRoZSBET00gaW5jb3JyZWN0bHlcbiAgICAgIC8vICAgY2FuIHRocm93IGFuIGV4Y2VwdGlvbiBpbiBzb21lIGNpcmN1bXN0YW5jZXMuXG4gICAgICB2YXIgdGFyZ2V0O1xuICAgICAgdHJ5IHtcbiAgICAgICAgdGFyZ2V0ID0gaHRtbFRyZWVBc1N0cmluZyhldnQudGFyZ2V0KTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgdGFyZ2V0ID0gJzx1bmtub3duPic7XG4gICAgICB9XG5cbiAgICAgIHNlbGYuY2FwdHVyZUJyZWFkY3J1bWIoe1xuICAgICAgICBjYXRlZ29yeTogJ3VpLicgKyBldnROYW1lLCAvLyBlLmcuIHVpLmNsaWNrLCB1aS5pbnB1dFxuICAgICAgICBtZXNzYWdlOiB0YXJnZXRcbiAgICAgIH0pO1xuICAgIH07XG4gIH0sXG5cbiAgLyoqXG4gICAqIFdyYXBzIGFkZEV2ZW50TGlzdGVuZXIgdG8gY2FwdHVyZSBrZXlwcmVzcyBVSSBldmVudHNcbiAgICogQHJldHVybnMge0Z1bmN0aW9ufVxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgX2tleXByZXNzRXZlbnRIYW5kbGVyOiBmdW5jdGlvbigpIHtcbiAgICB2YXIgc2VsZiA9IHRoaXMsXG4gICAgICBkZWJvdW5jZUR1cmF0aW9uID0gMTAwMDsgLy8gbWlsbGlzZWNvbmRzXG5cbiAgICAvLyBUT0RPOiBpZiBzb21laG93IHVzZXIgc3dpdGNoZXMga2V5cHJlc3MgdGFyZ2V0IGJlZm9yZVxuICAgIC8vICAgICAgIGRlYm91bmNlIHRpbWVvdXQgaXMgdHJpZ2dlcmVkLCB3ZSB3aWxsIG9ubHkgY2FwdHVyZVxuICAgIC8vICAgICAgIGEgc2luZ2xlIGJyZWFkY3J1bWIgZnJvbSB0aGUgRklSU1QgdGFyZ2V0IChhY2NlcHRhYmxlPylcbiAgICByZXR1cm4gZnVuY3Rpb24oZXZ0KSB7XG4gICAgICB2YXIgdGFyZ2V0O1xuICAgICAgdHJ5IHtcbiAgICAgICAgdGFyZ2V0ID0gZXZ0LnRhcmdldDtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgLy8ganVzdCBhY2Nlc3NpbmcgZXZlbnQgcHJvcGVydGllcyBjYW4gdGhyb3cgYW4gZXhjZXB0aW9uIGluIHNvbWUgcmFyZSBjaXJjdW1zdGFuY2VzXG4gICAgICAgIC8vIHNlZTogaHR0cHM6Ly9naXRodWIuY29tL2dldHNlbnRyeS9yYXZlbi1qcy9pc3N1ZXMvODM4XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIHZhciB0YWdOYW1lID0gdGFyZ2V0ICYmIHRhcmdldC50YWdOYW1lO1xuXG4gICAgICAvLyBvbmx5IGNvbnNpZGVyIGtleXByZXNzIGV2ZW50cyBvbiBhY3R1YWwgaW5wdXQgZWxlbWVudHNcbiAgICAgIC8vIHRoaXMgd2lsbCBkaXNyZWdhcmQga2V5cHJlc3NlcyB0YXJnZXRpbmcgYm9keSAoZS5nLiB0YWJiaW5nXG4gICAgICAvLyB0aHJvdWdoIGVsZW1lbnRzLCBob3RrZXlzLCBldGMpXG4gICAgICBpZiAoXG4gICAgICAgICF0YWdOYW1lIHx8XG4gICAgICAgICh0YWdOYW1lICE9PSAnSU5QVVQnICYmIHRhZ05hbWUgIT09ICdURVhUQVJFQScgJiYgIXRhcmdldC5pc0NvbnRlbnRFZGl0YWJsZSlcbiAgICAgIClcbiAgICAgICAgcmV0dXJuO1xuXG4gICAgICAvLyByZWNvcmQgZmlyc3Qga2V5cHJlc3MgaW4gYSBzZXJpZXMsIGJ1dCBpZ25vcmUgc3Vic2VxdWVudFxuICAgICAgLy8ga2V5cHJlc3NlcyB1bnRpbCBkZWJvdW5jZSBjbGVhcnNcbiAgICAgIHZhciB0aW1lb3V0ID0gc2VsZi5fa2V5cHJlc3NUaW1lb3V0O1xuICAgICAgaWYgKCF0aW1lb3V0KSB7XG4gICAgICAgIHNlbGYuX2JyZWFkY3J1bWJFdmVudEhhbmRsZXIoJ2lucHV0JykoZXZ0KTtcbiAgICAgIH1cbiAgICAgIGNsZWFyVGltZW91dCh0aW1lb3V0KTtcbiAgICAgIHNlbGYuX2tleXByZXNzVGltZW91dCA9IHNldFRpbWVvdXQoZnVuY3Rpb24oKSB7XG4gICAgICAgIHNlbGYuX2tleXByZXNzVGltZW91dCA9IG51bGw7XG4gICAgICB9LCBkZWJvdW5jZUR1cmF0aW9uKTtcbiAgICB9O1xuICB9LFxuXG4gIC8qKlxuICAgKiBDYXB0dXJlcyBhIGJyZWFkY3J1bWIgb2YgdHlwZSBcIm5hdmlnYXRpb25cIiwgbm9ybWFsaXppbmcgaW5wdXQgVVJMc1xuICAgKiBAcGFyYW0gdG8gdGhlIG9yaWdpbmF0aW5nIFVSTFxuICAgKiBAcGFyYW0gZnJvbSB0aGUgdGFyZ2V0IFVSTFxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgX2NhcHR1cmVVcmxDaGFuZ2U6IGZ1bmN0aW9uKGZyb20sIHRvKSB7XG4gICAgdmFyIHBhcnNlZExvYyA9IHBhcnNlVXJsKHRoaXMuX2xvY2F0aW9uLmhyZWYpO1xuICAgIHZhciBwYXJzZWRUbyA9IHBhcnNlVXJsKHRvKTtcbiAgICB2YXIgcGFyc2VkRnJvbSA9IHBhcnNlVXJsKGZyb20pO1xuXG4gICAgLy8gYmVjYXVzZSBvbnBvcHN0YXRlIG9ubHkgdGVsbHMgeW91IHRoZSBcIm5ld1wiICh0bykgdmFsdWUgb2YgbG9jYXRpb24uaHJlZiwgYW5kXG4gICAgLy8gbm90IHRoZSBwcmV2aW91cyAoZnJvbSkgdmFsdWUsIHdlIG5lZWQgdG8gdHJhY2sgdGhlIHZhbHVlIG9mIHRoZSBjdXJyZW50IFVSTFxuICAgIC8vIHN0YXRlIG91cnNlbHZlc1xuICAgIHRoaXMuX2xhc3RIcmVmID0gdG87XG5cbiAgICAvLyBVc2Ugb25seSB0aGUgcGF0aCBjb21wb25lbnQgb2YgdGhlIFVSTCBpZiB0aGUgVVJMIG1hdGNoZXMgdGhlIGN1cnJlbnRcbiAgICAvLyBkb2N1bWVudCAoYWxtb3N0IGFsbCB0aGUgdGltZSB3aGVuIHVzaW5nIHB1c2hTdGF0ZSlcbiAgICBpZiAocGFyc2VkTG9jLnByb3RvY29sID09PSBwYXJzZWRUby5wcm90b2NvbCAmJiBwYXJzZWRMb2MuaG9zdCA9PT0gcGFyc2VkVG8uaG9zdClcbiAgICAgIHRvID0gcGFyc2VkVG8ucmVsYXRpdmU7XG4gICAgaWYgKHBhcnNlZExvYy5wcm90b2NvbCA9PT0gcGFyc2VkRnJvbS5wcm90b2NvbCAmJiBwYXJzZWRMb2MuaG9zdCA9PT0gcGFyc2VkRnJvbS5ob3N0KVxuICAgICAgZnJvbSA9IHBhcnNlZEZyb20ucmVsYXRpdmU7XG5cbiAgICB0aGlzLmNhcHR1cmVCcmVhZGNydW1iKHtcbiAgICAgIGNhdGVnb3J5OiAnbmF2aWdhdGlvbicsXG4gICAgICBkYXRhOiB7XG4gICAgICAgIHRvOiB0byxcbiAgICAgICAgZnJvbTogZnJvbVxuICAgICAgfVxuICAgIH0pO1xuICB9LFxuXG4gIF9wYXRjaEZ1bmN0aW9uVG9TdHJpbmc6IGZ1bmN0aW9uKCkge1xuICAgIHZhciBzZWxmID0gdGhpcztcbiAgICBzZWxmLl9vcmlnaW5hbEZ1bmN0aW9uVG9TdHJpbmcgPSBGdW5jdGlvbi5wcm90b3R5cGUudG9TdHJpbmc7XG4gICAgLy8gZXNsaW50LWRpc2FibGUtbmV4dC1saW5lIG5vLWV4dGVuZC1uYXRpdmVcbiAgICBGdW5jdGlvbi5wcm90b3R5cGUudG9TdHJpbmcgPSBmdW5jdGlvbigpIHtcbiAgICAgIGlmICh0eXBlb2YgdGhpcyA9PT0gJ2Z1bmN0aW9uJyAmJiB0aGlzLl9fcmF2ZW5fXykge1xuICAgICAgICByZXR1cm4gc2VsZi5fb3JpZ2luYWxGdW5jdGlvblRvU3RyaW5nLmFwcGx5KHRoaXMuX19vcmlnX18sIGFyZ3VtZW50cyk7XG4gICAgICB9XG4gICAgICByZXR1cm4gc2VsZi5fb3JpZ2luYWxGdW5jdGlvblRvU3RyaW5nLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG4gICAgfTtcbiAgfSxcblxuICBfdW5wYXRjaEZ1bmN0aW9uVG9TdHJpbmc6IGZ1bmN0aW9uKCkge1xuICAgIGlmICh0aGlzLl9vcmlnaW5hbEZ1bmN0aW9uVG9TdHJpbmcpIHtcbiAgICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby1leHRlbmQtbmF0aXZlXG4gICAgICBGdW5jdGlvbi5wcm90b3R5cGUudG9TdHJpbmcgPSB0aGlzLl9vcmlnaW5hbEZ1bmN0aW9uVG9TdHJpbmc7XG4gICAgfVxuICB9LFxuXG4gIC8qKlxuICAgKiBXcmFwIHRpbWVyIGZ1bmN0aW9ucyBhbmQgZXZlbnQgdGFyZ2V0cyB0byBjYXRjaCBlcnJvcnMgYW5kIHByb3ZpZGVcbiAgICogYmV0dGVyIG1ldGFkYXRhLlxuICAgKi9cbiAgX2luc3RydW1lbnRUcnlDYXRjaDogZnVuY3Rpb24oKSB7XG4gICAgdmFyIHNlbGYgPSB0aGlzO1xuXG4gICAgdmFyIHdyYXBwZWRCdWlsdElucyA9IHNlbGYuX3dyYXBwZWRCdWlsdElucztcblxuICAgIGZ1bmN0aW9uIHdyYXBUaW1lRm4ob3JpZykge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKGZuLCB0KSB7XG4gICAgICAgIC8vIHByZXNlcnZlIGFyaXR5XG4gICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBhcmd1bWVudHMgdG8gcHJldmVudCBkZW9wdGltaXphdGlvblxuICAgICAgICAvLyBodHRwczovL2dpdGh1Yi5jb20vcGV0a2FhbnRvbm92L2JsdWViaXJkL3dpa2kvT3B0aW1pemF0aW9uLWtpbGxlcnMjMzItbGVha2luZy1hcmd1bWVudHNcbiAgICAgICAgdmFyIGFyZ3MgPSBuZXcgQXJyYXkoYXJndW1lbnRzLmxlbmd0aCk7XG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJncy5sZW5ndGg7ICsraSkge1xuICAgICAgICAgIGFyZ3NbaV0gPSBhcmd1bWVudHNbaV07XG4gICAgICAgIH1cbiAgICAgICAgdmFyIG9yaWdpbmFsQ2FsbGJhY2sgPSBhcmdzWzBdO1xuICAgICAgICBpZiAoaXNGdW5jdGlvbihvcmlnaW5hbENhbGxiYWNrKSkge1xuICAgICAgICAgIGFyZ3NbMF0gPSBzZWxmLndyYXAoXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIG1lY2hhbmlzbToge1xuICAgICAgICAgICAgICAgIHR5cGU6ICdpbnN0cnVtZW50JyxcbiAgICAgICAgICAgICAgICBkYXRhOiB7ZnVuY3Rpb246IG9yaWcubmFtZSB8fCAnPGFub255bW91cz4nfVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgb3JpZ2luYWxDYWxsYmFja1xuICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBJRSA8IDkgZG9lc24ndCBzdXBwb3J0IC5jYWxsLy5hcHBseSBvbiBzZXRJbnRlcnZhbC9zZXRUaW1lb3V0LCBidXQgaXRcbiAgICAgICAgLy8gYWxzbyBzdXBwb3J0cyBvbmx5IHR3byBhcmd1bWVudHMgYW5kIGRvZXNuJ3QgY2FyZSB3aGF0IHRoaXMgaXMsIHNvIHdlXG4gICAgICAgIC8vIGNhbiBqdXN0IGNhbGwgdGhlIG9yaWdpbmFsIGZ1bmN0aW9uIGRpcmVjdGx5LlxuICAgICAgICBpZiAob3JpZy5hcHBseSkge1xuICAgICAgICAgIHJldHVybiBvcmlnLmFwcGx5KHRoaXMsIGFyZ3MpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHJldHVybiBvcmlnKGFyZ3NbMF0sIGFyZ3NbMV0pO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH1cblxuICAgIHZhciBhdXRvQnJlYWRjcnVtYnMgPSB0aGlzLl9nbG9iYWxPcHRpb25zLmF1dG9CcmVhZGNydW1icztcblxuICAgIGZ1bmN0aW9uIHdyYXBFdmVudFRhcmdldChnbG9iYWwpIHtcbiAgICAgIHZhciBwcm90byA9IF93aW5kb3dbZ2xvYmFsXSAmJiBfd2luZG93W2dsb2JhbF0ucHJvdG90eXBlO1xuICAgICAgaWYgKHByb3RvICYmIHByb3RvLmhhc093blByb3BlcnR5ICYmIHByb3RvLmhhc093blByb3BlcnR5KCdhZGRFdmVudExpc3RlbmVyJykpIHtcbiAgICAgICAgZmlsbChcbiAgICAgICAgICBwcm90byxcbiAgICAgICAgICAnYWRkRXZlbnRMaXN0ZW5lcicsXG4gICAgICAgICAgZnVuY3Rpb24ob3JpZykge1xuICAgICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uKGV2dE5hbWUsIGZuLCBjYXB0dXJlLCBzZWN1cmUpIHtcbiAgICAgICAgICAgICAgLy8gcHJlc2VydmUgYXJpdHlcbiAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBpZiAoZm4gJiYgZm4uaGFuZGxlRXZlbnQpIHtcbiAgICAgICAgICAgICAgICAgIGZuLmhhbmRsZUV2ZW50ID0gc2VsZi53cmFwKFxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgbWVjaGFuaXNtOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0eXBlOiAnaW5zdHJ1bWVudCcsXG4gICAgICAgICAgICAgICAgICAgICAgICBkYXRhOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIHRhcmdldDogZ2xvYmFsLFxuICAgICAgICAgICAgICAgICAgICAgICAgICBmdW5jdGlvbjogJ2hhbmRsZUV2ZW50JyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgaGFuZGxlcjogKGZuICYmIGZuLm5hbWUpIHx8ICc8YW5vbnltb3VzPidcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICAgIGZuLmhhbmRsZUV2ZW50XG4gICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgICAgICAgICAgLy8gY2FuIHNvbWV0aW1lcyBnZXQgJ1Blcm1pc3Npb24gZGVuaWVkIHRvIGFjY2VzcyBwcm9wZXJ0eSBcImhhbmRsZSBFdmVudCdcbiAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgIC8vIE1vcmUgYnJlYWRjcnVtYiBET00gY2FwdHVyZSAuLi4gZG9uZSBoZXJlIGFuZCBub3QgaW4gYF9pbnN0cnVtZW50QnJlYWRjcnVtYnNgXG4gICAgICAgICAgICAgIC8vIHNvIHRoYXQgd2UgZG9uJ3QgaGF2ZSBtb3JlIHRoYW4gb25lIHdyYXBwZXIgZnVuY3Rpb25cbiAgICAgICAgICAgICAgdmFyIGJlZm9yZSwgY2xpY2tIYW5kbGVyLCBrZXlwcmVzc0hhbmRsZXI7XG5cbiAgICAgICAgICAgICAgaWYgKFxuICAgICAgICAgICAgICAgIGF1dG9CcmVhZGNydW1icyAmJlxuICAgICAgICAgICAgICAgIGF1dG9CcmVhZGNydW1icy5kb20gJiZcbiAgICAgICAgICAgICAgICAoZ2xvYmFsID09PSAnRXZlbnRUYXJnZXQnIHx8IGdsb2JhbCA9PT0gJ05vZGUnKVxuICAgICAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgICAvLyBOT1RFOiBnZW5lcmF0aW5nIG11bHRpcGxlIGhhbmRsZXJzIHBlciBhZGRFdmVudExpc3RlbmVyIGludm9jYXRpb24sIHNob3VsZFxuICAgICAgICAgICAgICAgIC8vICAgICAgIHJldmlzaXQgYW5kIHZlcmlmeSB3ZSBjYW4ganVzdCB1c2Ugb25lIChhbG1vc3QgY2VydGFpbmx5KVxuICAgICAgICAgICAgICAgIGNsaWNrSGFuZGxlciA9IHNlbGYuX2JyZWFkY3J1bWJFdmVudEhhbmRsZXIoJ2NsaWNrJyk7XG4gICAgICAgICAgICAgICAga2V5cHJlc3NIYW5kbGVyID0gc2VsZi5fa2V5cHJlc3NFdmVudEhhbmRsZXIoKTtcbiAgICAgICAgICAgICAgICBiZWZvcmUgPSBmdW5jdGlvbihldnQpIHtcbiAgICAgICAgICAgICAgICAgIC8vIG5lZWQgdG8gaW50ZXJjZXB0IGV2ZXJ5IERPTSBldmVudCBpbiBgYmVmb3JlYCBhcmd1bWVudCwgaW4gY2FzZSB0aGF0XG4gICAgICAgICAgICAgICAgICAvLyBzYW1lIHdyYXBwZWQgbWV0aG9kIGlzIHJlLXVzZWQgZm9yIGRpZmZlcmVudCBldmVudHMgKGUuZy4gbW91c2Vtb3ZlIFRIRU4gY2xpY2spXG4gICAgICAgICAgICAgICAgICAvLyBzZWUgIzcyNFxuICAgICAgICAgICAgICAgICAgaWYgKCFldnQpIHJldHVybjtcblxuICAgICAgICAgICAgICAgICAgdmFyIGV2ZW50VHlwZTtcbiAgICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICAgIGV2ZW50VHlwZSA9IGV2dC50eXBlO1xuICAgICAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgICAgICAvLyBqdXN0IGFjY2Vzc2luZyBldmVudCBwcm9wZXJ0aWVzIGNhbiB0aHJvdyBhbiBleGNlcHRpb24gaW4gc29tZSByYXJlIGNpcmN1bXN0YW5jZXNcbiAgICAgICAgICAgICAgICAgICAgLy8gc2VlOiBodHRwczovL2dpdGh1Yi5jb20vZ2V0c2VudHJ5L3JhdmVuLWpzL2lzc3Vlcy84MzhcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgaWYgKGV2ZW50VHlwZSA9PT0gJ2NsaWNrJykgcmV0dXJuIGNsaWNrSGFuZGxlcihldnQpO1xuICAgICAgICAgICAgICAgICAgZWxzZSBpZiAoZXZlbnRUeXBlID09PSAna2V5cHJlc3MnKSByZXR1cm4ga2V5cHJlc3NIYW5kbGVyKGV2dCk7XG4gICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICByZXR1cm4gb3JpZy5jYWxsKFxuICAgICAgICAgICAgICAgIHRoaXMsXG4gICAgICAgICAgICAgICAgZXZ0TmFtZSxcbiAgICAgICAgICAgICAgICBzZWxmLndyYXAoXG4gICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgIG1lY2hhbmlzbToge1xuICAgICAgICAgICAgICAgICAgICAgIHR5cGU6ICdpbnN0cnVtZW50JyxcbiAgICAgICAgICAgICAgICAgICAgICBkYXRhOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0YXJnZXQ6IGdsb2JhbCxcbiAgICAgICAgICAgICAgICAgICAgICAgIGZ1bmN0aW9uOiAnYWRkRXZlbnRMaXN0ZW5lcicsXG4gICAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVyOiAoZm4gJiYgZm4ubmFtZSkgfHwgJzxhbm9ueW1vdXM+J1xuICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgIGZuLFxuICAgICAgICAgICAgICAgICAgYmVmb3JlXG4gICAgICAgICAgICAgICAgKSxcbiAgICAgICAgICAgICAgICBjYXB0dXJlLFxuICAgICAgICAgICAgICAgIHNlY3VyZVxuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIHdyYXBwZWRCdWlsdEluc1xuICAgICAgICApO1xuICAgICAgICBmaWxsKFxuICAgICAgICAgIHByb3RvLFxuICAgICAgICAgICdyZW1vdmVFdmVudExpc3RlbmVyJyxcbiAgICAgICAgICBmdW5jdGlvbihvcmlnKSB7XG4gICAgICAgICAgICByZXR1cm4gZnVuY3Rpb24oZXZ0LCBmbiwgY2FwdHVyZSwgc2VjdXJlKSB7XG4gICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgZm4gPSBmbiAmJiAoZm4uX19yYXZlbl93cmFwcGVyX18gPyBmbi5fX3JhdmVuX3dyYXBwZXJfXyA6IGZuKTtcbiAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgIC8vIGlnbm9yZSwgYWNjZXNzaW5nIF9fcmF2ZW5fd3JhcHBlcl9fIHdpbGwgdGhyb3cgaW4gc29tZSBTZWxlbml1bSBlbnZpcm9ubWVudHNcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICByZXR1cm4gb3JpZy5jYWxsKHRoaXMsIGV2dCwgZm4sIGNhcHR1cmUsIHNlY3VyZSk7XG4gICAgICAgICAgICB9O1xuICAgICAgICAgIH0sXG4gICAgICAgICAgd3JhcHBlZEJ1aWx0SW5zXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgZmlsbChfd2luZG93LCAnc2V0VGltZW91dCcsIHdyYXBUaW1lRm4sIHdyYXBwZWRCdWlsdElucyk7XG4gICAgZmlsbChfd2luZG93LCAnc2V0SW50ZXJ2YWwnLCB3cmFwVGltZUZuLCB3cmFwcGVkQnVpbHRJbnMpO1xuICAgIGlmIChfd2luZG93LnJlcXVlc3RBbmltYXRpb25GcmFtZSkge1xuICAgICAgZmlsbChcbiAgICAgICAgX3dpbmRvdyxcbiAgICAgICAgJ3JlcXVlc3RBbmltYXRpb25GcmFtZScsXG4gICAgICAgIGZ1bmN0aW9uKG9yaWcpIHtcbiAgICAgICAgICByZXR1cm4gZnVuY3Rpb24oY2IpIHtcbiAgICAgICAgICAgIHJldHVybiBvcmlnKFxuICAgICAgICAgICAgICBzZWxmLndyYXAoXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgbWVjaGFuaXNtOiB7XG4gICAgICAgICAgICAgICAgICAgIHR5cGU6ICdpbnN0cnVtZW50JyxcbiAgICAgICAgICAgICAgICAgICAgZGF0YToge1xuICAgICAgICAgICAgICAgICAgICAgIGZ1bmN0aW9uOiAncmVxdWVzdEFuaW1hdGlvbkZyYW1lJyxcbiAgICAgICAgICAgICAgICAgICAgICBoYW5kbGVyOiAob3JpZyAmJiBvcmlnLm5hbWUpIHx8ICc8YW5vbnltb3VzPidcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgY2JcbiAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9O1xuICAgICAgICB9LFxuICAgICAgICB3cmFwcGVkQnVpbHRJbnNcbiAgICAgICk7XG4gICAgfVxuXG4gICAgLy8gZXZlbnQgdGFyZ2V0cyBib3Jyb3dlZCBmcm9tIGJ1Z3NuYWctanM6XG4gICAgLy8gaHR0cHM6Ly9naXRodWIuY29tL2J1Z3NuYWcvYnVnc25hZy1qcy9ibG9iL21hc3Rlci9zcmMvYnVnc25hZy5qcyNMNjY2XG4gICAgdmFyIGV2ZW50VGFyZ2V0cyA9IFtcbiAgICAgICdFdmVudFRhcmdldCcsXG4gICAgICAnV2luZG93JyxcbiAgICAgICdOb2RlJyxcbiAgICAgICdBcHBsaWNhdGlvbkNhY2hlJyxcbiAgICAgICdBdWRpb1RyYWNrTGlzdCcsXG4gICAgICAnQ2hhbm5lbE1lcmdlck5vZGUnLFxuICAgICAgJ0NyeXB0b09wZXJhdGlvbicsXG4gICAgICAnRXZlbnRTb3VyY2UnLFxuICAgICAgJ0ZpbGVSZWFkZXInLFxuICAgICAgJ0hUTUxVbmtub3duRWxlbWVudCcsXG4gICAgICAnSURCRGF0YWJhc2UnLFxuICAgICAgJ0lEQlJlcXVlc3QnLFxuICAgICAgJ0lEQlRyYW5zYWN0aW9uJyxcbiAgICAgICdLZXlPcGVyYXRpb24nLFxuICAgICAgJ01lZGlhQ29udHJvbGxlcicsXG4gICAgICAnTWVzc2FnZVBvcnQnLFxuICAgICAgJ01vZGFsV2luZG93JyxcbiAgICAgICdOb3RpZmljYXRpb24nLFxuICAgICAgJ1NWR0VsZW1lbnRJbnN0YW5jZScsXG4gICAgICAnU2NyZWVuJyxcbiAgICAgICdUZXh0VHJhY2snLFxuICAgICAgJ1RleHRUcmFja0N1ZScsXG4gICAgICAnVGV4dFRyYWNrTGlzdCcsXG4gICAgICAnV2ViU29ja2V0JyxcbiAgICAgICdXZWJTb2NrZXRXb3JrZXInLFxuICAgICAgJ1dvcmtlcicsXG4gICAgICAnWE1MSHR0cFJlcXVlc3QnLFxuICAgICAgJ1hNTEh0dHBSZXF1ZXN0RXZlbnRUYXJnZXQnLFxuICAgICAgJ1hNTEh0dHBSZXF1ZXN0VXBsb2FkJ1xuICAgIF07XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBldmVudFRhcmdldHMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHdyYXBFdmVudFRhcmdldChldmVudFRhcmdldHNbaV0pO1xuICAgIH1cbiAgfSxcblxuICAvKipcbiAgICogSW5zdHJ1bWVudCBicm93c2VyIGJ1aWx0LWlucyB3LyBicmVhZGNydW1iIGNhcHR1cmluZ1xuICAgKiAgLSBYTUxIdHRwUmVxdWVzdHNcbiAgICogIC0gRE9NIGludGVyYWN0aW9ucyAoY2xpY2svdHlwaW5nKVxuICAgKiAgLSB3aW5kb3cubG9jYXRpb24gY2hhbmdlc1xuICAgKiAgLSBjb25zb2xlXG4gICAqXG4gICAqIENhbiBiZSBkaXNhYmxlZCBvciBpbmRpdmlkdWFsbHkgY29uZmlndXJlZCB2aWEgdGhlIGBhdXRvQnJlYWRjcnVtYnNgIGNvbmZpZyBvcHRpb25cbiAgICovXG4gIF9pbnN0cnVtZW50QnJlYWRjcnVtYnM6IGZ1bmN0aW9uKCkge1xuICAgIHZhciBzZWxmID0gdGhpcztcbiAgICB2YXIgYXV0b0JyZWFkY3J1bWJzID0gdGhpcy5fZ2xvYmFsT3B0aW9ucy5hdXRvQnJlYWRjcnVtYnM7XG5cbiAgICB2YXIgd3JhcHBlZEJ1aWx0SW5zID0gc2VsZi5fd3JhcHBlZEJ1aWx0SW5zO1xuXG4gICAgZnVuY3Rpb24gd3JhcFByb3AocHJvcCwgeGhyKSB7XG4gICAgICBpZiAocHJvcCBpbiB4aHIgJiYgaXNGdW5jdGlvbih4aHJbcHJvcF0pKSB7XG4gICAgICAgIGZpbGwoeGhyLCBwcm9wLCBmdW5jdGlvbihvcmlnKSB7XG4gICAgICAgICAgcmV0dXJuIHNlbGYud3JhcChcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWVjaGFuaXNtOiB7XG4gICAgICAgICAgICAgICAgdHlwZTogJ2luc3RydW1lbnQnLFxuICAgICAgICAgICAgICAgIGRhdGE6IHtmdW5jdGlvbjogcHJvcCwgaGFuZGxlcjogKG9yaWcgJiYgb3JpZy5uYW1lKSB8fCAnPGFub255bW91cz4nfVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgb3JpZ1xuICAgICAgICAgICk7XG4gICAgICAgIH0pOyAvLyBpbnRlbnRpb25hbGx5IGRvbid0IHRyYWNrIGZpbGxlZCBtZXRob2RzIG9uIFhIUiBpbnN0YW5jZXNcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAoYXV0b0JyZWFkY3J1bWJzLnhociAmJiAnWE1MSHR0cFJlcXVlc3QnIGluIF93aW5kb3cpIHtcbiAgICAgIHZhciB4aHJwcm90byA9IF93aW5kb3cuWE1MSHR0cFJlcXVlc3QgJiYgX3dpbmRvdy5YTUxIdHRwUmVxdWVzdC5wcm90b3R5cGU7XG4gICAgICBmaWxsKFxuICAgICAgICB4aHJwcm90byxcbiAgICAgICAgJ29wZW4nLFxuICAgICAgICBmdW5jdGlvbihvcmlnT3Blbikge1xuICAgICAgICAgIHJldHVybiBmdW5jdGlvbihtZXRob2QsIHVybCkge1xuICAgICAgICAgICAgLy8gcHJlc2VydmUgYXJpdHlcblxuICAgICAgICAgICAgLy8gaWYgU2VudHJ5IGtleSBhcHBlYXJzIGluIFVSTCwgZG9uJ3QgY2FwdHVyZVxuICAgICAgICAgICAgaWYgKGlzU3RyaW5nKHVybCkgJiYgdXJsLmluZGV4T2Yoc2VsZi5fZ2xvYmFsS2V5KSA9PT0gLTEpIHtcbiAgICAgICAgICAgICAgdGhpcy5fX3JhdmVuX3hociA9IHtcbiAgICAgICAgICAgICAgICBtZXRob2Q6IG1ldGhvZCxcbiAgICAgICAgICAgICAgICB1cmw6IHVybCxcbiAgICAgICAgICAgICAgICBzdGF0dXNfY29kZTogbnVsbFxuICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICByZXR1cm4gb3JpZ09wZW4uYXBwbHkodGhpcywgYXJndW1lbnRzKTtcbiAgICAgICAgICB9O1xuICAgICAgICB9LFxuICAgICAgICB3cmFwcGVkQnVpbHRJbnNcbiAgICAgICk7XG5cbiAgICAgIGZpbGwoXG4gICAgICAgIHhocnByb3RvLFxuICAgICAgICAnc2VuZCcsXG4gICAgICAgIGZ1bmN0aW9uKG9yaWdTZW5kKSB7XG4gICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgLy8gcHJlc2VydmUgYXJpdHlcbiAgICAgICAgICAgIHZhciB4aHIgPSB0aGlzO1xuXG4gICAgICAgICAgICBmdW5jdGlvbiBvbnJlYWR5c3RhdGVjaGFuZ2VIYW5kbGVyKCkge1xuICAgICAgICAgICAgICBpZiAoeGhyLl9fcmF2ZW5feGhyICYmIHhoci5yZWFkeVN0YXRlID09PSA0KSB7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgIC8vIHRvdWNoaW5nIHN0YXR1c0NvZGUgaW4gc29tZSBwbGF0Zm9ybXMgdGhyb3dzXG4gICAgICAgICAgICAgICAgICAvLyBhbiBleGNlcHRpb25cbiAgICAgICAgICAgICAgICAgIHhoci5fX3JhdmVuX3hoci5zdGF0dXNfY29kZSA9IHhoci5zdGF0dXM7XG4gICAgICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgICAgICAgICAgLyogZG8gbm90aGluZyAqL1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHNlbGYuY2FwdHVyZUJyZWFkY3J1bWIoe1xuICAgICAgICAgICAgICAgICAgdHlwZTogJ2h0dHAnLFxuICAgICAgICAgICAgICAgICAgY2F0ZWdvcnk6ICd4aHInLFxuICAgICAgICAgICAgICAgICAgZGF0YTogeGhyLl9fcmF2ZW5feGhyXG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgdmFyIHByb3BzID0gWydvbmxvYWQnLCAnb25lcnJvcicsICdvbnByb2dyZXNzJ107XG4gICAgICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IHByb3BzLmxlbmd0aDsgaisrKSB7XG4gICAgICAgICAgICAgIHdyYXBQcm9wKHByb3BzW2pdLCB4aHIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAoJ29ucmVhZHlzdGF0ZWNoYW5nZScgaW4geGhyICYmIGlzRnVuY3Rpb24oeGhyLm9ucmVhZHlzdGF0ZWNoYW5nZSkpIHtcbiAgICAgICAgICAgICAgZmlsbChcbiAgICAgICAgICAgICAgICB4aHIsXG4gICAgICAgICAgICAgICAgJ29ucmVhZHlzdGF0ZWNoYW5nZScsXG4gICAgICAgICAgICAgICAgZnVuY3Rpb24ob3JpZykge1xuICAgICAgICAgICAgICAgICAgcmV0dXJuIHNlbGYud3JhcChcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgIG1lY2hhbmlzbToge1xuICAgICAgICAgICAgICAgICAgICAgICAgdHlwZTogJ2luc3RydW1lbnQnLFxuICAgICAgICAgICAgICAgICAgICAgICAgZGF0YToge1xuICAgICAgICAgICAgICAgICAgICAgICAgICBmdW5jdGlvbjogJ29ucmVhZHlzdGF0ZWNoYW5nZScsXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGhhbmRsZXI6IChvcmlnICYmIG9yaWcubmFtZSkgfHwgJzxhbm9ueW1vdXM+J1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgb3JpZyxcbiAgICAgICAgICAgICAgICAgICAgb25yZWFkeXN0YXRlY2hhbmdlSGFuZGxlclxuICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICB9IC8qIGludGVudGlvbmFsbHkgZG9uJ3QgdHJhY2sgdGhpcyBpbnN0cnVtZW50YXRpb24gKi9cbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIC8vIGlmIG9ucmVhZHlzdGF0ZWNoYW5nZSB3YXNuJ3QgYWN0dWFsbHkgc2V0IGJ5IHRoZSBwYWdlIG9uIHRoaXMgeGhyLCB3ZVxuICAgICAgICAgICAgICAvLyBhcmUgZnJlZSB0byBzZXQgb3VyIG93biBhbmQgY2FwdHVyZSB0aGUgYnJlYWRjcnVtYlxuICAgICAgICAgICAgICB4aHIub25yZWFkeXN0YXRlY2hhbmdlID0gb25yZWFkeXN0YXRlY2hhbmdlSGFuZGxlcjtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgcmV0dXJuIG9yaWdTZW5kLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG4gICAgICAgICAgfTtcbiAgICAgICAgfSxcbiAgICAgICAgd3JhcHBlZEJ1aWx0SW5zXG4gICAgICApO1xuICAgIH1cblxuICAgIGlmIChhdXRvQnJlYWRjcnVtYnMueGhyICYmIHN1cHBvcnRzRmV0Y2goKSkge1xuICAgICAgZmlsbChcbiAgICAgICAgX3dpbmRvdyxcbiAgICAgICAgJ2ZldGNoJyxcbiAgICAgICAgZnVuY3Rpb24ob3JpZ0ZldGNoKSB7XG4gICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgLy8gcHJlc2VydmUgYXJpdHlcbiAgICAgICAgICAgIC8vIE1ha2UgYSBjb3B5IG9mIHRoZSBhcmd1bWVudHMgdG8gcHJldmVudCBkZW9wdGltaXphdGlvblxuICAgICAgICAgICAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3BldGthYW50b25vdi9ibHVlYmlyZC93aWtpL09wdGltaXphdGlvbi1raWxsZXJzIzMyLWxlYWtpbmctYXJndW1lbnRzXG4gICAgICAgICAgICB2YXIgYXJncyA9IG5ldyBBcnJheShhcmd1bWVudHMubGVuZ3RoKTtcbiAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJncy5sZW5ndGg7ICsraSkge1xuICAgICAgICAgICAgICBhcmdzW2ldID0gYXJndW1lbnRzW2ldO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB2YXIgZmV0Y2hJbnB1dCA9IGFyZ3NbMF07XG4gICAgICAgICAgICB2YXIgbWV0aG9kID0gJ0dFVCc7XG4gICAgICAgICAgICB2YXIgdXJsO1xuXG4gICAgICAgICAgICBpZiAodHlwZW9mIGZldGNoSW5wdXQgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICAgIHVybCA9IGZldGNoSW5wdXQ7XG4gICAgICAgICAgICB9IGVsc2UgaWYgKCdSZXF1ZXN0JyBpbiBfd2luZG93ICYmIGZldGNoSW5wdXQgaW5zdGFuY2VvZiBfd2luZG93LlJlcXVlc3QpIHtcbiAgICAgICAgICAgICAgdXJsID0gZmV0Y2hJbnB1dC51cmw7XG4gICAgICAgICAgICAgIGlmIChmZXRjaElucHV0Lm1ldGhvZCkge1xuICAgICAgICAgICAgICAgIG1ldGhvZCA9IGZldGNoSW5wdXQubWV0aG9kO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICB1cmwgPSAnJyArIGZldGNoSW5wdXQ7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIGlmIFNlbnRyeSBrZXkgYXBwZWFycyBpbiBVUkwsIGRvbid0IGNhcHR1cmUsIGFzIGl0J3Mgb3VyIG93biByZXF1ZXN0XG4gICAgICAgICAgICBpZiAodXJsLmluZGV4T2Yoc2VsZi5fZ2xvYmFsS2V5KSAhPT0gLTEpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIG9yaWdGZXRjaC5hcHBseSh0aGlzLCBhcmdzKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKGFyZ3NbMV0gJiYgYXJnc1sxXS5tZXRob2QpIHtcbiAgICAgICAgICAgICAgbWV0aG9kID0gYXJnc1sxXS5tZXRob2Q7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHZhciBmZXRjaERhdGEgPSB7XG4gICAgICAgICAgICAgIG1ldGhvZDogbWV0aG9kLFxuICAgICAgICAgICAgICB1cmw6IHVybCxcbiAgICAgICAgICAgICAgc3RhdHVzX2NvZGU6IG51bGxcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHJldHVybiBvcmlnRmV0Y2hcbiAgICAgICAgICAgICAgLmFwcGx5KHRoaXMsIGFyZ3MpXG4gICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgZmV0Y2hEYXRhLnN0YXR1c19jb2RlID0gcmVzcG9uc2Uuc3RhdHVzO1xuXG4gICAgICAgICAgICAgICAgc2VsZi5jYXB0dXJlQnJlYWRjcnVtYih7XG4gICAgICAgICAgICAgICAgICB0eXBlOiAnaHR0cCcsXG4gICAgICAgICAgICAgICAgICBjYXRlZ29yeTogJ2ZldGNoJyxcbiAgICAgICAgICAgICAgICAgIGRhdGE6IGZldGNoRGF0YVxuICAgICAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICBbJ2NhdGNoJ10oZnVuY3Rpb24oZXJyKSB7XG4gICAgICAgICAgICAgICAgLy8gaWYgdGhlcmUgaXMgYW4gZXJyb3IgcGVyZm9ybWluZyB0aGUgcmVxdWVzdFxuICAgICAgICAgICAgICAgIHNlbGYuY2FwdHVyZUJyZWFkY3J1bWIoe1xuICAgICAgICAgICAgICAgICAgdHlwZTogJ2h0dHAnLFxuICAgICAgICAgICAgICAgICAgY2F0ZWdvcnk6ICdmZXRjaCcsXG4gICAgICAgICAgICAgICAgICBkYXRhOiBmZXRjaERhdGEsXG4gICAgICAgICAgICAgICAgICBsZXZlbDogJ2Vycm9yJ1xuICAgICAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICAgICAgdGhyb3cgZXJyO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICB9O1xuICAgICAgICB9LFxuICAgICAgICB3cmFwcGVkQnVpbHRJbnNcbiAgICAgICk7XG4gICAgfVxuXG4gICAgLy8gQ2FwdHVyZSBicmVhZGNydW1icyBmcm9tIGFueSBjbGljayB0aGF0IGlzIHVuaGFuZGxlZCAvIGJ1YmJsZWQgdXAgYWxsIHRoZSB3YXlcbiAgICAvLyB0byB0aGUgZG9jdW1lbnQuIERvIHRoaXMgYmVmb3JlIHdlIGluc3RydW1lbnQgYWRkRXZlbnRMaXN0ZW5lci5cbiAgICBpZiAoYXV0b0JyZWFkY3J1bWJzLmRvbSAmJiB0aGlzLl9oYXNEb2N1bWVudCkge1xuICAgICAgaWYgKF9kb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKSB7XG4gICAgICAgIF9kb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIHNlbGYuX2JyZWFkY3J1bWJFdmVudEhhbmRsZXIoJ2NsaWNrJyksIGZhbHNlKTtcbiAgICAgICAgX2RvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ2tleXByZXNzJywgc2VsZi5fa2V5cHJlc3NFdmVudEhhbmRsZXIoKSwgZmFsc2UpO1xuICAgICAgfSBlbHNlIGlmIChfZG9jdW1lbnQuYXR0YWNoRXZlbnQpIHtcbiAgICAgICAgLy8gSUU4IENvbXBhdGliaWxpdHlcbiAgICAgICAgX2RvY3VtZW50LmF0dGFjaEV2ZW50KCdvbmNsaWNrJywgc2VsZi5fYnJlYWRjcnVtYkV2ZW50SGFuZGxlcignY2xpY2snKSk7XG4gICAgICAgIF9kb2N1bWVudC5hdHRhY2hFdmVudCgnb25rZXlwcmVzcycsIHNlbGYuX2tleXByZXNzRXZlbnRIYW5kbGVyKCkpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIHJlY29yZCBuYXZpZ2F0aW9uIChVUkwpIGNoYW5nZXNcbiAgICAvLyBOT1RFOiBpbiBDaHJvbWUgQXBwIGVudmlyb25tZW50LCB0b3VjaGluZyBoaXN0b3J5LnB1c2hTdGF0ZSwgKmV2ZW4gaW5zaWRlXG4gICAgLy8gICAgICAgYSB0cnkvY2F0Y2ggYmxvY2sqLCB3aWxsIGNhdXNlIENocm9tZSB0byBvdXRwdXQgYW4gZXJyb3IgdG8gY29uc29sZS5lcnJvclxuICAgIC8vIGJvcnJvd2VkIGZyb206IGh0dHBzOi8vZ2l0aHViLmNvbS9hbmd1bGFyL2FuZ3VsYXIuanMvcHVsbC8xMzk0NS9maWxlc1xuICAgIHZhciBjaHJvbWUgPSBfd2luZG93LmNocm9tZTtcbiAgICB2YXIgaXNDaHJvbWVQYWNrYWdlZEFwcCA9IGNocm9tZSAmJiBjaHJvbWUuYXBwICYmIGNocm9tZS5hcHAucnVudGltZTtcbiAgICB2YXIgaGFzUHVzaEFuZFJlcGxhY2VTdGF0ZSA9XG4gICAgICAhaXNDaHJvbWVQYWNrYWdlZEFwcCAmJlxuICAgICAgX3dpbmRvdy5oaXN0b3J5ICYmXG4gICAgICBfd2luZG93Lmhpc3RvcnkucHVzaFN0YXRlICYmXG4gICAgICBfd2luZG93Lmhpc3RvcnkucmVwbGFjZVN0YXRlO1xuICAgIGlmIChhdXRvQnJlYWRjcnVtYnMubG9jYXRpb24gJiYgaGFzUHVzaEFuZFJlcGxhY2VTdGF0ZSkge1xuICAgICAgLy8gVE9ETzogcmVtb3ZlIG9ucG9wc3RhdGUgaGFuZGxlciBvbiB1bmluc3RhbGwoKVxuICAgICAgdmFyIG9sZE9uUG9wU3RhdGUgPSBfd2luZG93Lm9ucG9wc3RhdGU7XG4gICAgICBfd2luZG93Lm9ucG9wc3RhdGUgPSBmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIGN1cnJlbnRIcmVmID0gc2VsZi5fbG9jYXRpb24uaHJlZjtcbiAgICAgICAgc2VsZi5fY2FwdHVyZVVybENoYW5nZShzZWxmLl9sYXN0SHJlZiwgY3VycmVudEhyZWYpO1xuXG4gICAgICAgIGlmIChvbGRPblBvcFN0YXRlKSB7XG4gICAgICAgICAgcmV0dXJuIG9sZE9uUG9wU3RhdGUuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcbiAgICAgICAgfVxuICAgICAgfTtcblxuICAgICAgdmFyIGhpc3RvcnlSZXBsYWNlbWVudEZ1bmN0aW9uID0gZnVuY3Rpb24ob3JpZ0hpc3RGdW5jdGlvbikge1xuICAgICAgICAvLyBub3RlIGhpc3RvcnkucHVzaFN0YXRlLmxlbmd0aCBpcyAwOyBpbnRlbnRpb25hbGx5IG5vdCBkZWNsYXJpbmdcbiAgICAgICAgLy8gcGFyYW1zIHRvIHByZXNlcnZlIDAgYXJpdHlcbiAgICAgICAgcmV0dXJuIGZ1bmN0aW9uKC8qIHN0YXRlLCB0aXRsZSwgdXJsICovKSB7XG4gICAgICAgICAgdmFyIHVybCA9IGFyZ3VtZW50cy5sZW5ndGggPiAyID8gYXJndW1lbnRzWzJdIDogdW5kZWZpbmVkO1xuXG4gICAgICAgICAgLy8gdXJsIGFyZ3VtZW50IGlzIG9wdGlvbmFsXG4gICAgICAgICAgaWYgKHVybCkge1xuICAgICAgICAgICAgLy8gY29lcmNlIHRvIHN0cmluZyAodGhpcyBpcyB3aGF0IHB1c2hTdGF0ZSBkb2VzKVxuICAgICAgICAgICAgc2VsZi5fY2FwdHVyZVVybENoYW5nZShzZWxmLl9sYXN0SHJlZiwgdXJsICsgJycpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHJldHVybiBvcmlnSGlzdEZ1bmN0aW9uLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG4gICAgICAgIH07XG4gICAgICB9O1xuXG4gICAgICBmaWxsKF93aW5kb3cuaGlzdG9yeSwgJ3B1c2hTdGF0ZScsIGhpc3RvcnlSZXBsYWNlbWVudEZ1bmN0aW9uLCB3cmFwcGVkQnVpbHRJbnMpO1xuICAgICAgZmlsbChfd2luZG93Lmhpc3RvcnksICdyZXBsYWNlU3RhdGUnLCBoaXN0b3J5UmVwbGFjZW1lbnRGdW5jdGlvbiwgd3JhcHBlZEJ1aWx0SW5zKTtcbiAgICB9XG5cbiAgICBpZiAoYXV0b0JyZWFkY3J1bWJzLmNvbnNvbGUgJiYgJ2NvbnNvbGUnIGluIF93aW5kb3cgJiYgY29uc29sZS5sb2cpIHtcbiAgICAgIC8vIGNvbnNvbGVcbiAgICAgIHZhciBjb25zb2xlTWV0aG9kQ2FsbGJhY2sgPSBmdW5jdGlvbihtc2csIGRhdGEpIHtcbiAgICAgICAgc2VsZi5jYXB0dXJlQnJlYWRjcnVtYih7XG4gICAgICAgICAgbWVzc2FnZTogbXNnLFxuICAgICAgICAgIGxldmVsOiBkYXRhLmxldmVsLFxuICAgICAgICAgIGNhdGVnb3J5OiAnY29uc29sZSdcbiAgICAgICAgfSk7XG4gICAgICB9O1xuXG4gICAgICBlYWNoKFsnZGVidWcnLCAnaW5mbycsICd3YXJuJywgJ2Vycm9yJywgJ2xvZyddLCBmdW5jdGlvbihfLCBsZXZlbCkge1xuICAgICAgICB3cmFwQ29uc29sZU1ldGhvZChjb25zb2xlLCBsZXZlbCwgY29uc29sZU1ldGhvZENhbGxiYWNrKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgfSxcblxuICBfcmVzdG9yZUJ1aWx0SW5zOiBmdW5jdGlvbigpIHtcbiAgICAvLyByZXN0b3JlIGFueSB3cmFwcGVkIGJ1aWx0aW5zXG4gICAgdmFyIGJ1aWx0aW47XG4gICAgd2hpbGUgKHRoaXMuX3dyYXBwZWRCdWlsdElucy5sZW5ndGgpIHtcbiAgICAgIGJ1aWx0aW4gPSB0aGlzLl93cmFwcGVkQnVpbHRJbnMuc2hpZnQoKTtcblxuICAgICAgdmFyIG9iaiA9IGJ1aWx0aW5bMF0sXG4gICAgICAgIG5hbWUgPSBidWlsdGluWzFdLFxuICAgICAgICBvcmlnID0gYnVpbHRpblsyXTtcblxuICAgICAgb2JqW25hbWVdID0gb3JpZztcbiAgICB9XG4gIH0sXG5cbiAgX3Jlc3RvcmVDb25zb2xlOiBmdW5jdGlvbigpIHtcbiAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgZ3VhcmQtZm9yLWluXG4gICAgZm9yICh2YXIgbWV0aG9kIGluIHRoaXMuX29yaWdpbmFsQ29uc29sZU1ldGhvZHMpIHtcbiAgICAgIHRoaXMuX29yaWdpbmFsQ29uc29sZVttZXRob2RdID0gdGhpcy5fb3JpZ2luYWxDb25zb2xlTWV0aG9kc1ttZXRob2RdO1xuICAgIH1cbiAgfSxcblxuICBfZHJhaW5QbHVnaW5zOiBmdW5jdGlvbigpIHtcbiAgICB2YXIgc2VsZiA9IHRoaXM7XG5cbiAgICAvLyBGSVggTUUgVE9ET1xuICAgIGVhY2godGhpcy5fcGx1Z2lucywgZnVuY3Rpb24oXywgcGx1Z2luKSB7XG4gICAgICB2YXIgaW5zdGFsbGVyID0gcGx1Z2luWzBdO1xuICAgICAgdmFyIGFyZ3MgPSBwbHVnaW5bMV07XG4gICAgICBpbnN0YWxsZXIuYXBwbHkoc2VsZiwgW3NlbGZdLmNvbmNhdChhcmdzKSk7XG4gICAgfSk7XG4gIH0sXG5cbiAgX3BhcnNlRFNOOiBmdW5jdGlvbihzdHIpIHtcbiAgICB2YXIgbSA9IGRzblBhdHRlcm4uZXhlYyhzdHIpLFxuICAgICAgZHNuID0ge30sXG4gICAgICBpID0gNztcblxuICAgIHRyeSB7XG4gICAgICB3aGlsZSAoaS0tKSBkc25bZHNuS2V5c1tpXV0gPSBtW2ldIHx8ICcnO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIHRocm93IG5ldyBSYXZlbkNvbmZpZ0Vycm9yKCdJbnZhbGlkIERTTjogJyArIHN0cik7XG4gICAgfVxuXG4gICAgaWYgKGRzbi5wYXNzICYmICF0aGlzLl9nbG9iYWxPcHRpb25zLmFsbG93U2VjcmV0S2V5KSB7XG4gICAgICB0aHJvdyBuZXcgUmF2ZW5Db25maWdFcnJvcihcbiAgICAgICAgJ0RvIG5vdCBzcGVjaWZ5IHlvdXIgc2VjcmV0IGtleSBpbiB0aGUgRFNOLiBTZWU6IGh0dHA6Ly9iaXQubHkvcmF2ZW4tc2VjcmV0LWtleSdcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGRzbjtcbiAgfSxcblxuICBfZ2V0R2xvYmFsU2VydmVyOiBmdW5jdGlvbih1cmkpIHtcbiAgICAvLyBhc3NlbWJsZSB0aGUgZW5kcG9pbnQgZnJvbSB0aGUgdXJpIHBpZWNlc1xuICAgIHZhciBnbG9iYWxTZXJ2ZXIgPSAnLy8nICsgdXJpLmhvc3QgKyAodXJpLnBvcnQgPyAnOicgKyB1cmkucG9ydCA6ICcnKTtcblxuICAgIGlmICh1cmkucHJvdG9jb2wpIHtcbiAgICAgIGdsb2JhbFNlcnZlciA9IHVyaS5wcm90b2NvbCArICc6JyArIGdsb2JhbFNlcnZlcjtcbiAgICB9XG4gICAgcmV0dXJuIGdsb2JhbFNlcnZlcjtcbiAgfSxcblxuICBfaGFuZGxlT25FcnJvclN0YWNrSW5mbzogZnVuY3Rpb24oc3RhY2tJbmZvLCBvcHRpb25zKSB7XG4gICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG4gICAgb3B0aW9ucy5tZWNoYW5pc20gPSBvcHRpb25zLm1lY2hhbmlzbSB8fCB7XG4gICAgICB0eXBlOiAnb25lcnJvcicsXG4gICAgICBoYW5kbGVkOiBmYWxzZVxuICAgIH07XG5cbiAgICAvLyBpZiB3ZSBhcmUgaW50ZW50aW9uYWxseSBpZ25vcmluZyBlcnJvcnMgdmlhIG9uZXJyb3IsIGJhaWwgb3V0XG4gICAgaWYgKCF0aGlzLl9pZ25vcmVPbkVycm9yKSB7XG4gICAgICB0aGlzLl9oYW5kbGVTdGFja0luZm8oc3RhY2tJbmZvLCBvcHRpb25zKTtcbiAgICB9XG4gIH0sXG5cbiAgX2hhbmRsZVN0YWNrSW5mbzogZnVuY3Rpb24oc3RhY2tJbmZvLCBvcHRpb25zKSB7XG4gICAgdmFyIGZyYW1lcyA9IHRoaXMuX3ByZXBhcmVGcmFtZXMoc3RhY2tJbmZvLCBvcHRpb25zKTtcblxuICAgIHRoaXMuX3RyaWdnZXJFdmVudCgnaGFuZGxlJywge1xuICAgICAgc3RhY2tJbmZvOiBzdGFja0luZm8sXG4gICAgICBvcHRpb25zOiBvcHRpb25zXG4gICAgfSk7XG5cbiAgICB0aGlzLl9wcm9jZXNzRXhjZXB0aW9uKFxuICAgICAgc3RhY2tJbmZvLm5hbWUsXG4gICAgICBzdGFja0luZm8ubWVzc2FnZSxcbiAgICAgIHN0YWNrSW5mby51cmwsXG4gICAgICBzdGFja0luZm8ubGluZW5vLFxuICAgICAgZnJhbWVzLFxuICAgICAgb3B0aW9uc1xuICAgICk7XG4gIH0sXG5cbiAgX3ByZXBhcmVGcmFtZXM6IGZ1bmN0aW9uKHN0YWNrSW5mbywgb3B0aW9ucykge1xuICAgIHZhciBzZWxmID0gdGhpcztcbiAgICB2YXIgZnJhbWVzID0gW107XG4gICAgaWYgKHN0YWNrSW5mby5zdGFjayAmJiBzdGFja0luZm8uc3RhY2subGVuZ3RoKSB7XG4gICAgICBlYWNoKHN0YWNrSW5mby5zdGFjaywgZnVuY3Rpb24oaSwgc3RhY2spIHtcbiAgICAgICAgdmFyIGZyYW1lID0gc2VsZi5fbm9ybWFsaXplRnJhbWUoc3RhY2ssIHN0YWNrSW5mby51cmwpO1xuICAgICAgICBpZiAoZnJhbWUpIHtcbiAgICAgICAgICBmcmFtZXMucHVzaChmcmFtZSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuXG4gICAgICAvLyBlLmcuIGZyYW1lcyBjYXB0dXJlZCB2aWEgY2FwdHVyZU1lc3NhZ2UgdGhyb3dcbiAgICAgIGlmIChvcHRpb25zICYmIG9wdGlvbnMudHJpbUhlYWRGcmFtZXMpIHtcbiAgICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCBvcHRpb25zLnRyaW1IZWFkRnJhbWVzICYmIGogPCBmcmFtZXMubGVuZ3RoOyBqKyspIHtcbiAgICAgICAgICBmcmFtZXNbal0uaW5fYXBwID0gZmFsc2U7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgZnJhbWVzID0gZnJhbWVzLnNsaWNlKDAsIHRoaXMuX2dsb2JhbE9wdGlvbnMuc3RhY2tUcmFjZUxpbWl0KTtcbiAgICByZXR1cm4gZnJhbWVzO1xuICB9LFxuXG4gIF9ub3JtYWxpemVGcmFtZTogZnVuY3Rpb24oZnJhbWUsIHN0YWNrSW5mb1VybCkge1xuICAgIC8vIG5vcm1hbGl6ZSB0aGUgZnJhbWVzIGRhdGFcbiAgICB2YXIgbm9ybWFsaXplZCA9IHtcbiAgICAgIGZpbGVuYW1lOiBmcmFtZS51cmwsXG4gICAgICBsaW5lbm86IGZyYW1lLmxpbmUsXG4gICAgICBjb2xubzogZnJhbWUuY29sdW1uLFxuICAgICAgZnVuY3Rpb246IGZyYW1lLmZ1bmMgfHwgJz8nXG4gICAgfTtcblxuICAgIC8vIENhc2Ugd2hlbiB3ZSBkb24ndCBoYXZlIGFueSBpbmZvcm1hdGlvbiBhYm91dCB0aGUgZXJyb3JcbiAgICAvLyBFLmcuIHRocm93aW5nIGEgc3RyaW5nIG9yIHJhdyBvYmplY3QsIGluc3RlYWQgb2YgYW4gYEVycm9yYCBpbiBGaXJlZm94XG4gICAgLy8gR2VuZXJhdGluZyBzeW50aGV0aWMgZXJyb3IgZG9lc24ndCBhZGQgYW55IHZhbHVlIGhlcmVcbiAgICAvL1xuICAgIC8vIFdlIHNob3VsZCBwcm9iYWJseSBzb21laG93IGxldCBhIHVzZXIga25vdyB0aGF0IHRoZXkgc2hvdWxkIGZpeCB0aGVpciBjb2RlXG4gICAgaWYgKCFmcmFtZS51cmwpIHtcbiAgICAgIG5vcm1hbGl6ZWQuZmlsZW5hbWUgPSBzdGFja0luZm9Vcmw7IC8vIGZhbGxiYWNrIHRvIHdob2xlIHN0YWNrcyB1cmwgZnJvbSBvbmVycm9yIGhhbmRsZXJcbiAgICB9XG5cbiAgICBub3JtYWxpemVkLmluX2FwcCA9ICEvLyBkZXRlcm1pbmUgaWYgYW4gZXhjZXB0aW9uIGNhbWUgZnJvbSBvdXRzaWRlIG9mIG91ciBhcHBcbiAgICAvLyBmaXJzdCB3ZSBjaGVjayB0aGUgZ2xvYmFsIGluY2x1ZGVQYXRocyBsaXN0LlxuICAgIChcbiAgICAgICghIXRoaXMuX2dsb2JhbE9wdGlvbnMuaW5jbHVkZVBhdGhzLnRlc3QgJiZcbiAgICAgICAgIXRoaXMuX2dsb2JhbE9wdGlvbnMuaW5jbHVkZVBhdGhzLnRlc3Qobm9ybWFsaXplZC5maWxlbmFtZSkpIHx8XG4gICAgICAvLyBOb3cgd2UgY2hlY2sgZm9yIGZ1biwgaWYgdGhlIGZ1bmN0aW9uIG5hbWUgaXMgUmF2ZW4gb3IgVHJhY2VLaXRcbiAgICAgIC8oUmF2ZW58VHJhY2VLaXQpXFwuLy50ZXN0KG5vcm1hbGl6ZWRbJ2Z1bmN0aW9uJ10pIHx8XG4gICAgICAvLyBmaW5hbGx5LCB3ZSBkbyBhIGxhc3QgZGl0Y2ggZWZmb3J0IGFuZCBjaGVjayBmb3IgcmF2ZW4ubWluLmpzXG4gICAgICAvcmF2ZW5cXC4obWluXFwuKT9qcyQvLnRlc3Qobm9ybWFsaXplZC5maWxlbmFtZSlcbiAgICApO1xuXG4gICAgcmV0dXJuIG5vcm1hbGl6ZWQ7XG4gIH0sXG5cbiAgX3Byb2Nlc3NFeGNlcHRpb246IGZ1bmN0aW9uKHR5cGUsIG1lc3NhZ2UsIGZpbGV1cmwsIGxpbmVubywgZnJhbWVzLCBvcHRpb25zKSB7XG4gICAgdmFyIHByZWZpeGVkTWVzc2FnZSA9ICh0eXBlID8gdHlwZSArICc6ICcgOiAnJykgKyAobWVzc2FnZSB8fCAnJyk7XG4gICAgaWYgKFxuICAgICAgISF0aGlzLl9nbG9iYWxPcHRpb25zLmlnbm9yZUVycm9ycy50ZXN0ICYmXG4gICAgICAodGhpcy5fZ2xvYmFsT3B0aW9ucy5pZ25vcmVFcnJvcnMudGVzdChtZXNzYWdlKSB8fFxuICAgICAgICB0aGlzLl9nbG9iYWxPcHRpb25zLmlnbm9yZUVycm9ycy50ZXN0KHByZWZpeGVkTWVzc2FnZSkpXG4gICAgKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdmFyIHN0YWNrdHJhY2U7XG5cbiAgICBpZiAoZnJhbWVzICYmIGZyYW1lcy5sZW5ndGgpIHtcbiAgICAgIGZpbGV1cmwgPSBmcmFtZXNbMF0uZmlsZW5hbWUgfHwgZmlsZXVybDtcbiAgICAgIC8vIFNlbnRyeSBleHBlY3RzIGZyYW1lcyBvbGRlc3QgdG8gbmV3ZXN0XG4gICAgICAvLyBhbmQgSlMgc2VuZHMgdGhlbSBhcyBuZXdlc3QgdG8gb2xkZXN0XG4gICAgICBmcmFtZXMucmV2ZXJzZSgpO1xuICAgICAgc3RhY2t0cmFjZSA9IHtmcmFtZXM6IGZyYW1lc307XG4gICAgfSBlbHNlIGlmIChmaWxldXJsKSB7XG4gICAgICBzdGFja3RyYWNlID0ge1xuICAgICAgICBmcmFtZXM6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBmaWxlbmFtZTogZmlsZXVybCxcbiAgICAgICAgICAgIGxpbmVubzogbGluZW5vLFxuICAgICAgICAgICAgaW5fYXBwOiB0cnVlXG4gICAgICAgICAgfVxuICAgICAgICBdXG4gICAgICB9O1xuICAgIH1cblxuICAgIGlmIChcbiAgICAgICEhdGhpcy5fZ2xvYmFsT3B0aW9ucy5pZ25vcmVVcmxzLnRlc3QgJiZcbiAgICAgIHRoaXMuX2dsb2JhbE9wdGlvbnMuaWdub3JlVXJscy50ZXN0KGZpbGV1cmwpXG4gICAgKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgaWYgKFxuICAgICAgISF0aGlzLl9nbG9iYWxPcHRpb25zLndoaXRlbGlzdFVybHMudGVzdCAmJlxuICAgICAgIXRoaXMuX2dsb2JhbE9wdGlvbnMud2hpdGVsaXN0VXJscy50ZXN0KGZpbGV1cmwpXG4gICAgKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdmFyIGRhdGEgPSBvYmplY3RNZXJnZShcbiAgICAgIHtcbiAgICAgICAgLy8gc2VudHJ5LmludGVyZmFjZXMuRXhjZXB0aW9uXG4gICAgICAgIGV4Y2VwdGlvbjoge1xuICAgICAgICAgIHZhbHVlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICB0eXBlOiB0eXBlLFxuICAgICAgICAgICAgICB2YWx1ZTogbWVzc2FnZSxcbiAgICAgICAgICAgICAgc3RhY2t0cmFjZTogc3RhY2t0cmFjZVxuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgfSxcbiAgICAgICAgdHJhbnNhY3Rpb246IGZpbGV1cmxcbiAgICAgIH0sXG4gICAgICBvcHRpb25zXG4gICAgKTtcblxuICAgIHZhciBleCA9IGRhdGEuZXhjZXB0aW9uLnZhbHVlc1swXTtcbiAgICBpZiAoZXgudHlwZSA9PSBudWxsICYmIGV4LnZhbHVlID09PSAnJykge1xuICAgICAgZXgudmFsdWUgPSAnVW5yZWNvdmVyYWJsZSBlcnJvciBjYXVnaHQnO1xuICAgIH1cblxuICAgIC8vIE1vdmUgbWVjaGFuaXNtIGZyb20gb3B0aW9ucyB0byBleGNlcHRpb24gaW50ZXJmYWNlXG4gICAgLy8gV2UgZG8gdGhpcywgYXMgcmVxdWlyaW5nIHVzZXIgdG8gcGFzcyBge2V4Y2VwdGlvbjp7bWVjaGFuaXNtOnsgLi4uIH19fWAgd291bGQgYmVcbiAgICAvLyB0b28gbXVjaFxuICAgIGlmICghZGF0YS5leGNlcHRpb24ubWVjaGFuaXNtICYmIGRhdGEubWVjaGFuaXNtKSB7XG4gICAgICBkYXRhLmV4Y2VwdGlvbi5tZWNoYW5pc20gPSBkYXRhLm1lY2hhbmlzbTtcbiAgICAgIGRlbGV0ZSBkYXRhLm1lY2hhbmlzbTtcbiAgICB9XG5cbiAgICBkYXRhLmV4Y2VwdGlvbi5tZWNoYW5pc20gPSBvYmplY3RNZXJnZShcbiAgICAgIHtcbiAgICAgICAgdHlwZTogJ2dlbmVyaWMnLFxuICAgICAgICBoYW5kbGVkOiB0cnVlXG4gICAgICB9LFxuICAgICAgZGF0YS5leGNlcHRpb24ubWVjaGFuaXNtIHx8IHt9XG4gICAgKTtcblxuICAgIC8vIEZpcmUgYXdheSFcbiAgICB0aGlzLl9zZW5kKGRhdGEpO1xuICB9LFxuXG4gIF90cmltUGFja2V0OiBmdW5jdGlvbihkYXRhKSB7XG4gICAgLy8gRm9yIG5vdywgd2Ugb25seSB3YW50IHRvIHRydW5jYXRlIHRoZSB0d28gZGlmZmVyZW50IG1lc3NhZ2VzXG4gICAgLy8gYnV0IHRoaXMgY291bGQvc2hvdWxkIGJlIGV4cGFuZGVkIHRvIGp1c3QgdHJpbSBldmVyeXRoaW5nXG4gICAgdmFyIG1heCA9IHRoaXMuX2dsb2JhbE9wdGlvbnMubWF4TWVzc2FnZUxlbmd0aDtcbiAgICBpZiAoZGF0YS5tZXNzYWdlKSB7XG4gICAgICBkYXRhLm1lc3NhZ2UgPSB0cnVuY2F0ZShkYXRhLm1lc3NhZ2UsIG1heCk7XG4gICAgfVxuICAgIGlmIChkYXRhLmV4Y2VwdGlvbikge1xuICAgICAgdmFyIGV4Y2VwdGlvbiA9IGRhdGEuZXhjZXB0aW9uLnZhbHVlc1swXTtcbiAgICAgIGV4Y2VwdGlvbi52YWx1ZSA9IHRydW5jYXRlKGV4Y2VwdGlvbi52YWx1ZSwgbWF4KTtcbiAgICB9XG5cbiAgICB2YXIgcmVxdWVzdCA9IGRhdGEucmVxdWVzdDtcbiAgICBpZiAocmVxdWVzdCkge1xuICAgICAgaWYgKHJlcXVlc3QudXJsKSB7XG4gICAgICAgIHJlcXVlc3QudXJsID0gdHJ1bmNhdGUocmVxdWVzdC51cmwsIHRoaXMuX2dsb2JhbE9wdGlvbnMubWF4VXJsTGVuZ3RoKTtcbiAgICAgIH1cbiAgICAgIGlmIChyZXF1ZXN0LlJlZmVyZXIpIHtcbiAgICAgICAgcmVxdWVzdC5SZWZlcmVyID0gdHJ1bmNhdGUocmVxdWVzdC5SZWZlcmVyLCB0aGlzLl9nbG9iYWxPcHRpb25zLm1heFVybExlbmd0aCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKGRhdGEuYnJlYWRjcnVtYnMgJiYgZGF0YS5icmVhZGNydW1icy52YWx1ZXMpXG4gICAgICB0aGlzLl90cmltQnJlYWRjcnVtYnMoZGF0YS5icmVhZGNydW1icyk7XG5cbiAgICByZXR1cm4gZGF0YTtcbiAgfSxcblxuICAvKipcbiAgICogVHJ1bmNhdGUgYnJlYWRjcnVtYiB2YWx1ZXMgKHJpZ2h0IG5vdyBqdXN0IFVSTHMpXG4gICAqL1xuICBfdHJpbUJyZWFkY3J1bWJzOiBmdW5jdGlvbihicmVhZGNydW1icykge1xuICAgIC8vIGtub3duIGJyZWFkY3J1bWIgcHJvcGVydGllcyB3aXRoIHVybHNcbiAgICAvLyBUT0RPOiBhbHNvIGNvbnNpZGVyIGFyYml0cmFyeSBwcm9wIHZhbHVlcyB0aGF0IHN0YXJ0IHdpdGggKGh0dHBzPyk/Oi8vXG4gICAgdmFyIHVybFByb3BzID0gWyd0bycsICdmcm9tJywgJ3VybCddLFxuICAgICAgdXJsUHJvcCxcbiAgICAgIGNydW1iLFxuICAgICAgZGF0YTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnJlYWRjcnVtYnMudmFsdWVzLmxlbmd0aDsgKytpKSB7XG4gICAgICBjcnVtYiA9IGJyZWFkY3J1bWJzLnZhbHVlc1tpXTtcbiAgICAgIGlmIChcbiAgICAgICAgIWNydW1iLmhhc093blByb3BlcnR5KCdkYXRhJykgfHxcbiAgICAgICAgIWlzT2JqZWN0KGNydW1iLmRhdGEpIHx8XG4gICAgICAgIG9iamVjdEZyb3plbihjcnVtYi5kYXRhKVxuICAgICAgKVxuICAgICAgICBjb250aW51ZTtcblxuICAgICAgZGF0YSA9IG9iamVjdE1lcmdlKHt9LCBjcnVtYi5kYXRhKTtcbiAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgdXJsUHJvcHMubGVuZ3RoOyArK2opIHtcbiAgICAgICAgdXJsUHJvcCA9IHVybFByb3BzW2pdO1xuICAgICAgICBpZiAoZGF0YS5oYXNPd25Qcm9wZXJ0eSh1cmxQcm9wKSAmJiBkYXRhW3VybFByb3BdKSB7XG4gICAgICAgICAgZGF0YVt1cmxQcm9wXSA9IHRydW5jYXRlKGRhdGFbdXJsUHJvcF0sIHRoaXMuX2dsb2JhbE9wdGlvbnMubWF4VXJsTGVuZ3RoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgYnJlYWRjcnVtYnMudmFsdWVzW2ldLmRhdGEgPSBkYXRhO1xuICAgIH1cbiAgfSxcblxuICBfZ2V0SHR0cERhdGE6IGZ1bmN0aW9uKCkge1xuICAgIGlmICghdGhpcy5faGFzTmF2aWdhdG9yICYmICF0aGlzLl9oYXNEb2N1bWVudCkgcmV0dXJuO1xuICAgIHZhciBodHRwRGF0YSA9IHt9O1xuXG4gICAgaWYgKHRoaXMuX2hhc05hdmlnYXRvciAmJiBfbmF2aWdhdG9yLnVzZXJBZ2VudCkge1xuICAgICAgaHR0cERhdGEuaGVhZGVycyA9IHtcbiAgICAgICAgJ1VzZXItQWdlbnQnOiBfbmF2aWdhdG9yLnVzZXJBZ2VudFxuICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyBDaGVjayBpbiBgd2luZG93YCBpbnN0ZWFkIG9mIGBkb2N1bWVudGAsIGFzIHdlIG1heSBiZSBpbiBTZXJ2aWNlV29ya2VyIGVudmlyb25tZW50XG4gICAgaWYgKF93aW5kb3cubG9jYXRpb24gJiYgX3dpbmRvdy5sb2NhdGlvbi5ocmVmKSB7XG4gICAgICBodHRwRGF0YS51cmwgPSBfd2luZG93LmxvY2F0aW9uLmhyZWY7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuX2hhc0RvY3VtZW50ICYmIF9kb2N1bWVudC5yZWZlcnJlcikge1xuICAgICAgaWYgKCFodHRwRGF0YS5oZWFkZXJzKSBodHRwRGF0YS5oZWFkZXJzID0ge307XG4gICAgICBodHRwRGF0YS5oZWFkZXJzLlJlZmVyZXIgPSBfZG9jdW1lbnQucmVmZXJyZXI7XG4gICAgfVxuXG4gICAgcmV0dXJuIGh0dHBEYXRhO1xuICB9LFxuXG4gIF9yZXNldEJhY2tvZmY6IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMuX2JhY2tvZmZEdXJhdGlvbiA9IDA7XG4gICAgdGhpcy5fYmFja29mZlN0YXJ0ID0gbnVsbDtcbiAgfSxcblxuICBfc2hvdWxkQmFja29mZjogZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuX2JhY2tvZmZEdXJhdGlvbiAmJiBub3coKSAtIHRoaXMuX2JhY2tvZmZTdGFydCA8IHRoaXMuX2JhY2tvZmZEdXJhdGlvbjtcbiAgfSxcblxuICAvKipcbiAgICogUmV0dXJucyB0cnVlIGlmIHRoZSBpbi1wcm9jZXNzIGRhdGEgcGF5bG9hZCBtYXRjaGVzIHRoZSBzaWduYXR1cmVcbiAgICogb2YgdGhlIHByZXZpb3VzbHktc2VudCBkYXRhXG4gICAqXG4gICAqIE5PVEU6IFRoaXMgaGFzIHRvIGJlIGRvbmUgYXQgdGhpcyBsZXZlbCBiZWNhdXNlIFRyYWNlS2l0IGNhbiBnZW5lcmF0ZVxuICAgKiAgICAgICBkYXRhIGZyb20gd2luZG93Lm9uZXJyb3IgV0lUSE9VVCBhbiBleGNlcHRpb24gb2JqZWN0IChJRTgsIElFOSxcbiAgICogICAgICAgb3RoZXIgb2xkIGJyb3dzZXJzKS4gVGhpcyBjYW4gdGFrZSB0aGUgZm9ybSBvZiBhbiBcImV4Y2VwdGlvblwiXG4gICAqICAgICAgIGRhdGEgb2JqZWN0IHdpdGggYSBzaW5nbGUgZnJhbWUgKGRlcml2ZWQgZnJvbSB0aGUgb25lcnJvciBhcmdzKS5cbiAgICovXG4gIF9pc1JlcGVhdERhdGE6IGZ1bmN0aW9uKGN1cnJlbnQpIHtcbiAgICB2YXIgbGFzdCA9IHRoaXMuX2xhc3REYXRhO1xuXG4gICAgaWYgKFxuICAgICAgIWxhc3QgfHxcbiAgICAgIGN1cnJlbnQubWVzc2FnZSAhPT0gbGFzdC5tZXNzYWdlIHx8IC8vIGRlZmluZWQgZm9yIGNhcHR1cmVNZXNzYWdlXG4gICAgICBjdXJyZW50LnRyYW5zYWN0aW9uICE9PSBsYXN0LnRyYW5zYWN0aW9uIC8vIGRlZmluZWQgZm9yIGNhcHR1cmVFeGNlcHRpb24vb25lcnJvclxuICAgIClcbiAgICAgIHJldHVybiBmYWxzZTtcblxuICAgIC8vIFN0YWNrdHJhY2UgaW50ZXJmYWNlIChpLmUuIGZyb20gY2FwdHVyZU1lc3NhZ2UpXG4gICAgaWYgKGN1cnJlbnQuc3RhY2t0cmFjZSB8fCBsYXN0LnN0YWNrdHJhY2UpIHtcbiAgICAgIHJldHVybiBpc1NhbWVTdGFja3RyYWNlKGN1cnJlbnQuc3RhY2t0cmFjZSwgbGFzdC5zdGFja3RyYWNlKTtcbiAgICB9IGVsc2UgaWYgKGN1cnJlbnQuZXhjZXB0aW9uIHx8IGxhc3QuZXhjZXB0aW9uKSB7XG4gICAgICAvLyBFeGNlcHRpb24gaW50ZXJmYWNlIChpLmUuIGZyb20gY2FwdHVyZUV4Y2VwdGlvbi9vbmVycm9yKVxuICAgICAgcmV0dXJuIGlzU2FtZUV4Y2VwdGlvbihjdXJyZW50LmV4Y2VwdGlvbiwgbGFzdC5leGNlcHRpb24pO1xuICAgIH0gZWxzZSBpZiAoY3VycmVudC5maW5nZXJwcmludCB8fCBsYXN0LmZpbmdlcnByaW50KSB7XG4gICAgICByZXR1cm4gQm9vbGVhbihjdXJyZW50LmZpbmdlcnByaW50ICYmIGxhc3QuZmluZ2VycHJpbnQpICYmXG4gICAgICAgIEpTT04uc3RyaW5naWZ5KGN1cnJlbnQuZmluZ2VycHJpbnQpID09PSBKU09OLnN0cmluZ2lmeShsYXN0LmZpbmdlcnByaW50KVxuICAgIH1cblxuICAgIHJldHVybiB0cnVlO1xuICB9LFxuXG4gIF9zZXRCYWNrb2ZmU3RhdGU6IGZ1bmN0aW9uKHJlcXVlc3QpIHtcbiAgICAvLyBJZiB3ZSBhcmUgYWxyZWFkeSBpbiBhIGJhY2tvZmYgc3RhdGUsIGRvbid0IGNoYW5nZSBhbnl0aGluZ1xuICAgIGlmICh0aGlzLl9zaG91bGRCYWNrb2ZmKCkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICB2YXIgc3RhdHVzID0gcmVxdWVzdC5zdGF0dXM7XG5cbiAgICAvLyA0MDAgLSBwcm9qZWN0X2lkIGRvZXNuJ3QgZXhpc3Qgb3Igc29tZSBvdGhlciBmYXRhbFxuICAgIC8vIDQwMSAtIGludmFsaWQvcmV2b2tlZCBkc25cbiAgICAvLyA0MjkgLSB0b28gbWFueSByZXF1ZXN0c1xuICAgIGlmICghKHN0YXR1cyA9PT0gNDAwIHx8IHN0YXR1cyA9PT0gNDAxIHx8IHN0YXR1cyA9PT0gNDI5KSkgcmV0dXJuO1xuXG4gICAgdmFyIHJldHJ5O1xuICAgIHRyeSB7XG4gICAgICAvLyBJZiBSZXRyeS1BZnRlciBpcyBub3QgaW4gQWNjZXNzLUNvbnRyb2wtRXhwb3NlLUhlYWRlcnMsIG1vc3RcbiAgICAgIC8vIGJyb3dzZXJzIHdpbGwgdGhyb3cgYW4gZXhjZXB0aW9uIHRyeWluZyB0byBhY2Nlc3MgaXRcbiAgICAgIGlmIChzdXBwb3J0c0ZldGNoKCkpIHtcbiAgICAgICAgcmV0cnkgPSByZXF1ZXN0LmhlYWRlcnMuZ2V0KCdSZXRyeS1BZnRlcicpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0cnkgPSByZXF1ZXN0LmdldFJlc3BvbnNlSGVhZGVyKCdSZXRyeS1BZnRlcicpO1xuICAgICAgfVxuXG4gICAgICAvLyBSZXRyeS1BZnRlciBpcyByZXR1cm5lZCBpbiBzZWNvbmRzXG4gICAgICByZXRyeSA9IHBhcnNlSW50KHJldHJ5LCAxMCkgKiAxMDAwO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIC8qIGVzbGludCBuby1lbXB0eTowICovXG4gICAgfVxuXG4gICAgdGhpcy5fYmFja29mZkR1cmF0aW9uID0gcmV0cnlcbiAgICAgID8gLy8gSWYgU2VudHJ5IHNlcnZlciByZXR1cm5lZCBhIFJldHJ5LUFmdGVyIHZhbHVlLCB1c2UgaXRcbiAgICAgICAgcmV0cnlcbiAgICAgIDogLy8gT3RoZXJ3aXNlLCBkb3VibGUgdGhlIGxhc3QgYmFja29mZiBkdXJhdGlvbiAoc3RhcnRzIGF0IDEgc2VjKVxuICAgICAgICB0aGlzLl9iYWNrb2ZmRHVyYXRpb24gKiAyIHx8IDEwMDA7XG5cbiAgICB0aGlzLl9iYWNrb2ZmU3RhcnQgPSBub3coKTtcbiAgfSxcblxuICBfc2VuZDogZnVuY3Rpb24oZGF0YSkge1xuICAgIHZhciBnbG9iYWxPcHRpb25zID0gdGhpcy5fZ2xvYmFsT3B0aW9ucztcblxuICAgIHZhciBiYXNlRGF0YSA9IHtcbiAgICAgICAgcHJvamVjdDogdGhpcy5fZ2xvYmFsUHJvamVjdCxcbiAgICAgICAgbG9nZ2VyOiBnbG9iYWxPcHRpb25zLmxvZ2dlcixcbiAgICAgICAgcGxhdGZvcm06ICdqYXZhc2NyaXB0J1xuICAgICAgfSxcbiAgICAgIGh0dHBEYXRhID0gdGhpcy5fZ2V0SHR0cERhdGEoKTtcblxuICAgIGlmIChodHRwRGF0YSkge1xuICAgICAgYmFzZURhdGEucmVxdWVzdCA9IGh0dHBEYXRhO1xuICAgIH1cblxuICAgIC8vIEhBQ0s6IGRlbGV0ZSBgdHJpbUhlYWRGcmFtZXNgIHRvIHByZXZlbnQgZnJvbSBhcHBlYXJpbmcgaW4gb3V0Ym91bmQgcGF5bG9hZFxuICAgIGlmIChkYXRhLnRyaW1IZWFkRnJhbWVzKSBkZWxldGUgZGF0YS50cmltSGVhZEZyYW1lcztcblxuICAgIGRhdGEgPSBvYmplY3RNZXJnZShiYXNlRGF0YSwgZGF0YSk7XG5cbiAgICAvLyBNZXJnZSBpbiB0aGUgdGFncyBhbmQgZXh0cmEgc2VwYXJhdGVseSBzaW5jZSBvYmplY3RNZXJnZSBkb2Vzbid0IGhhbmRsZSBhIGRlZXAgbWVyZ2VcbiAgICBkYXRhLnRhZ3MgPSBvYmplY3RNZXJnZShvYmplY3RNZXJnZSh7fSwgdGhpcy5fZ2xvYmFsQ29udGV4dC50YWdzKSwgZGF0YS50YWdzKTtcbiAgICBkYXRhLmV4dHJhID0gb2JqZWN0TWVyZ2Uob2JqZWN0TWVyZ2Uoe30sIHRoaXMuX2dsb2JhbENvbnRleHQuZXh0cmEpLCBkYXRhLmV4dHJhKTtcblxuICAgIC8vIFNlbmQgYWxvbmcgb3VyIG93biBjb2xsZWN0ZWQgbWV0YWRhdGEgd2l0aCBleHRyYVxuICAgIGRhdGEuZXh0cmFbJ3Nlc3Npb246ZHVyYXRpb24nXSA9IG5vdygpIC0gdGhpcy5fc3RhcnRUaW1lO1xuXG4gICAgaWYgKHRoaXMuX2JyZWFkY3J1bWJzICYmIHRoaXMuX2JyZWFkY3J1bWJzLmxlbmd0aCA+IDApIHtcbiAgICAgIC8vIGludGVudGlvbmFsbHkgbWFrZSBzaGFsbG93IGNvcHkgc28gdGhhdCBhZGRpdGlvbnNcbiAgICAgIC8vIHRvIGJyZWFkY3J1bWJzIGFyZW4ndCBhY2NpZGVudGFsbHkgc2VudCBpbiB0aGlzIHJlcXVlc3RcbiAgICAgIGRhdGEuYnJlYWRjcnVtYnMgPSB7XG4gICAgICAgIHZhbHVlczogW10uc2xpY2UuY2FsbCh0aGlzLl9icmVhZGNydW1icywgMClcbiAgICAgIH07XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuX2dsb2JhbENvbnRleHQudXNlcikge1xuICAgICAgLy8gc2VudHJ5LmludGVyZmFjZXMuVXNlclxuICAgICAgZGF0YS51c2VyID0gdGhpcy5fZ2xvYmFsQ29udGV4dC51c2VyO1xuICAgIH1cblxuICAgIC8vIEluY2x1ZGUgdGhlIGVudmlyb25tZW50IGlmIGl0J3MgZGVmaW5lZCBpbiBnbG9iYWxPcHRpb25zXG4gICAgaWYgKGdsb2JhbE9wdGlvbnMuZW52aXJvbm1lbnQpIGRhdGEuZW52aXJvbm1lbnQgPSBnbG9iYWxPcHRpb25zLmVudmlyb25tZW50O1xuXG4gICAgLy8gSW5jbHVkZSB0aGUgcmVsZWFzZSBpZiBpdCdzIGRlZmluZWQgaW4gZ2xvYmFsT3B0aW9uc1xuICAgIGlmIChnbG9iYWxPcHRpb25zLnJlbGVhc2UpIGRhdGEucmVsZWFzZSA9IGdsb2JhbE9wdGlvbnMucmVsZWFzZTtcblxuICAgIC8vIEluY2x1ZGUgc2VydmVyX25hbWUgaWYgaXQncyBkZWZpbmVkIGluIGdsb2JhbE9wdGlvbnNcbiAgICBpZiAoZ2xvYmFsT3B0aW9ucy5zZXJ2ZXJOYW1lKSBkYXRhLnNlcnZlcl9uYW1lID0gZ2xvYmFsT3B0aW9ucy5zZXJ2ZXJOYW1lO1xuXG4gICAgZGF0YSA9IHRoaXMuX3Nhbml0aXplRGF0YShkYXRhKTtcblxuICAgIC8vIENsZWFudXAgZW1wdHkgcHJvcGVydGllcyBiZWZvcmUgc2VuZGluZyB0aGVtIHRvIHRoZSBzZXJ2ZXJcbiAgICBPYmplY3Qua2V5cyhkYXRhKS5mb3JFYWNoKGZ1bmN0aW9uKGtleSkge1xuICAgICAgaWYgKGRhdGFba2V5XSA9PSBudWxsIHx8IGRhdGFba2V5XSA9PT0gJycgfHwgaXNFbXB0eU9iamVjdChkYXRhW2tleV0pKSB7XG4gICAgICAgIGRlbGV0ZSBkYXRhW2tleV07XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBpZiAoaXNGdW5jdGlvbihnbG9iYWxPcHRpb25zLmRhdGFDYWxsYmFjaykpIHtcbiAgICAgIGRhdGEgPSBnbG9iYWxPcHRpb25zLmRhdGFDYWxsYmFjayhkYXRhKSB8fCBkYXRhO1xuICAgIH1cblxuICAgIC8vIFdoeT8/Pz8/Pz8/Pz9cbiAgICBpZiAoIWRhdGEgfHwgaXNFbXB0eU9iamVjdChkYXRhKSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIENoZWNrIGlmIHRoZSByZXF1ZXN0IHNob3VsZCBiZSBmaWx0ZXJlZCBvciBub3RcbiAgICBpZiAoXG4gICAgICBpc0Z1bmN0aW9uKGdsb2JhbE9wdGlvbnMuc2hvdWxkU2VuZENhbGxiYWNrKSAmJlxuICAgICAgIWdsb2JhbE9wdGlvbnMuc2hvdWxkU2VuZENhbGxiYWNrKGRhdGEpXG4gICAgKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gQmFja29mZiBzdGF0ZTogU2VudHJ5IHNlcnZlciBwcmV2aW91c2x5IHJlc3BvbmRlZCB3LyBhbiBlcnJvciAoZS5nLiA0MjkgLSB0b28gbWFueSByZXF1ZXN0cyksXG4gICAgLy8gc28gZHJvcCByZXF1ZXN0cyB1bnRpbCBcImNvb2wtb2ZmXCIgcGVyaW9kIGhhcyBlbGFwc2VkLlxuICAgIGlmICh0aGlzLl9zaG91bGRCYWNrb2ZmKCkpIHtcbiAgICAgIHRoaXMuX2xvZ0RlYnVnKCd3YXJuJywgJ1JhdmVuIGRyb3BwZWQgZXJyb3IgZHVlIHRvIGJhY2tvZmY6ICcsIGRhdGEpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgZ2xvYmFsT3B0aW9ucy5zYW1wbGVSYXRlID09PSAnbnVtYmVyJykge1xuICAgICAgaWYgKE1hdGgucmFuZG9tKCkgPCBnbG9iYWxPcHRpb25zLnNhbXBsZVJhdGUpIHtcbiAgICAgICAgdGhpcy5fc2VuZFByb2Nlc3NlZFBheWxvYWQoZGF0YSk7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuX3NlbmRQcm9jZXNzZWRQYXlsb2FkKGRhdGEpO1xuICAgIH1cbiAgfSxcblxuICBfc2FuaXRpemVEYXRhOiBmdW5jdGlvbihkYXRhKSB7XG4gICAgcmV0dXJuIHNhbml0aXplKGRhdGEsIHRoaXMuX2dsb2JhbE9wdGlvbnMuc2FuaXRpemVLZXlzKTtcbiAgfSxcblxuICBfZ2V0VXVpZDogZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHV1aWQ0KCk7XG4gIH0sXG5cbiAgX3NlbmRQcm9jZXNzZWRQYXlsb2FkOiBmdW5jdGlvbihkYXRhLCBjYWxsYmFjaykge1xuICAgIHZhciBzZWxmID0gdGhpcztcbiAgICB2YXIgZ2xvYmFsT3B0aW9ucyA9IHRoaXMuX2dsb2JhbE9wdGlvbnM7XG5cbiAgICBpZiAoIXRoaXMuaXNTZXR1cCgpKSByZXR1cm47XG5cbiAgICAvLyBUcnkgYW5kIGNsZWFuIHVwIHRoZSBwYWNrZXQgYmVmb3JlIHNlbmRpbmcgYnkgdHJ1bmNhdGluZyBsb25nIHZhbHVlc1xuICAgIGRhdGEgPSB0aGlzLl90cmltUGFja2V0KGRhdGEpO1xuXG4gICAgLy8gaWRlYWxseSBkdXBsaWNhdGUgZXJyb3IgdGVzdGluZyBzaG91bGQgb2NjdXIgKmJlZm9yZSogZGF0YUNhbGxiYWNrL3Nob3VsZFNlbmRDYWxsYmFjayxcbiAgICAvLyBidXQgdGhpcyB3b3VsZCByZXF1aXJlIGNvcHlpbmcgYW4gdW4tdHJ1bmNhdGVkIGNvcHkgb2YgdGhlIGRhdGEgcGFja2V0LCB3aGljaCBjYW4gYmVcbiAgICAvLyBhcmJpdHJhcmlseSBkZWVwIChleHRyYV9kYXRhKSAtLSBjb3VsZCBiZSB3b3J0aHdoaWxlPyB3aWxsIHJldmlzaXRcbiAgICBpZiAoIXRoaXMuX2dsb2JhbE9wdGlvbnMuYWxsb3dEdXBsaWNhdGVzICYmIHRoaXMuX2lzUmVwZWF0RGF0YShkYXRhKSkge1xuICAgICAgdGhpcy5fbG9nRGVidWcoJ3dhcm4nLCAnUmF2ZW4gZHJvcHBlZCByZXBlYXQgZXZlbnQ6ICcsIGRhdGEpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIFNlbmQgYWxvbmcgYW4gZXZlbnRfaWQgaWYgbm90IGV4cGxpY2l0bHkgcGFzc2VkLlxuICAgIC8vIFRoaXMgZXZlbnRfaWQgY2FuIGJlIHVzZWQgdG8gcmVmZXJlbmNlIHRoZSBlcnJvciB3aXRoaW4gU2VudHJ5IGl0c2VsZi5cbiAgICAvLyBTZXQgbGFzdEV2ZW50SWQgYWZ0ZXIgd2Uga25vdyB0aGUgZXJyb3Igc2hvdWxkIGFjdHVhbGx5IGJlIHNlbnRcbiAgICB0aGlzLl9sYXN0RXZlbnRJZCA9IGRhdGEuZXZlbnRfaWQgfHwgKGRhdGEuZXZlbnRfaWQgPSB0aGlzLl9nZXRVdWlkKCkpO1xuXG4gICAgLy8gU3RvcmUgb3V0Ym91bmQgcGF5bG9hZCBhZnRlciB0cmltXG4gICAgdGhpcy5fbGFzdERhdGEgPSBkYXRhO1xuXG4gICAgdGhpcy5fbG9nRGVidWcoJ2RlYnVnJywgJ1JhdmVuIGFib3V0IHRvIHNlbmQ6JywgZGF0YSk7XG5cbiAgICB2YXIgYXV0aCA9IHtcbiAgICAgIHNlbnRyeV92ZXJzaW9uOiAnNycsXG4gICAgICBzZW50cnlfY2xpZW50OiAncmF2ZW4tanMvJyArIHRoaXMuVkVSU0lPTixcbiAgICAgIHNlbnRyeV9rZXk6IHRoaXMuX2dsb2JhbEtleVxuICAgIH07XG5cbiAgICBpZiAodGhpcy5fZ2xvYmFsU2VjcmV0KSB7XG4gICAgICBhdXRoLnNlbnRyeV9zZWNyZXQgPSB0aGlzLl9nbG9iYWxTZWNyZXQ7XG4gICAgfVxuXG4gICAgdmFyIGV4Y2VwdGlvbiA9IGRhdGEuZXhjZXB0aW9uICYmIGRhdGEuZXhjZXB0aW9uLnZhbHVlc1swXTtcblxuICAgIC8vIG9ubHkgY2FwdHVyZSAnc2VudHJ5JyBicmVhZGNydW1iIGlzIGF1dG9CcmVhZGNydW1icyBpcyB0cnV0aHlcbiAgICBpZiAoXG4gICAgICB0aGlzLl9nbG9iYWxPcHRpb25zLmF1dG9CcmVhZGNydW1icyAmJlxuICAgICAgdGhpcy5fZ2xvYmFsT3B0aW9ucy5hdXRvQnJlYWRjcnVtYnMuc2VudHJ5XG4gICAgKSB7XG4gICAgICB0aGlzLmNhcHR1cmVCcmVhZGNydW1iKHtcbiAgICAgICAgY2F0ZWdvcnk6ICdzZW50cnknLFxuICAgICAgICBtZXNzYWdlOiBleGNlcHRpb25cbiAgICAgICAgICA/IChleGNlcHRpb24udHlwZSA/IGV4Y2VwdGlvbi50eXBlICsgJzogJyA6ICcnKSArIGV4Y2VwdGlvbi52YWx1ZVxuICAgICAgICAgIDogZGF0YS5tZXNzYWdlLFxuICAgICAgICBldmVudF9pZDogZGF0YS5ldmVudF9pZCxcbiAgICAgICAgbGV2ZWw6IGRhdGEubGV2ZWwgfHwgJ2Vycm9yJyAvLyBwcmVzdW1lIGVycm9yIHVubGVzcyBzcGVjaWZpZWRcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHZhciB1cmwgPSB0aGlzLl9nbG9iYWxFbmRwb2ludDtcbiAgICAoZ2xvYmFsT3B0aW9ucy50cmFuc3BvcnQgfHwgdGhpcy5fbWFrZVJlcXVlc3QpLmNhbGwodGhpcywge1xuICAgICAgdXJsOiB1cmwsXG4gICAgICBhdXRoOiBhdXRoLFxuICAgICAgZGF0YTogZGF0YSxcbiAgICAgIG9wdGlvbnM6IGdsb2JhbE9wdGlvbnMsXG4gICAgICBvblN1Y2Nlc3M6IGZ1bmN0aW9uIHN1Y2Nlc3MoKSB7XG4gICAgICAgIHNlbGYuX3Jlc2V0QmFja29mZigpO1xuXG4gICAgICAgIHNlbGYuX3RyaWdnZXJFdmVudCgnc3VjY2VzcycsIHtcbiAgICAgICAgICBkYXRhOiBkYXRhLFxuICAgICAgICAgIHNyYzogdXJsXG4gICAgICAgIH0pO1xuICAgICAgICBjYWxsYmFjayAmJiBjYWxsYmFjaygpO1xuICAgICAgfSxcbiAgICAgIG9uRXJyb3I6IGZ1bmN0aW9uIGZhaWx1cmUoZXJyb3IpIHtcbiAgICAgICAgc2VsZi5fbG9nRGVidWcoJ2Vycm9yJywgJ1JhdmVuIHRyYW5zcG9ydCBmYWlsZWQgdG8gc2VuZDogJywgZXJyb3IpO1xuXG4gICAgICAgIGlmIChlcnJvci5yZXF1ZXN0KSB7XG4gICAgICAgICAgc2VsZi5fc2V0QmFja29mZlN0YXRlKGVycm9yLnJlcXVlc3QpO1xuICAgICAgICB9XG5cbiAgICAgICAgc2VsZi5fdHJpZ2dlckV2ZW50KCdmYWlsdXJlJywge1xuICAgICAgICAgIGRhdGE6IGRhdGEsXG4gICAgICAgICAgc3JjOiB1cmxcbiAgICAgICAgfSk7XG4gICAgICAgIGVycm9yID0gZXJyb3IgfHwgbmV3IEVycm9yKCdSYXZlbiBzZW5kIGZhaWxlZCAobm8gYWRkaXRpb25hbCBkZXRhaWxzIHByb3ZpZGVkKScpO1xuICAgICAgICBjYWxsYmFjayAmJiBjYWxsYmFjayhlcnJvcik7XG4gICAgICB9XG4gICAgfSk7XG4gIH0sXG5cbiAgX21ha2VSZXF1ZXN0OiBmdW5jdGlvbihvcHRzKSB7XG4gICAgLy8gQXV0aCBpcyBpbnRlbnRpb25hbGx5IHNlbnQgYXMgcGFydCBvZiBxdWVyeSBzdHJpbmcgKE5PVCBhcyBjdXN0b20gSFRUUCBoZWFkZXIpIHRvIGF2b2lkIHByZWZsaWdodCBDT1JTIHJlcXVlc3RzXG4gICAgdmFyIHVybCA9IG9wdHMudXJsICsgJz8nICsgdXJsZW5jb2RlKG9wdHMuYXV0aCk7XG5cbiAgICB2YXIgZXZhbHVhdGVkSGVhZGVycyA9IG51bGw7XG4gICAgdmFyIGV2YWx1YXRlZEZldGNoUGFyYW1ldGVycyA9IHt9O1xuXG4gICAgaWYgKG9wdHMub3B0aW9ucy5oZWFkZXJzKSB7XG4gICAgICBldmFsdWF0ZWRIZWFkZXJzID0gdGhpcy5fZXZhbHVhdGVIYXNoKG9wdHMub3B0aW9ucy5oZWFkZXJzKTtcbiAgICB9XG5cbiAgICBpZiAob3B0cy5vcHRpb25zLmZldGNoUGFyYW1ldGVycykge1xuICAgICAgZXZhbHVhdGVkRmV0Y2hQYXJhbWV0ZXJzID0gdGhpcy5fZXZhbHVhdGVIYXNoKG9wdHMub3B0aW9ucy5mZXRjaFBhcmFtZXRlcnMpO1xuICAgIH1cblxuICAgIGlmIChzdXBwb3J0c0ZldGNoKCkpIHtcbiAgICAgIGV2YWx1YXRlZEZldGNoUGFyYW1ldGVycy5ib2R5ID0gc3RyaW5naWZ5KG9wdHMuZGF0YSk7XG5cbiAgICAgIHZhciBkZWZhdWx0RmV0Y2hPcHRpb25zID0gb2JqZWN0TWVyZ2Uoe30sIHRoaXMuX2ZldGNoRGVmYXVsdHMpO1xuICAgICAgdmFyIGZldGNoT3B0aW9ucyA9IG9iamVjdE1lcmdlKGRlZmF1bHRGZXRjaE9wdGlvbnMsIGV2YWx1YXRlZEZldGNoUGFyYW1ldGVycyk7XG5cbiAgICAgIGlmIChldmFsdWF0ZWRIZWFkZXJzKSB7XG4gICAgICAgIGZldGNoT3B0aW9ucy5oZWFkZXJzID0gZXZhbHVhdGVkSGVhZGVycztcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIF93aW5kb3dcbiAgICAgICAgLmZldGNoKHVybCwgZmV0Y2hPcHRpb25zKVxuICAgICAgICAudGhlbihmdW5jdGlvbihyZXNwb25zZSkge1xuICAgICAgICAgIGlmIChyZXNwb25zZS5vaykge1xuICAgICAgICAgICAgb3B0cy5vblN1Y2Nlc3MgJiYgb3B0cy5vblN1Y2Nlc3MoKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdmFyIGVycm9yID0gbmV3IEVycm9yKCdTZW50cnkgZXJyb3IgY29kZTogJyArIHJlc3BvbnNlLnN0YXR1cyk7XG4gICAgICAgICAgICAvLyBJdCdzIGNhbGxlZCByZXF1ZXN0IG9ubHkgdG8ga2VlcCBjb21wYXRpYmlsaXR5IHdpdGggWEhSIGludGVyZmFjZVxuICAgICAgICAgICAgLy8gYW5kIG5vdCBhZGQgbW9yZSByZWR1bmRhbnQgY2hlY2tzIGluIHNldEJhY2tvZmZTdGF0ZSBtZXRob2RcbiAgICAgICAgICAgIGVycm9yLnJlcXVlc3QgPSByZXNwb25zZTtcbiAgICAgICAgICAgIG9wdHMub25FcnJvciAmJiBvcHRzLm9uRXJyb3IoZXJyb3IpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSlcbiAgICAgICAgWydjYXRjaCddKGZ1bmN0aW9uKCkge1xuICAgICAgICAgIG9wdHMub25FcnJvciAmJlxuICAgICAgICAgICAgb3B0cy5vbkVycm9yKG5ldyBFcnJvcignU2VudHJ5IGVycm9yIGNvZGU6IG5ldHdvcmsgdW5hdmFpbGFibGUnKSk7XG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIHZhciByZXF1ZXN0ID0gX3dpbmRvdy5YTUxIdHRwUmVxdWVzdCAmJiBuZXcgX3dpbmRvdy5YTUxIdHRwUmVxdWVzdCgpO1xuICAgIGlmICghcmVxdWVzdCkgcmV0dXJuO1xuXG4gICAgLy8gaWYgYnJvd3NlciBkb2Vzbid0IHN1cHBvcnQgQ09SUyAoZS5nLiBJRTcpLCB3ZSBhcmUgb3V0IG9mIGx1Y2tcbiAgICB2YXIgaGFzQ09SUyA9ICd3aXRoQ3JlZGVudGlhbHMnIGluIHJlcXVlc3QgfHwgdHlwZW9mIFhEb21haW5SZXF1ZXN0ICE9PSAndW5kZWZpbmVkJztcblxuICAgIGlmICghaGFzQ09SUykgcmV0dXJuO1xuXG4gICAgaWYgKCd3aXRoQ3JlZGVudGlhbHMnIGluIHJlcXVlc3QpIHtcbiAgICAgIHJlcXVlc3Qub25yZWFkeXN0YXRlY2hhbmdlID0gZnVuY3Rpb24oKSB7XG4gICAgICAgIGlmIChyZXF1ZXN0LnJlYWR5U3RhdGUgIT09IDQpIHtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH0gZWxzZSBpZiAocmVxdWVzdC5zdGF0dXMgPT09IDIwMCkge1xuICAgICAgICAgIG9wdHMub25TdWNjZXNzICYmIG9wdHMub25TdWNjZXNzKCk7XG4gICAgICAgIH0gZWxzZSBpZiAob3B0cy5vbkVycm9yKSB7XG4gICAgICAgICAgdmFyIGVyciA9IG5ldyBFcnJvcignU2VudHJ5IGVycm9yIGNvZGU6ICcgKyByZXF1ZXN0LnN0YXR1cyk7XG4gICAgICAgICAgZXJyLnJlcXVlc3QgPSByZXF1ZXN0O1xuICAgICAgICAgIG9wdHMub25FcnJvcihlcnIpO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH0gZWxzZSB7XG4gICAgICByZXF1ZXN0ID0gbmV3IFhEb21haW5SZXF1ZXN0KCk7XG4gICAgICAvLyB4ZG9tYWlucmVxdWVzdCBjYW5ub3QgZ28gaHR0cCAtPiBodHRwcyAob3IgdmljZSB2ZXJzYSksXG4gICAgICAvLyBzbyBhbHdheXMgdXNlIHByb3RvY29sIHJlbGF0aXZlXG4gICAgICB1cmwgPSB1cmwucmVwbGFjZSgvXmh0dHBzPzovLCAnJyk7XG5cbiAgICAgIC8vIG9ucmVhZHlzdGF0ZWNoYW5nZSBub3Qgc3VwcG9ydGVkIGJ5IFhEb21haW5SZXF1ZXN0XG4gICAgICBpZiAob3B0cy5vblN1Y2Nlc3MpIHtcbiAgICAgICAgcmVxdWVzdC5vbmxvYWQgPSBvcHRzLm9uU3VjY2VzcztcbiAgICAgIH1cbiAgICAgIGlmIChvcHRzLm9uRXJyb3IpIHtcbiAgICAgICAgcmVxdWVzdC5vbmVycm9yID0gZnVuY3Rpb24oKSB7XG4gICAgICAgICAgdmFyIGVyciA9IG5ldyBFcnJvcignU2VudHJ5IGVycm9yIGNvZGU6IFhEb21haW5SZXF1ZXN0Jyk7XG4gICAgICAgICAgZXJyLnJlcXVlc3QgPSByZXF1ZXN0O1xuICAgICAgICAgIG9wdHMub25FcnJvcihlcnIpO1xuICAgICAgICB9O1xuICAgICAgfVxuICAgIH1cblxuICAgIHJlcXVlc3Qub3BlbignUE9TVCcsIHVybCk7XG5cbiAgICBpZiAoZXZhbHVhdGVkSGVhZGVycykge1xuICAgICAgZWFjaChldmFsdWF0ZWRIZWFkZXJzLCBmdW5jdGlvbihrZXksIHZhbHVlKSB7XG4gICAgICAgIHJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcihrZXksIHZhbHVlKTtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHJlcXVlc3Quc2VuZChzdHJpbmdpZnkob3B0cy5kYXRhKSk7XG4gIH0sXG5cbiAgX2V2YWx1YXRlSGFzaDogZnVuY3Rpb24oaGFzaCkge1xuICAgIHZhciBldmFsdWF0ZWQgPSB7fTtcblxuICAgIGZvciAodmFyIGtleSBpbiBoYXNoKSB7XG4gICAgICBpZiAoaGFzaC5oYXNPd25Qcm9wZXJ0eShrZXkpKSB7XG4gICAgICAgIHZhciB2YWx1ZSA9IGhhc2hba2V5XTtcbiAgICAgICAgZXZhbHVhdGVkW2tleV0gPSB0eXBlb2YgdmFsdWUgPT09ICdmdW5jdGlvbicgPyB2YWx1ZSgpIDogdmFsdWU7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIGV2YWx1YXRlZDtcbiAgfSxcblxuICBfbG9nRGVidWc6IGZ1bmN0aW9uKGxldmVsKSB7XG4gICAgLy8gV2UgYWxsb3cgYFJhdmVuLmRlYnVnYCBhbmQgYFJhdmVuLmNvbmZpZyhEU04sIHsgZGVidWc6IHRydWUgfSlgIHRvIG5vdCBtYWtlIGJhY2t3YXJkIGluY29tcGF0aWJsZSBBUEkgY2hhbmdlXG4gICAgaWYgKFxuICAgICAgdGhpcy5fb3JpZ2luYWxDb25zb2xlTWV0aG9kc1tsZXZlbF0gJiZcbiAgICAgICh0aGlzLmRlYnVnIHx8IHRoaXMuX2dsb2JhbE9wdGlvbnMuZGVidWcpXG4gICAgKSB7XG4gICAgICAvLyBJbiBJRTwxMCBjb25zb2xlIG1ldGhvZHMgZG8gbm90IGhhdmUgdGhlaXIgb3duICdhcHBseScgbWV0aG9kXG4gICAgICBGdW5jdGlvbi5wcm90b3R5cGUuYXBwbHkuY2FsbChcbiAgICAgICAgdGhpcy5fb3JpZ2luYWxDb25zb2xlTWV0aG9kc1tsZXZlbF0sXG4gICAgICAgIHRoaXMuX29yaWdpbmFsQ29uc29sZSxcbiAgICAgICAgW10uc2xpY2UuY2FsbChhcmd1bWVudHMsIDEpXG4gICAgICApO1xuICAgIH1cbiAgfSxcblxuICBfbWVyZ2VDb250ZXh0OiBmdW5jdGlvbihrZXksIGNvbnRleHQpIHtcbiAgICBpZiAoaXNVbmRlZmluZWQoY29udGV4dCkpIHtcbiAgICAgIGRlbGV0ZSB0aGlzLl9nbG9iYWxDb250ZXh0W2tleV07XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuX2dsb2JhbENvbnRleHRba2V5XSA9IG9iamVjdE1lcmdlKHRoaXMuX2dsb2JhbENvbnRleHRba2V5XSB8fCB7fSwgY29udGV4dCk7XG4gICAgfVxuICB9XG59O1xuXG4vLyBEZXByZWNhdGlvbnNcblJhdmVuLnByb3RvdHlwZS5zZXRVc2VyID0gUmF2ZW4ucHJvdG90eXBlLnNldFVzZXJDb250ZXh0O1xuUmF2ZW4ucHJvdG90eXBlLnNldFJlbGVhc2VDb250ZXh0ID0gUmF2ZW4ucHJvdG90eXBlLnNldFJlbGVhc2U7XG5cbm1vZHVsZS5leHBvcnRzID0gUmF2ZW47XG4iLCIvKipcbiAqIEVuZm9yY2VzIGEgc2luZ2xlIGluc3RhbmNlIG9mIHRoZSBSYXZlbiBjbGllbnQsIGFuZCB0aGVcbiAqIG1haW4gZW50cnkgcG9pbnQgZm9yIFJhdmVuLiBJZiB5b3UgYXJlIGEgY29uc3VtZXIgb2YgdGhlXG4gKiBSYXZlbiBsaWJyYXJ5LCB5b3UgU0hPVUxEIGxvYWQgdGhpcyBmaWxlICh2cyByYXZlbi5qcykuXG4gKiovXG5cbnZhciBSYXZlbkNvbnN0cnVjdG9yID0gcmVxdWlyZSgnLi9yYXZlbicpO1xuXG4vLyBUaGlzIGlzIHRvIGJlIGRlZmVuc2l2ZSBpbiBlbnZpcm9ubWVudHMgd2hlcmUgd2luZG93IGRvZXMgbm90IGV4aXN0IChzZWUgaHR0cHM6Ly9naXRodWIuY29tL2dldHNlbnRyeS9yYXZlbi1qcy9wdWxsLzc4NSlcbnZhciBfd2luZG93ID1cbiAgdHlwZW9mIHdpbmRvdyAhPT0gJ3VuZGVmaW5lZCdcbiAgICA/IHdpbmRvd1xuICAgIDogdHlwZW9mIGdsb2JhbCAhPT0gJ3VuZGVmaW5lZCcgPyBnbG9iYWwgOiB0eXBlb2Ygc2VsZiAhPT0gJ3VuZGVmaW5lZCcgPyBzZWxmIDoge307XG52YXIgX1JhdmVuID0gX3dpbmRvdy5SYXZlbjtcblxudmFyIFJhdmVuID0gbmV3IFJhdmVuQ29uc3RydWN0b3IoKTtcblxuLypcbiAqIEFsbG93IG11bHRpcGxlIHZlcnNpb25zIG9mIFJhdmVuIHRvIGJlIGluc3RhbGxlZC5cbiAqIFN0cmlwIFJhdmVuIGZyb20gdGhlIGdsb2JhbCBjb250ZXh0IGFuZCByZXR1cm5zIHRoZSBpbnN0YW5jZS5cbiAqXG4gKiBAcmV0dXJuIHtSYXZlbn1cbiAqL1xuUmF2ZW4ubm9Db25mbGljdCA9IGZ1bmN0aW9uKCkge1xuICBfd2luZG93LlJhdmVuID0gX1JhdmVuO1xuICByZXR1cm4gUmF2ZW47XG59O1xuXG5SYXZlbi5hZnRlckxvYWQoKTtcblxubW9kdWxlLmV4cG9ydHMgPSBSYXZlbjtcblxuLyoqXG4gKiBESVNDTEFJTUVSOlxuICpcbiAqIEV4cG9zZSBgQ2xpZW50YCBjb25zdHJ1Y3RvciBmb3IgY2FzZXMgd2hlcmUgdXNlciB3YW50IHRvIHRyYWNrIG11bHRpcGxlIFwic3ViLWFwcGxpY2F0aW9uc1wiIGluIG9uZSBsYXJnZXIgYXBwLlxuICogSXQncyBub3QgbWVhbnQgdG8gYmUgdXNlZCBieSBhIHdpZGUgYXVkaWVuY2UsIHNvIHBsZWFhYXNlIG1ha2Ugc3VyZSB0aGF0IHlvdSBrbm93IHdoYXQgeW91J3JlIGRvaW5nIGJlZm9yZSB1c2luZyBpdC5cbiAqIEFjY2lkZW50YWxseSBjYWxsaW5nIGBpbnN0YWxsYCBtdWx0aXBsZSB0aW1lcywgbWF5IHJlc3VsdCBpbiBhbiB1bmV4cGVjdGVkIGJlaGF2aW9yIHRoYXQncyB2ZXJ5IGhhcmQgdG8gZGVidWcuXG4gKlxuICogSXQncyBjYWxsZWQgYENsaWVudCcgdG8gYmUgaW4tbGluZSB3aXRoIFJhdmVuIE5vZGUgaW1wbGVtZW50YXRpb24uXG4gKlxuICogSE9XVE86XG4gKlxuICogaW1wb3J0IFJhdmVuIGZyb20gJ3JhdmVuLWpzJztcbiAqXG4gKiBjb25zdCBzb21lQXBwUmVwb3J0ZXIgPSBuZXcgUmF2ZW4uQ2xpZW50KCk7XG4gKiBjb25zdCBzb21lT3RoZXJBcHBSZXBvcnRlciA9IG5ldyBSYXZlbi5DbGllbnQoKTtcbiAqXG4gKiBzb21lQXBwUmVwb3J0ZXIuY29uZmlnKCdfX0RTTl9fJywge1xuICogICAuLi5jb25maWcgZ29lcyBoZXJlXG4gKiB9KTtcbiAqXG4gKiBzb21lT3RoZXJBcHBSZXBvcnRlci5jb25maWcoJ19fT1RIRVJfRFNOX18nLCB7XG4gKiAgIC4uLmNvbmZpZyBnb2VzIGhlcmVcbiAqIH0pO1xuICpcbiAqIHNvbWVBcHBSZXBvcnRlci5jYXB0dXJlTWVzc2FnZSguLi4pO1xuICogc29tZUFwcFJlcG9ydGVyLmNhcHR1cmVFeGNlcHRpb24oLi4uKTtcbiAqIHNvbWVBcHBSZXBvcnRlci5jYXB0dXJlQnJlYWRjcnVtYiguLi4pO1xuICpcbiAqIHNvbWVPdGhlckFwcFJlcG9ydGVyLmNhcHR1cmVNZXNzYWdlKC4uLik7XG4gKiBzb21lT3RoZXJBcHBSZXBvcnRlci5jYXB0dXJlRXhjZXB0aW9uKC4uLik7XG4gKiBzb21lT3RoZXJBcHBSZXBvcnRlci5jYXB0dXJlQnJlYWRjcnVtYiguLi4pO1xuICpcbiAqIEl0IHNob3VsZCBcImp1c3Qgd29ya1wiLlxuICovXG5tb2R1bGUuZXhwb3J0cy5DbGllbnQgPSBSYXZlbkNvbnN0cnVjdG9yO1xuIiwidmFyIHN0cmluZ2lmeSA9IHJlcXVpcmUoJy4uL3ZlbmRvci9qc29uLXN0cmluZ2lmeS1zYWZlL3N0cmluZ2lmeScpO1xuXG52YXIgX3dpbmRvdyA9XG4gIHR5cGVvZiB3aW5kb3cgIT09ICd1bmRlZmluZWQnXG4gICAgPyB3aW5kb3dcbiAgICA6IHR5cGVvZiBnbG9iYWwgIT09ICd1bmRlZmluZWQnXG4gICAgICA/IGdsb2JhbFxuICAgICAgOiB0eXBlb2Ygc2VsZiAhPT0gJ3VuZGVmaW5lZCdcbiAgICAgICAgPyBzZWxmXG4gICAgICAgIDoge307XG5cbmZ1bmN0aW9uIGlzT2JqZWN0KHdoYXQpIHtcbiAgcmV0dXJuIHR5cGVvZiB3aGF0ID09PSAnb2JqZWN0JyAmJiB3aGF0ICE9PSBudWxsO1xufVxuXG4vLyBZYW5rZWQgZnJvbSBodHRwczovL2dpdC5pby92UzhEViByZS11c2VkIHVuZGVyIENDMFxuLy8gd2l0aCBzb21lIHRpbnkgbW9kaWZpY2F0aW9uc1xuZnVuY3Rpb24gaXNFcnJvcih2YWx1ZSkge1xuICBzd2l0Y2ggKE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbCh2YWx1ZSkpIHtcbiAgICBjYXNlICdbb2JqZWN0IEVycm9yXSc6XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICBjYXNlICdbb2JqZWN0IEV4Y2VwdGlvbl0nOlxuICAgICAgcmV0dXJuIHRydWU7XG4gICAgY2FzZSAnW29iamVjdCBET01FeGNlcHRpb25dJzpcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIGRlZmF1bHQ6XG4gICAgICByZXR1cm4gdmFsdWUgaW5zdGFuY2VvZiBFcnJvcjtcbiAgfVxufVxuXG5mdW5jdGlvbiBpc0Vycm9yRXZlbnQodmFsdWUpIHtcbiAgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbCh2YWx1ZSkgPT09ICdbb2JqZWN0IEVycm9yRXZlbnRdJztcbn1cblxuZnVuY3Rpb24gaXNET01FcnJvcih2YWx1ZSkge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHZhbHVlKSA9PT0gJ1tvYmplY3QgRE9NRXJyb3JdJztcbn1cblxuZnVuY3Rpb24gaXNET01FeGNlcHRpb24odmFsdWUpIHtcbiAgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbCh2YWx1ZSkgPT09ICdbb2JqZWN0IERPTUV4Y2VwdGlvbl0nO1xufVxuXG5mdW5jdGlvbiBpc1VuZGVmaW5lZCh3aGF0KSB7XG4gIHJldHVybiB3aGF0ID09PSB2b2lkIDA7XG59XG5cbmZ1bmN0aW9uIGlzRnVuY3Rpb24od2hhdCkge1xuICByZXR1cm4gdHlwZW9mIHdoYXQgPT09ICdmdW5jdGlvbic7XG59XG5cbmZ1bmN0aW9uIGlzUGxhaW5PYmplY3Qod2hhdCkge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHdoYXQpID09PSAnW29iamVjdCBPYmplY3RdJztcbn1cblxuZnVuY3Rpb24gaXNTdHJpbmcod2hhdCkge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHdoYXQpID09PSAnW29iamVjdCBTdHJpbmddJztcbn1cblxuZnVuY3Rpb24gaXNBcnJheSh3aGF0KSB7XG4gIHJldHVybiBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwod2hhdCkgPT09ICdbb2JqZWN0IEFycmF5XSc7XG59XG5cbmZ1bmN0aW9uIGlzRW1wdHlPYmplY3Qod2hhdCkge1xuICBpZiAoIWlzUGxhaW5PYmplY3Qod2hhdCkpIHJldHVybiBmYWxzZTtcblxuICBmb3IgKHZhciBfIGluIHdoYXQpIHtcbiAgICBpZiAod2hhdC5oYXNPd25Qcm9wZXJ0eShfKSkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgfVxuICByZXR1cm4gdHJ1ZTtcbn1cblxuZnVuY3Rpb24gc3VwcG9ydHNFcnJvckV2ZW50KCkge1xuICB0cnkge1xuICAgIG5ldyBFcnJvckV2ZW50KCcnKTsgLy8gZXNsaW50LWRpc2FibGUtbGluZSBuby1uZXdcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxufVxuXG5mdW5jdGlvbiBzdXBwb3J0c0RPTUVycm9yKCkge1xuICB0cnkge1xuICAgIG5ldyBET01FcnJvcignJyk7IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgbm8tbmV3XG4gICAgcmV0dXJuIHRydWU7XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbn1cblxuZnVuY3Rpb24gc3VwcG9ydHNET01FeGNlcHRpb24oKSB7XG4gIHRyeSB7XG4gICAgbmV3IERPTUV4Y2VwdGlvbignJyk7IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgbm8tbmV3XG4gICAgcmV0dXJuIHRydWU7XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbn1cblxuZnVuY3Rpb24gc3VwcG9ydHNGZXRjaCgpIHtcbiAgaWYgKCEoJ2ZldGNoJyBpbiBfd2luZG93KSkgcmV0dXJuIGZhbHNlO1xuXG4gIHRyeSB7XG4gICAgbmV3IEhlYWRlcnMoKTsgLy8gZXNsaW50LWRpc2FibGUtbGluZSBuby1uZXdcbiAgICBuZXcgUmVxdWVzdCgnJyk7IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgbm8tbmV3XG4gICAgbmV3IFJlc3BvbnNlKCk7IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgbm8tbmV3XG4gICAgcmV0dXJuIHRydWU7XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbn1cblxuLy8gRGVzcGl0ZSBhbGwgc3RhcnMgaW4gdGhlIHNreSBzYXlpbmcgdGhhdCBFZGdlIHN1cHBvcnRzIG9sZCBkcmFmdCBzeW50YXgsIGFrYSAnbmV2ZXInLCAnYWx3YXlzJywgJ29yaWdpbicgYW5kICdkZWZhdWx0XG4vLyBodHRwczovL2Nhbml1c2UuY29tLyNmZWF0PXJlZmVycmVyLXBvbGljeVxuLy8gSXQgZG9lc24ndC4gQW5kIGl0IHRocm93IGV4Y2VwdGlvbiBpbnN0ZWFkIG9mIGlnbm9yaW5nIHRoaXMgcGFyYW1ldGVyLi4uXG4vLyBSRUY6IGh0dHBzOi8vZ2l0aHViLmNvbS9nZXRzZW50cnkvcmF2ZW4tanMvaXNzdWVzLzEyMzNcbmZ1bmN0aW9uIHN1cHBvcnRzUmVmZXJyZXJQb2xpY3koKSB7XG4gIGlmICghc3VwcG9ydHNGZXRjaCgpKSByZXR1cm4gZmFsc2U7XG5cbiAgdHJ5IHtcbiAgICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tbmV3XG4gICAgbmV3IFJlcXVlc3QoJ3BpY2tsZVJpY2snLCB7XG4gICAgICByZWZlcnJlclBvbGljeTogJ29yaWdpbidcbiAgICB9KTtcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxufVxuXG5mdW5jdGlvbiBzdXBwb3J0c1Byb21pc2VSZWplY3Rpb25FdmVudCgpIHtcbiAgcmV0dXJuIHR5cGVvZiBQcm9taXNlUmVqZWN0aW9uRXZlbnQgPT09ICdmdW5jdGlvbic7XG59XG5cbmZ1bmN0aW9uIHdyYXBwZWRDYWxsYmFjayhjYWxsYmFjaykge1xuICBmdW5jdGlvbiBkYXRhQ2FsbGJhY2soZGF0YSwgb3JpZ2luYWwpIHtcbiAgICB2YXIgbm9ybWFsaXplZERhdGEgPSBjYWxsYmFjayhkYXRhKSB8fCBkYXRhO1xuICAgIGlmIChvcmlnaW5hbCkge1xuICAgICAgcmV0dXJuIG9yaWdpbmFsKG5vcm1hbGl6ZWREYXRhKSB8fCBub3JtYWxpemVkRGF0YTtcbiAgICB9XG4gICAgcmV0dXJuIG5vcm1hbGl6ZWREYXRhO1xuICB9XG5cbiAgcmV0dXJuIGRhdGFDYWxsYmFjaztcbn1cblxuZnVuY3Rpb24gZWFjaChvYmosIGNhbGxiYWNrKSB7XG4gIHZhciBpLCBqO1xuXG4gIGlmIChpc1VuZGVmaW5lZChvYmoubGVuZ3RoKSkge1xuICAgIGZvciAoaSBpbiBvYmopIHtcbiAgICAgIGlmIChoYXNLZXkob2JqLCBpKSkge1xuICAgICAgICBjYWxsYmFjay5jYWxsKG51bGwsIGksIG9ialtpXSk7XG4gICAgICB9XG4gICAgfVxuICB9IGVsc2Uge1xuICAgIGogPSBvYmoubGVuZ3RoO1xuICAgIGlmIChqKSB7XG4gICAgICBmb3IgKGkgPSAwOyBpIDwgajsgaSsrKSB7XG4gICAgICAgIGNhbGxiYWNrLmNhbGwobnVsbCwgaSwgb2JqW2ldKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn1cblxuZnVuY3Rpb24gb2JqZWN0TWVyZ2Uob2JqMSwgb2JqMikge1xuICBpZiAoIW9iajIpIHtcbiAgICByZXR1cm4gb2JqMTtcbiAgfVxuICBlYWNoKG9iajIsIGZ1bmN0aW9uKGtleSwgdmFsdWUpIHtcbiAgICBvYmoxW2tleV0gPSB2YWx1ZTtcbiAgfSk7XG4gIHJldHVybiBvYmoxO1xufVxuXG4vKipcbiAqIFRoaXMgZnVuY3Rpb24gaXMgb25seSB1c2VkIGZvciByZWFjdC1uYXRpdmUuXG4gKiByZWFjdC1uYXRpdmUgZnJlZXplcyBvYmplY3QgdGhhdCBoYXZlIGFscmVhZHkgYmVlbiBzZW50IG92ZXIgdGhlXG4gKiBqcyBicmlkZ2UuIFdlIG5lZWQgdGhpcyBmdW5jdGlvbiBpbiBvcmRlciB0byBjaGVjayBpZiB0aGUgb2JqZWN0IGlzIGZyb3plbi5cbiAqIFNvIGl0J3Mgb2sgdGhhdCBvYmplY3RGcm96ZW4gcmV0dXJucyBmYWxzZSBpZiBPYmplY3QuaXNGcm96ZW4gaXMgbm90XG4gKiBzdXBwb3J0ZWQgYmVjYXVzZSBpdCdzIG5vdCByZWxldmFudCBmb3Igb3RoZXIgXCJwbGF0Zm9ybXNcIi4gU2VlIHJlbGF0ZWQgaXNzdWU6XG4gKiBodHRwczovL2dpdGh1Yi5jb20vZ2V0c2VudHJ5L3JlYWN0LW5hdGl2ZS1zZW50cnkvaXNzdWVzLzU3XG4gKi9cbmZ1bmN0aW9uIG9iamVjdEZyb3plbihvYmopIHtcbiAgaWYgKCFPYmplY3QuaXNGcm96ZW4pIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbiAgcmV0dXJuIE9iamVjdC5pc0Zyb3plbihvYmopO1xufVxuXG5mdW5jdGlvbiB0cnVuY2F0ZShzdHIsIG1heCkge1xuICBpZiAodHlwZW9mIG1heCAhPT0gJ251bWJlcicpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJzJuZCBhcmd1bWVudCB0byBgdHJ1bmNhdGVgIGZ1bmN0aW9uIHNob3VsZCBiZSBhIG51bWJlcicpO1xuICB9XG4gIGlmICh0eXBlb2Ygc3RyICE9PSAnc3RyaW5nJyB8fCBtYXggPT09IDApIHtcbiAgICByZXR1cm4gc3RyO1xuICB9XG4gIHJldHVybiBzdHIubGVuZ3RoIDw9IG1heCA/IHN0ciA6IHN0ci5zdWJzdHIoMCwgbWF4KSArICdcXHUyMDI2Jztcbn1cblxuLyoqXG4gKiBoYXNLZXksIGEgYmV0dGVyIGZvcm0gb2YgaGFzT3duUHJvcGVydHlcbiAqIEV4YW1wbGU6IGhhc0tleShNYWluSG9zdE9iamVjdCwgcHJvcGVydHkpID09PSB0cnVlL2ZhbHNlXG4gKlxuICogQHBhcmFtIHtPYmplY3R9IGhvc3Qgb2JqZWN0IHRvIGNoZWNrIHByb3BlcnR5XG4gKiBAcGFyYW0ge3N0cmluZ30ga2V5IHRvIGNoZWNrXG4gKi9cbmZ1bmN0aW9uIGhhc0tleShvYmplY3QsIGtleSkge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iamVjdCwga2V5KTtcbn1cblxuZnVuY3Rpb24gam9pblJlZ0V4cChwYXR0ZXJucykge1xuICAvLyBDb21iaW5lIGFuIGFycmF5IG9mIHJlZ3VsYXIgZXhwcmVzc2lvbnMgYW5kIHN0cmluZ3MgaW50byBvbmUgbGFyZ2UgcmVnZXhwXG4gIC8vIEJlIG1hZC5cbiAgdmFyIHNvdXJjZXMgPSBbXSxcbiAgICBpID0gMCxcbiAgICBsZW4gPSBwYXR0ZXJucy5sZW5ndGgsXG4gICAgcGF0dGVybjtcblxuICBmb3IgKDsgaSA8IGxlbjsgaSsrKSB7XG4gICAgcGF0dGVybiA9IHBhdHRlcm5zW2ldO1xuICAgIGlmIChpc1N0cmluZyhwYXR0ZXJuKSkge1xuICAgICAgLy8gSWYgaXQncyBhIHN0cmluZywgd2UgbmVlZCB0byBlc2NhcGUgaXRcbiAgICAgIC8vIFRha2VuIGZyb206IGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0phdmFTY3JpcHQvR3VpZGUvUmVndWxhcl9FeHByZXNzaW9uc1xuICAgICAgc291cmNlcy5wdXNoKHBhdHRlcm4ucmVwbGFjZSgvKFsuKis/Xj0hOiR7fSgpfFxcW1xcXVxcL1xcXFxdKS9nLCAnXFxcXCQxJykpO1xuICAgIH0gZWxzZSBpZiAocGF0dGVybiAmJiBwYXR0ZXJuLnNvdXJjZSkge1xuICAgICAgLy8gSWYgaXQncyBhIHJlZ2V4cCBhbHJlYWR5LCB3ZSB3YW50IHRvIGV4dHJhY3QgdGhlIHNvdXJjZVxuICAgICAgc291cmNlcy5wdXNoKHBhdHRlcm4uc291cmNlKTtcbiAgICB9XG4gICAgLy8gSW50ZW50aW9uYWxseSBza2lwIG90aGVyIGNhc2VzXG4gIH1cbiAgcmV0dXJuIG5ldyBSZWdFeHAoc291cmNlcy5qb2luKCd8JyksICdpJyk7XG59XG5cbmZ1bmN0aW9uIHVybGVuY29kZShvKSB7XG4gIHZhciBwYWlycyA9IFtdO1xuICBlYWNoKG8sIGZ1bmN0aW9uKGtleSwgdmFsdWUpIHtcbiAgICBwYWlycy5wdXNoKGVuY29kZVVSSUNvbXBvbmVudChrZXkpICsgJz0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHZhbHVlKSk7XG4gIH0pO1xuICByZXR1cm4gcGFpcnMuam9pbignJicpO1xufVxuXG4vLyBib3Jyb3dlZCBmcm9tIGh0dHBzOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmMzOTg2I2FwcGVuZGl4LUJcbi8vIGludGVudGlvbmFsbHkgdXNpbmcgcmVnZXggYW5kIG5vdCA8YS8+IGhyZWYgcGFyc2luZyB0cmljayBiZWNhdXNlIFJlYWN0IE5hdGl2ZSBhbmQgb3RoZXJcbi8vIGVudmlyb25tZW50cyB3aGVyZSBET00gbWlnaHQgbm90IGJlIGF2YWlsYWJsZVxuZnVuY3Rpb24gcGFyc2VVcmwodXJsKSB7XG4gIGlmICh0eXBlb2YgdXJsICE9PSAnc3RyaW5nJykgcmV0dXJuIHt9O1xuICB2YXIgbWF0Y2ggPSB1cmwubWF0Y2goL14oKFteOlxcLz8jXSspOik/KFxcL1xcLyhbXlxcLz8jXSopKT8oW14/I10qKShcXD8oW14jXSopKT8oIyguKikpPyQvKTtcblxuICAvLyBjb2VyY2UgdG8gdW5kZWZpbmVkIHZhbHVlcyB0byBlbXB0eSBzdHJpbmcgc28gd2UgZG9uJ3QgZ2V0ICd1bmRlZmluZWQnXG4gIHZhciBxdWVyeSA9IG1hdGNoWzZdIHx8ICcnO1xuICB2YXIgZnJhZ21lbnQgPSBtYXRjaFs4XSB8fCAnJztcbiAgcmV0dXJuIHtcbiAgICBwcm90b2NvbDogbWF0Y2hbMl0sXG4gICAgaG9zdDogbWF0Y2hbNF0sXG4gICAgcGF0aDogbWF0Y2hbNV0sXG4gICAgcmVsYXRpdmU6IG1hdGNoWzVdICsgcXVlcnkgKyBmcmFnbWVudCAvLyBldmVyeXRoaW5nIG1pbnVzIG9yaWdpblxuICB9O1xufVxuZnVuY3Rpb24gdXVpZDQoKSB7XG4gIHZhciBjcnlwdG8gPSBfd2luZG93LmNyeXB0byB8fCBfd2luZG93Lm1zQ3J5cHRvO1xuXG4gIGlmICghaXNVbmRlZmluZWQoY3J5cHRvKSAmJiBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKSB7XG4gICAgLy8gVXNlIHdpbmRvdy5jcnlwdG8gQVBJIGlmIGF2YWlsYWJsZVxuICAgIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby11bmRlZlxuICAgIHZhciBhcnIgPSBuZXcgVWludDE2QXJyYXkoOCk7XG4gICAgY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhhcnIpO1xuXG4gICAgLy8gc2V0IDQgaW4gYnl0ZSA3XG4gICAgYXJyWzNdID0gKGFyclszXSAmIDB4ZmZmKSB8IDB4NDAwMDtcbiAgICAvLyBzZXQgMiBtb3N0IHNpZ25pZmljYW50IGJpdHMgb2YgYnl0ZSA5IHRvICcxMCdcbiAgICBhcnJbNF0gPSAoYXJyWzRdICYgMHgzZmZmKSB8IDB4ODAwMDtcblxuICAgIHZhciBwYWQgPSBmdW5jdGlvbihudW0pIHtcbiAgICAgIHZhciB2ID0gbnVtLnRvU3RyaW5nKDE2KTtcbiAgICAgIHdoaWxlICh2Lmxlbmd0aCA8IDQpIHtcbiAgICAgICAgdiA9ICcwJyArIHY7XG4gICAgICB9XG4gICAgICByZXR1cm4gdjtcbiAgICB9O1xuXG4gICAgcmV0dXJuIChcbiAgICAgIHBhZChhcnJbMF0pICtcbiAgICAgIHBhZChhcnJbMV0pICtcbiAgICAgIHBhZChhcnJbMl0pICtcbiAgICAgIHBhZChhcnJbM10pICtcbiAgICAgIHBhZChhcnJbNF0pICtcbiAgICAgIHBhZChhcnJbNV0pICtcbiAgICAgIHBhZChhcnJbNl0pICtcbiAgICAgIHBhZChhcnJbN10pXG4gICAgKTtcbiAgfSBlbHNlIHtcbiAgICAvLyBodHRwOi8vc3RhY2tvdmVyZmxvdy5jb20vcXVlc3Rpb25zLzEwNTAzNC9ob3ctdG8tY3JlYXRlLWEtZ3VpZC11dWlkLWluLWphdmFzY3JpcHQvMjExNzUyMyMyMTE3NTIzXG4gICAgcmV0dXJuICd4eHh4eHh4eHh4eHg0eHh4eXh4eHh4eHh4eHh4eHh4eCcucmVwbGFjZSgvW3h5XS9nLCBmdW5jdGlvbihjKSB7XG4gICAgICB2YXIgciA9IChNYXRoLnJhbmRvbSgpICogMTYpIHwgMCxcbiAgICAgICAgdiA9IGMgPT09ICd4JyA/IHIgOiAociAmIDB4MykgfCAweDg7XG4gICAgICByZXR1cm4gdi50b1N0cmluZygxNik7XG4gICAgfSk7XG4gIH1cbn1cblxuLyoqXG4gKiBHaXZlbiBhIGNoaWxkIERPTSBlbGVtZW50LCByZXR1cm5zIGEgcXVlcnktc2VsZWN0b3Igc3RhdGVtZW50IGRlc2NyaWJpbmcgdGhhdFxuICogYW5kIGl0cyBhbmNlc3RvcnNcbiAqIGUuZy4gW0hUTUxFbGVtZW50XSA9PiBib2R5ID4gZGl2ID4gaW5wdXQjZm9vLmJ0bltuYW1lPWJhel1cbiAqIEBwYXJhbSBlbGVtXG4gKiBAcmV0dXJucyB7c3RyaW5nfVxuICovXG5mdW5jdGlvbiBodG1sVHJlZUFzU3RyaW5nKGVsZW0pIHtcbiAgLyogZXNsaW50IG5vLWV4dHJhLXBhcmVuczowKi9cbiAgdmFyIE1BWF9UUkFWRVJTRV9IRUlHSFQgPSA1LFxuICAgIE1BWF9PVVRQVVRfTEVOID0gODAsXG4gICAgb3V0ID0gW10sXG4gICAgaGVpZ2h0ID0gMCxcbiAgICBsZW4gPSAwLFxuICAgIHNlcGFyYXRvciA9ICcgPiAnLFxuICAgIHNlcExlbmd0aCA9IHNlcGFyYXRvci5sZW5ndGgsXG4gICAgbmV4dFN0cjtcblxuICB3aGlsZSAoZWxlbSAmJiBoZWlnaHQrKyA8IE1BWF9UUkFWRVJTRV9IRUlHSFQpIHtcbiAgICBuZXh0U3RyID0gaHRtbEVsZW1lbnRBc1N0cmluZyhlbGVtKTtcbiAgICAvLyBiYWlsIG91dCBpZlxuICAgIC8vIC0gbmV4dFN0ciBpcyB0aGUgJ2h0bWwnIGVsZW1lbnRcbiAgICAvLyAtIHRoZSBsZW5ndGggb2YgdGhlIHN0cmluZyB0aGF0IHdvdWxkIGJlIGNyZWF0ZWQgZXhjZWVkcyBNQVhfT1VUUFVUX0xFTlxuICAgIC8vICAgKGlnbm9yZSB0aGlzIGxpbWl0IGlmIHdlIGFyZSBvbiB0aGUgZmlyc3QgaXRlcmF0aW9uKVxuICAgIGlmIChcbiAgICAgIG5leHRTdHIgPT09ICdodG1sJyB8fFxuICAgICAgKGhlaWdodCA+IDEgJiYgbGVuICsgb3V0Lmxlbmd0aCAqIHNlcExlbmd0aCArIG5leHRTdHIubGVuZ3RoID49IE1BWF9PVVRQVVRfTEVOKVxuICAgICkge1xuICAgICAgYnJlYWs7XG4gICAgfVxuXG4gICAgb3V0LnB1c2gobmV4dFN0cik7XG5cbiAgICBsZW4gKz0gbmV4dFN0ci5sZW5ndGg7XG4gICAgZWxlbSA9IGVsZW0ucGFyZW50Tm9kZTtcbiAgfVxuXG4gIHJldHVybiBvdXQucmV2ZXJzZSgpLmpvaW4oc2VwYXJhdG9yKTtcbn1cblxuLyoqXG4gKiBSZXR1cm5zIGEgc2ltcGxlLCBxdWVyeS1zZWxlY3RvciByZXByZXNlbnRhdGlvbiBvZiBhIERPTSBlbGVtZW50XG4gKiBlLmcuIFtIVE1MRWxlbWVudF0gPT4gaW5wdXQjZm9vLmJ0bltuYW1lPWJhel1cbiAqIEBwYXJhbSBIVE1MRWxlbWVudFxuICogQHJldHVybnMge3N0cmluZ31cbiAqL1xuZnVuY3Rpb24gaHRtbEVsZW1lbnRBc1N0cmluZyhlbGVtKSB7XG4gIHZhciBvdXQgPSBbXSxcbiAgICBjbGFzc05hbWUsXG4gICAgY2xhc3NlcyxcbiAgICBrZXksXG4gICAgYXR0cixcbiAgICBpO1xuXG4gIGlmICghZWxlbSB8fCAhZWxlbS50YWdOYW1lKSB7XG4gICAgcmV0dXJuICcnO1xuICB9XG5cbiAgb3V0LnB1c2goZWxlbS50YWdOYW1lLnRvTG93ZXJDYXNlKCkpO1xuICBpZiAoZWxlbS5pZCkge1xuICAgIG91dC5wdXNoKCcjJyArIGVsZW0uaWQpO1xuICB9XG5cbiAgY2xhc3NOYW1lID0gZWxlbS5jbGFzc05hbWU7XG4gIGlmIChjbGFzc05hbWUgJiYgaXNTdHJpbmcoY2xhc3NOYW1lKSkge1xuICAgIGNsYXNzZXMgPSBjbGFzc05hbWUuc3BsaXQoL1xccysvKTtcbiAgICBmb3IgKGkgPSAwOyBpIDwgY2xhc3Nlcy5sZW5ndGg7IGkrKykge1xuICAgICAgb3V0LnB1c2goJy4nICsgY2xhc3Nlc1tpXSk7XG4gICAgfVxuICB9XG4gIHZhciBhdHRyV2hpdGVsaXN0ID0gWyd0eXBlJywgJ25hbWUnLCAndGl0bGUnLCAnYWx0J107XG4gIGZvciAoaSA9IDA7IGkgPCBhdHRyV2hpdGVsaXN0Lmxlbmd0aDsgaSsrKSB7XG4gICAga2V5ID0gYXR0cldoaXRlbGlzdFtpXTtcbiAgICBhdHRyID0gZWxlbS5nZXRBdHRyaWJ1dGUoa2V5KTtcbiAgICBpZiAoYXR0cikge1xuICAgICAgb3V0LnB1c2goJ1snICsga2V5ICsgJz1cIicgKyBhdHRyICsgJ1wiXScpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gb3V0LmpvaW4oJycpO1xufVxuXG4vKipcbiAqIFJldHVybnMgdHJ1ZSBpZiBlaXRoZXIgYSBPUiBiIGlzIHRydXRoeSwgYnV0IG5vdCBib3RoXG4gKi9cbmZ1bmN0aW9uIGlzT25seU9uZVRydXRoeShhLCBiKSB7XG4gIHJldHVybiAhISghIWEgXiAhIWIpO1xufVxuXG4vKipcbiAqIFJldHVybnMgdHJ1ZSBpZiBib3RoIHBhcmFtZXRlcnMgYXJlIHVuZGVmaW5lZFxuICovXG5mdW5jdGlvbiBpc0JvdGhVbmRlZmluZWQoYSwgYikge1xuICByZXR1cm4gaXNVbmRlZmluZWQoYSkgJiYgaXNVbmRlZmluZWQoYik7XG59XG5cbi8qKlxuICogUmV0dXJucyB0cnVlIGlmIHRoZSB0d28gaW5wdXQgZXhjZXB0aW9uIGludGVyZmFjZXMgaGF2ZSB0aGUgc2FtZSBjb250ZW50XG4gKi9cbmZ1bmN0aW9uIGlzU2FtZUV4Y2VwdGlvbihleDEsIGV4Mikge1xuICBpZiAoaXNPbmx5T25lVHJ1dGh5KGV4MSwgZXgyKSkgcmV0dXJuIGZhbHNlO1xuXG4gIGV4MSA9IGV4MS52YWx1ZXNbMF07XG4gIGV4MiA9IGV4Mi52YWx1ZXNbMF07XG5cbiAgaWYgKGV4MS50eXBlICE9PSBleDIudHlwZSB8fCBleDEudmFsdWUgIT09IGV4Mi52YWx1ZSkgcmV0dXJuIGZhbHNlO1xuXG4gIC8vIGluIGNhc2UgYm90aCBzdGFja3RyYWNlcyBhcmUgdW5kZWZpbmVkLCB3ZSBjYW4ndCBkZWNpZGUgc28gZGVmYXVsdCB0byBmYWxzZVxuICBpZiAoaXNCb3RoVW5kZWZpbmVkKGV4MS5zdGFja3RyYWNlLCBleDIuc3RhY2t0cmFjZSkpIHJldHVybiBmYWxzZTtcblxuICByZXR1cm4gaXNTYW1lU3RhY2t0cmFjZShleDEuc3RhY2t0cmFjZSwgZXgyLnN0YWNrdHJhY2UpO1xufVxuXG4vKipcbiAqIFJldHVybnMgdHJ1ZSBpZiB0aGUgdHdvIGlucHV0IHN0YWNrIHRyYWNlIGludGVyZmFjZXMgaGF2ZSB0aGUgc2FtZSBjb250ZW50XG4gKi9cbmZ1bmN0aW9uIGlzU2FtZVN0YWNrdHJhY2Uoc3RhY2sxLCBzdGFjazIpIHtcbiAgaWYgKGlzT25seU9uZVRydXRoeShzdGFjazEsIHN0YWNrMikpIHJldHVybiBmYWxzZTtcblxuICB2YXIgZnJhbWVzMSA9IHN0YWNrMS5mcmFtZXM7XG4gIHZhciBmcmFtZXMyID0gc3RhY2syLmZyYW1lcztcblxuICAvLyBFeGl0IGVhcmx5IGlmIHN0YWNrdHJhY2UgaXMgbWFsZm9ybWVkXG4gIGlmIChmcmFtZXMxID09PSB1bmRlZmluZWQgfHwgZnJhbWVzMiA9PT0gdW5kZWZpbmVkKSByZXR1cm4gZmFsc2U7XG5cbiAgLy8gRXhpdCBlYXJseSBpZiBmcmFtZSBjb3VudCBkaWZmZXJzXG4gIGlmIChmcmFtZXMxLmxlbmd0aCAhPT0gZnJhbWVzMi5sZW5ndGgpIHJldHVybiBmYWxzZTtcblxuICAvLyBJdGVyYXRlIHRocm91Z2ggZXZlcnkgZnJhbWU7IGJhaWwgb3V0IGlmIGFueXRoaW5nIGRpZmZlcnNcbiAgdmFyIGEsIGI7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgZnJhbWVzMS5sZW5ndGg7IGkrKykge1xuICAgIGEgPSBmcmFtZXMxW2ldO1xuICAgIGIgPSBmcmFtZXMyW2ldO1xuICAgIGlmIChcbiAgICAgIGEuZmlsZW5hbWUgIT09IGIuZmlsZW5hbWUgfHxcbiAgICAgIGEubGluZW5vICE9PSBiLmxpbmVubyB8fFxuICAgICAgYS5jb2xubyAhPT0gYi5jb2xubyB8fFxuICAgICAgYVsnZnVuY3Rpb24nXSAhPT0gYlsnZnVuY3Rpb24nXVxuICAgIClcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgfVxuICByZXR1cm4gdHJ1ZTtcbn1cblxuLyoqXG4gKiBQb2x5ZmlsbCBhIG1ldGhvZFxuICogQHBhcmFtIG9iaiBvYmplY3QgZS5nLiBgZG9jdW1lbnRgXG4gKiBAcGFyYW0gbmFtZSBtZXRob2QgbmFtZSBwcmVzZW50IG9uIG9iamVjdCBlLmcuIGBhZGRFdmVudExpc3RlbmVyYFxuICogQHBhcmFtIHJlcGxhY2VtZW50IHJlcGxhY2VtZW50IGZ1bmN0aW9uXG4gKiBAcGFyYW0gdHJhY2sge29wdGlvbmFsfSByZWNvcmQgaW5zdHJ1bWVudGF0aW9uIHRvIGFuIGFycmF5XG4gKi9cbmZ1bmN0aW9uIGZpbGwob2JqLCBuYW1lLCByZXBsYWNlbWVudCwgdHJhY2spIHtcbiAgaWYgKG9iaiA9PSBudWxsKSByZXR1cm47XG4gIHZhciBvcmlnID0gb2JqW25hbWVdO1xuICBvYmpbbmFtZV0gPSByZXBsYWNlbWVudChvcmlnKTtcbiAgb2JqW25hbWVdLl9fcmF2ZW5fXyA9IHRydWU7XG4gIG9ialtuYW1lXS5fX29yaWdfXyA9IG9yaWc7XG4gIGlmICh0cmFjaykge1xuICAgIHRyYWNrLnB1c2goW29iaiwgbmFtZSwgb3JpZ10pO1xuICB9XG59XG5cbi8qKlxuICogSm9pbiB2YWx1ZXMgaW4gYXJyYXlcbiAqIEBwYXJhbSBpbnB1dCBhcnJheSBvZiB2YWx1ZXMgdG8gYmUgam9pbmVkIHRvZ2V0aGVyXG4gKiBAcGFyYW0gZGVsaW1pdGVyIHN0cmluZyB0byBiZSBwbGFjZWQgaW4tYmV0d2VlbiB2YWx1ZXNcbiAqIEByZXR1cm5zIHtzdHJpbmd9XG4gKi9cbmZ1bmN0aW9uIHNhZmVKb2luKGlucHV0LCBkZWxpbWl0ZXIpIHtcbiAgaWYgKCFpc0FycmF5KGlucHV0KSkgcmV0dXJuICcnO1xuXG4gIHZhciBvdXRwdXQgPSBbXTtcblxuICBmb3IgKHZhciBpID0gMDsgaSA8IGlucHV0Lmxlbmd0aDsgaSsrKSB7XG4gICAgdHJ5IHtcbiAgICAgIG91dHB1dC5wdXNoKFN0cmluZyhpbnB1dFtpXSkpO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIG91dHB1dC5wdXNoKCdbdmFsdWUgY2Fubm90IGJlIHNlcmlhbGl6ZWRdJyk7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIG91dHB1dC5qb2luKGRlbGltaXRlcik7XG59XG5cbi8vIERlZmF1bHQgTm9kZS5qcyBSRVBMIGRlcHRoXG52YXIgTUFYX1NFUklBTElaRV9FWENFUFRJT05fREVQVEggPSAzO1xuLy8gNTBrQiwgYXMgMTAwa0IgaXMgbWF4IHBheWxvYWQgc2l6ZSwgc28gaGFsZiBzb3VuZHMgcmVhc29uYWJsZVxudmFyIE1BWF9TRVJJQUxJWkVfRVhDRVBUSU9OX1NJWkUgPSA1MCAqIDEwMjQ7XG52YXIgTUFYX1NFUklBTElaRV9LRVlTX0xFTkdUSCA9IDQwO1xuXG5mdW5jdGlvbiB1dGY4TGVuZ3RoKHZhbHVlKSB7XG4gIHJldHVybiB+LWVuY29kZVVSSSh2YWx1ZSkuc3BsaXQoLyUuLnwuLykubGVuZ3RoO1xufVxuXG5mdW5jdGlvbiBqc29uU2l6ZSh2YWx1ZSkge1xuICByZXR1cm4gdXRmOExlbmd0aChKU09OLnN0cmluZ2lmeSh2YWx1ZSkpO1xufVxuXG5mdW5jdGlvbiBzZXJpYWxpemVWYWx1ZSh2YWx1ZSkge1xuICBpZiAodHlwZW9mIHZhbHVlID09PSAnc3RyaW5nJykge1xuICAgIHZhciBtYXhMZW5ndGggPSA0MDtcbiAgICByZXR1cm4gdHJ1bmNhdGUodmFsdWUsIG1heExlbmd0aCk7XG4gIH0gZWxzZSBpZiAoXG4gICAgdHlwZW9mIHZhbHVlID09PSAnbnVtYmVyJyB8fFxuICAgIHR5cGVvZiB2YWx1ZSA9PT0gJ2Jvb2xlYW4nIHx8XG4gICAgdHlwZW9mIHZhbHVlID09PSAndW5kZWZpbmVkJ1xuICApIHtcbiAgICByZXR1cm4gdmFsdWU7XG4gIH1cblxuICB2YXIgdHlwZSA9IE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbCh2YWx1ZSk7XG5cbiAgLy8gTm9kZS5qcyBSRVBMIG5vdGF0aW9uXG4gIGlmICh0eXBlID09PSAnW29iamVjdCBPYmplY3RdJykgcmV0dXJuICdbT2JqZWN0XSc7XG4gIGlmICh0eXBlID09PSAnW29iamVjdCBBcnJheV0nKSByZXR1cm4gJ1tBcnJheV0nO1xuICBpZiAodHlwZSA9PT0gJ1tvYmplY3QgRnVuY3Rpb25dJylcbiAgICByZXR1cm4gdmFsdWUubmFtZSA/ICdbRnVuY3Rpb246ICcgKyB2YWx1ZS5uYW1lICsgJ10nIDogJ1tGdW5jdGlvbl0nO1xuXG4gIHJldHVybiB2YWx1ZTtcbn1cblxuZnVuY3Rpb24gc2VyaWFsaXplT2JqZWN0KHZhbHVlLCBkZXB0aCkge1xuICBpZiAoZGVwdGggPT09IDApIHJldHVybiBzZXJpYWxpemVWYWx1ZSh2YWx1ZSk7XG5cbiAgaWYgKGlzUGxhaW5PYmplY3QodmFsdWUpKSB7XG4gICAgcmV0dXJuIE9iamVjdC5rZXlzKHZhbHVlKS5yZWR1Y2UoZnVuY3Rpb24oYWNjLCBrZXkpIHtcbiAgICAgIGFjY1trZXldID0gc2VyaWFsaXplT2JqZWN0KHZhbHVlW2tleV0sIGRlcHRoIC0gMSk7XG4gICAgICByZXR1cm4gYWNjO1xuICAgIH0sIHt9KTtcbiAgfSBlbHNlIGlmIChBcnJheS5pc0FycmF5KHZhbHVlKSkge1xuICAgIHJldHVybiB2YWx1ZS5tYXAoZnVuY3Rpb24odmFsKSB7XG4gICAgICByZXR1cm4gc2VyaWFsaXplT2JqZWN0KHZhbCwgZGVwdGggLSAxKTtcbiAgICB9KTtcbiAgfVxuXG4gIHJldHVybiBzZXJpYWxpemVWYWx1ZSh2YWx1ZSk7XG59XG5cbmZ1bmN0aW9uIHNlcmlhbGl6ZUV4Y2VwdGlvbihleCwgZGVwdGgsIG1heFNpemUpIHtcbiAgaWYgKCFpc1BsYWluT2JqZWN0KGV4KSkgcmV0dXJuIGV4O1xuXG4gIGRlcHRoID0gdHlwZW9mIGRlcHRoICE9PSAnbnVtYmVyJyA/IE1BWF9TRVJJQUxJWkVfRVhDRVBUSU9OX0RFUFRIIDogZGVwdGg7XG4gIG1heFNpemUgPSB0eXBlb2YgZGVwdGggIT09ICdudW1iZXInID8gTUFYX1NFUklBTElaRV9FWENFUFRJT05fU0laRSA6IG1heFNpemU7XG5cbiAgdmFyIHNlcmlhbGl6ZWQgPSBzZXJpYWxpemVPYmplY3QoZXgsIGRlcHRoKTtcblxuICBpZiAoanNvblNpemUoc3RyaW5naWZ5KHNlcmlhbGl6ZWQpKSA+IG1heFNpemUpIHtcbiAgICByZXR1cm4gc2VyaWFsaXplRXhjZXB0aW9uKGV4LCBkZXB0aCAtIDEpO1xuICB9XG5cbiAgcmV0dXJuIHNlcmlhbGl6ZWQ7XG59XG5cbmZ1bmN0aW9uIHNlcmlhbGl6ZUtleXNGb3JNZXNzYWdlKGtleXMsIG1heExlbmd0aCkge1xuICBpZiAodHlwZW9mIGtleXMgPT09ICdudW1iZXInIHx8IHR5cGVvZiBrZXlzID09PSAnc3RyaW5nJykgcmV0dXJuIGtleXMudG9TdHJpbmcoKTtcbiAgaWYgKCFBcnJheS5pc0FycmF5KGtleXMpKSByZXR1cm4gJyc7XG5cbiAga2V5cyA9IGtleXMuZmlsdGVyKGZ1bmN0aW9uKGtleSkge1xuICAgIHJldHVybiB0eXBlb2Yga2V5ID09PSAnc3RyaW5nJztcbiAgfSk7XG4gIGlmIChrZXlzLmxlbmd0aCA9PT0gMCkgcmV0dXJuICdbb2JqZWN0IGhhcyBubyBrZXlzXSc7XG5cbiAgbWF4TGVuZ3RoID0gdHlwZW9mIG1heExlbmd0aCAhPT0gJ251bWJlcicgPyBNQVhfU0VSSUFMSVpFX0tFWVNfTEVOR1RIIDogbWF4TGVuZ3RoO1xuICBpZiAoa2V5c1swXS5sZW5ndGggPj0gbWF4TGVuZ3RoKSByZXR1cm4ga2V5c1swXTtcblxuICBmb3IgKHZhciB1c2VkS2V5cyA9IGtleXMubGVuZ3RoOyB1c2VkS2V5cyA+IDA7IHVzZWRLZXlzLS0pIHtcbiAgICB2YXIgc2VyaWFsaXplZCA9IGtleXMuc2xpY2UoMCwgdXNlZEtleXMpLmpvaW4oJywgJyk7XG4gICAgaWYgKHNlcmlhbGl6ZWQubGVuZ3RoID4gbWF4TGVuZ3RoKSBjb250aW51ZTtcbiAgICBpZiAodXNlZEtleXMgPT09IGtleXMubGVuZ3RoKSByZXR1cm4gc2VyaWFsaXplZDtcbiAgICByZXR1cm4gc2VyaWFsaXplZCArICdcXHUyMDI2JztcbiAgfVxuXG4gIHJldHVybiAnJztcbn1cblxuZnVuY3Rpb24gc2FuaXRpemUoaW5wdXQsIHNhbml0aXplS2V5cykge1xuICBpZiAoIWlzQXJyYXkoc2FuaXRpemVLZXlzKSB8fCAoaXNBcnJheShzYW5pdGl6ZUtleXMpICYmIHNhbml0aXplS2V5cy5sZW5ndGggPT09IDApKVxuICAgIHJldHVybiBpbnB1dDtcblxuICB2YXIgc2FuaXRpemVSZWdFeHAgPSBqb2luUmVnRXhwKHNhbml0aXplS2V5cyk7XG4gIHZhciBzYW5pdGl6ZU1hc2sgPSAnKioqKioqKionO1xuICB2YXIgc2FmZUlucHV0O1xuXG4gIHRyeSB7XG4gICAgc2FmZUlucHV0ID0gSlNPTi5wYXJzZShzdHJpbmdpZnkoaW5wdXQpKTtcbiAgfSBjYXRjaCAob19PKSB7XG4gICAgcmV0dXJuIGlucHV0O1xuICB9XG5cbiAgZnVuY3Rpb24gc2FuaXRpemVXb3JrZXIod29ya2VySW5wdXQpIHtcbiAgICBpZiAoaXNBcnJheSh3b3JrZXJJbnB1dCkpIHtcbiAgICAgIHJldHVybiB3b3JrZXJJbnB1dC5tYXAoZnVuY3Rpb24odmFsKSB7XG4gICAgICAgIHJldHVybiBzYW5pdGl6ZVdvcmtlcih2YWwpO1xuICAgICAgfSk7XG4gICAgfVxuXG4gICAgaWYgKGlzUGxhaW5PYmplY3Qod29ya2VySW5wdXQpKSB7XG4gICAgICByZXR1cm4gT2JqZWN0LmtleXMod29ya2VySW5wdXQpLnJlZHVjZShmdW5jdGlvbihhY2MsIGspIHtcbiAgICAgICAgaWYgKHNhbml0aXplUmVnRXhwLnRlc3QoaykpIHtcbiAgICAgICAgICBhY2Nba10gPSBzYW5pdGl6ZU1hc2s7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgYWNjW2tdID0gc2FuaXRpemVXb3JrZXIod29ya2VySW5wdXRba10pO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBhY2M7XG4gICAgICB9LCB7fSk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHdvcmtlcklucHV0O1xuICB9XG5cbiAgcmV0dXJuIHNhbml0aXplV29ya2VyKHNhZmVJbnB1dCk7XG59XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICBpc09iamVjdDogaXNPYmplY3QsXG4gIGlzRXJyb3I6IGlzRXJyb3IsXG4gIGlzRXJyb3JFdmVudDogaXNFcnJvckV2ZW50LFxuICBpc0RPTUVycm9yOiBpc0RPTUVycm9yLFxuICBpc0RPTUV4Y2VwdGlvbjogaXNET01FeGNlcHRpb24sXG4gIGlzVW5kZWZpbmVkOiBpc1VuZGVmaW5lZCxcbiAgaXNGdW5jdGlvbjogaXNGdW5jdGlvbixcbiAgaXNQbGFpbk9iamVjdDogaXNQbGFpbk9iamVjdCxcbiAgaXNTdHJpbmc6IGlzU3RyaW5nLFxuICBpc0FycmF5OiBpc0FycmF5LFxuICBpc0VtcHR5T2JqZWN0OiBpc0VtcHR5T2JqZWN0LFxuICBzdXBwb3J0c0Vycm9yRXZlbnQ6IHN1cHBvcnRzRXJyb3JFdmVudCxcbiAgc3VwcG9ydHNET01FcnJvcjogc3VwcG9ydHNET01FcnJvcixcbiAgc3VwcG9ydHNET01FeGNlcHRpb246IHN1cHBvcnRzRE9NRXhjZXB0aW9uLFxuICBzdXBwb3J0c0ZldGNoOiBzdXBwb3J0c0ZldGNoLFxuICBzdXBwb3J0c1JlZmVycmVyUG9saWN5OiBzdXBwb3J0c1JlZmVycmVyUG9saWN5LFxuICBzdXBwb3J0c1Byb21pc2VSZWplY3Rpb25FdmVudDogc3VwcG9ydHNQcm9taXNlUmVqZWN0aW9uRXZlbnQsXG4gIHdyYXBwZWRDYWxsYmFjazogd3JhcHBlZENhbGxiYWNrLFxuICBlYWNoOiBlYWNoLFxuICBvYmplY3RNZXJnZTogb2JqZWN0TWVyZ2UsXG4gIHRydW5jYXRlOiB0cnVuY2F0ZSxcbiAgb2JqZWN0RnJvemVuOiBvYmplY3RGcm96ZW4sXG4gIGhhc0tleTogaGFzS2V5LFxuICBqb2luUmVnRXhwOiBqb2luUmVnRXhwLFxuICB1cmxlbmNvZGU6IHVybGVuY29kZSxcbiAgdXVpZDQ6IHV1aWQ0LFxuICBodG1sVHJlZUFzU3RyaW5nOiBodG1sVHJlZUFzU3RyaW5nLFxuICBodG1sRWxlbWVudEFzU3RyaW5nOiBodG1sRWxlbWVudEFzU3RyaW5nLFxuICBpc1NhbWVFeGNlcHRpb246IGlzU2FtZUV4Y2VwdGlvbixcbiAgaXNTYW1lU3RhY2t0cmFjZTogaXNTYW1lU3RhY2t0cmFjZSxcbiAgcGFyc2VVcmw6IHBhcnNlVXJsLFxuICBmaWxsOiBmaWxsLFxuICBzYWZlSm9pbjogc2FmZUpvaW4sXG4gIHNlcmlhbGl6ZUV4Y2VwdGlvbjogc2VyaWFsaXplRXhjZXB0aW9uLFxuICBzZXJpYWxpemVLZXlzRm9yTWVzc2FnZTogc2VyaWFsaXplS2V5c0Zvck1lc3NhZ2UsXG4gIHNhbml0aXplOiBzYW5pdGl6ZVxufTtcbiIsInZhciB1dGlscyA9IHJlcXVpcmUoJy4uLy4uL3NyYy91dGlscycpO1xuXG4vKlxuIFRyYWNlS2l0IC0gQ3Jvc3MgYnJvd2VyIHN0YWNrIHRyYWNlc1xuXG4gVGhpcyB3YXMgb3JpZ2luYWxseSBmb3JrZWQgZnJvbSBnaXRodWIuY29tL29jYy9UcmFjZUtpdCwgYnV0IGhhcyBzaW5jZSBiZWVuXG4gbGFyZ2VseSByZS13cml0dGVuIGFuZCBpcyBub3cgbWFpbnRhaW5lZCBhcyBwYXJ0IG9mIHJhdmVuLWpzLiAgVGVzdHMgZm9yXG4gdGhpcyBhcmUgaW4gdGVzdC92ZW5kb3IuXG5cbiBNSVQgbGljZW5zZVxuKi9cblxudmFyIFRyYWNlS2l0ID0ge1xuICBjb2xsZWN0V2luZG93RXJyb3JzOiB0cnVlLFxuICBkZWJ1ZzogZmFsc2Vcbn07XG5cbi8vIFRoaXMgaXMgdG8gYmUgZGVmZW5zaXZlIGluIGVudmlyb25tZW50cyB3aGVyZSB3aW5kb3cgZG9lcyBub3QgZXhpc3QgKHNlZSBodHRwczovL2dpdGh1Yi5jb20vZ2V0c2VudHJ5L3JhdmVuLWpzL3B1bGwvNzg1KVxudmFyIF93aW5kb3cgPVxuICB0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJ1xuICAgID8gd2luZG93XG4gICAgOiB0eXBlb2YgZ2xvYmFsICE9PSAndW5kZWZpbmVkJ1xuICAgID8gZ2xvYmFsXG4gICAgOiB0eXBlb2Ygc2VsZiAhPT0gJ3VuZGVmaW5lZCdcbiAgICA/IHNlbGZcbiAgICA6IHt9O1xuXG4vLyBnbG9iYWwgcmVmZXJlbmNlIHRvIHNsaWNlXG52YXIgX3NsaWNlID0gW10uc2xpY2U7XG52YXIgVU5LTk9XTl9GVU5DVElPTiA9ICc/JztcblxuLy8gaHR0cHM6Ly9kZXZlbG9wZXIubW96aWxsYS5vcmcvZW4tVVMvZG9jcy9XZWIvSmF2YVNjcmlwdC9SZWZlcmVuY2UvR2xvYmFsX09iamVjdHMvRXJyb3IjRXJyb3JfdHlwZXNcbnZhciBFUlJPUl9UWVBFU19SRSA9IC9eKD86W1V1XW5jYXVnaHQgKD86ZXhjZXB0aW9uOiApPyk/KD86KCg/OkV2YWx8SW50ZXJuYWx8UmFuZ2V8UmVmZXJlbmNlfFN5bnRheHxUeXBlfFVSSXwpRXJyb3IpOiApPyguKikkLztcblxuZnVuY3Rpb24gZ2V0TG9jYXRpb25IcmVmKCkge1xuICBpZiAodHlwZW9mIGRvY3VtZW50ID09PSAndW5kZWZpbmVkJyB8fCBkb2N1bWVudC5sb2NhdGlvbiA9PSBudWxsKSByZXR1cm4gJyc7XG4gIHJldHVybiBkb2N1bWVudC5sb2NhdGlvbi5ocmVmO1xufVxuXG5mdW5jdGlvbiBnZXRMb2NhdGlvbk9yaWdpbigpIHtcbiAgaWYgKHR5cGVvZiBkb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcgfHwgZG9jdW1lbnQubG9jYXRpb24gPT0gbnVsbCkgcmV0dXJuICcnO1xuXG4gIC8vIE9oIGRlYXIgSUUxMC4uLlxuICBpZiAoIWRvY3VtZW50LmxvY2F0aW9uLm9yaWdpbikge1xuICAgIHJldHVybiAoXG4gICAgICBkb2N1bWVudC5sb2NhdGlvbi5wcm90b2NvbCArXG4gICAgICAnLy8nICtcbiAgICAgIGRvY3VtZW50LmxvY2F0aW9uLmhvc3RuYW1lICtcbiAgICAgIChkb2N1bWVudC5sb2NhdGlvbi5wb3J0ID8gJzonICsgZG9jdW1lbnQubG9jYXRpb24ucG9ydCA6ICcnKVxuICAgICk7XG4gIH1cblxuICByZXR1cm4gZG9jdW1lbnQubG9jYXRpb24ub3JpZ2luO1xufVxuXG4vKipcbiAqIFRyYWNlS2l0LnJlcG9ydDogY3Jvc3MtYnJvd3NlciBwcm9jZXNzaW5nIG9mIHVuaGFuZGxlZCBleGNlcHRpb25zXG4gKlxuICogU3ludGF4OlxuICogICBUcmFjZUtpdC5yZXBvcnQuc3Vic2NyaWJlKGZ1bmN0aW9uKHN0YWNrSW5mbykgeyAuLi4gfSlcbiAqICAgVHJhY2VLaXQucmVwb3J0LnVuc3Vic2NyaWJlKGZ1bmN0aW9uKHN0YWNrSW5mbykgeyAuLi4gfSlcbiAqICAgVHJhY2VLaXQucmVwb3J0KGV4Y2VwdGlvbilcbiAqICAgdHJ5IHsgLi4uY29kZS4uLiB9IGNhdGNoKGV4KSB7IFRyYWNlS2l0LnJlcG9ydChleCk7IH1cbiAqXG4gKiBTdXBwb3J0czpcbiAqICAgLSBGaXJlZm94OiBmdWxsIHN0YWNrIHRyYWNlIHdpdGggbGluZSBudW1iZXJzLCBwbHVzIGNvbHVtbiBudW1iZXJcbiAqICAgICAgICAgICAgICBvbiB0b3AgZnJhbWU7IGNvbHVtbiBudW1iZXIgaXMgbm90IGd1YXJhbnRlZWRcbiAqICAgLSBPcGVyYTogICBmdWxsIHN0YWNrIHRyYWNlIHdpdGggbGluZSBhbmQgY29sdW1uIG51bWJlcnNcbiAqICAgLSBDaHJvbWU6ICBmdWxsIHN0YWNrIHRyYWNlIHdpdGggbGluZSBhbmQgY29sdW1uIG51bWJlcnNcbiAqICAgLSBTYWZhcmk6ICBsaW5lIGFuZCBjb2x1bW4gbnVtYmVyIGZvciB0aGUgdG9wIGZyYW1lIG9ubHk7IHNvbWUgZnJhbWVzXG4gKiAgICAgICAgICAgICAgbWF5IGJlIG1pc3NpbmcsIGFuZCBjb2x1bW4gbnVtYmVyIGlzIG5vdCBndWFyYW50ZWVkXG4gKiAgIC0gSUU6ICAgICAgbGluZSBhbmQgY29sdW1uIG51bWJlciBmb3IgdGhlIHRvcCBmcmFtZSBvbmx5OyBzb21lIGZyYW1lc1xuICogICAgICAgICAgICAgIG1heSBiZSBtaXNzaW5nLCBhbmQgY29sdW1uIG51bWJlciBpcyBub3QgZ3VhcmFudGVlZFxuICpcbiAqIEluIHRoZW9yeSwgVHJhY2VLaXQgc2hvdWxkIHdvcmsgb24gYWxsIG9mIHRoZSBmb2xsb3dpbmcgdmVyc2lvbnM6XG4gKiAgIC0gSUU1LjUrIChvbmx5IDguMCB0ZXN0ZWQpXG4gKiAgIC0gRmlyZWZveCAwLjkrIChvbmx5IDMuNSsgdGVzdGVkKVxuICogICAtIE9wZXJhIDcrIChvbmx5IDEwLjUwIHRlc3RlZDsgdmVyc2lvbnMgOSBhbmQgZWFybGllciBtYXkgcmVxdWlyZVxuICogICAgIEV4Y2VwdGlvbnMgSGF2ZSBTdGFja3RyYWNlIHRvIGJlIGVuYWJsZWQgaW4gb3BlcmE6Y29uZmlnKVxuICogICAtIFNhZmFyaSAzKyAob25seSA0KyB0ZXN0ZWQpXG4gKiAgIC0gQ2hyb21lIDErIChvbmx5IDUrIHRlc3RlZClcbiAqICAgLSBLb25xdWVyb3IgMy41KyAodW50ZXN0ZWQpXG4gKlxuICogUmVxdWlyZXMgVHJhY2VLaXQuY29tcHV0ZVN0YWNrVHJhY2UuXG4gKlxuICogVHJpZXMgdG8gY2F0Y2ggYWxsIHVuaGFuZGxlZCBleGNlcHRpb25zIGFuZCByZXBvcnQgdGhlbSB0byB0aGVcbiAqIHN1YnNjcmliZWQgaGFuZGxlcnMuIFBsZWFzZSBub3RlIHRoYXQgVHJhY2VLaXQucmVwb3J0IHdpbGwgcmV0aHJvdyB0aGVcbiAqIGV4Y2VwdGlvbi4gVGhpcyBpcyBSRVFVSVJFRCBpbiBvcmRlciB0byBnZXQgYSB1c2VmdWwgc3RhY2sgdHJhY2UgaW4gSUUuXG4gKiBJZiB0aGUgZXhjZXB0aW9uIGRvZXMgbm90IHJlYWNoIHRoZSB0b3Agb2YgdGhlIGJyb3dzZXIsIHlvdSB3aWxsIG9ubHlcbiAqIGdldCBhIHN0YWNrIHRyYWNlIGZyb20gdGhlIHBvaW50IHdoZXJlIFRyYWNlS2l0LnJlcG9ydCB3YXMgY2FsbGVkLlxuICpcbiAqIEhhbmRsZXJzIHJlY2VpdmUgYSBzdGFja0luZm8gb2JqZWN0IGFzIGRlc2NyaWJlZCBpbiB0aGVcbiAqIFRyYWNlS2l0LmNvbXB1dGVTdGFja1RyYWNlIGRvY3MuXG4gKi9cblRyYWNlS2l0LnJlcG9ydCA9IChmdW5jdGlvbiByZXBvcnRNb2R1bGVXcmFwcGVyKCkge1xuICB2YXIgaGFuZGxlcnMgPSBbXSxcbiAgICBsYXN0QXJncyA9IG51bGwsXG4gICAgbGFzdEV4Y2VwdGlvbiA9IG51bGwsXG4gICAgbGFzdEV4Y2VwdGlvblN0YWNrID0gbnVsbDtcblxuICAvKipcbiAgICogQWRkIGEgY3Jhc2ggaGFuZGxlci5cbiAgICogQHBhcmFtIHtGdW5jdGlvbn0gaGFuZGxlclxuICAgKi9cbiAgZnVuY3Rpb24gc3Vic2NyaWJlKGhhbmRsZXIpIHtcbiAgICBpbnN0YWxsR2xvYmFsSGFuZGxlcigpO1xuICAgIGhhbmRsZXJzLnB1c2goaGFuZGxlcik7XG4gIH1cblxuICAvKipcbiAgICogUmVtb3ZlIGEgY3Jhc2ggaGFuZGxlci5cbiAgICogQHBhcmFtIHtGdW5jdGlvbn0gaGFuZGxlclxuICAgKi9cbiAgZnVuY3Rpb24gdW5zdWJzY3JpYmUoaGFuZGxlcikge1xuICAgIGZvciAodmFyIGkgPSBoYW5kbGVycy5sZW5ndGggLSAxOyBpID49IDA7IC0taSkge1xuICAgICAgaWYgKGhhbmRsZXJzW2ldID09PSBoYW5kbGVyKSB7XG4gICAgICAgIGhhbmRsZXJzLnNwbGljZShpLCAxKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmVtb3ZlIGFsbCBjcmFzaCBoYW5kbGVycy5cbiAgICovXG4gIGZ1bmN0aW9uIHVuc3Vic2NyaWJlQWxsKCkge1xuICAgIHVuaW5zdGFsbEdsb2JhbEhhbmRsZXIoKTtcbiAgICBoYW5kbGVycyA9IFtdO1xuICB9XG5cbiAgLyoqXG4gICAqIERpc3BhdGNoIHN0YWNrIGluZm9ybWF0aW9uIHRvIGFsbCBoYW5kbGVycy5cbiAgICogQHBhcmFtIHtPYmplY3QuPHN0cmluZywgKj59IHN0YWNrXG4gICAqL1xuICBmdW5jdGlvbiBub3RpZnlIYW5kbGVycyhzdGFjaywgaXNXaW5kb3dFcnJvcikge1xuICAgIHZhciBleGNlcHRpb24gPSBudWxsO1xuICAgIGlmIChpc1dpbmRvd0Vycm9yICYmICFUcmFjZUtpdC5jb2xsZWN0V2luZG93RXJyb3JzKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGZvciAodmFyIGkgaW4gaGFuZGxlcnMpIHtcbiAgICAgIGlmIChoYW5kbGVycy5oYXNPd25Qcm9wZXJ0eShpKSkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGhhbmRsZXJzW2ldLmFwcGx5KG51bGwsIFtzdGFja10uY29uY2F0KF9zbGljZS5jYWxsKGFyZ3VtZW50cywgMikpKTtcbiAgICAgICAgfSBjYXRjaCAoaW5uZXIpIHtcbiAgICAgICAgICBleGNlcHRpb24gPSBpbm5lcjtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChleGNlcHRpb24pIHtcbiAgICAgIHRocm93IGV4Y2VwdGlvbjtcbiAgICB9XG4gIH1cblxuICB2YXIgX29sZE9uZXJyb3JIYW5kbGVyLCBfb25FcnJvckhhbmRsZXJJbnN0YWxsZWQ7XG5cbiAgLyoqXG4gICAqIEVuc3VyZXMgYWxsIGdsb2JhbCB1bmhhbmRsZWQgZXhjZXB0aW9ucyBhcmUgcmVjb3JkZWQuXG4gICAqIFN1cHBvcnRlZCBieSBHZWNrbyBhbmQgSUUuXG4gICAqIEBwYXJhbSB7c3RyaW5nfSBtc2cgRXJyb3IgbWVzc2FnZS5cbiAgICogQHBhcmFtIHtzdHJpbmd9IHVybCBVUkwgb2Ygc2NyaXB0IHRoYXQgZ2VuZXJhdGVkIHRoZSBleGNlcHRpb24uXG4gICAqIEBwYXJhbSB7KG51bWJlcnxzdHJpbmcpfSBsaW5lTm8gVGhlIGxpbmUgbnVtYmVyIGF0IHdoaWNoIHRoZSBlcnJvclxuICAgKiBvY2N1cnJlZC5cbiAgICogQHBhcmFtIHs/KG51bWJlcnxzdHJpbmcpfSBjb2xObyBUaGUgY29sdW1uIG51bWJlciBhdCB3aGljaCB0aGUgZXJyb3JcbiAgICogb2NjdXJyZWQuXG4gICAqIEBwYXJhbSB7P0Vycm9yfSBleCBUaGUgYWN0dWFsIEVycm9yIG9iamVjdC5cbiAgICovXG4gIGZ1bmN0aW9uIHRyYWNlS2l0V2luZG93T25FcnJvcihtc2csIHVybCwgbGluZU5vLCBjb2xObywgZXgpIHtcbiAgICB2YXIgc3RhY2sgPSBudWxsO1xuICAgIC8vIElmICdleCcgaXMgRXJyb3JFdmVudCwgZ2V0IHJlYWwgRXJyb3IgZnJvbSBpbnNpZGVcbiAgICB2YXIgZXhjZXB0aW9uID0gdXRpbHMuaXNFcnJvckV2ZW50KGV4KSA/IGV4LmVycm9yIDogZXg7XG4gICAgLy8gSWYgJ21zZycgaXMgRXJyb3JFdmVudCwgZ2V0IHJlYWwgbWVzc2FnZSBmcm9tIGluc2lkZVxuICAgIHZhciBtZXNzYWdlID0gdXRpbHMuaXNFcnJvckV2ZW50KG1zZykgPyBtc2cubWVzc2FnZSA6IG1zZztcblxuICAgIGlmIChsYXN0RXhjZXB0aW9uU3RhY2spIHtcbiAgICAgIFRyYWNlS2l0LmNvbXB1dGVTdGFja1RyYWNlLmF1Z21lbnRTdGFja1RyYWNlV2l0aEluaXRpYWxFbGVtZW50KFxuICAgICAgICBsYXN0RXhjZXB0aW9uU3RhY2ssXG4gICAgICAgIHVybCxcbiAgICAgICAgbGluZU5vLFxuICAgICAgICBtZXNzYWdlXG4gICAgICApO1xuICAgICAgcHJvY2Vzc0xhc3RFeGNlcHRpb24oKTtcbiAgICB9IGVsc2UgaWYgKGV4Y2VwdGlvbiAmJiB1dGlscy5pc0Vycm9yKGV4Y2VwdGlvbikpIHtcbiAgICAgIC8vIG5vbi1zdHJpbmcgYGV4Y2VwdGlvbmAgYXJnOyBhdHRlbXB0IHRvIGV4dHJhY3Qgc3RhY2sgdHJhY2VcblxuICAgICAgLy8gTmV3IGNocm9tZSBhbmQgYmxpbmsgc2VuZCBhbG9uZyBhIHJlYWwgZXJyb3Igb2JqZWN0XG4gICAgICAvLyBMZXQncyBqdXN0IHJlcG9ydCB0aGF0IGxpa2UgYSBub3JtYWwgZXJyb3IuXG4gICAgICAvLyBTZWU6IGh0dHBzOi8vbWlrZXdlc3Qub3JnLzIwMTMvMDgvZGVidWdnaW5nLXJ1bnRpbWUtZXJyb3JzLXdpdGgtd2luZG93LW9uZXJyb3JcbiAgICAgIHN0YWNrID0gVHJhY2VLaXQuY29tcHV0ZVN0YWNrVHJhY2UoZXhjZXB0aW9uKTtcbiAgICAgIG5vdGlmeUhhbmRsZXJzKHN0YWNrLCB0cnVlKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdmFyIGxvY2F0aW9uID0ge1xuICAgICAgICB1cmw6IHVybCxcbiAgICAgICAgbGluZTogbGluZU5vLFxuICAgICAgICBjb2x1bW46IGNvbE5vXG4gICAgICB9O1xuXG4gICAgICB2YXIgbmFtZSA9IHVuZGVmaW5lZDtcbiAgICAgIHZhciBncm91cHM7XG5cbiAgICAgIGlmICh7fS50b1N0cmluZy5jYWxsKG1lc3NhZ2UpID09PSAnW29iamVjdCBTdHJpbmddJykge1xuICAgICAgICB2YXIgZ3JvdXBzID0gbWVzc2FnZS5tYXRjaChFUlJPUl9UWVBFU19SRSk7XG4gICAgICAgIGlmIChncm91cHMpIHtcbiAgICAgICAgICBuYW1lID0gZ3JvdXBzWzFdO1xuICAgICAgICAgIG1lc3NhZ2UgPSBncm91cHNbMl07XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgbG9jYXRpb24uZnVuYyA9IFVOS05PV05fRlVOQ1RJT047XG5cbiAgICAgIHN0YWNrID0ge1xuICAgICAgICBuYW1lOiBuYW1lLFxuICAgICAgICBtZXNzYWdlOiBtZXNzYWdlLFxuICAgICAgICB1cmw6IGdldExvY2F0aW9uSHJlZigpLFxuICAgICAgICBzdGFjazogW2xvY2F0aW9uXVxuICAgICAgfTtcbiAgICAgIG5vdGlmeUhhbmRsZXJzKHN0YWNrLCB0cnVlKTtcbiAgICB9XG5cbiAgICBpZiAoX29sZE9uZXJyb3JIYW5kbGVyKSB7XG4gICAgICByZXR1cm4gX29sZE9uZXJyb3JIYW5kbGVyLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgZnVuY3Rpb24gaW5zdGFsbEdsb2JhbEhhbmRsZXIoKSB7XG4gICAgaWYgKF9vbkVycm9ySGFuZGxlckluc3RhbGxlZCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBfb2xkT25lcnJvckhhbmRsZXIgPSBfd2luZG93Lm9uZXJyb3I7XG4gICAgX3dpbmRvdy5vbmVycm9yID0gdHJhY2VLaXRXaW5kb3dPbkVycm9yO1xuICAgIF9vbkVycm9ySGFuZGxlckluc3RhbGxlZCA9IHRydWU7XG4gIH1cblxuICBmdW5jdGlvbiB1bmluc3RhbGxHbG9iYWxIYW5kbGVyKCkge1xuICAgIGlmICghX29uRXJyb3JIYW5kbGVySW5zdGFsbGVkKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIF93aW5kb3cub25lcnJvciA9IF9vbGRPbmVycm9ySGFuZGxlcjtcbiAgICBfb25FcnJvckhhbmRsZXJJbnN0YWxsZWQgPSBmYWxzZTtcbiAgICBfb2xkT25lcnJvckhhbmRsZXIgPSB1bmRlZmluZWQ7XG4gIH1cblxuICBmdW5jdGlvbiBwcm9jZXNzTGFzdEV4Y2VwdGlvbigpIHtcbiAgICB2YXIgX2xhc3RFeGNlcHRpb25TdGFjayA9IGxhc3RFeGNlcHRpb25TdGFjayxcbiAgICAgIF9sYXN0QXJncyA9IGxhc3RBcmdzO1xuICAgIGxhc3RBcmdzID0gbnVsbDtcbiAgICBsYXN0RXhjZXB0aW9uU3RhY2sgPSBudWxsO1xuICAgIGxhc3RFeGNlcHRpb24gPSBudWxsO1xuICAgIG5vdGlmeUhhbmRsZXJzLmFwcGx5KG51bGwsIFtfbGFzdEV4Y2VwdGlvblN0YWNrLCBmYWxzZV0uY29uY2F0KF9sYXN0QXJncykpO1xuICB9XG5cbiAgLyoqXG4gICAqIFJlcG9ydHMgYW4gdW5oYW5kbGVkIEVycm9yIHRvIFRyYWNlS2l0LlxuICAgKiBAcGFyYW0ge0Vycm9yfSBleFxuICAgKiBAcGFyYW0gez9ib29sZWFufSByZXRocm93IElmIGZhbHNlLCBkbyBub3QgcmUtdGhyb3cgdGhlIGV4Y2VwdGlvbi5cbiAgICogT25seSB1c2VkIGZvciB3aW5kb3cub25lcnJvciB0byBub3QgY2F1c2UgYW4gaW5maW5pdGUgbG9vcCBvZlxuICAgKiByZXRocm93aW5nLlxuICAgKi9cbiAgZnVuY3Rpb24gcmVwb3J0KGV4LCByZXRocm93KSB7XG4gICAgdmFyIGFyZ3MgPSBfc2xpY2UuY2FsbChhcmd1bWVudHMsIDEpO1xuICAgIGlmIChsYXN0RXhjZXB0aW9uU3RhY2spIHtcbiAgICAgIGlmIChsYXN0RXhjZXB0aW9uID09PSBleCkge1xuICAgICAgICByZXR1cm47IC8vIGFscmVhZHkgY2F1Z2h0IGJ5IGFuIGlubmVyIGNhdGNoIGJsb2NrLCBpZ25vcmVcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHByb2Nlc3NMYXN0RXhjZXB0aW9uKCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdmFyIHN0YWNrID0gVHJhY2VLaXQuY29tcHV0ZVN0YWNrVHJhY2UoZXgpO1xuICAgIGxhc3RFeGNlcHRpb25TdGFjayA9IHN0YWNrO1xuICAgIGxhc3RFeGNlcHRpb24gPSBleDtcbiAgICBsYXN0QXJncyA9IGFyZ3M7XG5cbiAgICAvLyBJZiB0aGUgc3RhY2sgdHJhY2UgaXMgaW5jb21wbGV0ZSwgd2FpdCBmb3IgMiBzZWNvbmRzIGZvclxuICAgIC8vIHNsb3cgc2xvdyBJRSB0byBzZWUgaWYgb25lcnJvciBvY2N1cnMgb3Igbm90IGJlZm9yZSByZXBvcnRpbmdcbiAgICAvLyB0aGlzIGV4Y2VwdGlvbjsgb3RoZXJ3aXNlLCB3ZSB3aWxsIGVuZCB1cCB3aXRoIGFuIGluY29tcGxldGVcbiAgICAvLyBzdGFjayB0cmFjZVxuICAgIHNldFRpbWVvdXQoXG4gICAgICBmdW5jdGlvbigpIHtcbiAgICAgICAgaWYgKGxhc3RFeGNlcHRpb24gPT09IGV4KSB7XG4gICAgICAgICAgcHJvY2Vzc0xhc3RFeGNlcHRpb24oKTtcbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIHN0YWNrLmluY29tcGxldGUgPyAyMDAwIDogMFxuICAgICk7XG5cbiAgICBpZiAocmV0aHJvdyAhPT0gZmFsc2UpIHtcbiAgICAgIHRocm93IGV4OyAvLyByZS10aHJvdyB0byBwcm9wYWdhdGUgdG8gdGhlIHRvcCBsZXZlbCAoYW5kIGNhdXNlIHdpbmRvdy5vbmVycm9yKVxuICAgIH1cbiAgfVxuXG4gIHJlcG9ydC5zdWJzY3JpYmUgPSBzdWJzY3JpYmU7XG4gIHJlcG9ydC51bnN1YnNjcmliZSA9IHVuc3Vic2NyaWJlO1xuICByZXBvcnQudW5pbnN0YWxsID0gdW5zdWJzY3JpYmVBbGw7XG4gIHJldHVybiByZXBvcnQ7XG59KSgpO1xuXG4vKipcbiAqIFRyYWNlS2l0LmNvbXB1dGVTdGFja1RyYWNlOiBjcm9zcy1icm93c2VyIHN0YWNrIHRyYWNlcyBpbiBKYXZhU2NyaXB0XG4gKlxuICogU3ludGF4OlxuICogICBzID0gVHJhY2VLaXQuY29tcHV0ZVN0YWNrVHJhY2UoZXhjZXB0aW9uKSAvLyBjb25zaWRlciB1c2luZyBUcmFjZUtpdC5yZXBvcnQgaW5zdGVhZCAoc2VlIGJlbG93KVxuICogUmV0dXJuczpcbiAqICAgcy5uYW1lICAgICAgICAgICAgICAtIGV4Y2VwdGlvbiBuYW1lXG4gKiAgIHMubWVzc2FnZSAgICAgICAgICAgLSBleGNlcHRpb24gbWVzc2FnZVxuICogICBzLnN0YWNrW2ldLnVybCAgICAgIC0gSmF2YVNjcmlwdCBvciBIVE1MIGZpbGUgVVJMXG4gKiAgIHMuc3RhY2tbaV0uZnVuYyAgICAgLSBmdW5jdGlvbiBuYW1lLCBvciBlbXB0eSBmb3IgYW5vbnltb3VzIGZ1bmN0aW9ucyAoaWYgZ3Vlc3NpbmcgZGlkIG5vdCB3b3JrKVxuICogICBzLnN0YWNrW2ldLmFyZ3MgICAgIC0gYXJndW1lbnRzIHBhc3NlZCB0byB0aGUgZnVuY3Rpb24sIGlmIGtub3duXG4gKiAgIHMuc3RhY2tbaV0ubGluZSAgICAgLSBsaW5lIG51bWJlciwgaWYga25vd25cbiAqICAgcy5zdGFja1tpXS5jb2x1bW4gICAtIGNvbHVtbiBudW1iZXIsIGlmIGtub3duXG4gKlxuICogU3VwcG9ydHM6XG4gKiAgIC0gRmlyZWZveDogIGZ1bGwgc3RhY2sgdHJhY2Ugd2l0aCBsaW5lIG51bWJlcnMgYW5kIHVucmVsaWFibGUgY29sdW1uXG4gKiAgICAgICAgICAgICAgIG51bWJlciBvbiB0b3AgZnJhbWVcbiAqICAgLSBPcGVyYSAxMDogZnVsbCBzdGFjayB0cmFjZSB3aXRoIGxpbmUgYW5kIGNvbHVtbiBudW1iZXJzXG4gKiAgIC0gT3BlcmEgOS06IGZ1bGwgc3RhY2sgdHJhY2Ugd2l0aCBsaW5lIG51bWJlcnNcbiAqICAgLSBDaHJvbWU6ICAgZnVsbCBzdGFjayB0cmFjZSB3aXRoIGxpbmUgYW5kIGNvbHVtbiBudW1iZXJzXG4gKiAgIC0gU2FmYXJpOiAgIGxpbmUgYW5kIGNvbHVtbiBudW1iZXIgZm9yIHRoZSB0b3Btb3N0IHN0YWNrdHJhY2UgZWxlbWVudFxuICogICAgICAgICAgICAgICBvbmx5XG4gKiAgIC0gSUU6ICAgICAgIG5vIGxpbmUgbnVtYmVycyB3aGF0c29ldmVyXG4gKlxuICogVHJpZXMgdG8gZ3Vlc3MgbmFtZXMgb2YgYW5vbnltb3VzIGZ1bmN0aW9ucyBieSBsb29raW5nIGZvciBhc3NpZ25tZW50c1xuICogaW4gdGhlIHNvdXJjZSBjb2RlLiBJbiBJRSBhbmQgU2FmYXJpLCB3ZSBoYXZlIHRvIGd1ZXNzIHNvdXJjZSBmaWxlIG5hbWVzXG4gKiBieSBzZWFyY2hpbmcgZm9yIGZ1bmN0aW9uIGJvZGllcyBpbnNpZGUgYWxsIHBhZ2Ugc2NyaXB0cy4gVGhpcyB3aWxsIG5vdFxuICogd29yayBmb3Igc2NyaXB0cyB0aGF0IGFyZSBsb2FkZWQgY3Jvc3MtZG9tYWluLlxuICogSGVyZSBiZSBkcmFnb25zOiBzb21lIGZ1bmN0aW9uIG5hbWVzIG1heSBiZSBndWVzc2VkIGluY29ycmVjdGx5LCBhbmRcbiAqIGR1cGxpY2F0ZSBmdW5jdGlvbnMgbWF5IGJlIG1pc21hdGNoZWQuXG4gKlxuICogVHJhY2VLaXQuY29tcHV0ZVN0YWNrVHJhY2Ugc2hvdWxkIG9ubHkgYmUgdXNlZCBmb3IgdHJhY2luZyBwdXJwb3Nlcy5cbiAqIExvZ2dpbmcgb2YgdW5oYW5kbGVkIGV4Y2VwdGlvbnMgc2hvdWxkIGJlIGRvbmUgd2l0aCBUcmFjZUtpdC5yZXBvcnQsXG4gKiB3aGljaCBidWlsZHMgb24gdG9wIG9mIFRyYWNlS2l0LmNvbXB1dGVTdGFja1RyYWNlIGFuZCBwcm92aWRlcyBiZXR0ZXJcbiAqIElFIHN1cHBvcnQgYnkgdXRpbGl6aW5nIHRoZSB3aW5kb3cub25lcnJvciBldmVudCB0byByZXRyaWV2ZSBpbmZvcm1hdGlvblxuICogYWJvdXQgdGhlIHRvcCBvZiB0aGUgc3RhY2suXG4gKlxuICogTm90ZTogSW4gSUUgYW5kIFNhZmFyaSwgbm8gc3RhY2sgdHJhY2UgaXMgcmVjb3JkZWQgb24gdGhlIEVycm9yIG9iamVjdCxcbiAqIHNvIGNvbXB1dGVTdGFja1RyYWNlIGluc3RlYWQgd2Fsa3MgaXRzICpvd24qIGNoYWluIG9mIGNhbGxlcnMuXG4gKiBUaGlzIG1lYW5zIHRoYXQ6XG4gKiAgKiBpbiBTYWZhcmksIHNvbWUgbWV0aG9kcyBtYXkgYmUgbWlzc2luZyBmcm9tIHRoZSBzdGFjayB0cmFjZTtcbiAqICAqIGluIElFLCB0aGUgdG9wbW9zdCBmdW5jdGlvbiBpbiB0aGUgc3RhY2sgdHJhY2Ugd2lsbCBhbHdheXMgYmUgdGhlXG4gKiAgICBjYWxsZXIgb2YgY29tcHV0ZVN0YWNrVHJhY2UuXG4gKlxuICogVGhpcyBpcyBva2F5IGZvciB0cmFjaW5nIChiZWNhdXNlIHlvdSBhcmUgbGlrZWx5IHRvIGJlIGNhbGxpbmdcbiAqIGNvbXB1dGVTdGFja1RyYWNlIGZyb20gdGhlIGZ1bmN0aW9uIHlvdSB3YW50IHRvIGJlIHRoZSB0b3Btb3N0IGVsZW1lbnRcbiAqIG9mIHRoZSBzdGFjayB0cmFjZSBhbnl3YXkpLCBidXQgbm90IG9rYXkgZm9yIGxvZ2dpbmcgdW5oYW5kbGVkXG4gKiBleGNlcHRpb25zIChiZWNhdXNlIHlvdXIgY2F0Y2ggYmxvY2sgd2lsbCBsaWtlbHkgYmUgZmFyIGF3YXkgZnJvbSB0aGVcbiAqIGlubmVyIGZ1bmN0aW9uIHRoYXQgYWN0dWFsbHkgY2F1c2VkIHRoZSBleGNlcHRpb24pLlxuICpcbiAqL1xuVHJhY2VLaXQuY29tcHV0ZVN0YWNrVHJhY2UgPSAoZnVuY3Rpb24gY29tcHV0ZVN0YWNrVHJhY2VXcmFwcGVyKCkge1xuICAvLyBDb250ZW50cyBvZiBFeGNlcHRpb24gaW4gdmFyaW91cyBicm93c2Vycy5cbiAgLy9cbiAgLy8gU0FGQVJJOlxuICAvLyBleC5tZXNzYWdlID0gQ2FuJ3QgZmluZCB2YXJpYWJsZTogcXFcbiAgLy8gZXgubGluZSA9IDU5XG4gIC8vIGV4LnNvdXJjZUlkID0gNTgwMjM4MTkyXG4gIC8vIGV4LnNvdXJjZVVSTCA9IGh0dHA6Ly8uLi5cbiAgLy8gZXguZXhwcmVzc2lvbkJlZ2luT2Zmc2V0ID0gOTZcbiAgLy8gZXguZXhwcmVzc2lvbkNhcmV0T2Zmc2V0ID0gOThcbiAgLy8gZXguZXhwcmVzc2lvbkVuZE9mZnNldCA9IDk4XG4gIC8vIGV4Lm5hbWUgPSBSZWZlcmVuY2VFcnJvclxuICAvL1xuICAvLyBGSVJFRk9YOlxuICAvLyBleC5tZXNzYWdlID0gcXEgaXMgbm90IGRlZmluZWRcbiAgLy8gZXguZmlsZU5hbWUgPSBodHRwOi8vLi4uXG4gIC8vIGV4LmxpbmVOdW1iZXIgPSA1OVxuICAvLyBleC5jb2x1bW5OdW1iZXIgPSA2OVxuICAvLyBleC5zdGFjayA9IC4uLnN0YWNrIHRyYWNlLi4uIChzZWUgdGhlIGV4YW1wbGUgYmVsb3cpXG4gIC8vIGV4Lm5hbWUgPSBSZWZlcmVuY2VFcnJvclxuICAvL1xuICAvLyBDSFJPTUU6XG4gIC8vIGV4Lm1lc3NhZ2UgPSBxcSBpcyBub3QgZGVmaW5lZFxuICAvLyBleC5uYW1lID0gUmVmZXJlbmNlRXJyb3JcbiAgLy8gZXgudHlwZSA9IG5vdF9kZWZpbmVkXG4gIC8vIGV4LmFyZ3VtZW50cyA9IFsnYWEnXVxuICAvLyBleC5zdGFjayA9IC4uLnN0YWNrIHRyYWNlLi4uXG4gIC8vXG4gIC8vIElOVEVSTkVUIEVYUExPUkVSOlxuICAvLyBleC5tZXNzYWdlID0gLi4uXG4gIC8vIGV4Lm5hbWUgPSBSZWZlcmVuY2VFcnJvclxuICAvL1xuICAvLyBPUEVSQTpcbiAgLy8gZXgubWVzc2FnZSA9IC4uLm1lc3NhZ2UuLi4gKHNlZSB0aGUgZXhhbXBsZSBiZWxvdylcbiAgLy8gZXgubmFtZSA9IFJlZmVyZW5jZUVycm9yXG4gIC8vIGV4Lm9wZXJhI3NvdXJjZWxvYyA9IDExICAocHJldHR5IG11Y2ggdXNlbGVzcywgZHVwbGljYXRlcyB0aGUgaW5mbyBpbiBleC5tZXNzYWdlKVxuICAvLyBleC5zdGFja3RyYWNlID0gbi9hOyBzZWUgJ29wZXJhOmNvbmZpZyNVc2VyUHJlZnN8RXhjZXB0aW9ucyBIYXZlIFN0YWNrdHJhY2UnXG5cbiAgLyoqXG4gICAqIENvbXB1dGVzIHN0YWNrIHRyYWNlIGluZm9ybWF0aW9uIGZyb20gdGhlIHN0YWNrIHByb3BlcnR5LlxuICAgKiBDaHJvbWUgYW5kIEdlY2tvIHVzZSB0aGlzIHByb3BlcnR5LlxuICAgKiBAcGFyYW0ge0Vycm9yfSBleFxuICAgKiBAcmV0dXJuIHs/T2JqZWN0LjxzdHJpbmcsICo+fSBTdGFjayB0cmFjZSBpbmZvcm1hdGlvbi5cbiAgICovXG4gIGZ1bmN0aW9uIGNvbXB1dGVTdGFja1RyYWNlRnJvbVN0YWNrUHJvcChleCkge1xuICAgIGlmICh0eXBlb2YgZXguc3RhY2sgPT09ICd1bmRlZmluZWQnIHx8ICFleC5zdGFjaykgcmV0dXJuO1xuXG4gICAgdmFyIGNocm9tZSA9IC9eXFxzKmF0ICg/OiguKj8pID9cXCgpPygoPzpmaWxlfGh0dHBzP3xibG9ifGNocm9tZS1leHRlbnNpb258bmF0aXZlfGV2YWx8d2VicGFja3w8YW5vbnltb3VzPnxbYS16XTp8XFwvKS4qPykoPzo6KFxcZCspKT8oPzo6KFxcZCspKT9cXCk/XFxzKiQvaTtcbiAgICB2YXIgd2luanMgPSAvXlxccyphdCAoPzooKD86XFxbb2JqZWN0IG9iamVjdFxcXSk/LispICk/XFwoPygoPzpmaWxlfG1zLWFwcHgoPzotd2ViKXxodHRwcz98d2VicGFja3xibG9iKTouKj8pOihcXGQrKSg/OjooXFxkKykpP1xcKT9cXHMqJC9pO1xuICAgIC8vIE5PVEU6IGJsb2IgdXJscyBhcmUgbm93IHN1cHBvc2VkIHRvIGFsd2F5cyBoYXZlIGFuIG9yaWdpbiwgdGhlcmVmb3JlIGl0J3MgZm9ybWF0XG4gICAgLy8gd2hpY2ggaXMgYGJsb2I6aHR0cDovL3VybC9wYXRoL3dpdGgtc29tZS11dWlkYCwgaXMgbWF0Y2hlZCBieSBgYmxvYi4qPzpcXC9gIGFzIHdlbGxcbiAgICB2YXIgZ2Vja28gPSAvXlxccyooLio/KSg/OlxcKCguKj8pXFwpKT8oPzpefEApKCg/OmZpbGV8aHR0cHM/fGJsb2J8Y2hyb21lfHdlYnBhY2t8cmVzb3VyY2V8bW96LWV4dGVuc2lvbikuKj86XFwvLio/fFxcW25hdGl2ZSBjb2RlXFxdfFteQF0qKD86YnVuZGxlfFxcZCtcXC5qcykpKD86OihcXGQrKSk/KD86OihcXGQrKSk/XFxzKiQvaTtcbiAgICAvLyBVc2VkIHRvIGFkZGl0aW9uYWxseSBwYXJzZSBVUkwvbGluZS9jb2x1bW4gZnJvbSBldmFsIGZyYW1lc1xuICAgIHZhciBnZWNrb0V2YWwgPSAvKFxcUyspIGxpbmUgKFxcZCspKD86ID4gZXZhbCBsaW5lIFxcZCspKiA+IGV2YWwvaTtcbiAgICB2YXIgY2hyb21lRXZhbCA9IC9cXCgoXFxTKikoPzo6KFxcZCspKSg/OjooXFxkKykpXFwpLztcbiAgICB2YXIgbGluZXMgPSBleC5zdGFjay5zcGxpdCgnXFxuJyk7XG4gICAgdmFyIHN0YWNrID0gW107XG4gICAgdmFyIHN1Ym1hdGNoO1xuICAgIHZhciBwYXJ0cztcbiAgICB2YXIgZWxlbWVudDtcbiAgICB2YXIgcmVmZXJlbmNlID0gL14oLiopIGlzIHVuZGVmaW5lZCQvLmV4ZWMoZXgubWVzc2FnZSk7XG5cbiAgICBmb3IgKHZhciBpID0gMCwgaiA9IGxpbmVzLmxlbmd0aDsgaSA8IGo7ICsraSkge1xuICAgICAgaWYgKChwYXJ0cyA9IGNocm9tZS5leGVjKGxpbmVzW2ldKSkpIHtcbiAgICAgICAgdmFyIGlzTmF0aXZlID0gcGFydHNbMl0gJiYgcGFydHNbMl0uaW5kZXhPZignbmF0aXZlJykgPT09IDA7IC8vIHN0YXJ0IG9mIGxpbmVcbiAgICAgICAgdmFyIGlzRXZhbCA9IHBhcnRzWzJdICYmIHBhcnRzWzJdLmluZGV4T2YoJ2V2YWwnKSA9PT0gMDsgLy8gc3RhcnQgb2YgbGluZVxuICAgICAgICBpZiAoaXNFdmFsICYmIChzdWJtYXRjaCA9IGNocm9tZUV2YWwuZXhlYyhwYXJ0c1syXSkpKSB7XG4gICAgICAgICAgLy8gdGhyb3cgb3V0IGV2YWwgbGluZS9jb2x1bW4gYW5kIHVzZSB0b3AtbW9zdCBsaW5lL2NvbHVtbiBudW1iZXJcbiAgICAgICAgICBwYXJ0c1syXSA9IHN1Ym1hdGNoWzFdOyAvLyB1cmxcbiAgICAgICAgICBwYXJ0c1szXSA9IHN1Ym1hdGNoWzJdOyAvLyBsaW5lXG4gICAgICAgICAgcGFydHNbNF0gPSBzdWJtYXRjaFszXTsgLy8gY29sdW1uXG4gICAgICAgIH1cbiAgICAgICAgZWxlbWVudCA9IHtcbiAgICAgICAgICB1cmw6ICFpc05hdGl2ZSA/IHBhcnRzWzJdIDogbnVsbCxcbiAgICAgICAgICBmdW5jOiBwYXJ0c1sxXSB8fCBVTktOT1dOX0ZVTkNUSU9OLFxuICAgICAgICAgIGFyZ3M6IGlzTmF0aXZlID8gW3BhcnRzWzJdXSA6IFtdLFxuICAgICAgICAgIGxpbmU6IHBhcnRzWzNdID8gK3BhcnRzWzNdIDogbnVsbCxcbiAgICAgICAgICBjb2x1bW46IHBhcnRzWzRdID8gK3BhcnRzWzRdIDogbnVsbFxuICAgICAgICB9O1xuICAgICAgfSBlbHNlIGlmICgocGFydHMgPSB3aW5qcy5leGVjKGxpbmVzW2ldKSkpIHtcbiAgICAgICAgZWxlbWVudCA9IHtcbiAgICAgICAgICB1cmw6IHBhcnRzWzJdLFxuICAgICAgICAgIGZ1bmM6IHBhcnRzWzFdIHx8IFVOS05PV05fRlVOQ1RJT04sXG4gICAgICAgICAgYXJnczogW10sXG4gICAgICAgICAgbGluZTogK3BhcnRzWzNdLFxuICAgICAgICAgIGNvbHVtbjogcGFydHNbNF0gPyArcGFydHNbNF0gOiBudWxsXG4gICAgICAgIH07XG4gICAgICB9IGVsc2UgaWYgKChwYXJ0cyA9IGdlY2tvLmV4ZWMobGluZXNbaV0pKSkge1xuICAgICAgICB2YXIgaXNFdmFsID0gcGFydHNbM10gJiYgcGFydHNbM10uaW5kZXhPZignID4gZXZhbCcpID4gLTE7XG4gICAgICAgIGlmIChpc0V2YWwgJiYgKHN1Ym1hdGNoID0gZ2Vja29FdmFsLmV4ZWMocGFydHNbM10pKSkge1xuICAgICAgICAgIC8vIHRocm93IG91dCBldmFsIGxpbmUvY29sdW1uIGFuZCB1c2UgdG9wLW1vc3QgbGluZSBudW1iZXJcbiAgICAgICAgICBwYXJ0c1szXSA9IHN1Ym1hdGNoWzFdO1xuICAgICAgICAgIHBhcnRzWzRdID0gc3VibWF0Y2hbMl07XG4gICAgICAgICAgcGFydHNbNV0gPSBudWxsOyAvLyBubyBjb2x1bW4gd2hlbiBldmFsXG4gICAgICAgIH0gZWxzZSBpZiAoaSA9PT0gMCAmJiAhcGFydHNbNV0gJiYgdHlwZW9mIGV4LmNvbHVtbk51bWJlciAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICAvLyBGaXJlRm94IHVzZXMgdGhpcyBhd2Vzb21lIGNvbHVtbk51bWJlciBwcm9wZXJ0eSBmb3IgaXRzIHRvcCBmcmFtZVxuICAgICAgICAgIC8vIEFsc28gbm90ZSwgRmlyZWZveCdzIGNvbHVtbiBudW1iZXIgaXMgMC1iYXNlZCBhbmQgZXZlcnl0aGluZyBlbHNlIGV4cGVjdHMgMS1iYXNlZCxcbiAgICAgICAgICAvLyBzbyBhZGRpbmcgMVxuICAgICAgICAgIC8vIE5PVEU6IHRoaXMgaGFjayBkb2Vzbid0IHdvcmsgaWYgdG9wLW1vc3QgZnJhbWUgaXMgZXZhbFxuICAgICAgICAgIHN0YWNrWzBdLmNvbHVtbiA9IGV4LmNvbHVtbk51bWJlciArIDE7XG4gICAgICAgIH1cbiAgICAgICAgZWxlbWVudCA9IHtcbiAgICAgICAgICB1cmw6IHBhcnRzWzNdLFxuICAgICAgICAgIGZ1bmM6IHBhcnRzWzFdIHx8IFVOS05PV05fRlVOQ1RJT04sXG4gICAgICAgICAgYXJnczogcGFydHNbMl0gPyBwYXJ0c1syXS5zcGxpdCgnLCcpIDogW10sXG4gICAgICAgICAgbGluZTogcGFydHNbNF0gPyArcGFydHNbNF0gOiBudWxsLFxuICAgICAgICAgIGNvbHVtbjogcGFydHNbNV0gPyArcGFydHNbNV0gOiBudWxsXG4gICAgICAgIH07XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKCFlbGVtZW50LmZ1bmMgJiYgZWxlbWVudC5saW5lKSB7XG4gICAgICAgIGVsZW1lbnQuZnVuYyA9IFVOS05PV05fRlVOQ1RJT047XG4gICAgICB9XG5cbiAgICAgIGlmIChlbGVtZW50LnVybCAmJiBlbGVtZW50LnVybC5zdWJzdHIoMCwgNSkgPT09ICdibG9iOicpIHtcbiAgICAgICAgLy8gU3BlY2lhbCBjYXNlIGZvciBoYW5kbGluZyBKYXZhU2NyaXB0IGxvYWRlZCBpbnRvIGEgYmxvYi5cbiAgICAgICAgLy8gV2UgdXNlIGEgc3luY2hyb25vdXMgQUpBWCByZXF1ZXN0IGhlcmUgYXMgYSBibG9iIGlzIGFscmVhZHkgaW5cbiAgICAgICAgLy8gbWVtb3J5IC0gaXQncyBub3QgbWFraW5nIGEgbmV0d29yayByZXF1ZXN0LiAgVGhpcyB3aWxsIGdlbmVyYXRlIGEgd2FybmluZ1xuICAgICAgICAvLyBpbiB0aGUgYnJvd3NlciBjb25zb2xlLCBidXQgdGhlcmUgaGFzIGFscmVhZHkgYmVlbiBhbiBlcnJvciBzbyB0aGF0J3Mgbm90XG4gICAgICAgIC8vIHRoYXQgbXVjaCBvZiBhbiBpc3N1ZS5cbiAgICAgICAgdmFyIHhociA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpO1xuICAgICAgICB4aHIub3BlbignR0VUJywgZWxlbWVudC51cmwsIGZhbHNlKTtcbiAgICAgICAgeGhyLnNlbmQobnVsbCk7XG5cbiAgICAgICAgLy8gSWYgd2UgZmFpbGVkIHRvIGRvd25sb2FkIHRoZSBzb3VyY2UsIHNraXAgdGhpcyBwYXRjaFxuICAgICAgICBpZiAoeGhyLnN0YXR1cyA9PT0gMjAwKSB7XG4gICAgICAgICAgdmFyIHNvdXJjZSA9IHhoci5yZXNwb25zZVRleHQgfHwgJyc7XG5cbiAgICAgICAgICAvLyBXZSB0cmltIHRoZSBzb3VyY2UgZG93biB0byB0aGUgbGFzdCAzMDAgY2hhcmFjdGVycyBhcyBzb3VyY2VNYXBwaW5nVVJMIGlzIGFsd2F5cyBhdCB0aGUgZW5kIG9mIHRoZSBmaWxlLlxuICAgICAgICAgIC8vIFdoeSAzMDA/IFRvIGJlIGluIGxpbmUgd2l0aDogaHR0cHM6Ly9naXRodWIuY29tL2dldHNlbnRyeS9zZW50cnkvYmxvYi80YWYyOWU4ZjIzNTBlMjBjMjhhNjkzMzM1NGU0ZjQyNDM3YjRiYTQyL3NyYy9zZW50cnkvbGFuZy9qYXZhc2NyaXB0L3Byb2Nlc3Nvci5weSNMMTY0LUwxNzVcbiAgICAgICAgICBzb3VyY2UgPSBzb3VyY2Uuc2xpY2UoLTMwMCk7XG5cbiAgICAgICAgICAvLyBOb3cgd2UgZGlnIG91dCB0aGUgc291cmNlIG1hcCBVUkxcbiAgICAgICAgICB2YXIgc291cmNlTWFwcyA9IHNvdXJjZS5tYXRjaCgvXFwvXFwvIyBzb3VyY2VNYXBwaW5nVVJMPSguKikkLyk7XG5cbiAgICAgICAgICAvLyBJZiB3ZSBkb24ndCBmaW5kIGEgc291cmNlIG1hcCBjb21tZW50IG9yIHdlIGZpbmQgbW9yZSB0aGFuIG9uZSwgY29udGludWUgb24gdG8gdGhlIG5leHQgZWxlbWVudC5cbiAgICAgICAgICBpZiAoc291cmNlTWFwcykge1xuICAgICAgICAgICAgdmFyIHNvdXJjZU1hcEFkZHJlc3MgPSBzb3VyY2VNYXBzWzFdO1xuXG4gICAgICAgICAgICAvLyBOb3cgd2UgY2hlY2sgdG8gc2VlIGlmIGl0J3MgYSByZWxhdGl2ZSBVUkwuXG4gICAgICAgICAgICAvLyBJZiBpdCBpcywgY29udmVydCBpdCB0byBhbiBhYnNvbHV0ZSBvbmUuXG4gICAgICAgICAgICBpZiAoc291cmNlTWFwQWRkcmVzcy5jaGFyQXQoMCkgPT09ICd+Jykge1xuICAgICAgICAgICAgICBzb3VyY2VNYXBBZGRyZXNzID0gZ2V0TG9jYXRpb25PcmlnaW4oKSArIHNvdXJjZU1hcEFkZHJlc3Muc2xpY2UoMSk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE5vdyB3ZSBzdHJpcCB0aGUgJy5tYXAnIG9mZiBvZiB0aGUgZW5kIG9mIHRoZSBVUkwgYW5kIHVwZGF0ZSB0aGVcbiAgICAgICAgICAgIC8vIGVsZW1lbnQgc28gdGhhdCBTZW50cnkgY2FuIG1hdGNoIHRoZSBtYXAgdG8gdGhlIGJsb2IuXG4gICAgICAgICAgICBlbGVtZW50LnVybCA9IHNvdXJjZU1hcEFkZHJlc3Muc2xpY2UoMCwgLTQpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBzdGFjay5wdXNoKGVsZW1lbnQpO1xuICAgIH1cblxuICAgIGlmICghc3RhY2subGVuZ3RoKSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG5cbiAgICByZXR1cm4ge1xuICAgICAgbmFtZTogZXgubmFtZSxcbiAgICAgIG1lc3NhZ2U6IGV4Lm1lc3NhZ2UsXG4gICAgICB1cmw6IGdldExvY2F0aW9uSHJlZigpLFxuICAgICAgc3RhY2s6IHN0YWNrXG4gICAgfTtcbiAgfVxuXG4gIC8qKlxuICAgKiBBZGRzIGluZm9ybWF0aW9uIGFib3V0IHRoZSBmaXJzdCBmcmFtZSB0byBpbmNvbXBsZXRlIHN0YWNrIHRyYWNlcy5cbiAgICogU2FmYXJpIGFuZCBJRSByZXF1aXJlIHRoaXMgdG8gZ2V0IGNvbXBsZXRlIGRhdGEgb24gdGhlIGZpcnN0IGZyYW1lLlxuICAgKiBAcGFyYW0ge09iamVjdC48c3RyaW5nLCAqPn0gc3RhY2tJbmZvIFN0YWNrIHRyYWNlIGluZm9ybWF0aW9uIGZyb21cbiAgICogb25lIG9mIHRoZSBjb21wdXRlKiBtZXRob2RzLlxuICAgKiBAcGFyYW0ge3N0cmluZ30gdXJsIFRoZSBVUkwgb2YgdGhlIHNjcmlwdCB0aGF0IGNhdXNlZCBhbiBlcnJvci5cbiAgICogQHBhcmFtIHsobnVtYmVyfHN0cmluZyl9IGxpbmVObyBUaGUgbGluZSBudW1iZXIgb2YgdGhlIHNjcmlwdCB0aGF0XG4gICAqIGNhdXNlZCBhbiBlcnJvci5cbiAgICogQHBhcmFtIHtzdHJpbmc9fSBtZXNzYWdlIFRoZSBlcnJvciBnZW5lcmF0ZWQgYnkgdGhlIGJyb3dzZXIsIHdoaWNoXG4gICAqIGhvcGVmdWxseSBjb250YWlucyB0aGUgbmFtZSBvZiB0aGUgb2JqZWN0IHRoYXQgY2F1c2VkIHRoZSBlcnJvci5cbiAgICogQHJldHVybiB7Ym9vbGVhbn0gV2hldGhlciBvciBub3QgdGhlIHN0YWNrIGluZm9ybWF0aW9uIHdhc1xuICAgKiBhdWdtZW50ZWQuXG4gICAqL1xuICBmdW5jdGlvbiBhdWdtZW50U3RhY2tUcmFjZVdpdGhJbml0aWFsRWxlbWVudChzdGFja0luZm8sIHVybCwgbGluZU5vLCBtZXNzYWdlKSB7XG4gICAgdmFyIGluaXRpYWwgPSB7XG4gICAgICB1cmw6IHVybCxcbiAgICAgIGxpbmU6IGxpbmVOb1xuICAgIH07XG5cbiAgICBpZiAoaW5pdGlhbC51cmwgJiYgaW5pdGlhbC5saW5lKSB7XG4gICAgICBzdGFja0luZm8uaW5jb21wbGV0ZSA9IGZhbHNlO1xuXG4gICAgICBpZiAoIWluaXRpYWwuZnVuYykge1xuICAgICAgICBpbml0aWFsLmZ1bmMgPSBVTktOT1dOX0ZVTkNUSU9OO1xuICAgICAgfVxuXG4gICAgICBpZiAoc3RhY2tJbmZvLnN0YWNrLmxlbmd0aCA+IDApIHtcbiAgICAgICAgaWYgKHN0YWNrSW5mby5zdGFja1swXS51cmwgPT09IGluaXRpYWwudXJsKSB7XG4gICAgICAgICAgaWYgKHN0YWNrSW5mby5zdGFja1swXS5saW5lID09PSBpbml0aWFsLmxpbmUpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTsgLy8gYWxyZWFkeSBpbiBzdGFjayB0cmFjZVxuICAgICAgICAgIH0gZWxzZSBpZiAoXG4gICAgICAgICAgICAhc3RhY2tJbmZvLnN0YWNrWzBdLmxpbmUgJiZcbiAgICAgICAgICAgIHN0YWNrSW5mby5zdGFja1swXS5mdW5jID09PSBpbml0aWFsLmZ1bmNcbiAgICAgICAgICApIHtcbiAgICAgICAgICAgIHN0YWNrSW5mby5zdGFja1swXS5saW5lID0gaW5pdGlhbC5saW5lO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBzdGFja0luZm8uc3RhY2sudW5zaGlmdChpbml0aWFsKTtcbiAgICAgIHN0YWNrSW5mby5wYXJ0aWFsID0gdHJ1ZTtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH0gZWxzZSB7XG4gICAgICBzdGFja0luZm8uaW5jb21wbGV0ZSA9IHRydWU7XG4gICAgfVxuXG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgLyoqXG4gICAqIENvbXB1dGVzIHN0YWNrIHRyYWNlIGluZm9ybWF0aW9uIGJ5IHdhbGtpbmcgdGhlIGFyZ3VtZW50cy5jYWxsZXJcbiAgICogY2hhaW4gYXQgdGhlIHRpbWUgdGhlIGV4Y2VwdGlvbiBvY2N1cnJlZC4gVGhpcyB3aWxsIGNhdXNlIGVhcmxpZXJcbiAgICogZnJhbWVzIHRvIGJlIG1pc3NlZCBidXQgaXMgdGhlIG9ubHkgd2F5IHRvIGdldCBhbnkgc3RhY2sgdHJhY2UgaW5cbiAgICogU2FmYXJpIGFuZCBJRS4gVGhlIHRvcCBmcmFtZSBpcyByZXN0b3JlZCBieVxuICAgKiB7QGxpbmsgYXVnbWVudFN0YWNrVHJhY2VXaXRoSW5pdGlhbEVsZW1lbnR9LlxuICAgKiBAcGFyYW0ge0Vycm9yfSBleFxuICAgKiBAcmV0dXJuIHs/T2JqZWN0LjxzdHJpbmcsICo+fSBTdGFjayB0cmFjZSBpbmZvcm1hdGlvbi5cbiAgICovXG4gIGZ1bmN0aW9uIGNvbXB1dGVTdGFja1RyYWNlQnlXYWxraW5nQ2FsbGVyQ2hhaW4oZXgsIGRlcHRoKSB7XG4gICAgdmFyIGZ1bmN0aW9uTmFtZSA9IC9mdW5jdGlvblxccysoW18kYS16QS1aXFx4QTAtXFx1RkZGRl1bXyRhLXpBLVowLTlcXHhBMC1cXHVGRkZGXSopP1xccypcXCgvaSxcbiAgICAgIHN0YWNrID0gW10sXG4gICAgICBmdW5jcyA9IHt9LFxuICAgICAgcmVjdXJzaW9uID0gZmFsc2UsXG4gICAgICBwYXJ0cyxcbiAgICAgIGl0ZW0sXG4gICAgICBzb3VyY2U7XG5cbiAgICBmb3IgKFxuICAgICAgdmFyIGN1cnIgPSBjb21wdXRlU3RhY2tUcmFjZUJ5V2Fsa2luZ0NhbGxlckNoYWluLmNhbGxlcjtcbiAgICAgIGN1cnIgJiYgIXJlY3Vyc2lvbjtcbiAgICAgIGN1cnIgPSBjdXJyLmNhbGxlclxuICAgICkge1xuICAgICAgaWYgKGN1cnIgPT09IGNvbXB1dGVTdGFja1RyYWNlIHx8IGN1cnIgPT09IFRyYWNlS2l0LnJlcG9ydCkge1xuICAgICAgICAvLyBjb25zb2xlLmxvZygnc2tpcHBpbmcgaW50ZXJuYWwgZnVuY3Rpb24nKTtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIGl0ZW0gPSB7XG4gICAgICAgIHVybDogbnVsbCxcbiAgICAgICAgZnVuYzogVU5LTk9XTl9GVU5DVElPTixcbiAgICAgICAgbGluZTogbnVsbCxcbiAgICAgICAgY29sdW1uOiBudWxsXG4gICAgICB9O1xuXG4gICAgICBpZiAoY3Vyci5uYW1lKSB7XG4gICAgICAgIGl0ZW0uZnVuYyA9IGN1cnIubmFtZTtcbiAgICAgIH0gZWxzZSBpZiAoKHBhcnRzID0gZnVuY3Rpb25OYW1lLmV4ZWMoY3Vyci50b1N0cmluZygpKSkpIHtcbiAgICAgICAgaXRlbS5mdW5jID0gcGFydHNbMV07XG4gICAgICB9XG5cbiAgICAgIGlmICh0eXBlb2YgaXRlbS5mdW5jID09PSAndW5kZWZpbmVkJykge1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGl0ZW0uZnVuYyA9IHBhcnRzLmlucHV0LnN1YnN0cmluZygwLCBwYXJ0cy5pbnB1dC5pbmRleE9mKCd7JykpO1xuICAgICAgICB9IGNhdGNoIChlKSB7fVxuICAgICAgfVxuXG4gICAgICBpZiAoZnVuY3NbJycgKyBjdXJyXSkge1xuICAgICAgICByZWN1cnNpb24gPSB0cnVlO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgZnVuY3NbJycgKyBjdXJyXSA9IHRydWU7XG4gICAgICB9XG5cbiAgICAgIHN0YWNrLnB1c2goaXRlbSk7XG4gICAgfVxuXG4gICAgaWYgKGRlcHRoKSB7XG4gICAgICAvLyBjb25zb2xlLmxvZygnZGVwdGggaXMgJyArIGRlcHRoKTtcbiAgICAgIC8vIGNvbnNvbGUubG9nKCdzdGFjayBpcyAnICsgc3RhY2subGVuZ3RoKTtcbiAgICAgIHN0YWNrLnNwbGljZSgwLCBkZXB0aCk7XG4gICAgfVxuXG4gICAgdmFyIHJlc3VsdCA9IHtcbiAgICAgIG5hbWU6IGV4Lm5hbWUsXG4gICAgICBtZXNzYWdlOiBleC5tZXNzYWdlLFxuICAgICAgdXJsOiBnZXRMb2NhdGlvbkhyZWYoKSxcbiAgICAgIHN0YWNrOiBzdGFja1xuICAgIH07XG4gICAgYXVnbWVudFN0YWNrVHJhY2VXaXRoSW5pdGlhbEVsZW1lbnQoXG4gICAgICByZXN1bHQsXG4gICAgICBleC5zb3VyY2VVUkwgfHwgZXguZmlsZU5hbWUsXG4gICAgICBleC5saW5lIHx8IGV4LmxpbmVOdW1iZXIsXG4gICAgICBleC5tZXNzYWdlIHx8IGV4LmRlc2NyaXB0aW9uXG4gICAgKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgLyoqXG4gICAqIENvbXB1dGVzIGEgc3RhY2sgdHJhY2UgZm9yIGFuIGV4Y2VwdGlvbi5cbiAgICogQHBhcmFtIHtFcnJvcn0gZXhcbiAgICogQHBhcmFtIHsoc3RyaW5nfG51bWJlcik9fSBkZXB0aFxuICAgKi9cbiAgZnVuY3Rpb24gY29tcHV0ZVN0YWNrVHJhY2UoZXgsIGRlcHRoKSB7XG4gICAgdmFyIHN0YWNrID0gbnVsbDtcbiAgICBkZXB0aCA9IGRlcHRoID09IG51bGwgPyAwIDogK2RlcHRoO1xuXG4gICAgdHJ5IHtcbiAgICAgIHN0YWNrID0gY29tcHV0ZVN0YWNrVHJhY2VGcm9tU3RhY2tQcm9wKGV4KTtcbiAgICAgIGlmIChzdGFjaykge1xuICAgICAgICByZXR1cm4gc3RhY2s7XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgaWYgKFRyYWNlS2l0LmRlYnVnKSB7XG4gICAgICAgIHRocm93IGU7XG4gICAgICB9XG4gICAgfVxuXG4gICAgdHJ5IHtcbiAgICAgIHN0YWNrID0gY29tcHV0ZVN0YWNrVHJhY2VCeVdhbGtpbmdDYWxsZXJDaGFpbihleCwgZGVwdGggKyAxKTtcbiAgICAgIGlmIChzdGFjaykge1xuICAgICAgICByZXR1cm4gc3RhY2s7XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgaWYgKFRyYWNlS2l0LmRlYnVnKSB7XG4gICAgICAgIHRocm93IGU7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiB7XG4gICAgICBuYW1lOiBleC5uYW1lLFxuICAgICAgbWVzc2FnZTogZXgubWVzc2FnZSxcbiAgICAgIHVybDogZ2V0TG9jYXRpb25IcmVmKClcbiAgICB9O1xuICB9XG5cbiAgY29tcHV0ZVN0YWNrVHJhY2UuYXVnbWVudFN0YWNrVHJhY2VXaXRoSW5pdGlhbEVsZW1lbnQgPSBhdWdtZW50U3RhY2tUcmFjZVdpdGhJbml0aWFsRWxlbWVudDtcbiAgY29tcHV0ZVN0YWNrVHJhY2UuY29tcHV0ZVN0YWNrVHJhY2VGcm9tU3RhY2tQcm9wID0gY29tcHV0ZVN0YWNrVHJhY2VGcm9tU3RhY2tQcm9wO1xuXG4gIHJldHVybiBjb21wdXRlU3RhY2tUcmFjZTtcbn0pKCk7XG5cbm1vZHVsZS5leHBvcnRzID0gVHJhY2VLaXQ7XG4iLCIvKlxuIGpzb24tc3RyaW5naWZ5LXNhZmVcbiBMaWtlIEpTT04uc3RyaW5naWZ5LCBidXQgZG9lc24ndCB0aHJvdyBvbiBjaXJjdWxhciByZWZlcmVuY2VzLlxuXG4gT3JpZ2luYWxseSBmb3JrZWQgZnJvbSBodHRwczovL2dpdGh1Yi5jb20vaXNhYWNzL2pzb24tc3RyaW5naWZ5LXNhZmVcbiB2ZXJzaW9uIDUuMC4xIG9uIDMvOC8yMDE3IGFuZCBtb2RpZmllZCB0byBoYW5kbGUgRXJyb3JzIHNlcmlhbGl6YXRpb25cbiBhbmQgSUU4IGNvbXBhdGliaWxpdHkuIFRlc3RzIGZvciB0aGlzIGFyZSBpbiB0ZXN0L3ZlbmRvci5cblxuIElTQyBsaWNlbnNlOiBodHRwczovL2dpdGh1Yi5jb20vaXNhYWNzL2pzb24tc3RyaW5naWZ5LXNhZmUvYmxvYi9tYXN0ZXIvTElDRU5TRVxuKi9cblxuZXhwb3J0cyA9IG1vZHVsZS5leHBvcnRzID0gc3RyaW5naWZ5O1xuZXhwb3J0cy5nZXRTZXJpYWxpemUgPSBzZXJpYWxpemVyO1xuXG5mdW5jdGlvbiBpbmRleE9mKGhheXN0YWNrLCBuZWVkbGUpIHtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBoYXlzdGFjay5sZW5ndGg7ICsraSkge1xuICAgIGlmIChoYXlzdGFja1tpXSA9PT0gbmVlZGxlKSByZXR1cm4gaTtcbiAgfVxuICByZXR1cm4gLTE7XG59XG5cbmZ1bmN0aW9uIHN0cmluZ2lmeShvYmosIHJlcGxhY2VyLCBzcGFjZXMsIGN5Y2xlUmVwbGFjZXIpIHtcbiAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KG9iaiwgc2VyaWFsaXplcihyZXBsYWNlciwgY3ljbGVSZXBsYWNlciksIHNwYWNlcyk7XG59XG5cbi8vIGh0dHBzOi8vZ2l0aHViLmNvbS9mdGxhYnMvanMtYWJicmV2aWF0ZS9ibG9iL2ZhNzA5ZTVmMTM5ZTc3NzBhNzE4MjdiMTg5M2YyMjQxODA5N2ZiZGEvaW5kZXguanMjTDk1LUwxMDZcbmZ1bmN0aW9uIHN0cmluZ2lmeUVycm9yKHZhbHVlKSB7XG4gIHZhciBlcnIgPSB7XG4gICAgLy8gVGhlc2UgcHJvcGVydGllcyBhcmUgaW1wbGVtZW50ZWQgYXMgbWFnaWNhbCBnZXR0ZXJzIGFuZCBkb24ndCBzaG93IHVwIGluIGZvciBpblxuICAgIHN0YWNrOiB2YWx1ZS5zdGFjayxcbiAgICBtZXNzYWdlOiB2YWx1ZS5tZXNzYWdlLFxuICAgIG5hbWU6IHZhbHVlLm5hbWVcbiAgfTtcblxuICBmb3IgKHZhciBpIGluIHZhbHVlKSB7XG4gICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbCh2YWx1ZSwgaSkpIHtcbiAgICAgIGVycltpXSA9IHZhbHVlW2ldO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBlcnI7XG59XG5cbmZ1bmN0aW9uIHNlcmlhbGl6ZXIocmVwbGFjZXIsIGN5Y2xlUmVwbGFjZXIpIHtcbiAgdmFyIHN0YWNrID0gW107XG4gIHZhciBrZXlzID0gW107XG5cbiAgaWYgKGN5Y2xlUmVwbGFjZXIgPT0gbnVsbCkge1xuICAgIGN5Y2xlUmVwbGFjZXIgPSBmdW5jdGlvbihrZXksIHZhbHVlKSB7XG4gICAgICBpZiAoc3RhY2tbMF0gPT09IHZhbHVlKSB7XG4gICAgICAgIHJldHVybiAnW0NpcmN1bGFyIH5dJztcbiAgICAgIH1cbiAgICAgIHJldHVybiAnW0NpcmN1bGFyIH4uJyArIGtleXMuc2xpY2UoMCwgaW5kZXhPZihzdGFjaywgdmFsdWUpKS5qb2luKCcuJykgKyAnXSc7XG4gICAgfTtcbiAgfVxuXG4gIHJldHVybiBmdW5jdGlvbihrZXksIHZhbHVlKSB7XG4gICAgaWYgKHN0YWNrLmxlbmd0aCA+IDApIHtcbiAgICAgIHZhciB0aGlzUG9zID0gaW5kZXhPZihzdGFjaywgdGhpcyk7XG4gICAgICB+dGhpc1BvcyA/IHN0YWNrLnNwbGljZSh0aGlzUG9zICsgMSkgOiBzdGFjay5wdXNoKHRoaXMpO1xuICAgICAgfnRoaXNQb3MgPyBrZXlzLnNwbGljZSh0aGlzUG9zLCBJbmZpbml0eSwga2V5KSA6IGtleXMucHVzaChrZXkpO1xuXG4gICAgICBpZiAofmluZGV4T2Yoc3RhY2ssIHZhbHVlKSkge1xuICAgICAgICB2YWx1ZSA9IGN5Y2xlUmVwbGFjZXIuY2FsbCh0aGlzLCBrZXksIHZhbHVlKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgc3RhY2sucHVzaCh2YWx1ZSk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcGxhY2VyID09IG51bGxcbiAgICAgID8gdmFsdWUgaW5zdGFuY2VvZiBFcnJvciA/IHN0cmluZ2lmeUVycm9yKHZhbHVlKSA6IHZhbHVlXG4gICAgICA6IHJlcGxhY2VyLmNhbGwodGhpcywga2V5LCB2YWx1ZSk7XG4gIH07XG59XG4iLCIvKlxuICogSmF2YVNjcmlwdCBNRDVcbiAqIGh0dHBzOi8vZ2l0aHViLmNvbS9ibHVlaW1wL0phdmFTY3JpcHQtTUQ1XG4gKlxuICogQ29weXJpZ2h0IDIwMTEsIFNlYmFzdGlhbiBUc2NoYW5cbiAqIGh0dHBzOi8vYmx1ZWltcC5uZXRcbiAqXG4gKiBMaWNlbnNlZCB1bmRlciB0aGUgTUlUIGxpY2Vuc2U6XG4gKiBodHRwczovL29wZW5zb3VyY2Uub3JnL2xpY2Vuc2VzL01JVFxuICpcbiAqIEJhc2VkIG9uXG4gKiBBIEphdmFTY3JpcHQgaW1wbGVtZW50YXRpb24gb2YgdGhlIFJTQSBEYXRhIFNlY3VyaXR5LCBJbmMuIE1ENSBNZXNzYWdlXG4gKiBEaWdlc3QgQWxnb3JpdGhtLCBhcyBkZWZpbmVkIGluIFJGQyAxMzIxLlxuICogVmVyc2lvbiAyLjIgQ29weXJpZ2h0IChDKSBQYXVsIEpvaG5zdG9uIDE5OTkgLSAyMDA5XG4gKiBPdGhlciBjb250cmlidXRvcnM6IEdyZWcgSG9sdCwgQW5kcmV3IEtlcGVydCwgWWRuYXIsIExvc3RpbmV0XG4gKiBEaXN0cmlidXRlZCB1bmRlciB0aGUgQlNEIExpY2Vuc2VcbiAqIFNlZSBodHRwOi8vcGFqaG9tZS5vcmcudWsvY3J5cHQvbWQ1IGZvciBtb3JlIGluZm8uXG4gKi9cblxuLypcbiogQWRkIGludGVnZXJzLCB3cmFwcGluZyBhdCAyXjMyLiBUaGlzIHVzZXMgMTYtYml0IG9wZXJhdGlvbnMgaW50ZXJuYWxseVxuKiB0byB3b3JrIGFyb3VuZCBidWdzIGluIHNvbWUgSlMgaW50ZXJwcmV0ZXJzLlxuKi9cbmZ1bmN0aW9uIHNhZmVBZGQoeCwgeSkge1xuICB2YXIgbHN3ID0gKHggJiAweGZmZmYpICsgKHkgJiAweGZmZmYpO1xuICB2YXIgbXN3ID0gKHggPj4gMTYpICsgKHkgPj4gMTYpICsgKGxzdyA+PiAxNik7XG4gIHJldHVybiAobXN3IDw8IDE2KSB8IChsc3cgJiAweGZmZmYpO1xufVxuXG4vKlxuKiBCaXR3aXNlIHJvdGF0ZSBhIDMyLWJpdCBudW1iZXIgdG8gdGhlIGxlZnQuXG4qL1xuZnVuY3Rpb24gYml0Um90YXRlTGVmdChudW0sIGNudCkge1xuICByZXR1cm4gKG51bSA8PCBjbnQpIHwgKG51bSA+Pj4gKDMyIC0gY250KSk7XG59XG5cbi8qXG4qIFRoZXNlIGZ1bmN0aW9ucyBpbXBsZW1lbnQgdGhlIGZvdXIgYmFzaWMgb3BlcmF0aW9ucyB0aGUgYWxnb3JpdGhtIHVzZXMuXG4qL1xuZnVuY3Rpb24gbWQ1Y21uKHEsIGEsIGIsIHgsIHMsIHQpIHtcbiAgcmV0dXJuIHNhZmVBZGQoYml0Um90YXRlTGVmdChzYWZlQWRkKHNhZmVBZGQoYSwgcSksIHNhZmVBZGQoeCwgdCkpLCBzKSwgYik7XG59XG5mdW5jdGlvbiBtZDVmZihhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG4gIHJldHVybiBtZDVjbW4oKGIgJiBjKSB8ICh+YiAmIGQpLCBhLCBiLCB4LCBzLCB0KTtcbn1cbmZ1bmN0aW9uIG1kNWdnKGEsIGIsIGMsIGQsIHgsIHMsIHQpIHtcbiAgcmV0dXJuIG1kNWNtbigoYiAmIGQpIHwgKGMgJiB+ZCksIGEsIGIsIHgsIHMsIHQpO1xufVxuZnVuY3Rpb24gbWQ1aGgoYSwgYiwgYywgZCwgeCwgcywgdCkge1xuICByZXR1cm4gbWQ1Y21uKGIgXiBjIF4gZCwgYSwgYiwgeCwgcywgdCk7XG59XG5mdW5jdGlvbiBtZDVpaShhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG4gIHJldHVybiBtZDVjbW4oYyBeIChiIHwgfmQpLCBhLCBiLCB4LCBzLCB0KTtcbn1cblxuLypcbiogQ2FsY3VsYXRlIHRoZSBNRDUgb2YgYW4gYXJyYXkgb2YgbGl0dGxlLWVuZGlhbiB3b3JkcywgYW5kIGEgYml0IGxlbmd0aC5cbiovXG5mdW5jdGlvbiBiaW5sTUQ1KHgsIGxlbikge1xuICAvKiBhcHBlbmQgcGFkZGluZyAqL1xuICB4W2xlbiA+PiA1XSB8PSAweDgwIDw8IChsZW4gJSAzMik7XG4gIHhbKCgobGVuICsgNjQpID4+PiA5KSA8PCA0KSArIDE0XSA9IGxlbjtcblxuICB2YXIgaTtcbiAgdmFyIG9sZGE7XG4gIHZhciBvbGRiO1xuICB2YXIgb2xkYztcbiAgdmFyIG9sZGQ7XG4gIHZhciBhID0gMTczMjU4NDE5MztcbiAgdmFyIGIgPSAtMjcxNzMzODc5O1xuICB2YXIgYyA9IC0xNzMyNTg0MTk0O1xuICB2YXIgZCA9IDI3MTczMzg3ODtcblxuICBmb3IgKGkgPSAwOyBpIDwgeC5sZW5ndGg7IGkgKz0gMTYpIHtcbiAgICBvbGRhID0gYTtcbiAgICBvbGRiID0gYjtcbiAgICBvbGRjID0gYztcbiAgICBvbGRkID0gZDtcblxuICAgIGEgPSBtZDVmZihhLCBiLCBjLCBkLCB4W2ldLCA3LCAtNjgwODc2OTM2KTtcbiAgICBkID0gbWQ1ZmYoZCwgYSwgYiwgYywgeFtpICsgMV0sIDEyLCAtMzg5NTY0NTg2KTtcbiAgICBjID0gbWQ1ZmYoYywgZCwgYSwgYiwgeFtpICsgMl0sIDE3LCA2MDYxMDU4MTkpO1xuICAgIGIgPSBtZDVmZihiLCBjLCBkLCBhLCB4W2kgKyAzXSwgMjIsIC0xMDQ0NTI1MzMwKTtcbiAgICBhID0gbWQ1ZmYoYSwgYiwgYywgZCwgeFtpICsgNF0sIDcsIC0xNzY0MTg4OTcpO1xuICAgIGQgPSBtZDVmZihkLCBhLCBiLCBjLCB4W2kgKyA1XSwgMTIsIDEyMDAwODA0MjYpO1xuICAgIGMgPSBtZDVmZihjLCBkLCBhLCBiLCB4W2kgKyA2XSwgMTcsIC0xNDczMjMxMzQxKTtcbiAgICBiID0gbWQ1ZmYoYiwgYywgZCwgYSwgeFtpICsgN10sIDIyLCAtNDU3MDU5ODMpO1xuICAgIGEgPSBtZDVmZihhLCBiLCBjLCBkLCB4W2kgKyA4XSwgNywgMTc3MDAzNTQxNik7XG4gICAgZCA9IG1kNWZmKGQsIGEsIGIsIGMsIHhbaSArIDldLCAxMiwgLTE5NTg0MTQ0MTcpO1xuICAgIGMgPSBtZDVmZihjLCBkLCBhLCBiLCB4W2kgKyAxMF0sIDE3LCAtNDIwNjMpO1xuICAgIGIgPSBtZDVmZihiLCBjLCBkLCBhLCB4W2kgKyAxMV0sIDIyLCAtMTk5MDQwNDE2Mik7XG4gICAgYSA9IG1kNWZmKGEsIGIsIGMsIGQsIHhbaSArIDEyXSwgNywgMTgwNDYwMzY4Mik7XG4gICAgZCA9IG1kNWZmKGQsIGEsIGIsIGMsIHhbaSArIDEzXSwgMTIsIC00MDM0MTEwMSk7XG4gICAgYyA9IG1kNWZmKGMsIGQsIGEsIGIsIHhbaSArIDE0XSwgMTcsIC0xNTAyMDAyMjkwKTtcbiAgICBiID0gbWQ1ZmYoYiwgYywgZCwgYSwgeFtpICsgMTVdLCAyMiwgMTIzNjUzNTMyOSk7XG5cbiAgICBhID0gbWQ1Z2coYSwgYiwgYywgZCwgeFtpICsgMV0sIDUsIC0xNjU3OTY1MTApO1xuICAgIGQgPSBtZDVnZyhkLCBhLCBiLCBjLCB4W2kgKyA2XSwgOSwgLTEwNjk1MDE2MzIpO1xuICAgIGMgPSBtZDVnZyhjLCBkLCBhLCBiLCB4W2kgKyAxMV0sIDE0LCA2NDM3MTc3MTMpO1xuICAgIGIgPSBtZDVnZyhiLCBjLCBkLCBhLCB4W2ldLCAyMCwgLTM3Mzg5NzMwMik7XG4gICAgYSA9IG1kNWdnKGEsIGIsIGMsIGQsIHhbaSArIDVdLCA1LCAtNzAxNTU4NjkxKTtcbiAgICBkID0gbWQ1Z2coZCwgYSwgYiwgYywgeFtpICsgMTBdLCA5LCAzODAxNjA4Myk7XG4gICAgYyA9IG1kNWdnKGMsIGQsIGEsIGIsIHhbaSArIDE1XSwgMTQsIC02NjA0NzgzMzUpO1xuICAgIGIgPSBtZDVnZyhiLCBjLCBkLCBhLCB4W2kgKyA0XSwgMjAsIC00MDU1Mzc4NDgpO1xuICAgIGEgPSBtZDVnZyhhLCBiLCBjLCBkLCB4W2kgKyA5XSwgNSwgNTY4NDQ2NDM4KTtcbiAgICBkID0gbWQ1Z2coZCwgYSwgYiwgYywgeFtpICsgMTRdLCA5LCAtMTAxOTgwMzY5MCk7XG4gICAgYyA9IG1kNWdnKGMsIGQsIGEsIGIsIHhbaSArIDNdLCAxNCwgLTE4NzM2Mzk2MSk7XG4gICAgYiA9IG1kNWdnKGIsIGMsIGQsIGEsIHhbaSArIDhdLCAyMCwgMTE2MzUzMTUwMSk7XG4gICAgYSA9IG1kNWdnKGEsIGIsIGMsIGQsIHhbaSArIDEzXSwgNSwgLTE0NDQ2ODE0NjcpO1xuICAgIGQgPSBtZDVnZyhkLCBhLCBiLCBjLCB4W2kgKyAyXSwgOSwgLTUxNDAzNzg0KTtcbiAgICBjID0gbWQ1Z2coYywgZCwgYSwgYiwgeFtpICsgN10sIDE0LCAxNzM1MzI4NDczKTtcbiAgICBiID0gbWQ1Z2coYiwgYywgZCwgYSwgeFtpICsgMTJdLCAyMCwgLTE5MjY2MDc3MzQpO1xuXG4gICAgYSA9IG1kNWhoKGEsIGIsIGMsIGQsIHhbaSArIDVdLCA0LCAtMzc4NTU4KTtcbiAgICBkID0gbWQ1aGgoZCwgYSwgYiwgYywgeFtpICsgOF0sIDExLCAtMjAyMjU3NDQ2Myk7XG4gICAgYyA9IG1kNWhoKGMsIGQsIGEsIGIsIHhbaSArIDExXSwgMTYsIDE4MzkwMzA1NjIpO1xuICAgIGIgPSBtZDVoaChiLCBjLCBkLCBhLCB4W2kgKyAxNF0sIDIzLCAtMzUzMDk1NTYpO1xuICAgIGEgPSBtZDVoaChhLCBiLCBjLCBkLCB4W2kgKyAxXSwgNCwgLTE1MzA5OTIwNjApO1xuICAgIGQgPSBtZDVoaChkLCBhLCBiLCBjLCB4W2kgKyA0XSwgMTEsIDEyNzI4OTMzNTMpO1xuICAgIGMgPSBtZDVoaChjLCBkLCBhLCBiLCB4W2kgKyA3XSwgMTYsIC0xNTU0OTc2MzIpO1xuICAgIGIgPSBtZDVoaChiLCBjLCBkLCBhLCB4W2kgKyAxMF0sIDIzLCAtMTA5NDczMDY0MCk7XG4gICAgYSA9IG1kNWhoKGEsIGIsIGMsIGQsIHhbaSArIDEzXSwgNCwgNjgxMjc5MTc0KTtcbiAgICBkID0gbWQ1aGgoZCwgYSwgYiwgYywgeFtpXSwgMTEsIC0zNTg1MzcyMjIpO1xuICAgIGMgPSBtZDVoaChjLCBkLCBhLCBiLCB4W2kgKyAzXSwgMTYsIC03MjI1MjE5NzkpO1xuICAgIGIgPSBtZDVoaChiLCBjLCBkLCBhLCB4W2kgKyA2XSwgMjMsIDc2MDI5MTg5KTtcbiAgICBhID0gbWQ1aGgoYSwgYiwgYywgZCwgeFtpICsgOV0sIDQsIC02NDAzNjQ0ODcpO1xuICAgIGQgPSBtZDVoaChkLCBhLCBiLCBjLCB4W2kgKyAxMl0sIDExLCAtNDIxODE1ODM1KTtcbiAgICBjID0gbWQ1aGgoYywgZCwgYSwgYiwgeFtpICsgMTVdLCAxNiwgNTMwNzQyNTIwKTtcbiAgICBiID0gbWQ1aGgoYiwgYywgZCwgYSwgeFtpICsgMl0sIDIzLCAtOTk1MzM4NjUxKTtcblxuICAgIGEgPSBtZDVpaShhLCBiLCBjLCBkLCB4W2ldLCA2LCAtMTk4NjMwODQ0KTtcbiAgICBkID0gbWQ1aWkoZCwgYSwgYiwgYywgeFtpICsgN10sIDEwLCAxMTI2ODkxNDE1KTtcbiAgICBjID0gbWQ1aWkoYywgZCwgYSwgYiwgeFtpICsgMTRdLCAxNSwgLTE0MTYzNTQ5MDUpO1xuICAgIGIgPSBtZDVpaShiLCBjLCBkLCBhLCB4W2kgKyA1XSwgMjEsIC01NzQzNDA1NSk7XG4gICAgYSA9IG1kNWlpKGEsIGIsIGMsIGQsIHhbaSArIDEyXSwgNiwgMTcwMDQ4NTU3MSk7XG4gICAgZCA9IG1kNWlpKGQsIGEsIGIsIGMsIHhbaSArIDNdLCAxMCwgLTE4OTQ5ODY2MDYpO1xuICAgIGMgPSBtZDVpaShjLCBkLCBhLCBiLCB4W2kgKyAxMF0sIDE1LCAtMTA1MTUyMyk7XG4gICAgYiA9IG1kNWlpKGIsIGMsIGQsIGEsIHhbaSArIDFdLCAyMSwgLTIwNTQ5MjI3OTkpO1xuICAgIGEgPSBtZDVpaShhLCBiLCBjLCBkLCB4W2kgKyA4XSwgNiwgMTg3MzMxMzM1OSk7XG4gICAgZCA9IG1kNWlpKGQsIGEsIGIsIGMsIHhbaSArIDE1XSwgMTAsIC0zMDYxMTc0NCk7XG4gICAgYyA9IG1kNWlpKGMsIGQsIGEsIGIsIHhbaSArIDZdLCAxNSwgLTE1NjAxOTgzODApO1xuICAgIGIgPSBtZDVpaShiLCBjLCBkLCBhLCB4W2kgKyAxM10sIDIxLCAxMzA5MTUxNjQ5KTtcbiAgICBhID0gbWQ1aWkoYSwgYiwgYywgZCwgeFtpICsgNF0sIDYsIC0xNDU1MjMwNzApO1xuICAgIGQgPSBtZDVpaShkLCBhLCBiLCBjLCB4W2kgKyAxMV0sIDEwLCAtMTEyMDIxMDM3OSk7XG4gICAgYyA9IG1kNWlpKGMsIGQsIGEsIGIsIHhbaSArIDJdLCAxNSwgNzE4Nzg3MjU5KTtcbiAgICBiID0gbWQ1aWkoYiwgYywgZCwgYSwgeFtpICsgOV0sIDIxLCAtMzQzNDg1NTUxKTtcblxuICAgIGEgPSBzYWZlQWRkKGEsIG9sZGEpO1xuICAgIGIgPSBzYWZlQWRkKGIsIG9sZGIpO1xuICAgIGMgPSBzYWZlQWRkKGMsIG9sZGMpO1xuICAgIGQgPSBzYWZlQWRkKGQsIG9sZGQpO1xuICB9XG4gIHJldHVybiBbYSwgYiwgYywgZF07XG59XG5cbi8qXG4qIENvbnZlcnQgYW4gYXJyYXkgb2YgbGl0dGxlLWVuZGlhbiB3b3JkcyB0byBhIHN0cmluZ1xuKi9cbmZ1bmN0aW9uIGJpbmwycnN0cihpbnB1dCkge1xuICB2YXIgaTtcbiAgdmFyIG91dHB1dCA9ICcnO1xuICB2YXIgbGVuZ3RoMzIgPSBpbnB1dC5sZW5ndGggKiAzMjtcbiAgZm9yIChpID0gMDsgaSA8IGxlbmd0aDMyOyBpICs9IDgpIHtcbiAgICBvdXRwdXQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZSgoaW5wdXRbaSA+PiA1XSA+Pj4gKGkgJSAzMikpICYgMHhmZik7XG4gIH1cbiAgcmV0dXJuIG91dHB1dDtcbn1cblxuLypcbiogQ29udmVydCBhIHJhdyBzdHJpbmcgdG8gYW4gYXJyYXkgb2YgbGl0dGxlLWVuZGlhbiB3b3Jkc1xuKiBDaGFyYWN0ZXJzID4yNTUgaGF2ZSB0aGVpciBoaWdoLWJ5dGUgc2lsZW50bHkgaWdub3JlZC5cbiovXG5mdW5jdGlvbiByc3RyMmJpbmwoaW5wdXQpIHtcbiAgdmFyIGk7XG4gIHZhciBvdXRwdXQgPSBbXTtcbiAgb3V0cHV0WyhpbnB1dC5sZW5ndGggPj4gMikgLSAxXSA9IHVuZGVmaW5lZDtcbiAgZm9yIChpID0gMDsgaSA8IG91dHB1dC5sZW5ndGg7IGkgKz0gMSkge1xuICAgIG91dHB1dFtpXSA9IDA7XG4gIH1cbiAgdmFyIGxlbmd0aDggPSBpbnB1dC5sZW5ndGggKiA4O1xuICBmb3IgKGkgPSAwOyBpIDwgbGVuZ3RoODsgaSArPSA4KSB7XG4gICAgb3V0cHV0W2kgPj4gNV0gfD0gKGlucHV0LmNoYXJDb2RlQXQoaSAvIDgpICYgMHhmZikgPDwgKGkgJSAzMik7XG4gIH1cbiAgcmV0dXJuIG91dHB1dDtcbn1cblxuLypcbiogQ2FsY3VsYXRlIHRoZSBNRDUgb2YgYSByYXcgc3RyaW5nXG4qL1xuZnVuY3Rpb24gcnN0ck1ENShzKSB7XG4gIHJldHVybiBiaW5sMnJzdHIoYmlubE1ENShyc3RyMmJpbmwocyksIHMubGVuZ3RoICogOCkpO1xufVxuXG4vKlxuKiBDYWxjdWxhdGUgdGhlIEhNQUMtTUQ1LCBvZiBhIGtleSBhbmQgc29tZSBkYXRhIChyYXcgc3RyaW5ncylcbiovXG5mdW5jdGlvbiByc3RySE1BQ01ENShrZXksIGRhdGEpIHtcbiAgdmFyIGk7XG4gIHZhciBia2V5ID0gcnN0cjJiaW5sKGtleSk7XG4gIHZhciBpcGFkID0gW107XG4gIHZhciBvcGFkID0gW107XG4gIHZhciBoYXNoO1xuICBpcGFkWzE1XSA9IG9wYWRbMTVdID0gdW5kZWZpbmVkO1xuICBpZiAoYmtleS5sZW5ndGggPiAxNikge1xuICAgIGJrZXkgPSBiaW5sTUQ1KGJrZXksIGtleS5sZW5ndGggKiA4KTtcbiAgfVxuICBmb3IgKGkgPSAwOyBpIDwgMTY7IGkgKz0gMSkge1xuICAgIGlwYWRbaV0gPSBia2V5W2ldIF4gMHgzNjM2MzYzNjtcbiAgICBvcGFkW2ldID0gYmtleVtpXSBeIDB4NWM1YzVjNWM7XG4gIH1cbiAgaGFzaCA9IGJpbmxNRDUoaXBhZC5jb25jYXQocnN0cjJiaW5sKGRhdGEpKSwgNTEyICsgZGF0YS5sZW5ndGggKiA4KTtcbiAgcmV0dXJuIGJpbmwycnN0cihiaW5sTUQ1KG9wYWQuY29uY2F0KGhhc2gpLCA1MTIgKyAxMjgpKTtcbn1cblxuLypcbiogQ29udmVydCBhIHJhdyBzdHJpbmcgdG8gYSBoZXggc3RyaW5nXG4qL1xuZnVuY3Rpb24gcnN0cjJoZXgoaW5wdXQpIHtcbiAgdmFyIGhleFRhYiA9ICcwMTIzNDU2Nzg5YWJjZGVmJztcbiAgdmFyIG91dHB1dCA9ICcnO1xuICB2YXIgeDtcbiAgdmFyIGk7XG4gIGZvciAoaSA9IDA7IGkgPCBpbnB1dC5sZW5ndGg7IGkgKz0gMSkge1xuICAgIHggPSBpbnB1dC5jaGFyQ29kZUF0KGkpO1xuICAgIG91dHB1dCArPSBoZXhUYWIuY2hhckF0KCh4ID4+PiA0KSAmIDB4MGYpICsgaGV4VGFiLmNoYXJBdCh4ICYgMHgwZik7XG4gIH1cbiAgcmV0dXJuIG91dHB1dDtcbn1cblxuLypcbiogRW5jb2RlIGEgc3RyaW5nIGFzIHV0Zi04XG4qL1xuZnVuY3Rpb24gc3RyMnJzdHJVVEY4KGlucHV0KSB7XG4gIHJldHVybiB1bmVzY2FwZShlbmNvZGVVUklDb21wb25lbnQoaW5wdXQpKTtcbn1cblxuLypcbiogVGFrZSBzdHJpbmcgYXJndW1lbnRzIGFuZCByZXR1cm4gZWl0aGVyIHJhdyBvciBoZXggZW5jb2RlZCBzdHJpbmdzXG4qL1xuZnVuY3Rpb24gcmF3TUQ1KHMpIHtcbiAgcmV0dXJuIHJzdHJNRDUoc3RyMnJzdHJVVEY4KHMpKTtcbn1cbmZ1bmN0aW9uIGhleE1ENShzKSB7XG4gIHJldHVybiByc3RyMmhleChyYXdNRDUocykpO1xufVxuZnVuY3Rpb24gcmF3SE1BQ01ENShrLCBkKSB7XG4gIHJldHVybiByc3RySE1BQ01ENShzdHIycnN0clVURjgoayksIHN0cjJyc3RyVVRGOChkKSk7XG59XG5mdW5jdGlvbiBoZXhITUFDTUQ1KGssIGQpIHtcbiAgcmV0dXJuIHJzdHIyaGV4KHJhd0hNQUNNRDUoaywgZCkpO1xufVxuXG5mdW5jdGlvbiBtZDUoc3RyaW5nLCBrZXksIHJhdykge1xuICBpZiAoIWtleSkge1xuICAgIGlmICghcmF3KSB7XG4gICAgICByZXR1cm4gaGV4TUQ1KHN0cmluZyk7XG4gICAgfVxuICAgIHJldHVybiByYXdNRDUoc3RyaW5nKTtcbiAgfVxuICBpZiAoIXJhdykge1xuICAgIHJldHVybiBoZXhITUFDTUQ1KGtleSwgc3RyaW5nKTtcbiAgfVxuICByZXR1cm4gcmF3SE1BQ01ENShrZXksIHN0cmluZyk7XG59XG5cbm1vZHVsZS5leHBvcnRzID0gbWQ1O1xuIiwiLy8gQ29weXJpZ2h0IEpveWVudCwgSW5jLiBhbmQgb3RoZXIgTm9kZSBjb250cmlidXRvcnMuXG4vL1xuLy8gUGVybWlzc2lvbiBpcyBoZXJlYnkgZ3JhbnRlZCwgZnJlZSBvZiBjaGFyZ2UsIHRvIGFueSBwZXJzb24gb2J0YWluaW5nIGFcbi8vIGNvcHkgb2YgdGhpcyBzb2Z0d2FyZSBhbmQgYXNzb2NpYXRlZCBkb2N1bWVudGF0aW9uIGZpbGVzICh0aGVcbi8vIFwiU29mdHdhcmVcIiksIHRvIGRlYWwgaW4gdGhlIFNvZnR3YXJlIHdpdGhvdXQgcmVzdHJpY3Rpb24sIGluY2x1ZGluZ1xuLy8gd2l0aG91dCBsaW1pdGF0aW9uIHRoZSByaWdodHMgdG8gdXNlLCBjb3B5LCBtb2RpZnksIG1lcmdlLCBwdWJsaXNoLFxuLy8gZGlzdHJpYnV0ZSwgc3VibGljZW5zZSwgYW5kL29yIHNlbGwgY29waWVzIG9mIHRoZSBTb2Z0d2FyZSwgYW5kIHRvIHBlcm1pdFxuLy8gcGVyc29ucyB0byB3aG9tIHRoZSBTb2Z0d2FyZSBpcyBmdXJuaXNoZWQgdG8gZG8gc28sIHN1YmplY3QgdG8gdGhlXG4vLyBmb2xsb3dpbmcgY29uZGl0aW9uczpcbi8vXG4vLyBUaGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwZXJtaXNzaW9uIG5vdGljZSBzaGFsbCBiZSBpbmNsdWRlZFxuLy8gaW4gYWxsIGNvcGllcyBvciBzdWJzdGFudGlhbCBwb3J0aW9ucyBvZiB0aGUgU29mdHdhcmUuXG4vL1xuLy8gVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiwgV0lUSE9VVCBXQVJSQU5UWSBPRiBBTlkgS0lORCwgRVhQUkVTU1xuLy8gT1IgSU1QTElFRCwgSU5DTFVESU5HIEJVVCBOT1QgTElNSVRFRCBUTyBUSEUgV0FSUkFOVElFUyBPRlxuLy8gTUVSQ0hBTlRBQklMSVRZLCBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRSBBTkQgTk9OSU5GUklOR0VNRU5ULiBJTlxuLy8gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUlMgT1IgQ09QWVJJR0hUIEhPTERFUlMgQkUgTElBQkxFIEZPUiBBTlkgQ0xBSU0sXG4vLyBEQU1BR0VTIE9SIE9USEVSIExJQUJJTElUWSwgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIFRPUlQgT1Jcbi8vIE9USEVSV0lTRSwgQVJJU0lORyBGUk9NLCBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBTT0ZUV0FSRSBPUiBUSEVcbi8vIFVTRSBPUiBPVEhFUiBERUFMSU5HUyBJTiBUSEUgU09GVFdBUkUuXG5cbid1c2Ugc3RyaWN0JztcblxudmFyIHB1bnljb2RlID0gcmVxdWlyZSgncHVueWNvZGUnKTtcbnZhciB1dGlsID0gcmVxdWlyZSgnLi91dGlsJyk7XG5cbmV4cG9ydHMucGFyc2UgPSB1cmxQYXJzZTtcbmV4cG9ydHMucmVzb2x2ZSA9IHVybFJlc29sdmU7XG5leHBvcnRzLnJlc29sdmVPYmplY3QgPSB1cmxSZXNvbHZlT2JqZWN0O1xuZXhwb3J0cy5mb3JtYXQgPSB1cmxGb3JtYXQ7XG5cbmV4cG9ydHMuVXJsID0gVXJsO1xuXG5mdW5jdGlvbiBVcmwoKSB7XG4gIHRoaXMucHJvdG9jb2wgPSBudWxsO1xuICB0aGlzLnNsYXNoZXMgPSBudWxsO1xuICB0aGlzLmF1dGggPSBudWxsO1xuICB0aGlzLmhvc3QgPSBudWxsO1xuICB0aGlzLnBvcnQgPSBudWxsO1xuICB0aGlzLmhvc3RuYW1lID0gbnVsbDtcbiAgdGhpcy5oYXNoID0gbnVsbDtcbiAgdGhpcy5zZWFyY2ggPSBudWxsO1xuICB0aGlzLnF1ZXJ5ID0gbnVsbDtcbiAgdGhpcy5wYXRobmFtZSA9IG51bGw7XG4gIHRoaXMucGF0aCA9IG51bGw7XG4gIHRoaXMuaHJlZiA9IG51bGw7XG59XG5cbi8vIFJlZmVyZW5jZTogUkZDIDM5ODYsIFJGQyAxODA4LCBSRkMgMjM5NlxuXG4vLyBkZWZpbmUgdGhlc2UgaGVyZSBzbyBhdCBsZWFzdCB0aGV5IG9ubHkgaGF2ZSB0byBiZVxuLy8gY29tcGlsZWQgb25jZSBvbiB0aGUgZmlyc3QgbW9kdWxlIGxvYWQuXG52YXIgcHJvdG9jb2xQYXR0ZXJuID0gL14oW2EtejAtOS4rLV0rOikvaSxcbiAgICBwb3J0UGF0dGVybiA9IC86WzAtOV0qJC8sXG5cbiAgICAvLyBTcGVjaWFsIGNhc2UgZm9yIGEgc2ltcGxlIHBhdGggVVJMXG4gICAgc2ltcGxlUGF0aFBhdHRlcm4gPSAvXihcXC9cXC8/KD8hXFwvKVteXFw/XFxzXSopKFxcP1teXFxzXSopPyQvLFxuXG4gICAgLy8gUkZDIDIzOTY6IGNoYXJhY3RlcnMgcmVzZXJ2ZWQgZm9yIGRlbGltaXRpbmcgVVJMcy5cbiAgICAvLyBXZSBhY3R1YWxseSBqdXN0IGF1dG8tZXNjYXBlIHRoZXNlLlxuICAgIGRlbGltcyA9IFsnPCcsICc+JywgJ1wiJywgJ2AnLCAnICcsICdcXHInLCAnXFxuJywgJ1xcdCddLFxuXG4gICAgLy8gUkZDIDIzOTY6IGNoYXJhY3RlcnMgbm90IGFsbG93ZWQgZm9yIHZhcmlvdXMgcmVhc29ucy5cbiAgICB1bndpc2UgPSBbJ3snLCAnfScsICd8JywgJ1xcXFwnLCAnXicsICdgJ10uY29uY2F0KGRlbGltcyksXG5cbiAgICAvLyBBbGxvd2VkIGJ5IFJGQ3MsIGJ1dCBjYXVzZSBvZiBYU1MgYXR0YWNrcy4gIEFsd2F5cyBlc2NhcGUgdGhlc2UuXG4gICAgYXV0b0VzY2FwZSA9IFsnXFwnJ10uY29uY2F0KHVud2lzZSksXG4gICAgLy8gQ2hhcmFjdGVycyB0aGF0IGFyZSBuZXZlciBldmVyIGFsbG93ZWQgaW4gYSBob3N0bmFtZS5cbiAgICAvLyBOb3RlIHRoYXQgYW55IGludmFsaWQgY2hhcnMgYXJlIGFsc28gaGFuZGxlZCwgYnV0IHRoZXNlXG4gICAgLy8gYXJlIHRoZSBvbmVzIHRoYXQgYXJlICpleHBlY3RlZCogdG8gYmUgc2Vlbiwgc28gd2UgZmFzdC1wYXRoXG4gICAgLy8gdGhlbS5cbiAgICBub25Ib3N0Q2hhcnMgPSBbJyUnLCAnLycsICc/JywgJzsnLCAnIyddLmNvbmNhdChhdXRvRXNjYXBlKSxcbiAgICBob3N0RW5kaW5nQ2hhcnMgPSBbJy8nLCAnPycsICcjJ10sXG4gICAgaG9zdG5hbWVNYXhMZW4gPSAyNTUsXG4gICAgaG9zdG5hbWVQYXJ0UGF0dGVybiA9IC9eWythLXowLTlBLVpfLV17MCw2M30kLyxcbiAgICBob3N0bmFtZVBhcnRTdGFydCA9IC9eKFsrYS16MC05QS1aXy1dezAsNjN9KSguKikkLyxcbiAgICAvLyBwcm90b2NvbHMgdGhhdCBjYW4gYWxsb3cgXCJ1bnNhZmVcIiBhbmQgXCJ1bndpc2VcIiBjaGFycy5cbiAgICB1bnNhZmVQcm90b2NvbCA9IHtcbiAgICAgICdqYXZhc2NyaXB0JzogdHJ1ZSxcbiAgICAgICdqYXZhc2NyaXB0Oic6IHRydWVcbiAgICB9LFxuICAgIC8vIHByb3RvY29scyB0aGF0IG5ldmVyIGhhdmUgYSBob3N0bmFtZS5cbiAgICBob3N0bGVzc1Byb3RvY29sID0ge1xuICAgICAgJ2phdmFzY3JpcHQnOiB0cnVlLFxuICAgICAgJ2phdmFzY3JpcHQ6JzogdHJ1ZVxuICAgIH0sXG4gICAgLy8gcHJvdG9jb2xzIHRoYXQgYWx3YXlzIGNvbnRhaW4gYSAvLyBiaXQuXG4gICAgc2xhc2hlZFByb3RvY29sID0ge1xuICAgICAgJ2h0dHAnOiB0cnVlLFxuICAgICAgJ2h0dHBzJzogdHJ1ZSxcbiAgICAgICdmdHAnOiB0cnVlLFxuICAgICAgJ2dvcGhlcic6IHRydWUsXG4gICAgICAnZmlsZSc6IHRydWUsXG4gICAgICAnaHR0cDonOiB0cnVlLFxuICAgICAgJ2h0dHBzOic6IHRydWUsXG4gICAgICAnZnRwOic6IHRydWUsXG4gICAgICAnZ29waGVyOic6IHRydWUsXG4gICAgICAnZmlsZTonOiB0cnVlXG4gICAgfSxcbiAgICBxdWVyeXN0cmluZyA9IHJlcXVpcmUoJ3F1ZXJ5c3RyaW5nJyk7XG5cbmZ1bmN0aW9uIHVybFBhcnNlKHVybCwgcGFyc2VRdWVyeVN0cmluZywgc2xhc2hlc0Rlbm90ZUhvc3QpIHtcbiAgaWYgKHVybCAmJiB1dGlsLmlzT2JqZWN0KHVybCkgJiYgdXJsIGluc3RhbmNlb2YgVXJsKSByZXR1cm4gdXJsO1xuXG4gIHZhciB1ID0gbmV3IFVybDtcbiAgdS5wYXJzZSh1cmwsIHBhcnNlUXVlcnlTdHJpbmcsIHNsYXNoZXNEZW5vdGVIb3N0KTtcbiAgcmV0dXJuIHU7XG59XG5cblVybC5wcm90b3R5cGUucGFyc2UgPSBmdW5jdGlvbih1cmwsIHBhcnNlUXVlcnlTdHJpbmcsIHNsYXNoZXNEZW5vdGVIb3N0KSB7XG4gIGlmICghdXRpbC5pc1N0cmluZyh1cmwpKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlBhcmFtZXRlciAndXJsJyBtdXN0IGJlIGEgc3RyaW5nLCBub3QgXCIgKyB0eXBlb2YgdXJsKTtcbiAgfVxuXG4gIC8vIENvcHkgY2hyb21lLCBJRSwgb3BlcmEgYmFja3NsYXNoLWhhbmRsaW5nIGJlaGF2aW9yLlxuICAvLyBCYWNrIHNsYXNoZXMgYmVmb3JlIHRoZSBxdWVyeSBzdHJpbmcgZ2V0IGNvbnZlcnRlZCB0byBmb3J3YXJkIHNsYXNoZXNcbiAgLy8gU2VlOiBodHRwczovL2NvZGUuZ29vZ2xlLmNvbS9wL2Nocm9taXVtL2lzc3Vlcy9kZXRhaWw/aWQ9MjU5MTZcbiAgdmFyIHF1ZXJ5SW5kZXggPSB1cmwuaW5kZXhPZignPycpLFxuICAgICAgc3BsaXR0ZXIgPVxuICAgICAgICAgIChxdWVyeUluZGV4ICE9PSAtMSAmJiBxdWVyeUluZGV4IDwgdXJsLmluZGV4T2YoJyMnKSkgPyAnPycgOiAnIycsXG4gICAgICB1U3BsaXQgPSB1cmwuc3BsaXQoc3BsaXR0ZXIpLFxuICAgICAgc2xhc2hSZWdleCA9IC9cXFxcL2c7XG4gIHVTcGxpdFswXSA9IHVTcGxpdFswXS5yZXBsYWNlKHNsYXNoUmVnZXgsICcvJyk7XG4gIHVybCA9IHVTcGxpdC5qb2luKHNwbGl0dGVyKTtcblxuICB2YXIgcmVzdCA9IHVybDtcblxuICAvLyB0cmltIGJlZm9yZSBwcm9jZWVkaW5nLlxuICAvLyBUaGlzIGlzIHRvIHN1cHBvcnQgcGFyc2Ugc3R1ZmYgbGlrZSBcIiAgaHR0cDovL2Zvby5jb20gIFxcblwiXG4gIHJlc3QgPSByZXN0LnRyaW0oKTtcblxuICBpZiAoIXNsYXNoZXNEZW5vdGVIb3N0ICYmIHVybC5zcGxpdCgnIycpLmxlbmd0aCA9PT0gMSkge1xuICAgIC8vIFRyeSBmYXN0IHBhdGggcmVnZXhwXG4gICAgdmFyIHNpbXBsZVBhdGggPSBzaW1wbGVQYXRoUGF0dGVybi5leGVjKHJlc3QpO1xuICAgIGlmIChzaW1wbGVQYXRoKSB7XG4gICAgICB0aGlzLnBhdGggPSByZXN0O1xuICAgICAgdGhpcy5ocmVmID0gcmVzdDtcbiAgICAgIHRoaXMucGF0aG5hbWUgPSBzaW1wbGVQYXRoWzFdO1xuICAgICAgaWYgKHNpbXBsZVBhdGhbMl0pIHtcbiAgICAgICAgdGhpcy5zZWFyY2ggPSBzaW1wbGVQYXRoWzJdO1xuICAgICAgICBpZiAocGFyc2VRdWVyeVN0cmluZykge1xuICAgICAgICAgIHRoaXMucXVlcnkgPSBxdWVyeXN0cmluZy5wYXJzZSh0aGlzLnNlYXJjaC5zdWJzdHIoMSkpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHRoaXMucXVlcnkgPSB0aGlzLnNlYXJjaC5zdWJzdHIoMSk7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSBpZiAocGFyc2VRdWVyeVN0cmluZykge1xuICAgICAgICB0aGlzLnNlYXJjaCA9ICcnO1xuICAgICAgICB0aGlzLnF1ZXJ5ID0ge307XG4gICAgICB9XG4gICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gIH1cblxuICB2YXIgcHJvdG8gPSBwcm90b2NvbFBhdHRlcm4uZXhlYyhyZXN0KTtcbiAgaWYgKHByb3RvKSB7XG4gICAgcHJvdG8gPSBwcm90b1swXTtcbiAgICB2YXIgbG93ZXJQcm90byA9IHByb3RvLnRvTG93ZXJDYXNlKCk7XG4gICAgdGhpcy5wcm90b2NvbCA9IGxvd2VyUHJvdG87XG4gICAgcmVzdCA9IHJlc3Quc3Vic3RyKHByb3RvLmxlbmd0aCk7XG4gIH1cblxuICAvLyBmaWd1cmUgb3V0IGlmIGl0J3MgZ290IGEgaG9zdFxuICAvLyB1c2VyQHNlcnZlciBpcyAqYWx3YXlzKiBpbnRlcnByZXRlZCBhcyBhIGhvc3RuYW1lLCBhbmQgdXJsXG4gIC8vIHJlc29sdXRpb24gd2lsbCB0cmVhdCAvL2Zvby9iYXIgYXMgaG9zdD1mb28scGF0aD1iYXIgYmVjYXVzZSB0aGF0J3NcbiAgLy8gaG93IHRoZSBicm93c2VyIHJlc29sdmVzIHJlbGF0aXZlIFVSTHMuXG4gIGlmIChzbGFzaGVzRGVub3RlSG9zdCB8fCBwcm90byB8fCByZXN0Lm1hdGNoKC9eXFwvXFwvW15AXFwvXStAW15AXFwvXSsvKSkge1xuICAgIHZhciBzbGFzaGVzID0gcmVzdC5zdWJzdHIoMCwgMikgPT09ICcvLyc7XG4gICAgaWYgKHNsYXNoZXMgJiYgIShwcm90byAmJiBob3N0bGVzc1Byb3RvY29sW3Byb3RvXSkpIHtcbiAgICAgIHJlc3QgPSByZXN0LnN1YnN0cigyKTtcbiAgICAgIHRoaXMuc2xhc2hlcyA9IHRydWU7XG4gICAgfVxuICB9XG5cbiAgaWYgKCFob3N0bGVzc1Byb3RvY29sW3Byb3RvXSAmJlxuICAgICAgKHNsYXNoZXMgfHwgKHByb3RvICYmICFzbGFzaGVkUHJvdG9jb2xbcHJvdG9dKSkpIHtcblxuICAgIC8vIHRoZXJlJ3MgYSBob3N0bmFtZS5cbiAgICAvLyB0aGUgZmlyc3QgaW5zdGFuY2Ugb2YgLywgPywgOywgb3IgIyBlbmRzIHRoZSBob3N0LlxuICAgIC8vXG4gICAgLy8gSWYgdGhlcmUgaXMgYW4gQCBpbiB0aGUgaG9zdG5hbWUsIHRoZW4gbm9uLWhvc3QgY2hhcnMgKmFyZSogYWxsb3dlZFxuICAgIC8vIHRvIHRoZSBsZWZ0IG9mIHRoZSBsYXN0IEAgc2lnbiwgdW5sZXNzIHNvbWUgaG9zdC1lbmRpbmcgY2hhcmFjdGVyXG4gICAgLy8gY29tZXMgKmJlZm9yZSogdGhlIEAtc2lnbi5cbiAgICAvLyBVUkxzIGFyZSBvYm5veGlvdXMuXG4gICAgLy9cbiAgICAvLyBleDpcbiAgICAvLyBodHRwOi8vYUBiQGMvID0+IHVzZXI6YUBiIGhvc3Q6Y1xuICAgIC8vIGh0dHA6Ly9hQGI/QGMgPT4gdXNlcjphIGhvc3Q6YyBwYXRoOi8/QGNcblxuICAgIC8vIHYwLjEyIFRPRE8oaXNhYWNzKTogVGhpcyBpcyBub3QgcXVpdGUgaG93IENocm9tZSBkb2VzIHRoaW5ncy5cbiAgICAvLyBSZXZpZXcgb3VyIHRlc3QgY2FzZSBhZ2FpbnN0IGJyb3dzZXJzIG1vcmUgY29tcHJlaGVuc2l2ZWx5LlxuXG4gICAgLy8gZmluZCB0aGUgZmlyc3QgaW5zdGFuY2Ugb2YgYW55IGhvc3RFbmRpbmdDaGFyc1xuICAgIHZhciBob3N0RW5kID0gLTE7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBob3N0RW5kaW5nQ2hhcnMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHZhciBoZWMgPSByZXN0LmluZGV4T2YoaG9zdEVuZGluZ0NoYXJzW2ldKTtcbiAgICAgIGlmIChoZWMgIT09IC0xICYmIChob3N0RW5kID09PSAtMSB8fCBoZWMgPCBob3N0RW5kKSlcbiAgICAgICAgaG9zdEVuZCA9IGhlYztcbiAgICB9XG5cbiAgICAvLyBhdCB0aGlzIHBvaW50LCBlaXRoZXIgd2UgaGF2ZSBhbiBleHBsaWNpdCBwb2ludCB3aGVyZSB0aGVcbiAgICAvLyBhdXRoIHBvcnRpb24gY2Fubm90IGdvIHBhc3QsIG9yIHRoZSBsYXN0IEAgY2hhciBpcyB0aGUgZGVjaWRlci5cbiAgICB2YXIgYXV0aCwgYXRTaWduO1xuICAgIGlmIChob3N0RW5kID09PSAtMSkge1xuICAgICAgLy8gYXRTaWduIGNhbiBiZSBhbnl3aGVyZS5cbiAgICAgIGF0U2lnbiA9IHJlc3QubGFzdEluZGV4T2YoJ0AnKTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gYXRTaWduIG11c3QgYmUgaW4gYXV0aCBwb3J0aW9uLlxuICAgICAgLy8gaHR0cDovL2FAYi9jQGQgPT4gaG9zdDpiIGF1dGg6YSBwYXRoOi9jQGRcbiAgICAgIGF0U2lnbiA9IHJlc3QubGFzdEluZGV4T2YoJ0AnLCBob3N0RW5kKTtcbiAgICB9XG5cbiAgICAvLyBOb3cgd2UgaGF2ZSBhIHBvcnRpb24gd2hpY2ggaXMgZGVmaW5pdGVseSB0aGUgYXV0aC5cbiAgICAvLyBQdWxsIHRoYXQgb2ZmLlxuICAgIGlmIChhdFNpZ24gIT09IC0xKSB7XG4gICAgICBhdXRoID0gcmVzdC5zbGljZSgwLCBhdFNpZ24pO1xuICAgICAgcmVzdCA9IHJlc3Quc2xpY2UoYXRTaWduICsgMSk7XG4gICAgICB0aGlzLmF1dGggPSBkZWNvZGVVUklDb21wb25lbnQoYXV0aCk7XG4gICAgfVxuXG4gICAgLy8gdGhlIGhvc3QgaXMgdGhlIHJlbWFpbmluZyB0byB0aGUgbGVmdCBvZiB0aGUgZmlyc3Qgbm9uLWhvc3QgY2hhclxuICAgIGhvc3RFbmQgPSAtMTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IG5vbkhvc3RDaGFycy5sZW5ndGg7IGkrKykge1xuICAgICAgdmFyIGhlYyA9IHJlc3QuaW5kZXhPZihub25Ib3N0Q2hhcnNbaV0pO1xuICAgICAgaWYgKGhlYyAhPT0gLTEgJiYgKGhvc3RFbmQgPT09IC0xIHx8IGhlYyA8IGhvc3RFbmQpKVxuICAgICAgICBob3N0RW5kID0gaGVjO1xuICAgIH1cbiAgICAvLyBpZiB3ZSBzdGlsbCBoYXZlIG5vdCBoaXQgaXQsIHRoZW4gdGhlIGVudGlyZSB0aGluZyBpcyBhIGhvc3QuXG4gICAgaWYgKGhvc3RFbmQgPT09IC0xKVxuICAgICAgaG9zdEVuZCA9IHJlc3QubGVuZ3RoO1xuXG4gICAgdGhpcy5ob3N0ID0gcmVzdC5zbGljZSgwLCBob3N0RW5kKTtcbiAgICByZXN0ID0gcmVzdC5zbGljZShob3N0RW5kKTtcblxuICAgIC8vIHB1bGwgb3V0IHBvcnQuXG4gICAgdGhpcy5wYXJzZUhvc3QoKTtcblxuICAgIC8vIHdlJ3ZlIGluZGljYXRlZCB0aGF0IHRoZXJlIGlzIGEgaG9zdG5hbWUsXG4gICAgLy8gc28gZXZlbiBpZiBpdCdzIGVtcHR5LCBpdCBoYXMgdG8gYmUgcHJlc2VudC5cbiAgICB0aGlzLmhvc3RuYW1lID0gdGhpcy5ob3N0bmFtZSB8fCAnJztcblxuICAgIC8vIGlmIGhvc3RuYW1lIGJlZ2lucyB3aXRoIFsgYW5kIGVuZHMgd2l0aCBdXG4gICAgLy8gYXNzdW1lIHRoYXQgaXQncyBhbiBJUHY2IGFkZHJlc3MuXG4gICAgdmFyIGlwdjZIb3N0bmFtZSA9IHRoaXMuaG9zdG5hbWVbMF0gPT09ICdbJyAmJlxuICAgICAgICB0aGlzLmhvc3RuYW1lW3RoaXMuaG9zdG5hbWUubGVuZ3RoIC0gMV0gPT09ICddJztcblxuICAgIC8vIHZhbGlkYXRlIGEgbGl0dGxlLlxuICAgIGlmICghaXB2Nkhvc3RuYW1lKSB7XG4gICAgICB2YXIgaG9zdHBhcnRzID0gdGhpcy5ob3N0bmFtZS5zcGxpdCgvXFwuLyk7XG4gICAgICBmb3IgKHZhciBpID0gMCwgbCA9IGhvc3RwYXJ0cy5sZW5ndGg7IGkgPCBsOyBpKyspIHtcbiAgICAgICAgdmFyIHBhcnQgPSBob3N0cGFydHNbaV07XG4gICAgICAgIGlmICghcGFydCkgY29udGludWU7XG4gICAgICAgIGlmICghcGFydC5tYXRjaChob3N0bmFtZVBhcnRQYXR0ZXJuKSkge1xuICAgICAgICAgIHZhciBuZXdwYXJ0ID0gJyc7XG4gICAgICAgICAgZm9yICh2YXIgaiA9IDAsIGsgPSBwYXJ0Lmxlbmd0aDsgaiA8IGs7IGorKykge1xuICAgICAgICAgICAgaWYgKHBhcnQuY2hhckNvZGVBdChqKSA+IDEyNykge1xuICAgICAgICAgICAgICAvLyB3ZSByZXBsYWNlIG5vbi1BU0NJSSBjaGFyIHdpdGggYSB0ZW1wb3JhcnkgcGxhY2Vob2xkZXJcbiAgICAgICAgICAgICAgLy8gd2UgbmVlZCB0aGlzIHRvIG1ha2Ugc3VyZSBzaXplIG9mIGhvc3RuYW1lIGlzIG5vdFxuICAgICAgICAgICAgICAvLyBicm9rZW4gYnkgcmVwbGFjaW5nIG5vbi1BU0NJSSBieSBub3RoaW5nXG4gICAgICAgICAgICAgIG5ld3BhcnQgKz0gJ3gnO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgbmV3cGFydCArPSBwYXJ0W2pdO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgICAvLyB3ZSB0ZXN0IGFnYWluIHdpdGggQVNDSUkgY2hhciBvbmx5XG4gICAgICAgICAgaWYgKCFuZXdwYXJ0Lm1hdGNoKGhvc3RuYW1lUGFydFBhdHRlcm4pKSB7XG4gICAgICAgICAgICB2YXIgdmFsaWRQYXJ0cyA9IGhvc3RwYXJ0cy5zbGljZSgwLCBpKTtcbiAgICAgICAgICAgIHZhciBub3RIb3N0ID0gaG9zdHBhcnRzLnNsaWNlKGkgKyAxKTtcbiAgICAgICAgICAgIHZhciBiaXQgPSBwYXJ0Lm1hdGNoKGhvc3RuYW1lUGFydFN0YXJ0KTtcbiAgICAgICAgICAgIGlmIChiaXQpIHtcbiAgICAgICAgICAgICAgdmFsaWRQYXJ0cy5wdXNoKGJpdFsxXSk7XG4gICAgICAgICAgICAgIG5vdEhvc3QudW5zaGlmdChiaXRbMl0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKG5vdEhvc3QubGVuZ3RoKSB7XG4gICAgICAgICAgICAgIHJlc3QgPSAnLycgKyBub3RIb3N0LmpvaW4oJy4nKSArIHJlc3Q7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB0aGlzLmhvc3RuYW1lID0gdmFsaWRQYXJ0cy5qb2luKCcuJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAodGhpcy5ob3N0bmFtZS5sZW5ndGggPiBob3N0bmFtZU1heExlbikge1xuICAgICAgdGhpcy5ob3N0bmFtZSA9ICcnO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBob3N0bmFtZXMgYXJlIGFsd2F5cyBsb3dlciBjYXNlLlxuICAgICAgdGhpcy5ob3N0bmFtZSA9IHRoaXMuaG9zdG5hbWUudG9Mb3dlckNhc2UoKTtcbiAgICB9XG5cbiAgICBpZiAoIWlwdjZIb3N0bmFtZSkge1xuICAgICAgLy8gSUROQSBTdXBwb3J0OiBSZXR1cm5zIGEgcHVueWNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIFwiZG9tYWluXCIuXG4gICAgICAvLyBJdCBvbmx5IGNvbnZlcnRzIHBhcnRzIG9mIHRoZSBkb21haW4gbmFtZSB0aGF0XG4gICAgICAvLyBoYXZlIG5vbi1BU0NJSSBjaGFyYWN0ZXJzLCBpLmUuIGl0IGRvZXNuJ3QgbWF0dGVyIGlmXG4gICAgICAvLyB5b3UgY2FsbCBpdCB3aXRoIGEgZG9tYWluIHRoYXQgYWxyZWFkeSBpcyBBU0NJSS1vbmx5LlxuICAgICAgdGhpcy5ob3N0bmFtZSA9IHB1bnljb2RlLnRvQVNDSUkodGhpcy5ob3N0bmFtZSk7XG4gICAgfVxuXG4gICAgdmFyIHAgPSB0aGlzLnBvcnQgPyAnOicgKyB0aGlzLnBvcnQgOiAnJztcbiAgICB2YXIgaCA9IHRoaXMuaG9zdG5hbWUgfHwgJyc7XG4gICAgdGhpcy5ob3N0ID0gaCArIHA7XG4gICAgdGhpcy5ocmVmICs9IHRoaXMuaG9zdDtcblxuICAgIC8vIHN0cmlwIFsgYW5kIF0gZnJvbSB0aGUgaG9zdG5hbWVcbiAgICAvLyB0aGUgaG9zdCBmaWVsZCBzdGlsbCByZXRhaW5zIHRoZW0sIHRob3VnaFxuICAgIGlmIChpcHY2SG9zdG5hbWUpIHtcbiAgICAgIHRoaXMuaG9zdG5hbWUgPSB0aGlzLmhvc3RuYW1lLnN1YnN0cigxLCB0aGlzLmhvc3RuYW1lLmxlbmd0aCAtIDIpO1xuICAgICAgaWYgKHJlc3RbMF0gIT09ICcvJykge1xuICAgICAgICByZXN0ID0gJy8nICsgcmVzdDtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvLyBub3cgcmVzdCBpcyBzZXQgdG8gdGhlIHBvc3QtaG9zdCBzdHVmZi5cbiAgLy8gY2hvcCBvZmYgYW55IGRlbGltIGNoYXJzLlxuICBpZiAoIXVuc2FmZVByb3RvY29sW2xvd2VyUHJvdG9dKSB7XG5cbiAgICAvLyBGaXJzdCwgbWFrZSAxMDAlIHN1cmUgdGhhdCBhbnkgXCJhdXRvRXNjYXBlXCIgY2hhcnMgZ2V0XG4gICAgLy8gZXNjYXBlZCwgZXZlbiBpZiBlbmNvZGVVUklDb21wb25lbnQgZG9lc24ndCB0aGluayB0aGV5XG4gICAgLy8gbmVlZCB0byBiZS5cbiAgICBmb3IgKHZhciBpID0gMCwgbCA9IGF1dG9Fc2NhcGUubGVuZ3RoOyBpIDwgbDsgaSsrKSB7XG4gICAgICB2YXIgYWUgPSBhdXRvRXNjYXBlW2ldO1xuICAgICAgaWYgKHJlc3QuaW5kZXhPZihhZSkgPT09IC0xKVxuICAgICAgICBjb250aW51ZTtcbiAgICAgIHZhciBlc2MgPSBlbmNvZGVVUklDb21wb25lbnQoYWUpO1xuICAgICAgaWYgKGVzYyA9PT0gYWUpIHtcbiAgICAgICAgZXNjID0gZXNjYXBlKGFlKTtcbiAgICAgIH1cbiAgICAgIHJlc3QgPSByZXN0LnNwbGl0KGFlKS5qb2luKGVzYyk7XG4gICAgfVxuICB9XG5cblxuICAvLyBjaG9wIG9mZiBmcm9tIHRoZSB0YWlsIGZpcnN0LlxuICB2YXIgaGFzaCA9IHJlc3QuaW5kZXhPZignIycpO1xuICBpZiAoaGFzaCAhPT0gLTEpIHtcbiAgICAvLyBnb3QgYSBmcmFnbWVudCBzdHJpbmcuXG4gICAgdGhpcy5oYXNoID0gcmVzdC5zdWJzdHIoaGFzaCk7XG4gICAgcmVzdCA9IHJlc3Quc2xpY2UoMCwgaGFzaCk7XG4gIH1cbiAgdmFyIHFtID0gcmVzdC5pbmRleE9mKCc/Jyk7XG4gIGlmIChxbSAhPT0gLTEpIHtcbiAgICB0aGlzLnNlYXJjaCA9IHJlc3Quc3Vic3RyKHFtKTtcbiAgICB0aGlzLnF1ZXJ5ID0gcmVzdC5zdWJzdHIocW0gKyAxKTtcbiAgICBpZiAocGFyc2VRdWVyeVN0cmluZykge1xuICAgICAgdGhpcy5xdWVyeSA9IHF1ZXJ5c3RyaW5nLnBhcnNlKHRoaXMucXVlcnkpO1xuICAgIH1cbiAgICByZXN0ID0gcmVzdC5zbGljZSgwLCBxbSk7XG4gIH0gZWxzZSBpZiAocGFyc2VRdWVyeVN0cmluZykge1xuICAgIC8vIG5vIHF1ZXJ5IHN0cmluZywgYnV0IHBhcnNlUXVlcnlTdHJpbmcgc3RpbGwgcmVxdWVzdGVkXG4gICAgdGhpcy5zZWFyY2ggPSAnJztcbiAgICB0aGlzLnF1ZXJ5ID0ge307XG4gIH1cbiAgaWYgKHJlc3QpIHRoaXMucGF0aG5hbWUgPSByZXN0O1xuICBpZiAoc2xhc2hlZFByb3RvY29sW2xvd2VyUHJvdG9dICYmXG4gICAgICB0aGlzLmhvc3RuYW1lICYmICF0aGlzLnBhdGhuYW1lKSB7XG4gICAgdGhpcy5wYXRobmFtZSA9ICcvJztcbiAgfVxuXG4gIC8vdG8gc3VwcG9ydCBodHRwLnJlcXVlc3RcbiAgaWYgKHRoaXMucGF0aG5hbWUgfHwgdGhpcy5zZWFyY2gpIHtcbiAgICB2YXIgcCA9IHRoaXMucGF0aG5hbWUgfHwgJyc7XG4gICAgdmFyIHMgPSB0aGlzLnNlYXJjaCB8fCAnJztcbiAgICB0aGlzLnBhdGggPSBwICsgcztcbiAgfVxuXG4gIC8vIGZpbmFsbHksIHJlY29uc3RydWN0IHRoZSBocmVmIGJhc2VkIG9uIHdoYXQgaGFzIGJlZW4gdmFsaWRhdGVkLlxuICB0aGlzLmhyZWYgPSB0aGlzLmZvcm1hdCgpO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8vIGZvcm1hdCBhIHBhcnNlZCBvYmplY3QgaW50byBhIHVybCBzdHJpbmdcbmZ1bmN0aW9uIHVybEZvcm1hdChvYmopIHtcbiAgLy8gZW5zdXJlIGl0J3MgYW4gb2JqZWN0LCBhbmQgbm90IGEgc3RyaW5nIHVybC5cbiAgLy8gSWYgaXQncyBhbiBvYmosIHRoaXMgaXMgYSBuby1vcC5cbiAgLy8gdGhpcyB3YXksIHlvdSBjYW4gY2FsbCB1cmxfZm9ybWF0KCkgb24gc3RyaW5nc1xuICAvLyB0byBjbGVhbiB1cCBwb3RlbnRpYWxseSB3b25reSB1cmxzLlxuICBpZiAodXRpbC5pc1N0cmluZyhvYmopKSBvYmogPSB1cmxQYXJzZShvYmopO1xuICBpZiAoIShvYmogaW5zdGFuY2VvZiBVcmwpKSByZXR1cm4gVXJsLnByb3RvdHlwZS5mb3JtYXQuY2FsbChvYmopO1xuICByZXR1cm4gb2JqLmZvcm1hdCgpO1xufVxuXG5VcmwucHJvdG90eXBlLmZvcm1hdCA9IGZ1bmN0aW9uKCkge1xuICB2YXIgYXV0aCA9IHRoaXMuYXV0aCB8fCAnJztcbiAgaWYgKGF1dGgpIHtcbiAgICBhdXRoID0gZW5jb2RlVVJJQ29tcG9uZW50KGF1dGgpO1xuICAgIGF1dGggPSBhdXRoLnJlcGxhY2UoLyUzQS9pLCAnOicpO1xuICAgIGF1dGggKz0gJ0AnO1xuICB9XG5cbiAgdmFyIHByb3RvY29sID0gdGhpcy5wcm90b2NvbCB8fCAnJyxcbiAgICAgIHBhdGhuYW1lID0gdGhpcy5wYXRobmFtZSB8fCAnJyxcbiAgICAgIGhhc2ggPSB0aGlzLmhhc2ggfHwgJycsXG4gICAgICBob3N0ID0gZmFsc2UsXG4gICAgICBxdWVyeSA9ICcnO1xuXG4gIGlmICh0aGlzLmhvc3QpIHtcbiAgICBob3N0ID0gYXV0aCArIHRoaXMuaG9zdDtcbiAgfSBlbHNlIGlmICh0aGlzLmhvc3RuYW1lKSB7XG4gICAgaG9zdCA9IGF1dGggKyAodGhpcy5ob3N0bmFtZS5pbmRleE9mKCc6JykgPT09IC0xID9cbiAgICAgICAgdGhpcy5ob3N0bmFtZSA6XG4gICAgICAgICdbJyArIHRoaXMuaG9zdG5hbWUgKyAnXScpO1xuICAgIGlmICh0aGlzLnBvcnQpIHtcbiAgICAgIGhvc3QgKz0gJzonICsgdGhpcy5wb3J0O1xuICAgIH1cbiAgfVxuXG4gIGlmICh0aGlzLnF1ZXJ5ICYmXG4gICAgICB1dGlsLmlzT2JqZWN0KHRoaXMucXVlcnkpICYmXG4gICAgICBPYmplY3Qua2V5cyh0aGlzLnF1ZXJ5KS5sZW5ndGgpIHtcbiAgICBxdWVyeSA9IHF1ZXJ5c3RyaW5nLnN0cmluZ2lmeSh0aGlzLnF1ZXJ5KTtcbiAgfVxuXG4gIHZhciBzZWFyY2ggPSB0aGlzLnNlYXJjaCB8fCAocXVlcnkgJiYgKCc/JyArIHF1ZXJ5KSkgfHwgJyc7XG5cbiAgaWYgKHByb3RvY29sICYmIHByb3RvY29sLnN1YnN0cigtMSkgIT09ICc6JykgcHJvdG9jb2wgKz0gJzonO1xuXG4gIC8vIG9ubHkgdGhlIHNsYXNoZWRQcm90b2NvbHMgZ2V0IHRoZSAvLy4gIE5vdCBtYWlsdG86LCB4bXBwOiwgZXRjLlxuICAvLyB1bmxlc3MgdGhleSBoYWQgdGhlbSB0byBiZWdpbiB3aXRoLlxuICBpZiAodGhpcy5zbGFzaGVzIHx8XG4gICAgICAoIXByb3RvY29sIHx8IHNsYXNoZWRQcm90b2NvbFtwcm90b2NvbF0pICYmIGhvc3QgIT09IGZhbHNlKSB7XG4gICAgaG9zdCA9ICcvLycgKyAoaG9zdCB8fCAnJyk7XG4gICAgaWYgKHBhdGhuYW1lICYmIHBhdGhuYW1lLmNoYXJBdCgwKSAhPT0gJy8nKSBwYXRobmFtZSA9ICcvJyArIHBhdGhuYW1lO1xuICB9IGVsc2UgaWYgKCFob3N0KSB7XG4gICAgaG9zdCA9ICcnO1xuICB9XG5cbiAgaWYgKGhhc2ggJiYgaGFzaC5jaGFyQXQoMCkgIT09ICcjJykgaGFzaCA9ICcjJyArIGhhc2g7XG4gIGlmIChzZWFyY2ggJiYgc2VhcmNoLmNoYXJBdCgwKSAhPT0gJz8nKSBzZWFyY2ggPSAnPycgKyBzZWFyY2g7XG5cbiAgcGF0aG5hbWUgPSBwYXRobmFtZS5yZXBsYWNlKC9bPyNdL2csIGZ1bmN0aW9uKG1hdGNoKSB7XG4gICAgcmV0dXJuIGVuY29kZVVSSUNvbXBvbmVudChtYXRjaCk7XG4gIH0pO1xuICBzZWFyY2ggPSBzZWFyY2gucmVwbGFjZSgnIycsICclMjMnKTtcblxuICByZXR1cm4gcHJvdG9jb2wgKyBob3N0ICsgcGF0aG5hbWUgKyBzZWFyY2ggKyBoYXNoO1xufTtcblxuZnVuY3Rpb24gdXJsUmVzb2x2ZShzb3VyY2UsIHJlbGF0aXZlKSB7XG4gIHJldHVybiB1cmxQYXJzZShzb3VyY2UsIGZhbHNlLCB0cnVlKS5yZXNvbHZlKHJlbGF0aXZlKTtcbn1cblxuVXJsLnByb3RvdHlwZS5yZXNvbHZlID0gZnVuY3Rpb24ocmVsYXRpdmUpIHtcbiAgcmV0dXJuIHRoaXMucmVzb2x2ZU9iamVjdCh1cmxQYXJzZShyZWxhdGl2ZSwgZmFsc2UsIHRydWUpKS5mb3JtYXQoKTtcbn07XG5cbmZ1bmN0aW9uIHVybFJlc29sdmVPYmplY3Qoc291cmNlLCByZWxhdGl2ZSkge1xuICBpZiAoIXNvdXJjZSkgcmV0dXJuIHJlbGF0aXZlO1xuICByZXR1cm4gdXJsUGFyc2Uoc291cmNlLCBmYWxzZSwgdHJ1ZSkucmVzb2x2ZU9iamVjdChyZWxhdGl2ZSk7XG59XG5cblVybC5wcm90b3R5cGUucmVzb2x2ZU9iamVjdCA9IGZ1bmN0aW9uKHJlbGF0aXZlKSB7XG4gIGlmICh1dGlsLmlzU3RyaW5nKHJlbGF0aXZlKSkge1xuICAgIHZhciByZWwgPSBuZXcgVXJsKCk7XG4gICAgcmVsLnBhcnNlKHJlbGF0aXZlLCBmYWxzZSwgdHJ1ZSk7XG4gICAgcmVsYXRpdmUgPSByZWw7XG4gIH1cblxuICB2YXIgcmVzdWx0ID0gbmV3IFVybCgpO1xuICB2YXIgdGtleXMgPSBPYmplY3Qua2V5cyh0aGlzKTtcbiAgZm9yICh2YXIgdGsgPSAwOyB0ayA8IHRrZXlzLmxlbmd0aDsgdGsrKykge1xuICAgIHZhciB0a2V5ID0gdGtleXNbdGtdO1xuICAgIHJlc3VsdFt0a2V5XSA9IHRoaXNbdGtleV07XG4gIH1cblxuICAvLyBoYXNoIGlzIGFsd2F5cyBvdmVycmlkZGVuLCBubyBtYXR0ZXIgd2hhdC5cbiAgLy8gZXZlbiBocmVmPVwiXCIgd2lsbCByZW1vdmUgaXQuXG4gIHJlc3VsdC5oYXNoID0gcmVsYXRpdmUuaGFzaDtcblxuICAvLyBpZiB0aGUgcmVsYXRpdmUgdXJsIGlzIGVtcHR5LCB0aGVuIHRoZXJlJ3Mgbm90aGluZyBsZWZ0IHRvIGRvIGhlcmUuXG4gIGlmIChyZWxhdGl2ZS5ocmVmID09PSAnJykge1xuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICAvLyBocmVmcyBsaWtlIC8vZm9vL2JhciBhbHdheXMgY3V0IHRvIHRoZSBwcm90b2NvbC5cbiAgaWYgKHJlbGF0aXZlLnNsYXNoZXMgJiYgIXJlbGF0aXZlLnByb3RvY29sKSB7XG4gICAgLy8gdGFrZSBldmVyeXRoaW5nIGV4Y2VwdCB0aGUgcHJvdG9jb2wgZnJvbSByZWxhdGl2ZVxuICAgIHZhciBya2V5cyA9IE9iamVjdC5rZXlzKHJlbGF0aXZlKTtcbiAgICBmb3IgKHZhciByayA9IDA7IHJrIDwgcmtleXMubGVuZ3RoOyByaysrKSB7XG4gICAgICB2YXIgcmtleSA9IHJrZXlzW3JrXTtcbiAgICAgIGlmIChya2V5ICE9PSAncHJvdG9jb2wnKVxuICAgICAgICByZXN1bHRbcmtleV0gPSByZWxhdGl2ZVtya2V5XTtcbiAgICB9XG5cbiAgICAvL3VybFBhcnNlIGFwcGVuZHMgdHJhaWxpbmcgLyB0byB1cmxzIGxpa2UgaHR0cDovL3d3dy5leGFtcGxlLmNvbVxuICAgIGlmIChzbGFzaGVkUHJvdG9jb2xbcmVzdWx0LnByb3RvY29sXSAmJlxuICAgICAgICByZXN1bHQuaG9zdG5hbWUgJiYgIXJlc3VsdC5wYXRobmFtZSkge1xuICAgICAgcmVzdWx0LnBhdGggPSByZXN1bHQucGF0aG5hbWUgPSAnLyc7XG4gICAgfVxuXG4gICAgcmVzdWx0LmhyZWYgPSByZXN1bHQuZm9ybWF0KCk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIGlmIChyZWxhdGl2ZS5wcm90b2NvbCAmJiByZWxhdGl2ZS5wcm90b2NvbCAhPT0gcmVzdWx0LnByb3RvY29sKSB7XG4gICAgLy8gaWYgaXQncyBhIGtub3duIHVybCBwcm90b2NvbCwgdGhlbiBjaGFuZ2luZ1xuICAgIC8vIHRoZSBwcm90b2NvbCBkb2VzIHdlaXJkIHRoaW5nc1xuICAgIC8vIGZpcnN0LCBpZiBpdCdzIG5vdCBmaWxlOiwgdGhlbiB3ZSBNVVNUIGhhdmUgYSBob3N0LFxuICAgIC8vIGFuZCBpZiB0aGVyZSB3YXMgYSBwYXRoXG4gICAgLy8gdG8gYmVnaW4gd2l0aCwgdGhlbiB3ZSBNVVNUIGhhdmUgYSBwYXRoLlxuICAgIC8vIGlmIGl0IGlzIGZpbGU6LCB0aGVuIHRoZSBob3N0IGlzIGRyb3BwZWQsXG4gICAgLy8gYmVjYXVzZSB0aGF0J3Mga25vd24gdG8gYmUgaG9zdGxlc3MuXG4gICAgLy8gYW55dGhpbmcgZWxzZSBpcyBhc3N1bWVkIHRvIGJlIGFic29sdXRlLlxuICAgIGlmICghc2xhc2hlZFByb3RvY29sW3JlbGF0aXZlLnByb3RvY29sXSkge1xuICAgICAgdmFyIGtleXMgPSBPYmplY3Qua2V5cyhyZWxhdGl2ZSk7XG4gICAgICBmb3IgKHZhciB2ID0gMDsgdiA8IGtleXMubGVuZ3RoOyB2KyspIHtcbiAgICAgICAgdmFyIGsgPSBrZXlzW3ZdO1xuICAgICAgICByZXN1bHRba10gPSByZWxhdGl2ZVtrXTtcbiAgICAgIH1cbiAgICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICB9XG5cbiAgICByZXN1bHQucHJvdG9jb2wgPSByZWxhdGl2ZS5wcm90b2NvbDtcbiAgICBpZiAoIXJlbGF0aXZlLmhvc3QgJiYgIWhvc3RsZXNzUHJvdG9jb2xbcmVsYXRpdmUucHJvdG9jb2xdKSB7XG4gICAgICB2YXIgcmVsUGF0aCA9IChyZWxhdGl2ZS5wYXRobmFtZSB8fCAnJykuc3BsaXQoJy8nKTtcbiAgICAgIHdoaWxlIChyZWxQYXRoLmxlbmd0aCAmJiAhKHJlbGF0aXZlLmhvc3QgPSByZWxQYXRoLnNoaWZ0KCkpKTtcbiAgICAgIGlmICghcmVsYXRpdmUuaG9zdCkgcmVsYXRpdmUuaG9zdCA9ICcnO1xuICAgICAgaWYgKCFyZWxhdGl2ZS5ob3N0bmFtZSkgcmVsYXRpdmUuaG9zdG5hbWUgPSAnJztcbiAgICAgIGlmIChyZWxQYXRoWzBdICE9PSAnJykgcmVsUGF0aC51bnNoaWZ0KCcnKTtcbiAgICAgIGlmIChyZWxQYXRoLmxlbmd0aCA8IDIpIHJlbFBhdGgudW5zaGlmdCgnJyk7XG4gICAgICByZXN1bHQucGF0aG5hbWUgPSByZWxQYXRoLmpvaW4oJy8nKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzdWx0LnBhdGhuYW1lID0gcmVsYXRpdmUucGF0aG5hbWU7XG4gICAgfVxuICAgIHJlc3VsdC5zZWFyY2ggPSByZWxhdGl2ZS5zZWFyY2g7XG4gICAgcmVzdWx0LnF1ZXJ5ID0gcmVsYXRpdmUucXVlcnk7XG4gICAgcmVzdWx0Lmhvc3QgPSByZWxhdGl2ZS5ob3N0IHx8ICcnO1xuICAgIHJlc3VsdC5hdXRoID0gcmVsYXRpdmUuYXV0aDtcbiAgICByZXN1bHQuaG9zdG5hbWUgPSByZWxhdGl2ZS5ob3N0bmFtZSB8fCByZWxhdGl2ZS5ob3N0O1xuICAgIHJlc3VsdC5wb3J0ID0gcmVsYXRpdmUucG9ydDtcbiAgICAvLyB0byBzdXBwb3J0IGh0dHAucmVxdWVzdFxuICAgIGlmIChyZXN1bHQucGF0aG5hbWUgfHwgcmVzdWx0LnNlYXJjaCkge1xuICAgICAgdmFyIHAgPSByZXN1bHQucGF0aG5hbWUgfHwgJyc7XG4gICAgICB2YXIgcyA9IHJlc3VsdC5zZWFyY2ggfHwgJyc7XG4gICAgICByZXN1bHQucGF0aCA9IHAgKyBzO1xuICAgIH1cbiAgICByZXN1bHQuc2xhc2hlcyA9IHJlc3VsdC5zbGFzaGVzIHx8IHJlbGF0aXZlLnNsYXNoZXM7XG4gICAgcmVzdWx0LmhyZWYgPSByZXN1bHQuZm9ybWF0KCk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIHZhciBpc1NvdXJjZUFicyA9IChyZXN1bHQucGF0aG5hbWUgJiYgcmVzdWx0LnBhdGhuYW1lLmNoYXJBdCgwKSA9PT0gJy8nKSxcbiAgICAgIGlzUmVsQWJzID0gKFxuICAgICAgICAgIHJlbGF0aXZlLmhvc3QgfHxcbiAgICAgICAgICByZWxhdGl2ZS5wYXRobmFtZSAmJiByZWxhdGl2ZS5wYXRobmFtZS5jaGFyQXQoMCkgPT09ICcvJ1xuICAgICAgKSxcbiAgICAgIG11c3RFbmRBYnMgPSAoaXNSZWxBYnMgfHwgaXNTb3VyY2VBYnMgfHxcbiAgICAgICAgICAgICAgICAgICAgKHJlc3VsdC5ob3N0ICYmIHJlbGF0aXZlLnBhdGhuYW1lKSksXG4gICAgICByZW1vdmVBbGxEb3RzID0gbXVzdEVuZEFicyxcbiAgICAgIHNyY1BhdGggPSByZXN1bHQucGF0aG5hbWUgJiYgcmVzdWx0LnBhdGhuYW1lLnNwbGl0KCcvJykgfHwgW10sXG4gICAgICByZWxQYXRoID0gcmVsYXRpdmUucGF0aG5hbWUgJiYgcmVsYXRpdmUucGF0aG5hbWUuc3BsaXQoJy8nKSB8fCBbXSxcbiAgICAgIHBzeWNob3RpYyA9IHJlc3VsdC5wcm90b2NvbCAmJiAhc2xhc2hlZFByb3RvY29sW3Jlc3VsdC5wcm90b2NvbF07XG5cbiAgLy8gaWYgdGhlIHVybCBpcyBhIG5vbi1zbGFzaGVkIHVybCwgdGhlbiByZWxhdGl2ZVxuICAvLyBsaW5rcyBsaWtlIC4uLy4uIHNob3VsZCBiZSBhYmxlXG4gIC8vIHRvIGNyYXdsIHVwIHRvIHRoZSBob3N0bmFtZSwgYXMgd2VsbC4gIFRoaXMgaXMgc3RyYW5nZS5cbiAgLy8gcmVzdWx0LnByb3RvY29sIGhhcyBhbHJlYWR5IGJlZW4gc2V0IGJ5IG5vdy5cbiAgLy8gTGF0ZXIgb24sIHB1dCB0aGUgZmlyc3QgcGF0aCBwYXJ0IGludG8gdGhlIGhvc3QgZmllbGQuXG4gIGlmIChwc3ljaG90aWMpIHtcbiAgICByZXN1bHQuaG9zdG5hbWUgPSAnJztcbiAgICByZXN1bHQucG9ydCA9IG51bGw7XG4gICAgaWYgKHJlc3VsdC5ob3N0KSB7XG4gICAgICBpZiAoc3JjUGF0aFswXSA9PT0gJycpIHNyY1BhdGhbMF0gPSByZXN1bHQuaG9zdDtcbiAgICAgIGVsc2Ugc3JjUGF0aC51bnNoaWZ0KHJlc3VsdC5ob3N0KTtcbiAgICB9XG4gICAgcmVzdWx0Lmhvc3QgPSAnJztcbiAgICBpZiAocmVsYXRpdmUucHJvdG9jb2wpIHtcbiAgICAgIHJlbGF0aXZlLmhvc3RuYW1lID0gbnVsbDtcbiAgICAgIHJlbGF0aXZlLnBvcnQgPSBudWxsO1xuICAgICAgaWYgKHJlbGF0aXZlLmhvc3QpIHtcbiAgICAgICAgaWYgKHJlbFBhdGhbMF0gPT09ICcnKSByZWxQYXRoWzBdID0gcmVsYXRpdmUuaG9zdDtcbiAgICAgICAgZWxzZSByZWxQYXRoLnVuc2hpZnQocmVsYXRpdmUuaG9zdCk7XG4gICAgICB9XG4gICAgICByZWxhdGl2ZS5ob3N0ID0gbnVsbDtcbiAgICB9XG4gICAgbXVzdEVuZEFicyA9IG11c3RFbmRBYnMgJiYgKHJlbFBhdGhbMF0gPT09ICcnIHx8IHNyY1BhdGhbMF0gPT09ICcnKTtcbiAgfVxuXG4gIGlmIChpc1JlbEFicykge1xuICAgIC8vIGl0J3MgYWJzb2x1dGUuXG4gICAgcmVzdWx0Lmhvc3QgPSAocmVsYXRpdmUuaG9zdCB8fCByZWxhdGl2ZS5ob3N0ID09PSAnJykgP1xuICAgICAgICAgICAgICAgICAgcmVsYXRpdmUuaG9zdCA6IHJlc3VsdC5ob3N0O1xuICAgIHJlc3VsdC5ob3N0bmFtZSA9IChyZWxhdGl2ZS5ob3N0bmFtZSB8fCByZWxhdGl2ZS5ob3N0bmFtZSA9PT0gJycpID9cbiAgICAgICAgICAgICAgICAgICAgICByZWxhdGl2ZS5ob3N0bmFtZSA6IHJlc3VsdC5ob3N0bmFtZTtcbiAgICByZXN1bHQuc2VhcmNoID0gcmVsYXRpdmUuc2VhcmNoO1xuICAgIHJlc3VsdC5xdWVyeSA9IHJlbGF0aXZlLnF1ZXJ5O1xuICAgIHNyY1BhdGggPSByZWxQYXRoO1xuICAgIC8vIGZhbGwgdGhyb3VnaCB0byB0aGUgZG90LWhhbmRsaW5nIGJlbG93LlxuICB9IGVsc2UgaWYgKHJlbFBhdGgubGVuZ3RoKSB7XG4gICAgLy8gaXQncyByZWxhdGl2ZVxuICAgIC8vIHRocm93IGF3YXkgdGhlIGV4aXN0aW5nIGZpbGUsIGFuZCB0YWtlIHRoZSBuZXcgcGF0aCBpbnN0ZWFkLlxuICAgIGlmICghc3JjUGF0aCkgc3JjUGF0aCA9IFtdO1xuICAgIHNyY1BhdGgucG9wKCk7XG4gICAgc3JjUGF0aCA9IHNyY1BhdGguY29uY2F0KHJlbFBhdGgpO1xuICAgIHJlc3VsdC5zZWFyY2ggPSByZWxhdGl2ZS5zZWFyY2g7XG4gICAgcmVzdWx0LnF1ZXJ5ID0gcmVsYXRpdmUucXVlcnk7XG4gIH0gZWxzZSBpZiAoIXV0aWwuaXNOdWxsT3JVbmRlZmluZWQocmVsYXRpdmUuc2VhcmNoKSkge1xuICAgIC8vIGp1c3QgcHVsbCBvdXQgdGhlIHNlYXJjaC5cbiAgICAvLyBsaWtlIGhyZWY9Jz9mb28nLlxuICAgIC8vIFB1dCB0aGlzIGFmdGVyIHRoZSBvdGhlciB0d28gY2FzZXMgYmVjYXVzZSBpdCBzaW1wbGlmaWVzIHRoZSBib29sZWFuc1xuICAgIGlmIChwc3ljaG90aWMpIHtcbiAgICAgIHJlc3VsdC5ob3N0bmFtZSA9IHJlc3VsdC5ob3N0ID0gc3JjUGF0aC5zaGlmdCgpO1xuICAgICAgLy9vY2NhdGlvbmFseSB0aGUgYXV0aCBjYW4gZ2V0IHN0dWNrIG9ubHkgaW4gaG9zdFxuICAgICAgLy90aGlzIGVzcGVjaWFsbHkgaGFwcGVucyBpbiBjYXNlcyBsaWtlXG4gICAgICAvL3VybC5yZXNvbHZlT2JqZWN0KCdtYWlsdG86bG9jYWwxQGRvbWFpbjEnLCAnbG9jYWwyQGRvbWFpbjInKVxuICAgICAgdmFyIGF1dGhJbkhvc3QgPSByZXN1bHQuaG9zdCAmJiByZXN1bHQuaG9zdC5pbmRleE9mKCdAJykgPiAwID9cbiAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0Lmhvc3Quc3BsaXQoJ0AnKSA6IGZhbHNlO1xuICAgICAgaWYgKGF1dGhJbkhvc3QpIHtcbiAgICAgICAgcmVzdWx0LmF1dGggPSBhdXRoSW5Ib3N0LnNoaWZ0KCk7XG4gICAgICAgIHJlc3VsdC5ob3N0ID0gcmVzdWx0Lmhvc3RuYW1lID0gYXV0aEluSG9zdC5zaGlmdCgpO1xuICAgICAgfVxuICAgIH1cbiAgICByZXN1bHQuc2VhcmNoID0gcmVsYXRpdmUuc2VhcmNoO1xuICAgIHJlc3VsdC5xdWVyeSA9IHJlbGF0aXZlLnF1ZXJ5O1xuICAgIC8vdG8gc3VwcG9ydCBodHRwLnJlcXVlc3RcbiAgICBpZiAoIXV0aWwuaXNOdWxsKHJlc3VsdC5wYXRobmFtZSkgfHwgIXV0aWwuaXNOdWxsKHJlc3VsdC5zZWFyY2gpKSB7XG4gICAgICByZXN1bHQucGF0aCA9IChyZXN1bHQucGF0aG5hbWUgPyByZXN1bHQucGF0aG5hbWUgOiAnJykgK1xuICAgICAgICAgICAgICAgICAgICAocmVzdWx0LnNlYXJjaCA/IHJlc3VsdC5zZWFyY2ggOiAnJyk7XG4gICAgfVxuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICBpZiAoIXNyY1BhdGgubGVuZ3RoKSB7XG4gICAgLy8gbm8gcGF0aCBhdCBhbGwuICBlYXN5LlxuICAgIC8vIHdlJ3ZlIGFscmVhZHkgaGFuZGxlZCB0aGUgb3RoZXIgc3R1ZmYgYWJvdmUuXG4gICAgcmVzdWx0LnBhdGhuYW1lID0gbnVsbDtcbiAgICAvL3RvIHN1cHBvcnQgaHR0cC5yZXF1ZXN0XG4gICAgaWYgKHJlc3VsdC5zZWFyY2gpIHtcbiAgICAgIHJlc3VsdC5wYXRoID0gJy8nICsgcmVzdWx0LnNlYXJjaDtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzdWx0LnBhdGggPSBudWxsO1xuICAgIH1cbiAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgLy8gaWYgYSB1cmwgRU5EcyBpbiAuIG9yIC4uLCB0aGVuIGl0IG11c3QgZ2V0IGEgdHJhaWxpbmcgc2xhc2guXG4gIC8vIGhvd2V2ZXIsIGlmIGl0IGVuZHMgaW4gYW55dGhpbmcgZWxzZSBub24tc2xhc2h5LFxuICAvLyB0aGVuIGl0IG11c3QgTk9UIGdldCBhIHRyYWlsaW5nIHNsYXNoLlxuICB2YXIgbGFzdCA9IHNyY1BhdGguc2xpY2UoLTEpWzBdO1xuICB2YXIgaGFzVHJhaWxpbmdTbGFzaCA9IChcbiAgICAgIChyZXN1bHQuaG9zdCB8fCByZWxhdGl2ZS5ob3N0IHx8IHNyY1BhdGgubGVuZ3RoID4gMSkgJiZcbiAgICAgIChsYXN0ID09PSAnLicgfHwgbGFzdCA9PT0gJy4uJykgfHwgbGFzdCA9PT0gJycpO1xuXG4gIC8vIHN0cmlwIHNpbmdsZSBkb3RzLCByZXNvbHZlIGRvdWJsZSBkb3RzIHRvIHBhcmVudCBkaXJcbiAgLy8gaWYgdGhlIHBhdGggdHJpZXMgdG8gZ28gYWJvdmUgdGhlIHJvb3QsIGB1cGAgZW5kcyB1cCA+IDBcbiAgdmFyIHVwID0gMDtcbiAgZm9yICh2YXIgaSA9IHNyY1BhdGgubGVuZ3RoOyBpID49IDA7IGktLSkge1xuICAgIGxhc3QgPSBzcmNQYXRoW2ldO1xuICAgIGlmIChsYXN0ID09PSAnLicpIHtcbiAgICAgIHNyY1BhdGguc3BsaWNlKGksIDEpO1xuICAgIH0gZWxzZSBpZiAobGFzdCA9PT0gJy4uJykge1xuICAgICAgc3JjUGF0aC5zcGxpY2UoaSwgMSk7XG4gICAgICB1cCsrO1xuICAgIH0gZWxzZSBpZiAodXApIHtcbiAgICAgIHNyY1BhdGguc3BsaWNlKGksIDEpO1xuICAgICAgdXAtLTtcbiAgICB9XG4gIH1cblxuICAvLyBpZiB0aGUgcGF0aCBpcyBhbGxvd2VkIHRvIGdvIGFib3ZlIHRoZSByb290LCByZXN0b3JlIGxlYWRpbmcgLi5zXG4gIGlmICghbXVzdEVuZEFicyAmJiAhcmVtb3ZlQWxsRG90cykge1xuICAgIGZvciAoOyB1cC0tOyB1cCkge1xuICAgICAgc3JjUGF0aC51bnNoaWZ0KCcuLicpO1xuICAgIH1cbiAgfVxuXG4gIGlmIChtdXN0RW5kQWJzICYmIHNyY1BhdGhbMF0gIT09ICcnICYmXG4gICAgICAoIXNyY1BhdGhbMF0gfHwgc3JjUGF0aFswXS5jaGFyQXQoMCkgIT09ICcvJykpIHtcbiAgICBzcmNQYXRoLnVuc2hpZnQoJycpO1xuICB9XG5cbiAgaWYgKGhhc1RyYWlsaW5nU2xhc2ggJiYgKHNyY1BhdGguam9pbignLycpLnN1YnN0cigtMSkgIT09ICcvJykpIHtcbiAgICBzcmNQYXRoLnB1c2goJycpO1xuICB9XG5cbiAgdmFyIGlzQWJzb2x1dGUgPSBzcmNQYXRoWzBdID09PSAnJyB8fFxuICAgICAgKHNyY1BhdGhbMF0gJiYgc3JjUGF0aFswXS5jaGFyQXQoMCkgPT09ICcvJyk7XG5cbiAgLy8gcHV0IHRoZSBob3N0IGJhY2tcbiAgaWYgKHBzeWNob3RpYykge1xuICAgIHJlc3VsdC5ob3N0bmFtZSA9IHJlc3VsdC5ob3N0ID0gaXNBYnNvbHV0ZSA/ICcnIDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNyY1BhdGgubGVuZ3RoID8gc3JjUGF0aC5zaGlmdCgpIDogJyc7XG4gICAgLy9vY2NhdGlvbmFseSB0aGUgYXV0aCBjYW4gZ2V0IHN0dWNrIG9ubHkgaW4gaG9zdFxuICAgIC8vdGhpcyBlc3BlY2lhbGx5IGhhcHBlbnMgaW4gY2FzZXMgbGlrZVxuICAgIC8vdXJsLnJlc29sdmVPYmplY3QoJ21haWx0bzpsb2NhbDFAZG9tYWluMScsICdsb2NhbDJAZG9tYWluMicpXG4gICAgdmFyIGF1dGhJbkhvc3QgPSByZXN1bHQuaG9zdCAmJiByZXN1bHQuaG9zdC5pbmRleE9mKCdAJykgPiAwID9cbiAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5ob3N0LnNwbGl0KCdAJykgOiBmYWxzZTtcbiAgICBpZiAoYXV0aEluSG9zdCkge1xuICAgICAgcmVzdWx0LmF1dGggPSBhdXRoSW5Ib3N0LnNoaWZ0KCk7XG4gICAgICByZXN1bHQuaG9zdCA9IHJlc3VsdC5ob3N0bmFtZSA9IGF1dGhJbkhvc3Quc2hpZnQoKTtcbiAgICB9XG4gIH1cblxuICBtdXN0RW5kQWJzID0gbXVzdEVuZEFicyB8fCAocmVzdWx0Lmhvc3QgJiYgc3JjUGF0aC5sZW5ndGgpO1xuXG4gIGlmIChtdXN0RW5kQWJzICYmICFpc0Fic29sdXRlKSB7XG4gICAgc3JjUGF0aC51bnNoaWZ0KCcnKTtcbiAgfVxuXG4gIGlmICghc3JjUGF0aC5sZW5ndGgpIHtcbiAgICByZXN1bHQucGF0aG5hbWUgPSBudWxsO1xuICAgIHJlc3VsdC5wYXRoID0gbnVsbDtcbiAgfSBlbHNlIHtcbiAgICByZXN1bHQucGF0aG5hbWUgPSBzcmNQYXRoLmpvaW4oJy8nKTtcbiAgfVxuXG4gIC8vdG8gc3VwcG9ydCByZXF1ZXN0Lmh0dHBcbiAgaWYgKCF1dGlsLmlzTnVsbChyZXN1bHQucGF0aG5hbWUpIHx8ICF1dGlsLmlzTnVsbChyZXN1bHQuc2VhcmNoKSkge1xuICAgIHJlc3VsdC5wYXRoID0gKHJlc3VsdC5wYXRobmFtZSA/IHJlc3VsdC5wYXRobmFtZSA6ICcnKSArXG4gICAgICAgICAgICAgICAgICAocmVzdWx0LnNlYXJjaCA/IHJlc3VsdC5zZWFyY2ggOiAnJyk7XG4gIH1cbiAgcmVzdWx0LmF1dGggPSByZWxhdGl2ZS5hdXRoIHx8IHJlc3VsdC5hdXRoO1xuICByZXN1bHQuc2xhc2hlcyA9IHJlc3VsdC5zbGFzaGVzIHx8IHJlbGF0aXZlLnNsYXNoZXM7XG4gIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICByZXR1cm4gcmVzdWx0O1xufTtcblxuVXJsLnByb3RvdHlwZS5wYXJzZUhvc3QgPSBmdW5jdGlvbigpIHtcbiAgdmFyIGhvc3QgPSB0aGlzLmhvc3Q7XG4gIHZhciBwb3J0ID0gcG9ydFBhdHRlcm4uZXhlYyhob3N0KTtcbiAgaWYgKHBvcnQpIHtcbiAgICBwb3J0ID0gcG9ydFswXTtcbiAgICBpZiAocG9ydCAhPT0gJzonKSB7XG4gICAgICB0aGlzLnBvcnQgPSBwb3J0LnN1YnN0cigxKTtcbiAgICB9XG4gICAgaG9zdCA9IGhvc3Quc3Vic3RyKDAsIGhvc3QubGVuZ3RoIC0gcG9ydC5sZW5ndGgpO1xuICB9XG4gIGlmIChob3N0KSB0aGlzLmhvc3RuYW1lID0gaG9zdDtcbn07XG4iLCIndXNlIHN0cmljdCc7XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICBpc1N0cmluZzogZnVuY3Rpb24oYXJnKSB7XG4gICAgcmV0dXJuIHR5cGVvZihhcmcpID09PSAnc3RyaW5nJztcbiAgfSxcbiAgaXNPYmplY3Q6IGZ1bmN0aW9uKGFyZykge1xuICAgIHJldHVybiB0eXBlb2YoYXJnKSA9PT0gJ29iamVjdCcgJiYgYXJnICE9PSBudWxsO1xuICB9LFxuICBpc051bGw6IGZ1bmN0aW9uKGFyZykge1xuICAgIHJldHVybiBhcmcgPT09IG51bGw7XG4gIH0sXG4gIGlzTnVsbE9yVW5kZWZpbmVkOiBmdW5jdGlvbihhcmcpIHtcbiAgICByZXR1cm4gYXJnID09IG51bGw7XG4gIH1cbn07XG4iLCIvKipcbiAqIENvbnZlcnQgYXJyYXkgb2YgMTYgYnl0ZSB2YWx1ZXMgdG8gVVVJRCBzdHJpbmcgZm9ybWF0IG9mIHRoZSBmb3JtOlxuICogWFhYWFhYWFgtWFhYWC1YWFhYLVhYWFgtWFhYWFhYWFhYWFhYXG4gKi9cbnZhciBieXRlVG9IZXggPSBbXTtcbmZvciAodmFyIGkgPSAwOyBpIDwgMjU2OyArK2kpIHtcbiAgYnl0ZVRvSGV4W2ldID0gKGkgKyAweDEwMCkudG9TdHJpbmcoMTYpLnN1YnN0cigxKTtcbn1cblxuZnVuY3Rpb24gYnl0ZXNUb1V1aWQoYnVmLCBvZmZzZXQpIHtcbiAgdmFyIGkgPSBvZmZzZXQgfHwgMDtcbiAgdmFyIGJ0aCA9IGJ5dGVUb0hleDtcbiAgLy8gam9pbiB1c2VkIHRvIGZpeCBtZW1vcnkgaXNzdWUgY2F1c2VkIGJ5IGNvbmNhdGVuYXRpb246IGh0dHBzOi8vYnVncy5jaHJvbWl1bS5vcmcvcC92OC9pc3N1ZXMvZGV0YWlsP2lkPTMxNzUjYzRcbiAgcmV0dXJuIChbYnRoW2J1ZltpKytdXSwgYnRoW2J1ZltpKytdXSwgXG5cdGJ0aFtidWZbaSsrXV0sIGJ0aFtidWZbaSsrXV0sICctJyxcblx0YnRoW2J1ZltpKytdXSwgYnRoW2J1ZltpKytdXSwgJy0nLFxuXHRidGhbYnVmW2krK11dLCBidGhbYnVmW2krK11dLCAnLScsXG5cdGJ0aFtidWZbaSsrXV0sIGJ0aFtidWZbaSsrXV0sICctJyxcblx0YnRoW2J1ZltpKytdXSwgYnRoW2J1ZltpKytdXSxcblx0YnRoW2J1ZltpKytdXSwgYnRoW2J1ZltpKytdXSxcblx0YnRoW2J1ZltpKytdXSwgYnRoW2J1ZltpKytdXV0pLmpvaW4oJycpO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IGJ5dGVzVG9VdWlkO1xuIiwiLy8gVW5pcXVlIElEIGNyZWF0aW9uIHJlcXVpcmVzIGEgaGlnaCBxdWFsaXR5IHJhbmRvbSAjIGdlbmVyYXRvci4gIEluIHRoZVxuLy8gYnJvd3NlciB0aGlzIGlzIGEgbGl0dGxlIGNvbXBsaWNhdGVkIGR1ZSB0byB1bmtub3duIHF1YWxpdHkgb2YgTWF0aC5yYW5kb20oKVxuLy8gYW5kIGluY29uc2lzdGVudCBzdXBwb3J0IGZvciB0aGUgYGNyeXB0b2AgQVBJLiAgV2UgZG8gdGhlIGJlc3Qgd2UgY2FuIHZpYVxuLy8gZmVhdHVyZS1kZXRlY3Rpb25cblxuLy8gZ2V0UmFuZG9tVmFsdWVzIG5lZWRzIHRvIGJlIGludm9rZWQgaW4gYSBjb250ZXh0IHdoZXJlIFwidGhpc1wiIGlzIGEgQ3J5cHRvXG4vLyBpbXBsZW1lbnRhdGlvbi4gQWxzbywgZmluZCB0aGUgY29tcGxldGUgaW1wbGVtZW50YXRpb24gb2YgY3J5cHRvIG9uIElFMTEuXG52YXIgZ2V0UmFuZG9tVmFsdWVzID0gKHR5cGVvZihjcnlwdG8pICE9ICd1bmRlZmluZWQnICYmIGNyeXB0by5nZXRSYW5kb21WYWx1ZXMgJiYgY3J5cHRvLmdldFJhbmRvbVZhbHVlcy5iaW5kKGNyeXB0bykpIHx8XG4gICAgICAgICAgICAgICAgICAgICAgKHR5cGVvZihtc0NyeXB0bykgIT0gJ3VuZGVmaW5lZCcgJiYgdHlwZW9mIHdpbmRvdy5tc0NyeXB0by5nZXRSYW5kb21WYWx1ZXMgPT0gJ2Z1bmN0aW9uJyAmJiBtc0NyeXB0by5nZXRSYW5kb21WYWx1ZXMuYmluZChtc0NyeXB0bykpO1xuXG5pZiAoZ2V0UmFuZG9tVmFsdWVzKSB7XG4gIC8vIFdIQVRXRyBjcnlwdG8gUk5HIC0gaHR0cDovL3dpa2kud2hhdHdnLm9yZy93aWtpL0NyeXB0b1xuICB2YXIgcm5kczggPSBuZXcgVWludDhBcnJheSgxNik7IC8vIGVzbGludC1kaXNhYmxlLWxpbmUgbm8tdW5kZWZcblxuICBtb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIHdoYXR3Z1JORygpIHtcbiAgICBnZXRSYW5kb21WYWx1ZXMocm5kczgpO1xuICAgIHJldHVybiBybmRzODtcbiAgfTtcbn0gZWxzZSB7XG4gIC8vIE1hdGgucmFuZG9tKCktYmFzZWQgKFJORylcbiAgLy9cbiAgLy8gSWYgYWxsIGVsc2UgZmFpbHMsIHVzZSBNYXRoLnJhbmRvbSgpLiAgSXQncyBmYXN0LCBidXQgaXMgb2YgdW5zcGVjaWZpZWRcbiAgLy8gcXVhbGl0eS5cbiAgdmFyIHJuZHMgPSBuZXcgQXJyYXkoMTYpO1xuXG4gIG1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gbWF0aFJORygpIHtcbiAgICBmb3IgKHZhciBpID0gMCwgcjsgaSA8IDE2OyBpKyspIHtcbiAgICAgIGlmICgoaSAmIDB4MDMpID09PSAwKSByID0gTWF0aC5yYW5kb20oKSAqIDB4MTAwMDAwMDAwO1xuICAgICAgcm5kc1tpXSA9IHIgPj4+ICgoaSAmIDB4MDMpIDw8IDMpICYgMHhmZjtcbiAgICB9XG5cbiAgICByZXR1cm4gcm5kcztcbiAgfTtcbn1cbiIsIi8vIEFkYXB0ZWQgZnJvbSBDaHJpcyBWZW5lc3MnIFNIQTEgY29kZSBhdFxuLy8gaHR0cDovL3d3dy5tb3ZhYmxlLXR5cGUuY28udWsvc2NyaXB0cy9zaGExLmh0bWxcbid1c2Ugc3RyaWN0JztcblxuZnVuY3Rpb24gZihzLCB4LCB5LCB6KSB7XG4gIHN3aXRjaCAocykge1xuICAgIGNhc2UgMDogcmV0dXJuICh4ICYgeSkgXiAofnggJiB6KTtcbiAgICBjYXNlIDE6IHJldHVybiB4IF4geSBeIHo7XG4gICAgY2FzZSAyOiByZXR1cm4gKHggJiB5KSBeICh4ICYgeikgXiAoeSAmIHopO1xuICAgIGNhc2UgMzogcmV0dXJuIHggXiB5IF4gejtcbiAgfVxufVxuXG5mdW5jdGlvbiBST1RMKHgsIG4pIHtcbiAgcmV0dXJuICh4IDw8IG4pIHwgKHg+Pj4gKDMyIC0gbikpO1xufVxuXG5mdW5jdGlvbiBzaGExKGJ5dGVzKSB7XG4gIHZhciBLID0gWzB4NWE4Mjc5OTksIDB4NmVkOWViYTEsIDB4OGYxYmJjZGMsIDB4Y2E2MmMxZDZdO1xuICB2YXIgSCA9IFsweDY3NDUyMzAxLCAweGVmY2RhYjg5LCAweDk4YmFkY2ZlLCAweDEwMzI1NDc2LCAweGMzZDJlMWYwXTtcblxuICBpZiAodHlwZW9mKGJ5dGVzKSA9PSAnc3RyaW5nJykge1xuICAgIHZhciBtc2cgPSB1bmVzY2FwZShlbmNvZGVVUklDb21wb25lbnQoYnl0ZXMpKTsgLy8gVVRGOCBlc2NhcGVcbiAgICBieXRlcyA9IG5ldyBBcnJheShtc2cubGVuZ3RoKTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IG1zZy5sZW5ndGg7IGkrKykgYnl0ZXNbaV0gPSBtc2cuY2hhckNvZGVBdChpKTtcbiAgfVxuXG4gIGJ5dGVzLnB1c2goMHg4MCk7XG5cbiAgdmFyIGwgPSBieXRlcy5sZW5ndGgvNCArIDI7XG4gIHZhciBOID0gTWF0aC5jZWlsKGwvMTYpO1xuICB2YXIgTSA9IG5ldyBBcnJheShOKTtcblxuICBmb3IgKHZhciBpPTA7IGk8TjsgaSsrKSB7XG4gICAgTVtpXSA9IG5ldyBBcnJheSgxNik7XG4gICAgZm9yICh2YXIgaj0wOyBqPDE2OyBqKyspIHtcbiAgICAgIE1baV1bal0gPVxuICAgICAgICBieXRlc1tpICogNjQgKyBqICogNF0gPDwgMjQgfFxuICAgICAgICBieXRlc1tpICogNjQgKyBqICogNCArIDFdIDw8IDE2IHxcbiAgICAgICAgYnl0ZXNbaSAqIDY0ICsgaiAqIDQgKyAyXSA8PCA4IHxcbiAgICAgICAgYnl0ZXNbaSAqIDY0ICsgaiAqIDQgKyAzXTtcbiAgICB9XG4gIH1cblxuICBNW04gLSAxXVsxNF0gPSAoKGJ5dGVzLmxlbmd0aCAtIDEpICogOCkgL1xuICAgIE1hdGgucG93KDIsIDMyKTsgTVtOIC0gMV1bMTRdID0gTWF0aC5mbG9vcihNW04gLSAxXVsxNF0pO1xuICBNW04gLSAxXVsxNV0gPSAoKGJ5dGVzLmxlbmd0aCAtIDEpICogOCkgJiAweGZmZmZmZmZmO1xuXG4gIGZvciAodmFyIGk9MDsgaTxOOyBpKyspIHtcbiAgICB2YXIgVyA9IG5ldyBBcnJheSg4MCk7XG5cbiAgICBmb3IgKHZhciB0PTA7IHQ8MTY7IHQrKykgV1t0XSA9IE1baV1bdF07XG4gICAgZm9yICh2YXIgdD0xNjsgdDw4MDsgdCsrKSB7XG4gICAgICBXW3RdID0gUk9UTChXW3QgLSAzXSBeIFdbdCAtIDhdIF4gV1t0IC0gMTRdIF4gV1t0IC0gMTZdLCAxKTtcbiAgICB9XG5cbiAgICB2YXIgYSA9IEhbMF07XG4gICAgdmFyIGIgPSBIWzFdO1xuICAgIHZhciBjID0gSFsyXTtcbiAgICB2YXIgZCA9IEhbM107XG4gICAgdmFyIGUgPSBIWzRdO1xuXG4gICAgZm9yICh2YXIgdD0wOyB0PDgwOyB0KyspIHtcbiAgICAgIHZhciBzID0gTWF0aC5mbG9vcih0LzIwKTtcbiAgICAgIHZhciBUID0gUk9UTChhLCA1KSArIGYocywgYiwgYywgZCkgKyBlICsgS1tzXSArIFdbdF0gPj4+IDA7XG4gICAgICBlID0gZDtcbiAgICAgIGQgPSBjO1xuICAgICAgYyA9IFJPVEwoYiwgMzApID4+PiAwO1xuICAgICAgYiA9IGE7XG4gICAgICBhID0gVDtcbiAgICB9XG5cbiAgICBIWzBdID0gKEhbMF0gKyBhKSA+Pj4gMDtcbiAgICBIWzFdID0gKEhbMV0gKyBiKSA+Pj4gMDtcbiAgICBIWzJdID0gKEhbMl0gKyBjKSA+Pj4gMDtcbiAgICBIWzNdID0gKEhbM10gKyBkKSA+Pj4gMDtcbiAgICBIWzRdID0gKEhbNF0gKyBlKSA+Pj4gMDtcbiAgfVxuXG4gIHJldHVybiBbXG4gICAgSFswXSA+PiAyNCAmIDB4ZmYsIEhbMF0gPj4gMTYgJiAweGZmLCBIWzBdID4+IDggJiAweGZmLCBIWzBdICYgMHhmZixcbiAgICBIWzFdID4+IDI0ICYgMHhmZiwgSFsxXSA+PiAxNiAmIDB4ZmYsIEhbMV0gPj4gOCAmIDB4ZmYsIEhbMV0gJiAweGZmLFxuICAgIEhbMl0gPj4gMjQgJiAweGZmLCBIWzJdID4+IDE2ICYgMHhmZiwgSFsyXSA+PiA4ICYgMHhmZiwgSFsyXSAmIDB4ZmYsXG4gICAgSFszXSA+PiAyNCAmIDB4ZmYsIEhbM10gPj4gMTYgJiAweGZmLCBIWzNdID4+IDggJiAweGZmLCBIWzNdICYgMHhmZixcbiAgICBIWzRdID4+IDI0ICYgMHhmZiwgSFs0XSA+PiAxNiAmIDB4ZmYsIEhbNF0gPj4gOCAmIDB4ZmYsIEhbNF0gJiAweGZmXG4gIF07XG59XG5cbm1vZHVsZS5leHBvcnRzID0gc2hhMTtcbiIsInZhciBieXRlc1RvVXVpZCA9IHJlcXVpcmUoJy4vYnl0ZXNUb1V1aWQnKTtcblxuZnVuY3Rpb24gdXVpZFRvQnl0ZXModXVpZCkge1xuICAvLyBOb3RlOiBXZSBhc3N1bWUgd2UncmUgYmVpbmcgcGFzc2VkIGEgdmFsaWQgdXVpZCBzdHJpbmdcbiAgdmFyIGJ5dGVzID0gW107XG4gIHV1aWQucmVwbGFjZSgvW2EtZkEtRjAtOV17Mn0vZywgZnVuY3Rpb24oaGV4KSB7XG4gICAgYnl0ZXMucHVzaChwYXJzZUludChoZXgsIDE2KSk7XG4gIH0pO1xuXG4gIHJldHVybiBieXRlcztcbn1cblxuZnVuY3Rpb24gc3RyaW5nVG9CeXRlcyhzdHIpIHtcbiAgc3RyID0gdW5lc2NhcGUoZW5jb2RlVVJJQ29tcG9uZW50KHN0cikpOyAvLyBVVEY4IGVzY2FwZVxuICB2YXIgYnl0ZXMgPSBuZXcgQXJyYXkoc3RyLmxlbmd0aCk7XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgc3RyLmxlbmd0aDsgaSsrKSB7XG4gICAgYnl0ZXNbaV0gPSBzdHIuY2hhckNvZGVBdChpKTtcbiAgfVxuICByZXR1cm4gYnl0ZXM7XG59XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24obmFtZSwgdmVyc2lvbiwgaGFzaGZ1bmMpIHtcbiAgdmFyIGdlbmVyYXRlVVVJRCA9IGZ1bmN0aW9uKHZhbHVlLCBuYW1lc3BhY2UsIGJ1Ziwgb2Zmc2V0KSB7XG4gICAgdmFyIG9mZiA9IGJ1ZiAmJiBvZmZzZXQgfHwgMDtcblxuICAgIGlmICh0eXBlb2YodmFsdWUpID09ICdzdHJpbmcnKSB2YWx1ZSA9IHN0cmluZ1RvQnl0ZXModmFsdWUpO1xuICAgIGlmICh0eXBlb2YobmFtZXNwYWNlKSA9PSAnc3RyaW5nJykgbmFtZXNwYWNlID0gdXVpZFRvQnl0ZXMobmFtZXNwYWNlKTtcblxuICAgIGlmICghQXJyYXkuaXNBcnJheSh2YWx1ZSkpIHRocm93IFR5cGVFcnJvcigndmFsdWUgbXVzdCBiZSBhbiBhcnJheSBvZiBieXRlcycpO1xuICAgIGlmICghQXJyYXkuaXNBcnJheShuYW1lc3BhY2UpIHx8IG5hbWVzcGFjZS5sZW5ndGggIT09IDE2KSB0aHJvdyBUeXBlRXJyb3IoJ25hbWVzcGFjZSBtdXN0IGJlIHV1aWQgc3RyaW5nIG9yIGFuIEFycmF5IG9mIDE2IGJ5dGUgdmFsdWVzJyk7XG5cbiAgICAvLyBQZXIgNC4zXG4gICAgdmFyIGJ5dGVzID0gaGFzaGZ1bmMobmFtZXNwYWNlLmNvbmNhdCh2YWx1ZSkpO1xuICAgIGJ5dGVzWzZdID0gKGJ5dGVzWzZdICYgMHgwZikgfCB2ZXJzaW9uO1xuICAgIGJ5dGVzWzhdID0gKGJ5dGVzWzhdICYgMHgzZikgfCAweDgwO1xuXG4gICAgaWYgKGJ1Zikge1xuICAgICAgZm9yICh2YXIgaWR4ID0gMDsgaWR4IDwgMTY7ICsraWR4KSB7XG4gICAgICAgIGJ1ZltvZmYraWR4XSA9IGJ5dGVzW2lkeF07XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIGJ1ZiB8fCBieXRlc1RvVXVpZChieXRlcyk7XG4gIH07XG5cbiAgLy8gRnVuY3Rpb24jbmFtZSBpcyBub3Qgc2V0dGFibGUgb24gc29tZSBwbGF0Zm9ybXMgKCMyNzApXG4gIHRyeSB7XG4gICAgZ2VuZXJhdGVVVUlELm5hbWUgPSBuYW1lO1xuICB9IGNhdGNoIChlcnIpIHtcbiAgfVxuXG4gIC8vIFByZS1kZWZpbmVkIG5hbWVzcGFjZXMsIHBlciBBcHBlbmRpeCBDXG4gIGdlbmVyYXRlVVVJRC5ETlMgPSAnNmJhN2I4MTAtOWRhZC0xMWQxLTgwYjQtMDBjMDRmZDQzMGM4JztcbiAgZ2VuZXJhdGVVVUlELlVSTCA9ICc2YmE3YjgxMS05ZGFkLTExZDEtODBiNC0wMGMwNGZkNDMwYzgnO1xuXG4gIHJldHVybiBnZW5lcmF0ZVVVSUQ7XG59O1xuIiwidmFyIHJuZyA9IHJlcXVpcmUoJy4vbGliL3JuZycpO1xudmFyIGJ5dGVzVG9VdWlkID0gcmVxdWlyZSgnLi9saWIvYnl0ZXNUb1V1aWQnKTtcblxuZnVuY3Rpb24gdjQob3B0aW9ucywgYnVmLCBvZmZzZXQpIHtcbiAgdmFyIGkgPSBidWYgJiYgb2Zmc2V0IHx8IDA7XG5cbiAgaWYgKHR5cGVvZihvcHRpb25zKSA9PSAnc3RyaW5nJykge1xuICAgIGJ1ZiA9IG9wdGlvbnMgPT09ICdiaW5hcnknID8gbmV3IEFycmF5KDE2KSA6IG51bGw7XG4gICAgb3B0aW9ucyA9IG51bGw7XG4gIH1cbiAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG5cbiAgdmFyIHJuZHMgPSBvcHRpb25zLnJhbmRvbSB8fCAob3B0aW9ucy5ybmcgfHwgcm5nKSgpO1xuXG4gIC8vIFBlciA0LjQsIHNldCBiaXRzIGZvciB2ZXJzaW9uIGFuZCBgY2xvY2tfc2VxX2hpX2FuZF9yZXNlcnZlZGBcbiAgcm5kc1s2XSA9IChybmRzWzZdICYgMHgwZikgfCAweDQwO1xuICBybmRzWzhdID0gKHJuZHNbOF0gJiAweDNmKSB8IDB4ODA7XG5cbiAgLy8gQ29weSBieXRlcyB0byBidWZmZXIsIGlmIHByb3ZpZGVkXG4gIGlmIChidWYpIHtcbiAgICBmb3IgKHZhciBpaSA9IDA7IGlpIDwgMTY7ICsraWkpIHtcbiAgICAgIGJ1ZltpICsgaWldID0gcm5kc1tpaV07XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIGJ1ZiB8fCBieXRlc1RvVXVpZChybmRzKTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSB2NDtcbiIsInZhciB2MzUgPSByZXF1aXJlKCcuL2xpYi92MzUuanMnKTtcbnZhciBzaGExID0gcmVxdWlyZSgnLi9saWIvc2hhMScpO1xubW9kdWxlLmV4cG9ydHMgPSB2MzUoJ3Y1JywgMHg1MCwgc2hhMSk7XG4iLCIndXNlIHN0cmljdCc7XG5cbmNvbnN0IHY0ID0gcmVxdWlyZSgndXVpZC92NCcpLFxuICAgICAgdjUgPSByZXF1aXJlKCd1dWlkL3Y1Jyk7XG5cbmNvbnN0IHV1aWR2NCA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIHY0KCk7XG59O1xuXG51dWlkdjQucmVnZXggPSB7XG4gIHY0OiAvXihbYS1mMC05XXs4fS1bYS1mMC05XXs0fS00W2EtZjAtOV17M30tW2EtZjAtOV17NH0tW2EtZjAtOV17MTJ9KXwoMHs4fS0wezR9LTB7NH0tMHs0fS0wezEyfSkkLyxcbiAgdjU6IC9eKFthLWYwLTldezh9LVthLWYwLTldezR9LTVbYS1mMC05XXszfS1bYS1mMC05XXs0fS1bYS1mMC05XXsxMn0pfCgwezh9LTB7NH0tMHs0fS0wezR9LTB7MTJ9KSQvXG59O1xuXG51dWlkdjQuaXMgPSBmdW5jdGlvbiAodmFsdWUpIHtcbiAgaWYgKCF2YWx1ZSkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIHJldHVybiB1dWlkdjQucmVnZXgudjQudGVzdCh2YWx1ZSkgfHwgdXVpZHY0LnJlZ2V4LnY1LnRlc3QodmFsdWUpO1xufTtcblxudXVpZHY0LmVtcHR5ID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gJzAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCc7XG59O1xuXG51dWlkdjQuZnJvbVN0cmluZyA9IGZ1bmN0aW9uICh0ZXh0KSB7XG4gIGlmICghdGV4dCkge1xuICAgIHRocm93IG5ldyBFcnJvcignVGV4dCBpcyBtaXNzaW5nLicpO1xuICB9XG5cbiAgY29uc3QgbmFtZXNwYWNlID0gJ2JiNWQwZmZhLTlhNGMtNGQ3Yy04ZmMyLTBhN2QyMjIwYmE0NSc7XG5cbiAgY29uc3QgdXVpZEZyb21TdHJpbmcgPSB2NSh0ZXh0LCBuYW1lc3BhY2UpO1xuXG4gIHJldHVybiB1dWlkRnJvbVN0cmluZztcbn07XG5cbm1vZHVsZS5leHBvcnRzID0gdXVpZHY0O1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG4vLyBDb3B5cmlnaHQgMjAxOCBUaGUgT3V0bGluZSBBdXRob3JzXG4vL1xuLy8gTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbi8vIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbi8vIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuLy9cbi8vICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4vL1xuLy8gVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuLy8gZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuLy8gV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4vLyBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4vLyBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbnZhciBfX3JlYWQgPSAodGhpcyAmJiB0aGlzLl9fcmVhZCkgfHwgZnVuY3Rpb24gKG8sIG4pIHtcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl07XG4gICAgaWYgKCFtKSByZXR1cm4gbztcbiAgICB2YXIgaSA9IG0uY2FsbChvKSwgciwgYXIgPSBbXSwgZTtcbiAgICB0cnkge1xuICAgICAgICB3aGlsZSAoKG4gPT09IHZvaWQgMCB8fCBuLS0gPiAwKSAmJiAhKHIgPSBpLm5leHQoKSkuZG9uZSkgYXIucHVzaChyLnZhbHVlKTtcbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7IGUgPSB7IGVycm9yOiBlcnJvciB9OyB9XG4gICAgZmluYWxseSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBpZiAociAmJiAhci5kb25lICYmIChtID0gaVtcInJldHVyblwiXSkpIG0uY2FsbChpKTtcbiAgICAgICAgfVxuICAgICAgICBmaW5hbGx5IHsgaWYgKGUpIHRocm93IGUuZXJyb3I7IH1cbiAgICB9XG4gICAgcmV0dXJuIGFyO1xufTtcbnZhciBfX3NwcmVhZCA9ICh0aGlzICYmIHRoaXMuX19zcHJlYWQpIHx8IGZ1bmN0aW9uICgpIHtcbiAgICBmb3IgKHZhciBhciA9IFtdLCBpID0gMDsgaSA8IGFyZ3VtZW50cy5sZW5ndGg7IGkrKykgYXIgPSBhci5jb25jYXQoX19yZWFkKGFyZ3VtZW50c1tpXSkpO1xuICAgIHJldHVybiBhcjtcbn07XG52YXIgX192YWx1ZXMgPSAodGhpcyAmJiB0aGlzLl9fdmFsdWVzKSB8fCBmdW5jdGlvbihvKSB7XG4gICAgdmFyIHMgPSB0eXBlb2YgU3ltYm9sID09PSBcImZ1bmN0aW9uXCIgJiYgU3ltYm9sLml0ZXJhdG9yLCBtID0gcyAmJiBvW3NdLCBpID0gMDtcbiAgICBpZiAobSkgcmV0dXJuIG0uY2FsbChvKTtcbiAgICBpZiAobyAmJiB0eXBlb2Ygby5sZW5ndGggPT09IFwibnVtYmVyXCIpIHJldHVybiB7XG4gICAgICAgIG5leHQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGlmIChvICYmIGkgPj0gby5sZW5ndGgpIG8gPSB2b2lkIDA7XG4gICAgICAgICAgICByZXR1cm4geyB2YWx1ZTogbyAmJiBvW2krK10sIGRvbmU6ICFvIH07XG4gICAgICAgIH1cbiAgICB9O1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IocyA/IFwiT2JqZWN0IGlzIG5vdCBpdGVyYWJsZS5cIiA6IFwiU3ltYm9sLml0ZXJhdG9yIGlzIG5vdCBkZWZpbmVkLlwiKTtcbn07XG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG52YXIgc2hhZG93c29ja3NfY29uZmlnXzEgPSByZXF1aXJlKFwiU2hhZG93c29ja3NDb25maWcvc2hhZG93c29ja3NfY29uZmlnXCIpO1xudmFyIGVycm9ycyA9IHJlcXVpcmUoXCIuLi9tb2RlbC9lcnJvcnNcIik7XG52YXIgZXZlbnRzID0gcmVxdWlyZShcIi4uL21vZGVsL2V2ZW50c1wiKTtcbnZhciBzZXR0aW5nc18xID0gcmVxdWlyZShcIi4vc2V0dGluZ3NcIik7XG4vLyBJZiBzIGlzIGEgVVJMIHdob3NlIGZyYWdtZW50IGNvbnRhaW5zIGEgU2hhZG93c29ja3MgVVJMIHRoZW4gcmV0dXJuIHRoYXQgU2hhZG93c29ja3MgVVJMLFxuLy8gb3RoZXJ3aXNlIHJldHVybiBzLlxuZnVuY3Rpb24gdW53cmFwSW52aXRlKHMpIHtcbiAgICB0cnkge1xuICAgICAgICB2YXIgdXJsID0gbmV3IFVSTChzKTtcbiAgICAgICAgaWYgKHVybC5oYXNoKSB7XG4gICAgICAgICAgICB2YXIgZGVjb2RlZEZyYWdtZW50ID0gZGVjb2RlVVJJQ29tcG9uZW50KHVybC5oYXNoKTtcbiAgICAgICAgICAgIC8vIFNlYXJjaCBpbiB0aGUgZnJhZ21lbnQgZm9yIHNzOi8vIGZvciB0d28gcmVhc29uczpcbiAgICAgICAgICAgIC8vICAtIFVSTC5oYXNoIGluY2x1ZGVzIHRoZSBsZWFkaW5nICMgKHdoYXQpLlxuICAgICAgICAgICAgLy8gIC0gV2hlbiBhIHVzZXIgb3BlbnMgaW52aXRlLmh0bWwjRU5DT0RFRFNTVVJMIGluIHRoZWlyIGJyb3dzZXIsIHRoZSB3ZWJzaXRlIChjdXJyZW50bHkpXG4gICAgICAgICAgICAvLyAgICByZWRpcmVjdHMgdG8gaW52aXRlLmh0bWwjL2VuL2ludml0ZS9FTkNPREVEU1NVUkwuIFNpbmNlIGNvcHlpbmcgdGhhdCByZWRpcmVjdGVkIFVSTFxuICAgICAgICAgICAgLy8gICAgc2VlbXMgbGlrZSBhIHJlYXNvbmFibGUgdGhpbmcgdG8gZG8sIGxldCdzIHN1cHBvcnQgdGhvc2UgVVJMcyB0b28uXG4gICAgICAgICAgICB2YXIgcG9zc2libGVTaGFkb3dzb2Nrc1VybCA9IGRlY29kZWRGcmFnbWVudC5zdWJzdHJpbmcoZGVjb2RlZEZyYWdtZW50LmluZGV4T2YoJ3NzOi8vJykpO1xuICAgICAgICAgICAgaWYgKG5ldyBVUkwocG9zc2libGVTaGFkb3dzb2Nrc1VybCkucHJvdG9jb2wgPT09ICdzczonKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHBvc3NpYmxlU2hhZG93c29ja3NVcmw7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG4gICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgLy8gU29tZXRoaW5nIHdhc24ndCBhIFVSTCwgb3IgaXQgY291bGRuJ3QgYmUgZGVjb2RlZCAtIG5vIHByb2JsZW0sIHBlb3BsZSBwdXQgYWxsIGtpbmRzIG9mXG4gICAgICAgIC8vIGNyYXp5IHRoaW5ncyBpbiB0aGUgY2xpcGJvYXJkLlxuICAgIH1cbiAgICByZXR1cm4gcztcbn1cbmV4cG9ydHMudW53cmFwSW52aXRlID0gdW53cmFwSW52aXRlO1xudmFyIEFwcCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBBcHAoZXZlbnRRdWV1ZSwgc2VydmVyUmVwbywgcm9vdEVsLCBkZWJ1Z01vZGUsIHVybEludGVyY2VwdG9yLCBjbGlwYm9hcmQsIGVycm9yUmVwb3J0ZXIsIHNldHRpbmdzLCBlbnZpcm9ubWVudFZhcnMsIHVwZGF0ZXIsIHF1aXRBcHBsaWNhdGlvbiwgZG9jdW1lbnQpIHtcbiAgICAgICAgaWYgKGRvY3VtZW50ID09PSB2b2lkIDApIHsgZG9jdW1lbnQgPSB3aW5kb3cuZG9jdW1lbnQ7IH1cbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlID0gZXZlbnRRdWV1ZTtcbiAgICAgICAgdGhpcy5zZXJ2ZXJSZXBvID0gc2VydmVyUmVwbztcbiAgICAgICAgdGhpcy5yb290RWwgPSByb290RWw7XG4gICAgICAgIHRoaXMuZGVidWdNb2RlID0gZGVidWdNb2RlO1xuICAgICAgICB0aGlzLmNsaXBib2FyZCA9IGNsaXBib2FyZDtcbiAgICAgICAgdGhpcy5lcnJvclJlcG9ydGVyID0gZXJyb3JSZXBvcnRlcjtcbiAgICAgICAgdGhpcy5zZXR0aW5ncyA9IHNldHRpbmdzO1xuICAgICAgICB0aGlzLmVudmlyb25tZW50VmFycyA9IGVudmlyb25tZW50VmFycztcbiAgICAgICAgdGhpcy51cGRhdGVyID0gdXBkYXRlcjtcbiAgICAgICAgdGhpcy5xdWl0QXBwbGljYXRpb24gPSBxdWl0QXBwbGljYXRpb247XG4gICAgICAgIHRoaXMuaWdub3JlZEFjY2Vzc0tleXMgPSB7fTtcbiAgICAgICAgdGhpcy5zZXJ2ZXJMaXN0RWwgPSByb290RWwuJC5zZXJ2ZXJzVmlldy4kLnNlcnZlckxpc3Q7XG4gICAgICAgIHRoaXMuZmVlZGJhY2tWaWV3RWwgPSByb290RWwuJC5mZWVkYmFja1ZpZXc7XG4gICAgICAgIHRoaXMuc3luY1NlcnZlcnNUb1VJKCk7XG4gICAgICAgIHRoaXMuc3luY0Nvbm5lY3Rpdml0eVN0YXRlVG9TZXJ2ZXJDYXJkcygpO1xuICAgICAgICByb290RWwuJC5hYm91dFZpZXcudmVyc2lvbiA9IGVudmlyb25tZW50VmFycy5BUFBfVkVSU0lPTjtcbiAgICAgICAgdGhpcy5sb2NhbGl6ZSA9IHRoaXMucm9vdEVsLmxvY2FsaXplLmJpbmQodGhpcy5yb290RWwpO1xuICAgICAgICBpZiAodXJsSW50ZXJjZXB0b3IpIHtcbiAgICAgICAgICAgIHRoaXMucmVnaXN0ZXJVcmxJbnRlcmNlcHRpb25MaXN0ZW5lcih1cmxJbnRlcmNlcHRvcik7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oJ25vIHVybEludGVyY2VwdG9yLCBzczovLyB1cmxzIHdpbGwgbm90IGJlIGludGVyY2VwdGVkJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5jbGlwYm9hcmQuc2V0TGlzdGVuZXIodGhpcy5oYW5kbGVDbGlwYm9hcmRUZXh0LmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLnVwZGF0ZXIuc2V0TGlzdGVuZXIodGhpcy51cGRhdGVEb3dubG9hZGVkLmJpbmQodGhpcykpO1xuICAgICAgICAvLyBSZWdpc3RlciBDb3Jkb3ZhIG1vYmlsZSBmb3JlZ3JvdW5kIGV2ZW50IHRvIHN5bmMgc2VydmVyIGNvbm5lY3Rpdml0eS5cbiAgICAgICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigncmVzdW1lJywgdGhpcy5zeW5jQ29ubmVjdGl2aXR5U3RhdGVUb1NlcnZlckNhcmRzLmJpbmQodGhpcykpO1xuICAgICAgICAvLyBSZWdpc3RlciBoYW5kbGVycyBmb3IgZXZlbnRzIGZpcmVkIGJ5IFBvbHltZXIgY29tcG9uZW50cy5cbiAgICAgICAgdGhpcy5yb290RWwuYWRkRXZlbnRMaXN0ZW5lcignUHJvbXB0QWRkU2VydmVyUmVxdWVzdGVkJywgdGhpcy5yZXF1ZXN0UHJvbXB0QWRkU2VydmVyLmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLnJvb3RFbC5hZGRFdmVudExpc3RlbmVyKCdBZGRTZXJ2ZXJDb25maXJtYXRpb25SZXF1ZXN0ZWQnLCB0aGlzLnJlcXVlc3RBZGRTZXJ2ZXJDb25maXJtYXRpb24uYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMucm9vdEVsLmFkZEV2ZW50TGlzdGVuZXIoJ0FkZFNlcnZlclJlcXVlc3RlZCcsIHRoaXMucmVxdWVzdEFkZFNlcnZlci5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5yb290RWwuYWRkRXZlbnRMaXN0ZW5lcignSWdub3JlU2VydmVyUmVxdWVzdGVkJywgdGhpcy5yZXF1ZXN0SWdub3JlU2VydmVyLmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLnJvb3RFbC5hZGRFdmVudExpc3RlbmVyKCdDb25uZWN0UHJlc3NlZCcsIHRoaXMuY29ubmVjdFNlcnZlci5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5yb290RWwuYWRkRXZlbnRMaXN0ZW5lcignRGlzY29ubmVjdFByZXNzZWQnLCB0aGlzLmRpc2Nvbm5lY3RTZXJ2ZXIuYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMucm9vdEVsLmFkZEV2ZW50TGlzdGVuZXIoJ0ZvcmdldFByZXNzZWQnLCB0aGlzLmZvcmdldFNlcnZlci5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5yb290RWwuYWRkRXZlbnRMaXN0ZW5lcignUmVuYW1lUmVxdWVzdGVkJywgdGhpcy5yZW5hbWVTZXJ2ZXIuYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMucm9vdEVsLmFkZEV2ZW50TGlzdGVuZXIoJ1F1aXRQcmVzc2VkJywgdGhpcy5xdWl0QXBwbGljYXRpb24uYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMucm9vdEVsLmFkZEV2ZW50TGlzdGVuZXIoJ0F1dG9Db25uZWN0RGlhbG9nRGlzbWlzc2VkJywgdGhpcy5hdXRvQ29ubmVjdERpYWxvZ0Rpc21pc3NlZC5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5yb290RWwuYWRkRXZlbnRMaXN0ZW5lcignU2hvd1NlcnZlclJlbmFtZScsIHRoaXMucm9vdEVsLnNob3dTZXJ2ZXJSZW5hbWUuYmluZCh0aGlzLnJvb3RFbCkpO1xuICAgICAgICB0aGlzLmZlZWRiYWNrVmlld0VsLiQuc3VibWl0QnV0dG9uLmFkZEV2ZW50TGlzdGVuZXIoJ3RhcCcsIHRoaXMuc3VibWl0RmVlZGJhY2suYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMucm9vdEVsLmFkZEV2ZW50TGlzdGVuZXIoJ1ByaXZhY3lUZXJtc0Fja2VkJywgdGhpcy5hY2tQcml2YWN5VGVybXMuYmluZCh0aGlzKSk7XG4gICAgICAgIC8vIFJlZ2lzdGVyIGhhbmRsZXJzIGZvciBldmVudHMgcHVibGlzaGVkIHRvIG91ciBldmVudCBxdWV1ZS5cbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlLnN1YnNjcmliZShldmVudHMuU2VydmVyQWRkZWQsIHRoaXMuc2hvd1NlcnZlckFkZGVkLmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLmV2ZW50UXVldWUuc3Vic2NyaWJlKGV2ZW50cy5TZXJ2ZXJGb3Jnb3R0ZW4sIHRoaXMuc2hvd1NlcnZlckZvcmdvdHRlbi5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlLnN1YnNjcmliZShldmVudHMuU2VydmVyUmVuYW1lZCwgdGhpcy5zaG93U2VydmVyUmVuYW1lZC5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlLnN1YnNjcmliZShldmVudHMuU2VydmVyRm9yZ2V0VW5kb25lLCB0aGlzLnNob3dTZXJ2ZXJGb3JnZXRVbmRvbmUuYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMuZXZlbnRRdWV1ZS5zdWJzY3JpYmUoZXZlbnRzLlNlcnZlckNvbm5lY3RlZCwgdGhpcy5zaG93U2VydmVyQ29ubmVjdGVkLmJpbmQodGhpcykpO1xuICAgICAgICB0aGlzLmV2ZW50UXVldWUuc3Vic2NyaWJlKGV2ZW50cy5TZXJ2ZXJEaXNjb25uZWN0ZWQsIHRoaXMuc2hvd1NlcnZlckRpc2Nvbm5lY3RlZC5iaW5kKHRoaXMpKTtcbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlLnN1YnNjcmliZShldmVudHMuU2VydmVyUmVjb25uZWN0aW5nLCB0aGlzLnNob3dTZXJ2ZXJSZWNvbm5lY3RpbmcuYmluZCh0aGlzKSk7XG4gICAgICAgIHRoaXMuZXZlbnRRdWV1ZS5zdGFydFB1Ymxpc2hpbmcoKTtcbiAgICAgICAgaWYgKCF0aGlzLmFyZVByaXZhY3lUZXJtc0Fja2VkKCkpIHtcbiAgICAgICAgICAgIHRoaXMuZGlzcGxheVByaXZhY3lWaWV3KCk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5kaXNwbGF5WmVyb1N0YXRlVWkoKTtcbiAgICAgICAgdGhpcy5wdWxsQ2xpcGJvYXJkVGV4dCgpO1xuICAgIH1cbiAgICBBcHAucHJvdG90eXBlLnNob3dMb2NhbGl6ZWRFcnJvciA9IGZ1bmN0aW9uIChlLCB0b2FzdER1cmF0aW9uKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIGlmICh0b2FzdER1cmF0aW9uID09PSB2b2lkIDApIHsgdG9hc3REdXJhdGlvbiA9IDEwMDAwOyB9XG4gICAgICAgIHZhciBtZXNzYWdlS2V5O1xuICAgICAgICB2YXIgbWVzc2FnZVBhcmFtcztcbiAgICAgICAgdmFyIGJ1dHRvbktleTtcbiAgICAgICAgdmFyIGJ1dHRvbkhhbmRsZXI7XG4gICAgICAgIHZhciBidXR0b25MaW5rO1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIGVycm9ycy5WcG5QZXJtaXNzaW9uTm90R3JhbnRlZCkge1xuICAgICAgICAgICAgbWVzc2FnZUtleSA9ICdvdXRsaW5lLXBsdWdpbi1lcnJvci12cG4tcGVybWlzc2lvbi1ub3QtZ3JhbnRlZCc7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIGVycm9ycy5JbnZhbGlkU2VydmVyQ3JlZGVudGlhbHMpIHtcbiAgICAgICAgICAgIG1lc3NhZ2VLZXkgPSAnb3V0bGluZS1wbHVnaW4tZXJyb3ItaW52YWxpZC1zZXJ2ZXItY3JlZGVudGlhbHMnO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBlcnJvcnMuUmVtb3RlVWRwRm9yd2FyZGluZ0Rpc2FibGVkKSB7XG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ291dGxpbmUtcGx1Z2luLWVycm9yLXVkcC1mb3J3YXJkaW5nLW5vdC1lbmFibGVkJztcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgZXJyb3JzLlNlcnZlclVucmVhY2hhYmxlKSB7XG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ291dGxpbmUtcGx1Z2luLWVycm9yLXNlcnZlci11bnJlYWNoYWJsZSc7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIGVycm9ycy5GZWVkYmFja1N1Ym1pc3Npb25FcnJvcikge1xuICAgICAgICAgICAgbWVzc2FnZUtleSA9ICdlcnJvci1mZWVkYmFjay1zdWJtaXNzaW9uJztcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgZXJyb3JzLlNlcnZlclVybEludmFsaWQpIHtcbiAgICAgICAgICAgIG1lc3NhZ2VLZXkgPSAnZXJyb3ItaW52YWxpZC1hY2Nlc3Mta2V5JztcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgZXJyb3JzLlNlcnZlckluY29tcGF0aWJsZSkge1xuICAgICAgICAgICAgbWVzc2FnZUtleSA9ICdlcnJvci1zZXJ2ZXItaW5jb21wYXRpYmxlJztcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgZXJyb3JzLk9wZXJhdGlvblRpbWVkT3V0KSB7XG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ2Vycm9yLXRpbWVvdXQnO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBlcnJvcnMuU2hhZG93c29ja3NTdGFydEZhaWx1cmUgJiYgdGhpcy5pc1dpbmRvd3MoKSkge1xuICAgICAgICAgICAgLy8gRmFsbCB0aHJvdWdoIHRvIGBlcnJvci11bmV4cGVjdGVkYCBmb3Igb3RoZXIgcGxhdGZvcm1zLlxuICAgICAgICAgICAgbWVzc2FnZUtleSA9ICdvdXRsaW5lLXBsdWdpbi1lcnJvci1hbnRpdmlydXMnO1xuICAgICAgICAgICAgYnV0dG9uS2V5ID0gJ2ZpeC10aGlzJztcbiAgICAgICAgICAgIGJ1dHRvbkxpbmsgPSAnaHR0cHM6Ly9zMy5hbWF6b25hd3MuY29tL291dGxpbmUtdnBuL2luZGV4Lmh0bWwjL2VuL3N1cHBvcnQvYW50aXZpcnVzQmxvY2snO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBlcnJvcnMuQ29uZmlndXJlU3lzdGVtUHJveHlGYWlsdXJlKSB7XG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ291dGxpbmUtcGx1Z2luLWVycm9yLXJvdXRpbmctdGFibGVzJztcbiAgICAgICAgICAgIGJ1dHRvbktleSA9ICdmZWVkYmFjay1wYWdlLXRpdGxlJztcbiAgICAgICAgICAgIGJ1dHRvbkhhbmRsZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgLy8gVE9ETzogRHJvcC1kb3duIGhhcyBubyBzZWxlY3RlZCBpdGVtLCB3aHkgbm90P1xuICAgICAgICAgICAgICAgIF90aGlzLnJvb3RFbC5jaGFuZ2VQYWdlKCdmZWVkYmFjaycpO1xuICAgICAgICAgICAgfTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgZXJyb3JzLk5vQWRtaW5QZXJtaXNzaW9ucykge1xuICAgICAgICAgICAgbWVzc2FnZUtleSA9ICdvdXRsaW5lLXBsdWdpbi1lcnJvci1hZG1pbi1wZXJtaXNzaW9ucyc7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIGVycm9ycy5VbnN1cHBvcnRlZFJvdXRpbmdUYWJsZSkge1xuICAgICAgICAgICAgbWVzc2FnZUtleSA9ICdvdXRsaW5lLXBsdWdpbi1lcnJvci11bnN1cHBvcnRlZC1yb3V0aW5nLXRhYmxlJztcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgZXJyb3JzLlNlcnZlckFscmVhZHlBZGRlZCkge1xuICAgICAgICAgICAgbWVzc2FnZUtleSA9ICdlcnJvci1zZXJ2ZXItYWxyZWFkeS1hZGRlZCc7XG4gICAgICAgICAgICBtZXNzYWdlUGFyYW1zID0gWydzZXJ2ZXJOYW1lJywgZS5zZXJ2ZXIubmFtZV07XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIGVycm9ycy5TeXN0ZW1Db25maWd1cmF0aW9uRXhjZXB0aW9uKSB7XG4gICAgICAgICAgICBtZXNzYWdlS2V5ID0gJ291dGxpbmUtcGx1Z2luLWVycm9yLXN5c3RlbS1jb25maWd1cmF0aW9uJztcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIG1lc3NhZ2VLZXkgPSAnZXJyb3ItdW5leHBlY3RlZCc7XG4gICAgICAgIH1cbiAgICAgICAgdmFyIG1lc3NhZ2UgPSBtZXNzYWdlUGFyYW1zID8gdGhpcy5sb2NhbGl6ZS5hcHBseSh0aGlzLCBfX3NwcmVhZChbbWVzc2FnZUtleV0sIG1lc3NhZ2VQYXJhbXMpKSA6IHRoaXMubG9jYWxpemUobWVzc2FnZUtleSk7XG4gICAgICAgIC8vIERlZmVyIGJ5IDUwMG1zIHNvIHRoYXQgdGhpcyB0b2FzdCBpcyBzaG93biBhZnRlciBhbnkgdG9hc3RzIHRoYXQgZ2V0IHNob3duIHdoZW4gYW55XG4gICAgICAgIC8vIGN1cnJlbnRseS1pbi1mbGlnaHQgZG9tYWluIGV2ZW50cyBsYW5kIChlLmcuIGZha2Ugc2VydmVycyBhZGRlZCkuXG4gICAgICAgIGlmICh0aGlzLnJvb3RFbCAmJiB0aGlzLnJvb3RFbC5hc3luYykge1xuICAgICAgICAgICAgdGhpcy5yb290RWwuYXN5bmMoZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIF90aGlzLnJvb3RFbC5zaG93VG9hc3QobWVzc2FnZSwgdG9hc3REdXJhdGlvbiwgYnV0dG9uS2V5ID8gX3RoaXMubG9jYWxpemUoYnV0dG9uS2V5KSA6IHVuZGVmaW5lZCwgYnV0dG9uSGFuZGxlciwgYnV0dG9uTGluayk7XG4gICAgICAgICAgICB9LCA1MDApO1xuICAgICAgICB9XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnB1bGxDbGlwYm9hcmRUZXh0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICB0aGlzLmNsaXBib2FyZC5nZXRDb250ZW50cygpLnRoZW4oZnVuY3Rpb24gKHRleHQpIHtcbiAgICAgICAgICAgIF90aGlzLmhhbmRsZUNsaXBib2FyZFRleHQodGV4dCk7XG4gICAgICAgIH0sIGZ1bmN0aW9uIChlKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oJ2Nhbm5vdCByZWFkIGNsaXBib2FyZCwgc3lzdGVtIG1heSBsYWNrIGNsaXBib2FyZCBzdXBwb3J0Jyk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5zaG93U2VydmVyQ29ubmVjdGVkID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIGNvbnNvbGUuZGVidWcoXCJzZXJ2ZXIgXCIgKyBldmVudC5zZXJ2ZXIuaWQgKyBcIiBjb25uZWN0ZWRcIik7XG4gICAgICAgIHZhciBjYXJkID0gdGhpcy5zZXJ2ZXJMaXN0RWwuZ2V0U2VydmVyQ2FyZChldmVudC5zZXJ2ZXIuaWQpO1xuICAgICAgICBjYXJkLnN0YXRlID0gJ0NPTk5FQ1RFRCc7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnNob3dTZXJ2ZXJEaXNjb25uZWN0ZWQgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgY29uc29sZS5kZWJ1ZyhcInNlcnZlciBcIiArIGV2ZW50LnNlcnZlci5pZCArIFwiIGRpc2Nvbm5lY3RlZFwiKTtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHRoaXMuc2VydmVyTGlzdEVsLmdldFNlcnZlckNhcmQoZXZlbnQuc2VydmVyLmlkKS5zdGF0ZSA9ICdESVNDT05ORUNURUQnO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oJ3NlcnZlciBjYXJkIG5vdCBmb3VuZCBhZnRlciBkaXNjb25uZWN0aW9uIGV2ZW50LCBhc3N1bWluZyBmb3Jnb3R0ZW4nKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5zaG93U2VydmVyUmVjb25uZWN0aW5nID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIGNvbnNvbGUuZGVidWcoXCJzZXJ2ZXIgXCIgKyBldmVudC5zZXJ2ZXIuaWQgKyBcIiByZWNvbm5lY3RpbmdcIik7XG4gICAgICAgIHZhciBjYXJkID0gdGhpcy5zZXJ2ZXJMaXN0RWwuZ2V0U2VydmVyQ2FyZChldmVudC5zZXJ2ZXIuaWQpO1xuICAgICAgICBjYXJkLnN0YXRlID0gJ1JFQ09OTkVDVElORyc7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLmRpc3BsYXlaZXJvU3RhdGVVaSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKHRoaXMucm9vdEVsLiQuc2VydmVyc1ZpZXcuc2hvdWxkU2hvd1plcm9TdGF0ZSkge1xuICAgICAgICAgICAgdGhpcy5yb290RWwuJC5hZGRTZXJ2ZXJWaWV3Lm9wZW5BZGRTZXJ2ZXJTaGVldCgpO1xuICAgICAgICB9XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLmFyZVByaXZhY3lUZXJtc0Fja2VkID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuc2V0dGluZ3MuZ2V0KHNldHRpbmdzXzEuU2V0dGluZ3NLZXkuUFJJVkFDWV9BQ0spID09PSAndHJ1ZSc7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJjb3VsZCBub3QgcmVhZCBwcml2YWN5IGFja25vd2xlZGdlbWVudCBzZXR0aW5nLCBhc3N1bWluZyBub3QgYWNrbm93bGVkZ2VkXCIpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuZGlzcGxheVByaXZhY3lWaWV3ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB0aGlzLnJvb3RFbC4kLnNlcnZlcnNWaWV3LmhpZGRlbiA9IHRydWU7XG4gICAgICAgIHRoaXMucm9vdEVsLiQucHJpdmFjeVZpZXcuaGlkZGVuID0gZmFsc2U7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLmFja1ByaXZhY3lUZXJtcyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdGhpcy5yb290RWwuJC5zZXJ2ZXJzVmlldy5oaWRkZW4gPSBmYWxzZTtcbiAgICAgICAgdGhpcy5yb290RWwuJC5wcml2YWN5Vmlldy5oaWRkZW4gPSB0cnVlO1xuICAgICAgICB0aGlzLnNldHRpbmdzLnNldChzZXR0aW5nc18xLlNldHRpbmdzS2V5LlBSSVZBQ1lfQUNLLCAndHJ1ZScpO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5oYW5kbGVDbGlwYm9hcmRUZXh0ID0gZnVuY3Rpb24gKHRleHQpIHtcbiAgICAgICAgLy8gU2hvcnRlbiwgc2FuaXRpc2UuXG4gICAgICAgIC8vIE5vdGUgdGhhdCB3ZSBhbHdheXMgY2hlY2sgdGhlIHRleHQsIGV2ZW4gaWYgdGhlIGNvbnRlbnRzIGFyZSBzYW1lIGFzIGxhc3QgdGltZSwgYmVjYXVzZSB3ZVxuICAgICAgICAvLyBrZWVwIGFuIGluLW1lbW9yeSBjYWNoZSBvZiB1c2VyLWlnbm9yZWQgYWNjZXNzIGtleXMuXG4gICAgICAgIHRleHQgPSB0ZXh0LnN1YnN0cmluZygwLCAxMDAwKS50cmltKCk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB0aGlzLmNvbmZpcm1BZGRTZXJ2ZXIodGV4dCwgdHJ1ZSk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGVycikge1xuICAgICAgICAgICAgLy8gRG9uJ3QgYWxlcnQgdGhlIHVzZXI7IGhpZ2ggZmFsc2UgcG9zaXRpdmUgcmF0ZS5cbiAgICAgICAgfVxuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS51cGRhdGVEb3dubG9hZGVkID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB0aGlzLnJvb3RFbC5zaG93VG9hc3QodGhpcy5sb2NhbGl6ZSgndXBkYXRlLWRvd25sb2FkZWQnKSwgNjAwMDApO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5yZXF1ZXN0UHJvbXB0QWRkU2VydmVyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB0aGlzLnJvb3RFbC5wcm9tcHRBZGRTZXJ2ZXIoKTtcbiAgICB9O1xuICAgIC8vIENhY2hlcyBhbiBpZ25vcmVkIHNlcnZlciBhY2Nlc3Mga2V5IHNvIHdlIGRvbid0IHByb21wdCB0aGUgdXNlciB0byBhZGQgaXQgYWdhaW4uXG4gICAgQXBwLnByb3RvdHlwZS5yZXF1ZXN0SWdub3JlU2VydmVyID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIHZhciBhY2Nlc3NLZXkgPSBldmVudC5kZXRhaWwuYWNjZXNzS2V5O1xuICAgICAgICB0aGlzLmlnbm9yZWRBY2Nlc3NLZXlzW2FjY2Vzc0tleV0gPSB0cnVlO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5yZXF1ZXN0QWRkU2VydmVyID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB0aGlzLnNlcnZlclJlcG8uYWRkKGV2ZW50LmRldGFpbC5zZXJ2ZXJDb25maWcpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlcnIpIHtcbiAgICAgICAgICAgIHRoaXMuY2hhbmdlVG9EZWZhdWx0UGFnZSgpO1xuICAgICAgICAgICAgdGhpcy5zaG93TG9jYWxpemVkRXJyb3IoZXJyKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5yZXF1ZXN0QWRkU2VydmVyQ29uZmlybWF0aW9uID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIHZhciBhY2Nlc3NLZXkgPSBldmVudC5kZXRhaWwuYWNjZXNzS2V5O1xuICAgICAgICBjb25zb2xlLmRlYnVnKCdHb3QgYWRkIHNlcnZlciBjb25maXJtYXRpb24gcmVxdWVzdCBmcm9tIFVJJyk7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB0aGlzLmNvbmZpcm1BZGRTZXJ2ZXIoYWNjZXNzS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdGYWlsZWQgdG8gY29uZmlybSBhZGQgc2V2ZXIuJywgZXJyKTtcbiAgICAgICAgICAgIHZhciBhZGRTZXJ2ZXJWaWV3ID0gdGhpcy5yb290RWwuJC5hZGRTZXJ2ZXJWaWV3O1xuICAgICAgICAgICAgYWRkU2VydmVyVmlldy4kLmFjY2Vzc0tleUlucHV0LmludmFsaWQgPSB0cnVlO1xuICAgICAgICB9XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLmNvbmZpcm1BZGRTZXJ2ZXIgPSBmdW5jdGlvbiAoYWNjZXNzS2V5LCBmcm9tQ2xpcGJvYXJkKSB7XG4gICAgICAgIGlmIChmcm9tQ2xpcGJvYXJkID09PSB2b2lkIDApIHsgZnJvbUNsaXBib2FyZCA9IGZhbHNlOyB9XG4gICAgICAgIHZhciBhZGRTZXJ2ZXJWaWV3ID0gdGhpcy5yb290RWwuJC5hZGRTZXJ2ZXJWaWV3O1xuICAgICAgICBhY2Nlc3NLZXkgPSB1bndyYXBJbnZpdGUoYWNjZXNzS2V5KTtcbiAgICAgICAgaWYgKGZyb21DbGlwYm9hcmQgJiYgYWNjZXNzS2V5IGluIHRoaXMuaWdub3JlZEFjY2Vzc0tleXMpIHtcbiAgICAgICAgICAgIHJldHVybiBjb25zb2xlLmRlYnVnKCdJZ25vcmluZyBhY2Nlc3Mga2V5Jyk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAoZnJvbUNsaXBib2FyZCAmJiBhZGRTZXJ2ZXJWaWV3LmlzQWRkaW5nU2VydmVyKCkpIHtcbiAgICAgICAgICAgIHJldHVybiBjb25zb2xlLmRlYnVnKCdBbHJlYWR5IGFkZGluZyBhIHNlcnZlcicpO1xuICAgICAgICB9XG4gICAgICAgIC8vIEV4cGVjdCBTSEFET1dTT0NLU19VUkkucGFyc2UgdG8gdGhyb3cgb24gaW52YWxpZCBhY2Nlc3Mga2V5OyBwcm9wYWdhdGUgYW55IGV4Y2VwdGlvbi5cbiAgICAgICAgdmFyIHNoYWRvd3NvY2tzQ29uZmlnID0gbnVsbDtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHNoYWRvd3NvY2tzQ29uZmlnID0gc2hhZG93c29ja3NfY29uZmlnXzEuU0hBRE9XU09DS1NfVVJJLnBhcnNlKGFjY2Vzc0tleSk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICB2YXIgbWVzc2FnZSA9ICEhZXJyb3IubWVzc2FnZSA/IGVycm9yLm1lc3NhZ2UgOiAnRmFpbGVkIHRvIHBhcnNlIGFjY2VzcyBrZXknO1xuICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9ycy5TZXJ2ZXJVcmxJbnZhbGlkKG1lc3NhZ2UpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChzaGFkb3dzb2Nrc0NvbmZpZy5ob3N0LmlzSVB2Nikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IGVycm9ycy5TZXJ2ZXJJbmNvbXBhdGlibGUoJ09ubHkgSVB2NCBhZGRyZXNzZXMgYXJlIGN1cnJlbnRseSBzdXBwb3J0ZWQnKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgbmFtZSA9IHNoYWRvd3NvY2tzQ29uZmlnLmV4dHJhLm91dGxpbmUgP1xuICAgICAgICAgICAgdGhpcy5sb2NhbGl6ZSgnc2VydmVyLWRlZmF1bHQtbmFtZS1vdXRsaW5lJykgOlxuICAgICAgICAgICAgc2hhZG93c29ja3NDb25maWcudGFnLmRhdGEgPyBzaGFkb3dzb2Nrc0NvbmZpZy50YWcuZGF0YSA6XG4gICAgICAgICAgICAgICAgdGhpcy5sb2NhbGl6ZSgnc2VydmVyLWRlZmF1bHQtbmFtZScpO1xuICAgICAgICB2YXIgc2VydmVyQ29uZmlnID0ge1xuICAgICAgICAgICAgaG9zdDogc2hhZG93c29ja3NDb25maWcuaG9zdC5kYXRhLFxuICAgICAgICAgICAgcG9ydDogc2hhZG93c29ja3NDb25maWcucG9ydC5kYXRhLFxuICAgICAgICAgICAgbWV0aG9kOiBzaGFkb3dzb2Nrc0NvbmZpZy5tZXRob2QuZGF0YSxcbiAgICAgICAgICAgIHBhc3N3b3JkOiBzaGFkb3dzb2Nrc0NvbmZpZy5wYXNzd29yZC5kYXRhLFxuICAgICAgICAgICAgbmFtZTogbmFtZSxcbiAgICAgICAgfTtcbiAgICAgICAgaWYgKCF0aGlzLnNlcnZlclJlcG8uY29udGFpbnNTZXJ2ZXIoc2VydmVyQ29uZmlnKSkge1xuICAgICAgICAgICAgLy8gT25seSBwcm9tcHQgdGhlIHVzZXIgdG8gYWRkIG5ldyBzZXJ2ZXJzLlxuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBhZGRTZXJ2ZXJWaWV3Lm9wZW5BZGRTZXJ2ZXJDb25maXJtYXRpb25TaGVldChhY2Nlc3NLZXksIHNlcnZlckNvbmZpZyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcignRmFpbGVkIHRvIG9wZW4gYWRkIHNldmVyIGNvbmZpcm1hdGlvbiBzaGVldDonLCBlcnIubWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgaWYgKCFmcm9tQ2xpcGJvYXJkKVxuICAgICAgICAgICAgICAgICAgICB0aGlzLnNob3dMb2NhbGl6ZWRFcnJvcigpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKCFmcm9tQ2xpcGJvYXJkKSB7XG4gICAgICAgICAgICAvLyBEaXNwbGF5IGVycm9yIG1lc3NhZ2UgaWYgdGhpcyBpcyBub3QgYSBjbGlwYm9hcmQgYWRkLlxuICAgICAgICAgICAgYWRkU2VydmVyVmlldy5jbG9zZSgpO1xuICAgICAgICAgICAgdGhpcy5zaG93TG9jYWxpemVkRXJyb3IobmV3IGVycm9ycy5TZXJ2ZXJBbHJlYWR5QWRkZWQodGhpcy5zZXJ2ZXJSZXBvLmNyZWF0ZVNlcnZlcignJywgc2VydmVyQ29uZmlnLCB0aGlzLmV2ZW50UXVldWUpKSk7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuZm9yZ2V0U2VydmVyID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHZhciBzZXJ2ZXJJZCA9IGV2ZW50LmRldGFpbC5zZXJ2ZXJJZDtcbiAgICAgICAgdmFyIHNlcnZlciA9IHRoaXMuc2VydmVyUmVwby5nZXRCeUlkKHNlcnZlcklkKTtcbiAgICAgICAgaWYgKCFzZXJ2ZXIpIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJObyBzZXJ2ZXIgd2l0aCBpZCBcIiArIHNlcnZlcklkKTtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnNob3dMb2NhbGl6ZWRFcnJvcigpO1xuICAgICAgICB9XG4gICAgICAgIHZhciBvbmNlTm90UnVubmluZyA9IHNlcnZlci5jaGVja1J1bm5pbmcoKS50aGVuKGZ1bmN0aW9uIChpc1J1bm5pbmcpIHtcbiAgICAgICAgICAgIHJldHVybiBpc1J1bm5pbmcgPyBfdGhpcy5kaXNjb25uZWN0U2VydmVyKGV2ZW50KSA6IFByb21pc2UucmVzb2x2ZSgpO1xuICAgICAgICB9KTtcbiAgICAgICAgb25jZU5vdFJ1bm5pbmcudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBfdGhpcy5zZXJ2ZXJSZXBvLmZvcmdldChzZXJ2ZXJJZCk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5yZW5hbWVTZXJ2ZXIgPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgdmFyIHNlcnZlcklkID0gZXZlbnQuZGV0YWlsLnNlcnZlcklkO1xuICAgICAgICB2YXIgbmV3TmFtZSA9IGV2ZW50LmRldGFpbC5uZXdOYW1lO1xuICAgICAgICB0aGlzLnNlcnZlclJlcG8ucmVuYW1lKHNlcnZlcklkLCBuZXdOYW1lKTtcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuY29ubmVjdFNlcnZlciA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICB2YXIgc2VydmVySWQgPSBldmVudC5kZXRhaWwuc2VydmVySWQ7XG4gICAgICAgIGlmICghc2VydmVySWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcImNvbm5lY3RTZXJ2ZXIgZXZlbnQgaGFkIG5vIHNlcnZlciBJRFwiKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgc2VydmVyID0gdGhpcy5nZXRTZXJ2ZXJCeVNlcnZlcklkKHNlcnZlcklkKTtcbiAgICAgICAgdmFyIGNhcmQgPSB0aGlzLmdldENhcmRCeVNlcnZlcklkKHNlcnZlcklkKTtcbiAgICAgICAgY29uc29sZS5sb2coXCJjb25uZWN0aW5nIHRvIHNlcnZlciBcIiArIHNlcnZlcklkKTtcbiAgICAgICAgY2FyZC5zdGF0ZSA9ICdDT05ORUNUSU5HJztcbiAgICAgICAgc2VydmVyLmNvbm5lY3QoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGNhcmQuc3RhdGUgPSAnQ09OTkVDVEVEJztcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiY29ubmVjdGVkIHRvIHNlcnZlciBcIiArIHNlcnZlcklkKTtcbiAgICAgICAgICAgIF90aGlzLnJvb3RFbC5zaG93VG9hc3QoX3RoaXMubG9jYWxpemUoJ3NlcnZlci1jb25uZWN0ZWQnLCAnc2VydmVyTmFtZScsIHNlcnZlci5uYW1lKSk7XG4gICAgICAgICAgICBfdGhpcy5tYXliZVNob3dBdXRvQ29ubmVjdERpYWxvZygpO1xuICAgICAgICB9LCBmdW5jdGlvbiAoZSkge1xuICAgICAgICAgICAgY2FyZC5zdGF0ZSA9ICdESVNDT05ORUNURUQnO1xuICAgICAgICAgICAgX3RoaXMuc2hvd0xvY2FsaXplZEVycm9yKGUpO1xuICAgICAgICAgICAgY29uc29sZS5lcnJvcihcImNvdWxkIG5vdCBjb25uZWN0IHRvIHNlcnZlciBcIiArIHNlcnZlcklkICsgXCI6IFwiICsgZS5uYW1lKTtcbiAgICAgICAgICAgIGlmICghKGUgaW5zdGFuY2VvZiBlcnJvcnMuUmVndWxhck5hdGl2ZUVycm9yKSkge1xuICAgICAgICAgICAgICAgIF90aGlzLmVycm9yUmVwb3J0ZXIucmVwb3J0KFwiY29ubmVjdGlvbiBmYWlsdXJlOiBcIiArIGUubmFtZSwgJ2Nvbm5lY3Rpb24tZmFpbHVyZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUubWF5YmVTaG93QXV0b0Nvbm5lY3REaWFsb2cgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHZhciBkaXNtaXNzZWQgPSBmYWxzZTtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGRpc21pc3NlZCA9IHRoaXMuc2V0dGluZ3MuZ2V0KHNldHRpbmdzXzEuU2V0dGluZ3NLZXkuQVVUT19DT05ORUNUX0RJQUxPR19ESVNNSVNTRUQpID09PSAndHJ1ZSc7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoXCJGYWlsZWQgdG8gcmVhZCBhdXRvLWNvbm5lY3QgZGlhbG9nIHN0YXR1cywgYXNzdW1pbmcgbm90IGRpc21pc3NlZDogXCIgKyBlKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIWRpc21pc3NlZCkge1xuICAgICAgICAgICAgdGhpcy5yb290RWwuJC5zZXJ2ZXJzVmlldy4kLmF1dG9Db25uZWN0RGlhbG9nLnNob3coKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5hdXRvQ29ubmVjdERpYWxvZ0Rpc21pc3NlZCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdGhpcy5zZXR0aW5ncy5zZXQoc2V0dGluZ3NfMS5TZXR0aW5nc0tleS5BVVRPX0NPTk5FQ1RfRElBTE9HX0RJU01JU1NFRCwgJ3RydWUnKTtcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuZGlzY29ubmVjdFNlcnZlciA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICB2YXIgc2VydmVySWQgPSBldmVudC5kZXRhaWwuc2VydmVySWQ7XG4gICAgICAgIGlmICghc2VydmVySWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcImRpc2Nvbm5lY3RTZXJ2ZXIgZXZlbnQgaGFkIG5vIHNlcnZlciBJRFwiKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgc2VydmVyID0gdGhpcy5nZXRTZXJ2ZXJCeVNlcnZlcklkKHNlcnZlcklkKTtcbiAgICAgICAgdmFyIGNhcmQgPSB0aGlzLmdldENhcmRCeVNlcnZlcklkKHNlcnZlcklkKTtcbiAgICAgICAgY29uc29sZS5sb2coXCJkaXNjb25uZWN0aW5nIGZyb20gc2VydmVyIFwiICsgc2VydmVySWQpO1xuICAgICAgICBjYXJkLnN0YXRlID0gJ0RJU0NPTk5FQ1RJTkcnO1xuICAgICAgICBzZXJ2ZXIuZGlzY29ubmVjdCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgY2FyZC5zdGF0ZSA9ICdESVNDT05ORUNURUQnO1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCJkaXNjb25uZWN0ZWQgZnJvbSBzZXJ2ZXIgXCIgKyBzZXJ2ZXJJZCk7XG4gICAgICAgICAgICBfdGhpcy5yb290RWwuc2hvd1RvYXN0KF90aGlzLmxvY2FsaXplKCdzZXJ2ZXItZGlzY29ubmVjdGVkJywgJ3NlcnZlck5hbWUnLCBzZXJ2ZXIubmFtZSkpO1xuICAgICAgICB9LCBmdW5jdGlvbiAoZSkge1xuICAgICAgICAgICAgY2FyZC5zdGF0ZSA9ICdDT05ORUNURUQnO1xuICAgICAgICAgICAgX3RoaXMuc2hvd0xvY2FsaXplZEVycm9yKGUpO1xuICAgICAgICAgICAgY29uc29sZS53YXJuKFwiY291bGQgbm90IGRpc2Nvbm5lY3QgZnJvbSBzZXJ2ZXIgXCIgKyBzZXJ2ZXJJZCArIFwiOiBcIiArIGUubmFtZSk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5zdWJtaXRGZWVkYmFjayA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICB2YXIgZm9ybURhdGEgPSB0aGlzLmZlZWRiYWNrVmlld0VsLmdldFZhbGlkYXRlZEZvcm1EYXRhKCk7XG4gICAgICAgIGlmICghZm9ybURhdGEpIHtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICB2YXIgZmVlZGJhY2sgPSBmb3JtRGF0YS5mZWVkYmFjaywgY2F0ZWdvcnkgPSBmb3JtRGF0YS5jYXRlZ29yeSwgZW1haWwgPSBmb3JtRGF0YS5lbWFpbDtcbiAgICAgICAgdGhpcy5yb290RWwuJC5mZWVkYmFja1ZpZXcuc3VibWl0dGluZyA9IHRydWU7XG4gICAgICAgIHRoaXMuZXJyb3JSZXBvcnRlci5yZXBvcnQoZmVlZGJhY2ssIGNhdGVnb3J5LCBlbWFpbClcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIF90aGlzLnJvb3RFbC4kLmZlZWRiYWNrVmlldy5zdWJtaXR0aW5nID0gZmFsc2U7XG4gICAgICAgICAgICBfdGhpcy5yb290RWwuJC5mZWVkYmFja1ZpZXcucmVzZXRGb3JtKCk7XG4gICAgICAgICAgICBfdGhpcy5jaGFuZ2VUb0RlZmF1bHRQYWdlKCk7XG4gICAgICAgICAgICBfdGhpcy5yb290RWwuc2hvd1RvYXN0KF90aGlzLnJvb3RFbC5sb2NhbGl6ZSgnZmVlZGJhY2stdGhhbmtzJykpO1xuICAgICAgICB9LCBmdW5jdGlvbiAoZXJyKSB7XG4gICAgICAgICAgICBfdGhpcy5yb290RWwuJC5mZWVkYmFja1ZpZXcuc3VibWl0dGluZyA9IGZhbHNlO1xuICAgICAgICAgICAgX3RoaXMuc2hvd0xvY2FsaXplZEVycm9yKG5ldyBlcnJvcnMuRmVlZGJhY2tTdWJtaXNzaW9uRXJyb3IoKSk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgLy8gRXZlbnRRdWV1ZSBldmVudCBoYW5kbGVyczpcbiAgICBBcHAucHJvdG90eXBlLnNob3dTZXJ2ZXJBZGRlZCA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICB2YXIgc2VydmVyID0gZXZlbnQuc2VydmVyO1xuICAgICAgICBjb25zb2xlLmRlYnVnKCdTZXJ2ZXIgYWRkZWQnKTtcbiAgICAgICAgdGhpcy5zeW5jU2VydmVyc1RvVUkoKTtcbiAgICAgICAgdGhpcy5zeW5jU2VydmVyQ29ubmVjdGl2aXR5U3RhdGUoc2VydmVyKTtcbiAgICAgICAgdGhpcy5jaGFuZ2VUb0RlZmF1bHRQYWdlKCk7XG4gICAgICAgIHRoaXMucm9vdEVsLnNob3dUb2FzdCh0aGlzLmxvY2FsaXplKCdzZXJ2ZXItYWRkZWQnLCAnc2VydmVyTmFtZScsIHNlcnZlci5uYW1lKSk7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnNob3dTZXJ2ZXJGb3Jnb3R0ZW4gPSBmdW5jdGlvbiAoZXZlbnQpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgdmFyIHNlcnZlciA9IGV2ZW50LnNlcnZlcjtcbiAgICAgICAgY29uc29sZS5kZWJ1ZygnU2VydmVyIGZvcmdvdHRlbicpO1xuICAgICAgICB0aGlzLnN5bmNTZXJ2ZXJzVG9VSSgpO1xuICAgICAgICB0aGlzLnJvb3RFbC5zaG93VG9hc3QodGhpcy5sb2NhbGl6ZSgnc2VydmVyLWZvcmdvdHRlbicsICdzZXJ2ZXJOYW1lJywgc2VydmVyLm5hbWUpLCAxMDAwMCwgdGhpcy5sb2NhbGl6ZSgndW5kby1idXR0b24tbGFiZWwnKSwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgX3RoaXMuc2VydmVyUmVwby51bmRvRm9yZ2V0KHNlcnZlci5pZCk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5zaG93U2VydmVyRm9yZ2V0VW5kb25lID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIHRoaXMuc3luY1NlcnZlcnNUb1VJKCk7XG4gICAgICAgIHZhciBzZXJ2ZXIgPSBldmVudC5zZXJ2ZXI7XG4gICAgICAgIHRoaXMucm9vdEVsLnNob3dUb2FzdCh0aGlzLmxvY2FsaXplKCdzZXJ2ZXItZm9yZ290dGVuLXVuZG8nLCAnc2VydmVyTmFtZScsIHNlcnZlci5uYW1lKSk7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnNob3dTZXJ2ZXJSZW5hbWVkID0gZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgIHZhciBzZXJ2ZXIgPSBldmVudC5zZXJ2ZXI7XG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ1NlcnZlciByZW5hbWVkJyk7XG4gICAgICAgIHRoaXMuc2VydmVyTGlzdEVsLmdldFNlcnZlckNhcmQoc2VydmVyLmlkKS5zZXJ2ZXJOYW1lID0gc2VydmVyLm5hbWU7XG4gICAgICAgIHRoaXMucm9vdEVsLnNob3dUb2FzdCh0aGlzLmxvY2FsaXplKCdzZXJ2ZXItcmVuYW1lLWNvbXBsZXRlJykpO1xuICAgIH07XG4gICAgLy8gSGVscGVyczpcbiAgICBBcHAucHJvdG90eXBlLnN5bmNTZXJ2ZXJzVG9VSSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdGhpcy5yb290RWwuc2VydmVycyA9IHRoaXMuc2VydmVyUmVwby5nZXRBbGwoKTtcbiAgICB9O1xuICAgIEFwcC5wcm90b3R5cGUuc3luY0Nvbm5lY3Rpdml0eVN0YXRlVG9TZXJ2ZXJDYXJkcyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdmFyIGVfMSwgX2E7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBmb3IgKHZhciBfYiA9IF9fdmFsdWVzKHRoaXMuc2VydmVyUmVwby5nZXRBbGwoKSksIF9jID0gX2IubmV4dCgpOyAhX2MuZG9uZTsgX2MgPSBfYi5uZXh0KCkpIHtcbiAgICAgICAgICAgICAgICB2YXIgc2VydmVyID0gX2MudmFsdWU7XG4gICAgICAgICAgICAgICAgdGhpcy5zeW5jU2VydmVyQ29ubmVjdGl2aXR5U3RhdGUoc2VydmVyKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZV8xXzEpIHsgZV8xID0geyBlcnJvcjogZV8xXzEgfTsgfVxuICAgICAgICBmaW5hbGx5IHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgaWYgKF9jICYmICFfYy5kb25lICYmIChfYSA9IF9iLnJldHVybikpIF9hLmNhbGwoX2IpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZmluYWxseSB7IGlmIChlXzEpIHRocm93IGVfMS5lcnJvcjsgfVxuICAgICAgICB9XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnN5bmNTZXJ2ZXJDb25uZWN0aXZpdHlTdGF0ZSA9IGZ1bmN0aW9uIChzZXJ2ZXIpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgc2VydmVyLmNoZWNrUnVubmluZygpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbiAoaXNSdW5uaW5nKSB7XG4gICAgICAgICAgICB2YXIgY2FyZCA9IF90aGlzLnNlcnZlckxpc3RFbC5nZXRTZXJ2ZXJDYXJkKHNlcnZlci5pZCk7XG4gICAgICAgICAgICBpZiAoIWlzUnVubmluZykge1xuICAgICAgICAgICAgICAgIGNhcmQuc3RhdGUgPSAnRElTQ09OTkVDVEVEJztcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBzZXJ2ZXIuY2hlY2tSZWFjaGFibGUoKS50aGVuKGZ1bmN0aW9uIChpc1JlYWNoYWJsZSkge1xuICAgICAgICAgICAgICAgIGlmIChpc1JlYWNoYWJsZSkge1xuICAgICAgICAgICAgICAgICAgICBjYXJkLnN0YXRlID0gJ0NPTk5FQ1RFRCc7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZyhcIlNlcnZlciBcIiArIHNlcnZlci5pZCArIFwiIHJlY29ubmVjdGluZ1wiKTtcbiAgICAgICAgICAgICAgICAgICAgY2FyZC5zdGF0ZSA9ICdSRUNPTk5FQ1RJTkcnO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KVxuICAgICAgICAgICAgLmNhdGNoKGZ1bmN0aW9uIChlKSB7XG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdGYWlsZWQgdG8gc3luYyBzZXJ2ZXIgY29ubmVjdGl2aXR5IHN0YXRlJywgZSk7XG4gICAgICAgIH0pO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5yZWdpc3RlclVybEludGVyY2VwdGlvbkxpc3RlbmVyID0gZnVuY3Rpb24gKHVybEludGVyY2VwdG9yKSB7XG4gICAgICAgIHZhciBfdGhpcyA9IHRoaXM7XG4gICAgICAgIHVybEludGVyY2VwdG9yLnJlZ2lzdGVyTGlzdGVuZXIoZnVuY3Rpb24gKHVybCkge1xuICAgICAgICAgICAgaWYgKCF1cmwgfHwgIXVud3JhcEludml0ZSh1cmwpLnN0YXJ0c1dpdGgoJ3NzOi8vJykpIHtcbiAgICAgICAgICAgICAgICAvLyBUaGlzIGNoZWNrIGlzIG5lY2Vzc2FyeSB0byBpZ25vcmUgZW1wdHkgYW5kIG1hbGZvcm1lZCBpbnN0YWxsLXJlZmVycmVyIFVSTHMgaW4gQW5kcm9pZFxuICAgICAgICAgICAgICAgIC8vIHdoaWxlIGFsbG93aW5nIHNzOi8vIGFuZCBpbnZpdGUgVVJMcy5cbiAgICAgICAgICAgICAgICAvLyBUT0RPOiBTdG9wIHJlY2VpdmluZyBpbnN0YWxsIHJlZmVycmVyIGludGVudHMgc28gd2UgY2FuIHJlbW92ZSB0aGlzLlxuICAgICAgICAgICAgICAgIHJldHVybiBjb25zb2xlLmRlYnVnKFwiSWdub3JpbmcgaW50ZXJjZXB0ZWQgbm9uLXNoYWRvd3NvY2tzIHVybFwiKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgX3RoaXMuY29uZmlybUFkZFNlcnZlcih1cmwpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2F0Y2ggKGVycikge1xuICAgICAgICAgICAgICAgIF90aGlzLnNob3dMb2NhbGl6ZWRFcnJvckluRGVmYXVsdFBhZ2UoZXJyKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLmNoYW5nZVRvRGVmYXVsdFBhZ2UgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRoaXMucm9vdEVsLmNoYW5nZVBhZ2UodGhpcy5yb290RWwuREVGQVVMVF9QQUdFKTtcbiAgICB9O1xuICAgIC8vIFJldHVybnMgdGhlIHNlcnZlciBoYXZpbmcgc2VydmVySWQsIHRocm93cyBpZiB0aGUgc2VydmVyIGNhbm5vdCBiZSBmb3VuZC5cbiAgICBBcHAucHJvdG90eXBlLmdldFNlcnZlckJ5U2VydmVySWQgPSBmdW5jdGlvbiAoc2VydmVySWQpIHtcbiAgICAgICAgdmFyIHNlcnZlciA9IHRoaXMuc2VydmVyUmVwby5nZXRCeUlkKHNlcnZlcklkKTtcbiAgICAgICAgaWYgKCFzZXJ2ZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcImNvdWxkIG5vdCBmaW5kIHNlcnZlciB3aXRoIElEIFwiICsgc2VydmVySWQpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBzZXJ2ZXI7XG4gICAgfTtcbiAgICAvLyBSZXR1cm5zIHRoZSBjYXJkIGFzc29jaWF0ZWQgd2l0aCBzZXJ2ZXJJZCwgdGhyb3dzIGlmIG5vIHN1Y2ggY2FyZCBleGlzdHMuXG4gICAgLy8gU2VlIHNlcnZlci1saXN0Lmh0bWwuXG4gICAgQXBwLnByb3RvdHlwZS5nZXRDYXJkQnlTZXJ2ZXJJZCA9IGZ1bmN0aW9uIChzZXJ2ZXJJZCkge1xuICAgICAgICByZXR1cm4gdGhpcy5zZXJ2ZXJMaXN0RWwuZ2V0U2VydmVyQ2FyZChzZXJ2ZXJJZCk7XG4gICAgfTtcbiAgICBBcHAucHJvdG90eXBlLnNob3dMb2NhbGl6ZWRFcnJvckluRGVmYXVsdFBhZ2UgPSBmdW5jdGlvbiAoZXJyKSB7XG4gICAgICAgIHRoaXMuY2hhbmdlVG9EZWZhdWx0UGFnZSgpO1xuICAgICAgICB0aGlzLnNob3dMb2NhbGl6ZWRFcnJvcihlcnIpO1xuICAgIH07XG4gICAgQXBwLnByb3RvdHlwZS5pc1dpbmRvd3MgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiAhKCdjb3Jkb3ZhJyBpbiB3aW5kb3cpO1xuICAgIH07XG4gICAgcmV0dXJuIEFwcDtcbn0oKSk7XG5leHBvcnRzLkFwcCA9IEFwcDtcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG4vLyBHZW5lcmljIGNsaXBib2FyZC4gSW1wbGVtZW50YXRpb25zIHNob3VsZCBvbmx5IGhhdmUgdG8gaW1wbGVtZW50IGdldENvbnRlbnRzKCkuXG52YXIgQWJzdHJhY3RDbGlwYm9hcmQgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gQWJzdHJhY3RDbGlwYm9hcmQoKSB7XG4gICAgICAgIHRoaXMubGlzdGVuZXIgPSBudWxsO1xuICAgIH1cbiAgICBBYnN0cmFjdENsaXBib2FyZC5wcm90b3R5cGUuZ2V0Q29udGVudHMgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgRXJyb3IoJ3VuaW1wbGVtZW50ZWQgc2tlbGV0b24gbWV0aG9kJykpO1xuICAgIH07XG4gICAgQWJzdHJhY3RDbGlwYm9hcmQucHJvdG90eXBlLnNldExpc3RlbmVyID0gZnVuY3Rpb24gKGxpc3RlbmVyKSB7XG4gICAgICAgIHRoaXMubGlzdGVuZXIgPSBsaXN0ZW5lcjtcbiAgICB9O1xuICAgIEFic3RyYWN0Q2xpcGJvYXJkLnByb3RvdHlwZS5lbWl0RXZlbnQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmICh0aGlzLmxpc3RlbmVyKSB7XG4gICAgICAgICAgICB0aGlzLmdldENvbnRlbnRzKCkudGhlbih0aGlzLmxpc3RlbmVyKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgcmV0dXJuIEFic3RyYWN0Q2xpcGJvYXJkO1xufSgpKTtcbmV4cG9ydHMuQWJzdHJhY3RDbGlwYm9hcmQgPSBBYnN0cmFjdENsaXBib2FyZDtcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG52YXIgX19leHRlbmRzID0gKHRoaXMgJiYgdGhpcy5fX2V4dGVuZHMpIHx8IChmdW5jdGlvbiAoKSB7XG4gICAgdmFyIGV4dGVuZFN0YXRpY3MgPSBmdW5jdGlvbiAoZCwgYikge1xuICAgICAgICBleHRlbmRTdGF0aWNzID0gT2JqZWN0LnNldFByb3RvdHlwZU9mIHx8XG4gICAgICAgICAgICAoeyBfX3Byb3RvX186IFtdIH0gaW5zdGFuY2VvZiBBcnJheSAmJiBmdW5jdGlvbiAoZCwgYikgeyBkLl9fcHJvdG9fXyA9IGI7IH0pIHx8XG4gICAgICAgICAgICBmdW5jdGlvbiAoZCwgYikgeyBmb3IgKHZhciBwIGluIGIpIGlmIChiLmhhc093blByb3BlcnR5KHApKSBkW3BdID0gYltwXTsgfTtcbiAgICAgICAgcmV0dXJuIGV4dGVuZFN0YXRpY3MoZCwgYik7XG4gICAgfTtcbiAgICByZXR1cm4gZnVuY3Rpb24gKGQsIGIpIHtcbiAgICAgICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcbiAgICAgICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XG4gICAgICAgIGQucHJvdG90eXBlID0gYiA9PT0gbnVsbCA/IE9iamVjdC5jcmVhdGUoYikgOiAoX18ucHJvdG90eXBlID0gYi5wcm90b3R5cGUsIG5ldyBfXygpKTtcbiAgICB9O1xufSkoKTtcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbi8vLyA8cmVmZXJlbmNlIHBhdGg9Jy4uLy4uL3R5cGVzL2FtYmllbnQvb3V0bGluZVBsdWdpbi5kLnRzJy8+XG4vLy8gPHJlZmVyZW5jZSBwYXRoPScuLi8uLi90eXBlcy9hbWJpZW50L3dlYmludGVudHMuZC50cycvPlxudmFyIFJhdmVuID0gcmVxdWlyZShcInJhdmVuLWpzXCIpO1xudmFyIGNsaXBib2FyZF8xID0gcmVxdWlyZShcIi4vY2xpcGJvYXJkXCIpO1xudmFyIGVycm9yX3JlcG9ydGVyXzEgPSByZXF1aXJlKFwiLi9lcnJvcl9yZXBvcnRlclwiKTtcbnZhciBmYWtlX2Nvbm5lY3Rpb25fMSA9IHJlcXVpcmUoXCIuL2Zha2VfY29ubmVjdGlvblwiKTtcbnZhciBtYWluXzEgPSByZXF1aXJlKFwiLi9tYWluXCIpO1xudmFyIG91dGxpbmVfc2VydmVyXzEgPSByZXF1aXJlKFwiLi9vdXRsaW5lX3NlcnZlclwiKTtcbnZhciB1cGRhdGVyXzEgPSByZXF1aXJlKFwiLi91cGRhdGVyXCIpO1xudmFyIGludGVyY2VwdG9ycyA9IHJlcXVpcmUoXCIuL3VybF9pbnRlcmNlcHRvclwiKTtcbi8vIFB1c2hlcyBhIGNsaXBib2FyZCBldmVudCB3aGVuZXZlciB0aGUgYXBwIGlzIGJyb3VnaHQgdG8gdGhlIGZvcmVncm91bmQuXG52YXIgQ29yZG92YUNsaXBib2FyZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoQ29yZG92YUNsaXBib2FyZCwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBDb3Jkb3ZhQ2xpcGJvYXJkKCkge1xuICAgICAgICB2YXIgX3RoaXMgPSBfc3VwZXIuY2FsbCh0aGlzKSB8fCB0aGlzO1xuICAgICAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdyZXN1bWUnLCBfdGhpcy5lbWl0RXZlbnQuYmluZChfdGhpcykpO1xuICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgfVxuICAgIENvcmRvdmFDbGlwYm9hcmQucHJvdG90eXBlLmdldENvbnRlbnRzID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgICAgICAgICAgY29yZG92YS5wbHVnaW5zLmNsaXBib2FyZC5wYXN0ZShyZXNvbHZlLCByZWplY3QpO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIHJldHVybiBDb3Jkb3ZhQ2xpcGJvYXJkO1xufShjbGlwYm9hcmRfMS5BYnN0cmFjdENsaXBib2FyZCkpO1xuLy8gQWRkcyByZXBvcnRzIGZyb20gdGhlIChuYXRpdmUpIENvcmRvdmEgcGx1Z2luLlxudmFyIENvcmRvdmFFcnJvclJlcG9ydGVyID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhDb3Jkb3ZhRXJyb3JSZXBvcnRlciwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBDb3Jkb3ZhRXJyb3JSZXBvcnRlcihhcHBWZXJzaW9uLCBhcHBCdWlsZE51bWJlciwgZHNuLCBuYXRpdmVEc24pIHtcbiAgICAgICAgdmFyIF90aGlzID0gX3N1cGVyLmNhbGwodGhpcywgYXBwVmVyc2lvbiwgZHNuLCB7ICdidWlsZC5udW1iZXInOiBhcHBCdWlsZE51bWJlciB9KSB8fCB0aGlzO1xuICAgICAgICBjb3Jkb3ZhLnBsdWdpbnMub3V0bGluZS5sb2cuaW5pdGlhbGl6ZShuYXRpdmVEc24pLmNhdGNoKGNvbnNvbGUuZXJyb3IpO1xuICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgfVxuICAgIENvcmRvdmFFcnJvclJlcG9ydGVyLnByb3RvdHlwZS5yZXBvcnQgPSBmdW5jdGlvbiAodXNlckZlZWRiYWNrLCBmZWVkYmFja0NhdGVnb3J5LCB1c2VyRW1haWwpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlci5wcm90b3R5cGUucmVwb3J0LmNhbGwodGhpcywgdXNlckZlZWRiYWNrLCBmZWVkYmFja0NhdGVnb3J5LCB1c2VyRW1haWwpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuIGNvcmRvdmEucGx1Z2lucy5vdXRsaW5lLmxvZy5zZW5kKFJhdmVuLmxhc3RFdmVudElkKCkpO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIHJldHVybiBDb3Jkb3ZhRXJyb3JSZXBvcnRlcjtcbn0oZXJyb3JfcmVwb3J0ZXJfMS5TZW50cnlFcnJvclJlcG9ydGVyKSk7XG5leHBvcnRzLkNvcmRvdmFFcnJvclJlcG9ydGVyID0gQ29yZG92YUVycm9yUmVwb3J0ZXI7XG4vLyBUaGlzIGNsYXNzIHNob3VsZCBvbmx5IGJlIGluc3RhbnRpYXRlZCBhZnRlciBDb3Jkb3ZhIGZpcmVzIHRoZSBkZXZpY2VyZWFkeSBldmVudC5cbnZhciBDb3Jkb3ZhUGxhdGZvcm0gPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gQ29yZG92YVBsYXRmb3JtKCkge1xuICAgIH1cbiAgICBDb3Jkb3ZhUGxhdGZvcm0uaXNCcm93c2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gZGV2aWNlLnBsYXRmb3JtID09PSAnYnJvd3Nlcic7XG4gICAgfTtcbiAgICBDb3Jkb3ZhUGxhdGZvcm0ucHJvdG90eXBlLmhhc0RldmljZVN1cHBvcnQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiAhQ29yZG92YVBsYXRmb3JtLmlzQnJvd3NlcigpO1xuICAgIH07XG4gICAgQ29yZG92YVBsYXRmb3JtLnByb3RvdHlwZS5nZXRQZXJzaXN0ZW50U2VydmVyRmFjdG9yeSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdmFyIF90aGlzID0gdGhpcztcbiAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIChzZXJ2ZXJJZCwgY29uZmlnLCBldmVudFF1ZXVlKSB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IG91dGxpbmVfc2VydmVyXzEuT3V0bGluZVNlcnZlcihzZXJ2ZXJJZCwgY29uZmlnLCBfdGhpcy5oYXNEZXZpY2VTdXBwb3J0KCkgPyBuZXcgY29yZG92YS5wbHVnaW5zLm91dGxpbmUuQ29ubmVjdGlvbihjb25maWcsIHNlcnZlcklkKSA6XG4gICAgICAgICAgICAgICAgbmV3IGZha2VfY29ubmVjdGlvbl8xLkZha2VPdXRsaW5lQ29ubmVjdGlvbihjb25maWcsIHNlcnZlcklkKSwgZXZlbnRRdWV1ZSk7XG4gICAgICAgIH07XG4gICAgfTtcbiAgICBDb3Jkb3ZhUGxhdGZvcm0ucHJvdG90eXBlLmdldFVybEludGVyY2VwdG9yID0gZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAoZGV2aWNlLnBsYXRmb3JtID09PSAnaU9TJyB8fCBkZXZpY2UucGxhdGZvcm0gPT09ICdNYWMgT1MgWCcpIHtcbiAgICAgICAgICAgIHJldHVybiBuZXcgaW50ZXJjZXB0b3JzLkFwcGxlVXJsSW50ZXJjZXB0b3IoYXBwbGVMYXVuY2hVcmwpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKGRldmljZS5wbGF0Zm9ybSA9PT0gJ0FuZHJvaWQnKSB7XG4gICAgICAgICAgICByZXR1cm4gbmV3IGludGVyY2VwdG9ycy5BbmRyb2lkVXJsSW50ZXJjZXB0b3IoKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zb2xlLndhcm4oJ25vIGludGVudCBpbnRlcmNlcHRvciBhdmFpbGFibGUnKTtcbiAgICAgICAgcmV0dXJuIG5ldyBpbnRlcmNlcHRvcnMuVXJsSW50ZXJjZXB0b3IoKTtcbiAgICB9O1xuICAgIENvcmRvdmFQbGF0Zm9ybS5wcm90b3R5cGUuZ2V0Q2xpcGJvYXJkID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gbmV3IENvcmRvdmFDbGlwYm9hcmQoKTtcbiAgICB9O1xuICAgIENvcmRvdmFQbGF0Zm9ybS5wcm90b3R5cGUuZ2V0RXJyb3JSZXBvcnRlciA9IGZ1bmN0aW9uIChlbnYpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuaGFzRGV2aWNlU3VwcG9ydCgpID9cbiAgICAgICAgICAgIG5ldyBDb3Jkb3ZhRXJyb3JSZXBvcnRlcihlbnYuQVBQX1ZFUlNJT04sIGVudi5BUFBfQlVJTERfTlVNQkVSLCBlbnYuU0VOVFJZX0RTTiwgZW52LlNFTlRSWV9OQVRJVkVfRFNOKSA6XG4gICAgICAgICAgICBuZXcgZXJyb3JfcmVwb3J0ZXJfMS5TZW50cnlFcnJvclJlcG9ydGVyKGVudi5BUFBfVkVSU0lPTiwgZW52LlNFTlRSWV9EU04sIHt9KTtcbiAgICB9O1xuICAgIENvcmRvdmFQbGF0Zm9ybS5wcm90b3R5cGUuZ2V0VXBkYXRlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIG5ldyB1cGRhdGVyXzEuQWJzdHJhY3RVcGRhdGVyKCk7XG4gICAgfTtcbiAgICBDb3Jkb3ZhUGxhdGZvcm0ucHJvdG90eXBlLnF1aXRBcHBsaWNhdGlvbiA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgLy8gT25seSB1c2VkIGluIG1hY09TIGJlY2F1c2UgbWVudSBiYXIgYXBwcyBwcm92aWRlIG5vIGFsdGVybmF0aXZlIHdheSBvZiBxdWl0dGluZy5cbiAgICAgICAgY29yZG92YS5wbHVnaW5zLm91dGxpbmUucXVpdEFwcGxpY2F0aW9uKCk7XG4gICAgfTtcbiAgICByZXR1cm4gQ29yZG92YVBsYXRmb3JtO1xufSgpKTtcbi8vIGh0dHBzOi8vY29yZG92YS5hcGFjaGUub3JnL2RvY3MvZW4vbGF0ZXN0L2NvcmRvdmEvZXZlbnRzL2V2ZW50cy5odG1sI2RldmljZXJlYWR5XG52YXIgb25jZURldmljZVJlYWR5ID0gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUpIHtcbiAgICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKCdkZXZpY2VyZWFkeScsIHJlc29sdmUpO1xufSk7XG4vLyBjb3Jkb3ZhLVtpb3N8b3N4XSBjYWxsIGEgZ2xvYmFsIGZ1bmN0aW9uIHdpdGggdGhpcyBzaWduYXR1cmUgd2hlbiBhIFVSTCBpc1xuLy8gaW50ZXJjZXB0ZWQuIFdlIGhhbmRsZSBVUkwgaW50ZXJjZXB0aW9ucyB3aXRoIGFuIGludGVudCBpbnRlcmNlcHRvcjsgaG93ZXZlcixcbi8vIHdoZW4gdGhlIGFwcCBpcyBsYXVuY2hlZCB2aWEgVVJMIG91ciBzdGFydCB1cCBzZXF1ZW5jZSBtaXNzZXMgdGhlIGNhbGwgZHVlIHRvXG4vLyBhIHJhY2UuIERlZmluZSB0aGUgZnVuY3Rpb24gdGVtcG9yYXJpbHkgaGVyZSwgYW5kIHNldCBhIGdsb2JhbCB2YXJpYWJsZS5cbnZhciBhcHBsZUxhdW5jaFVybDtcbndpbmRvdy5oYW5kbGVPcGVuVVJMID0gZnVuY3Rpb24gKHVybCkge1xuICAgIGFwcGxlTGF1bmNoVXJsID0gdXJsO1xufTtcbm9uY2VEZXZpY2VSZWFkeS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICBtYWluXzEubWFpbihuZXcgQ29yZG92YVBsYXRmb3JtKCkpO1xufSk7XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCAyMDE4IFRoZSBPdXRsaW5lIEF1dGhvcnNcbi8vXG4vLyBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuLy8geW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuLy8gWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4vL1xuLy8gICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbi8vXG4vLyBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4vLyBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4vLyBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbi8vIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbi8vIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxuT2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFwiX19lc01vZHVsZVwiLCB7IHZhbHVlOiB0cnVlIH0pO1xuLy8gS2VlcCB0aGVzZSBpbiBzeW5jIHdpdGggdGhlIEVudmlyb25tZW50VmFyaWFibGVzIGludGVyZmFjZSBhYm92ZS5cbnZhciBFTlZfS0VZUyA9IHtcbiAgICBBUFBfVkVSU0lPTjogJ0FQUF9WRVJTSU9OJyxcbiAgICBBUFBfQlVJTERfTlVNQkVSOiAnQVBQX0JVSUxEX05VTUJFUicsXG4gICAgU0VOVFJZX0RTTjogJ1NFTlRSWV9EU04nLFxuICAgIFNFTlRSWV9OQVRJVkVfRFNOOiAnU0VOVFJZX05BVElWRV9EU04nXG59O1xuZnVuY3Rpb24gdmFsaWRhdGVFbnZWYXJzKGpzb24pIHtcbiAgICBmb3IgKHZhciBrZXkgaW4gRU5WX0tFWVMpIHtcbiAgICAgICAgaWYgKCFqc29uLmhhc093blByb3BlcnR5KGtleSkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIk1pc3NpbmcgZW52aXJvbm1lbnQgdmFyaWFibGU6IFwiICsga2V5KTtcbiAgICAgICAgfVxuICAgIH1cbn1cbi8vIEFjY29yZGluZyB0byBodHRwOi8vY2FuaXVzZS5jb20vI2ZlYXQ9ZmV0Y2ggZmV0Y2ggZGlkbid0IGhpdCBpT1MgU2FmYXJpXG4vLyB1bnRpbCB2MTAuMyByZWxlYXNlZCAzLzI2LzE3LCBzbyB1c2UgWE1MSHR0cFJlcXVlc3QgaW5zdGVhZC5cbmV4cG9ydHMub25jZUVudlZhcnMgPSBuZXcgUHJvbWlzZShmdW5jdGlvbiAocmVzb2x2ZSwgcmVqZWN0KSB7XG4gICAgdmFyIHhociA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpO1xuICAgIHhoci5vbmxvYWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB2YXIganNvbiA9IEpTT04ucGFyc2UoeGhyLnJlc3BvbnNlVGV4dCk7XG4gICAgICAgICAgICB2YWxpZGF0ZUVudlZhcnMoanNvbik7XG4gICAgICAgICAgICBjb25zb2xlLmRlYnVnKCdSZXNvbHZpbmcgd2l0aCBlbnZWYXJzOicsIGpzb24pO1xuICAgICAgICAgICAgcmVzb2x2ZShqc29uKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgeGhyLm9wZW4oJ0dFVCcsICdlbnZpcm9ubWVudC5qc29uJywgdHJ1ZSk7XG4gICAgeGhyLnNlbmQoKTtcbn0pO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG4vLyBDb3B5cmlnaHQgMjAxOCBUaGUgT3V0bGluZSBBdXRob3JzXG4vL1xuLy8gTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbi8vIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbi8vIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuLy9cbi8vICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4vL1xuLy8gVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuLy8gZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuLy8gV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4vLyBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4vLyBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbnZhciBSYXZlbiA9IHJlcXVpcmUoXCJyYXZlbi1qc1wiKTtcbnZhciBTZW50cnlFcnJvclJlcG9ydGVyID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIFNlbnRyeUVycm9yUmVwb3J0ZXIoYXBwVmVyc2lvbiwgZHNuLCB0YWdzKSB7XG4gICAgICAgIFJhdmVuLmNvbmZpZyhkc24sIHsgcmVsZWFzZTogYXBwVmVyc2lvbiwgJ3RhZ3MnOiB0YWdzIH0pLmluc3RhbGwoKTtcbiAgICAgICAgdGhpcy5zZXRVcFVuaGFuZGxlZFJlamVjdGlvbkxpc3RlbmVyKCk7XG4gICAgfVxuICAgIFNlbnRyeUVycm9yUmVwb3J0ZXIucHJvdG90eXBlLnJlcG9ydCA9IGZ1bmN0aW9uICh1c2VyRmVlZGJhY2ssIGZlZWRiYWNrQ2F0ZWdvcnksIHVzZXJFbWFpbCkge1xuICAgICAgICBSYXZlbi5zZXRVc2VyQ29udGV4dCh7IGVtYWlsOiB1c2VyRW1haWwgfHwgJycgfSk7XG4gICAgICAgIFJhdmVuLmNhcHR1cmVNZXNzYWdlKHVzZXJGZWVkYmFjaywgeyB0YWdzOiB7IGNhdGVnb3J5OiBmZWVkYmFja0NhdGVnb3J5IH0gfSk7XG4gICAgICAgIFJhdmVuLnNldFVzZXJDb250ZXh0KCk7IC8vIFJlc2V0IHRoZSB1c2VyIGNvbnRleHQsIGRvbid0IGNhY2hlIHRoZSBlbWFpbFxuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgfTtcbiAgICBTZW50cnlFcnJvclJlcG9ydGVyLnByb3RvdHlwZS5zZXRVcFVuaGFuZGxlZFJlamVjdGlvbkxpc3RlbmVyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAvLyBDaHJvbWUgaXMgdGhlIG9ubHkgYnJvd3NlciB0aGF0IHN1cHBvcnRzIHRoZSB1bmhhbmRsZWRyZWplY3Rpb24gZXZlbnQuXG4gICAgICAgIC8vIFRoaXMgaXMgZmluZSBmb3IgQW5kcm9pZCwgYnV0IHdpbGwgbm90IHdvcmsgaW4gaU9TLlxuICAgICAgICB2YXIgdW5oYW5kbGVkUmVqZWN0aW9uID0gJ3VuaGFuZGxlZHJlamVjdGlvbic7XG4gICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKHVuaGFuZGxlZFJlamVjdGlvbiwgZnVuY3Rpb24gKGV2ZW50KSB7XG4gICAgICAgICAgICB2YXIgcmVhc29uID0gZXZlbnQucmVhc29uO1xuICAgICAgICAgICAgdmFyIG1zZyA9IHJlYXNvbi5zdGFjayA/IHJlYXNvbi5zdGFjayA6IHJlYXNvbjtcbiAgICAgICAgICAgIFJhdmVuLmNhcHR1cmVCcmVhZGNydW1iKHsgbWVzc2FnZTogbXNnLCBjYXRlZ29yeTogdW5oYW5kbGVkUmVqZWN0aW9uIH0pO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIHJldHVybiBTZW50cnlFcnJvclJlcG9ydGVyO1xufSgpKTtcbmV4cG9ydHMuU2VudHJ5RXJyb3JSZXBvcnRlciA9IFNlbnRyeUVycm9yUmVwb3J0ZXI7XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCAyMDE4IFRoZSBPdXRsaW5lIEF1dGhvcnNcbi8vXG4vLyBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuLy8geW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuLy8gWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4vL1xuLy8gICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbi8vXG4vLyBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4vLyBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4vLyBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbi8vIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbi8vIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxuT2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFwiX19lc01vZHVsZVwiLCB7IHZhbHVlOiB0cnVlIH0pO1xuLy8vIDxyZWZlcmVuY2UgcGF0aD0nLi4vLi4vdHlwZXMvYW1iaWVudC9vdXRsaW5lUGx1Z2luLmQudHMnLz5cbnZhciBlcnJvcnMgPSByZXF1aXJlKFwiLi4vbW9kZWwvZXJyb3JzXCIpO1xuLy8gTm90ZSB0aGF0IGJlY2F1c2UgdGhpcyBpbXBsZW1lbnRhdGlvbiBkb2VzIG5vdCBlbWl0IGRpc2Nvbm5lY3Rpb24gZXZlbnRzLCBcInN3aXRjaGluZ1wiIGJldHdlZW5cbi8vIHNlcnZlcnMgaW4gdGhlIHNlcnZlciBsaXN0IHdpbGwgbm90IHdvcmsgYXMgZXhwZWN0ZWQuXG52YXIgRmFrZU91dGxpbmVDb25uZWN0aW9uID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIEZha2VPdXRsaW5lQ29ubmVjdGlvbihjb25maWcsIGlkKSB7XG4gICAgICAgIHRoaXMuY29uZmlnID0gY29uZmlnO1xuICAgICAgICB0aGlzLmlkID0gaWQ7XG4gICAgICAgIHRoaXMucnVubmluZyA9IGZhbHNlO1xuICAgIH1cbiAgICBGYWtlT3V0bGluZUNvbm5lY3Rpb24ucHJvdG90eXBlLnBsYXlCcm9rZW4gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiB0aGlzLmNvbmZpZy5uYW1lICYmIHRoaXMuY29uZmlnLm5hbWUudG9Mb3dlckNhc2UoKS5pbmNsdWRlcygnYnJva2VuJyk7XG4gICAgfTtcbiAgICBGYWtlT3V0bGluZUNvbm5lY3Rpb24ucHJvdG90eXBlLnBsYXlVbnJlYWNoYWJsZSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuICEodGhpcy5jb25maWcubmFtZSAmJiB0aGlzLmNvbmZpZy5uYW1lLnRvTG93ZXJDYXNlKCkuaW5jbHVkZXMoJ3VucmVhY2hhYmxlJykpO1xuICAgIH07XG4gICAgRmFrZU91dGxpbmVDb25uZWN0aW9uLnByb3RvdHlwZS5zdGFydCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKHRoaXMucnVubmluZykge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghdGhpcy5wbGF5VW5yZWFjaGFibGUoKSkge1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBlcnJvcnMuT3V0bGluZVBsdWdpbkVycm9yKDUgLyogU0VSVkVSX1VOUkVBQ0hBQkxFICovKSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodGhpcy5wbGF5QnJva2VuKCkpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgZXJyb3JzLk91dGxpbmVQbHVnaW5FcnJvcig4IC8qIFNIQURPV1NPQ0tTX1NUQVJUX0ZBSUxVUkUgKi8pKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHRoaXMucnVubmluZyA9IHRydWU7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgIH1cbiAgICB9O1xuICAgIEZha2VPdXRsaW5lQ29ubmVjdGlvbi5wcm90b3R5cGUuc3RvcCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKCF0aGlzLnJ1bm5pbmcpIHtcbiAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnJ1bm5pbmcgPSBmYWxzZTtcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgIH07XG4gICAgRmFrZU91dGxpbmVDb25uZWN0aW9uLnByb3RvdHlwZS5pc1J1bm5pbmcgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcy5ydW5uaW5nKTtcbiAgICB9O1xuICAgIEZha2VPdXRsaW5lQ29ubmVjdGlvbi5wcm90b3R5cGUuaXNSZWFjaGFibGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoIXRoaXMucGxheVVucmVhY2hhYmxlKCkpO1xuICAgIH07XG4gICAgRmFrZU91dGxpbmVDb25uZWN0aW9uLnByb3RvdHlwZS5vblN0YXR1c0NoYW5nZSA9IGZ1bmN0aW9uIChsaXN0ZW5lcikge1xuICAgICAgICAvLyBOT09QXG4gICAgfTtcbiAgICByZXR1cm4gRmFrZU91dGxpbmVDb25uZWN0aW9uO1xufSgpKTtcbmV4cG9ydHMuRmFrZU91dGxpbmVDb25uZWN0aW9uID0gRmFrZU91dGxpbmVDb25uZWN0aW9uO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG4vLyBDb3B5cmlnaHQgMjAxOCBUaGUgT3V0bGluZSBBdXRob3JzXG4vL1xuLy8gTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbi8vIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbi8vIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuLy9cbi8vICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4vL1xuLy8gVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuLy8gZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuLy8gV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4vLyBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4vLyBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbnZhciBfX3JlYWQgPSAodGhpcyAmJiB0aGlzLl9fcmVhZCkgfHwgZnVuY3Rpb24gKG8sIG4pIHtcbiAgICB2YXIgbSA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBvW1N5bWJvbC5pdGVyYXRvcl07XG4gICAgaWYgKCFtKSByZXR1cm4gbztcbiAgICB2YXIgaSA9IG0uY2FsbChvKSwgciwgYXIgPSBbXSwgZTtcbiAgICB0cnkge1xuICAgICAgICB3aGlsZSAoKG4gPT09IHZvaWQgMCB8fCBuLS0gPiAwKSAmJiAhKHIgPSBpLm5leHQoKSkuZG9uZSkgYXIucHVzaChyLnZhbHVlKTtcbiAgICB9XG4gICAgY2F0Y2ggKGVycm9yKSB7IGUgPSB7IGVycm9yOiBlcnJvciB9OyB9XG4gICAgZmluYWxseSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBpZiAociAmJiAhci5kb25lICYmIChtID0gaVtcInJldHVyblwiXSkpIG0uY2FsbChpKTtcbiAgICAgICAgfVxuICAgICAgICBmaW5hbGx5IHsgaWYgKGUpIHRocm93IGUuZXJyb3I7IH1cbiAgICB9XG4gICAgcmV0dXJuIGFyO1xufTtcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbnZhciB1cmwgPSByZXF1aXJlKFwidXJsXCIpO1xudmFyIGV2ZW50c18xID0gcmVxdWlyZShcIi4uL21vZGVsL2V2ZW50c1wiKTtcbnZhciBhcHBfMSA9IHJlcXVpcmUoXCIuL2FwcFwiKTtcbnZhciBlbnZpcm9ubWVudF8xID0gcmVxdWlyZShcIi4vZW52aXJvbm1lbnRcIik7XG52YXIgcGVyc2lzdGVudF9zZXJ2ZXJfMSA9IHJlcXVpcmUoXCIuL3BlcnNpc3RlbnRfc2VydmVyXCIpO1xudmFyIHNldHRpbmdzXzEgPSByZXF1aXJlKFwiLi9zZXR0aW5nc1wiKTtcbi8vIFVzZWQgdG8gZGV0ZXJtaW5lIHdoZXRoZXIgdG8gdXNlIFBvbHltZXIgZnVuY3Rpb25hbGl0eSBvbiBhcHAgaW5pdGlhbGl6YXRpb24gZmFpbHVyZS5cbnZhciB3ZWJDb21wb25lbnRzQXJlUmVhZHkgPSBmYWxzZTtcbmRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ1dlYkNvbXBvbmVudHNSZWFkeScsIGZ1bmN0aW9uICgpIHtcbiAgICBjb25zb2xlLmRlYnVnKCdyZWNlaXZlZCBXZWJDb21wb25lbnRzUmVhZHkgZXZlbnQnKTtcbiAgICB3ZWJDb21wb25lbnRzQXJlUmVhZHkgPSB0cnVlO1xufSk7XG4vLyBVc2VkIHRvIGRlbGF5IGxvYWRpbmcgdGhlIGFwcCB1bnRpbCAodHJhbnNsYXRpb24pIHJlc291cmNlcyBoYXZlIGJlZW4gbG9hZGVkLiBUaGlzIGNhbiBoYXBwZW4gYVxuLy8gbGl0dGxlIGxhdGVyIHRoYW4gV2ViQ29tcG9uZW50c1JlYWR5LlxudmFyIG9uY2VQb2x5bWVySXNSZWFkeSA9IG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlKSB7XG4gICAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcignYXBwLWxvY2FsaXplLXJlc291cmNlcy1sb2FkZWQnLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ3JlY2VpdmVkIGFwcC1sb2NhbGl6ZS1yZXNvdXJjZXMtbG9hZGVkIGV2ZW50Jyk7XG4gICAgICAgIHJlc29sdmUoKTtcbiAgICB9KTtcbn0pO1xuLy8gSGVscGVyc1xuLy8gRG8gbm90IGNhbGwgdW50aWwgV2ViQ29tcG9uZW50c1JlYWR5IGhhcyBmaXJlZCFcbmZ1bmN0aW9uIGdldFJvb3RFbCgpIHtcbiAgICByZXR1cm4gZG9jdW1lbnQucXVlcnlTZWxlY3RvcignYXBwLXJvb3QnKTtcbn1cbmZ1bmN0aW9uIGNyZWF0ZVNlcnZlclJlcG8oZXZlbnRRdWV1ZSwgc3RvcmFnZSwgZGV2aWNlU3VwcG9ydCwgY29ubmVjdGlvblR5cGUpIHtcbiAgICB2YXIgcmVwbyA9IG5ldyBwZXJzaXN0ZW50X3NlcnZlcl8xLlBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5KGNvbm5lY3Rpb25UeXBlLCBldmVudFF1ZXVlLCBzdG9yYWdlKTtcbiAgICBpZiAoIWRldmljZVN1cHBvcnQpIHtcbiAgICAgICAgY29uc29sZS5kZWJ1ZygnRGV0ZWN0ZWQgZGV2ZWxvcG1lbnQgZW52aXJvbm1lbnQsIHVzaW5nIGZha2Ugc2VydmVycy4nKTtcbiAgICAgICAgaWYgKHJlcG8uZ2V0QWxsKCkubGVuZ3RoID09PSAwKSB7XG4gICAgICAgICAgICByZXBvLmFkZCh7IG5hbWU6ICdGYWtlIFdvcmtpbmcgU2VydmVyJywgaG9zdDogJzEyNy4wLjAuMScsIHBvcnQ6IDEyMyB9KTtcbiAgICAgICAgICAgIHJlcG8uYWRkKHsgbmFtZTogJ0Zha2UgQnJva2VuIFNlcnZlcicsIGhvc3Q6ICcxOTIuMC4yLjEnLCBwb3J0OiAxMjMgfSk7XG4gICAgICAgICAgICByZXBvLmFkZCh7IG5hbWU6ICdGYWtlIFVucmVhY2hhYmxlIFNlcnZlcicsIGhvc3Q6ICcxMC4wLjAuMjQnLCBwb3J0OiAxMjMgfSk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHJlcG87XG59XG5mdW5jdGlvbiBtYWluKHBsYXRmb3JtKSB7XG4gICAgcmV0dXJuIFByb21pc2UuYWxsKFtlbnZpcm9ubWVudF8xLm9uY2VFbnZWYXJzLCBvbmNlUG9seW1lcklzUmVhZHldKVxuICAgICAgICAudGhlbihmdW5jdGlvbiAoX2EpIHtcbiAgICAgICAgdmFyIF9iID0gX19yZWFkKF9hLCAxKSwgZW52aXJvbm1lbnRWYXJzID0gX2JbMF07XG4gICAgICAgIGNvbnNvbGUuZGVidWcoJ3J1bm5pbmcgbWFpbigpIGZ1bmN0aW9uJyk7XG4gICAgICAgIHZhciBxdWVyeVBhcmFtcyA9IHVybC5wYXJzZShkb2N1bWVudC5VUkwsIHRydWUpLnF1ZXJ5O1xuICAgICAgICB2YXIgZGVidWdNb2RlID0gcXVlcnlQYXJhbXMuZGVidWcgPT09ICd0cnVlJztcbiAgICAgICAgdmFyIGV2ZW50UXVldWUgPSBuZXcgZXZlbnRzXzEuRXZlbnRRdWV1ZSgpO1xuICAgICAgICB2YXIgc2VydmVyUmVwbyA9IGNyZWF0ZVNlcnZlclJlcG8oZXZlbnRRdWV1ZSwgd2luZG93LmxvY2FsU3RvcmFnZSwgcGxhdGZvcm0uaGFzRGV2aWNlU3VwcG9ydCgpLCBwbGF0Zm9ybS5nZXRQZXJzaXN0ZW50U2VydmVyRmFjdG9yeSgpKTtcbiAgICAgICAgdmFyIHNldHRpbmdzID0gbmV3IHNldHRpbmdzXzEuU2V0dGluZ3MoKTtcbiAgICAgICAgdmFyIGFwcCA9IG5ldyBhcHBfMS5BcHAoZXZlbnRRdWV1ZSwgc2VydmVyUmVwbywgZ2V0Um9vdEVsKCksIGRlYnVnTW9kZSwgcGxhdGZvcm0uZ2V0VXJsSW50ZXJjZXB0b3IoKSwgcGxhdGZvcm0uZ2V0Q2xpcGJvYXJkKCksIHBsYXRmb3JtLmdldEVycm9yUmVwb3J0ZXIoZW52aXJvbm1lbnRWYXJzKSwgc2V0dGluZ3MsIGVudmlyb25tZW50VmFycywgcGxhdGZvcm0uZ2V0VXBkYXRlcigpLCBwbGF0Zm9ybS5xdWl0QXBwbGljYXRpb24pO1xuICAgIH0sIGZ1bmN0aW9uIChlKSB7XG4gICAgICAgIG9uVW5leHBlY3RlZEVycm9yKGUpO1xuICAgICAgICB0aHJvdyBlO1xuICAgIH0pO1xufVxuZXhwb3J0cy5tYWluID0gbWFpbjtcbmZ1bmN0aW9uIG9uVW5leHBlY3RlZEVycm9yKGVycm9yKSB7XG4gICAgdmFyIHJvb3RFbCA9IGdldFJvb3RFbCgpO1xuICAgIGlmICh3ZWJDb21wb25lbnRzQXJlUmVhZHkgJiYgcm9vdEVsICYmIHJvb3RFbC5sb2NhbGl6ZSkge1xuICAgICAgICB2YXIgbG9jYWxpemUgPSByb290RWwubG9jYWxpemUuYmluZChyb290RWwpO1xuICAgICAgICByb290RWwuc2hvd1RvYXN0KGxvY2FsaXplKCdlcnJvci11bmV4cGVjdGVkJyksIDEyMDAwMCk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICAvLyBTb21ldGhpbmcgd2VudCB0ZXJyaWJseSB3cm9uZyAoaS5lLiBQb2x5bWVyIGZhaWxlZCB0byBpbml0aWFsaXplKS4gUHJvdmlkZSBzb21lIG1lc3NhZ2luZyB0b1xuICAgICAgICAvLyB0aGUgdXNlciwgZXZlbiBpZiB3ZSBhcmUgbm90IGFibGUgdG8gZGlzcGxheSBpdCBpbiBhIHRvYXN0IG9yIGxvY2FsaXplIGl0LlxuICAgICAgICAvLyBUT0RPOiBwcm92aWRlIGFuIGhlbHAgZW1haWwgb25jZSB3ZSBoYXZlIGEgZG9tYWluLlxuICAgICAgICBhbGVydChcIkFuIHVuZXhwZWN0ZWQgZXJyb3Igb2NjdXJyZWQuXCIpO1xuICAgIH1cbiAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbn1cbi8vIFJldHVybnMgUG9seW1lcidzIGxvY2FsaXphdGlvbiBmdW5jdGlvbi4gTXVzdCBiZSBjYWxsZWQgYWZ0ZXIgV2ViQ29tcG9uZW50c1JlYWR5IGhhcyBmaXJlZC5cbmZ1bmN0aW9uIGdldExvY2FsaXphdGlvbkZ1bmN0aW9uKCkge1xuICAgIHZhciByb290RWwgPSBnZXRSb290RWwoKTtcbiAgICBpZiAoIXJvb3RFbCkge1xuICAgICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgcmV0dXJuIHJvb3RFbC5sb2NhbGl6ZTtcbn1cbmV4cG9ydHMuZ2V0TG9jYWxpemF0aW9uRnVuY3Rpb24gPSBnZXRMb2NhbGl6YXRpb25GdW5jdGlvbjtcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG5PYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgXCJfX2VzTW9kdWxlXCIsIHsgdmFsdWU6IHRydWUgfSk7XG4vLy8gPHJlZmVyZW5jZSBwYXRoPScuLi8uLi90eXBlcy9hbWJpZW50L291dGxpbmVQbHVnaW4uZC50cycvPlxudmFyIGVycm9ycyA9IHJlcXVpcmUoXCIuLi9tb2RlbC9lcnJvcnNcIik7XG52YXIgZXZlbnRzID0gcmVxdWlyZShcIi4uL21vZGVsL2V2ZW50c1wiKTtcbnZhciBPdXRsaW5lU2VydmVyID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIE91dGxpbmVTZXJ2ZXIoaWQsIGNvbmZpZywgY29ubmVjdGlvbiwgZXZlbnRRdWV1ZSkge1xuICAgICAgICB2YXIgX3RoaXMgPSB0aGlzO1xuICAgICAgICB0aGlzLmlkID0gaWQ7XG4gICAgICAgIHRoaXMuY29uZmlnID0gY29uZmlnO1xuICAgICAgICB0aGlzLmNvbm5lY3Rpb24gPSBjb25uZWN0aW9uO1xuICAgICAgICB0aGlzLmV2ZW50UXVldWUgPSBldmVudFF1ZXVlO1xuICAgICAgICB0aGlzLmNvbm5lY3Rpb24ub25TdGF0dXNDaGFuZ2UoZnVuY3Rpb24gKHN0YXR1cykge1xuICAgICAgICAgICAgdmFyIHN0YXR1c0V2ZW50O1xuICAgICAgICAgICAgc3dpdGNoIChzdGF0dXMpIHtcbiAgICAgICAgICAgICAgICBjYXNlIDAgLyogQ09OTkVDVEVEICovOlxuICAgICAgICAgICAgICAgICAgICBzdGF0dXNFdmVudCA9IG5ldyBldmVudHMuU2VydmVyQ29ubmVjdGVkKF90aGlzKTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAxIC8qIERJU0NPTk5FQ1RFRCAqLzpcbiAgICAgICAgICAgICAgICAgICAgc3RhdHVzRXZlbnQgPSBuZXcgZXZlbnRzLlNlcnZlckRpc2Nvbm5lY3RlZChfdGhpcyk7XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgMiAvKiBSRUNPTk5FQ1RJTkcgKi86XG4gICAgICAgICAgICAgICAgICAgIHN0YXR1c0V2ZW50ID0gbmV3IGV2ZW50cy5TZXJ2ZXJSZWNvbm5lY3RpbmcoX3RoaXMpO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLndhcm4oXCJSZWNlaXZlZCB1bmtub3duIGNvbm5lY3Rpb24gc3RhdHVzIFwiICsgc3RhdHVzKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZXZlbnRRdWV1ZS5lbnF1ZXVlKHN0YXR1c0V2ZW50KTtcbiAgICAgICAgfSk7XG4gICAgfVxuICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShPdXRsaW5lU2VydmVyLnByb3RvdHlwZSwgXCJuYW1lXCIsIHtcbiAgICAgICAgZ2V0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5jb25maWcubmFtZSB8fCB0aGlzLmNvbmZpZy5ob3N0IHx8ICcnO1xuICAgICAgICB9LFxuICAgICAgICBzZXQ6IGZ1bmN0aW9uIChuZXdOYW1lKSB7XG4gICAgICAgICAgICB0aGlzLmNvbmZpZy5uYW1lID0gbmV3TmFtZTtcbiAgICAgICAgfSxcbiAgICAgICAgZW51bWVyYWJsZTogdHJ1ZSxcbiAgICAgICAgY29uZmlndXJhYmxlOiB0cnVlXG4gICAgfSk7XG4gICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KE91dGxpbmVTZXJ2ZXIucHJvdG90eXBlLCBcImhvc3RcIiwge1xuICAgICAgICBnZXQ6IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLmNvbmZpZy5ob3N0O1xuICAgICAgICB9LFxuICAgICAgICBlbnVtZXJhYmxlOiB0cnVlLFxuICAgICAgICBjb25maWd1cmFibGU6IHRydWVcbiAgICB9KTtcbiAgICBPdXRsaW5lU2VydmVyLnByb3RvdHlwZS5jb25uZWN0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gdGhpcy5jb25uZWN0aW9uLnN0YXJ0KCkuY2F0Y2goZnVuY3Rpb24gKGUpIHtcbiAgICAgICAgICAgIC8vIGUgb3JpZ2luYXRlcyBpbiBcIm5hdGl2ZVwiIGNvZGU6IGVpdGhlciBDb3Jkb3ZhIG9yIEVsZWN0cm9uJ3MgbWFpbiBwcm9jZXNzLlxuICAgICAgICAgICAgLy8gQmVjYXVzZSBvZiB0aGlzLCB3ZSBjYW5ub3QgYXNzdW1lIFwiaW5zdGFuY2VvZiBPdXRsaW5lUGx1Z2luRXJyb3JcIiB3aWxsIHdvcmsuXG4gICAgICAgICAgICBpZiAoZS5lcnJvckNvZGUpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBlcnJvcnMuZnJvbUVycm9yQ29kZShlLmVycm9yQ29kZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB0aHJvdyBlO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIE91dGxpbmVTZXJ2ZXIucHJvdG90eXBlLmRpc2Nvbm5lY3QgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiB0aGlzLmNvbm5lY3Rpb24uc3RvcCgpLmNhdGNoKGZ1bmN0aW9uIChlKSB7XG4gICAgICAgICAgICAvLyBUT0RPOiBOb25lIG9mIHRoZSBwbHVnaW5zIGN1cnJlbnRseSByZXR1cm4gYW4gRXJyb3JDb2RlIG9uIGRpc2Nvbm5lY3Rpb24uXG4gICAgICAgICAgICB0aHJvdyBuZXcgZXJyb3JzLlJlZ3VsYXJOYXRpdmVFcnJvcigpO1xuICAgICAgICB9KTtcbiAgICB9O1xuICAgIE91dGxpbmVTZXJ2ZXIucHJvdG90eXBlLmNoZWNrUnVubmluZyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMuY29ubmVjdGlvbi5pc1J1bm5pbmcoKTtcbiAgICB9O1xuICAgIE91dGxpbmVTZXJ2ZXIucHJvdG90eXBlLmNoZWNrUmVhY2hhYmxlID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gdGhpcy5jb25uZWN0aW9uLmlzUmVhY2hhYmxlKCk7XG4gICAgfTtcbiAgICByZXR1cm4gT3V0bGluZVNlcnZlcjtcbn0oKSk7XG5leHBvcnRzLk91dGxpbmVTZXJ2ZXIgPSBPdXRsaW5lU2VydmVyO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG4vLyBDb3B5cmlnaHQgMjAxOCBUaGUgT3V0bGluZSBBdXRob3JzXG4vL1xuLy8gTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbi8vIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbi8vIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuLy9cbi8vICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4vL1xuLy8gVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuLy8gZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuLy8gV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4vLyBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4vLyBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbnZhciBfX3ZhbHVlcyA9ICh0aGlzICYmIHRoaXMuX192YWx1ZXMpIHx8IGZ1bmN0aW9uKG8pIHtcbiAgICB2YXIgcyA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBTeW1ib2wuaXRlcmF0b3IsIG0gPSBzICYmIG9bc10sIGkgPSAwO1xuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xuICAgIGlmIChvICYmIHR5cGVvZiBvLmxlbmd0aCA9PT0gXCJudW1iZXJcIikgcmV0dXJuIHtcbiAgICAgICAgbmV4dDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgaWYgKG8gJiYgaSA+PSBvLmxlbmd0aCkgbyA9IHZvaWQgMDtcbiAgICAgICAgICAgIHJldHVybiB7IHZhbHVlOiBvICYmIG9baSsrXSwgZG9uZTogIW8gfTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihzID8gXCJPYmplY3QgaXMgbm90IGl0ZXJhYmxlLlwiIDogXCJTeW1ib2wuaXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xufTtcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbnZhciB1dWlkdjQgPSByZXF1aXJlKFwidXVpZHY0XCIpO1xudmFyIGVycm9yc18xID0gcmVxdWlyZShcIi4uL21vZGVsL2Vycm9yc1wiKTtcbnZhciBldmVudHMgPSByZXF1aXJlKFwiLi4vbW9kZWwvZXZlbnRzXCIpO1xuLy8gTWFpbnRhaW5zIGEgcGVyc2lzdGVkIHNldCBvZiBzZXJ2ZXJzIGFuZCBsaWFpc2VzIHdpdGggdGhlIGNvcmUuXG52YXIgUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkoY3JlYXRlU2VydmVyLCBldmVudFF1ZXVlLCBzdG9yYWdlKSB7XG4gICAgICAgIHRoaXMuY3JlYXRlU2VydmVyID0gY3JlYXRlU2VydmVyO1xuICAgICAgICB0aGlzLmV2ZW50UXVldWUgPSBldmVudFF1ZXVlO1xuICAgICAgICB0aGlzLnN0b3JhZ2UgPSBzdG9yYWdlO1xuICAgICAgICB0aGlzLmxhc3RGb3Jnb3R0ZW5TZXJ2ZXIgPSBudWxsO1xuICAgICAgICB0aGlzLmxvYWRTZXJ2ZXJzKCk7XG4gICAgfVxuICAgIFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5LnByb3RvdHlwZS5nZXRBbGwgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiBBcnJheS5mcm9tKHRoaXMuc2VydmVyQnlJZC52YWx1ZXMoKSk7XG4gICAgfTtcbiAgICBQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeS5wcm90b3R5cGUuZ2V0QnlJZCA9IGZ1bmN0aW9uIChzZXJ2ZXJJZCkge1xuICAgICAgICByZXR1cm4gdGhpcy5zZXJ2ZXJCeUlkLmdldChzZXJ2ZXJJZCk7XG4gICAgfTtcbiAgICBQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeS5wcm90b3R5cGUuYWRkID0gZnVuY3Rpb24gKHNlcnZlckNvbmZpZykge1xuICAgICAgICB2YXIgYWxyZWFkeUFkZGVkU2VydmVyID0gdGhpcy5zZXJ2ZXJGcm9tQ29uZmlnKHNlcnZlckNvbmZpZyk7XG4gICAgICAgIGlmIChhbHJlYWR5QWRkZWRTZXJ2ZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBlcnJvcnNfMS5TZXJ2ZXJBbHJlYWR5QWRkZWQoYWxyZWFkeUFkZGVkU2VydmVyKTtcbiAgICAgICAgfVxuICAgICAgICB2YXIgc2VydmVyID0gdGhpcy5jcmVhdGVTZXJ2ZXIodXVpZHY0KCksIHNlcnZlckNvbmZpZywgdGhpcy5ldmVudFF1ZXVlKTtcbiAgICAgICAgdGhpcy5zZXJ2ZXJCeUlkLnNldChzZXJ2ZXIuaWQsIHNlcnZlcik7XG4gICAgICAgIHRoaXMuc3RvcmVTZXJ2ZXJzKCk7XG4gICAgICAgIHRoaXMuZXZlbnRRdWV1ZS5lbnF1ZXVlKG5ldyBldmVudHMuU2VydmVyQWRkZWQoc2VydmVyKSk7XG4gICAgfTtcbiAgICBQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeS5wcm90b3R5cGUucmVuYW1lID0gZnVuY3Rpb24gKHNlcnZlcklkLCBuZXdOYW1lKSB7XG4gICAgICAgIHZhciBzZXJ2ZXIgPSB0aGlzLnNlcnZlckJ5SWQuZ2V0KHNlcnZlcklkKTtcbiAgICAgICAgaWYgKCFzZXJ2ZXIpIHtcbiAgICAgICAgICAgIGNvbnNvbGUud2FybihcIkNhbm5vdCByZW5hbWUgbm9uZXhpc3RlbnQgc2VydmVyIFwiICsgc2VydmVySWQpO1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIHNlcnZlci5uYW1lID0gbmV3TmFtZTtcbiAgICAgICAgdGhpcy5zdG9yZVNlcnZlcnMoKTtcbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlLmVucXVldWUobmV3IGV2ZW50cy5TZXJ2ZXJSZW5hbWVkKHNlcnZlcikpO1xuICAgIH07XG4gICAgUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkucHJvdG90eXBlLmZvcmdldCA9IGZ1bmN0aW9uIChzZXJ2ZXJJZCkge1xuICAgICAgICB2YXIgc2VydmVyID0gdGhpcy5zZXJ2ZXJCeUlkLmdldChzZXJ2ZXJJZCk7XG4gICAgICAgIGlmICghc2VydmVyKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oXCJDYW5ub3QgcmVtb3ZlIG5vbmV4aXN0ZW50IHNlcnZlciBcIiArIHNlcnZlcklkKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnNlcnZlckJ5SWQuZGVsZXRlKHNlcnZlcklkKTtcbiAgICAgICAgdGhpcy5sYXN0Rm9yZ290dGVuU2VydmVyID0gc2VydmVyO1xuICAgICAgICB0aGlzLnN0b3JlU2VydmVycygpO1xuICAgICAgICB0aGlzLmV2ZW50UXVldWUuZW5xdWV1ZShuZXcgZXZlbnRzLlNlcnZlckZvcmdvdHRlbihzZXJ2ZXIpKTtcbiAgICB9O1xuICAgIFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5LnByb3RvdHlwZS51bmRvRm9yZ2V0ID0gZnVuY3Rpb24gKHNlcnZlcklkKSB7XG4gICAgICAgIGlmICghdGhpcy5sYXN0Rm9yZ290dGVuU2VydmVyKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oJ05vIGZvcmdvdHRlbiBzZXJ2ZXIgdG8gdW5mb3JnZXQnKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICh0aGlzLmxhc3RGb3Jnb3R0ZW5TZXJ2ZXIuaWQgIT09IHNlcnZlcklkKSB7XG4gICAgICAgICAgICBjb25zb2xlLndhcm4oJ2lkIG9mIGZvcmdvdHRlbiBzZXJ2ZXInLCB0aGlzLmxhc3RGb3Jnb3R0ZW5TZXJ2ZXIsICdkb2VzIG5vdCBtYXRjaCcsIHNlcnZlcklkKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnNlcnZlckJ5SWQuc2V0KHRoaXMubGFzdEZvcmdvdHRlblNlcnZlci5pZCwgdGhpcy5sYXN0Rm9yZ290dGVuU2VydmVyKTtcbiAgICAgICAgdGhpcy5zdG9yZVNlcnZlcnMoKTtcbiAgICAgICAgdGhpcy5ldmVudFF1ZXVlLmVucXVldWUobmV3IGV2ZW50cy5TZXJ2ZXJGb3JnZXRVbmRvbmUodGhpcy5sYXN0Rm9yZ290dGVuU2VydmVyKSk7XG4gICAgICAgIHRoaXMubGFzdEZvcmdvdHRlblNlcnZlciA9IG51bGw7XG4gICAgfTtcbiAgICBQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeS5wcm90b3R5cGUuY29udGFpbnNTZXJ2ZXIgPSBmdW5jdGlvbiAoY29uZmlnKSB7XG4gICAgICAgIHJldHVybiAhIXRoaXMuc2VydmVyRnJvbUNvbmZpZyhjb25maWcpO1xuICAgIH07XG4gICAgUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkucHJvdG90eXBlLnNlcnZlckZyb21Db25maWcgPSBmdW5jdGlvbiAoY29uZmlnKSB7XG4gICAgICAgIHZhciBlXzEsIF9hO1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgZm9yICh2YXIgX2IgPSBfX3ZhbHVlcyh0aGlzLmdldEFsbCgpKSwgX2MgPSBfYi5uZXh0KCk7ICFfYy5kb25lOyBfYyA9IF9iLm5leHQoKSkge1xuICAgICAgICAgICAgICAgIHZhciBzZXJ2ZXIgPSBfYy52YWx1ZTtcbiAgICAgICAgICAgICAgICBpZiAoY29uZmlnc01hdGNoKHNlcnZlci5jb25maWcsIGNvbmZpZykpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHNlcnZlcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGVfMV8xKSB7IGVfMSA9IHsgZXJyb3I6IGVfMV8xIH07IH1cbiAgICAgICAgZmluYWxseSB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGlmIChfYyAmJiAhX2MuZG9uZSAmJiAoX2EgPSBfYi5yZXR1cm4pKSBfYS5jYWxsKF9iKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGZpbmFsbHkgeyBpZiAoZV8xKSB0aHJvdyBlXzEuZXJyb3I7IH1cbiAgICAgICAgfVxuICAgIH07XG4gICAgUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkucHJvdG90eXBlLnN0b3JlU2VydmVycyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdmFyIGVfMiwgX2E7XG4gICAgICAgIHZhciBjb25maWdCeUlkID0ge307XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBmb3IgKHZhciBfYiA9IF9fdmFsdWVzKHRoaXMuc2VydmVyQnlJZC52YWx1ZXMoKSksIF9jID0gX2IubmV4dCgpOyAhX2MuZG9uZTsgX2MgPSBfYi5uZXh0KCkpIHtcbiAgICAgICAgICAgICAgICB2YXIgc2VydmVyID0gX2MudmFsdWU7XG4gICAgICAgICAgICAgICAgY29uZmlnQnlJZFtzZXJ2ZXIuaWRdID0gc2VydmVyLmNvbmZpZztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBjYXRjaCAoZV8yXzEpIHsgZV8yID0geyBlcnJvcjogZV8yXzEgfTsgfVxuICAgICAgICBmaW5hbGx5IHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgaWYgKF9jICYmICFfYy5kb25lICYmIChfYSA9IF9iLnJldHVybikpIF9hLmNhbGwoX2IpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZmluYWxseSB7IGlmIChlXzIpIHRocm93IGVfMi5lcnJvcjsgfVxuICAgICAgICB9XG4gICAgICAgIHZhciBqc29uID0gSlNPTi5zdHJpbmdpZnkoY29uZmlnQnlJZCk7XG4gICAgICAgIHRoaXMuc3RvcmFnZS5zZXRJdGVtKFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5LlNFUlZFUlNfU1RPUkFHRV9LRVksIGpzb24pO1xuICAgIH07XG4gICAgLy8gTG9hZHMgc2VydmVycyBmcm9tIHN0b3JhZ2UsXG4gICAgLy8gcmFpc2luZyBhbiBlcnJvciBpZiB0aGVyZSBpcyBhbnkgcHJvYmxlbSBsb2FkaW5nLlxuICAgIFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5LnByb3RvdHlwZS5sb2FkU2VydmVycyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgdGhpcy5zZXJ2ZXJCeUlkID0gbmV3IE1hcCgpO1xuICAgICAgICB2YXIgc2VydmVyc0pzb24gPSB0aGlzLnN0b3JhZ2UuZ2V0SXRlbShQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeS5TRVJWRVJTX1NUT1JBR0VfS0VZKTtcbiAgICAgICAgaWYgKCFzZXJ2ZXJzSnNvbikge1xuICAgICAgICAgICAgY29uc29sZS5kZWJ1ZyhcIm5vIHNlcnZlcnMgZm91bmQgaW4gc3RvcmFnZVwiKTtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICB2YXIgY29uZmlnQnlJZCA9IHt9O1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgY29uZmlnQnlJZCA9IEpTT04ucGFyc2Uoc2VydmVyc0pzb24pO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJjb3VsZCBub3QgcGFyc2Ugc2F2ZWQgc2VydmVyczogXCIgKyBlLm1lc3NhZ2UpO1xuICAgICAgICB9XG4gICAgICAgIGZvciAodmFyIHNlcnZlcklkIGluIGNvbmZpZ0J5SWQpIHtcbiAgICAgICAgICAgIGlmIChjb25maWdCeUlkLmhhc093blByb3BlcnR5KHNlcnZlcklkKSkge1xuICAgICAgICAgICAgICAgIHZhciBjb25maWcgPSBjb25maWdCeUlkW3NlcnZlcklkXTtcbiAgICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgICAgICB2YXIgc2VydmVyID0gdGhpcy5jcmVhdGVTZXJ2ZXIoc2VydmVySWQsIGNvbmZpZywgdGhpcy5ldmVudFF1ZXVlKTtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXJ2ZXJCeUlkLnNldChzZXJ2ZXJJZCwgc2VydmVyKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gRG9uJ3QgcHJvcGFnYXRlIHNvIG90aGVyIHN0b3JlZCBzZXJ2ZXJzIGNhbiBiZSBjcmVhdGVkLlxuICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH07XG4gICAgLy8gTmFtZSBieSB3aGljaCBzZXJ2ZXJzIGFyZSBzYXZlZCB0byBzdG9yYWdlLlxuICAgIFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5LlNFUlZFUlNfU1RPUkFHRV9LRVkgPSAnc2VydmVycyc7XG4gICAgcmV0dXJuIFBlcnNpc3RlbnRTZXJ2ZXJSZXBvc2l0b3J5O1xufSgpKTtcbmV4cG9ydHMuUGVyc2lzdGVudFNlcnZlclJlcG9zaXRvcnkgPSBQZXJzaXN0ZW50U2VydmVyUmVwb3NpdG9yeTtcbmZ1bmN0aW9uIGNvbmZpZ3NNYXRjaChsZWZ0LCByaWdodCkge1xuICAgIHJldHVybiBsZWZ0Lmhvc3QgPT09IHJpZ2h0Lmhvc3QgJiYgbGVmdC5wb3J0ID09PSByaWdodC5wb3J0ICYmIGxlZnQubWV0aG9kID09PSByaWdodC5tZXRob2QgJiZcbiAgICAgICAgbGVmdC5wYXNzd29yZCA9PT0gcmlnaHQucGFzc3dvcmQ7XG59XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCAyMDE4IFRoZSBPdXRsaW5lIEF1dGhvcnNcbi8vXG4vLyBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuLy8geW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuLy8gWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4vL1xuLy8gICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbi8vXG4vLyBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4vLyBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4vLyBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbi8vIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbi8vIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxudmFyIF9fdmFsdWVzID0gKHRoaXMgJiYgdGhpcy5fX3ZhbHVlcykgfHwgZnVuY3Rpb24obykge1xuICAgIHZhciBzID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIFN5bWJvbC5pdGVyYXRvciwgbSA9IHMgJiYgb1tzXSwgaSA9IDA7XG4gICAgaWYgKG0pIHJldHVybiBtLmNhbGwobyk7XG4gICAgaWYgKG8gJiYgdHlwZW9mIG8ubGVuZ3RoID09PSBcIm51bWJlclwiKSByZXR1cm4ge1xuICAgICAgICBuZXh0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBpZiAobyAmJiBpID49IG8ubGVuZ3RoKSBvID0gdm9pZCAwO1xuICAgICAgICAgICAgcmV0dXJuIHsgdmFsdWU6IG8gJiYgb1tpKytdLCBkb25lOiAhbyB9O1xuICAgICAgICB9XG4gICAgfTtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKHMgPyBcIk9iamVjdCBpcyBub3QgaXRlcmFibGUuXCIgOiBcIlN5bWJvbC5pdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XG59O1xudmFyIF9fcmVhZCA9ICh0aGlzICYmIHRoaXMuX19yZWFkKSB8fCBmdW5jdGlvbiAobywgbikge1xuICAgIHZhciBtID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIG9bU3ltYm9sLml0ZXJhdG9yXTtcbiAgICBpZiAoIW0pIHJldHVybiBvO1xuICAgIHZhciBpID0gbS5jYWxsKG8pLCByLCBhciA9IFtdLCBlO1xuICAgIHRyeSB7XG4gICAgICAgIHdoaWxlICgobiA9PT0gdm9pZCAwIHx8IG4tLSA+IDApICYmICEociA9IGkubmV4dCgpKS5kb25lKSBhci5wdXNoKHIudmFsdWUpO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHsgZSA9IHsgZXJyb3I6IGVycm9yIH07IH1cbiAgICBmaW5hbGx5IHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGlmIChyICYmICFyLmRvbmUgJiYgKG0gPSBpW1wicmV0dXJuXCJdKSkgbS5jYWxsKGkpO1xuICAgICAgICB9XG4gICAgICAgIGZpbmFsbHkgeyBpZiAoZSkgdGhyb3cgZS5lcnJvcjsgfVxuICAgIH1cbiAgICByZXR1cm4gYXI7XG59O1xuT2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFwiX19lc01vZHVsZVwiLCB7IHZhbHVlOiB0cnVlIH0pO1xuLy8gU2V0dGluZyBrZXlzIHN1cHBvcnRlZCBieSB0aGUgYFNldHRpbmdzYCBjbGFzcy5cbnZhciBTZXR0aW5nc0tleTtcbihmdW5jdGlvbiAoU2V0dGluZ3NLZXkpIHtcbiAgICBTZXR0aW5nc0tleVtcIlZQTl9XQVJOSU5HX0RJU01JU1NFRFwiXSA9IFwidnBuLXdhcm5pbmctZGlzbWlzc2VkXCI7XG4gICAgU2V0dGluZ3NLZXlbXCJBVVRPX0NPTk5FQ1RfRElBTE9HX0RJU01JU1NFRFwiXSA9IFwiYXV0by1jb25uZWN0LWRpYWxvZy1kaXNtaXNzZWRcIjtcbiAgICBTZXR0aW5nc0tleVtcIlBSSVZBQ1lfQUNLXCJdID0gXCJwcml2YWN5LWFja1wiO1xufSkoU2V0dGluZ3NLZXkgPSBleHBvcnRzLlNldHRpbmdzS2V5IHx8IChleHBvcnRzLlNldHRpbmdzS2V5ID0ge30pKTtcbi8vIFBlcnNpc3RlbnQgc3RvcmFnZSBmb3IgdXNlciBzZXR0aW5ncyB0aGF0IHN1cHBvcnRzIGEgbGltaXRlZCBzZXQgb2Yga2V5cy5cbnZhciBTZXR0aW5ncyA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBTZXR0aW5ncyhzdG9yYWdlLCB2YWxpZEtleXMpIHtcbiAgICAgICAgaWYgKHN0b3JhZ2UgPT09IHZvaWQgMCkgeyBzdG9yYWdlID0gd2luZG93LmxvY2FsU3RvcmFnZTsgfVxuICAgICAgICBpZiAodmFsaWRLZXlzID09PSB2b2lkIDApIHsgdmFsaWRLZXlzID0gT2JqZWN0LnZhbHVlcyhTZXR0aW5nc0tleSk7IH1cbiAgICAgICAgdGhpcy5zdG9yYWdlID0gc3RvcmFnZTtcbiAgICAgICAgdGhpcy52YWxpZEtleXMgPSB2YWxpZEtleXM7XG4gICAgICAgIHRoaXMuc2V0dGluZ3MgPSBuZXcgTWFwKCk7XG4gICAgICAgIHRoaXMubG9hZFNldHRpbmdzKCk7XG4gICAgfVxuICAgIFNldHRpbmdzLnByb3RvdHlwZS5nZXQgPSBmdW5jdGlvbiAoa2V5KSB7XG4gICAgICAgIHJldHVybiB0aGlzLnNldHRpbmdzLmdldChrZXkpO1xuICAgIH07XG4gICAgU2V0dGluZ3MucHJvdG90eXBlLnNldCA9IGZ1bmN0aW9uIChrZXksIHZhbHVlKSB7XG4gICAgICAgIGlmICghdGhpcy5pc1ZhbGlkU2V0dGluZyhrZXkpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJDYW5ub3Qgc2V0IGludmFsaWQga2V5IFwiICsga2V5KTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnNldHRpbmdzLnNldChrZXksIHZhbHVlKTtcbiAgICAgICAgdGhpcy5zdG9yZVNldHRpbmdzKCk7XG4gICAgfTtcbiAgICBTZXR0aW5ncy5wcm90b3R5cGUucmVtb3ZlID0gZnVuY3Rpb24gKGtleSkge1xuICAgICAgICB0aGlzLnNldHRpbmdzLmRlbGV0ZShrZXkpO1xuICAgICAgICB0aGlzLnN0b3JlU2V0dGluZ3MoKTtcbiAgICB9O1xuICAgIFNldHRpbmdzLnByb3RvdHlwZS5pc1ZhbGlkU2V0dGluZyA9IGZ1bmN0aW9uIChrZXkpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMudmFsaWRLZXlzLmluY2x1ZGVzKGtleSk7XG4gICAgfTtcbiAgICBTZXR0aW5ncy5wcm90b3R5cGUubG9hZFNldHRpbmdzID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgc2V0dGluZ3NKc29uID0gdGhpcy5zdG9yYWdlLmdldEl0ZW0oU2V0dGluZ3MuU1RPUkFHRV9LRVkpO1xuICAgICAgICBpZiAoIXNldHRpbmdzSnNvbikge1xuICAgICAgICAgICAgY29uc29sZS5kZWJ1ZyhcIk5vIHNldHRpbmdzIGZvdW5kIGluIHN0b3JhZ2VcIik7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgdmFyIHN0b3JhZ2VTZXR0aW5ncyA9IEpTT04ucGFyc2Uoc2V0dGluZ3NKc29uKTtcbiAgICAgICAgZm9yICh2YXIga2V5IGluIHN0b3JhZ2VTZXR0aW5ncykge1xuICAgICAgICAgICAgaWYgKHN0b3JhZ2VTZXR0aW5ncy5oYXNPd25Qcm9wZXJ0eShrZXkpKSB7XG4gICAgICAgICAgICAgICAgdGhpcy5zZXR0aW5ncy5zZXQoa2V5LCBzdG9yYWdlU2V0dGluZ3Nba2V5XSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9O1xuICAgIFNldHRpbmdzLnByb3RvdHlwZS5zdG9yZVNldHRpbmdzID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgZV8xLCBfYTtcbiAgICAgICAgdmFyIHN0b3JhZ2VTZXR0aW5ncyA9IHt9O1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgZm9yICh2YXIgX2IgPSBfX3ZhbHVlcyh0aGlzLnNldHRpbmdzKSwgX2MgPSBfYi5uZXh0KCk7ICFfYy5kb25lOyBfYyA9IF9iLm5leHQoKSkge1xuICAgICAgICAgICAgICAgIHZhciBfZCA9IF9fcmVhZChfYy52YWx1ZSwgMiksIGtleSA9IF9kWzBdLCB2YWx1ZSA9IF9kWzFdO1xuICAgICAgICAgICAgICAgIHN0b3JhZ2VTZXR0aW5nc1trZXldID0gdmFsdWU7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2ggKGVfMV8xKSB7IGVfMSA9IHsgZXJyb3I6IGVfMV8xIH07IH1cbiAgICAgICAgZmluYWxseSB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGlmIChfYyAmJiAhX2MuZG9uZSAmJiAoX2EgPSBfYi5yZXR1cm4pKSBfYS5jYWxsKF9iKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGZpbmFsbHkgeyBpZiAoZV8xKSB0aHJvdyBlXzEuZXJyb3I7IH1cbiAgICAgICAgfVxuICAgICAgICB2YXIgc3RvcmFnZVNldHRpbmdzSnNvbiA9IEpTT04uc3RyaW5naWZ5KHN0b3JhZ2VTZXR0aW5ncyk7XG4gICAgICAgIHRoaXMuc3RvcmFnZS5zZXRJdGVtKFNldHRpbmdzLlNUT1JBR0VfS0VZLCBzdG9yYWdlU2V0dGluZ3NKc29uKTtcbiAgICB9O1xuICAgIFNldHRpbmdzLlNUT1JBR0VfS0VZID0gJ3NldHRpbmdzJztcbiAgICByZXR1cm4gU2V0dGluZ3M7XG59KCkpO1xuZXhwb3J0cy5TZXR0aW5ncyA9IFNldHRpbmdzO1xuIiwiXCJ1c2Ugc3RyaWN0XCI7XG4vLyBDb3B5cmlnaHQgMjAxOCBUaGUgT3V0bGluZSBBdXRob3JzXG4vL1xuLy8gTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbi8vIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbi8vIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuLy9cbi8vICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4vL1xuLy8gVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuLy8gZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuLy8gV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4vLyBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4vLyBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbnZhciBBYnN0cmFjdFVwZGF0ZXIgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gQWJzdHJhY3RVcGRhdGVyKCkge1xuICAgICAgICB0aGlzLmxpc3RlbmVyID0gbnVsbDtcbiAgICB9XG4gICAgQWJzdHJhY3RVcGRhdGVyLnByb3RvdHlwZS5zZXRMaXN0ZW5lciA9IGZ1bmN0aW9uIChsaXN0ZW5lcikge1xuICAgICAgICB0aGlzLmxpc3RlbmVyID0gbGlzdGVuZXI7XG4gICAgfTtcbiAgICBBYnN0cmFjdFVwZGF0ZXIucHJvdG90eXBlLmVtaXRFdmVudCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKHRoaXMubGlzdGVuZXIpIHtcbiAgICAgICAgICAgIHRoaXMubGlzdGVuZXIoKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgcmV0dXJuIEFic3RyYWN0VXBkYXRlcjtcbn0oKSk7XG5leHBvcnRzLkFic3RyYWN0VXBkYXRlciA9IEFic3RyYWN0VXBkYXRlcjtcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG52YXIgX19leHRlbmRzID0gKHRoaXMgJiYgdGhpcy5fX2V4dGVuZHMpIHx8IChmdW5jdGlvbiAoKSB7XG4gICAgdmFyIGV4dGVuZFN0YXRpY3MgPSBmdW5jdGlvbiAoZCwgYikge1xuICAgICAgICBleHRlbmRTdGF0aWNzID0gT2JqZWN0LnNldFByb3RvdHlwZU9mIHx8XG4gICAgICAgICAgICAoeyBfX3Byb3RvX186IFtdIH0gaW5zdGFuY2VvZiBBcnJheSAmJiBmdW5jdGlvbiAoZCwgYikgeyBkLl9fcHJvdG9fXyA9IGI7IH0pIHx8XG4gICAgICAgICAgICBmdW5jdGlvbiAoZCwgYikgeyBmb3IgKHZhciBwIGluIGIpIGlmIChiLmhhc093blByb3BlcnR5KHApKSBkW3BdID0gYltwXTsgfTtcbiAgICAgICAgcmV0dXJuIGV4dGVuZFN0YXRpY3MoZCwgYik7XG4gICAgfTtcbiAgICByZXR1cm4gZnVuY3Rpb24gKGQsIGIpIHtcbiAgICAgICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcbiAgICAgICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XG4gICAgICAgIGQucHJvdG90eXBlID0gYiA9PT0gbnVsbCA/IE9iamVjdC5jcmVhdGUoYikgOiAoX18ucHJvdG90eXBlID0gYi5wcm90b3R5cGUsIG5ldyBfXygpKTtcbiAgICB9O1xufSkoKTtcbnZhciBfX3ZhbHVlcyA9ICh0aGlzICYmIHRoaXMuX192YWx1ZXMpIHx8IGZ1bmN0aW9uKG8pIHtcbiAgICB2YXIgcyA9IHR5cGVvZiBTeW1ib2wgPT09IFwiZnVuY3Rpb25cIiAmJiBTeW1ib2wuaXRlcmF0b3IsIG0gPSBzICYmIG9bc10sIGkgPSAwO1xuICAgIGlmIChtKSByZXR1cm4gbS5jYWxsKG8pO1xuICAgIGlmIChvICYmIHR5cGVvZiBvLmxlbmd0aCA9PT0gXCJudW1iZXJcIikgcmV0dXJuIHtcbiAgICAgICAgbmV4dDogZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgaWYgKG8gJiYgaSA+PSBvLmxlbmd0aCkgbyA9IHZvaWQgMDtcbiAgICAgICAgICAgIHJldHVybiB7IHZhbHVlOiBvICYmIG9baSsrXSwgZG9uZTogIW8gfTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihzID8gXCJPYmplY3QgaXMgbm90IGl0ZXJhYmxlLlwiIDogXCJTeW1ib2wuaXRlcmF0b3IgaXMgbm90IGRlZmluZWQuXCIpO1xufTtcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbi8vLyA8cmVmZXJlbmNlIHBhdGg9Jy4uLy4uL3R5cGVzL2FtYmllbnQvd2ViaW50ZW50cy5kLnRzJy8+XG52YXIgVXJsSW50ZXJjZXB0b3IgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gVXJsSW50ZXJjZXB0b3IoKSB7XG4gICAgICAgIHRoaXMubGlzdGVuZXJzID0gW107XG4gICAgfVxuICAgIFVybEludGVyY2VwdG9yLnByb3RvdHlwZS5yZWdpc3Rlckxpc3RlbmVyID0gZnVuY3Rpb24gKGxpc3RlbmVyKSB7XG4gICAgICAgIHRoaXMubGlzdGVuZXJzLnB1c2gobGlzdGVuZXIpO1xuICAgICAgICBpZiAodGhpcy5sYXVuY2hVcmwpIHtcbiAgICAgICAgICAgIGxpc3RlbmVyKHRoaXMubGF1bmNoVXJsKTtcbiAgICAgICAgICAgIHRoaXMubGF1bmNoVXJsID0gdW5kZWZpbmVkO1xuICAgICAgICB9XG4gICAgfTtcbiAgICBVcmxJbnRlcmNlcHRvci5wcm90b3R5cGUuZXhlY3V0ZUxpc3RlbmVycyA9IGZ1bmN0aW9uICh1cmwpIHtcbiAgICAgICAgdmFyIGVfMSwgX2E7XG4gICAgICAgIGlmICghdXJsKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCF0aGlzLmxpc3RlbmVycy5sZW5ndGgpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCdubyBsaXN0ZW5lcnMgaGF2ZSBiZWVuIGFkZGVkLCBkZWxheWluZyBpbnRlbnQgZmlyaW5nJyk7XG4gICAgICAgICAgICB0aGlzLmxhdW5jaFVybCA9IHVybDtcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgICB0cnkge1xuICAgICAgICAgICAgZm9yICh2YXIgX2IgPSBfX3ZhbHVlcyh0aGlzLmxpc3RlbmVycyksIF9jID0gX2IubmV4dCgpOyAhX2MuZG9uZTsgX2MgPSBfYi5uZXh0KCkpIHtcbiAgICAgICAgICAgICAgICB2YXIgbGlzdGVuZXIgPSBfYy52YWx1ZTtcbiAgICAgICAgICAgICAgICBsaXN0ZW5lcih1cmwpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGNhdGNoIChlXzFfMSkgeyBlXzEgPSB7IGVycm9yOiBlXzFfMSB9OyB9XG4gICAgICAgIGZpbmFsbHkge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBpZiAoX2MgJiYgIV9jLmRvbmUgJiYgKF9hID0gX2IucmV0dXJuKSkgX2EuY2FsbChfYik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBmaW5hbGx5IHsgaWYgKGVfMSkgdGhyb3cgZV8xLmVycm9yOyB9XG4gICAgICAgIH1cbiAgICB9O1xuICAgIHJldHVybiBVcmxJbnRlcmNlcHRvcjtcbn0oKSk7XG5leHBvcnRzLlVybEludGVyY2VwdG9yID0gVXJsSW50ZXJjZXB0b3I7XG52YXIgQW5kcm9pZFVybEludGVyY2VwdG9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhBbmRyb2lkVXJsSW50ZXJjZXB0b3IsIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gQW5kcm9pZFVybEludGVyY2VwdG9yKCkge1xuICAgICAgICB2YXIgX3RoaXMgPSBfc3VwZXIuY2FsbCh0aGlzKSB8fCB0aGlzO1xuICAgICAgICB3aW5kb3cud2ViaW50ZW50LmdldFVyaShmdW5jdGlvbiAobGF1bmNoVXJsKSB7XG4gICAgICAgICAgICB3aW5kb3cud2ViaW50ZW50Lm9uTmV3SW50ZW50KF90aGlzLmV4ZWN1dGVMaXN0ZW5lcnMuYmluZChfdGhpcykpO1xuICAgICAgICAgICAgX3RoaXMuZXhlY3V0ZUxpc3RlbmVycyhsYXVuY2hVcmwpO1xuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIF90aGlzO1xuICAgIH1cbiAgICByZXR1cm4gQW5kcm9pZFVybEludGVyY2VwdG9yO1xufShVcmxJbnRlcmNlcHRvcikpO1xuZXhwb3J0cy5BbmRyb2lkVXJsSW50ZXJjZXB0b3IgPSBBbmRyb2lkVXJsSW50ZXJjZXB0b3I7XG52YXIgQXBwbGVVcmxJbnRlcmNlcHRvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoQXBwbGVVcmxJbnRlcmNlcHRvciwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBBcHBsZVVybEludGVyY2VwdG9yKGxhdW5jaFVybCkge1xuICAgICAgICB2YXIgX3RoaXMgPSBfc3VwZXIuY2FsbCh0aGlzKSB8fCB0aGlzO1xuICAgICAgICAvLyBjb3Jkb3ZhLVtpb3N8b3N4XSBjYWxsIGEgZ2xvYmFsIGZ1bmN0aW9uIHdpdGggdGhpcyBzaWduYXR1cmUgd2hlbiBhIFVSTCBpcyBpbnRlcmNlcHRlZC5cbiAgICAgICAgLy8gV2UgZGVmaW5lIGl0IGluIHxjb3Jkb3ZhX21haW58LCByZWRlZmluZSBpdCB0byB1c2UgdGhpcyBpbnRlcmNlcHRvci5cbiAgICAgICAgd2luZG93LmhhbmRsZU9wZW5VUkwgPSBmdW5jdGlvbiAodXJsKSB7XG4gICAgICAgICAgICBfdGhpcy5leGVjdXRlTGlzdGVuZXJzKHVybCk7XG4gICAgICAgIH07XG4gICAgICAgIGlmIChsYXVuY2hVcmwpIHtcbiAgICAgICAgICAgIF90aGlzLmV4ZWN1dGVMaXN0ZW5lcnMobGF1bmNoVXJsKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgfVxuICAgIHJldHVybiBBcHBsZVVybEludGVyY2VwdG9yO1xufShVcmxJbnRlcmNlcHRvcikpO1xuZXhwb3J0cy5BcHBsZVVybEludGVyY2VwdG9yID0gQXBwbGVVcmxJbnRlcmNlcHRvcjtcbiIsIlwidXNlIHN0cmljdFwiO1xuLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG52YXIgX19leHRlbmRzID0gKHRoaXMgJiYgdGhpcy5fX2V4dGVuZHMpIHx8IChmdW5jdGlvbiAoKSB7XG4gICAgdmFyIGV4dGVuZFN0YXRpY3MgPSBmdW5jdGlvbiAoZCwgYikge1xuICAgICAgICBleHRlbmRTdGF0aWNzID0gT2JqZWN0LnNldFByb3RvdHlwZU9mIHx8XG4gICAgICAgICAgICAoeyBfX3Byb3RvX186IFtdIH0gaW5zdGFuY2VvZiBBcnJheSAmJiBmdW5jdGlvbiAoZCwgYikgeyBkLl9fcHJvdG9fXyA9IGI7IH0pIHx8XG4gICAgICAgICAgICBmdW5jdGlvbiAoZCwgYikgeyBmb3IgKHZhciBwIGluIGIpIGlmIChiLmhhc093blByb3BlcnR5KHApKSBkW3BdID0gYltwXTsgfTtcbiAgICAgICAgcmV0dXJuIGV4dGVuZFN0YXRpY3MoZCwgYik7XG4gICAgfTtcbiAgICByZXR1cm4gZnVuY3Rpb24gKGQsIGIpIHtcbiAgICAgICAgZXh0ZW5kU3RhdGljcyhkLCBiKTtcbiAgICAgICAgZnVuY3Rpb24gX18oKSB7IHRoaXMuY29uc3RydWN0b3IgPSBkOyB9XG4gICAgICAgIGQucHJvdG90eXBlID0gYiA9PT0gbnVsbCA/IE9iamVjdC5jcmVhdGUoYikgOiAoX18ucHJvdG90eXBlID0gYi5wcm90b3R5cGUsIG5ldyBfXygpKTtcbiAgICB9O1xufSkoKTtcbk9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCBcIl9fZXNNb2R1bGVcIiwgeyB2YWx1ZTogdHJ1ZSB9KTtcbnZhciBPdXRsaW5lRXJyb3IgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKE91dGxpbmVFcnJvciwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBPdXRsaW5lRXJyb3IobWVzc2FnZSkge1xuICAgICAgICB2YXIgX25ld1RhcmdldCA9IHRoaXMuY29uc3RydWN0b3I7XG4gICAgICAgIHZhciBfdGhpcyA9IFxuICAgICAgICAvLyByZWY6XG4gICAgICAgIC8vIGh0dHBzOi8vd3d3LnR5cGVzY3JpcHRsYW5nLm9yZy9kb2NzL2hhbmRib29rL3JlbGVhc2Utbm90ZXMvdHlwZXNjcmlwdC0yLTIuaHRtbCNzdXBwb3J0LWZvci1uZXd0YXJnZXRcbiAgICAgICAgX3N1cGVyLmNhbGwodGhpcywgbWVzc2FnZSkgfHwgdGhpcztcbiAgICAgICAgT2JqZWN0LnNldFByb3RvdHlwZU9mKF90aGlzLCBfbmV3VGFyZ2V0LnByb3RvdHlwZSk7IC8vIHJlc3RvcmUgcHJvdG90eXBlIGNoYWluXG4gICAgICAgIF90aGlzLm5hbWUgPSBfbmV3VGFyZ2V0Lm5hbWU7XG4gICAgICAgIHJldHVybiBfdGhpcztcbiAgICB9XG4gICAgcmV0dXJuIE91dGxpbmVFcnJvcjtcbn0oRXJyb3IpKTtcbmV4cG9ydHMuT3V0bGluZUVycm9yID0gT3V0bGluZUVycm9yO1xudmFyIFNlcnZlckFscmVhZHlBZGRlZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoU2VydmVyQWxyZWFkeUFkZGVkLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIFNlcnZlckFscmVhZHlBZGRlZChzZXJ2ZXIpIHtcbiAgICAgICAgdmFyIF90aGlzID0gX3N1cGVyLmNhbGwodGhpcykgfHwgdGhpcztcbiAgICAgICAgX3RoaXMuc2VydmVyID0gc2VydmVyO1xuICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgfVxuICAgIHJldHVybiBTZXJ2ZXJBbHJlYWR5QWRkZWQ7XG59KE91dGxpbmVFcnJvcikpO1xuZXhwb3J0cy5TZXJ2ZXJBbHJlYWR5QWRkZWQgPSBTZXJ2ZXJBbHJlYWR5QWRkZWQ7XG52YXIgU2VydmVySW5jb21wYXRpYmxlID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhTZXJ2ZXJJbmNvbXBhdGlibGUsIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gU2VydmVySW5jb21wYXRpYmxlKG1lc3NhZ2UpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlci5jYWxsKHRoaXMsIG1lc3NhZ2UpIHx8IHRoaXM7XG4gICAgfVxuICAgIHJldHVybiBTZXJ2ZXJJbmNvbXBhdGlibGU7XG59KE91dGxpbmVFcnJvcikpO1xuZXhwb3J0cy5TZXJ2ZXJJbmNvbXBhdGlibGUgPSBTZXJ2ZXJJbmNvbXBhdGlibGU7XG52YXIgU2VydmVyVXJsSW52YWxpZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoU2VydmVyVXJsSW52YWxpZCwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJVcmxJbnZhbGlkKG1lc3NhZ2UpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlci5jYWxsKHRoaXMsIG1lc3NhZ2UpIHx8IHRoaXM7XG4gICAgfVxuICAgIHJldHVybiBTZXJ2ZXJVcmxJbnZhbGlkO1xufShPdXRsaW5lRXJyb3IpKTtcbmV4cG9ydHMuU2VydmVyVXJsSW52YWxpZCA9IFNlcnZlclVybEludmFsaWQ7XG52YXIgT3BlcmF0aW9uVGltZWRPdXQgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKE9wZXJhdGlvblRpbWVkT3V0LCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIE9wZXJhdGlvblRpbWVkT3V0KHRpbWVvdXRNcywgb3BlcmF0aW9uTmFtZSkge1xuICAgICAgICB2YXIgX3RoaXMgPSBfc3VwZXIuY2FsbCh0aGlzKSB8fCB0aGlzO1xuICAgICAgICBfdGhpcy50aW1lb3V0TXMgPSB0aW1lb3V0TXM7XG4gICAgICAgIF90aGlzLm9wZXJhdGlvbk5hbWUgPSBvcGVyYXRpb25OYW1lO1xuICAgICAgICByZXR1cm4gX3RoaXM7XG4gICAgfVxuICAgIHJldHVybiBPcGVyYXRpb25UaW1lZE91dDtcbn0oT3V0bGluZUVycm9yKSk7XG5leHBvcnRzLk9wZXJhdGlvblRpbWVkT3V0ID0gT3BlcmF0aW9uVGltZWRPdXQ7XG52YXIgRmVlZGJhY2tTdWJtaXNzaW9uRXJyb3IgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKEZlZWRiYWNrU3VibWlzc2lvbkVycm9yLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIEZlZWRiYWNrU3VibWlzc2lvbkVycm9yKCkge1xuICAgICAgICByZXR1cm4gX3N1cGVyLmNhbGwodGhpcykgfHwgdGhpcztcbiAgICB9XG4gICAgcmV0dXJuIEZlZWRiYWNrU3VibWlzc2lvbkVycm9yO1xufShPdXRsaW5lRXJyb3IpKTtcbmV4cG9ydHMuRmVlZGJhY2tTdWJtaXNzaW9uRXJyb3IgPSBGZWVkYmFja1N1Ym1pc3Npb25FcnJvcjtcbi8vIEVycm9yIHRocm93biBieSBcIm5hdGl2ZVwiIGNvZGUuXG4vL1xuLy8gTXVzdCBiZSBrZXB0IGluIHN5bmMgd2l0aCBpdHMgQ29yZG92YSBkb3BwZWxnYW5nZXI6XG4vLyAgIGNvcmRvdmEtcGx1Z2luLW91dGxpbmUvb3V0bGluZVBsdWdpbi5qc1xuLy9cbi8vIFRPRE86IFJlbmFtZSB0aGlzIGNsYXNzLCBcInBsdWdpblwiIGlzIGEgcG9vciBuYW1lIHNpbmNlIHRoZSBFbGVjdHJvbiBhcHBzIGRvIG5vdCBoYXZlIHBsdWdpbnMuXG52YXIgT3V0bGluZVBsdWdpbkVycm9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhPdXRsaW5lUGx1Z2luRXJyb3IsIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gT3V0bGluZVBsdWdpbkVycm9yKGVycm9yQ29kZSkge1xuICAgICAgICB2YXIgX3RoaXMgPSBfc3VwZXIuY2FsbCh0aGlzKSB8fCB0aGlzO1xuICAgICAgICBfdGhpcy5lcnJvckNvZGUgPSBlcnJvckNvZGU7XG4gICAgICAgIHJldHVybiBfdGhpcztcbiAgICB9XG4gICAgcmV0dXJuIE91dGxpbmVQbHVnaW5FcnJvcjtcbn0oT3V0bGluZUVycm9yKSk7XG5leHBvcnRzLk91dGxpbmVQbHVnaW5FcnJvciA9IE91dGxpbmVQbHVnaW5FcnJvcjtcbi8vIE1hcmtlciBjbGFzcyBmb3IgZXJyb3JzIG9yaWdpbmF0aW5nIGluIG5hdGl2ZSBjb2RlLlxuLy8gQmlmdXJjYXRlcyBpbnRvIHR3byBzdWJjbGFzc2VzOlxuLy8gIC0gXCJleHBlY3RlZFwiIGVycm9ycyBvcmlnaW5hdGluZyBpbiBuYXRpdmUgY29kZSwgZS5nLiBpbmNvcnJlY3QgcGFzc3dvcmRcbi8vICAtIFwidW5leHBlY3RlZFwiIGVycm9ycyBvcmlnaW5hdGluZyBpbiBuYXRpdmUgY29kZSwgZS5nLiB1bmhhbmRsZWQgcm91dGluZyB0YWJsZVxudmFyIE5hdGl2ZUVycm9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhOYXRpdmVFcnJvciwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBOYXRpdmVFcnJvcigpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gTmF0aXZlRXJyb3I7XG59KE91dGxpbmVFcnJvcikpO1xuZXhwb3J0cy5OYXRpdmVFcnJvciA9IE5hdGl2ZUVycm9yO1xudmFyIFJlZ3VsYXJOYXRpdmVFcnJvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoUmVndWxhck5hdGl2ZUVycm9yLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIFJlZ3VsYXJOYXRpdmVFcnJvcigpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gUmVndWxhck5hdGl2ZUVycm9yO1xufShOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5SZWd1bGFyTmF0aXZlRXJyb3IgPSBSZWd1bGFyTmF0aXZlRXJyb3I7XG52YXIgUmVkRmxhZ05hdGl2ZUVycm9yID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhSZWRGbGFnTmF0aXZlRXJyb3IsIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gUmVkRmxhZ05hdGl2ZUVycm9yKCkge1xuICAgICAgICByZXR1cm4gX3N1cGVyICE9PSBudWxsICYmIF9zdXBlci5hcHBseSh0aGlzLCBhcmd1bWVudHMpIHx8IHRoaXM7XG4gICAgfVxuICAgIHJldHVybiBSZWRGbGFnTmF0aXZlRXJyb3I7XG59KE5hdGl2ZUVycm9yKSk7XG5leHBvcnRzLlJlZEZsYWdOYXRpdmVFcnJvciA9IFJlZEZsYWdOYXRpdmVFcnJvcjtcbi8vLy8vL1xuLy8gXCJFeHBlY3RlZFwiIGVycm9ycy5cbi8vLy8vL1xudmFyIFVuZXhwZWN0ZWRQbHVnaW5FcnJvciA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoVW5leHBlY3RlZFBsdWdpbkVycm9yLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIFVuZXhwZWN0ZWRQbHVnaW5FcnJvcigpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gVW5leHBlY3RlZFBsdWdpbkVycm9yO1xufShSZWd1bGFyTmF0aXZlRXJyb3IpKTtcbmV4cG9ydHMuVW5leHBlY3RlZFBsdWdpbkVycm9yID0gVW5leHBlY3RlZFBsdWdpbkVycm9yO1xudmFyIFZwblBlcm1pc3Npb25Ob3RHcmFudGVkID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhWcG5QZXJtaXNzaW9uTm90R3JhbnRlZCwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBWcG5QZXJtaXNzaW9uTm90R3JhbnRlZCgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gVnBuUGVybWlzc2lvbk5vdEdyYW50ZWQ7XG59KFJlZ3VsYXJOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5WcG5QZXJtaXNzaW9uTm90R3JhbnRlZCA9IFZwblBlcm1pc3Npb25Ob3RHcmFudGVkO1xudmFyIEludmFsaWRTZXJ2ZXJDcmVkZW50aWFscyA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoSW52YWxpZFNlcnZlckNyZWRlbnRpYWxzLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIEludmFsaWRTZXJ2ZXJDcmVkZW50aWFscygpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gSW52YWxpZFNlcnZlckNyZWRlbnRpYWxzO1xufShSZWd1bGFyTmF0aXZlRXJyb3IpKTtcbmV4cG9ydHMuSW52YWxpZFNlcnZlckNyZWRlbnRpYWxzID0gSW52YWxpZFNlcnZlckNyZWRlbnRpYWxzO1xudmFyIFJlbW90ZVVkcEZvcndhcmRpbmdEaXNhYmxlZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoUmVtb3RlVWRwRm9yd2FyZGluZ0Rpc2FibGVkLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIFJlbW90ZVVkcEZvcndhcmRpbmdEaXNhYmxlZCgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gUmVtb3RlVWRwRm9yd2FyZGluZ0Rpc2FibGVkO1xufShSZWd1bGFyTmF0aXZlRXJyb3IpKTtcbmV4cG9ydHMuUmVtb3RlVWRwRm9yd2FyZGluZ0Rpc2FibGVkID0gUmVtb3RlVWRwRm9yd2FyZGluZ0Rpc2FibGVkO1xudmFyIFNlcnZlclVucmVhY2hhYmxlID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhTZXJ2ZXJVbnJlYWNoYWJsZSwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJVbnJlYWNoYWJsZSgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gU2VydmVyVW5yZWFjaGFibGU7XG59KFJlZ3VsYXJOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5TZXJ2ZXJVbnJlYWNoYWJsZSA9IFNlcnZlclVucmVhY2hhYmxlO1xudmFyIElsbGVnYWxTZXJ2ZXJDb25maWd1cmF0aW9uID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhJbGxlZ2FsU2VydmVyQ29uZmlndXJhdGlvbiwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBJbGxlZ2FsU2VydmVyQ29uZmlndXJhdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gSWxsZWdhbFNlcnZlckNvbmZpZ3VyYXRpb247XG59KFJlZ3VsYXJOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5JbGxlZ2FsU2VydmVyQ29uZmlndXJhdGlvbiA9IElsbGVnYWxTZXJ2ZXJDb25maWd1cmF0aW9uO1xudmFyIE5vQWRtaW5QZXJtaXNzaW9ucyA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoTm9BZG1pblBlcm1pc3Npb25zLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIE5vQWRtaW5QZXJtaXNzaW9ucygpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gTm9BZG1pblBlcm1pc3Npb25zO1xufShSZWd1bGFyTmF0aXZlRXJyb3IpKTtcbmV4cG9ydHMuTm9BZG1pblBlcm1pc3Npb25zID0gTm9BZG1pblBlcm1pc3Npb25zO1xudmFyIFN5c3RlbUNvbmZpZ3VyYXRpb25FeGNlcHRpb24gPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKFN5c3RlbUNvbmZpZ3VyYXRpb25FeGNlcHRpb24sIF9zdXBlcik7XG4gICAgZnVuY3Rpb24gU3lzdGVtQ29uZmlndXJhdGlvbkV4Y2VwdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gU3lzdGVtQ29uZmlndXJhdGlvbkV4Y2VwdGlvbjtcbn0oUmVndWxhck5hdGl2ZUVycm9yKSk7XG5leHBvcnRzLlN5c3RlbUNvbmZpZ3VyYXRpb25FeGNlcHRpb24gPSBTeXN0ZW1Db25maWd1cmF0aW9uRXhjZXB0aW9uO1xuLy8vLy8vXG4vLyBOb3csIFwidW5leHBlY3RlZFwiIGVycm9ycy5cbi8vIFVzZSB0aGVzZSBzcGFyaW5nbHkgYmVjYXVzZSBlYWNoIG9jY3VycmVuY2UgdHJpZ2dlcnMgYSBTZW50cnkgcmVwb3J0LlxuLy8vLy8vXG4vLyBXaW5kb3dzLlxudmFyIFNoYWRvd3NvY2tzU3RhcnRGYWlsdXJlID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhTaGFkb3dzb2Nrc1N0YXJ0RmFpbHVyZSwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBTaGFkb3dzb2Nrc1N0YXJ0RmFpbHVyZSgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gU2hhZG93c29ja3NTdGFydEZhaWx1cmU7XG59KFJlZEZsYWdOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5TaGFkb3dzb2Nrc1N0YXJ0RmFpbHVyZSA9IFNoYWRvd3NvY2tzU3RhcnRGYWlsdXJlO1xudmFyIENvbmZpZ3VyZVN5c3RlbVByb3h5RmFpbHVyZSA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uIChfc3VwZXIpIHtcbiAgICBfX2V4dGVuZHMoQ29uZmlndXJlU3lzdGVtUHJveHlGYWlsdXJlLCBfc3VwZXIpO1xuICAgIGZ1bmN0aW9uIENvbmZpZ3VyZVN5c3RlbVByb3h5RmFpbHVyZSgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gQ29uZmlndXJlU3lzdGVtUHJveHlGYWlsdXJlO1xufShSZWRGbGFnTmF0aXZlRXJyb3IpKTtcbmV4cG9ydHMuQ29uZmlndXJlU3lzdGVtUHJveHlGYWlsdXJlID0gQ29uZmlndXJlU3lzdGVtUHJveHlGYWlsdXJlO1xudmFyIFVuc3VwcG9ydGVkUm91dGluZ1RhYmxlID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKF9zdXBlcikge1xuICAgIF9fZXh0ZW5kcyhVbnN1cHBvcnRlZFJvdXRpbmdUYWJsZSwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBVbnN1cHBvcnRlZFJvdXRpbmdUYWJsZSgpIHtcbiAgICAgICAgcmV0dXJuIF9zdXBlciAhPT0gbnVsbCAmJiBfc3VwZXIuYXBwbHkodGhpcywgYXJndW1lbnRzKSB8fCB0aGlzO1xuICAgIH1cbiAgICByZXR1cm4gVW5zdXBwb3J0ZWRSb3V0aW5nVGFibGU7XG59KFJlZEZsYWdOYXRpdmVFcnJvcikpO1xuZXhwb3J0cy5VbnN1cHBvcnRlZFJvdXRpbmdUYWJsZSA9IFVuc3VwcG9ydGVkUm91dGluZ1RhYmxlO1xuLy8gVXNlZCBvbiBBbmRyb2lkIGFuZCBBcHBsZSB0byBpbmRpY2F0ZSB0aGF0IHRoZSBwbHVnaW4gZmFpbGVkIHRvIGVzdGFibGlzaCB0aGUgVlBOIHR1bm5lbC5cbnZhciBWcG5TdGFydEZhaWx1cmUgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoX3N1cGVyKSB7XG4gICAgX19leHRlbmRzKFZwblN0YXJ0RmFpbHVyZSwgX3N1cGVyKTtcbiAgICBmdW5jdGlvbiBWcG5TdGFydEZhaWx1cmUoKSB7XG4gICAgICAgIHJldHVybiBfc3VwZXIgIT09IG51bGwgJiYgX3N1cGVyLmFwcGx5KHRoaXMsIGFyZ3VtZW50cykgfHwgdGhpcztcbiAgICB9XG4gICAgcmV0dXJuIFZwblN0YXJ0RmFpbHVyZTtcbn0oUmVkRmxhZ05hdGl2ZUVycm9yKSk7XG5leHBvcnRzLlZwblN0YXJ0RmFpbHVyZSA9IFZwblN0YXJ0RmFpbHVyZTtcbi8vIENvbnZlcnRzIGFuIEVycm9yQ29kZSAtIG9yaWdpbmF0aW5nIGluIFwibmF0aXZlXCIgY29kZSAtIHRvIGFuIGluc3RhbmNlIG9mIHRoZSByZWxldmFudFxuLy8gT3V0bGluZUVycm9yIHN1YmNsYXNzLlxuLy8gVGhyb3dzIGlmIHRoZSBlcnJvciBjb2RlIGlzIG5vdCBvbmUgZGVmaW5lZCBpbiBFcnJvckNvZGUgb3IgaXMgRXJyb3JDb2RlLk5PX0VSUk9SLlxuZnVuY3Rpb24gZnJvbUVycm9yQ29kZShlcnJvckNvZGUpIHtcbiAgICBzd2l0Y2ggKGVycm9yQ29kZSkge1xuICAgICAgICBjYXNlIDEgLyogVU5FWFBFQ1RFRCAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgVW5leHBlY3RlZFBsdWdpbkVycm9yKCk7XG4gICAgICAgIGNhc2UgMiAvKiBWUE5fUEVSTUlTU0lPTl9OT1RfR1JBTlRFRCAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgVnBuUGVybWlzc2lvbk5vdEdyYW50ZWQoKTtcbiAgICAgICAgY2FzZSAzIC8qIElOVkFMSURfU0VSVkVSX0NSRURFTlRJQUxTICovOlxuICAgICAgICAgICAgcmV0dXJuIG5ldyBJbnZhbGlkU2VydmVyQ3JlZGVudGlhbHMoKTtcbiAgICAgICAgY2FzZSA0IC8qIFVEUF9SRUxBWV9OT1RfRU5BQkxFRCAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgUmVtb3RlVWRwRm9yd2FyZGluZ0Rpc2FibGVkKCk7XG4gICAgICAgIGNhc2UgNSAvKiBTRVJWRVJfVU5SRUFDSEFCTEUgKi86XG4gICAgICAgICAgICByZXR1cm4gbmV3IFNlcnZlclVucmVhY2hhYmxlKCk7XG4gICAgICAgIGNhc2UgNiAvKiBWUE5fU1RBUlRfRkFJTFVSRSAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgVnBuU3RhcnRGYWlsdXJlKCk7XG4gICAgICAgIGNhc2UgNyAvKiBJTExFR0FMX1NFUlZFUl9DT05GSUdVUkFUSU9OICovOlxuICAgICAgICAgICAgcmV0dXJuIG5ldyBJbGxlZ2FsU2VydmVyQ29uZmlndXJhdGlvbigpO1xuICAgICAgICBjYXNlIDggLyogU0hBRE9XU09DS1NfU1RBUlRfRkFJTFVSRSAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgU2hhZG93c29ja3NTdGFydEZhaWx1cmUoKTtcbiAgICAgICAgY2FzZSA5IC8qIENPTkZJR1VSRV9TWVNURU1fUFJPWFlfRkFJTFVSRSAqLzpcbiAgICAgICAgICAgIHJldHVybiBuZXcgQ29uZmlndXJlU3lzdGVtUHJveHlGYWlsdXJlKCk7XG4gICAgICAgIGNhc2UgMTAgLyogTk9fQURNSU5fUEVSTUlTU0lPTlMgKi86XG4gICAgICAgICAgICByZXR1cm4gbmV3IE5vQWRtaW5QZXJtaXNzaW9ucygpO1xuICAgICAgICBjYXNlIDExIC8qIFVOU1VQUE9SVEVEX1JPVVRJTkdfVEFCTEUgKi86XG4gICAgICAgICAgICByZXR1cm4gbmV3IFVuc3VwcG9ydGVkUm91dGluZ1RhYmxlKCk7XG4gICAgICAgIGNhc2UgMTIgLyogU1lTVEVNX01JU0NPTkZJR1VSRUQgKi86XG4gICAgICAgICAgICByZXR1cm4gbmV3IFN5c3RlbUNvbmZpZ3VyYXRpb25FeGNlcHRpb24oKTtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcInVua25vd24gRXJyb3JDb2RlIFwiICsgZXJyb3JDb2RlKTtcbiAgICB9XG59XG5leHBvcnRzLmZyb21FcnJvckNvZGUgPSBmcm9tRXJyb3JDb2RlO1xuLy8gQ29udmVydHMgYSBOYXRpdmVFcnJvciB0byBhbiBFcnJvckNvZGUuXG4vLyBUaHJvd3MgaWYgdGhlIGVycm9yIGlzIG5vdCBhIHN1YmNsYXNzIG9mIE5hdGl2ZUVycm9yLlxuZnVuY3Rpb24gdG9FcnJvckNvZGUoZSkge1xuICAgIGlmIChlIGluc3RhbmNlb2YgVW5leHBlY3RlZFBsdWdpbkVycm9yKSB7XG4gICAgICAgIHJldHVybiAxIC8qIFVORVhQRUNURUQgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBWcG5QZXJtaXNzaW9uTm90R3JhbnRlZCkge1xuICAgICAgICByZXR1cm4gMiAvKiBWUE5fUEVSTUlTU0lPTl9OT1RfR1JBTlRFRCAqLztcbiAgICB9XG4gICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEludmFsaWRTZXJ2ZXJDcmVkZW50aWFscykge1xuICAgICAgICByZXR1cm4gMyAvKiBJTlZBTElEX1NFUlZFUl9DUkVERU5USUFMUyAqLztcbiAgICB9XG4gICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIFJlbW90ZVVkcEZvcndhcmRpbmdEaXNhYmxlZCkge1xuICAgICAgICByZXR1cm4gNCAvKiBVRFBfUkVMQVlfTk9UX0VOQUJMRUQgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBTZXJ2ZXJVbnJlYWNoYWJsZSkge1xuICAgICAgICByZXR1cm4gNSAvKiBTRVJWRVJfVU5SRUFDSEFCTEUgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBWcG5TdGFydEZhaWx1cmUpIHtcbiAgICAgICAgcmV0dXJuIDYgLyogVlBOX1NUQVJUX0ZBSUxVUkUgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBJbGxlZ2FsU2VydmVyQ29uZmlndXJhdGlvbikge1xuICAgICAgICByZXR1cm4gNyAvKiBJTExFR0FMX1NFUlZFUl9DT05GSUdVUkFUSU9OICovO1xuICAgIH1cbiAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgU2hhZG93c29ja3NTdGFydEZhaWx1cmUpIHtcbiAgICAgICAgcmV0dXJuIDggLyogU0hBRE9XU09DS1NfU1RBUlRfRkFJTFVSRSAqLztcbiAgICB9XG4gICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIENvbmZpZ3VyZVN5c3RlbVByb3h5RmFpbHVyZSkge1xuICAgICAgICByZXR1cm4gOSAvKiBDT05GSUdVUkVfU1lTVEVNX1BST1hZX0ZBSUxVUkUgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBVbnN1cHBvcnRlZFJvdXRpbmdUYWJsZSkge1xuICAgICAgICByZXR1cm4gMTEgLyogVU5TVVBQT1JURURfUk9VVElOR19UQUJMRSAqLztcbiAgICB9XG4gICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIE5vQWRtaW5QZXJtaXNzaW9ucykge1xuICAgICAgICByZXR1cm4gMTAgLyogTk9fQURNSU5fUEVSTUlTU0lPTlMgKi87XG4gICAgfVxuICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBTeXN0ZW1Db25maWd1cmF0aW9uRXhjZXB0aW9uKSB7XG4gICAgICAgIHJldHVybiAxMiAvKiBTWVNURU1fTUlTQ09ORklHVVJFRCAqLztcbiAgICB9XG4gICAgdGhyb3cgbmV3IEVycm9yKFwidW5rbm93biBOYXRpdmVFcnJvciBcIiArIGUubmFtZSk7XG59XG5leHBvcnRzLnRvRXJyb3JDb2RlID0gdG9FcnJvckNvZGU7XG4iLCJcInVzZSBzdHJpY3RcIjtcbi8vIENvcHlyaWdodCAyMDE4IFRoZSBPdXRsaW5lIEF1dGhvcnNcbi8vXG4vLyBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuLy8geW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuLy8gWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4vL1xuLy8gICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbi8vXG4vLyBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4vLyBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4vLyBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbi8vIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbi8vIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxudmFyIF9fdmFsdWVzID0gKHRoaXMgJiYgdGhpcy5fX3ZhbHVlcykgfHwgZnVuY3Rpb24obykge1xuICAgIHZhciBzID0gdHlwZW9mIFN5bWJvbCA9PT0gXCJmdW5jdGlvblwiICYmIFN5bWJvbC5pdGVyYXRvciwgbSA9IHMgJiYgb1tzXSwgaSA9IDA7XG4gICAgaWYgKG0pIHJldHVybiBtLmNhbGwobyk7XG4gICAgaWYgKG8gJiYgdHlwZW9mIG8ubGVuZ3RoID09PSBcIm51bWJlclwiKSByZXR1cm4ge1xuICAgICAgICBuZXh0OiBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBpZiAobyAmJiBpID49IG8ubGVuZ3RoKSBvID0gdm9pZCAwO1xuICAgICAgICAgICAgcmV0dXJuIHsgdmFsdWU6IG8gJiYgb1tpKytdLCBkb25lOiAhbyB9O1xuICAgICAgICB9XG4gICAgfTtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKHMgPyBcIk9iamVjdCBpcyBub3QgaXRlcmFibGUuXCIgOiBcIlN5bWJvbC5pdGVyYXRvciBpcyBub3QgZGVmaW5lZC5cIik7XG59O1xuT2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIFwiX19lc01vZHVsZVwiLCB7IHZhbHVlOiB0cnVlIH0pO1xudmFyIFNlcnZlckFkZGVkID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIFNlcnZlckFkZGVkKHNlcnZlcikge1xuICAgICAgICB0aGlzLnNlcnZlciA9IHNlcnZlcjtcbiAgICB9XG4gICAgcmV0dXJuIFNlcnZlckFkZGVkO1xufSgpKTtcbmV4cG9ydHMuU2VydmVyQWRkZWQgPSBTZXJ2ZXJBZGRlZDtcbnZhciBTZXJ2ZXJGb3Jnb3R0ZW4gPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gU2VydmVyRm9yZ290dGVuKHNlcnZlcikge1xuICAgICAgICB0aGlzLnNlcnZlciA9IHNlcnZlcjtcbiAgICB9XG4gICAgcmV0dXJuIFNlcnZlckZvcmdvdHRlbjtcbn0oKSk7XG5leHBvcnRzLlNlcnZlckZvcmdvdHRlbiA9IFNlcnZlckZvcmdvdHRlbjtcbnZhciBTZXJ2ZXJGb3JnZXRVbmRvbmUgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gU2VydmVyRm9yZ2V0VW5kb25lKHNlcnZlcikge1xuICAgICAgICB0aGlzLnNlcnZlciA9IHNlcnZlcjtcbiAgICB9XG4gICAgcmV0dXJuIFNlcnZlckZvcmdldFVuZG9uZTtcbn0oKSk7XG5leHBvcnRzLlNlcnZlckZvcmdldFVuZG9uZSA9IFNlcnZlckZvcmdldFVuZG9uZTtcbnZhciBTZXJ2ZXJSZW5hbWVkID0gLyoqIEBjbGFzcyAqLyAoZnVuY3Rpb24gKCkge1xuICAgIGZ1bmN0aW9uIFNlcnZlclJlbmFtZWQoc2VydmVyKSB7XG4gICAgICAgIHRoaXMuc2VydmVyID0gc2VydmVyO1xuICAgIH1cbiAgICByZXR1cm4gU2VydmVyUmVuYW1lZDtcbn0oKSk7XG5leHBvcnRzLlNlcnZlclJlbmFtZWQgPSBTZXJ2ZXJSZW5hbWVkO1xudmFyIFNlcnZlckNvbm5lY3RlZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJDb25uZWN0ZWQoc2VydmVyKSB7XG4gICAgICAgIHRoaXMuc2VydmVyID0gc2VydmVyO1xuICAgIH1cbiAgICByZXR1cm4gU2VydmVyQ29ubmVjdGVkO1xufSgpKTtcbmV4cG9ydHMuU2VydmVyQ29ubmVjdGVkID0gU2VydmVyQ29ubmVjdGVkO1xudmFyIFNlcnZlckRpc2Nvbm5lY3RlZCA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJEaXNjb25uZWN0ZWQoc2VydmVyKSB7XG4gICAgICAgIHRoaXMuc2VydmVyID0gc2VydmVyO1xuICAgIH1cbiAgICByZXR1cm4gU2VydmVyRGlzY29ubmVjdGVkO1xufSgpKTtcbmV4cG9ydHMuU2VydmVyRGlzY29ubmVjdGVkID0gU2VydmVyRGlzY29ubmVjdGVkO1xudmFyIFNlcnZlclJlY29ubmVjdGluZyA9IC8qKiBAY2xhc3MgKi8gKGZ1bmN0aW9uICgpIHtcbiAgICBmdW5jdGlvbiBTZXJ2ZXJSZWNvbm5lY3Rpbmcoc2VydmVyKSB7XG4gICAgICAgIHRoaXMuc2VydmVyID0gc2VydmVyO1xuICAgIH1cbiAgICByZXR1cm4gU2VydmVyUmVjb25uZWN0aW5nO1xufSgpKTtcbmV4cG9ydHMuU2VydmVyUmVjb25uZWN0aW5nID0gU2VydmVyUmVjb25uZWN0aW5nO1xuLy8gU2ltcGxlIHB1Ymxpc2hlci1zdWJzY3JpYmVyIHF1ZXVlLlxudmFyIEV2ZW50UXVldWUgPSAvKiogQGNsYXNzICovIChmdW5jdGlvbiAoKSB7XG4gICAgZnVuY3Rpb24gRXZlbnRRdWV1ZSgpIHtcbiAgICAgICAgdGhpcy5xdWV1ZWRFdmVudHMgPSBbXTtcbiAgICAgICAgLy8gdHNsaW50OmRpc2FibGUtbmV4dC1saW5lOiBuby1hbnlcbiAgICAgICAgdGhpcy5saXN0ZW5lcnNCeUV2ZW50VHlwZSA9IG5ldyBNYXAoKTtcbiAgICAgICAgdGhpcy5pc1N0YXJ0ZWQgPSBmYWxzZTtcbiAgICAgICAgdGhpcy5pc1B1Ymxpc2hpbmcgPSBmYWxzZTtcbiAgICB9XG4gICAgRXZlbnRRdWV1ZS5wcm90b3R5cGUuc3RhcnRQdWJsaXNoaW5nID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB0aGlzLmlzU3RhcnRlZCA9IHRydWU7XG4gICAgICAgIHRoaXMucHVibGlzaFF1ZXVlZEV2ZW50cygpO1xuICAgIH07XG4gICAgLy8gUmVnaXN0ZXJzIGEgbGlzdGVuZXIgZm9yIGV2ZW50cyBvZiB0aGUgdHlwZSBvZiB0aGUgZ2l2ZW4gY29uc3RydWN0b3IuXG4gICAgRXZlbnRRdWV1ZS5wcm90b3R5cGUuc3Vic2NyaWJlID0gZnVuY3Rpb24gKFxuICAgIC8vIHRzbGludDpkaXNhYmxlLW5leHQtbGluZTogbm8tYW55XG4gICAgZXZlbnRDb25zdHJ1Y3RvciwgbGlzdGVuZXIpIHtcbiAgICAgICAgdmFyIGxpc3RlbmVycyA9IHRoaXMubGlzdGVuZXJzQnlFdmVudFR5cGUuZ2V0KGV2ZW50Q29uc3RydWN0b3IubmFtZSk7XG4gICAgICAgIGlmICghbGlzdGVuZXJzKSB7XG4gICAgICAgICAgICBsaXN0ZW5lcnMgPSBbXTtcbiAgICAgICAgICAgIHRoaXMubGlzdGVuZXJzQnlFdmVudFR5cGUuc2V0KGV2ZW50Q29uc3RydWN0b3IubmFtZSwgbGlzdGVuZXJzKTtcbiAgICAgICAgfVxuICAgICAgICBsaXN0ZW5lcnMucHVzaChsaXN0ZW5lcik7XG4gICAgfTtcbiAgICAvLyBFbnF1ZXVlcyB0aGUgZ2l2ZW4gZXZlbnQgZm9yIHB1Ymxpc2hpbmcgYW5kIHB1Ymxpc2hlcyBhbGwgcXVldWVkIGV2ZW50cyBpZlxuICAgIC8vIHB1Ymxpc2hpbmcgaXMgbm90IGFscmVhZHkgaGFwcGVuaW5nLlxuICAgIC8vXG4gICAgLy8gVGhlIGVucXVldWUgbWV0aG9kIGlzIHJlZW50cmFudDogaXQgbWF5IGJlIGNhbGxlZCBieSBhbiBldmVudCBsaXN0ZW5lclxuICAgIC8vIGR1cmluZyB0aGUgcHVibGlzaGluZyBvZiB0aGUgZXZlbnRzLiBJbiB0aGF0IGNhc2UgdGhlIG1ldGhvZCBhZGRzIHRoZSBldmVudFxuICAgIC8vIHRvIHRoZSBlbmQgb2YgdGhlIHF1ZXVlIGFuZCByZXR1cm5zIGltbWVkaWF0ZWx5LlxuICAgIC8vXG4gICAgLy8gVGhpcyBndWFyYW50ZWVzIHRoYXQgZXZlbnRzIGFyZSBwdWJsaXNoZWQgYW5kIGhhbmRsZWQgaW4gdGhlIG9yZGVyIHRoYXRcbiAgICAvLyB0aGV5IGFyZSBxdWV1ZWQuXG4gICAgLy9cbiAgICAvLyBUaGVyZSdzIG5vIGd1YXJhbnRlZSB0aGF0IHRoZSBzdWJzY3JpYmVycyBmb3IgdGhlIGV2ZW50IGhhdmUgYmVlbiBjYWxsZWQgYnlcbiAgICAvLyB0aGUgdGltZSB0aGlzIGZ1bmN0aW9uIHJldHVybnMuXG4gICAgRXZlbnRRdWV1ZS5wcm90b3R5cGUuZW5xdWV1ZSA9IGZ1bmN0aW9uIChldmVudCkge1xuICAgICAgICB0aGlzLnF1ZXVlZEV2ZW50cy5wdXNoKGV2ZW50KTtcbiAgICAgICAgaWYgKHRoaXMuaXNTdGFydGVkKSB7XG4gICAgICAgICAgICB0aGlzLnB1Ymxpc2hRdWV1ZWRFdmVudHMoKTtcbiAgICAgICAgfVxuICAgIH07XG4gICAgLy8gVHJpZ2dlcnMgdGhlIHN1YnNjcmliZXJzIGZvciBhbGwgdGhlIGVucXVldWVkIGV2ZW50cy5cbiAgICBFdmVudFF1ZXVlLnByb3RvdHlwZS5wdWJsaXNoUXVldWVkRXZlbnRzID0gZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgZV8xLCBfYTtcbiAgICAgICAgaWYgKHRoaXMuaXNQdWJsaXNoaW5nKVxuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICB0aGlzLmlzUHVibGlzaGluZyA9IHRydWU7XG4gICAgICAgIHdoaWxlICh0aGlzLnF1ZXVlZEV2ZW50cy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICB2YXIgZXZlbnRfMSA9IHRoaXMucXVldWVkRXZlbnRzLnNoaWZ0KCk7XG4gICAgICAgICAgICB2YXIgbGlzdGVuZXJzID0gdGhpcy5saXN0ZW5lcnNCeUV2ZW50VHlwZS5nZXQoZXZlbnRfMS5jb25zdHJ1Y3Rvci5uYW1lKTtcbiAgICAgICAgICAgIGlmICghbGlzdGVuZXJzKSB7XG4gICAgICAgICAgICAgICAgY29uc29sZS53YXJuKCdEcm9wcGluZyBldmVudCB3aXRoIG5vIGxpc3RlbmVyczonLCBldmVudF8xKTtcbiAgICAgICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgZm9yICh2YXIgbGlzdGVuZXJzXzEgPSAoZV8xID0gdm9pZCAwLCBfX3ZhbHVlcyhsaXN0ZW5lcnMpKSwgbGlzdGVuZXJzXzFfMSA9IGxpc3RlbmVyc18xLm5leHQoKTsgIWxpc3RlbmVyc18xXzEuZG9uZTsgbGlzdGVuZXJzXzFfMSA9IGxpc3RlbmVyc18xLm5leHQoKSkge1xuICAgICAgICAgICAgICAgICAgICB2YXIgbGlzdGVuZXIgPSBsaXN0ZW5lcnNfMV8xLnZhbHVlO1xuICAgICAgICAgICAgICAgICAgICBsaXN0ZW5lcihldmVudF8xKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCAoZV8xXzEpIHsgZV8xID0geyBlcnJvcjogZV8xXzEgfTsgfVxuICAgICAgICAgICAgZmluYWxseSB7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGxpc3RlbmVyc18xXzEgJiYgIWxpc3RlbmVyc18xXzEuZG9uZSAmJiAoX2EgPSBsaXN0ZW5lcnNfMS5yZXR1cm4pKSBfYS5jYWxsKGxpc3RlbmVyc18xKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZmluYWxseSB7IGlmIChlXzEpIHRocm93IGVfMS5lcnJvcjsgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHRoaXMuaXNQdWJsaXNoaW5nID0gZmFsc2U7XG4gICAgfTtcbiAgICByZXR1cm4gRXZlbnRRdWV1ZTtcbn0oKSk7XG5leHBvcnRzLkV2ZW50UXVldWUgPSBFdmVudFF1ZXVlO1xuIl19
