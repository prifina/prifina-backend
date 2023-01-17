'use strict';

var require$$0$5 = require('@aws-sdk/client-dynamodb');
var require$$1$1 = require('@aws-sdk/lib-dynamodb');
var require$$2 = require('@aws-sdk/client-s3');
var require$$3 = require('@aws-sdk/client-athena');
var node_path = require('node:path');
var node_os = require('node:os');
var node_fs = require('node:fs');
var require$$0$4 = require('node:url');
var node_buffer = require('node:buffer');
var node_http = require('node:http');
var node_child_process = require('node:child_process');
var node_util = require('node:util');
var require$$1 = require('node:crypto');
var require$$13 = require('@aws-sdk/node-http-handler');
var node_process = require('node:process');
var require$$5$1 = require('@aws-sdk/client-cognito-identity-provider');
var require$$6 = require('@aws-sdk/client-sesv2');
var require$$7 = require('@aws-sdk/client-sns');
var require$$8 = require('@aws-sdk/client-eventbridge');
var require$$9 = require('@aws-sdk/client-cloudwatch');
var require$$2$1 = require('node:https');
var require$$15 = require('@aws-sdk/s3-request-presigner');
var require$$19 = require('@aws-sdk/client-cognito-identity');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var require$$0__default = /*#__PURE__*/_interopDefaultLegacy(require$$0$5);
var require$$1__default = /*#__PURE__*/_interopDefaultLegacy(require$$1$1);
var require$$2__default = /*#__PURE__*/_interopDefaultLegacy(require$$2);
var require$$3__default = /*#__PURE__*/_interopDefaultLegacy(require$$3);
var require$$0__default$1 = /*#__PURE__*/_interopDefaultLegacy(require$$0$4);
var require$$1__default$1 = /*#__PURE__*/_interopDefaultLegacy(require$$1);
var require$$13__default = /*#__PURE__*/_interopDefaultLegacy(require$$13);
var require$$5__default = /*#__PURE__*/_interopDefaultLegacy(require$$5$1);
var require$$6__default = /*#__PURE__*/_interopDefaultLegacy(require$$6);
var require$$7__default = /*#__PURE__*/_interopDefaultLegacy(require$$7);
var require$$8__default = /*#__PURE__*/_interopDefaultLegacy(require$$8);
var require$$9__default = /*#__PURE__*/_interopDefaultLegacy(require$$9);
var require$$2__default$1 = /*#__PURE__*/_interopDefaultLegacy(require$$2$1);
var require$$15__default = /*#__PURE__*/_interopDefaultLegacy(require$$15);
var require$$19__default = /*#__PURE__*/_interopDefaultLegacy(require$$19);

function getAugmentedNamespace(n) {
  var f = n.default;
	if (typeof f == "function") {
		var a = function () {
			return f.apply(this, arguments);
		};
		a.prototype = f.prototype;
  } else a = {};
  Object.defineProperty(a, '__esModule', {value: true});
	Object.keys(n).forEach(function (k) {
		var d = Object.getOwnPropertyDescriptor(n, k);
		Object.defineProperty(a, k, d.get ? d : {
			enumerable: true,
			get: function () {
				return n[k];
			}
		});
	});
	return a;
}

class ProviderError extends Error {
    constructor(message, tryNextLink = true) {
        super(message);
        this.tryNextLink = tryNextLink;
        this.name = "ProviderError";
        Object.setPrototypeOf(this, ProviderError.prototype);
    }
    static from(error, tryNextLink = true) {
        return Object.assign(new this(error.message, tryNextLink), error);
    }
}

class CredentialsProviderError extends ProviderError {
    constructor(message, tryNextLink = true) {
        super(message, tryNextLink);
        this.tryNextLink = tryNextLink;
        this.name = "CredentialsProviderError";
        Object.setPrototypeOf(this, CredentialsProviderError.prototype);
    }
}

class TokenProviderError extends ProviderError {
    constructor(message, tryNextLink = true) {
        super(message, tryNextLink);
        this.tryNextLink = tryNextLink;
        this.name = "TokenProviderError";
        Object.setPrototypeOf(this, TokenProviderError.prototype);
    }
}

function chain(...providers) {
    return () => {
        let promise = Promise.reject(new ProviderError("No providers in chain"));
        for (const provider of providers) {
            promise = promise.catch((err) => {
                if (err?.tryNextLink) {
                    return provider();
                }
                throw err;
            });
        }
        return promise;
    };
}

const fromStatic$1 = (staticValue) => () => Promise.resolve(staticValue);

const memoize = (provider, isExpired, requiresRefresh) => {
    let resolved;
    let pending;
    let hasResult;
    let isConstant = false;
    const coalesceProvider = async () => {
        if (!pending) {
            pending = provider();
        }
        try {
            resolved = await pending;
            hasResult = true;
            isConstant = false;
        }
        finally {
            pending = undefined;
        }
        return resolved;
    };
    if (isExpired === undefined) {
        return async (options) => {
            if (!hasResult || options?.forceRefresh) {
                resolved = await coalesceProvider();
            }
            return resolved;
        };
    }
    return async (options) => {
        if (!hasResult || options?.forceRefresh) {
            resolved = await coalesceProvider();
        }
        if (isConstant) {
            return resolved;
        }
        if (requiresRefresh && !requiresRefresh(resolved)) {
            isConstant = true;
            return resolved;
        }
        if (isExpired(resolved)) {
            await coalesceProvider();
            return resolved;
        }
        return resolved;
    };
};

const ENV_KEY = "AWS_ACCESS_KEY_ID";
const ENV_SECRET = "AWS_SECRET_ACCESS_KEY";
const ENV_SESSION = "AWS_SESSION_TOKEN";
const ENV_EXPIRATION = "AWS_CREDENTIAL_EXPIRATION";
const fromEnv$1 = () => async () => {
    const accessKeyId = process.env[ENV_KEY];
    const secretAccessKey = process.env[ENV_SECRET];
    const sessionToken = process.env[ENV_SESSION];
    const expiry = process.env[ENV_EXPIRATION];
    if (accessKeyId && secretAccessKey) {
        return {
            accessKeyId,
            secretAccessKey,
            ...(sessionToken && { sessionToken }),
            ...(expiry && { expiration: new Date(expiry) }),
        };
    }
    throw new CredentialsProviderError("Unable to find environment variable credentials.");
};

const getHomeDir = () => {
    const { HOME, USERPROFILE, HOMEPATH, HOMEDRIVE = `C:${node_path.sep}` } = process.env;
    if (HOME)
        return HOME;
    if (USERPROFILE)
        return USERPROFILE;
    if (HOMEPATH)
        return `${HOMEDRIVE}${HOMEPATH}`;
    return node_os.homedir();
};

const ENV_PROFILE = "AWS_PROFILE";
const DEFAULT_PROFILE = "default";
const getProfileName = (init) => init.profile || process.env[ENV_PROFILE] || DEFAULT_PROFILE;

const getSSOTokenFilepath = (id) => {
    const hasher = require$$1.createHash("sha1");
    const cacheName = hasher.update(id).digest("hex");
    return node_path.join(getHomeDir(), ".aws", "sso", "cache", `${cacheName}.json`);
};

const { readFile: readFile$1 } = node_fs.promises;
const getSSOTokenFromFile = async (id) => {
    const ssoTokenFilepath = getSSOTokenFilepath(id);
    const ssoTokenText = await readFile$1(ssoTokenFilepath, "utf8");
    return JSON.parse(ssoTokenText);
};

const ENV_CONFIG_PATH = "AWS_CONFIG_FILE";
const getConfigFilepath = () => process.env[ENV_CONFIG_PATH] || node_path.join(getHomeDir(), ".aws", "config");

const ENV_CREDENTIALS_PATH = "AWS_SHARED_CREDENTIALS_FILE";
const getCredentialsFilepath = () => process.env[ENV_CREDENTIALS_PATH] || node_path.join(getHomeDir(), ".aws", "credentials");

const profileKeyRegex = /^profile\s(["'])?([^\1]+)\1$/;
const getProfileData = (data) => Object.entries(data)
    .filter(([key]) => profileKeyRegex.test(key))
    .reduce((acc, [key, value]) => ({ ...acc, [profileKeyRegex.exec(key)[2]]: value }), {
    ...(data.default && { default: data.default }),
});

const profileNameBlockList = ["__proto__", "profile __proto__"];
const parseIni = (iniData) => {
    const map = {};
    let currentSection;
    for (let line of iniData.split(/\r?\n/)) {
        line = line.split(/(^|\s)[;#]/)[0].trim();
        const isSection = line[0] === "[" && line[line.length - 1] === "]";
        if (isSection) {
            currentSection = line.substring(1, line.length - 1);
            if (profileNameBlockList.includes(currentSection)) {
                throw new Error(`Found invalid profile name "${currentSection}"`);
            }
        }
        else if (currentSection) {
            const indexOfEqualsSign = line.indexOf("=");
            const start = 0;
            const end = line.length - 1;
            const isAssignment = indexOfEqualsSign !== -1 && indexOfEqualsSign !== start && indexOfEqualsSign !== end;
            if (isAssignment) {
                const [name, value] = [
                    line.substring(0, indexOfEqualsSign).trim(),
                    line.substring(indexOfEqualsSign + 1).trim(),
                ];
                map[currentSection] = map[currentSection] || {};
                map[currentSection][name] = value;
            }
        }
    }
    return map;
};

const { readFile } = node_fs.promises;
const filePromisesHash = {};
const slurpFile = (path) => {
    if (!filePromisesHash[path]) {
        filePromisesHash[path] = readFile(path, "utf8");
    }
    return filePromisesHash[path];
};

const swallowError$1 = () => ({});
const loadSharedConfigFiles = async (init = {}) => {
    const { filepath = getCredentialsFilepath(), configFilepath = getConfigFilepath() } = init;
    const parsedFiles = await Promise.all([
        slurpFile(configFilepath).then(parseIni).then(getProfileData).catch(swallowError$1),
        slurpFile(filepath).then(parseIni).catch(swallowError$1),
    ]);
    return {
        configFile: parsedFiles[0],
        credentialsFile: parsedFiles[1],
    };
};

const ssoSessionKeyRegex = /^sso-session\s(["'])?([^\1]+)\1$/;
const getSsoSessionData = (data) => Object.entries(data)
    .filter(([key]) => ssoSessionKeyRegex.test(key))
    .reduce((acc, [key, value]) => ({ ...acc, [ssoSessionKeyRegex.exec(key)[2]]: value }), {});

const swallowError = () => ({});
const loadSsoSessionData = async (init = {}) => slurpFile(init.configFilepath ?? getConfigFilepath())
    .then(parseIni)
    .then(getSsoSessionData)
    .catch(swallowError);

const parseKnownFiles = async (init) => {
    const parsedFiles = await loadSharedConfigFiles(init);
    return {
        ...parsedFiles.configFile,
        ...parsedFiles.credentialsFile,
    };
};

function httpRequest(options) {
    return new Promise((resolve, reject) => {
        const req = node_http.request({
            method: "GET",
            ...options,
            hostname: options.hostname?.replace(/^\[(.+)\]$/, "$1"),
        });
        req.on("error", (err) => {
            reject(Object.assign(new ProviderError("Unable to connect to instance metadata service"), err));
            req.destroy();
        });
        req.on("timeout", () => {
            reject(new ProviderError("TimeoutError from instance metadata service"));
            req.destroy();
        });
        req.on("response", (res) => {
            const { statusCode = 400 } = res;
            if (statusCode < 200 || 300 <= statusCode) {
                reject(Object.assign(new ProviderError("Error response received from instance metadata service"), { statusCode }));
                req.destroy();
            }
            const chunks = [];
            res.on("data", (chunk) => {
                chunks.push(chunk);
            });
            res.on("end", () => {
                resolve(node_buffer.Buffer.concat(chunks));
                req.destroy();
            });
        });
        req.end();
    });
}

const isImdsCredentials = (arg) => Boolean(arg) &&
    typeof arg === "object" &&
    typeof arg.AccessKeyId === "string" &&
    typeof arg.SecretAccessKey === "string" &&
    typeof arg.Token === "string" &&
    typeof arg.Expiration === "string";
const fromImdsCredentials = (creds) => ({
    accessKeyId: creds.AccessKeyId,
    secretAccessKey: creds.SecretAccessKey,
    sessionToken: creds.Token,
    expiration: new Date(creds.Expiration),
});

const DEFAULT_TIMEOUT = 1000;
const DEFAULT_MAX_RETRIES = 0;
const providerConfigFromInit = ({ maxRetries = DEFAULT_MAX_RETRIES, timeout = DEFAULT_TIMEOUT, }) => ({ maxRetries, timeout });

const retry = (toRetry, maxRetries) => {
    let promise = toRetry();
    for (let i = 0; i < maxRetries; i++) {
        promise = promise.catch(toRetry);
    }
    return promise;
};

const ENV_CMDS_FULL_URI = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
const ENV_CMDS_RELATIVE_URI = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
const ENV_CMDS_AUTH_TOKEN = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
const fromContainerMetadata = (init = {}) => {
    const { timeout, maxRetries } = providerConfigFromInit(init);
    return () => retry(async () => {
        const requestOptions = await getCmdsUri();
        const credsResponse = JSON.parse(await requestFromEcsImds(timeout, requestOptions));
        if (!isImdsCredentials(credsResponse)) {
            throw new CredentialsProviderError("Invalid response received from instance metadata service.");
        }
        return fromImdsCredentials(credsResponse);
    }, maxRetries);
};
const requestFromEcsImds = async (timeout, options) => {
    if (process.env[ENV_CMDS_AUTH_TOKEN]) {
        options.headers = {
            ...options.headers,
            Authorization: process.env[ENV_CMDS_AUTH_TOKEN],
        };
    }
    const buffer = await httpRequest({
        ...options,
        timeout,
    });
    return buffer.toString();
};
const CMDS_IP = "169.254.170.2";
const GREENGRASS_HOSTS = {
    localhost: true,
    "127.0.0.1": true,
};
const GREENGRASS_PROTOCOLS = {
    "http:": true,
    "https:": true,
};
const getCmdsUri = async () => {
    if (process.env[ENV_CMDS_RELATIVE_URI]) {
        return {
            hostname: CMDS_IP,
            path: process.env[ENV_CMDS_RELATIVE_URI],
        };
    }
    if (process.env[ENV_CMDS_FULL_URI]) {
        const parsed = require$$0$4.parse(process.env[ENV_CMDS_FULL_URI]);
        if (!parsed.hostname || !(parsed.hostname in GREENGRASS_HOSTS)) {
            throw new CredentialsProviderError(`${parsed.hostname} is not a valid container metadata service hostname`, false);
        }
        if (!parsed.protocol || !(parsed.protocol in GREENGRASS_PROTOCOLS)) {
            throw new CredentialsProviderError(`${parsed.protocol} is not a valid container metadata service protocol`, false);
        }
        return {
            ...parsed,
            port: parsed.port ? parseInt(parsed.port, 10) : undefined,
        };
    }
    throw new CredentialsProviderError("The container metadata credential provider cannot be used unless" +
        ` the ${ENV_CMDS_RELATIVE_URI} or ${ENV_CMDS_FULL_URI} environment` +
        " variable is set", false);
};

const fromEnv = (envVarSelector) => async () => {
    try {
        const config = envVarSelector(process.env);
        if (config === undefined) {
            throw new Error();
        }
        return config;
    }
    catch (e) {
        throw new CredentialsProviderError(e.message || `Cannot load config from environment variables with getter: ${envVarSelector}`);
    }
};

const fromSharedConfigFiles = (configSelector, { preferredFile = "config", ...init } = {}) => async () => {
    const profile = getProfileName(init);
    const { configFile, credentialsFile } = await loadSharedConfigFiles(init);
    const profileFromCredentials = credentialsFile[profile] || {};
    const profileFromConfig = configFile[profile] || {};
    const mergedProfile = preferredFile === "config"
        ? { ...profileFromCredentials, ...profileFromConfig }
        : { ...profileFromConfig, ...profileFromCredentials };
    try {
        const configValue = configSelector(mergedProfile);
        if (configValue === undefined) {
            throw new Error();
        }
        return configValue;
    }
    catch (e) {
        throw new CredentialsProviderError(e.message ||
            `Cannot load config for profile ${profile} in SDK configuration files with getter: ${configSelector}`);
    }
};

const isFunction = (func) => typeof func === "function";
const fromStatic = (defaultValue) => isFunction(defaultValue) ? async () => await defaultValue() : fromStatic$1(defaultValue);

const loadConfig = ({ environmentVariableSelector, configFileSelector, default: defaultValue }, configuration = {}) => memoize(chain(fromEnv(environmentVariableSelector), fromSharedConfigFiles(configFileSelector, configuration), fromStatic(defaultValue)));

function parseQueryString(querystring) {
    const query = {};
    querystring = querystring.replace(/^\?/, "");
    if (querystring) {
        for (const pair of querystring.split("&")) {
            let [key, value = null] = pair.split("=");
            key = decodeURIComponent(key);
            if (value) {
                value = decodeURIComponent(value);
            }
            if (!(key in query)) {
                query[key] = value;
            }
            else if (Array.isArray(query[key])) {
                query[key].push(value);
            }
            else {
                query[key] = [query[key], value];
            }
        }
    }
    return query;
}

const parseUrl$1 = (url) => {
    if (typeof url === "string") {
        return parseUrl$1(new URL(url));
    }
    const { hostname, pathname, port, protocol, search } = url;
    let query;
    if (search) {
        query = parseQueryString(search);
    }
    return {
        hostname,
        port: port ? parseInt(port) : undefined,
        protocol,
        path: pathname,
        query,
    };
};

var distEs$6 = /*#__PURE__*/Object.freeze({
	__proto__: null,
	parseUrl: parseUrl$1
});

var Endpoint;
(function (Endpoint) {
    Endpoint["IPv4"] = "http://169.254.169.254";
    Endpoint["IPv6"] = "http://[fd00:ec2::254]";
})(Endpoint || (Endpoint = {}));

const ENV_ENDPOINT_NAME = "AWS_EC2_METADATA_SERVICE_ENDPOINT";
const CONFIG_ENDPOINT_NAME = "ec2_metadata_service_endpoint";
const ENDPOINT_CONFIG_OPTIONS = {
    environmentVariableSelector: (env) => env[ENV_ENDPOINT_NAME],
    configFileSelector: (profile) => profile[CONFIG_ENDPOINT_NAME],
    default: undefined,
};

var EndpointMode;
(function (EndpointMode) {
    EndpointMode["IPv4"] = "IPv4";
    EndpointMode["IPv6"] = "IPv6";
})(EndpointMode || (EndpointMode = {}));

const ENV_ENDPOINT_MODE_NAME = "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE";
const CONFIG_ENDPOINT_MODE_NAME = "ec2_metadata_service_endpoint_mode";
const ENDPOINT_MODE_CONFIG_OPTIONS = {
    environmentVariableSelector: (env) => env[ENV_ENDPOINT_MODE_NAME],
    configFileSelector: (profile) => profile[CONFIG_ENDPOINT_MODE_NAME],
    default: EndpointMode.IPv4,
};

const getInstanceMetadataEndpoint = async () => parseUrl$1((await getFromEndpointConfig()) || (await getFromEndpointModeConfig()));
const getFromEndpointConfig = async () => loadConfig(ENDPOINT_CONFIG_OPTIONS)();
const getFromEndpointModeConfig = async () => {
    const endpointMode = await loadConfig(ENDPOINT_MODE_CONFIG_OPTIONS)();
    switch (endpointMode) {
        case EndpointMode.IPv4:
            return Endpoint.IPv4;
        case EndpointMode.IPv6:
            return Endpoint.IPv6;
        default:
            throw new Error(`Unsupported endpoint mode: ${endpointMode}.` + ` Select from ${Object.values(EndpointMode)}`);
    }
};

const STATIC_STABILITY_REFRESH_INTERVAL_SECONDS = 5 * 60;
const STATIC_STABILITY_REFRESH_INTERVAL_JITTER_WINDOW_SECONDS = 5 * 60;
const STATIC_STABILITY_DOC_URL = "https://docs.aws.amazon.com/sdkref/latest/guide/feature-static-credentials.html";
const getExtendedInstanceMetadataCredentials = (credentials, logger) => {
    const refreshInterval = STATIC_STABILITY_REFRESH_INTERVAL_SECONDS +
        Math.floor(Math.random() * STATIC_STABILITY_REFRESH_INTERVAL_JITTER_WINDOW_SECONDS);
    const newExpiration = new Date(Date.now() + refreshInterval * 1000);
    logger.warn("Attempting credential expiration extension due to a credential service availability issue. A refresh of these " +
        "credentials will be attempted after ${new Date(newExpiration)}.\nFor more information, please visit: " +
        STATIC_STABILITY_DOC_URL);
    const originalExpiration = credentials.originalExpiration ?? credentials.expiration;
    return {
        ...credentials,
        ...(originalExpiration ? { originalExpiration } : {}),
        expiration: newExpiration,
    };
};

const staticStabilityProvider = (provider, options = {}) => {
    const logger = options?.logger || console;
    let pastCredentials;
    return async () => {
        let credentials;
        try {
            credentials = await provider();
            if (credentials.expiration && credentials.expiration.getTime() < Date.now()) {
                credentials = getExtendedInstanceMetadataCredentials(credentials, logger);
            }
        }
        catch (e) {
            if (pastCredentials) {
                logger.warn("Credential renew failed: ", e);
                credentials = getExtendedInstanceMetadataCredentials(pastCredentials, logger);
            }
            else {
                throw e;
            }
        }
        pastCredentials = credentials;
        return credentials;
    };
};

const IMDS_PATH = "/latest/meta-data/iam/security-credentials/";
const IMDS_TOKEN_PATH = "/latest/api/token";
const fromInstanceMetadata = (init = {}) => staticStabilityProvider(getInstanceImdsProvider(init), { logger: init.logger });
const getInstanceImdsProvider = (init) => {
    let disableFetchToken = false;
    const { timeout, maxRetries } = providerConfigFromInit(init);
    const getCredentials = async (maxRetries, options) => {
        const profile = (await retry(async () => {
            let profile;
            try {
                profile = await getProfile(options);
            }
            catch (err) {
                if (err.statusCode === 401) {
                    disableFetchToken = false;
                }
                throw err;
            }
            return profile;
        }, maxRetries)).trim();
        return retry(async () => {
            let creds;
            try {
                creds = await getCredentialsFromProfile(profile, options);
            }
            catch (err) {
                if (err.statusCode === 401) {
                    disableFetchToken = false;
                }
                throw err;
            }
            return creds;
        }, maxRetries);
    };
    return async () => {
        const endpoint = await getInstanceMetadataEndpoint();
        if (disableFetchToken) {
            return getCredentials(maxRetries, { ...endpoint, timeout });
        }
        else {
            let token;
            try {
                token = (await getMetadataToken({ ...endpoint, timeout })).toString();
            }
            catch (error) {
                if (error?.statusCode === 400) {
                    throw Object.assign(error, {
                        message: "EC2 Metadata token request returned error",
                    });
                }
                else if (error.message === "TimeoutError" || [403, 404, 405].includes(error.statusCode)) {
                    disableFetchToken = true;
                }
                return getCredentials(maxRetries, { ...endpoint, timeout });
            }
            return getCredentials(maxRetries, {
                ...endpoint,
                headers: {
                    "x-aws-ec2-metadata-token": token,
                },
                timeout,
            });
        }
    };
};
const getMetadataToken = async (options) => httpRequest({
    ...options,
    path: IMDS_TOKEN_PATH,
    method: "PUT",
    headers: {
        "x-aws-ec2-metadata-token-ttl-seconds": "21600",
    },
});
const getProfile = async (options) => (await httpRequest({ ...options, path: IMDS_PATH })).toString();
const getCredentialsFromProfile = async (profile, options) => {
    const credsResponse = JSON.parse((await httpRequest({
        ...options,
        path: IMDS_PATH + profile,
    })).toString());
    if (!isImdsCredentials(credsResponse)) {
        throw new CredentialsProviderError("Invalid response received from instance metadata service.");
    }
    return fromImdsCredentials(credsResponse);
};

const resolveCredentialSource = (credentialSource, profileName) => {
    const sourceProvidersMap = {
        EcsContainer: fromContainerMetadata,
        Ec2InstanceMetadata: fromInstanceMetadata,
        Environment: fromEnv$1,
    };
    if (credentialSource in sourceProvidersMap) {
        return sourceProvidersMap[credentialSource]();
    }
    else {
        throw new CredentialsProviderError(`Unsupported credential source in profile ${profileName}. Got ${credentialSource}, ` +
            `expected EcsContainer or Ec2InstanceMetadata or Environment.`);
    }
};

const isAssumeRoleProfile = (arg) => Boolean(arg) &&
    typeof arg === "object" &&
    typeof arg.role_arn === "string" &&
    ["undefined", "string"].indexOf(typeof arg.role_session_name) > -1 &&
    ["undefined", "string"].indexOf(typeof arg.external_id) > -1 &&
    ["undefined", "string"].indexOf(typeof arg.mfa_serial) > -1 &&
    (isAssumeRoleWithSourceProfile(arg) || isAssumeRoleWithProviderProfile(arg));
const isAssumeRoleWithSourceProfile = (arg) => typeof arg.source_profile === "string" && typeof arg.credential_source === "undefined";
const isAssumeRoleWithProviderProfile = (arg) => typeof arg.credential_source === "string" && typeof arg.source_profile === "undefined";
const resolveAssumeRoleCredentials = async (profileName, profiles, options, visitedProfiles = {}) => {
    const data = profiles[profileName];
    if (!options.roleAssumer) {
        throw new CredentialsProviderError(`Profile ${profileName} requires a role to be assumed, but no role assumption callback was provided.`, false);
    }
    const { source_profile } = data;
    if (source_profile && source_profile in visitedProfiles) {
        throw new CredentialsProviderError(`Detected a cycle attempting to resolve credentials for profile` +
            ` ${getProfileName(options)}. Profiles visited: ` +
            Object.keys(visitedProfiles).join(", "), false);
    }
    const sourceCredsProvider = source_profile
        ? resolveProfileData(source_profile, profiles, options, {
            ...visitedProfiles,
            [source_profile]: true,
        })
        : resolveCredentialSource(data.credential_source, profileName)();
    const params = {
        RoleArn: data.role_arn,
        RoleSessionName: data.role_session_name || `aws-sdk-js-${Date.now()}`,
        ExternalId: data.external_id,
    };
    const { mfa_serial } = data;
    if (mfa_serial) {
        if (!options.mfaCodeProvider) {
            throw new CredentialsProviderError(`Profile ${profileName} requires multi-factor authentication, but no MFA code callback was provided.`, false);
        }
        params.SerialNumber = mfa_serial;
        params.TokenCode = await options.mfaCodeProvider(mfa_serial);
    }
    const sourceCreds = await sourceCredsProvider;
    return options.roleAssumer(sourceCreds, params);
};

const getValidatedProcessCredentials = (profileName, data) => {
    if (data.Version !== 1) {
        throw Error(`Profile ${profileName} credential_process did not return Version 1.`);
    }
    if (data.AccessKeyId === undefined || data.SecretAccessKey === undefined) {
        throw Error(`Profile ${profileName} credential_process returned invalid credentials.`);
    }
    if (data.Expiration) {
        const currentTime = new Date();
        const expireTime = new Date(data.Expiration);
        if (expireTime < currentTime) {
            throw Error(`Profile ${profileName} credential_process returned expired credentials.`);
        }
    }
    return {
        accessKeyId: data.AccessKeyId,
        secretAccessKey: data.SecretAccessKey,
        ...(data.SessionToken && { sessionToken: data.SessionToken }),
        ...(data.Expiration && { expiration: new Date(data.Expiration) }),
    };
};

const resolveProcessCredentials$1 = async (profileName, profiles) => {
    const profile = profiles[profileName];
    if (profiles[profileName]) {
        const credentialProcess = profile["credential_process"];
        if (credentialProcess !== undefined) {
            const execPromise = node_util.promisify(node_child_process.exec);
            try {
                const { stdout } = await execPromise(credentialProcess);
                let data;
                try {
                    data = JSON.parse(stdout.trim());
                }
                catch {
                    throw Error(`Profile ${profileName} credential_process returned invalid JSON.`);
                }
                return getValidatedProcessCredentials(profileName, data);
            }
            catch (error) {
                throw new CredentialsProviderError(error.message);
            }
        }
        else {
            throw new CredentialsProviderError(`Profile ${profileName} did not contain credential_process.`);
        }
    }
    else {
        throw new CredentialsProviderError(`Profile ${profileName} could not be found in shared credentials file.`);
    }
};

const fromProcess = (init = {}) => async () => {
    const profiles = await parseKnownFiles(init);
    return resolveProcessCredentials$1(getProfileName(init), profiles);
};

const isProcessProfile = (arg) => Boolean(arg) &&
    typeof arg === "object" &&
    typeof arg.credential_process === "string";
const resolveProcessCredentials = async (options, profile) => fromProcess({
    ...options,
    profile,
})();

const isSsoProfile = (arg) => arg &&
    (typeof arg.sso_start_url === "string" ||
        typeof arg.sso_account_id === "string" ||
        typeof arg.sso_session === "string" ||
        typeof arg.sso_region === "string" ||
        typeof arg.sso_role_name === "string");

const resolveParamsForS3 = async (endpointParams) => {
    const bucket = endpointParams?.Bucket || "";
    if (typeof endpointParams.Bucket === "string") {
        endpointParams.Bucket = bucket.replace(/#/g, encodeURIComponent("#")).replace(/\?/g, encodeURIComponent("?"));
    }
    if (isArnBucketName(bucket)) {
        if (endpointParams.ForcePathStyle === true) {
            throw new Error("Path-style addressing cannot be used with ARN buckets");
        }
    }
    else if (!isDnsCompatibleBucketName(bucket) ||
        (bucket.indexOf(".") !== -1 && !String(endpointParams.Endpoint).startsWith("http:")) ||
        bucket.toLowerCase() !== bucket ||
        bucket.length < 3) {
        endpointParams.ForcePathStyle = true;
    }
    if (endpointParams.DisableMultiRegionAccessPoints) {
        endpointParams.disableMultiRegionAccessPoints = true;
        endpointParams.DisableMRAP = true;
    }
    return endpointParams;
};
const DOMAIN_PATTERN = /^[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]$/;
const IP_ADDRESS_PATTERN = /(\d+\.){3}\d+/;
const DOTS_PATTERN = /\.\./;
const isDnsCompatibleBucketName = (bucketName) => DOMAIN_PATTERN.test(bucketName) && !IP_ADDRESS_PATTERN.test(bucketName) && !DOTS_PATTERN.test(bucketName);
const isArnBucketName = (bucketName) => {
    const [arn, partition, service, region, account, typeOrId] = bucketName.split(":");
    const isArn = arn === "arn" && bucketName.split(":").length >= 6;
    const isValidArn = [arn, partition, service, account, typeOrId].filter(Boolean).length === 5;
    if (isArn && !isValidArn) {
        throw new Error(`Invalid ARN: ${bucketName} was an invalid ARN.`);
    }
    return arn === "arn" && !!partition && !!service && !!account && !!typeOrId;
};

const createConfigValueProvider = (configKey, canonicalEndpointParamKey, config) => {
    const configProvider = async () => {
        const configValue = config[configKey] ?? config[canonicalEndpointParamKey];
        if (typeof configValue === "function") {
            return configValue();
        }
        return configValue;
    };
    if (configKey === "endpoint" || canonicalEndpointParamKey === "endpoint") {
        return async () => {
            const endpoint = await configProvider();
            if (endpoint && typeof endpoint === "object") {
                if ("url" in endpoint) {
                    return endpoint.url.href;
                }
                if ("hostname" in endpoint) {
                    const { protocol, hostname, port, path } = endpoint;
                    return `${protocol}//${hostname}${port ? ":" + port : ""}${path}`;
                }
            }
            return endpoint;
        };
    }
    return configProvider;
};

const getEndpointFromInstructions = async (commandInput, instructionsSupplier, clientConfig, context) => {
    const endpointParams = await resolveParams(commandInput, instructionsSupplier, clientConfig);
    if (typeof clientConfig.endpointProvider !== "function") {
        throw new Error("config.endpointProvider is not set.");
    }
    const endpoint = clientConfig.endpointProvider(endpointParams, context);
    return endpoint;
};
const resolveParams = async (commandInput, instructionsSupplier, clientConfig) => {
    const endpointParams = {};
    const instructions = instructionsSupplier?.getEndpointParameterInstructions?.() || {};
    for (const [name, instruction] of Object.entries(instructions)) {
        switch (instruction.type) {
            case "staticContextParams":
                endpointParams[name] = instruction.value;
                break;
            case "contextParams":
                endpointParams[name] = commandInput[instruction.name];
                break;
            case "clientContextParams":
            case "builtInParams":
                endpointParams[name] = await createConfigValueProvider(instruction.name, name, clientConfig)();
                break;
            default:
                throw new Error("Unrecognized endpoint parameter instruction: " + JSON.stringify(instruction));
        }
    }
    if (Object.keys(instructions).length === 0) {
        Object.assign(endpointParams, clientConfig);
    }
    if (String(clientConfig.serviceId).toLowerCase() === "s3") {
        await resolveParamsForS3(endpointParams);
    }
    return endpointParams;
};

const toEndpointV1 = (endpoint) => {
    if (typeof endpoint === "object") {
        if ("url" in endpoint) {
            return parseUrl$1(endpoint.url);
        }
        return endpoint;
    }
    return parseUrl$1(endpoint);
};

const endpointMiddleware = ({ config, instructions, }) => {
    return (next, context) => async (args) => {
        const endpoint = await getEndpointFromInstructions(args.input, {
            getEndpointParameterInstructions() {
                return instructions;
            },
        }, { ...config }, context);
        context.endpointV2 = endpoint;
        context.authSchemes = endpoint.properties?.authSchemes;
        const authScheme = context.authSchemes?.[0];
        if (authScheme) {
            context["signing_region"] = authScheme.signingRegion;
            context["signing_service"] = authScheme.signingName;
        }
        return next({
            ...args,
        });
    };
};

const deserializerMiddleware = (options, deserializer) => (next, context) => async (args) => {
    const { response } = await next(args);
    try {
        const parsed = await deserializer(response, options);
        return {
            response,
            output: parsed,
        };
    }
    catch (error) {
        Object.defineProperty(error, "$response", {
            value: response,
        });
        throw error;
    }
};

const serializerMiddleware = (options, serializer) => (next, context) => async (args) => {
    const endpoint = context.endpointV2?.url && options.urlParser
        ? async () => options.urlParser(context.endpointV2.url)
        : options.endpoint;
    if (!endpoint) {
        throw new Error("No valid endpoint provider available.");
    }
    const request = await serializer(args.input, { ...options, endpoint });
    return next({
        ...args,
        request,
    });
};

const deserializerMiddlewareOption = {
    name: "deserializerMiddleware",
    step: "deserialize",
    tags: ["DESERIALIZER"],
    override: true,
};
const serializerMiddlewareOption = {
    name: "serializerMiddleware",
    step: "serialize",
    tags: ["SERIALIZER"],
    override: true,
};
function getSerdePlugin(config, serializer, deserializer) {
    return {
        applyToStack: (commandStack) => {
            commandStack.add(deserializerMiddleware(config, deserializer), deserializerMiddlewareOption);
            commandStack.add(serializerMiddleware(config, serializer), serializerMiddlewareOption);
        },
    };
}

const endpointMiddlewareOptions = {
    step: "serialize",
    tags: ["ENDPOINT_PARAMETERS", "ENDPOINT_V2", "ENDPOINT"],
    name: "endpointV2Middleware",
    override: true,
    relation: "before",
    toMiddleware: serializerMiddlewareOption.name,
};
const getEndpointPlugin = (config, instructions) => ({
    applyToStack: (clientStack) => {
        clientStack.addRelativeTo(endpointMiddleware({
            config,
            instructions,
        }), endpointMiddlewareOptions);
    },
});

const normalizeProvider = (input) => {
    if (typeof input === "function")
        return input;
    const promisified = Promise.resolve(input);
    return () => promisified;
};

const resolveEndpointConfig = (input) => {
    const tls = input.tls ?? true;
    const { endpoint } = input;
    const customEndpointProvider = endpoint != null ? async () => toEndpointV1(await normalizeProvider(endpoint)()) : undefined;
    const isCustomEndpoint = !!endpoint;
    return {
        ...input,
        endpoint: customEndpointProvider,
        tls,
        isCustomEndpoint,
        useDualstackEndpoint: normalizeProvider(input.useDualstackEndpoint ?? false),
        useFipsEndpoint: normalizeProvider(input.useFipsEndpoint ?? false),
    };
};

class NoOpLogger {
    trace() { }
    debug() { }
    info() { }
    warn() { }
    error() { }
}

const constructStack = () => {
    let absoluteEntries = [];
    let relativeEntries = [];
    const entriesNameSet = new Set();
    const sort = (entries) => entries.sort((a, b) => stepWeights[b.step] - stepWeights[a.step] ||
        priorityWeights[b.priority || "normal"] - priorityWeights[a.priority || "normal"]);
    const removeByName = (toRemove) => {
        let isRemoved = false;
        const filterCb = (entry) => {
            if (entry.name && entry.name === toRemove) {
                isRemoved = true;
                entriesNameSet.delete(toRemove);
                return false;
            }
            return true;
        };
        absoluteEntries = absoluteEntries.filter(filterCb);
        relativeEntries = relativeEntries.filter(filterCb);
        return isRemoved;
    };
    const removeByReference = (toRemove) => {
        let isRemoved = false;
        const filterCb = (entry) => {
            if (entry.middleware === toRemove) {
                isRemoved = true;
                if (entry.name)
                    entriesNameSet.delete(entry.name);
                return false;
            }
            return true;
        };
        absoluteEntries = absoluteEntries.filter(filterCb);
        relativeEntries = relativeEntries.filter(filterCb);
        return isRemoved;
    };
    const cloneTo = (toStack) => {
        absoluteEntries.forEach((entry) => {
            toStack.add(entry.middleware, { ...entry });
        });
        relativeEntries.forEach((entry) => {
            toStack.addRelativeTo(entry.middleware, { ...entry });
        });
        return toStack;
    };
    const expandRelativeMiddlewareList = (from) => {
        const expandedMiddlewareList = [];
        from.before.forEach((entry) => {
            if (entry.before.length === 0 && entry.after.length === 0) {
                expandedMiddlewareList.push(entry);
            }
            else {
                expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
            }
        });
        expandedMiddlewareList.push(from);
        from.after.reverse().forEach((entry) => {
            if (entry.before.length === 0 && entry.after.length === 0) {
                expandedMiddlewareList.push(entry);
            }
            else {
                expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
            }
        });
        return expandedMiddlewareList;
    };
    const getMiddlewareList = (debug = false) => {
        const normalizedAbsoluteEntries = [];
        const normalizedRelativeEntries = [];
        const normalizedEntriesNameMap = {};
        absoluteEntries.forEach((entry) => {
            const normalizedEntry = {
                ...entry,
                before: [],
                after: [],
            };
            if (normalizedEntry.name)
                normalizedEntriesNameMap[normalizedEntry.name] = normalizedEntry;
            normalizedAbsoluteEntries.push(normalizedEntry);
        });
        relativeEntries.forEach((entry) => {
            const normalizedEntry = {
                ...entry,
                before: [],
                after: [],
            };
            if (normalizedEntry.name)
                normalizedEntriesNameMap[normalizedEntry.name] = normalizedEntry;
            normalizedRelativeEntries.push(normalizedEntry);
        });
        normalizedRelativeEntries.forEach((entry) => {
            if (entry.toMiddleware) {
                const toMiddleware = normalizedEntriesNameMap[entry.toMiddleware];
                if (toMiddleware === undefined) {
                    if (debug) {
                        return;
                    }
                    throw new Error(`${entry.toMiddleware} is not found when adding ${entry.name || "anonymous"} middleware ${entry.relation} ${entry.toMiddleware}`);
                }
                if (entry.relation === "after") {
                    toMiddleware.after.push(entry);
                }
                if (entry.relation === "before") {
                    toMiddleware.before.push(entry);
                }
            }
        });
        const mainChain = sort(normalizedAbsoluteEntries)
            .map(expandRelativeMiddlewareList)
            .reduce((wholeList, expendedMiddlewareList) => {
            wholeList.push(...expendedMiddlewareList);
            return wholeList;
        }, []);
        return mainChain;
    };
    const stack = {
        add: (middleware, options = {}) => {
            const { name, override } = options;
            const entry = {
                step: "initialize",
                priority: "normal",
                middleware,
                ...options,
            };
            if (name) {
                if (entriesNameSet.has(name)) {
                    if (!override)
                        throw new Error(`Duplicate middleware name '${name}'`);
                    const toOverrideIndex = absoluteEntries.findIndex((entry) => entry.name === name);
                    const toOverride = absoluteEntries[toOverrideIndex];
                    if (toOverride.step !== entry.step || toOverride.priority !== entry.priority) {
                        throw new Error(`"${name}" middleware with ${toOverride.priority} priority in ${toOverride.step} step cannot be ` +
                            `overridden by same-name middleware with ${entry.priority} priority in ${entry.step} step.`);
                    }
                    absoluteEntries.splice(toOverrideIndex, 1);
                }
                entriesNameSet.add(name);
            }
            absoluteEntries.push(entry);
        },
        addRelativeTo: (middleware, options) => {
            const { name, override } = options;
            const entry = {
                middleware,
                ...options,
            };
            if (name) {
                if (entriesNameSet.has(name)) {
                    if (!override)
                        throw new Error(`Duplicate middleware name '${name}'`);
                    const toOverrideIndex = relativeEntries.findIndex((entry) => entry.name === name);
                    const toOverride = relativeEntries[toOverrideIndex];
                    if (toOverride.toMiddleware !== entry.toMiddleware || toOverride.relation !== entry.relation) {
                        throw new Error(`"${name}" middleware ${toOverride.relation} "${toOverride.toMiddleware}" middleware cannot be overridden ` +
                            `by same-name middleware ${entry.relation} "${entry.toMiddleware}" middleware.`);
                    }
                    relativeEntries.splice(toOverrideIndex, 1);
                }
                entriesNameSet.add(name);
            }
            relativeEntries.push(entry);
        },
        clone: () => cloneTo(constructStack()),
        use: (plugin) => {
            plugin.applyToStack(stack);
        },
        remove: (toRemove) => {
            if (typeof toRemove === "string")
                return removeByName(toRemove);
            else
                return removeByReference(toRemove);
        },
        removeByTag: (toRemove) => {
            let isRemoved = false;
            const filterCb = (entry) => {
                const { tags, name } = entry;
                if (tags && tags.includes(toRemove)) {
                    if (name)
                        entriesNameSet.delete(name);
                    isRemoved = true;
                    return false;
                }
                return true;
            };
            absoluteEntries = absoluteEntries.filter(filterCb);
            relativeEntries = relativeEntries.filter(filterCb);
            return isRemoved;
        },
        concat: (from) => {
            const cloned = cloneTo(constructStack());
            cloned.use(from);
            return cloned;
        },
        applyToStack: cloneTo,
        identify: () => {
            return getMiddlewareList(true).map((mw) => {
                return mw.name + ": " + (mw.tags || []).join(",");
            });
        },
        resolve: (handler, context) => {
            for (const middleware of getMiddlewareList()
                .map((entry) => entry.middleware)
                .reverse()) {
                handler = middleware(handler, context);
            }
            return handler;
        },
    };
    return stack;
};
const stepWeights = {
    initialize: 5,
    serialize: 4,
    build: 3,
    finalizeRequest: 2,
    deserialize: 1,
};
const priorityWeights = {
    high: 3,
    normal: 2,
    low: 1,
};

class Client {
    constructor(config) {
        this.middlewareStack = constructStack();
        this.config = config;
    }
    send(command, optionsOrCb, cb) {
        const options = typeof optionsOrCb !== "function" ? optionsOrCb : undefined;
        const callback = typeof optionsOrCb === "function" ? optionsOrCb : cb;
        const handler = command.resolveMiddleware(this.middlewareStack, this.config, options);
        if (callback) {
            handler(command)
                .then((result) => callback(null, result.output), (err) => callback(err))
                .catch(() => { });
        }
        else {
            return handler(command).then((result) => result.output);
        }
    }
    destroy() {
        if (this.config.requestHandler.destroy)
            this.config.requestHandler.destroy();
    }
}

class Command {
    constructor() {
        this.middlewareStack = constructStack();
    }
}

const SENSITIVE_STRING = "***SensitiveInformation***";

const expectLong = (value) => {
    if (value === null || value === undefined) {
        return undefined;
    }
    if (Number.isInteger(value) && !Number.isNaN(value)) {
        return value;
    }
    throw new TypeError(`Expected integer, got ${typeof value}: ${value}`);
};
const expectInt32 = (value) => expectSizedInt(value, 32);
const expectSizedInt = (value, size) => {
    const expected = expectLong(value);
    if (expected !== undefined && castInt(expected, size) !== expected) {
        throw new TypeError(`Expected ${size}-bit integer, got ${value}`);
    }
    return expected;
};
const castInt = (value, size) => {
    switch (size) {
        case 32:
            return Int32Array.of(value)[0];
        case 16:
            return Int16Array.of(value)[0];
        case 8:
            return Int8Array.of(value)[0];
    }
};
const expectNonNull = (value, location) => {
    if (value === null || value === undefined) {
        if (location) {
            throw new TypeError(`Expected a non-null value for ${location}`);
        }
        throw new TypeError("Expected a non-null value");
    }
    return value;
};
const expectObject = (value) => {
    if (value === null || value === undefined) {
        return undefined;
    }
    if (typeof value === "object" && !Array.isArray(value)) {
        return value;
    }
    const receivedType = Array.isArray(value) ? "array" : typeof value;
    throw new TypeError(`Expected object, got ${receivedType}: ${value}`);
};
const expectString = (value) => {
    if (value === null || value === undefined) {
        return undefined;
    }
    if (typeof value === "string") {
        return value;
    }
    if (["boolean", "number", "bigint"].includes(typeof value)) {
        logger.warn(stackTraceWarning(`Expected string, got ${typeof value}: ${value}`));
        return String(value);
    }
    throw new TypeError(`Expected string, got ${typeof value}: ${value}`);
};
const stackTraceWarning = (message) => {
    return String(new TypeError(message).stack || message)
        .split("\n")
        .slice(0, 5)
        .filter((s) => !s.includes("stackTraceWarning"))
        .join("\n");
};
const logger = {
    warn: console.warn,
};

class ServiceException extends Error {
    constructor(options) {
        super(options.message);
        Object.setPrototypeOf(this, ServiceException.prototype);
        this.name = options.name;
        this.$fault = options.$fault;
        this.$metadata = options.$metadata;
    }
}
const decorateServiceException = (exception, additions = {}) => {
    Object.entries(additions)
        .filter(([, v]) => v !== undefined)
        .forEach(([k, v]) => {
        if (exception[k] == undefined || exception[k] === "") {
            exception[k] = v;
        }
    });
    const message = exception.message || exception.Message || "UnknownError";
    exception.message = message;
    delete exception.Message;
    return exception;
};

const throwDefaultError = ({ output, parsedBody, exceptionCtor, errorCode }) => {
    const $metadata = deserializeMetadata$2(output);
    const statusCode = $metadata.httpStatusCode ? $metadata.httpStatusCode + "" : undefined;
    const response = new exceptionCtor({
        name: parsedBody.code || parsedBody.Code || errorCode || statusCode || "UnknownError",
        $fault: "client",
        $metadata,
    });
    throw decorateServiceException(response, parsedBody);
};
const deserializeMetadata$2 = (output) => ({
    httpStatusCode: output.statusCode,
    requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
    extendedRequestId: output.headers["x-amz-id-2"],
    cfId: output.headers["x-amz-cf-id"],
});

const loadConfigsForDefaultMode = (mode) => {
    switch (mode) {
        case "standard":
            return {
                retryMode: "standard",
                connectionTimeout: 3100,
            };
        case "in-region":
            return {
                retryMode: "standard",
                connectionTimeout: 1100,
            };
        case "cross-region":
            return {
                retryMode: "standard",
                connectionTimeout: 3100,
            };
        case "mobile":
            return {
                retryMode: "standard",
                connectionTimeout: 30000,
            };
        default:
            return {};
    }
};

let warningEmitted = false;
const emitWarningIfUnsupportedVersion = (version) => {
    if (version && !warningEmitted && parseInt(version.substring(1, version.indexOf("."))) < 14) {
        warningEmitted = true;
    }
};

const StringWrapper = function () {
    const Class = Object.getPrototypeOf(this).constructor;
    const Constructor = Function.bind.apply(String, [null, ...arguments]);
    const instance = new Constructor();
    Object.setPrototypeOf(instance, Class.prototype);
    return instance;
};
StringWrapper.prototype = Object.create(String.prototype, {
    constructor: {
        value: StringWrapper,
        enumerable: false,
        writable: true,
        configurable: true,
    },
});
Object.setPrototypeOf(StringWrapper, String);

function map$2(arg0, arg1, arg2) {
    let target;
    let filter;
    let instructions;
    if (typeof arg1 === "undefined" && typeof arg2 === "undefined") {
        target = {};
        instructions = arg0;
    }
    else {
        target = arg0;
        if (typeof arg1 === "function") {
            filter = arg1;
            instructions = arg2;
            return mapWithFilter(target, filter, instructions);
        }
        else {
            instructions = arg1;
        }
    }
    for (const key of Object.keys(instructions)) {
        if (!Array.isArray(instructions[key])) {
            target[key] = instructions[key];
            continue;
        }
        let [filter, value] = instructions[key];
        if (typeof value === "function") {
            let _value;
            const defaultFilterPassed = filter === undefined && (_value = value()) != null;
            const customFilterPassed = (typeof filter === "function" && !!filter(void 0)) || (typeof filter !== "function" && !!filter);
            if (defaultFilterPassed) {
                target[key] = _value;
            }
            else if (customFilterPassed) {
                target[key] = value();
            }
        }
        else {
            const defaultFilterPassed = filter === undefined && value != null;
            const customFilterPassed = (typeof filter === "function" && !!filter(value)) || (typeof filter !== "function" && !!filter);
            if (defaultFilterPassed || customFilterPassed) {
                target[key] = value;
            }
        }
    }
    return target;
}
const mapWithFilter = (target, filter, instructions) => {
    return map$2(target, Object.entries(instructions).reduce((_instructions, [key, value]) => {
        if (Array.isArray(value)) {
            _instructions[key] = value;
        }
        else {
            if (typeof value === "function") {
                _instructions[key] = [filter, value()];
            }
            else {
                _instructions[key] = [filter, value];
            }
        }
        return _instructions;
    }, {}));
};

class SSOServiceException extends ServiceException {
    constructor(options) {
        super(options);
        Object.setPrototypeOf(this, SSOServiceException.prototype);
    }
}

class InvalidRequestException$1 extends SSOServiceException {
    constructor(opts) {
        super({
            name: "InvalidRequestException",
            $fault: "client",
            ...opts,
        });
        this.name = "InvalidRequestException";
        this.$fault = "client";
        Object.setPrototypeOf(this, InvalidRequestException$1.prototype);
    }
}
class ResourceNotFoundException extends SSOServiceException {
    constructor(opts) {
        super({
            name: "ResourceNotFoundException",
            $fault: "client",
            ...opts,
        });
        this.name = "ResourceNotFoundException";
        this.$fault = "client";
        Object.setPrototypeOf(this, ResourceNotFoundException.prototype);
    }
}
class TooManyRequestsException extends SSOServiceException {
    constructor(opts) {
        super({
            name: "TooManyRequestsException",
            $fault: "client",
            ...opts,
        });
        this.name = "TooManyRequestsException";
        this.$fault = "client";
        Object.setPrototypeOf(this, TooManyRequestsException.prototype);
    }
}
class UnauthorizedException extends SSOServiceException {
    constructor(opts) {
        super({
            name: "UnauthorizedException",
            $fault: "client",
            ...opts,
        });
        this.name = "UnauthorizedException";
        this.$fault = "client";
        Object.setPrototypeOf(this, UnauthorizedException.prototype);
    }
}
const GetRoleCredentialsRequestFilterSensitiveLog = (obj) => ({
    ...obj,
    ...(obj.accessToken && { accessToken: SENSITIVE_STRING }),
});
const RoleCredentialsFilterSensitiveLog = (obj) => ({
    ...obj,
    ...(obj.secretAccessKey && { secretAccessKey: SENSITIVE_STRING }),
    ...(obj.sessionToken && { sessionToken: SENSITIVE_STRING }),
});
const GetRoleCredentialsResponseFilterSensitiveLog = (obj) => ({
    ...obj,
    ...(obj.roleCredentials && { roleCredentials: RoleCredentialsFilterSensitiveLog(obj.roleCredentials) }),
});

class HttpRequest$1 {
    constructor(options) {
        this.method = options.method || "GET";
        this.hostname = options.hostname || "localhost";
        this.port = options.port;
        this.query = options.query || {};
        this.headers = options.headers || {};
        this.body = options.body;
        this.protocol = options.protocol
            ? options.protocol.slice(-1) !== ":"
                ? `${options.protocol}:`
                : options.protocol
            : "https:";
        this.path = options.path ? (options.path.charAt(0) !== "/" ? `/${options.path}` : options.path) : "/";
    }
    static isInstance(request) {
        if (!request)
            return false;
        const req = request;
        return ("method" in req &&
            "protocol" in req &&
            "hostname" in req &&
            "path" in req &&
            typeof req["query"] === "object" &&
            typeof req["headers"] === "object");
    }
    clone() {
        const cloned = new HttpRequest$1({
            ...this,
            headers: { ...this.headers },
        });
        if (cloned.query)
            cloned.query = cloneQuery$1(cloned.query);
        return cloned;
    }
}
function cloneQuery$1(query) {
    return Object.keys(query).reduce((carry, paramName) => {
        const param = query[paramName];
        return {
            ...carry,
            [paramName]: Array.isArray(param) ? [...param] : param,
        };
    }, {});
}

class HttpResponse {
    constructor(options) {
        this.statusCode = options.statusCode;
        this.headers = options.headers || {};
        this.body = options.body;
    }
    static isInstance(response) {
        if (!response)
            return false;
        const resp = response;
        return typeof resp.statusCode === "number" && typeof resp.headers === "object";
    }
}

function isValidHostname(hostname) {
    const hostPattern = /^[a-z0-9][a-z0-9\.\-]*[a-z0-9]$/;
    return hostPattern.test(hostname);
}

var distEs$5 = /*#__PURE__*/Object.freeze({
	__proto__: null,
	HttpRequest: HttpRequest$1,
	HttpResponse: HttpResponse,
	isValidHostname: isValidHostname
});

const serializeAws_restJson1GetRoleCredentialsCommand = async (input, context) => {
    const { hostname, protocol = "https", port, path: basePath } = await context.endpoint();
    const headers = map$1({}, isSerializableHeaderValue, {
        "x-amz-sso_bearer_token": input.accessToken,
    });
    const resolvedPath = `${basePath?.endsWith("/") ? basePath.slice(0, -1) : basePath || ""}` + "/federation/credentials";
    const query = map$1({
        role_name: [, expectNonNull(input.roleName, `roleName`)],
        account_id: [, expectNonNull(input.accountId, `accountId`)],
    });
    let body;
    return new HttpRequest$1({
        protocol,
        hostname,
        port,
        method: "GET",
        headers,
        path: resolvedPath,
        query,
        body,
    });
};
const deserializeAws_restJson1GetRoleCredentialsCommand = async (output, context) => {
    if (output.statusCode !== 200 && output.statusCode >= 300) {
        return deserializeAws_restJson1GetRoleCredentialsCommandError(output, context);
    }
    const contents = map$1({
        $metadata: deserializeMetadata$1(output),
    });
    const data = expectNonNull(expectObject(await parseBody$1(output.body, context)), "body");
    if (data.roleCredentials != null) {
        contents.roleCredentials = deserializeAws_restJson1RoleCredentials(data.roleCredentials);
    }
    return contents;
};
const deserializeAws_restJson1GetRoleCredentialsCommandError = async (output, context) => {
    const parsedOutput = {
        ...output,
        body: await parseErrorBody$1(output.body, context),
    };
    const errorCode = loadRestJsonErrorCode$1(output, parsedOutput.body);
    switch (errorCode) {
        case "InvalidRequestException":
        case "com.amazonaws.sso#InvalidRequestException":
            throw await deserializeAws_restJson1InvalidRequestExceptionResponse$1(parsedOutput);
        case "ResourceNotFoundException":
        case "com.amazonaws.sso#ResourceNotFoundException":
            throw await deserializeAws_restJson1ResourceNotFoundExceptionResponse(parsedOutput);
        case "TooManyRequestsException":
        case "com.amazonaws.sso#TooManyRequestsException":
            throw await deserializeAws_restJson1TooManyRequestsExceptionResponse(parsedOutput);
        case "UnauthorizedException":
        case "com.amazonaws.sso#UnauthorizedException":
            throw await deserializeAws_restJson1UnauthorizedExceptionResponse(parsedOutput);
        default:
            const parsedBody = parsedOutput.body;
            throwDefaultError({
                output,
                parsedBody,
                exceptionCtor: SSOServiceException,
                errorCode,
            });
    }
};
const map$1 = map$2;
const deserializeAws_restJson1InvalidRequestExceptionResponse$1 = async (parsedOutput, context) => {
    const contents = map$1({});
    const data = parsedOutput.body;
    if (data.message != null) {
        contents.message = expectString(data.message);
    }
    const exception = new InvalidRequestException$1({
        $metadata: deserializeMetadata$1(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1ResourceNotFoundExceptionResponse = async (parsedOutput, context) => {
    const contents = map$1({});
    const data = parsedOutput.body;
    if (data.message != null) {
        contents.message = expectString(data.message);
    }
    const exception = new ResourceNotFoundException({
        $metadata: deserializeMetadata$1(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1TooManyRequestsExceptionResponse = async (parsedOutput, context) => {
    const contents = map$1({});
    const data = parsedOutput.body;
    if (data.message != null) {
        contents.message = expectString(data.message);
    }
    const exception = new TooManyRequestsException({
        $metadata: deserializeMetadata$1(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1UnauthorizedExceptionResponse = async (parsedOutput, context) => {
    const contents = map$1({});
    const data = parsedOutput.body;
    if (data.message != null) {
        contents.message = expectString(data.message);
    }
    const exception = new UnauthorizedException({
        $metadata: deserializeMetadata$1(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1RoleCredentials = (output, context) => {
    return {
        accessKeyId: expectString(output.accessKeyId),
        expiration: expectLong(output.expiration),
        secretAccessKey: expectString(output.secretAccessKey),
        sessionToken: expectString(output.sessionToken),
    };
};
const deserializeMetadata$1 = (output) => ({
    httpStatusCode: output.statusCode,
    requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
    extendedRequestId: output.headers["x-amz-id-2"],
    cfId: output.headers["x-amz-cf-id"],
});
const collectBody$1 = (streamBody = new Uint8Array(), context) => {
    if (streamBody instanceof Uint8Array) {
        return Promise.resolve(streamBody);
    }
    return context.streamCollector(streamBody) || Promise.resolve(new Uint8Array());
};
const collectBodyString$1 = (streamBody, context) => collectBody$1(streamBody, context).then((body) => context.utf8Encoder(body));
const isSerializableHeaderValue = (value) => value !== undefined &&
    value !== null &&
    value !== "" &&
    (!Object.getOwnPropertyNames(value).includes("length") || value.length != 0) &&
    (!Object.getOwnPropertyNames(value).includes("size") || value.size != 0);
const parseBody$1 = (streamBody, context) => collectBodyString$1(streamBody, context).then((encoded) => {
    if (encoded.length) {
        return JSON.parse(encoded);
    }
    return {};
});
const parseErrorBody$1 = async (errorBody, context) => {
    const value = await parseBody$1(errorBody, context);
    value.message = value.message ?? value.Message;
    return value;
};
const loadRestJsonErrorCode$1 = (output, data) => {
    const findKey = (object, key) => Object.keys(object).find((k) => k.toLowerCase() === key.toLowerCase());
    const sanitizeErrorCode = (rawValue) => {
        let cleanValue = rawValue;
        if (typeof cleanValue === "number") {
            cleanValue = cleanValue.toString();
        }
        if (cleanValue.indexOf(",") >= 0) {
            cleanValue = cleanValue.split(",")[0];
        }
        if (cleanValue.indexOf(":") >= 0) {
            cleanValue = cleanValue.split(":")[0];
        }
        if (cleanValue.indexOf("#") >= 0) {
            cleanValue = cleanValue.split("#")[1];
        }
        return cleanValue;
    };
    const headerKey = findKey(output.headers, "x-amzn-errortype");
    if (headerKey !== undefined) {
        return sanitizeErrorCode(output.headers[headerKey]);
    }
    if (data.code !== undefined) {
        return sanitizeErrorCode(data.code);
    }
    if (data["__type"] !== undefined) {
        return sanitizeErrorCode(data["__type"]);
    }
};

class GetRoleCredentialsCommand extends Command {
    constructor(input) {
        super();
        this.input = input;
    }
    static getEndpointParameterInstructions() {
        return {
            UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
            Endpoint: { type: "builtInParams", name: "endpoint" },
            Region: { type: "builtInParams", name: "region" },
            UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" },
        };
    }
    resolveMiddleware(clientStack, configuration, options) {
        this.middlewareStack.use(getSerdePlugin(configuration, this.serialize, this.deserialize));
        this.middlewareStack.use(getEndpointPlugin(configuration, GetRoleCredentialsCommand.getEndpointParameterInstructions()));
        const stack = clientStack.concat(this.middlewareStack);
        const { logger } = configuration;
        const clientName = "SSOClient";
        const commandName = "GetRoleCredentialsCommand";
        const handlerExecutionContext = {
            logger,
            clientName,
            commandName,
            inputFilterSensitiveLog: GetRoleCredentialsRequestFilterSensitiveLog,
            outputFilterSensitiveLog: GetRoleCredentialsResponseFilterSensitiveLog,
        };
        const { requestHandler } = configuration;
        return stack.resolve((request) => requestHandler.handle(request.request, options || {}), handlerExecutionContext);
    }
    serialize(input, context) {
        return serializeAws_restJson1GetRoleCredentialsCommand(input, context);
    }
    deserialize(output, context) {
        return deserializeAws_restJson1GetRoleCredentialsCommand(output, context);
    }
}

var SelectorType;
(function (SelectorType) {
    SelectorType["ENV"] = "env";
    SelectorType["CONFIG"] = "shared config entry";
})(SelectorType || (SelectorType = {}));
const booleanSelector = (obj, key, type) => {
    if (!(key in obj))
        return undefined;
    if (obj[key] === "true")
        return true;
    if (obj[key] === "false")
        return false;
    throw new Error(`Cannot load ${type} "${key}". Expected "true" or "false", got ${obj[key]}.`);
};

const ENV_USE_DUALSTACK_ENDPOINT = "AWS_USE_DUALSTACK_ENDPOINT";
const CONFIG_USE_DUALSTACK_ENDPOINT = "use_dualstack_endpoint";
const NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS = {
    environmentVariableSelector: (env) => booleanSelector(env, ENV_USE_DUALSTACK_ENDPOINT, SelectorType.ENV),
    configFileSelector: (profile) => booleanSelector(profile, CONFIG_USE_DUALSTACK_ENDPOINT, SelectorType.CONFIG),
    default: false,
};

const ENV_USE_FIPS_ENDPOINT = "AWS_USE_FIPS_ENDPOINT";
const CONFIG_USE_FIPS_ENDPOINT = "use_fips_endpoint";
const NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS = {
    environmentVariableSelector: (env) => booleanSelector(env, ENV_USE_FIPS_ENDPOINT, SelectorType.ENV),
    configFileSelector: (profile) => booleanSelector(profile, CONFIG_USE_FIPS_ENDPOINT, SelectorType.CONFIG),
    default: false,
};

const REGION_ENV_NAME = "AWS_REGION";
const REGION_INI_NAME = "region";
const NODE_REGION_CONFIG_OPTIONS = {
    environmentVariableSelector: (env) => env[REGION_ENV_NAME],
    configFileSelector: (profile) => profile[REGION_INI_NAME],
    default: () => {
        throw new Error("Region is missing");
    },
};
const NODE_REGION_CONFIG_FILE_OPTIONS = {
    preferredFile: "credentials",
};

const isFipsRegion = (region) => typeof region === "string" && (region.startsWith("fips-") || region.endsWith("-fips"));

const getRealRegion = (region) => isFipsRegion(region)
    ? ["fips-aws-global", "aws-fips"].includes(region)
        ? "us-east-1"
        : region.replace(/fips-(dkr-|prod-)?|-fips/, "")
    : region;

const resolveRegionConfig = (input) => {
    const { region, useFipsEndpoint } = input;
    if (!region) {
        throw new Error("Region is missing");
    }
    return {
        ...input,
        region: async () => {
            if (typeof region === "string") {
                return getRealRegion(region);
            }
            const providedRegion = await region();
            return getRealRegion(providedRegion);
        },
        useFipsEndpoint: async () => {
            const providedRegion = typeof region === "string" ? region : await region();
            if (isFipsRegion(providedRegion)) {
                return true;
            }
            return typeof useFipsEndpoint !== "function" ? Promise.resolve(!!useFipsEndpoint) : useFipsEndpoint();
        },
    };
};

const CONTENT_LENGTH_HEADER = "content-length";
function contentLengthMiddleware(bodyLengthChecker) {
    return (next) => async (args) => {
        const request = args.request;
        if (HttpRequest$1.isInstance(request)) {
            const { body, headers } = request;
            if (body &&
                Object.keys(headers)
                    .map((str) => str.toLowerCase())
                    .indexOf(CONTENT_LENGTH_HEADER) === -1) {
                try {
                    const length = bodyLengthChecker(body);
                    request.headers = {
                        ...request.headers,
                        [CONTENT_LENGTH_HEADER]: String(length),
                    };
                }
                catch (error) {
                }
            }
        }
        return next({
            ...args,
            request,
        });
    };
}
const contentLengthMiddlewareOptions = {
    step: "build",
    tags: ["SET_CONTENT_LENGTH", "CONTENT_LENGTH"],
    name: "contentLengthMiddleware",
    override: true,
};
const getContentLengthPlugin = (options) => ({
    applyToStack: (clientStack) => {
        clientStack.add(contentLengthMiddleware(options.bodyLengthChecker), contentLengthMiddlewareOptions);
    },
});

function resolveHostHeaderConfig(input) {
    return input;
}
const hostHeaderMiddleware = (options) => (next) => async (args) => {
    if (!HttpRequest$1.isInstance(args.request))
        return next(args);
    const { request } = args;
    const { handlerProtocol = "" } = options.requestHandler.metadata || {};
    if (handlerProtocol.indexOf("h2") >= 0 && !request.headers[":authority"]) {
        delete request.headers["host"];
        request.headers[":authority"] = "";
    }
    else if (!request.headers["host"]) {
        request.headers["host"] = request.hostname;
    }
    return next(args);
};
const hostHeaderMiddlewareOptions = {
    name: "hostHeaderMiddleware",
    step: "build",
    priority: "low",
    tags: ["HOST"],
    override: true,
};
const getHostHeaderPlugin = (options) => ({
    applyToStack: (clientStack) => {
        clientStack.add(hostHeaderMiddleware(options), hostHeaderMiddlewareOptions);
    },
});

const loggerMiddleware = () => (next, context) => async (args) => {
    const response = await next(args);
    const { clientName, commandName, logger, inputFilterSensitiveLog, outputFilterSensitiveLog, dynamoDbDocumentClientOptions = {}, } = context;
    const { overrideInputFilterSensitiveLog, overrideOutputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
    if (!logger) {
        return response;
    }
    if (typeof logger.info === "function") {
        const { $metadata, ...outputWithoutMetadata } = response.output;
        logger.info({
            clientName,
            commandName,
            input: (overrideInputFilterSensitiveLog ?? inputFilterSensitiveLog)(args.input),
            output: (overrideOutputFilterSensitiveLog ?? outputFilterSensitiveLog)(outputWithoutMetadata),
            metadata: $metadata,
        });
    }
    return response;
};
const loggerMiddlewareOptions = {
    name: "loggerMiddleware",
    tags: ["LOGGER"],
    step: "initialize",
    override: true,
};
const getLoggerPlugin = (options) => ({
    applyToStack: (clientStack) => {
        clientStack.add(loggerMiddleware(), loggerMiddlewareOptions);
    },
});

const TRACE_ID_HEADER_NAME = "X-Amzn-Trace-Id";
const ENV_LAMBDA_FUNCTION_NAME = "AWS_LAMBDA_FUNCTION_NAME";
const ENV_TRACE_ID = "_X_AMZN_TRACE_ID";
const recursionDetectionMiddleware = (options) => (next) => async (args) => {
    const { request } = args;
    if (!HttpRequest$1.isInstance(request) ||
        options.runtime !== "node" ||
        request.headers.hasOwnProperty(TRACE_ID_HEADER_NAME)) {
        return next(args);
    }
    const functionName = process.env[ENV_LAMBDA_FUNCTION_NAME];
    const traceId = process.env[ENV_TRACE_ID];
    const nonEmptyString = (str) => typeof str === "string" && str.length > 0;
    if (nonEmptyString(functionName) && nonEmptyString(traceId)) {
        request.headers[TRACE_ID_HEADER_NAME] = traceId;
    }
    return next({
        ...args,
        request,
    });
};
const addRecursionDetectionMiddlewareOptions = {
    step: "build",
    tags: ["RECURSION_DETECTION"],
    name: "recursionDetectionMiddleware",
    override: true,
    priority: "low",
};
const getRecursionDetectionPlugin = (options) => ({
    applyToStack: (clientStack) => {
        clientStack.add(recursionDetectionMiddleware(options), addRecursionDetectionMiddlewareOptions);
    },
});

var RETRY_MODES;
(function (RETRY_MODES) {
    RETRY_MODES["STANDARD"] = "standard";
    RETRY_MODES["ADAPTIVE"] = "adaptive";
})(RETRY_MODES || (RETRY_MODES = {}));
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_RETRY_MODE = "STANDARD";

const THROTTLING_ERROR_CODES = [
    "BandwidthLimitExceeded",
    "EC2ThrottledException",
    "LimitExceededException",
    "PriorRequestNotComplete",
    "ProvisionedThroughputExceededException",
    "RequestLimitExceeded",
    "RequestThrottled",
    "RequestThrottledException",
    "SlowDown",
    "ThrottledException",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "TransactionInProgressException",
];
const TRANSIENT_ERROR_CODES = ["AbortError", "TimeoutError", "RequestTimeout", "RequestTimeoutException"];
const TRANSIENT_ERROR_STATUS_CODES = [500, 502, 503, 504];
const NODEJS_TIMEOUT_ERROR_CODES = ["ECONNRESET", "EPIPE", "ETIMEDOUT"];

const isThrottlingError = (error) => error.$metadata?.httpStatusCode === 429 ||
    THROTTLING_ERROR_CODES.includes(error.name) ||
    error.$retryable?.throttling == true;
const isTransientError = (error) => TRANSIENT_ERROR_CODES.includes(error.name) ||
    NODEJS_TIMEOUT_ERROR_CODES.includes(error?.code || "") ||
    TRANSIENT_ERROR_STATUS_CODES.includes(error.$metadata?.httpStatusCode || 0);
const isServerError = (error) => {
    if (error.$metadata?.httpStatusCode !== undefined) {
        const statusCode = error.$metadata.httpStatusCode;
        if (500 <= statusCode && statusCode <= 599 && !isTransientError(error)) {
            return true;
        }
        return false;
    }
    return false;
};

class DefaultRateLimiter {
    constructor(options) {
        this.currentCapacity = 0;
        this.enabled = false;
        this.lastMaxRate = 0;
        this.measuredTxRate = 0;
        this.requestCount = 0;
        this.lastTimestamp = 0;
        this.timeWindow = 0;
        this.beta = options?.beta ?? 0.7;
        this.minCapacity = options?.minCapacity ?? 1;
        this.minFillRate = options?.minFillRate ?? 0.5;
        this.scaleConstant = options?.scaleConstant ?? 0.4;
        this.smooth = options?.smooth ?? 0.8;
        const currentTimeInSeconds = this.getCurrentTimeInSeconds();
        this.lastThrottleTime = currentTimeInSeconds;
        this.lastTxRateBucket = Math.floor(this.getCurrentTimeInSeconds());
        this.fillRate = this.minFillRate;
        this.maxCapacity = this.minCapacity;
    }
    getCurrentTimeInSeconds() {
        return Date.now() / 1000;
    }
    async getSendToken() {
        return this.acquireTokenBucket(1);
    }
    async acquireTokenBucket(amount) {
        if (!this.enabled) {
            return;
        }
        this.refillTokenBucket();
        if (amount > this.currentCapacity) {
            const delay = ((amount - this.currentCapacity) / this.fillRate) * 1000;
            await new Promise((resolve) => setTimeout(resolve, delay));
        }
        this.currentCapacity = this.currentCapacity - amount;
    }
    refillTokenBucket() {
        const timestamp = this.getCurrentTimeInSeconds();
        if (!this.lastTimestamp) {
            this.lastTimestamp = timestamp;
            return;
        }
        const fillAmount = (timestamp - this.lastTimestamp) * this.fillRate;
        this.currentCapacity = Math.min(this.maxCapacity, this.currentCapacity + fillAmount);
        this.lastTimestamp = timestamp;
    }
    updateClientSendingRate(response) {
        let calculatedRate;
        this.updateMeasuredRate();
        if (isThrottlingError(response)) {
            const rateToUse = !this.enabled ? this.measuredTxRate : Math.min(this.measuredTxRate, this.fillRate);
            this.lastMaxRate = rateToUse;
            this.calculateTimeWindow();
            this.lastThrottleTime = this.getCurrentTimeInSeconds();
            calculatedRate = this.cubicThrottle(rateToUse);
            this.enableTokenBucket();
        }
        else {
            this.calculateTimeWindow();
            calculatedRate = this.cubicSuccess(this.getCurrentTimeInSeconds());
        }
        const newRate = Math.min(calculatedRate, 2 * this.measuredTxRate);
        this.updateTokenBucketRate(newRate);
    }
    calculateTimeWindow() {
        this.timeWindow = this.getPrecise(Math.pow((this.lastMaxRate * (1 - this.beta)) / this.scaleConstant, 1 / 3));
    }
    cubicThrottle(rateToUse) {
        return this.getPrecise(rateToUse * this.beta);
    }
    cubicSuccess(timestamp) {
        return this.getPrecise(this.scaleConstant * Math.pow(timestamp - this.lastThrottleTime - this.timeWindow, 3) + this.lastMaxRate);
    }
    enableTokenBucket() {
        this.enabled = true;
    }
    updateTokenBucketRate(newRate) {
        this.refillTokenBucket();
        this.fillRate = Math.max(newRate, this.minFillRate);
        this.maxCapacity = Math.max(newRate, this.minCapacity);
        this.currentCapacity = Math.min(this.currentCapacity, this.maxCapacity);
    }
    updateMeasuredRate() {
        const t = this.getCurrentTimeInSeconds();
        const timeBucket = Math.floor(t * 2) / 2;
        this.requestCount++;
        if (timeBucket > this.lastTxRateBucket) {
            const currentRate = this.requestCount / (timeBucket - this.lastTxRateBucket);
            this.measuredTxRate = this.getPrecise(currentRate * this.smooth + this.measuredTxRate * (1 - this.smooth));
            this.requestCount = 0;
            this.lastTxRateBucket = timeBucket;
        }
    }
    getPrecise(num) {
        return parseFloat(num.toFixed(8));
    }
}

const DEFAULT_RETRY_DELAY_BASE = 100;
const MAXIMUM_RETRY_DELAY = 20 * 1000;
const THROTTLING_RETRY_DELAY_BASE = 500;
const INITIAL_RETRY_TOKENS = 500;
const RETRY_COST = 5;
const TIMEOUT_RETRY_COST = 10;
const NO_RETRY_INCREMENT = 1;
const INVOCATION_ID_HEADER = "amz-sdk-invocation-id";
const REQUEST_HEADER = "amz-sdk-request";

const getDefaultRetryBackoffStrategy = () => {
    let delayBase = DEFAULT_RETRY_DELAY_BASE;
    const computeNextBackoffDelay = (attempts) => {
        return Math.floor(Math.min(MAXIMUM_RETRY_DELAY, Math.random() * 2 ** attempts * delayBase));
    };
    const setDelayBase = (delay) => {
        delayBase = delay;
    };
    return {
        computeNextBackoffDelay,
        setDelayBase,
    };
};

const getDefaultRetryToken = (initialRetryTokens, initialRetryDelay, initialRetryCount, options) => {
    const MAX_CAPACITY = initialRetryTokens;
    const retryCost = options?.retryCost ?? RETRY_COST;
    const timeoutRetryCost = options?.timeoutRetryCost ?? TIMEOUT_RETRY_COST;
    const retryBackoffStrategy = options?.retryBackoffStrategy ?? getDefaultRetryBackoffStrategy();
    let availableCapacity = initialRetryTokens;
    let retryDelay = Math.min(MAXIMUM_RETRY_DELAY, initialRetryDelay);
    let lastRetryCost = undefined;
    let retryCount = initialRetryCount ?? 0;
    const getCapacityAmount = (errorType) => (errorType === "TRANSIENT" ? timeoutRetryCost : retryCost);
    const getRetryCount = () => retryCount;
    const getRetryDelay = () => retryDelay;
    const getLastRetryCost = () => lastRetryCost;
    const hasRetryTokens = (errorType) => getCapacityAmount(errorType) <= availableCapacity;
    const getRetryTokenCount = (errorInfo) => {
        const errorType = errorInfo.errorType;
        if (!hasRetryTokens(errorType)) {
            throw new Error("No retry token available");
        }
        const capacityAmount = getCapacityAmount(errorType);
        const delayBase = errorType === "THROTTLING" ? THROTTLING_RETRY_DELAY_BASE : DEFAULT_RETRY_DELAY_BASE;
        retryBackoffStrategy.setDelayBase(delayBase);
        const delayFromErrorType = retryBackoffStrategy.computeNextBackoffDelay(retryCount);
        if (errorInfo.retryAfterHint) {
            const delayFromRetryAfterHint = errorInfo.retryAfterHint.getTime() - Date.now();
            retryDelay = Math.max(delayFromRetryAfterHint || 0, delayFromErrorType);
        }
        else {
            retryDelay = delayFromErrorType;
        }
        retryCount++;
        lastRetryCost = capacityAmount;
        availableCapacity -= capacityAmount;
        return capacityAmount;
    };
    const releaseRetryTokens = (releaseAmount) => {
        availableCapacity += releaseAmount ?? NO_RETRY_INCREMENT;
        availableCapacity = Math.min(availableCapacity, MAX_CAPACITY);
    };
    return {
        getRetryCount,
        getRetryDelay,
        getLastRetryCost,
        hasRetryTokens,
        getRetryTokenCount,
        releaseRetryTokens,
    };
};

class StandardRetryStrategy {
    constructor(maxAttemptsProvider) {
        this.maxAttemptsProvider = maxAttemptsProvider;
        this.mode = RETRY_MODES.STANDARD;
        this.retryToken = getDefaultRetryToken(INITIAL_RETRY_TOKENS, DEFAULT_RETRY_DELAY_BASE);
        this.maxAttemptsProvider = maxAttemptsProvider;
    }
    async acquireInitialRetryToken(retryTokenScope) {
        return this.retryToken;
    }
    async refreshRetryTokenForRetry(tokenToRenew, errorInfo) {
        const maxAttempts = await this.getMaxAttempts();
        if (this.shouldRetry(tokenToRenew, errorInfo, maxAttempts)) {
            tokenToRenew.getRetryTokenCount(errorInfo);
            return tokenToRenew;
        }
        throw new Error("No retry token available");
    }
    recordSuccess(token) {
        this.retryToken.releaseRetryTokens(token.getLastRetryCost());
    }
    async getMaxAttempts() {
        try {
            return await this.maxAttemptsProvider();
        }
        catch (error) {
            console.warn(`Max attempts provider could not resolve. Using default of ${DEFAULT_MAX_ATTEMPTS}`);
            return DEFAULT_MAX_ATTEMPTS;
        }
    }
    shouldRetry(tokenToRenew, errorInfo, maxAttempts) {
        const attempts = tokenToRenew.getRetryCount();
        return (attempts < maxAttempts &&
            tokenToRenew.hasRetryTokens(errorInfo.errorType) &&
            this.isRetryableError(errorInfo.errorType));
    }
    isRetryableError(errorType) {
        return errorType === "THROTTLING" || errorType === "TRANSIENT";
    }
}

class AdaptiveRetryStrategy {
    constructor(maxAttemptsProvider, options) {
        this.maxAttemptsProvider = maxAttemptsProvider;
        this.mode = RETRY_MODES.ADAPTIVE;
        const { rateLimiter } = options ?? {};
        this.rateLimiter = rateLimiter ?? new DefaultRateLimiter();
        this.standardRetryStrategy = new StandardRetryStrategy(maxAttemptsProvider);
    }
    async acquireInitialRetryToken(retryTokenScope) {
        await this.rateLimiter.getSendToken();
        return this.standardRetryStrategy.acquireInitialRetryToken(retryTokenScope);
    }
    async refreshRetryTokenForRetry(tokenToRenew, errorInfo) {
        this.rateLimiter.updateClientSendingRate(errorInfo);
        return this.standardRetryStrategy.refreshRetryTokenForRetry(tokenToRenew, errorInfo);
    }
    recordSuccess(token) {
        this.rateLimiter.updateClientSendingRate({});
        this.standardRetryStrategy.recordSuccess(token);
    }
}

// Unique ID creation requires a high quality random # generator. In the browser we therefore
// require the crypto API and do not support built-in fallback to lower quality random number
// generators (like Math.random()).
var getRandomValues;
var rnds8 = new Uint8Array(16);
function rng() {
  // lazy load so that environments that need to polyfill have a chance to do so
  if (!getRandomValues) {
    // getRandomValues needs to be invoked in a context where "this" is a Crypto implementation. Also,
    // find the complete implementation of crypto (msCrypto) on IE11.
    getRandomValues = typeof crypto !== 'undefined' && crypto.getRandomValues && crypto.getRandomValues.bind(crypto) || typeof msCrypto !== 'undefined' && typeof msCrypto.getRandomValues === 'function' && msCrypto.getRandomValues.bind(msCrypto);

    if (!getRandomValues) {
      throw new Error('crypto.getRandomValues() not supported. See https://github.com/uuidjs/uuid#getrandomvalues-not-supported');
    }
  }

  return getRandomValues(rnds8);
}

var REGEX = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;

function validate(uuid) {
  return typeof uuid === 'string' && REGEX.test(uuid);
}

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */

var byteToHex = [];

for (var i$2 = 0; i$2 < 256; ++i$2) {
  byteToHex.push((i$2 + 0x100).toString(16).substr(1));
}

function stringify(arr) {
  var offset = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 0;
  // Note: Be careful editing this code!  It's been tuned for performance
  // and works in ways you may not expect. See https://github.com/uuidjs/uuid/pull/434
  var uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase(); // Consistency check for valid UUID.  If this throws, it's likely due to one
  // of the following:
  // - One or more input array values don't map to a hex octet (leading to
  // "undefined" in the uuid)
  // - Invalid input values for the RFC `version` or `variant` fields

  if (!validate(uuid)) {
    throw TypeError('Stringified UUID is invalid');
  }

  return uuid;
}

function parse(uuid) {
  if (!validate(uuid)) {
    throw TypeError('Invalid UUID');
  }

  var v;
  var arr = new Uint8Array(16); // Parse ########-....-....-....-............

  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 0xff;
  arr[2] = v >>> 8 & 0xff;
  arr[3] = v & 0xff; // Parse ........-####-....-....-............

  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 0xff; // Parse ........-....-####-....-............

  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 0xff; // Parse ........-....-....-####-............

  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 0xff; // Parse ........-....-....-....-############
  // (Use "/" to avoid 32-bit truncation when bit-shifting high-order bytes)

  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 0x10000000000 & 0xff;
  arr[11] = v / 0x100000000 & 0xff;
  arr[12] = v >>> 24 & 0xff;
  arr[13] = v >>> 16 & 0xff;
  arr[14] = v >>> 8 & 0xff;
  arr[15] = v & 0xff;
  return arr;
}

function stringToBytes(str) {
  str = unescape(encodeURIComponent(str)); // UTF8 escape

  var bytes = [];

  for (var i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }

  return bytes;
}

var DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
var URL$1 = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
function v35 (name, version, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === 'string') {
      value = stringToBytes(value);
    }

    if (typeof namespace === 'string') {
      namespace = parse(namespace);
    }

    if (namespace.length !== 16) {
      throw TypeError('Namespace must be array-like (16 iterable integer values, 0-255)');
    } // Compute hash of namespace and value, Per 4.3
    // Future: Use spread syntax when supported on all platforms, e.g. `bytes =
    // hashfunc([...namespace, ... value])`


    var bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 0x0f | version;
    bytes[8] = bytes[8] & 0x3f | 0x80;

    if (buf) {
      offset = offset || 0;

      for (var i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }

      return buf;
    }

    return stringify(bytes);
  } // Function#name is not settable on some platforms (#270)


  try {
    generateUUID.name = name; // eslint-disable-next-line no-empty
  } catch (err) {} // For CommonJS default export support


  generateUUID.DNS = DNS;
  generateUUID.URL = URL$1;
  return generateUUID;
}

/*
 * Browser-compatible JavaScript MD5
 *
 * Modification of JavaScript MD5
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
function md5(bytes) {
  if (typeof bytes === 'string') {
    var msg = unescape(encodeURIComponent(bytes)); // UTF8 escape

    bytes = new Uint8Array(msg.length);

    for (var i = 0; i < msg.length; ++i) {
      bytes[i] = msg.charCodeAt(i);
    }
  }

  return md5ToHexEncodedArray(wordsToMd5(bytesToWords(bytes), bytes.length * 8));
}
/*
 * Convert an array of little-endian words to an array of bytes
 */


function md5ToHexEncodedArray(input) {
  var output = [];
  var length32 = input.length * 32;
  var hexTab = '0123456789abcdef';

  for (var i = 0; i < length32; i += 8) {
    var x = input[i >> 5] >>> i % 32 & 0xff;
    var hex = parseInt(hexTab.charAt(x >>> 4 & 0x0f) + hexTab.charAt(x & 0x0f), 16);
    output.push(hex);
  }

  return output;
}
/**
 * Calculate output length with padding and bit length
 */


function getOutputLength(inputLength8) {
  return (inputLength8 + 64 >>> 9 << 4) + 14 + 1;
}
/*
 * Calculate the MD5 of an array of little-endian words, and a bit length.
 */


function wordsToMd5(x, len) {
  /* append padding */
  x[len >> 5] |= 0x80 << len % 32;
  x[getOutputLength(len) - 1] = len;
  var a = 1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d = 271733878;

  for (var i = 0; i < x.length; i += 16) {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
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
 * Convert an array bytes to an array of little-endian words
 * Characters >255 have their high-byte silently ignored.
 */


function bytesToWords(input) {
  if (input.length === 0) {
    return [];
  }

  var length8 = input.length * 8;
  var output = new Uint32Array(getOutputLength(length8));

  for (var i = 0; i < length8; i += 8) {
    output[i >> 5] |= (input[i / 8] & 0xff) << i % 32;
  }

  return output;
}
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

v35('v3', 0x30, md5);

function v4(options, buf, offset) {
  options = options || {};
  var rnds = options.random || (options.rng || rng)(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`

  rnds[6] = rnds[6] & 0x0f | 0x40;
  rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided

  if (buf) {
    offset = offset || 0;

    for (var i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }

    return buf;
  }

  return stringify(rnds);
}

// Adapted from Chris Veness' SHA1 code at
// http://www.movable-type.co.uk/scripts/sha1.html
function f$2(s, x, y, z) {
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

  if (typeof bytes === 'string') {
    var msg = unescape(encodeURIComponent(bytes)); // UTF8 escape

    bytes = [];

    for (var i = 0; i < msg.length; ++i) {
      bytes.push(msg.charCodeAt(i));
    }
  } else if (!Array.isArray(bytes)) {
    // Convert Array-like to Array
    bytes = Array.prototype.slice.call(bytes);
  }

  bytes.push(0x80);
  var l = bytes.length / 4 + 2;
  var N = Math.ceil(l / 16);
  var M = new Array(N);

  for (var _i = 0; _i < N; ++_i) {
    var arr = new Uint32Array(16);

    for (var j = 0; j < 16; ++j) {
      arr[j] = bytes[_i * 64 + j * 4] << 24 | bytes[_i * 64 + j * 4 + 1] << 16 | bytes[_i * 64 + j * 4 + 2] << 8 | bytes[_i * 64 + j * 4 + 3];
    }

    M[_i] = arr;
  }

  M[N - 1][14] = (bytes.length - 1) * 8 / Math.pow(2, 32);
  M[N - 1][14] = Math.floor(M[N - 1][14]);
  M[N - 1][15] = (bytes.length - 1) * 8 & 0xffffffff;

  for (var _i2 = 0; _i2 < N; ++_i2) {
    var W = new Uint32Array(80);

    for (var t = 0; t < 16; ++t) {
      W[t] = M[_i2][t];
    }

    for (var _t = 16; _t < 80; ++_t) {
      W[_t] = ROTL(W[_t - 3] ^ W[_t - 8] ^ W[_t - 14] ^ W[_t - 16], 1);
    }

    var a = H[0];
    var b = H[1];
    var c = H[2];
    var d = H[3];
    var e = H[4];

    for (var _t2 = 0; _t2 < 80; ++_t2) {
      var s = Math.floor(_t2 / 20);
      var T = ROTL(a, 5) + f$2(s, b, c, d) + e + K[s] + W[_t2] >>> 0;
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

v35('v5', 0x50, sha1);

const asSdkError = (error) => {
    if (error instanceof Error)
        return error;
    if (error instanceof Object)
        return Object.assign(new Error(), error);
    if (typeof error === "string")
        return new Error(error);
    return new Error(`AWS SDK error wrapper for ${error}`);
};

const ENV_MAX_ATTEMPTS = "AWS_MAX_ATTEMPTS";
const CONFIG_MAX_ATTEMPTS = "max_attempts";
const NODE_MAX_ATTEMPT_CONFIG_OPTIONS = {
    environmentVariableSelector: (env) => {
        const value = env[ENV_MAX_ATTEMPTS];
        if (!value)
            return undefined;
        const maxAttempt = parseInt(value);
        if (Number.isNaN(maxAttempt)) {
            throw new Error(`Environment variable ${ENV_MAX_ATTEMPTS} mast be a number, got "${value}"`);
        }
        return maxAttempt;
    },
    configFileSelector: (profile) => {
        const value = profile[CONFIG_MAX_ATTEMPTS];
        if (!value)
            return undefined;
        const maxAttempt = parseInt(value);
        if (Number.isNaN(maxAttempt)) {
            throw new Error(`Shared config file entry ${CONFIG_MAX_ATTEMPTS} mast be a number, got "${value}"`);
        }
        return maxAttempt;
    },
    default: DEFAULT_MAX_ATTEMPTS,
};
const resolveRetryConfig = (input) => {
    const { retryStrategy } = input;
    const maxAttempts = normalizeProvider(input.maxAttempts ?? DEFAULT_MAX_ATTEMPTS);
    return {
        ...input,
        maxAttempts,
        retryStrategy: async () => {
            if (retryStrategy) {
                return retryStrategy;
            }
            const retryMode = await normalizeProvider(input.retryMode)();
            if (retryMode === RETRY_MODES.ADAPTIVE) {
                return new AdaptiveRetryStrategy(maxAttempts);
            }
            return new StandardRetryStrategy(maxAttempts);
        },
    };
};
const ENV_RETRY_MODE = "AWS_RETRY_MODE";
const CONFIG_RETRY_MODE = "retry_mode";
const NODE_RETRY_MODE_CONFIG_OPTIONS = {
    environmentVariableSelector: (env) => env[ENV_RETRY_MODE],
    configFileSelector: (profile) => profile[CONFIG_RETRY_MODE],
    default: DEFAULT_RETRY_MODE,
};

const retryMiddleware = (options) => (next, context) => async (args) => {
    let retryStrategy = await options.retryStrategy();
    const maxAttempts = await options.maxAttempts();
    if (isRetryStrategyV2(retryStrategy)) {
        retryStrategy = retryStrategy;
        let retryToken = await retryStrategy.acquireInitialRetryToken(context["partition_id"]);
        let lastError = new Error();
        let attempts = 0;
        let totalRetryDelay = 0;
        const { request } = args;
        if (HttpRequest$1.isInstance(request)) {
            request.headers[INVOCATION_ID_HEADER] = v4();
        }
        while (true) {
            try {
                if (HttpRequest$1.isInstance(request)) {
                    request.headers[REQUEST_HEADER] = `attempt=${attempts + 1}; max=${maxAttempts}`;
                }
                const { response, output } = await next(args);
                retryStrategy.recordSuccess(retryToken);
                output.$metadata.attempts = attempts + 1;
                output.$metadata.totalRetryDelay = totalRetryDelay;
                return { response, output };
            }
            catch (e) {
                const retryErrorInfo = getRetyErrorInto(e);
                lastError = asSdkError(e);
                try {
                    retryToken = await retryStrategy.refreshRetryTokenForRetry(retryToken, retryErrorInfo);
                }
                catch (refreshError) {
                    if (!lastError.$metadata) {
                        lastError.$metadata = {};
                    }
                    lastError.$metadata.attempts = attempts + 1;
                    lastError.$metadata.totalRetryDelay = totalRetryDelay;
                    throw lastError;
                }
                attempts = retryToken.getRetryCount();
                const delay = retryToken.getRetryDelay();
                totalRetryDelay += delay;
                await new Promise((resolve) => setTimeout(resolve, delay));
            }
        }
    }
    else {
        retryStrategy = retryStrategy;
        if (retryStrategy?.mode)
            context.userAgent = [...(context.userAgent || []), ["cfg/retry-mode", retryStrategy.mode]];
        return retryStrategy.retry(next, args);
    }
};
const isRetryStrategyV2 = (retryStrategy) => typeof retryStrategy.acquireInitialRetryToken !== "undefined" &&
    typeof retryStrategy.refreshRetryTokenForRetry !== "undefined" &&
    typeof retryStrategy.recordSuccess !== "undefined";
const getRetyErrorInto = (error) => {
    const errorInfo = {
        errorType: getRetryErrorType(error),
    };
    const retryAfterHint = getRetryAfterHint(error.$response);
    if (retryAfterHint) {
        errorInfo.retryAfterHint = retryAfterHint;
    }
    return errorInfo;
};
const getRetryErrorType = (error) => {
    if (isThrottlingError(error))
        return "THROTTLING";
    if (isTransientError(error))
        return "TRANSIENT";
    if (isServerError(error))
        return "SERVER_ERROR";
    return "CLIENT_ERROR";
};
const retryMiddlewareOptions = {
    name: "retryMiddleware",
    tags: ["RETRY"],
    step: "finalizeRequest",
    priority: "high",
    override: true,
};
const getRetryPlugin = (options) => ({
    applyToStack: (clientStack) => {
        clientStack.add(retryMiddleware(options), retryMiddlewareOptions);
    },
});
const getRetryAfterHint = (response) => {
    if (!HttpResponse.isInstance(response))
        return;
    const retryAfterHeaderName = Object.keys(response.headers).find((key) => key.toLowerCase() === "retry-after");
    if (!retryAfterHeaderName)
        return;
    const retryAfter = response.headers[retryAfterHeaderName];
    const retryAfterSeconds = Number(retryAfter);
    if (!Number.isNaN(retryAfterSeconds))
        return new Date(retryAfterSeconds * 1000);
    const retryAfterDate = new Date(retryAfter);
    return retryAfterDate;
};

function resolveUserAgentConfig(input) {
    return {
        ...input,
        customUserAgent: typeof input.customUserAgent === "string" ? [[input.customUserAgent]] : input.customUserAgent,
    };
}

const USER_AGENT = "user-agent";
const X_AMZ_USER_AGENT = "x-amz-user-agent";
const SPACE = " ";
const UA_ESCAPE_REGEX = /[^\!\#\$\%\&\'\*\+\-\.\^\_\`\|\~\d\w]/g;

const userAgentMiddleware = (options) => (next, context) => async (args) => {
    const { request } = args;
    if (!HttpRequest$1.isInstance(request))
        return next(args);
    const { headers } = request;
    const userAgent = context?.userAgent?.map(escapeUserAgent) || [];
    const defaultUserAgent = (await options.defaultUserAgentProvider()).map(escapeUserAgent);
    const customUserAgent = options?.customUserAgent?.map(escapeUserAgent) || [];
    const sdkUserAgentValue = [...defaultUserAgent, ...userAgent, ...customUserAgent].join(SPACE);
    const normalUAValue = [
        ...defaultUserAgent.filter((section) => section.startsWith("aws-sdk-")),
        ...customUserAgent,
    ].join(SPACE);
    if (options.runtime !== "browser") {
        if (normalUAValue) {
            headers[X_AMZ_USER_AGENT] = headers[X_AMZ_USER_AGENT]
                ? `${headers[USER_AGENT]} ${normalUAValue}`
                : normalUAValue;
        }
        headers[USER_AGENT] = sdkUserAgentValue;
    }
    else {
        headers[X_AMZ_USER_AGENT] = sdkUserAgentValue;
    }
    return next({
        ...args,
        request,
    });
};
const escapeUserAgent = ([name, version]) => {
    const prefixSeparatorIndex = name.indexOf("/");
    const prefix = name.substring(0, prefixSeparatorIndex);
    let uaName = name.substring(prefixSeparatorIndex + 1);
    if (prefix === "api") {
        uaName = uaName.toLowerCase();
    }
    return [prefix, uaName, version]
        .filter((item) => item && item.length > 0)
        .map((item) => item?.replace(UA_ESCAPE_REGEX, "_"))
        .join("/");
};
const getUserAgentMiddlewareOptions = {
    name: "getUserAgentMiddleware",
    step: "build",
    priority: "low",
    tags: ["SET_USER_AGENT", "USER_AGENT"],
    override: true,
};
const getUserAgentPlugin = (config) => ({
    applyToStack: (clientStack) => {
        clientStack.add(userAgentMiddleware(config), getUserAgentMiddlewareOptions);
    },
});

const resolveClientEndpointParameters$1 = (options) => {
    return {
        ...options,
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        defaultSigningName: "awsssoportal",
    };
};

var name$1 = "@aws-sdk/client-sso";
var description$1 = "AWS SDK for JavaScript Sso Client for Node.js, Browser and React Native";
var version$2 = "3.245.0";
var scripts$1 = {
	build: "concurrently 'yarn:build:cjs' 'yarn:build:es' 'yarn:build:types'",
	"build:cjs": "tsc -p tsconfig.cjs.json",
	"build:docs": "typedoc",
	"build:es": "tsc -p tsconfig.es.json",
	"build:include:deps": "lerna run --scope $npm_package_name --include-dependencies build",
	"build:types": "tsc -p tsconfig.types.json",
	"build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
	clean: "rimraf ./dist-* && rimraf *.tsbuildinfo",
	"generate:client": "(cd ../../ && yarn generate-clients -g ./codegen/sdk-codegen/aws-models/sso.json --keepFiles)"
};
var main$1 = "./dist-cjs/index.js";
var types$1 = "./dist-types/index.d.ts";
var module$2 = "./dist-es/index.js";
var sideEffects$1 = false;
var dependencies$1 = {
	"@aws-crypto/sha256-browser": "2.0.0",
	"@aws-crypto/sha256-js": "2.0.0",
	"@aws-sdk/config-resolver": "3.234.0",
	"@aws-sdk/fetch-http-handler": "3.226.0",
	"@aws-sdk/hash-node": "3.226.0",
	"@aws-sdk/invalid-dependency": "3.226.0",
	"@aws-sdk/middleware-content-length": "3.226.0",
	"@aws-sdk/middleware-endpoint": "3.226.0",
	"@aws-sdk/middleware-host-header": "3.226.0",
	"@aws-sdk/middleware-logger": "3.226.0",
	"@aws-sdk/middleware-recursion-detection": "3.226.0",
	"@aws-sdk/middleware-retry": "3.235.0",
	"@aws-sdk/middleware-serde": "3.226.0",
	"@aws-sdk/middleware-stack": "3.226.0",
	"@aws-sdk/middleware-user-agent": "3.226.0",
	"@aws-sdk/node-config-provider": "3.226.0",
	"@aws-sdk/node-http-handler": "3.226.0",
	"@aws-sdk/protocol-http": "3.226.0",
	"@aws-sdk/smithy-client": "3.234.0",
	"@aws-sdk/types": "3.226.0",
	"@aws-sdk/url-parser": "3.226.0",
	"@aws-sdk/util-base64": "3.208.0",
	"@aws-sdk/util-body-length-browser": "3.188.0",
	"@aws-sdk/util-body-length-node": "3.208.0",
	"@aws-sdk/util-defaults-mode-browser": "3.234.0",
	"@aws-sdk/util-defaults-mode-node": "3.234.0",
	"@aws-sdk/util-endpoints": "3.245.0",
	"@aws-sdk/util-retry": "3.229.0",
	"@aws-sdk/util-user-agent-browser": "3.226.0",
	"@aws-sdk/util-user-agent-node": "3.226.0",
	"@aws-sdk/util-utf8-browser": "3.188.0",
	"@aws-sdk/util-utf8-node": "3.208.0",
	tslib: "^2.3.1"
};
var devDependencies$1 = {
	"@aws-sdk/service-client-documentation-generator": "3.208.0",
	"@tsconfig/node14": "1.0.3",
	"@types/node": "^14.14.31",
	concurrently: "7.0.0",
	"downlevel-dts": "0.10.1",
	rimraf: "3.0.2",
	typedoc: "0.19.2",
	typescript: "~4.6.2"
};
var overrides$1 = {
	typedoc: {
		typescript: "~4.6.2"
	}
};
var engines$1 = {
	node: ">=14.0.0"
};
var typesVersions$1 = {
	"<4.0": {
		"dist-types/*": [
			"dist-types/ts3.4/*"
		]
	}
};
var files$1 = [
	"dist-*"
];
var author$1 = {
	name: "AWS SDK for JavaScript Team",
	url: "https://aws.amazon.com/javascript/"
};
var license$1 = "Apache-2.0";
var browser$1 = {
	"./dist-es/runtimeConfig": "./dist-es/runtimeConfig.browser"
};
var homepage$1 = "https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-sso";
var repository$1 = {
	type: "git",
	url: "https://github.com/aws/aws-sdk-js-v3.git",
	directory: "clients/client-sso"
};
var packageInfo$1 = {
	name: name$1,
	description: description$1,
	version: version$2,
	scripts: scripts$1,
	main: main$1,
	types: types$1,
	module: module$2,
	sideEffects: sideEffects$1,
	dependencies: dependencies$1,
	devDependencies: devDependencies$1,
	overrides: overrides$1,
	engines: engines$1,
	typesVersions: typesVersions$1,
	files: files$1,
	author: author$1,
	license: license$1,
	browser: browser$1,
	"react-native": {
	"./dist-es/runtimeConfig": "./dist-es/runtimeConfig.native"
},
	homepage: homepage$1,
	repository: repository$1
};

const isArrayBuffer = (arg) => (typeof ArrayBuffer === "function" && arg instanceof ArrayBuffer) ||
    Object.prototype.toString.call(arg) === "[object ArrayBuffer]";

const fromArrayBuffer = (input, offset = 0, length = input.byteLength - offset) => {
    if (!isArrayBuffer(input)) {
        throw new TypeError(`The "input" argument must be ArrayBuffer. Received type ${typeof input} (${input})`);
    }
    return node_buffer.Buffer.from(input, offset, length);
};
const fromString = (input, encoding) => {
    if (typeof input !== "string") {
        throw new TypeError(`The "input" argument must be of type string. Received type ${typeof input} (${input})`);
    }
    return encoding ? node_buffer.Buffer.from(input, encoding) : node_buffer.Buffer.from(input);
};

class Hash {
    constructor(algorithmIdentifier, secret) {
        this.hash = secret ? require$$1.createHmac(algorithmIdentifier, castSourceData(secret)) : require$$1.createHash(algorithmIdentifier);
    }
    update(toHash, encoding) {
        this.hash.update(castSourceData(toHash, encoding));
    }
    digest() {
        return Promise.resolve(this.hash.digest());
    }
}
function castSourceData(toCast, encoding) {
    if (node_buffer.Buffer.isBuffer(toCast)) {
        return toCast;
    }
    if (typeof toCast === "string") {
        return fromString(toCast, encoding);
    }
    if (ArrayBuffer.isView(toCast)) {
        return fromArrayBuffer(toCast.buffer, toCast.byteOffset, toCast.byteLength);
    }
    return fromArrayBuffer(toCast);
}

const calculateBodyLength = (body) => {
    if (!body) {
        return 0;
    }
    if (typeof body === "string") {
        return Buffer.from(body).length;
    }
    else if (typeof body.byteLength === "number") {
        return body.byteLength;
    }
    else if (typeof body.size === "number") {
        return body.size;
    }
    else if (typeof body.path === "string" || Buffer.isBuffer(body.path)) {
        return node_fs.lstatSync(body.path).size;
    }
    else if (typeof body.fd === "number") {
        return node_fs.fstatSync(body.fd).size;
    }
    throw new Error(`Body Length computation failed for ${body}`);
};

const isCrtAvailable = () => {
    try {
        if (typeof require === "function" && typeof module !== "undefined" && module.require && require("aws-crt")) {
            return ["md/crt-avail"];
        }
        return null;
    }
    catch (e) {
        return null;
    }
};

const UA_APP_ID_ENV_NAME = "AWS_SDK_UA_APP_ID";
const UA_APP_ID_INI_NAME = "sdk-ua-app-id";
const defaultUserAgent = ({ serviceId, clientVersion }) => {
    const sections = [
        ["aws-sdk-js", clientVersion],
        [`os/${node_os.platform()}`, node_os.release()],
        ["lang/js"],
        ["md/nodejs", `${node_process.versions.node}`],
    ];
    const crtAvailable = isCrtAvailable();
    if (crtAvailable) {
        sections.push(crtAvailable);
    }
    if (serviceId) {
        sections.push([`api/${serviceId}`, clientVersion]);
    }
    if (node_process.env.AWS_EXECUTION_ENV) {
        sections.push([`exec-env/${node_process.env.AWS_EXECUTION_ENV}`]);
    }
    const appIdPromise = loadConfig({
        environmentVariableSelector: (env) => env[UA_APP_ID_ENV_NAME],
        configFileSelector: (profile) => profile[UA_APP_ID_INI_NAME],
        default: undefined,
    })();
    let resolvedUserAgent = undefined;
    return async () => {
        if (!resolvedUserAgent) {
            const appId = await appIdPromise;
            resolvedUserAgent = appId ? [...sections, [`app/${appId}`]] : [...sections];
        }
        return resolvedUserAgent;
    };
};

const fromUtf8$4 = (input) => {
    const buf = fromString(input, "utf8");
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength / Uint8Array.BYTES_PER_ELEMENT);
};
const toUtf8$3 = (input) => fromArrayBuffer(input.buffer, input.byteOffset, input.byteLength).toString("utf8");

const BASE64_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;
const fromBase64 = (input) => {
    if ((input.length * 3) % 4 !== 0) {
        throw new TypeError(`Incorrect padding on base64 string.`);
    }
    if (!BASE64_REGEX.exec(input)) {
        throw new TypeError(`Invalid base64 string.`);
    }
    const buffer = fromString(input, "base64");
    return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
};

const toBase64 = (input) => fromArrayBuffer(input.buffer, input.byteOffset, input.byteLength).toString("base64");

var partitions$1 = [
	{
		id: "aws",
		outputs: {
			dnsSuffix: "amazonaws.com",
			dualStackDnsSuffix: "api.aws",
			name: "aws",
			supportsDualStack: true,
			supportsFIPS: true
		},
		regionRegex: "^(us|eu|ap|sa|ca|me|af)\\-\\w+\\-\\d+$",
		regions: {
			"af-south-1": {
				description: "Africa (Cape Town)"
			},
			"ap-east-1": {
				description: "Asia Pacific (Hong Kong)"
			},
			"ap-northeast-1": {
				description: "Asia Pacific (Tokyo)"
			},
			"ap-northeast-2": {
				description: "Asia Pacific (Seoul)"
			},
			"ap-northeast-3": {
				description: "Asia Pacific (Osaka)"
			},
			"ap-south-1": {
				description: "Asia Pacific (Mumbai)"
			},
			"ap-south-2": {
				description: "Asia Pacific (Hyderabad)"
			},
			"ap-southeast-1": {
				description: "Asia Pacific (Singapore)"
			},
			"ap-southeast-2": {
				description: "Asia Pacific (Sydney)"
			},
			"ap-southeast-3": {
				description: "Asia Pacific (Jakarta)"
			},
			"aws-global": {
				description: "AWS Standard global region"
			},
			"ca-central-1": {
				description: "Canada (Central)"
			},
			"eu-central-1": {
				description: "Europe (Frankfurt)"
			},
			"eu-central-2": {
				description: "Europe (Zurich)"
			},
			"eu-north-1": {
				description: "Europe (Stockholm)"
			},
			"eu-south-1": {
				description: "Europe (Milan)"
			},
			"eu-south-2": {
				description: "Europe (Spain)"
			},
			"eu-west-1": {
				description: "Europe (Ireland)"
			},
			"eu-west-2": {
				description: "Europe (London)"
			},
			"eu-west-3": {
				description: "Europe (Paris)"
			},
			"me-central-1": {
				description: "Middle East (UAE)"
			},
			"me-south-1": {
				description: "Middle East (Bahrain)"
			},
			"sa-east-1": {
				description: "South America (Sao Paulo)"
			},
			"us-east-1": {
				description: "US East (N. Virginia)"
			},
			"us-east-2": {
				description: "US East (Ohio)"
			},
			"us-west-1": {
				description: "US West (N. California)"
			},
			"us-west-2": {
				description: "US West (Oregon)"
			}
		}
	},
	{
		id: "aws-cn",
		outputs: {
			dnsSuffix: "amazonaws.com.cn",
			dualStackDnsSuffix: "api.amazonwebservices.com.cn",
			name: "aws-cn",
			supportsDualStack: true,
			supportsFIPS: true
		},
		regionRegex: "^cn\\-\\w+\\-\\d+$",
		regions: {
			"aws-cn-global": {
				description: "AWS China global region"
			},
			"cn-north-1": {
				description: "China (Beijing)"
			},
			"cn-northwest-1": {
				description: "China (Ningxia)"
			}
		}
	},
	{
		id: "aws-us-gov",
		outputs: {
			dnsSuffix: "amazonaws.com",
			dualStackDnsSuffix: "api.aws",
			name: "aws-us-gov",
			supportsDualStack: true,
			supportsFIPS: true
		},
		regionRegex: "^us\\-gov\\-\\w+\\-\\d+$",
		regions: {
			"aws-us-gov-global": {
				description: "AWS GovCloud (US) global region"
			},
			"us-gov-east-1": {
				description: "AWS GovCloud (US-East)"
			},
			"us-gov-west-1": {
				description: "AWS GovCloud (US-West)"
			}
		}
	},
	{
		id: "aws-iso",
		outputs: {
			dnsSuffix: "c2s.ic.gov",
			dualStackDnsSuffix: "c2s.ic.gov",
			name: "aws-iso",
			supportsDualStack: false,
			supportsFIPS: true
		},
		regionRegex: "^us\\-iso\\-\\w+\\-\\d+$",
		regions: {
			"aws-iso-global": {
				description: "AWS ISO (US) global region"
			},
			"us-iso-east-1": {
				description: "US ISO East"
			},
			"us-iso-west-1": {
				description: "US ISO WEST"
			}
		}
	},
	{
		id: "aws-iso-b",
		outputs: {
			dnsSuffix: "sc2s.sgov.gov",
			dualStackDnsSuffix: "sc2s.sgov.gov",
			name: "aws-iso-b",
			supportsDualStack: false,
			supportsFIPS: true
		},
		regionRegex: "^us\\-isob\\-\\w+\\-\\d+$",
		regions: {
			"aws-iso-b-global": {
				description: "AWS ISOB (US) global region"
			},
			"us-isob-east-1": {
				description: "US ISOB East (Ohio)"
			}
		}
	}
];
var version$1 = "1.1";
var partitionsInfo = {
	partitions: partitions$1,
	version: version$1
};

const { partitions } = partitionsInfo;
const DEFAULT_PARTITION = partitions.find((partition) => partition.id === "aws");
const partition = (value) => {
    for (const partition of partitions) {
        const { regions, outputs } = partition;
        for (const [region, regionData] of Object.entries(regions)) {
            if (region === value) {
                return {
                    ...outputs,
                    ...regionData,
                };
            }
        }
    }
    for (const partition of partitions) {
        const { regionRegex, outputs } = partition;
        if (new RegExp(regionRegex).test(value)) {
            return {
                ...outputs,
            };
        }
    }
    if (!DEFAULT_PARTITION) {
        throw new Error("Provided region was not found in the partition array or regex," +
            " and default partition with id 'aws' doesn't exist.");
    }
    return {
        ...DEFAULT_PARTITION.outputs,
    };
};

const debugId = "endpoints";

function toDebugString(input) {
    if (typeof input !== "object" || input == null) {
        return input;
    }
    if ("ref" in input) {
        return `$${toDebugString(input.ref)}`;
    }
    if ("fn" in input) {
        return `${input.fn}(${(input.argv || []).map(toDebugString).join(", ")})`;
    }
    return JSON.stringify(input, null, 2);
}

class EndpointError extends Error {
    constructor(message) {
        super(message);
        this.name = "EndpointError";
    }
}

const IP_V4_REGEX = new RegExp(`^(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}$`);
const isIpAddress = (value) => IP_V4_REGEX.test(value) || (value.startsWith("[") && value.endsWith("]"));

const VALID_HOST_LABEL_REGEX = new RegExp(`^(?!.*-$)(?!-)[a-zA-Z0-9-]{1,63}$`);
const isValidHostLabel = (value, allowSubDomains = false) => {
    if (!allowSubDomains) {
        return VALID_HOST_LABEL_REGEX.test(value);
    }
    const labels = value.split(".");
    for (const label of labels) {
        if (!isValidHostLabel(label)) {
            return false;
        }
    }
    return true;
};

const isVirtualHostableS3Bucket = (value, allowSubDomains = false) => {
    if (allowSubDomains) {
        for (const label of value.split(".")) {
            if (!isVirtualHostableS3Bucket(label)) {
                return false;
            }
        }
        return true;
    }
    if (!isValidHostLabel(value)) {
        return false;
    }
    if (value.length < 3 || value.length > 63) {
        return false;
    }
    if (value !== value.toLowerCase()) {
        return false;
    }
    if (isIpAddress(value)) {
        return false;
    }
    return true;
};

const parseArn = (value) => {
    const segments = value.split(":");
    if (segments.length < 6)
        return null;
    const [arn, partition, service, region, accountId, ...resourceId] = segments;
    if (arn !== "arn" || partition === "" || service === "" || resourceId[0] === "")
        return null;
    return {
        partition,
        service,
        region,
        accountId,
        resourceId: resourceId[0].includes("/") ? resourceId[0].split("/") : resourceId,
    };
};

var index = /*#__PURE__*/Object.freeze({
	__proto__: null,
	isVirtualHostableS3Bucket: isVirtualHostableS3Bucket,
	parseArn: parseArn,
	partition: partition
});

const booleanEquals = (value1, value2) => value1 === value2;

const getAttrPathList = (path) => {
    const parts = path.split(".");
    const pathList = [];
    for (const part of parts) {
        const squareBracketIndex = part.indexOf("[");
        if (squareBracketIndex !== -1) {
            if (part.indexOf("]") !== part.length - 1) {
                throw new EndpointError(`Path: '${path}' does not end with ']'`);
            }
            const arrayIndex = part.slice(squareBracketIndex + 1, -1);
            if (Number.isNaN(parseInt(arrayIndex))) {
                throw new EndpointError(`Invalid array index: '${arrayIndex}' in path: '${path}'`);
            }
            if (squareBracketIndex !== 0) {
                pathList.push(part.slice(0, squareBracketIndex));
            }
            pathList.push(arrayIndex);
        }
        else {
            pathList.push(part);
        }
    }
    return pathList;
};

const getAttr = (value, path) => getAttrPathList(path).reduce((acc, index) => {
    if (typeof acc !== "object") {
        throw new EndpointError(`Index '${index}' in '${path}' not found in '${JSON.stringify(value)}'`);
    }
    else if (Array.isArray(acc)) {
        return acc[parseInt(index)];
    }
    return acc[index];
}, value);

const isSet = (value) => value != null;

const not = (value) => !value;

var EndpointURLScheme;
(function (EndpointURLScheme) {
    EndpointURLScheme["HTTP"] = "http";
    EndpointURLScheme["HTTPS"] = "https";
})(EndpointURLScheme || (EndpointURLScheme = {}));

const DEFAULT_PORTS = {
    [EndpointURLScheme.HTTP]: 80,
    [EndpointURLScheme.HTTPS]: 443,
};
const parseURL = (value) => {
    const whatwgURL = (() => {
        try {
            if (value instanceof URL) {
                return value;
            }
            if (typeof value === "object" && "hostname" in value) {
                const { hostname, port, protocol = "", path = "", query = {} } = value;
                const url = new URL(`${protocol}//${hostname}${port ? `:${port}` : ""}${path}`);
                url.search = Object.entries(query)
                    .map(([k, v]) => `${k}=${v}`)
                    .join("&");
                return url;
            }
            return new URL(value);
        }
        catch (error) {
            return null;
        }
    })();
    if (!whatwgURL) {
        console.error(`Unable to parse ${JSON.stringify(value)} as a whatwg URL.`);
        return null;
    }
    const urlString = whatwgURL.href;
    const { host, hostname, pathname, protocol, search } = whatwgURL;
    if (search) {
        return null;
    }
    const scheme = protocol.slice(0, -1);
    if (!Object.values(EndpointURLScheme).includes(scheme)) {
        return null;
    }
    const isIp = isIpAddress(hostname);
    const inputContainsDefaultPort = urlString.includes(`${host}:${DEFAULT_PORTS[scheme]}`) ||
        (typeof value === "string" && value.includes(`${host}:${DEFAULT_PORTS[scheme]}`));
    const authority = `${host}${inputContainsDefaultPort ? `:${DEFAULT_PORTS[scheme]}` : ``}`;
    return {
        scheme,
        authority,
        path: pathname,
        normalizedPath: pathname.endsWith("/") ? pathname : `${pathname}/`,
        isIp,
    };
};

const stringEquals = (value1, value2) => value1 === value2;

const substring = (input, start, stop, reverse) => {
    if (start >= stop || input.length < stop) {
        return null;
    }
    if (!reverse) {
        return input.substring(start, stop);
    }
    return input.substring(input.length - stop, input.length - start);
};

const uriEncode = (value) => encodeURIComponent(value).replace(/[!*'()]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

var lib$1 = /*#__PURE__*/Object.freeze({
	__proto__: null,
	aws: index,
	booleanEquals: booleanEquals,
	getAttr: getAttr,
	isSet: isSet,
	isValidHostLabel: isValidHostLabel,
	not: not,
	parseURL: parseURL,
	stringEquals: stringEquals,
	substring: substring,
	uriEncode: uriEncode
});

const evaluateTemplate = (template, options) => {
    const evaluatedTemplateArr = [];
    const templateContext = {
        ...options.endpointParams,
        ...options.referenceRecord,
    };
    let currentIndex = 0;
    while (currentIndex < template.length) {
        const openingBraceIndex = template.indexOf("{", currentIndex);
        if (openingBraceIndex === -1) {
            evaluatedTemplateArr.push(template.slice(currentIndex));
            break;
        }
        evaluatedTemplateArr.push(template.slice(currentIndex, openingBraceIndex));
        const closingBraceIndex = template.indexOf("}", openingBraceIndex);
        if (closingBraceIndex === -1) {
            evaluatedTemplateArr.push(template.slice(openingBraceIndex));
            break;
        }
        if (template[openingBraceIndex + 1] === "{" && template[closingBraceIndex + 1] === "}") {
            evaluatedTemplateArr.push(template.slice(openingBraceIndex + 1, closingBraceIndex));
            currentIndex = closingBraceIndex + 2;
        }
        const parameterName = template.substring(openingBraceIndex + 1, closingBraceIndex);
        if (parameterName.includes("#")) {
            const [refName, attrName] = parameterName.split("#");
            evaluatedTemplateArr.push(getAttr(templateContext[refName], attrName));
        }
        else {
            evaluatedTemplateArr.push(templateContext[parameterName]);
        }
        currentIndex = closingBraceIndex + 1;
    }
    return evaluatedTemplateArr.join("");
};

const getReferenceValue = ({ ref }, options) => {
    const referenceRecord = {
        ...options.endpointParams,
        ...options.referenceRecord,
    };
    return referenceRecord[ref];
};

const evaluateExpression = (obj, keyName, options) => {
    if (typeof obj === "string") {
        return evaluateTemplate(obj, options);
    }
    else if (obj["fn"]) {
        return callFunction(obj, options);
    }
    else if (obj["ref"]) {
        return getReferenceValue(obj, options);
    }
    throw new EndpointError(`'${keyName}': ${String(obj)} is not a string, function or reference.`);
};

const callFunction = ({ fn, argv }, options) => {
    const evaluatedArgs = argv.map((arg) => ["boolean", "number"].includes(typeof arg) ? arg : evaluateExpression(arg, "arg", options));
    return fn.split(".").reduce((acc, key) => acc[key], lib$1)(...evaluatedArgs);
};

const evaluateCondition = ({ assign, ...fnArgs }, options) => {
    if (assign && assign in options.referenceRecord) {
        throw new EndpointError(`'${assign}' is already defined in Reference Record.`);
    }
    const value = callFunction(fnArgs, options);
    options.logger?.debug?.(debugId, `evaluateCondition: ${toDebugString(fnArgs)} = ${toDebugString(value)}`);
    return {
        result: value === "" ? true : !!value,
        ...(assign != null && { toAssign: { name: assign, value } }),
    };
};

const evaluateConditions = (conditions = [], options) => {
    const conditionsReferenceRecord = {};
    for (const condition of conditions) {
        const { result, toAssign } = evaluateCondition(condition, {
            ...options,
            referenceRecord: {
                ...options.referenceRecord,
                ...conditionsReferenceRecord,
            },
        });
        if (!result) {
            return { result };
        }
        if (toAssign) {
            conditionsReferenceRecord[toAssign.name] = toAssign.value;
            options.logger?.debug?.(debugId, `assign: ${toAssign.name} := ${toDebugString(toAssign.value)}`);
        }
    }
    return { result: true, referenceRecord: conditionsReferenceRecord };
};

const getEndpointHeaders = (headers, options) => Object.entries(headers).reduce((acc, [headerKey, headerVal]) => ({
    ...acc,
    [headerKey]: headerVal.map((headerValEntry) => {
        const processedExpr = evaluateExpression(headerValEntry, "Header value entry", options);
        if (typeof processedExpr !== "string") {
            throw new EndpointError(`Header '${headerKey}' value '${processedExpr}' is not a string`);
        }
        return processedExpr;
    }),
}), {});

const getEndpointProperty = (property, options) => {
    if (Array.isArray(property)) {
        return property.map((propertyEntry) => getEndpointProperty(propertyEntry, options));
    }
    switch (typeof property) {
        case "string":
            return evaluateTemplate(property, options);
        case "object":
            if (property === null) {
                throw new EndpointError(`Unexpected endpoint property: ${property}`);
            }
            return getEndpointProperties(property, options);
        case "boolean":
            return property;
        default:
            throw new EndpointError(`Unexpected endpoint property type: ${typeof property}`);
    }
};

const getEndpointProperties = (properties, options) => Object.entries(properties).reduce((acc, [propertyKey, propertyVal]) => ({
    ...acc,
    [propertyKey]: getEndpointProperty(propertyVal, options),
}), {});

const getEndpointUrl = (endpointUrl, options) => {
    const expression = evaluateExpression(endpointUrl, "Endpoint URL", options);
    if (typeof expression === "string") {
        try {
            return new URL(expression);
        }
        catch (error) {
            console.error(`Failed to construct URL with ${expression}`, error);
            throw error;
        }
    }
    throw new EndpointError(`Endpoint URL must be a string, got ${typeof expression}`);
};

const evaluateEndpointRule = (endpointRule, options) => {
    const { conditions, endpoint } = endpointRule;
    const { result, referenceRecord } = evaluateConditions(conditions, options);
    if (!result) {
        return;
    }
    const endpointRuleOptions = {
        ...options,
        referenceRecord: { ...options.referenceRecord, ...referenceRecord },
    };
    const { url, properties, headers } = endpoint;
    options.logger?.debug?.(debugId, `Resolving endpoint from template: ${toDebugString(endpoint)}`);
    return {
        ...(headers != undefined && {
            headers: getEndpointHeaders(headers, endpointRuleOptions),
        }),
        ...(properties != undefined && {
            properties: getEndpointProperties(properties, endpointRuleOptions),
        }),
        url: getEndpointUrl(url, endpointRuleOptions),
    };
};

const evaluateErrorRule = (errorRule, options) => {
    const { conditions, error } = errorRule;
    const { result, referenceRecord } = evaluateConditions(conditions, options);
    if (!result) {
        return;
    }
    throw new EndpointError(evaluateExpression(error, "Error", {
        ...options,
        referenceRecord: { ...options.referenceRecord, ...referenceRecord },
    }));
};

const evaluateTreeRule = (treeRule, options) => {
    const { conditions, rules } = treeRule;
    const { result, referenceRecord } = evaluateConditions(conditions, options);
    if (!result) {
        return;
    }
    return evaluateRules(rules, {
        ...options,
        referenceRecord: { ...options.referenceRecord, ...referenceRecord },
    });
};

const evaluateRules = (rules, options) => {
    for (const rule of rules) {
        if (rule.type === "endpoint") {
            const endpointOrUndefined = evaluateEndpointRule(rule, options);
            if (endpointOrUndefined) {
                return endpointOrUndefined;
            }
        }
        else if (rule.type === "error") {
            evaluateErrorRule(rule, options);
        }
        else if (rule.type === "tree") {
            const endpointOrUndefined = evaluateTreeRule(rule, options);
            if (endpointOrUndefined) {
                return endpointOrUndefined;
            }
        }
        else {
            throw new EndpointError(`Unknown endpoint rule: ${rule}`);
        }
    }
    throw new EndpointError(`Rules evaluation failed`);
};

const resolveEndpoint = (ruleSetObject, options) => {
    const { endpointParams, logger } = options;
    const { parameters, rules } = ruleSetObject;
    options.logger?.debug?.(debugId, `Initial EndpointParams: ${toDebugString(endpointParams)}`);
    const paramsWithDefault = Object.entries(parameters)
        .filter(([, v]) => v.default != null)
        .map(([k, v]) => [k, v.default]);
    if (paramsWithDefault.length > 0) {
        for (const [paramKey, paramDefaultValue] of paramsWithDefault) {
            endpointParams[paramKey] = endpointParams[paramKey] ?? paramDefaultValue;
        }
    }
    const requiredParams = Object.entries(parameters)
        .filter(([, v]) => v.required)
        .map(([k]) => k);
    for (const requiredParam of requiredParams) {
        if (endpointParams[requiredParam] == null) {
            throw new EndpointError(`Missing required parameter: '${requiredParam}'`);
        }
    }
    const endpoint = evaluateRules(rules, { endpointParams, logger, referenceRecord: {} });
    if (options.endpointParams?.Endpoint) {
        try {
            const givenEndpoint = new URL(options.endpointParams.Endpoint);
            const { protocol, port } = givenEndpoint;
            endpoint.url.protocol = protocol;
            endpoint.url.port = port;
        }
        catch (e) {
        }
    }
    options.logger?.debug?.(debugId, `Resolved endpoint: ${toDebugString(endpoint)}`);
    return endpoint;
};

const p$1 = "required", q$1 = "fn", r$1 = "argv", s$1 = "ref";
const a$1 = "PartitionResult", b$1 = "tree", c$1 = "error", d$1 = "endpoint", e$1 = { [p$1]: false, "type": "String" }, f$1 = { [p$1]: true, "default": false, "type": "Boolean" }, g$1 = { [s$1]: "Endpoint" }, h$1 = { [q$1]: "booleanEquals", [r$1]: [{ [s$1]: "UseFIPS" }, true] }, i$1 = { [q$1]: "booleanEquals", [r$1]: [{ [s$1]: "UseDualStack" }, true] }, j$1 = {}, k$1 = { [q$1]: "booleanEquals", [r$1]: [true, { [q$1]: "getAttr", [r$1]: [{ [s$1]: a$1 }, "supportsFIPS"] }] }, l$1 = { [q$1]: "booleanEquals", [r$1]: [true, { [q$1]: "getAttr", [r$1]: [{ [s$1]: a$1 }, "supportsDualStack"] }] }, m$1 = [g$1], n$1 = [h$1], o$1 = [i$1];
const _data$1 = { version: "1.0", parameters: { Region: e$1, UseDualStack: f$1, UseFIPS: f$1, Endpoint: e$1 }, rules: [{ conditions: [{ [q$1]: "aws.partition", [r$1]: [{ [s$1]: "Region" }], assign: a$1 }], type: b$1, rules: [{ conditions: [{ [q$1]: "isSet", [r$1]: m$1 }, { [q$1]: "parseURL", [r$1]: m$1, assign: "url" }], type: b$1, rules: [{ conditions: n$1, error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: c$1 }, { type: b$1, rules: [{ conditions: o$1, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: c$1 }, { endpoint: { url: g$1, properties: j$1, headers: j$1 }, type: d$1 }] }] }, { conditions: [h$1, i$1], type: b$1, rules: [{ conditions: [k$1, l$1], type: b$1, rules: [{ endpoint: { url: "https://portal.sso-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: j$1, headers: j$1 }, type: d$1 }] }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: c$1 }] }, { conditions: n$1, type: b$1, rules: [{ conditions: [k$1], type: b$1, rules: [{ type: b$1, rules: [{ endpoint: { url: "https://portal.sso-fips.{Region}.{PartitionResult#dnsSuffix}", properties: j$1, headers: j$1 }, type: d$1 }] }] }, { error: "FIPS is enabled but this partition does not support FIPS", type: c$1 }] }, { conditions: o$1, type: b$1, rules: [{ conditions: [l$1], type: b$1, rules: [{ endpoint: { url: "https://portal.sso.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: j$1, headers: j$1 }, type: d$1 }] }, { error: "DualStack is enabled but this partition does not support DualStack", type: c$1 }] }, { endpoint: { url: "https://portal.sso.{Region}.{PartitionResult#dnsSuffix}", properties: j$1, headers: j$1 }, type: d$1 }] }] };
const ruleSet$1 = _data$1;

const defaultEndpointResolver$1 = (endpointParams, context = {}) => {
    return resolveEndpoint(ruleSet$1, {
        endpointParams: endpointParams,
        logger: context.logger,
    });
};

const getRuntimeConfig$3 = (config) => ({
    apiVersion: "2019-06-10",
    base64Decoder: config?.base64Decoder ?? fromBase64,
    base64Encoder: config?.base64Encoder ?? toBase64,
    disableHostPrefix: config?.disableHostPrefix ?? false,
    endpointProvider: config?.endpointProvider ?? defaultEndpointResolver$1,
    logger: config?.logger ?? new NoOpLogger(),
    serviceId: config?.serviceId ?? "SSO",
    urlParser: config?.urlParser ?? parseUrl$1,
});

const AWS_EXECUTION_ENV = "AWS_EXECUTION_ENV";
const AWS_REGION_ENV = "AWS_REGION";
const AWS_DEFAULT_REGION_ENV = "AWS_DEFAULT_REGION";
const ENV_IMDS_DISABLED$1 = "AWS_EC2_METADATA_DISABLED";
const DEFAULTS_MODE_OPTIONS = ["in-region", "cross-region", "mobile", "standard", "legacy"];
const IMDS_REGION_PATH = "/latest/meta-data/placement/region";

const AWS_DEFAULTS_MODE_ENV = "AWS_DEFAULTS_MODE";
const AWS_DEFAULTS_MODE_CONFIG = "defaults_mode";
const NODE_DEFAULTS_MODE_CONFIG_OPTIONS = {
    environmentVariableSelector: (env) => {
        return env[AWS_DEFAULTS_MODE_ENV];
    },
    configFileSelector: (profile) => {
        return profile[AWS_DEFAULTS_MODE_CONFIG];
    },
    default: "legacy",
};

const resolveDefaultsModeConfig = ({ region = loadConfig(NODE_REGION_CONFIG_OPTIONS), defaultsMode = loadConfig(NODE_DEFAULTS_MODE_CONFIG_OPTIONS), } = {}) => memoize(async () => {
    const mode = typeof defaultsMode === "function" ? await defaultsMode() : defaultsMode;
    switch (mode?.toLowerCase()) {
        case "auto":
            return resolveNodeDefaultsModeAuto(region);
        case "in-region":
        case "cross-region":
        case "mobile":
        case "standard":
        case "legacy":
            return Promise.resolve(mode?.toLocaleLowerCase());
        case undefined:
            return Promise.resolve("legacy");
        default:
            throw new Error(`Invalid parameter for "defaultsMode", expect ${DEFAULTS_MODE_OPTIONS.join(", ")}, got ${mode}`);
    }
});
const resolveNodeDefaultsModeAuto = async (clientRegion) => {
    if (clientRegion) {
        const resolvedRegion = typeof clientRegion === "function" ? await clientRegion() : clientRegion;
        const inferredRegion = await inferPhysicalRegion();
        if (!inferredRegion) {
            return "standard";
        }
        if (resolvedRegion === inferredRegion) {
            return "in-region";
        }
        else {
            return "cross-region";
        }
    }
    return "standard";
};
const inferPhysicalRegion = async () => {
    if (process.env[AWS_EXECUTION_ENV] && (process.env[AWS_REGION_ENV] || process.env[AWS_DEFAULT_REGION_ENV])) {
        return process.env[AWS_REGION_ENV] ?? process.env[AWS_DEFAULT_REGION_ENV];
    }
    if (!process.env[ENV_IMDS_DISABLED$1]) {
        try {
            const endpoint = await getInstanceMetadataEndpoint();
            return (await httpRequest({ ...endpoint, path: IMDS_REGION_PATH })).toString();
        }
        catch (e) {
        }
    }
};

const getRuntimeConfig$2 = (config) => {
    emitWarningIfUnsupportedVersion(process.version);
    const defaultsMode = resolveDefaultsModeConfig(config);
    const defaultConfigProvider = () => defaultsMode().then(loadConfigsForDefaultMode);
    const clientSharedValues = getRuntimeConfig$3(config);
    return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        bodyLengthChecker: config?.bodyLengthChecker ?? calculateBodyLength,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ??
            defaultUserAgent({ serviceId: clientSharedValues.serviceId, clientVersion: packageInfo$1.version }),
        maxAttempts: config?.maxAttempts ?? loadConfig(NODE_MAX_ATTEMPT_CONFIG_OPTIONS),
        region: config?.region ?? loadConfig(NODE_REGION_CONFIG_OPTIONS, NODE_REGION_CONFIG_FILE_OPTIONS),
        requestHandler: config?.requestHandler ?? new require$$13.NodeHttpHandler(defaultConfigProvider),
        retryMode: config?.retryMode ??
            loadConfig({
                ...NODE_RETRY_MODE_CONFIG_OPTIONS,
                default: async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE,
            }),
        sha256: config?.sha256 ?? Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? require$$13.streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? loadConfig(NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS),
        useFipsEndpoint: config?.useFipsEndpoint ?? loadConfig(NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS),
        utf8Decoder: config?.utf8Decoder ?? fromUtf8$4,
        utf8Encoder: config?.utf8Encoder ?? toUtf8$3,
    };
};

class SSOClient extends Client {
    constructor(configuration) {
        const _config_0 = getRuntimeConfig$2(configuration);
        const _config_1 = resolveClientEndpointParameters$1(_config_0);
        const _config_2 = resolveRegionConfig(_config_1);
        const _config_3 = resolveEndpointConfig(_config_2);
        const _config_4 = resolveRetryConfig(_config_3);
        const _config_5 = resolveHostHeaderConfig(_config_4);
        const _config_6 = resolveUserAgentConfig(_config_5);
        super(_config_6);
        this.config = _config_6;
        this.middlewareStack.use(getRetryPlugin(this.config));
        this.middlewareStack.use(getContentLengthPlugin(this.config));
        this.middlewareStack.use(getHostHeaderPlugin(this.config));
        this.middlewareStack.use(getLoggerPlugin(this.config));
        this.middlewareStack.use(getRecursionDetectionPlugin(this.config));
        this.middlewareStack.use(getUserAgentPlugin(this.config));
    }
    destroy() {
        super.destroy();
    }
}

const EXPIRE_WINDOW_MS$1 = 5 * 60 * 1000;
const REFRESH_MESSAGE = `To refresh this SSO session run 'aws sso login' with the corresponding profile.`;

class SSOOIDCServiceException extends ServiceException {
    constructor(options) {
        super(options);
        Object.setPrototypeOf(this, SSOOIDCServiceException.prototype);
    }
}

class AccessDeniedException extends SSOOIDCServiceException {
    constructor(opts) {
        super({
            name: "AccessDeniedException",
            $fault: "client",
            ...opts,
        });
        this.name = "AccessDeniedException";
        this.$fault = "client";
        Object.setPrototypeOf(this, AccessDeniedException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
    }
}
class AuthorizationPendingException extends SSOOIDCServiceException {
    constructor(opts) {
        super({
            name: "AuthorizationPendingException",
            $fault: "client",
            ...opts,
        });
        this.name = "AuthorizationPendingException";
        this.$fault = "client";
        Object.setPrototypeOf(this, AuthorizationPendingException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
    }
}
class ExpiredTokenException extends SSOOIDCServiceException {
    constructor(opts) {
        super({
            name: "ExpiredTokenException",
            $fault: "client",
            ...opts,
        });
        this.name = "ExpiredTokenException";
        this.$fault = "client";
        Object.setPrototypeOf(this, ExpiredTokenException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
    }
}
class InternalServerException extends SSOOIDCServiceException {
    constructor(opts) {
        super({
            name: "InternalServerException",
            $fault: "server",
            ...opts,
        });
        this.name = "InternalServerException";
        this.$fault = "server";
        Object.setPrototypeOf(this, InternalServerException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
    }
}
class InvalidClientException extends SSOOIDCServiceException {
    constructor(opts) {
        super({
            name: "InvalidClientException",
            $fault: "client",
            ...opts,
        });
        this.name = "InvalidClientException";
        this.$fault = "client";
        Object.setPrototypeOf(this, InvalidClientException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
    }
}
class InvalidGrantException extends SSOOIDCServiceException {
    constructor(opts) {
        super({
            name: "InvalidGrantException",
            $fault: "client",
            ...opts,
        });
        this.name = "InvalidGrantException";
        this.$fault = "client";
        Object.setPrototypeOf(this, InvalidGrantException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
    }
}
class InvalidRequestException extends SSOOIDCServiceException {
    constructor(opts) {
        super({
            name: "InvalidRequestException",
            $fault: "client",
            ...opts,
        });
        this.name = "InvalidRequestException";
        this.$fault = "client";
        Object.setPrototypeOf(this, InvalidRequestException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
    }
}
class InvalidScopeException extends SSOOIDCServiceException {
    constructor(opts) {
        super({
            name: "InvalidScopeException",
            $fault: "client",
            ...opts,
        });
        this.name = "InvalidScopeException";
        this.$fault = "client";
        Object.setPrototypeOf(this, InvalidScopeException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
    }
}
class SlowDownException extends SSOOIDCServiceException {
    constructor(opts) {
        super({
            name: "SlowDownException",
            $fault: "client",
            ...opts,
        });
        this.name = "SlowDownException";
        this.$fault = "client";
        Object.setPrototypeOf(this, SlowDownException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
    }
}
class UnauthorizedClientException extends SSOOIDCServiceException {
    constructor(opts) {
        super({
            name: "UnauthorizedClientException",
            $fault: "client",
            ...opts,
        });
        this.name = "UnauthorizedClientException";
        this.$fault = "client";
        Object.setPrototypeOf(this, UnauthorizedClientException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
    }
}
class UnsupportedGrantTypeException extends SSOOIDCServiceException {
    constructor(opts) {
        super({
            name: "UnsupportedGrantTypeException",
            $fault: "client",
            ...opts,
        });
        this.name = "UnsupportedGrantTypeException";
        this.$fault = "client";
        Object.setPrototypeOf(this, UnsupportedGrantTypeException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
    }
}
const CreateTokenRequestFilterSensitiveLog = (obj) => ({
    ...obj,
});
const CreateTokenResponseFilterSensitiveLog = (obj) => ({
    ...obj,
});

const serializeAws_restJson1CreateTokenCommand = async (input, context) => {
    const { hostname, protocol = "https", port, path: basePath } = await context.endpoint();
    const headers = {
        "content-type": "application/json",
    };
    const resolvedPath = `${basePath?.endsWith("/") ? basePath.slice(0, -1) : basePath || ""}` + "/token";
    let body;
    body = JSON.stringify({
        ...(input.clientId != null && { clientId: input.clientId }),
        ...(input.clientSecret != null && { clientSecret: input.clientSecret }),
        ...(input.code != null && { code: input.code }),
        ...(input.deviceCode != null && { deviceCode: input.deviceCode }),
        ...(input.grantType != null && { grantType: input.grantType }),
        ...(input.redirectUri != null && { redirectUri: input.redirectUri }),
        ...(input.refreshToken != null && { refreshToken: input.refreshToken }),
        ...(input.scope != null && { scope: serializeAws_restJson1Scopes(input.scope) }),
    });
    return new HttpRequest$1({
        protocol,
        hostname,
        port,
        method: "POST",
        headers,
        path: resolvedPath,
        body,
    });
};
const deserializeAws_restJson1CreateTokenCommand = async (output, context) => {
    if (output.statusCode !== 200 && output.statusCode >= 300) {
        return deserializeAws_restJson1CreateTokenCommandError(output, context);
    }
    const contents = map({
        $metadata: deserializeMetadata(output),
    });
    const data = expectNonNull(expectObject(await parseBody(output.body, context)), "body");
    if (data.accessToken != null) {
        contents.accessToken = expectString(data.accessToken);
    }
    if (data.expiresIn != null) {
        contents.expiresIn = expectInt32(data.expiresIn);
    }
    if (data.idToken != null) {
        contents.idToken = expectString(data.idToken);
    }
    if (data.refreshToken != null) {
        contents.refreshToken = expectString(data.refreshToken);
    }
    if (data.tokenType != null) {
        contents.tokenType = expectString(data.tokenType);
    }
    return contents;
};
const deserializeAws_restJson1CreateTokenCommandError = async (output, context) => {
    const parsedOutput = {
        ...output,
        body: await parseErrorBody(output.body, context),
    };
    const errorCode = loadRestJsonErrorCode(output, parsedOutput.body);
    switch (errorCode) {
        case "AccessDeniedException":
        case "com.amazonaws.ssooidc#AccessDeniedException":
            throw await deserializeAws_restJson1AccessDeniedExceptionResponse(parsedOutput);
        case "AuthorizationPendingException":
        case "com.amazonaws.ssooidc#AuthorizationPendingException":
            throw await deserializeAws_restJson1AuthorizationPendingExceptionResponse(parsedOutput);
        case "ExpiredTokenException":
        case "com.amazonaws.ssooidc#ExpiredTokenException":
            throw await deserializeAws_restJson1ExpiredTokenExceptionResponse(parsedOutput);
        case "InternalServerException":
        case "com.amazonaws.ssooidc#InternalServerException":
            throw await deserializeAws_restJson1InternalServerExceptionResponse(parsedOutput);
        case "InvalidClientException":
        case "com.amazonaws.ssooidc#InvalidClientException":
            throw await deserializeAws_restJson1InvalidClientExceptionResponse(parsedOutput);
        case "InvalidGrantException":
        case "com.amazonaws.ssooidc#InvalidGrantException":
            throw await deserializeAws_restJson1InvalidGrantExceptionResponse(parsedOutput);
        case "InvalidRequestException":
        case "com.amazonaws.ssooidc#InvalidRequestException":
            throw await deserializeAws_restJson1InvalidRequestExceptionResponse(parsedOutput);
        case "InvalidScopeException":
        case "com.amazonaws.ssooidc#InvalidScopeException":
            throw await deserializeAws_restJson1InvalidScopeExceptionResponse(parsedOutput);
        case "SlowDownException":
        case "com.amazonaws.ssooidc#SlowDownException":
            throw await deserializeAws_restJson1SlowDownExceptionResponse(parsedOutput);
        case "UnauthorizedClientException":
        case "com.amazonaws.ssooidc#UnauthorizedClientException":
            throw await deserializeAws_restJson1UnauthorizedClientExceptionResponse(parsedOutput);
        case "UnsupportedGrantTypeException":
        case "com.amazonaws.ssooidc#UnsupportedGrantTypeException":
            throw await deserializeAws_restJson1UnsupportedGrantTypeExceptionResponse(parsedOutput);
        default:
            const parsedBody = parsedOutput.body;
            throwDefaultError({
                output,
                parsedBody,
                exceptionCtor: SSOOIDCServiceException,
                errorCode,
            });
    }
};
const map = map$2;
const deserializeAws_restJson1AccessDeniedExceptionResponse = async (parsedOutput, context) => {
    const contents = map({});
    const data = parsedOutput.body;
    if (data.error != null) {
        contents.error = expectString(data.error);
    }
    if (data.error_description != null) {
        contents.error_description = expectString(data.error_description);
    }
    const exception = new AccessDeniedException({
        $metadata: deserializeMetadata(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1AuthorizationPendingExceptionResponse = async (parsedOutput, context) => {
    const contents = map({});
    const data = parsedOutput.body;
    if (data.error != null) {
        contents.error = expectString(data.error);
    }
    if (data.error_description != null) {
        contents.error_description = expectString(data.error_description);
    }
    const exception = new AuthorizationPendingException({
        $metadata: deserializeMetadata(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1ExpiredTokenExceptionResponse = async (parsedOutput, context) => {
    const contents = map({});
    const data = parsedOutput.body;
    if (data.error != null) {
        contents.error = expectString(data.error);
    }
    if (data.error_description != null) {
        contents.error_description = expectString(data.error_description);
    }
    const exception = new ExpiredTokenException({
        $metadata: deserializeMetadata(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1InternalServerExceptionResponse = async (parsedOutput, context) => {
    const contents = map({});
    const data = parsedOutput.body;
    if (data.error != null) {
        contents.error = expectString(data.error);
    }
    if (data.error_description != null) {
        contents.error_description = expectString(data.error_description);
    }
    const exception = new InternalServerException({
        $metadata: deserializeMetadata(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1InvalidClientExceptionResponse = async (parsedOutput, context) => {
    const contents = map({});
    const data = parsedOutput.body;
    if (data.error != null) {
        contents.error = expectString(data.error);
    }
    if (data.error_description != null) {
        contents.error_description = expectString(data.error_description);
    }
    const exception = new InvalidClientException({
        $metadata: deserializeMetadata(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1InvalidGrantExceptionResponse = async (parsedOutput, context) => {
    const contents = map({});
    const data = parsedOutput.body;
    if (data.error != null) {
        contents.error = expectString(data.error);
    }
    if (data.error_description != null) {
        contents.error_description = expectString(data.error_description);
    }
    const exception = new InvalidGrantException({
        $metadata: deserializeMetadata(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1InvalidRequestExceptionResponse = async (parsedOutput, context) => {
    const contents = map({});
    const data = parsedOutput.body;
    if (data.error != null) {
        contents.error = expectString(data.error);
    }
    if (data.error_description != null) {
        contents.error_description = expectString(data.error_description);
    }
    const exception = new InvalidRequestException({
        $metadata: deserializeMetadata(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1InvalidScopeExceptionResponse = async (parsedOutput, context) => {
    const contents = map({});
    const data = parsedOutput.body;
    if (data.error != null) {
        contents.error = expectString(data.error);
    }
    if (data.error_description != null) {
        contents.error_description = expectString(data.error_description);
    }
    const exception = new InvalidScopeException({
        $metadata: deserializeMetadata(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1SlowDownExceptionResponse = async (parsedOutput, context) => {
    const contents = map({});
    const data = parsedOutput.body;
    if (data.error != null) {
        contents.error = expectString(data.error);
    }
    if (data.error_description != null) {
        contents.error_description = expectString(data.error_description);
    }
    const exception = new SlowDownException({
        $metadata: deserializeMetadata(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1UnauthorizedClientExceptionResponse = async (parsedOutput, context) => {
    const contents = map({});
    const data = parsedOutput.body;
    if (data.error != null) {
        contents.error = expectString(data.error);
    }
    if (data.error_description != null) {
        contents.error_description = expectString(data.error_description);
    }
    const exception = new UnauthorizedClientException({
        $metadata: deserializeMetadata(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const deserializeAws_restJson1UnsupportedGrantTypeExceptionResponse = async (parsedOutput, context) => {
    const contents = map({});
    const data = parsedOutput.body;
    if (data.error != null) {
        contents.error = expectString(data.error);
    }
    if (data.error_description != null) {
        contents.error_description = expectString(data.error_description);
    }
    const exception = new UnsupportedGrantTypeException({
        $metadata: deserializeMetadata(parsedOutput),
        ...contents,
    });
    return decorateServiceException(exception, parsedOutput.body);
};
const serializeAws_restJson1Scopes = (input, context) => {
    return input
        .filter((e) => e != null)
        .map((entry) => {
        return entry;
    });
};
const deserializeMetadata = (output) => ({
    httpStatusCode: output.statusCode,
    requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
    extendedRequestId: output.headers["x-amz-id-2"],
    cfId: output.headers["x-amz-cf-id"],
});
const collectBody = (streamBody = new Uint8Array(), context) => {
    if (streamBody instanceof Uint8Array) {
        return Promise.resolve(streamBody);
    }
    return context.streamCollector(streamBody) || Promise.resolve(new Uint8Array());
};
const collectBodyString = (streamBody, context) => collectBody(streamBody, context).then((body) => context.utf8Encoder(body));
const parseBody = (streamBody, context) => collectBodyString(streamBody, context).then((encoded) => {
    if (encoded.length) {
        return JSON.parse(encoded);
    }
    return {};
});
const parseErrorBody = async (errorBody, context) => {
    const value = await parseBody(errorBody, context);
    value.message = value.message ?? value.Message;
    return value;
};
const loadRestJsonErrorCode = (output, data) => {
    const findKey = (object, key) => Object.keys(object).find((k) => k.toLowerCase() === key.toLowerCase());
    const sanitizeErrorCode = (rawValue) => {
        let cleanValue = rawValue;
        if (typeof cleanValue === "number") {
            cleanValue = cleanValue.toString();
        }
        if (cleanValue.indexOf(",") >= 0) {
            cleanValue = cleanValue.split(",")[0];
        }
        if (cleanValue.indexOf(":") >= 0) {
            cleanValue = cleanValue.split(":")[0];
        }
        if (cleanValue.indexOf("#") >= 0) {
            cleanValue = cleanValue.split("#")[1];
        }
        return cleanValue;
    };
    const headerKey = findKey(output.headers, "x-amzn-errortype");
    if (headerKey !== undefined) {
        return sanitizeErrorCode(output.headers[headerKey]);
    }
    if (data.code !== undefined) {
        return sanitizeErrorCode(data.code);
    }
    if (data["__type"] !== undefined) {
        return sanitizeErrorCode(data["__type"]);
    }
};

class CreateTokenCommand extends Command {
    constructor(input) {
        super();
        this.input = input;
    }
    static getEndpointParameterInstructions() {
        return {
            UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
            Endpoint: { type: "builtInParams", name: "endpoint" },
            Region: { type: "builtInParams", name: "region" },
            UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" },
        };
    }
    resolveMiddleware(clientStack, configuration, options) {
        this.middlewareStack.use(getSerdePlugin(configuration, this.serialize, this.deserialize));
        this.middlewareStack.use(getEndpointPlugin(configuration, CreateTokenCommand.getEndpointParameterInstructions()));
        const stack = clientStack.concat(this.middlewareStack);
        const { logger } = configuration;
        const clientName = "SSOOIDCClient";
        const commandName = "CreateTokenCommand";
        const handlerExecutionContext = {
            logger,
            clientName,
            commandName,
            inputFilterSensitiveLog: CreateTokenRequestFilterSensitiveLog,
            outputFilterSensitiveLog: CreateTokenResponseFilterSensitiveLog,
        };
        const { requestHandler } = configuration;
        return stack.resolve((request) => requestHandler.handle(request.request, options || {}), handlerExecutionContext);
    }
    serialize(input, context) {
        return serializeAws_restJson1CreateTokenCommand(input, context);
    }
    deserialize(output, context) {
        return deserializeAws_restJson1CreateTokenCommand(output, context);
    }
}

const resolveClientEndpointParameters = (options) => {
    return {
        ...options,
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        defaultSigningName: "awsssooidc",
    };
};

var name = "@aws-sdk/client-sso-oidc";
var description = "AWS SDK for JavaScript Sso Oidc Client for Node.js, Browser and React Native";
var version = "3.245.0";
var scripts = {
	build: "concurrently 'yarn:build:cjs' 'yarn:build:es' 'yarn:build:types'",
	"build:cjs": "tsc -p tsconfig.cjs.json",
	"build:docs": "typedoc",
	"build:es": "tsc -p tsconfig.es.json",
	"build:include:deps": "lerna run --scope $npm_package_name --include-dependencies build",
	"build:types": "tsc -p tsconfig.types.json",
	"build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
	clean: "rimraf ./dist-* && rimraf *.tsbuildinfo",
	"generate:client": "(cd ../../ && yarn generate-clients -g ./codegen/sdk-codegen/aws-models/sso-oidc.json --keepFiles)"
};
var main = "./dist-cjs/index.js";
var types = "./dist-types/index.d.ts";
var module$1 = "./dist-es/index.js";
var sideEffects = false;
var dependencies = {
	"@aws-crypto/sha256-browser": "2.0.0",
	"@aws-crypto/sha256-js": "2.0.0",
	"@aws-sdk/config-resolver": "3.234.0",
	"@aws-sdk/fetch-http-handler": "3.226.0",
	"@aws-sdk/hash-node": "3.226.0",
	"@aws-sdk/invalid-dependency": "3.226.0",
	"@aws-sdk/middleware-content-length": "3.226.0",
	"@aws-sdk/middleware-endpoint": "3.226.0",
	"@aws-sdk/middleware-host-header": "3.226.0",
	"@aws-sdk/middleware-logger": "3.226.0",
	"@aws-sdk/middleware-recursion-detection": "3.226.0",
	"@aws-sdk/middleware-retry": "3.235.0",
	"@aws-sdk/middleware-serde": "3.226.0",
	"@aws-sdk/middleware-stack": "3.226.0",
	"@aws-sdk/middleware-user-agent": "3.226.0",
	"@aws-sdk/node-config-provider": "3.226.0",
	"@aws-sdk/node-http-handler": "3.226.0",
	"@aws-sdk/protocol-http": "3.226.0",
	"@aws-sdk/smithy-client": "3.234.0",
	"@aws-sdk/types": "3.226.0",
	"@aws-sdk/url-parser": "3.226.0",
	"@aws-sdk/util-base64": "3.208.0",
	"@aws-sdk/util-body-length-browser": "3.188.0",
	"@aws-sdk/util-body-length-node": "3.208.0",
	"@aws-sdk/util-defaults-mode-browser": "3.234.0",
	"@aws-sdk/util-defaults-mode-node": "3.234.0",
	"@aws-sdk/util-endpoints": "3.245.0",
	"@aws-sdk/util-retry": "3.229.0",
	"@aws-sdk/util-user-agent-browser": "3.226.0",
	"@aws-sdk/util-user-agent-node": "3.226.0",
	"@aws-sdk/util-utf8-browser": "3.188.0",
	"@aws-sdk/util-utf8-node": "3.208.0",
	tslib: "^2.3.1"
};
var devDependencies = {
	"@aws-sdk/service-client-documentation-generator": "3.208.0",
	"@tsconfig/node14": "1.0.3",
	"@types/node": "^14.14.31",
	concurrently: "7.0.0",
	"downlevel-dts": "0.10.1",
	rimraf: "3.0.2",
	typedoc: "0.19.2",
	typescript: "~4.6.2"
};
var overrides = {
	typedoc: {
		typescript: "~4.6.2"
	}
};
var engines = {
	node: ">=14.0.0"
};
var typesVersions = {
	"<4.0": {
		"dist-types/*": [
			"dist-types/ts3.4/*"
		]
	}
};
var files = [
	"dist-*"
];
var author = {
	name: "AWS SDK for JavaScript Team",
	url: "https://aws.amazon.com/javascript/"
};
var license = "Apache-2.0";
var browser = {
	"./dist-es/runtimeConfig": "./dist-es/runtimeConfig.browser"
};
var homepage = "https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-sso-oidc";
var repository = {
	type: "git",
	url: "https://github.com/aws/aws-sdk-js-v3.git",
	directory: "clients/client-sso-oidc"
};
var packageInfo = {
	name: name,
	description: description,
	version: version,
	scripts: scripts,
	main: main,
	types: types,
	module: module$1,
	sideEffects: sideEffects,
	dependencies: dependencies,
	devDependencies: devDependencies,
	overrides: overrides,
	engines: engines,
	typesVersions: typesVersions,
	files: files,
	author: author,
	license: license,
	browser: browser,
	"react-native": {
	"./dist-es/runtimeConfig": "./dist-es/runtimeConfig.native"
},
	homepage: homepage,
	repository: repository
};

const p = "required", q = "fn", r = "argv", s = "ref";
const a = "PartitionResult", b = "tree", c = "error", d = "endpoint", e = { [p]: false, "type": "String" }, f = { [p]: true, "default": false, "type": "Boolean" }, g = { [s]: "Endpoint" }, h = { [q]: "booleanEquals", [r]: [{ [s]: "UseFIPS" }, true] }, i = { [q]: "booleanEquals", [r]: [{ [s]: "UseDualStack" }, true] }, j = {}, k = { [q]: "booleanEquals", [r]: [true, { [q]: "getAttr", [r]: [{ [s]: a }, "supportsFIPS"] }] }, l = { [q]: "booleanEquals", [r]: [true, { [q]: "getAttr", [r]: [{ [s]: a }, "supportsDualStack"] }] }, m = [g], n = [h], o = [i];
const _data = { version: "1.0", parameters: { Region: e, UseDualStack: f, UseFIPS: f, Endpoint: e }, rules: [{ conditions: [{ [q]: "aws.partition", [r]: [{ [s]: "Region" }], assign: a }], type: b, rules: [{ conditions: [{ [q]: "isSet", [r]: m }, { [q]: "parseURL", [r]: m, assign: "url" }], type: b, rules: [{ conditions: n, error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: c }, { type: b, rules: [{ conditions: o, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: c }, { endpoint: { url: g, properties: j, headers: j }, type: d }] }] }, { conditions: [h, i], type: b, rules: [{ conditions: [k, l], type: b, rules: [{ endpoint: { url: "https://oidc-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: j, headers: j }, type: d }] }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: c }] }, { conditions: n, type: b, rules: [{ conditions: [k], type: b, rules: [{ type: b, rules: [{ endpoint: { url: "https://oidc-fips.{Region}.{PartitionResult#dnsSuffix}", properties: j, headers: j }, type: d }] }] }, { error: "FIPS is enabled but this partition does not support FIPS", type: c }] }, { conditions: o, type: b, rules: [{ conditions: [l], type: b, rules: [{ endpoint: { url: "https://oidc.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: j, headers: j }, type: d }] }, { error: "DualStack is enabled but this partition does not support DualStack", type: c }] }, { endpoint: { url: "https://oidc.{Region}.{PartitionResult#dnsSuffix}", properties: j, headers: j }, type: d }] }] };
const ruleSet = _data;

const defaultEndpointResolver = (endpointParams, context = {}) => {
    return resolveEndpoint(ruleSet, {
        endpointParams: endpointParams,
        logger: context.logger,
    });
};

const getRuntimeConfig$1 = (config) => ({
    apiVersion: "2019-06-10",
    base64Decoder: config?.base64Decoder ?? fromBase64,
    base64Encoder: config?.base64Encoder ?? toBase64,
    disableHostPrefix: config?.disableHostPrefix ?? false,
    endpointProvider: config?.endpointProvider ?? defaultEndpointResolver,
    logger: config?.logger ?? new NoOpLogger(),
    serviceId: config?.serviceId ?? "SSO OIDC",
    urlParser: config?.urlParser ?? parseUrl$1,
});

const getRuntimeConfig = (config) => {
    emitWarningIfUnsupportedVersion(process.version);
    const defaultsMode = resolveDefaultsModeConfig(config);
    const defaultConfigProvider = () => defaultsMode().then(loadConfigsForDefaultMode);
    const clientSharedValues = getRuntimeConfig$1(config);
    return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        bodyLengthChecker: config?.bodyLengthChecker ?? calculateBodyLength,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ??
            defaultUserAgent({ serviceId: clientSharedValues.serviceId, clientVersion: packageInfo.version }),
        maxAttempts: config?.maxAttempts ?? loadConfig(NODE_MAX_ATTEMPT_CONFIG_OPTIONS),
        region: config?.region ?? loadConfig(NODE_REGION_CONFIG_OPTIONS, NODE_REGION_CONFIG_FILE_OPTIONS),
        requestHandler: config?.requestHandler ?? new require$$13.NodeHttpHandler(defaultConfigProvider),
        retryMode: config?.retryMode ??
            loadConfig({
                ...NODE_RETRY_MODE_CONFIG_OPTIONS,
                default: async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE,
            }),
        sha256: config?.sha256 ?? Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? require$$13.streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? loadConfig(NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS),
        useFipsEndpoint: config?.useFipsEndpoint ?? loadConfig(NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS),
        utf8Decoder: config?.utf8Decoder ?? fromUtf8$4,
        utf8Encoder: config?.utf8Encoder ?? toUtf8$3,
    };
};

class SSOOIDCClient extends Client {
    constructor(configuration) {
        const _config_0 = getRuntimeConfig(configuration);
        const _config_1 = resolveClientEndpointParameters(_config_0);
        const _config_2 = resolveRegionConfig(_config_1);
        const _config_3 = resolveEndpointConfig(_config_2);
        const _config_4 = resolveRetryConfig(_config_3);
        const _config_5 = resolveHostHeaderConfig(_config_4);
        const _config_6 = resolveUserAgentConfig(_config_5);
        super(_config_6);
        this.config = _config_6;
        this.middlewareStack.use(getRetryPlugin(this.config));
        this.middlewareStack.use(getContentLengthPlugin(this.config));
        this.middlewareStack.use(getHostHeaderPlugin(this.config));
        this.middlewareStack.use(getLoggerPlugin(this.config));
        this.middlewareStack.use(getRecursionDetectionPlugin(this.config));
        this.middlewareStack.use(getUserAgentPlugin(this.config));
    }
    destroy() {
        super.destroy();
    }
}

const ssoOidcClientsHash = {};
const getSsoOidcClient = (ssoRegion) => {
    if (ssoOidcClientsHash[ssoRegion]) {
        return ssoOidcClientsHash[ssoRegion];
    }
    const ssoOidcClient = new SSOOIDCClient({ region: ssoRegion });
    ssoOidcClientsHash[ssoRegion] = ssoOidcClient;
    return ssoOidcClient;
};

const getNewSsoOidcToken = (ssoToken, ssoRegion) => {
    const ssoOidcClient = getSsoOidcClient(ssoRegion);
    return ssoOidcClient.send(new CreateTokenCommand({
        clientId: ssoToken.clientId,
        clientSecret: ssoToken.clientSecret,
        refreshToken: ssoToken.refreshToken,
        grantType: "refresh_token",
    }));
};

const validateTokenExpiry = (token) => {
    if (token.expiration && token.expiration.getTime() < Date.now()) {
        throw new TokenProviderError(`Token is expired. ${REFRESH_MESSAGE}`, false);
    }
};

const validateTokenKey = (key, value, forRefresh = false) => {
    if (typeof value === "undefined") {
        throw new TokenProviderError(`Value not present for '${key}' in SSO Token${forRefresh ? ". Cannot refresh" : ""}. ${REFRESH_MESSAGE}`, false);
    }
};

const { writeFile } = node_fs.promises;
const writeSSOTokenToFile = (id, ssoToken) => {
    const tokenFilepath = getSSOTokenFilepath(id);
    const tokenString = JSON.stringify(ssoToken, null, 2);
    return writeFile(tokenFilepath, tokenString);
};

const lastRefreshAttemptTime = new Date(0);
const fromSso = (init = {}) => async () => {
    const profiles = await parseKnownFiles(init);
    const profileName = getProfileName(init);
    const profile = profiles[profileName];
    if (!profile) {
        throw new TokenProviderError(`Profile '${profileName}' could not be found in shared credentials file.`, false);
    }
    else if (!profile["sso_session"]) {
        throw new TokenProviderError(`Profile '${profileName}' is missing required property 'sso_session'.`);
    }
    const ssoSessionName = profile["sso_session"];
    const ssoSessions = await loadSsoSessionData(init);
    const ssoSession = ssoSessions[ssoSessionName];
    if (!ssoSession) {
        throw new TokenProviderError(`Sso session '${ssoSessionName}' could not be found in shared credentials file.`, false);
    }
    for (const ssoSessionRequiredKey of ["sso_start_url", "sso_region"]) {
        if (!ssoSession[ssoSessionRequiredKey]) {
            throw new TokenProviderError(`Sso session '${ssoSessionName}' is missing required property '${ssoSessionRequiredKey}'.`, false);
        }
    }
    ssoSession["sso_start_url"];
    const ssoRegion = ssoSession["sso_region"];
    let ssoToken;
    try {
        ssoToken = await getSSOTokenFromFile(ssoSessionName);
    }
    catch (e) {
        throw new TokenProviderError(`The SSO session token associated with profile=${profileName} was not found or is invalid. ${REFRESH_MESSAGE}`, false);
    }
    validateTokenKey("accessToken", ssoToken.accessToken);
    validateTokenKey("expiresAt", ssoToken.expiresAt);
    const { accessToken, expiresAt } = ssoToken;
    const existingToken = { token: accessToken, expiration: new Date(expiresAt) };
    if (existingToken.expiration.getTime() - Date.now() > EXPIRE_WINDOW_MS$1) {
        return existingToken;
    }
    if (Date.now() - lastRefreshAttemptTime.getTime() < 30 * 1000) {
        validateTokenExpiry(existingToken);
        return existingToken;
    }
    validateTokenKey("clientId", ssoToken.clientId, true);
    validateTokenKey("clientSecret", ssoToken.clientSecret, true);
    validateTokenKey("refreshToken", ssoToken.refreshToken, true);
    try {
        lastRefreshAttemptTime.setTime(Date.now());
        const newSsoOidcToken = await getNewSsoOidcToken(ssoToken, ssoRegion);
        validateTokenKey("accessToken", newSsoOidcToken.accessToken);
        validateTokenKey("expiresIn", newSsoOidcToken.expiresIn);
        const newTokenExpiration = new Date(Date.now() + newSsoOidcToken.expiresIn * 1000);
        try {
            await writeSSOTokenToFile(ssoSessionName, {
                ...ssoToken,
                accessToken: newSsoOidcToken.accessToken,
                expiresAt: newTokenExpiration.toISOString(),
                refreshToken: newSsoOidcToken.refreshToken,
            });
        }
        catch (error) {
        }
        return {
            token: newSsoOidcToken.accessToken,
            expiration: newTokenExpiration,
        };
    }
    catch (error) {
        validateTokenExpiry(existingToken);
        return existingToken;
    }
};

const EXPIRE_WINDOW_MS = 15 * 60 * 1000;
const SHOULD_FAIL_CREDENTIAL_CHAIN = false;
const resolveSSOCredentials = async ({ ssoStartUrl, ssoSession, ssoAccountId, ssoRegion, ssoRoleName, ssoClient, profile, }) => {
    let token;
    const refreshMessage = `To refresh this SSO session run aws sso login with the corresponding profile.`;
    if (ssoSession) {
        try {
            const _token = await fromSso({ profile })();
            token = {
                accessToken: _token.token,
                expiresAt: new Date(_token.expiration).toISOString(),
            };
        }
        catch (e) {
            throw new CredentialsProviderError(e.message, SHOULD_FAIL_CREDENTIAL_CHAIN);
        }
    }
    else {
        try {
            token = await getSSOTokenFromFile(ssoStartUrl);
        }
        catch (e) {
            throw new CredentialsProviderError(`The SSO session associated with this profile is invalid. ${refreshMessage}`, SHOULD_FAIL_CREDENTIAL_CHAIN);
        }
    }
    if (new Date(token.expiresAt).getTime() - Date.now() <= EXPIRE_WINDOW_MS) {
        throw new CredentialsProviderError(`The SSO session associated with this profile has expired. ${refreshMessage}`, SHOULD_FAIL_CREDENTIAL_CHAIN);
    }
    const { accessToken } = token;
    const sso = ssoClient || new SSOClient({ region: ssoRegion });
    let ssoResp;
    try {
        ssoResp = await sso.send(new GetRoleCredentialsCommand({
            accountId: ssoAccountId,
            roleName: ssoRoleName,
            accessToken,
        }));
    }
    catch (e) {
        throw CredentialsProviderError.from(e, SHOULD_FAIL_CREDENTIAL_CHAIN);
    }
    const { roleCredentials: { accessKeyId, secretAccessKey, sessionToken, expiration } = {} } = ssoResp;
    if (!accessKeyId || !secretAccessKey || !sessionToken || !expiration) {
        throw new CredentialsProviderError("SSO returns an invalid temporary credential.", SHOULD_FAIL_CREDENTIAL_CHAIN);
    }
    return { accessKeyId, secretAccessKey, sessionToken, expiration: new Date(expiration) };
};

const validateSsoProfile = (profile) => {
    const { sso_start_url, sso_account_id, sso_region, sso_role_name } = profile;
    if (!sso_start_url || !sso_account_id || !sso_region || !sso_role_name) {
        throw new CredentialsProviderError(`Profile is configured with invalid SSO credentials. Required parameters "sso_account_id", ` +
            `"sso_region", "sso_role_name", "sso_start_url". Got ${Object.keys(profile).join(", ")}\nReference: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html`, false);
    }
    return profile;
};

const fromSSO = (init = {}) => async () => {
    const { ssoStartUrl, ssoAccountId, ssoRegion, ssoRoleName, ssoClient, ssoSession } = init;
    const profileName = getProfileName(init);
    if (!ssoStartUrl && !ssoAccountId && !ssoRegion && !ssoRoleName && !ssoSession) {
        const profiles = await parseKnownFiles(init);
        const profile = profiles[profileName];
        if (!profile) {
            throw new CredentialsProviderError(`Profile ${profileName} was not found.`);
        }
        if (!isSsoProfile(profile)) {
            throw new CredentialsProviderError(`Profile ${profileName} is not configured with SSO credentials.`);
        }
        if (profile?.sso_session) {
            const ssoSessions = await loadSsoSessionData(init);
            const session = ssoSessions[profile.sso_session];
            const conflictMsg = ` configurations in profile ${profileName} and sso-session ${profile.sso_session}`;
            if (ssoRegion && ssoRegion !== session.sso_region) {
                throw new CredentialsProviderError(`Conflicting SSO region` + conflictMsg, false);
            }
            if (ssoStartUrl && ssoStartUrl !== session.sso_start_url) {
                throw new CredentialsProviderError(`Conflicting SSO start_url` + conflictMsg, false);
            }
            profile.sso_region = session.sso_region;
            profile.sso_start_url = session.sso_start_url;
        }
        const { sso_start_url, sso_account_id, sso_region, sso_role_name, sso_session } = validateSsoProfile(profile);
        return resolveSSOCredentials({
            ssoStartUrl: sso_start_url,
            ssoSession: sso_session,
            ssoAccountId: sso_account_id,
            ssoRegion: sso_region,
            ssoRoleName: sso_role_name,
            ssoClient: ssoClient,
            profile: profileName,
        });
    }
    else if (!ssoStartUrl || !ssoAccountId || !ssoRegion || !ssoRoleName) {
        throw new CredentialsProviderError("Incomplete configuration. The fromSSO() argument hash must include " +
            '"ssoStartUrl", "ssoAccountId", "ssoRegion", "ssoRoleName"');
    }
    else {
        return resolveSSOCredentials({
            ssoStartUrl,
            ssoSession,
            ssoAccountId,
            ssoRegion,
            ssoRoleName,
            ssoClient,
            profile: profileName,
        });
    }
};

const resolveSsoCredentials = (data) => {
    const { sso_start_url, sso_account_id, sso_session, sso_region, sso_role_name } = validateSsoProfile(data);
    return fromSSO({
        ssoStartUrl: sso_start_url,
        ssoAccountId: sso_account_id,
        ssoSession: sso_session,
        ssoRegion: sso_region,
        ssoRoleName: sso_role_name,
    })();
};

const isStaticCredsProfile = (arg) => Boolean(arg) &&
    typeof arg === "object" &&
    typeof arg.aws_access_key_id === "string" &&
    typeof arg.aws_secret_access_key === "string" &&
    ["undefined", "string"].indexOf(typeof arg.aws_session_token) > -1;
const resolveStaticCredentials = (profile) => Promise.resolve({
    accessKeyId: profile.aws_access_key_id,
    secretAccessKey: profile.aws_secret_access_key,
    sessionToken: profile.aws_session_token,
});

const fromWebToken = (init) => () => {
    const { roleArn, roleSessionName, webIdentityToken, providerId, policyArns, policy, durationSeconds, roleAssumerWithWebIdentity, } = init;
    if (!roleAssumerWithWebIdentity) {
        throw new CredentialsProviderError(`Role Arn '${roleArn}' needs to be assumed with web identity,` +
            ` but no role assumption callback was provided.`, false);
    }
    return roleAssumerWithWebIdentity({
        RoleArn: roleArn,
        RoleSessionName: roleSessionName ?? `aws-sdk-js-session-${Date.now()}`,
        WebIdentityToken: webIdentityToken,
        ProviderId: providerId,
        PolicyArns: policyArns,
        Policy: policy,
        DurationSeconds: durationSeconds,
    });
};

const ENV_TOKEN_FILE = "AWS_WEB_IDENTITY_TOKEN_FILE";
const ENV_ROLE_ARN = "AWS_ROLE_ARN";
const ENV_ROLE_SESSION_NAME = "AWS_ROLE_SESSION_NAME";
const fromTokenFile = (init = {}) => async () => {
    return resolveTokenFile(init);
};
const resolveTokenFile = (init) => {
    const webIdentityTokenFile = init?.webIdentityTokenFile ?? process.env[ENV_TOKEN_FILE];
    const roleArn = init?.roleArn ?? process.env[ENV_ROLE_ARN];
    const roleSessionName = init?.roleSessionName ?? process.env[ENV_ROLE_SESSION_NAME];
    if (!webIdentityTokenFile || !roleArn) {
        throw new CredentialsProviderError("Web identity configuration not specified");
    }
    return fromWebToken({
        ...init,
        webIdentityToken: node_fs.readFileSync(webIdentityTokenFile, { encoding: "ascii" }),
        roleArn,
        roleSessionName,
    })();
};

const isWebIdentityProfile = (arg) => Boolean(arg) &&
    typeof arg === "object" &&
    typeof arg.web_identity_token_file === "string" &&
    typeof arg.role_arn === "string" &&
    ["undefined", "string"].indexOf(typeof arg.role_session_name) > -1;
const resolveWebIdentityCredentials = async (profile, options) => fromTokenFile({
    webIdentityTokenFile: profile.web_identity_token_file,
    roleArn: profile.role_arn,
    roleSessionName: profile.role_session_name,
    roleAssumerWithWebIdentity: options.roleAssumerWithWebIdentity,
})();

const resolveProfileData = async (profileName, profiles, options, visitedProfiles = {}) => {
    const data = profiles[profileName];
    if (Object.keys(visitedProfiles).length > 0 && isStaticCredsProfile(data)) {
        return resolveStaticCredentials(data);
    }
    if (isAssumeRoleProfile(data)) {
        return resolveAssumeRoleCredentials(profileName, profiles, options, visitedProfiles);
    }
    if (isStaticCredsProfile(data)) {
        return resolveStaticCredentials(data);
    }
    if (isWebIdentityProfile(data)) {
        return resolveWebIdentityCredentials(data, options);
    }
    if (isProcessProfile(data)) {
        return resolveProcessCredentials(options, profileName);
    }
    if (isSsoProfile(data)) {
        return resolveSsoCredentials(data);
    }
    throw new CredentialsProviderError(`Profile ${profileName} could not be found or parsed in shared credentials file.`);
};

const fromIni = (init = {}) => async () => {
    const profiles = await parseKnownFiles(init);
    return resolveProfileData(getProfileName(init), profiles, init);
};

const ENV_IMDS_DISABLED = "AWS_EC2_METADATA_DISABLED";
const remoteProvider = (init) => {
    if (process.env[ENV_CMDS_RELATIVE_URI] || process.env[ENV_CMDS_FULL_URI]) {
        return fromContainerMetadata(init);
    }
    if (process.env[ENV_IMDS_DISABLED]) {
        return async () => {
            throw new CredentialsProviderError("EC2 Instance Metadata Service access disabled");
        };
    }
    return fromInstanceMetadata(init);
};

const defaultProvider$1 = (init = {}) => memoize(chain(...(init.profile || process.env[ENV_PROFILE] ? [] : [fromEnv$1()]), fromSSO(init), fromIni(init), fromProcess(init), fromTokenFile(init), remoteProvider(init), async () => {
    throw new CredentialsProviderError("Could not load credentials from any providers", false);
}), (credentials) => credentials.expiration !== undefined && credentials.expiration.getTime() - Date.now() < 300000, (credentials) => credentials.expiration !== undefined);

var distEs$4 = /*#__PURE__*/Object.freeze({
	__proto__: null,
	defaultProvider: defaultProvider$1
});

var require$$4 = /*@__PURE__*/getAugmentedNamespace(distEs$4);

/*
let AWS = require("aws-sdk");
const CREDS = new AWS.EnvironmentCredentials("AWS");
AWS.config.credentials = CREDS;
AWS.config.update({ region: process.env.REGION });
*/

const { DynamoDBClient } = require$$0__default["default"];
const { DynamoDBDocumentClient } = require$$1__default["default"];
const { S3Client } = require$$2__default["default"];
const { AthenaClient } = require$$3__default["default"];
const { defaultProvider } = require$$4;

const {
  CognitoIdentityProviderClient,
} = require$$5__default["default"];

const { SESv2Client } = require$$6__default["default"];
const { SNSClient } = require$$7__default["default"];

const { EventBridgeClient } = require$$8__default["default"];

const { CloudWatchClient } = require$$9__default["default"];

const defaultCredentials = defaultProvider();


/*
AWS.CredentialProviderChain.defaultProviders = [
  function () { return new AWS.EnvironmentCredentials('AWS'); },
  function () { return new AWS.EnvironmentCredentials('AMAZON'); },
  function () { return new AWS.SharedIniFileCredentials({profile: aws_profile ? aws_profile : 'default' }); },
  function () { return new AWS.EC2MetadataCredentials(); }
];
*/
const clientCredentials = {
  credentials: defaultCredentials,
  region: process.env.REGION,
};

const snsClientCredentials = {
  credentials: defaultCredentials,
  region: process.env.SNS_REGION || process.env.REGION,
};

const sesClientCredentials = {
  credentials: defaultCredentials,
  region: process.env.EMAIL_REGION || process.env.REGION,
};
const ddbClient = new DynamoDBClient(clientCredentials);

const cognitoClient$1 = new CognitoIdentityProviderClient(clientCredentials);

const sesV2Client$1 = new SESv2Client(sesClientCredentials);

const snsClient$1 = new SNSClient(snsClientCredentials);

// Create an Amazon S3 service client object.
const s3Client$1 = new S3Client(clientCredentials);

// Create an Amazon EventBridge service client object.
const ebClient$1 = new EventBridgeClient(clientCredentials);
const athenaClient$1 = new AthenaClient(clientCredentials);
const cwClient$1 = new CloudWatchClient(clientCredentials);


const marshallOptions = {
  // Whether to automatically convert empty strings, blobs, and sets to `null`.
  convertEmptyValues: false, // false, by default.
  // Whether to remove undefined values while marshalling.
  removeUndefinedValues: false, // false, by default.
  // Whether to convert typeof object to map attribute.
  convertClassInstanceToMap: false, // false, by default.
};

const unmarshallOptions = {
  // Whether to return numbers as a string instead of converting them to native JavaScript numbers.
  wrapNumbers: false, // false, by default.
};

const translateConfig = { marshallOptions, unmarshallOptions };

// Create the DynamoDB Document client.
const ddbDocClient$1 = DynamoDBDocumentClient.from(ddbClient, translateConfig);

var aws$1 = {
  ddbDocClient: ddbDocClient$1,
  ddbClient,
  cognitoClient: cognitoClient$1,
  sesV2Client: sesV2Client$1,
  snsClient: snsClient$1,
  s3Client: s3Client$1,
  ebClient: ebClient$1,
  athenaClient: athenaClient$1,
  cwClient: cwClient$1
};

const { urlToHttpOptions: urlToHttpOptions$1 } = require$$0__default$1["default"];

const timeout = (ms) => new Promise((res) => setTimeout(res, ms));
function sliceIntoChunks(arr, chunkSize) {
  const res = [];
  for (let i = 0; i < arr.length; i += chunkSize) {
    const chunk = arr.slice(i, i + chunkSize);
    res.push(chunk);
  }
  return res;
}

function uCfirst$1(string) {
  return string.charAt(0).toUpperCase() + string.slice(1).toLowerCase();
}

function randomNumbers(string_length = 6) {
  const chars = "1234567890";
  let randomstring = "";
  for (let i = 0; i < string_length; i++) {
    let rnum = Math.floor(Math.random() * chars.length);
    randomstring += chars.substring(rnum, rnum + 1);
  }

  return randomstring;
}

function parseJwt$1(token) {
  var base64Url = token.split(".")[1];
  var base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  var jsonPayload = decodeURIComponent(
    Buffer.from(base64, "base64")
      .toString("utf-8")
      .split("")
      .map(function (c) {
        return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
      })
      .join("")
  );

  return JSON.parse(jsonPayload);
}

function addS3HiveSyntax(dateStr, dateHour) {
  //dataJSON.sleep.dateOfSleep.replace(/-/g, "/")
  const keys = ["year", "month", "day", "hour"];
  const parts = dateStr.split("/");
  let s3Key = parts.map((k, i) => {
    return keys[i] + "=" + parseInt(k);
  });
  if (typeof dateHour !== "undefined") {
    s3Key.push("hour=" + parseInt(dateHour));
  }

  return s3Key.join("/");
}

function uniqueFileName() {
  const CRYPTO = require$$1__default$1["default"];
  return CRYPTO.randomBytes(16).toString("hex");
}
function createNonce$1(len = 10) {
  const CRYPTO = require$$1__default$1["default"];
  return CRYPTO.randomBytes(len).toString("hex");
}
function getRequest$1(requestUrl, oAuth, query = "") {
  //const URL = require("url");
  const HTTPS = require$$2__default$1["default"];
  //const options = URL.parse(requestUrl);

  let options = urlToHttpOptions$1(new URL(requestUrl));

  options.method = "GET";

  options.headers = {
    Authorization: oAuth,
    "Content-Type": "application/json",
  };
  if (query !== "") {
    options.query = query;
  }
  /*
  ["protocol", "host", "hostname", "pathname", "href", "port"].forEach((o) => {
    options[o] = urlOptions[o];
  });
  options.path = options.pathname;
*/
  console.log("OPTIONS ", options);

  return new Promise(function (resolve, reject) {
    const req = HTTPS.request(options, (res) => {
      console.log(`statusCode: ${res.statusCode}`);
      console.log("RES ", res);
      //Handle the response
      const chunks = [];
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        chunks.push(chunk);
      });
      res.on("end", function () {
        resolve(chunks.join(""));
      });
    });

    req.on("error", (error) => {
      console.error(error);
      reject(error);
    });

    req.end();
  });
}
function postRequest$1(requestUrl, oAuth, body, header = {}) {
  //const body = JSON.stringify(message);
  //const URL = require("url");
  const HTTPS = require$$2__default$1["default"];
  //const options = URL.parse(requestUrl);

  let options = urlToHttpOptions$1(new URL(requestUrl));

  options.method = "POST";
  options.headers = {
    Authorization: oAuth,
    "Content-Type": "application/x-www-form-urlencoded",
    "Content-Length": Buffer.byteLength(body),
  };
  if (Object.keys(header).length > 0) {
    Object.keys(header).forEach(key => {
      options.headers[key] = header[key];
    });
  }
  /*
  ["protocol", "host", "hostname", "pathname", "href", "port"].forEach((o) => {
    options[o] = urlOptions[o];
  });
  options.path = options.pathname;
  */
  console.log("OPTIONS ", options);

  return new Promise(function (resolve, reject) {
    var postReq = HTTPS.request(
      options,
      function (res) {
        console.log(`POST statusCode: ${res.statusCode}`);
        //console.log("RES ", res);
        //Handle the response
        const chunks = [];
        res.setEncoding("utf8");
        res.on("data", function (chunk) {
          console.log("RES DATA ", chunk);
          chunks.push(chunk);
        });
        res.on("end", function () {
          resolve(chunks.join(""));
        });
      },
      function (err) {
        console.log("Error  " + err);
        reject(err);
      }
    );
    postReq.write(body);
    postReq.end();
  });
}
var libUtils$1 = {
  uCfirst: uCfirst$1,
  randomNumbers,
  createNonce: createNonce$1,
  parseJwt: parseJwt$1,
  addS3HiveSyntax,
  uniqueFileName,
  getRequest: getRequest$1,
  postRequest: postRequest$1,
  timeout,
  sliceIntoChunks,
};

var require$$11 = /*@__PURE__*/getAugmentedNamespace(distEs$5);

const SHORT_TO_HEX = {};
for (let i = 0; i < 256; i++) {
    let encodedByte = i.toString(16).toLowerCase();
    if (encodedByte.length === 1) {
        encodedByte = `0${encodedByte}`;
    }
    SHORT_TO_HEX[i] = encodedByte;
}
function toHex(bytes) {
    let out = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        out += SHORT_TO_HEX[bytes[i]];
    }
    return out;
}

const ALGORITHM_QUERY_PARAM = "X-Amz-Algorithm";
const CREDENTIAL_QUERY_PARAM = "X-Amz-Credential";
const AMZ_DATE_QUERY_PARAM = "X-Amz-Date";
const SIGNED_HEADERS_QUERY_PARAM = "X-Amz-SignedHeaders";
const EXPIRES_QUERY_PARAM = "X-Amz-Expires";
const SIGNATURE_QUERY_PARAM = "X-Amz-Signature";
const TOKEN_QUERY_PARAM = "X-Amz-Security-Token";
const AUTH_HEADER = "authorization";
const AMZ_DATE_HEADER = AMZ_DATE_QUERY_PARAM.toLowerCase();
const DATE_HEADER = "date";
const GENERATED_HEADERS = [AUTH_HEADER, AMZ_DATE_HEADER, DATE_HEADER];
const SIGNATURE_HEADER = SIGNATURE_QUERY_PARAM.toLowerCase();
const SHA256_HEADER = "x-amz-content-sha256";
const TOKEN_HEADER = TOKEN_QUERY_PARAM.toLowerCase();
const ALWAYS_UNSIGNABLE_HEADERS = {
    authorization: true,
    "cache-control": true,
    connection: true,
    expect: true,
    from: true,
    "keep-alive": true,
    "max-forwards": true,
    pragma: true,
    referer: true,
    te: true,
    trailer: true,
    "transfer-encoding": true,
    upgrade: true,
    "user-agent": true,
    "x-amzn-trace-id": true,
};
const PROXY_HEADER_PATTERN = /^proxy-/;
const SEC_HEADER_PATTERN = /^sec-/;
const ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256";
const EVENT_ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256-PAYLOAD";
const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
const MAX_CACHE_SIZE = 50;
const KEY_TYPE_IDENTIFIER = "aws4_request";
const MAX_PRESIGNED_TTL = 60 * 60 * 24 * 7;

const signingKeyCache = {};
const cacheQueue = [];
const createScope = (shortDate, region, service) => `${shortDate}/${region}/${service}/${KEY_TYPE_IDENTIFIER}`;
const getSigningKey = async (sha256Constructor, credentials, shortDate, region, service) => {
    const credsHash = await hmac(sha256Constructor, credentials.secretAccessKey, credentials.accessKeyId);
    const cacheKey = `${shortDate}:${region}:${service}:${toHex(credsHash)}:${credentials.sessionToken}`;
    if (cacheKey in signingKeyCache) {
        return signingKeyCache[cacheKey];
    }
    cacheQueue.push(cacheKey);
    while (cacheQueue.length > MAX_CACHE_SIZE) {
        delete signingKeyCache[cacheQueue.shift()];
    }
    let key = `AWS4${credentials.secretAccessKey}`;
    for (const signable of [shortDate, region, service, KEY_TYPE_IDENTIFIER]) {
        key = await hmac(sha256Constructor, key, signable);
    }
    return (signingKeyCache[cacheKey] = key);
};
const clearCredentialCache = () => {
    cacheQueue.length = 0;
    Object.keys(signingKeyCache).forEach((cacheKey) => {
        delete signingKeyCache[cacheKey];
    });
};
const hmac = (ctor, secret, data) => {
    const hash = new ctor(secret);
    hash.update(data);
    return hash.digest();
};

const getCanonicalHeaders = ({ headers }, unsignableHeaders, signableHeaders) => {
    const canonical = {};
    for (const headerName of Object.keys(headers).sort()) {
        if (headers[headerName] == undefined) {
            continue;
        }
        const canonicalHeaderName = headerName.toLowerCase();
        if (canonicalHeaderName in ALWAYS_UNSIGNABLE_HEADERS ||
            unsignableHeaders?.has(canonicalHeaderName) ||
            PROXY_HEADER_PATTERN.test(canonicalHeaderName) ||
            SEC_HEADER_PATTERN.test(canonicalHeaderName)) {
            if (!signableHeaders || (signableHeaders && !signableHeaders.has(canonicalHeaderName))) {
                continue;
            }
        }
        canonical[canonicalHeaderName] = headers[headerName].trim().replace(/\s+/g, " ");
    }
    return canonical;
};

const escapeUri = (uri) => encodeURIComponent(uri).replace(/[!'()*]/g, hexEncode);
const hexEncode = (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`;

const getCanonicalQuery = ({ query = {} }) => {
    const keys = [];
    const serialized = {};
    for (const key of Object.keys(query).sort()) {
        if (key.toLowerCase() === SIGNATURE_HEADER) {
            continue;
        }
        keys.push(key);
        const value = query[key];
        if (typeof value === "string") {
            serialized[key] = `${escapeUri(key)}=${escapeUri(value)}`;
        }
        else if (Array.isArray(value)) {
            serialized[key] = value
                .slice(0)
                .sort()
                .reduce((encoded, value) => encoded.concat([`${escapeUri(key)}=${escapeUri(value)}`]), [])
                .join("&");
        }
    }
    return keys
        .map((key) => serialized[key])
        .filter((serialized) => serialized)
        .join("&");
};

const getPayloadHash = async ({ headers, body }, hashConstructor) => {
    for (const headerName of Object.keys(headers)) {
        if (headerName.toLowerCase() === SHA256_HEADER) {
            return headers[headerName];
        }
    }
    if (body == undefined) {
        return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    }
    else if (typeof body === "string" || ArrayBuffer.isView(body) || isArrayBuffer(body)) {
        const hashCtor = new hashConstructor();
        hashCtor.update(body);
        return toHex(await hashCtor.digest());
    }
    return UNSIGNED_PAYLOAD;
};

const hasHeader = (soughtHeader, headers) => {
    soughtHeader = soughtHeader.toLowerCase();
    for (const headerName of Object.keys(headers)) {
        if (soughtHeader === headerName.toLowerCase()) {
            return true;
        }
    }
    return false;
};

const cloneRequest = ({ headers, query, ...rest }) => ({
    ...rest,
    headers: { ...headers },
    query: query ? cloneQuery(query) : undefined,
});
const cloneQuery = (query) => Object.keys(query).reduce((carry, paramName) => {
    const param = query[paramName];
    return {
        ...carry,
        [paramName]: Array.isArray(param) ? [...param] : param,
    };
}, {});

const moveHeadersToQuery = (request, options = {}) => {
    const { headers, query = {} } = typeof request.clone === "function" ? request.clone() : cloneRequest(request);
    for (const name of Object.keys(headers)) {
        const lname = name.toLowerCase();
        if (lname.slice(0, 6) === "x-amz-" && !options.unhoistableHeaders?.has(lname)) {
            query[name] = headers[name];
            delete headers[name];
        }
    }
    return {
        ...request,
        headers,
        query,
    };
};

const prepareRequest = (request) => {
    request = typeof request.clone === "function" ? request.clone() : cloneRequest(request);
    for (const headerName of Object.keys(request.headers)) {
        if (GENERATED_HEADERS.indexOf(headerName.toLowerCase()) > -1) {
            delete request.headers[headerName];
        }
    }
    return request;
};

const iso8601 = (time) => toDate(time)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
const toDate = (time) => {
    if (typeof time === "number") {
        return new Date(time * 1000);
    }
    if (typeof time === "string") {
        if (Number(time)) {
            return new Date(Number(time) * 1000);
        }
        return new Date(time);
    }
    return time;
};

class SignatureV4$1 {
    constructor({ applyChecksum, credentials, region, service, sha256, uriEscapePath = true, }) {
        this.service = service;
        this.sha256 = sha256;
        this.uriEscapePath = uriEscapePath;
        this.applyChecksum = typeof applyChecksum === "boolean" ? applyChecksum : true;
        this.regionProvider = normalizeProvider(region);
        this.credentialProvider = normalizeProvider(credentials);
    }
    async presign(originalRequest, options = {}) {
        const { signingDate = new Date(), expiresIn = 3600, unsignableHeaders, unhoistableHeaders, signableHeaders, signingRegion, signingService, } = options;
        const credentials = await this.credentialProvider();
        this.validateResolvedCredentials(credentials);
        const region = signingRegion ?? (await this.regionProvider());
        const { longDate, shortDate } = formatDate(signingDate);
        if (expiresIn > MAX_PRESIGNED_TTL) {
            return Promise.reject("Signature version 4 presigned URLs" + " must have an expiration date less than one week in" + " the future");
        }
        const scope = createScope(shortDate, region, signingService ?? this.service);
        const request = moveHeadersToQuery(prepareRequest(originalRequest), { unhoistableHeaders });
        if (credentials.sessionToken) {
            request.query[TOKEN_QUERY_PARAM] = credentials.sessionToken;
        }
        request.query[ALGORITHM_QUERY_PARAM] = ALGORITHM_IDENTIFIER;
        request.query[CREDENTIAL_QUERY_PARAM] = `${credentials.accessKeyId}/${scope}`;
        request.query[AMZ_DATE_QUERY_PARAM] = longDate;
        request.query[EXPIRES_QUERY_PARAM] = expiresIn.toString(10);
        const canonicalHeaders = getCanonicalHeaders(request, unsignableHeaders, signableHeaders);
        request.query[SIGNED_HEADERS_QUERY_PARAM] = getCanonicalHeaderList(canonicalHeaders);
        request.query[SIGNATURE_QUERY_PARAM] = await this.getSignature(longDate, scope, this.getSigningKey(credentials, region, shortDate, signingService), this.createCanonicalRequest(request, canonicalHeaders, await getPayloadHash(originalRequest, this.sha256)));
        return request;
    }
    async sign(toSign, options) {
        if (typeof toSign === "string") {
            return this.signString(toSign, options);
        }
        else if (toSign.headers && toSign.payload) {
            return this.signEvent(toSign, options);
        }
        else {
            return this.signRequest(toSign, options);
        }
    }
    async signEvent({ headers, payload }, { signingDate = new Date(), priorSignature, signingRegion, signingService }) {
        const region = signingRegion ?? (await this.regionProvider());
        const { shortDate, longDate } = formatDate(signingDate);
        const scope = createScope(shortDate, region, signingService ?? this.service);
        const hashedPayload = await getPayloadHash({ headers: {}, body: payload }, this.sha256);
        const hash = new this.sha256();
        hash.update(headers);
        const hashedHeaders = toHex(await hash.digest());
        const stringToSign = [
            EVENT_ALGORITHM_IDENTIFIER,
            longDate,
            scope,
            priorSignature,
            hashedHeaders,
            hashedPayload,
        ].join("\n");
        return this.signString(stringToSign, { signingDate, signingRegion: region, signingService });
    }
    async signString(stringToSign, { signingDate = new Date(), signingRegion, signingService } = {}) {
        const credentials = await this.credentialProvider();
        this.validateResolvedCredentials(credentials);
        const region = signingRegion ?? (await this.regionProvider());
        const { shortDate } = formatDate(signingDate);
        const hash = new this.sha256(await this.getSigningKey(credentials, region, shortDate, signingService));
        hash.update(stringToSign);
        return toHex(await hash.digest());
    }
    async signRequest(requestToSign, { signingDate = new Date(), signableHeaders, unsignableHeaders, signingRegion, signingService, } = {}) {
        const credentials = await this.credentialProvider();
        this.validateResolvedCredentials(credentials);
        const region = signingRegion ?? (await this.regionProvider());
        const request = prepareRequest(requestToSign);
        const { longDate, shortDate } = formatDate(signingDate);
        const scope = createScope(shortDate, region, signingService ?? this.service);
        request.headers[AMZ_DATE_HEADER] = longDate;
        if (credentials.sessionToken) {
            request.headers[TOKEN_HEADER] = credentials.sessionToken;
        }
        const payloadHash = await getPayloadHash(request, this.sha256);
        if (!hasHeader(SHA256_HEADER, request.headers) && this.applyChecksum) {
            request.headers[SHA256_HEADER] = payloadHash;
        }
        const canonicalHeaders = getCanonicalHeaders(request, unsignableHeaders, signableHeaders);
        const signature = await this.getSignature(longDate, scope, this.getSigningKey(credentials, region, shortDate, signingService), this.createCanonicalRequest(request, canonicalHeaders, payloadHash));
        request.headers[AUTH_HEADER] =
            `${ALGORITHM_IDENTIFIER} ` +
                `Credential=${credentials.accessKeyId}/${scope}, ` +
                `SignedHeaders=${getCanonicalHeaderList(canonicalHeaders)}, ` +
                `Signature=${signature}`;
        return request;
    }
    createCanonicalRequest(request, canonicalHeaders, payloadHash) {
        const sortedHeaders = Object.keys(canonicalHeaders).sort();
        return `${request.method}
${this.getCanonicalPath(request)}
${getCanonicalQuery(request)}
${sortedHeaders.map((name) => `${name}:${canonicalHeaders[name]}`).join("\n")}

${sortedHeaders.join(";")}
${payloadHash}`;
    }
    async createStringToSign(longDate, credentialScope, canonicalRequest) {
        const hash = new this.sha256();
        hash.update(canonicalRequest);
        const hashedRequest = await hash.digest();
        return `${ALGORITHM_IDENTIFIER}
${longDate}
${credentialScope}
${toHex(hashedRequest)}`;
    }
    getCanonicalPath({ path }) {
        if (this.uriEscapePath) {
            const normalizedPathSegments = [];
            for (const pathSegment of path.split("/")) {
                if (pathSegment?.length === 0)
                    continue;
                if (pathSegment === ".")
                    continue;
                if (pathSegment === "..") {
                    normalizedPathSegments.pop();
                }
                else {
                    normalizedPathSegments.push(pathSegment);
                }
            }
            const normalizedPath = `${path?.startsWith("/") ? "/" : ""}${normalizedPathSegments.join("/")}${normalizedPathSegments.length > 0 && path?.endsWith("/") ? "/" : ""}`;
            const doubleEncoded = encodeURIComponent(normalizedPath);
            return doubleEncoded.replace(/%2F/g, "/");
        }
        return path;
    }
    async getSignature(longDate, credentialScope, keyPromise, canonicalRequest) {
        const stringToSign = await this.createStringToSign(longDate, credentialScope, canonicalRequest);
        const hash = new this.sha256(await keyPromise);
        hash.update(stringToSign);
        return toHex(await hash.digest());
    }
    getSigningKey(credentials, region, shortDate, service) {
        return getSigningKey(this.sha256, credentials, shortDate, region, service || this.service);
    }
    validateResolvedCredentials(credentials) {
        if (typeof credentials !== "object" ||
            typeof credentials.accessKeyId !== "string" ||
            typeof credentials.secretAccessKey !== "string") {
            throw new Error("Resolved credential object is not valid");
        }
    }
}
const formatDate = (now) => {
    const longDate = iso8601(now).replace(/[\-:]/g, "");
    return {
        longDate,
        shortDate: longDate.slice(0, 8),
    };
};
const getCanonicalHeaderList = (headers) => Object.keys(headers).sort().join(";");

var distEs$3 = /*#__PURE__*/Object.freeze({
	__proto__: null,
	getCanonicalHeaders: getCanonicalHeaders,
	getCanonicalQuery: getCanonicalQuery,
	getPayloadHash: getPayloadHash,
	moveHeadersToQuery: moveHeadersToQuery,
	prepareRequest: prepareRequest,
	SignatureV4: SignatureV4$1,
	createScope: createScope,
	getSigningKey: getSigningKey,
	clearCredentialCache: clearCredentialCache
});

var require$$12 = /*@__PURE__*/getAugmentedNamespace(distEs$3);

var build$4 = {};

/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics$2 = function(d, b) {
    extendStatics$2 = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics$2(d, b);
};

function __extends$2(d, b) {
    extendStatics$2(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign$2 = function() {
    __assign$2 = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    };
    return __assign$2.apply(this, arguments);
};

function __rest$2(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
}

function __decorate$2(decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
}

function __param$2(paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
}

function __metadata$2(metadataKey, metadataValue) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}

function __awaiter$2(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator$2(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

function __createBinding$2(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}

function __exportStar$2(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) exports[p] = m[p];
}

function __values$2(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

function __read$2(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spread$2() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read$2(arguments[i]));
    return ar;
}

function __spreadArrays$2() {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
}
function __await$2(v) {
    return this instanceof __await$2 ? (this.v = v, this) : new __await$2(v);
}

function __asyncGenerator$2(thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await$2 ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
}

function __asyncDelegator$2(o) {
    var i, p;
    return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
    function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await$2(o[n](v)), done: n === "return" } : f ? f(v) : v; } : f; }
}

function __asyncValues$2(o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values$2 === "function" ? __values$2(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
}

function __makeTemplateObject$2(cooked, raw) {
    if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
    return cooked;
}
function __importStar$2(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result.default = mod;
    return result;
}

function __importDefault$2(mod) {
    return (mod && mod.__esModule) ? mod : { default: mod };
}

function __classPrivateFieldGet$2(receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
}

function __classPrivateFieldSet$2(receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
}

var tslib_es6$2 = /*#__PURE__*/Object.freeze({
	__proto__: null,
	__extends: __extends$2,
	get __assign () { return __assign$2; },
	__rest: __rest$2,
	__decorate: __decorate$2,
	__param: __param$2,
	__metadata: __metadata$2,
	__awaiter: __awaiter$2,
	__generator: __generator$2,
	__createBinding: __createBinding$2,
	__exportStar: __exportStar$2,
	__values: __values$2,
	__read: __read$2,
	__spread: __spread$2,
	__spreadArrays: __spreadArrays$2,
	__await: __await$2,
	__asyncGenerator: __asyncGenerator$2,
	__asyncDelegator: __asyncDelegator$2,
	__asyncValues: __asyncValues$2,
	__makeTemplateObject: __makeTemplateObject$2,
	__importStar: __importStar$2,
	__importDefault: __importDefault$2,
	__classPrivateFieldGet: __classPrivateFieldGet$2,
	__classPrivateFieldSet: __classPrivateFieldSet$2
});

var require$$0$3 = /*@__PURE__*/getAugmentedNamespace(tslib_es6$2);

var crossPlatformSha256 = {};

var ie11Sha256 = {};

var isEmptyData$3 = {};

Object.defineProperty(isEmptyData$3, "__esModule", { value: true });
isEmptyData$3.isEmptyData = void 0;
function isEmptyData$2(data) {
    if (typeof data === "string") {
        return data.length === 0;
    }
    return data.byteLength === 0;
}
isEmptyData$3.isEmptyData = isEmptyData$2;

var constants$1 = {};

(function (exports) {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.EMPTY_DATA_SHA_256 = exports.SHA_256_HMAC_ALGO = exports.SHA_256_HASH = void 0;
	exports.SHA_256_HASH = { name: "SHA-256" };
	exports.SHA_256_HMAC_ALGO = {
	    name: "HMAC",
	    hash: exports.SHA_256_HASH
	};
	exports.EMPTY_DATA_SHA_256 = new Uint8Array([
	    227,
	    176,
	    196,
	    66,
	    152,
	    252,
	    28,
	    20,
	    154,
	    251,
	    244,
	    200,
	    153,
	    111,
	    185,
	    36,
	    39,
	    174,
	    65,
	    228,
	    100,
	    155,
	    147,
	    76,
	    164,
	    149,
	    153,
	    27,
	    120,
	    82,
	    184,
	    85
	]);
	
} (constants$1));

const fromUtf8$3 = (input) => {
    const bytes = [];
    for (let i = 0, len = input.length; i < len; i++) {
        const value = input.charCodeAt(i);
        if (value < 0x80) {
            bytes.push(value);
        }
        else if (value < 0x800) {
            bytes.push((value >> 6) | 0b11000000, (value & 0b111111) | 0b10000000);
        }
        else if (i + 1 < input.length && (value & 0xfc00) === 0xd800 && (input.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
            const surrogatePair = 0x10000 + ((value & 0b1111111111) << 10) + (input.charCodeAt(++i) & 0b1111111111);
            bytes.push((surrogatePair >> 18) | 0b11110000, ((surrogatePair >> 12) & 0b111111) | 0b10000000, ((surrogatePair >> 6) & 0b111111) | 0b10000000, (surrogatePair & 0b111111) | 0b10000000);
        }
        else {
            bytes.push((value >> 12) | 0b11100000, ((value >> 6) & 0b111111) | 0b10000000, (value & 0b111111) | 0b10000000);
        }
    }
    return Uint8Array.from(bytes);
};
const toUtf8$2 = (input) => {
    let decoded = "";
    for (let i = 0, len = input.length; i < len; i++) {
        const byte = input[i];
        if (byte < 0x80) {
            decoded += String.fromCharCode(byte);
        }
        else if (0b11000000 <= byte && byte < 0b11100000) {
            const nextByte = input[++i];
            decoded += String.fromCharCode(((byte & 0b11111) << 6) | (nextByte & 0b111111));
        }
        else if (0b11110000 <= byte && byte < 0b101101101) {
            const surrogatePair = [byte, input[++i], input[++i], input[++i]];
            const encoded = "%" + surrogatePair.map((byteValue) => byteValue.toString(16)).join("%");
            decoded += decodeURIComponent(encoded);
        }
        else {
            decoded += String.fromCharCode(((byte & 0b1111) << 12) | ((input[++i] & 0b111111) << 6) | (input[++i] & 0b111111));
        }
    }
    return decoded;
};

function fromUtf8$2(input) {
    return new TextEncoder().encode(input);
}
function toUtf8$1(input) {
    return new TextDecoder("utf-8").decode(input);
}

const fromUtf8$1 = (input) => typeof TextEncoder === "function" ? fromUtf8$2(input) : fromUtf8$3(input);
const toUtf8 = (input) => typeof TextDecoder === "function" ? toUtf8$1(input) : toUtf8$2(input);

var distEs$2 = /*#__PURE__*/Object.freeze({
	__proto__: null,
	fromUtf8: fromUtf8$1,
	toUtf8: toUtf8
});

var require$$0$2 = /*@__PURE__*/getAugmentedNamespace(distEs$2);

const fallbackWindow = {};
function locateWindow() {
    if (typeof window !== "undefined") {
        return window;
    }
    else if (typeof self !== "undefined") {
        return self;
    }
    return fallbackWindow;
}

var distEs$1 = /*#__PURE__*/Object.freeze({
	__proto__: null,
	locateWindow: locateWindow
});

var require$$5 = /*@__PURE__*/getAugmentedNamespace(distEs$1);

Object.defineProperty(ie11Sha256, "__esModule", { value: true });
ie11Sha256.Sha256 = void 0;
var isEmptyData_1 = isEmptyData$3;
var constants_1$1 = constants$1;
var util_utf8_browser_1$1 = require$$0$2;
var util_locate_window_1$2 = require$$5;
var Sha256$3 = /** @class */ (function () {
    function Sha256(secret) {
        if (secret) {
            this.operation = getKeyPromise(secret).then(function (keyData) {
                return (0, util_locate_window_1$2.locateWindow)().msCrypto.subtle.sign(constants_1$1.SHA_256_HMAC_ALGO, keyData);
            });
            this.operation.catch(function () { });
        }
        else {
            this.operation = Promise.resolve((0, util_locate_window_1$2.locateWindow)().msCrypto.subtle.digest("SHA-256"));
        }
    }
    Sha256.prototype.update = function (toHash) {
        var _this = this;
        if ((0, isEmptyData_1.isEmptyData)(toHash)) {
            return;
        }
        this.operation = this.operation.then(function (operation) {
            operation.onerror = function () {
                _this.operation = Promise.reject(new Error("Error encountered updating hash"));
            };
            operation.process(toArrayBufferView(toHash));
            return operation;
        });
        this.operation.catch(function () { });
    };
    Sha256.prototype.digest = function () {
        return this.operation.then(function (operation) {
            return new Promise(function (resolve, reject) {
                operation.onerror = function () {
                    reject(new Error("Error encountered finalizing hash"));
                };
                operation.oncomplete = function () {
                    if (operation.result) {
                        resolve(new Uint8Array(operation.result));
                    }
                    reject(new Error("Error encountered finalizing hash"));
                };
                operation.finish();
            });
        });
    };
    return Sha256;
}());
ie11Sha256.Sha256 = Sha256$3;
function getKeyPromise(secret) {
    return new Promise(function (resolve, reject) {
        var keyOperation = (0, util_locate_window_1$2.locateWindow)().msCrypto.subtle.importKey("raw", toArrayBufferView(secret), constants_1$1.SHA_256_HMAC_ALGO, false, ["sign"]);
        keyOperation.oncomplete = function () {
            if (keyOperation.result) {
                resolve(keyOperation.result);
            }
            reject(new Error("ImportKey completed without importing key."));
        };
        keyOperation.onerror = function () {
            reject(new Error("ImportKey failed to import key."));
        };
    });
}
function toArrayBufferView(data) {
    if (typeof data === "string") {
        return (0, util_utf8_browser_1$1.fromUtf8)(data);
    }
    if (ArrayBuffer.isView(data)) {
        return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
    }
    return new Uint8Array(data);
}

var webCryptoSha256 = {};

var build$3 = {};

var convertToBuffer$1 = {};

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(convertToBuffer$1, "__esModule", { value: true });
convertToBuffer$1.convertToBuffer = void 0;
var util_utf8_browser_1 = require$$0$2;
// Quick polyfill
var fromUtf8 = typeof Buffer !== "undefined" && Buffer.from
    ? function (input) { return Buffer.from(input, "utf8"); }
    : util_utf8_browser_1.fromUtf8;
function convertToBuffer(data) {
    // Already a Uint8, do nothing
    if (data instanceof Uint8Array)
        return data;
    if (typeof data === "string") {
        return fromUtf8(data);
    }
    if (ArrayBuffer.isView(data)) {
        return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
    }
    return new Uint8Array(data);
}
convertToBuffer$1.convertToBuffer = convertToBuffer;

var isEmptyData$1 = {};

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(isEmptyData$1, "__esModule", { value: true });
isEmptyData$1.isEmptyData = void 0;
function isEmptyData(data) {
    if (typeof data === "string") {
        return data.length === 0;
    }
    return data.byteLength === 0;
}
isEmptyData$1.isEmptyData = isEmptyData;

var numToUint8$1 = {};

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(numToUint8$1, "__esModule", { value: true });
numToUint8$1.numToUint8 = void 0;
function numToUint8(num) {
    return new Uint8Array([
        (num & 0xff000000) >> 24,
        (num & 0x00ff0000) >> 16,
        (num & 0x0000ff00) >> 8,
        num & 0x000000ff,
    ]);
}
numToUint8$1.numToUint8 = numToUint8;

var uint32ArrayFrom$1 = {};

// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
Object.defineProperty(uint32ArrayFrom$1, "__esModule", { value: true });
uint32ArrayFrom$1.uint32ArrayFrom = void 0;
// IE 11 does not support Array.from, so we do it manually
function uint32ArrayFrom(a_lookUpTable) {
    if (!Uint32Array.from) {
        var return_array = new Uint32Array(a_lookUpTable.length);
        var a_index = 0;
        while (a_index < a_lookUpTable.length) {
            return_array[a_index] = a_lookUpTable[a_index];
            a_index += 1;
        }
        return return_array;
    }
    return Uint32Array.from(a_lookUpTable);
}
uint32ArrayFrom$1.uint32ArrayFrom = uint32ArrayFrom;

(function (exports) {
	// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
	// SPDX-License-Identifier: Apache-2.0
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.uint32ArrayFrom = exports.numToUint8 = exports.isEmptyData = exports.convertToBuffer = void 0;
	var convertToBuffer_1 = convertToBuffer$1;
	Object.defineProperty(exports, "convertToBuffer", { enumerable: true, get: function () { return convertToBuffer_1.convertToBuffer; } });
	var isEmptyData_1 = isEmptyData$1;
	Object.defineProperty(exports, "isEmptyData", { enumerable: true, get: function () { return isEmptyData_1.isEmptyData; } });
	var numToUint8_1 = numToUint8$1;
	Object.defineProperty(exports, "numToUint8", { enumerable: true, get: function () { return numToUint8_1.numToUint8; } });
	var uint32ArrayFrom_1 = uint32ArrayFrom$1;
	Object.defineProperty(exports, "uint32ArrayFrom", { enumerable: true, get: function () { return uint32ArrayFrom_1.uint32ArrayFrom; } });
	
} (build$3));

Object.defineProperty(webCryptoSha256, "__esModule", { value: true });
webCryptoSha256.Sha256 = void 0;
var util_1 = build$3;
var constants_1 = constants$1;
var util_locate_window_1$1 = require$$5;
var Sha256$2 = /** @class */ (function () {
    function Sha256(secret) {
        this.toHash = new Uint8Array(0);
        if (secret !== void 0) {
            this.key = new Promise(function (resolve, reject) {
                (0, util_locate_window_1$1.locateWindow)()
                    .crypto.subtle.importKey("raw", (0, util_1.convertToBuffer)(secret), constants_1.SHA_256_HMAC_ALGO, false, ["sign"])
                    .then(resolve, reject);
            });
            this.key.catch(function () { });
        }
    }
    Sha256.prototype.update = function (data) {
        if ((0, util_1.isEmptyData)(data)) {
            return;
        }
        var update = (0, util_1.convertToBuffer)(data);
        var typedArray = new Uint8Array(this.toHash.byteLength + update.byteLength);
        typedArray.set(this.toHash, 0);
        typedArray.set(update, this.toHash.byteLength);
        this.toHash = typedArray;
    };
    Sha256.prototype.digest = function () {
        var _this = this;
        if (this.key) {
            return this.key.then(function (key) {
                return (0, util_locate_window_1$1.locateWindow)()
                    .crypto.subtle.sign(constants_1.SHA_256_HMAC_ALGO, key, _this.toHash)
                    .then(function (data) { return new Uint8Array(data); });
            });
        }
        if ((0, util_1.isEmptyData)(this.toHash)) {
            return Promise.resolve(constants_1.EMPTY_DATA_SHA_256);
        }
        return Promise.resolve()
            .then(function () {
            return (0, util_locate_window_1$1.locateWindow)().crypto.subtle.digest(constants_1.SHA_256_HASH, _this.toHash);
        })
            .then(function (data) { return Promise.resolve(new Uint8Array(data)); });
    };
    return Sha256;
}());
webCryptoSha256.Sha256 = Sha256$2;

var build$2 = {};

var jsSha256 = {};

var constants = {};

var hasRequiredConstants;

function requireConstants () {
	if (hasRequiredConstants) return constants;
	hasRequiredConstants = 1;
	Object.defineProperty(constants, "__esModule", { value: true });
	constants.MAX_HASHABLE_LENGTH = constants.INIT = constants.KEY = constants.DIGEST_LENGTH = constants.BLOCK_SIZE = void 0;
	/**
	 * @internal
	 */
	constants.BLOCK_SIZE = 64;
	/**
	 * @internal
	 */
	constants.DIGEST_LENGTH = 32;
	/**
	 * @internal
	 */
	constants.KEY = new Uint32Array([
	    0x428a2f98,
	    0x71374491,
	    0xb5c0fbcf,
	    0xe9b5dba5,
	    0x3956c25b,
	    0x59f111f1,
	    0x923f82a4,
	    0xab1c5ed5,
	    0xd807aa98,
	    0x12835b01,
	    0x243185be,
	    0x550c7dc3,
	    0x72be5d74,
	    0x80deb1fe,
	    0x9bdc06a7,
	    0xc19bf174,
	    0xe49b69c1,
	    0xefbe4786,
	    0x0fc19dc6,
	    0x240ca1cc,
	    0x2de92c6f,
	    0x4a7484aa,
	    0x5cb0a9dc,
	    0x76f988da,
	    0x983e5152,
	    0xa831c66d,
	    0xb00327c8,
	    0xbf597fc7,
	    0xc6e00bf3,
	    0xd5a79147,
	    0x06ca6351,
	    0x14292967,
	    0x27b70a85,
	    0x2e1b2138,
	    0x4d2c6dfc,
	    0x53380d13,
	    0x650a7354,
	    0x766a0abb,
	    0x81c2c92e,
	    0x92722c85,
	    0xa2bfe8a1,
	    0xa81a664b,
	    0xc24b8b70,
	    0xc76c51a3,
	    0xd192e819,
	    0xd6990624,
	    0xf40e3585,
	    0x106aa070,
	    0x19a4c116,
	    0x1e376c08,
	    0x2748774c,
	    0x34b0bcb5,
	    0x391c0cb3,
	    0x4ed8aa4a,
	    0x5b9cca4f,
	    0x682e6ff3,
	    0x748f82ee,
	    0x78a5636f,
	    0x84c87814,
	    0x8cc70208,
	    0x90befffa,
	    0xa4506ceb,
	    0xbef9a3f7,
	    0xc67178f2
	]);
	/**
	 * @internal
	 */
	constants.INIT = [
	    0x6a09e667,
	    0xbb67ae85,
	    0x3c6ef372,
	    0xa54ff53a,
	    0x510e527f,
	    0x9b05688c,
	    0x1f83d9ab,
	    0x5be0cd19
	];
	/**
	 * @internal
	 */
	constants.MAX_HASHABLE_LENGTH = Math.pow(2, 53) - 1;
	
	return constants;
}

var RawSha256 = {};

var hasRequiredRawSha256;

function requireRawSha256 () {
	if (hasRequiredRawSha256) return RawSha256;
	hasRequiredRawSha256 = 1;
	Object.defineProperty(RawSha256, "__esModule", { value: true });
	RawSha256.RawSha256 = void 0;
	var constants_1 = requireConstants();
	/**
	 * @internal
	 */
	var RawSha256$1 = /** @class */ (function () {
	    function RawSha256() {
	        this.state = Int32Array.from(constants_1.INIT);
	        this.temp = new Int32Array(64);
	        this.buffer = new Uint8Array(64);
	        this.bufferLength = 0;
	        this.bytesHashed = 0;
	        /**
	         * @internal
	         */
	        this.finished = false;
	    }
	    RawSha256.prototype.update = function (data) {
	        if (this.finished) {
	            throw new Error("Attempted to update an already finished hash.");
	        }
	        var position = 0;
	        var byteLength = data.byteLength;
	        this.bytesHashed += byteLength;
	        if (this.bytesHashed * 8 > constants_1.MAX_HASHABLE_LENGTH) {
	            throw new Error("Cannot hash more than 2^53 - 1 bits");
	        }
	        while (byteLength > 0) {
	            this.buffer[this.bufferLength++] = data[position++];
	            byteLength--;
	            if (this.bufferLength === constants_1.BLOCK_SIZE) {
	                this.hashBuffer();
	                this.bufferLength = 0;
	            }
	        }
	    };
	    RawSha256.prototype.digest = function () {
	        if (!this.finished) {
	            var bitsHashed = this.bytesHashed * 8;
	            var bufferView = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength);
	            var undecoratedLength = this.bufferLength;
	            bufferView.setUint8(this.bufferLength++, 0x80);
	            // Ensure the final block has enough room for the hashed length
	            if (undecoratedLength % constants_1.BLOCK_SIZE >= constants_1.BLOCK_SIZE - 8) {
	                for (var i = this.bufferLength; i < constants_1.BLOCK_SIZE; i++) {
	                    bufferView.setUint8(i, 0);
	                }
	                this.hashBuffer();
	                this.bufferLength = 0;
	            }
	            for (var i = this.bufferLength; i < constants_1.BLOCK_SIZE - 8; i++) {
	                bufferView.setUint8(i, 0);
	            }
	            bufferView.setUint32(constants_1.BLOCK_SIZE - 8, Math.floor(bitsHashed / 0x100000000), true);
	            bufferView.setUint32(constants_1.BLOCK_SIZE - 4, bitsHashed);
	            this.hashBuffer();
	            this.finished = true;
	        }
	        // The value in state is little-endian rather than big-endian, so flip
	        // each word into a new Uint8Array
	        var out = new Uint8Array(constants_1.DIGEST_LENGTH);
	        for (var i = 0; i < 8; i++) {
	            out[i * 4] = (this.state[i] >>> 24) & 0xff;
	            out[i * 4 + 1] = (this.state[i] >>> 16) & 0xff;
	            out[i * 4 + 2] = (this.state[i] >>> 8) & 0xff;
	            out[i * 4 + 3] = (this.state[i] >>> 0) & 0xff;
	        }
	        return out;
	    };
	    RawSha256.prototype.hashBuffer = function () {
	        var _a = this, buffer = _a.buffer, state = _a.state;
	        var state0 = state[0], state1 = state[1], state2 = state[2], state3 = state[3], state4 = state[4], state5 = state[5], state6 = state[6], state7 = state[7];
	        for (var i = 0; i < constants_1.BLOCK_SIZE; i++) {
	            if (i < 16) {
	                this.temp[i] =
	                    ((buffer[i * 4] & 0xff) << 24) |
	                        ((buffer[i * 4 + 1] & 0xff) << 16) |
	                        ((buffer[i * 4 + 2] & 0xff) << 8) |
	                        (buffer[i * 4 + 3] & 0xff);
	            }
	            else {
	                var u = this.temp[i - 2];
	                var t1_1 = ((u >>> 17) | (u << 15)) ^ ((u >>> 19) | (u << 13)) ^ (u >>> 10);
	                u = this.temp[i - 15];
	                var t2_1 = ((u >>> 7) | (u << 25)) ^ ((u >>> 18) | (u << 14)) ^ (u >>> 3);
	                this.temp[i] =
	                    ((t1_1 + this.temp[i - 7]) | 0) + ((t2_1 + this.temp[i - 16]) | 0);
	            }
	            var t1 = ((((((state4 >>> 6) | (state4 << 26)) ^
	                ((state4 >>> 11) | (state4 << 21)) ^
	                ((state4 >>> 25) | (state4 << 7))) +
	                ((state4 & state5) ^ (~state4 & state6))) |
	                0) +
	                ((state7 + ((constants_1.KEY[i] + this.temp[i]) | 0)) | 0)) |
	                0;
	            var t2 = ((((state0 >>> 2) | (state0 << 30)) ^
	                ((state0 >>> 13) | (state0 << 19)) ^
	                ((state0 >>> 22) | (state0 << 10))) +
	                ((state0 & state1) ^ (state0 & state2) ^ (state1 & state2))) |
	                0;
	            state7 = state6;
	            state6 = state5;
	            state5 = state4;
	            state4 = (state3 + t1) | 0;
	            state3 = state2;
	            state2 = state1;
	            state1 = state0;
	            state0 = (t1 + t2) | 0;
	        }
	        state[0] += state0;
	        state[1] += state1;
	        state[2] += state2;
	        state[3] += state3;
	        state[4] += state4;
	        state[5] += state5;
	        state[6] += state6;
	        state[7] += state7;
	    };
	    return RawSha256;
	}());
	RawSha256.RawSha256 = RawSha256$1;
	
	return RawSha256;
}

var hasRequiredJsSha256;

function requireJsSha256 () {
	if (hasRequiredJsSha256) return jsSha256;
	hasRequiredJsSha256 = 1;
	Object.defineProperty(jsSha256, "__esModule", { value: true });
	jsSha256.Sha256 = void 0;
	var tslib_1 = require$$0$3;
	var constants_1 = requireConstants();
	var RawSha256_1 = requireRawSha256();
	var util_1 = build$3;
	var Sha256 = /** @class */ (function () {
	    function Sha256(secret) {
	        this.hash = new RawSha256_1.RawSha256();
	        if (secret) {
	            this.outer = new RawSha256_1.RawSha256();
	            var inner = bufferFromSecret(secret);
	            var outer = new Uint8Array(constants_1.BLOCK_SIZE);
	            outer.set(inner);
	            for (var i = 0; i < constants_1.BLOCK_SIZE; i++) {
	                inner[i] ^= 0x36;
	                outer[i] ^= 0x5c;
	            }
	            this.hash.update(inner);
	            this.outer.update(outer);
	            // overwrite the copied key in memory
	            for (var i = 0; i < inner.byteLength; i++) {
	                inner[i] = 0;
	            }
	        }
	    }
	    Sha256.prototype.update = function (toHash) {
	        if ((0, util_1.isEmptyData)(toHash) || this.error) {
	            return;
	        }
	        try {
	            this.hash.update((0, util_1.convertToBuffer)(toHash));
	        }
	        catch (e) {
	            this.error = e;
	        }
	    };
	    /* This synchronous method keeps compatibility
	     * with the v2 aws-sdk.
	     */
	    Sha256.prototype.digestSync = function () {
	        if (this.error) {
	            throw this.error;
	        }
	        if (this.outer) {
	            if (!this.outer.finished) {
	                this.outer.update(this.hash.digest());
	            }
	            return this.outer.digest();
	        }
	        return this.hash.digest();
	    };
	    /* The underlying digest method here is synchronous.
	     * To keep the same interface with the other hash functions
	     * the default is to expose this as an async method.
	     * However, it can sometimes be useful to have a sync method.
	     */
	    Sha256.prototype.digest = function () {
	        return tslib_1.__awaiter(this, void 0, void 0, function () {
	            return tslib_1.__generator(this, function (_a) {
	                return [2 /*return*/, this.digestSync()];
	            });
	        });
	    };
	    return Sha256;
	}());
	jsSha256.Sha256 = Sha256;
	function bufferFromSecret(secret) {
	    var input = (0, util_1.convertToBuffer)(secret);
	    if (input.byteLength > constants_1.BLOCK_SIZE) {
	        var bufferHash = new RawSha256_1.RawSha256();
	        bufferHash.update(input);
	        input = bufferHash.digest();
	    }
	    var buffer = new Uint8Array(constants_1.BLOCK_SIZE);
	    buffer.set(input);
	    return buffer;
	}
	
	return jsSha256;
}

(function (exports) {
	Object.defineProperty(exports, "__esModule", { value: true });
	var tslib_1 = require$$0$3;
	tslib_1.__exportStar(requireJsSha256(), exports);
	
} (build$2));

var build$1 = {};

/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics$1 = function(d, b) {
    extendStatics$1 = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics$1(d, b);
};

function __extends$1(d, b) {
    extendStatics$1(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign$1 = function() {
    __assign$1 = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    };
    return __assign$1.apply(this, arguments);
};

function __rest$1(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
}

function __decorate$1(decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
}

function __param$1(paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
}

function __metadata$1(metadataKey, metadataValue) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}

function __awaiter$1(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator$1(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

function __createBinding$1(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}

function __exportStar$1(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) exports[p] = m[p];
}

function __values$1(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

function __read$1(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spread$1() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read$1(arguments[i]));
    return ar;
}

function __spreadArrays$1() {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
}
function __await$1(v) {
    return this instanceof __await$1 ? (this.v = v, this) : new __await$1(v);
}

function __asyncGenerator$1(thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await$1 ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
}

function __asyncDelegator$1(o) {
    var i, p;
    return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
    function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await$1(o[n](v)), done: n === "return" } : f ? f(v) : v; } : f; }
}

function __asyncValues$1(o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values$1 === "function" ? __values$1(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
}

function __makeTemplateObject$1(cooked, raw) {
    if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
    return cooked;
}
function __importStar$1(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result.default = mod;
    return result;
}

function __importDefault$1(mod) {
    return (mod && mod.__esModule) ? mod : { default: mod };
}

function __classPrivateFieldGet$1(receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
}

function __classPrivateFieldSet$1(receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
}

var tslib_es6$1 = /*#__PURE__*/Object.freeze({
	__proto__: null,
	__extends: __extends$1,
	get __assign () { return __assign$1; },
	__rest: __rest$1,
	__decorate: __decorate$1,
	__param: __param$1,
	__metadata: __metadata$1,
	__awaiter: __awaiter$1,
	__generator: __generator$1,
	__createBinding: __createBinding$1,
	__exportStar: __exportStar$1,
	__values: __values$1,
	__read: __read$1,
	__spread: __spread$1,
	__spreadArrays: __spreadArrays$1,
	__await: __await$1,
	__asyncGenerator: __asyncGenerator$1,
	__asyncDelegator: __asyncDelegator$1,
	__asyncValues: __asyncValues$1,
	__makeTemplateObject: __makeTemplateObject$1,
	__importStar: __importStar$1,
	__importDefault: __importDefault$1,
	__classPrivateFieldGet: __classPrivateFieldGet$1,
	__classPrivateFieldSet: __classPrivateFieldSet$1
});

var require$$0$1 = /*@__PURE__*/getAugmentedNamespace(tslib_es6$1);

var supportsWebCrypto = {};

var hasRequiredSupportsWebCrypto;

function requireSupportsWebCrypto () {
	if (hasRequiredSupportsWebCrypto) return supportsWebCrypto;
	hasRequiredSupportsWebCrypto = 1;
	Object.defineProperty(supportsWebCrypto, "__esModule", { value: true });
	supportsWebCrypto.supportsZeroByteGCM = supportsWebCrypto.supportsSubtleCrypto = supportsWebCrypto.supportsSecureRandom = supportsWebCrypto.supportsWebCrypto = void 0;
	var tslib_1 = require$$0$1;
	var subtleCryptoMethods = [
	    "decrypt",
	    "digest",
	    "encrypt",
	    "exportKey",
	    "generateKey",
	    "importKey",
	    "sign",
	    "verify"
	];
	function supportsWebCrypto$1(window) {
	    if (supportsSecureRandom(window) &&
	        typeof window.crypto.subtle === "object") {
	        var subtle = window.crypto.subtle;
	        return supportsSubtleCrypto(subtle);
	    }
	    return false;
	}
	supportsWebCrypto.supportsWebCrypto = supportsWebCrypto$1;
	function supportsSecureRandom(window) {
	    if (typeof window === "object" && typeof window.crypto === "object") {
	        var getRandomValues = window.crypto.getRandomValues;
	        return typeof getRandomValues === "function";
	    }
	    return false;
	}
	supportsWebCrypto.supportsSecureRandom = supportsSecureRandom;
	function supportsSubtleCrypto(subtle) {
	    return (subtle &&
	        subtleCryptoMethods.every(function (methodName) { return typeof subtle[methodName] === "function"; }));
	}
	supportsWebCrypto.supportsSubtleCrypto = supportsSubtleCrypto;
	function supportsZeroByteGCM(subtle) {
	    return tslib_1.__awaiter(this, void 0, void 0, function () {
	        var key, zeroByteAuthTag;
	        return tslib_1.__generator(this, function (_b) {
	            switch (_b.label) {
	                case 0:
	                    if (!supportsSubtleCrypto(subtle))
	                        return [2 /*return*/, false];
	                    _b.label = 1;
	                case 1:
	                    _b.trys.push([1, 4, , 5]);
	                    return [4 /*yield*/, subtle.generateKey({ name: "AES-GCM", length: 128 }, false, ["encrypt"])];
	                case 2:
	                    key = _b.sent();
	                    return [4 /*yield*/, subtle.encrypt({
	                            name: "AES-GCM",
	                            iv: new Uint8Array(Array(12)),
	                            additionalData: new Uint8Array(Array(16)),
	                            tagLength: 128
	                        }, key, new Uint8Array(0))];
	                case 3:
	                    zeroByteAuthTag = _b.sent();
	                    return [2 /*return*/, zeroByteAuthTag.byteLength === 16];
	                case 4:
	                    _b.sent();
	                    return [2 /*return*/, false];
	                case 5: return [2 /*return*/];
	            }
	        });
	    });
	}
	supportsWebCrypto.supportsZeroByteGCM = supportsZeroByteGCM;
	
	return supportsWebCrypto;
}

(function (exports) {
	Object.defineProperty(exports, "__esModule", { value: true });
	var tslib_1 = require$$0$1;
	tslib_1.__exportStar(requireSupportsWebCrypto(), exports);
	
} (build$1));

var build = {};

/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

var __assign = function() {
    __assign = Object.assign || function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};

function __rest(s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
}

function __decorate(decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
}

function __param(paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
}

function __metadata(metadataKey, metadataValue) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(metadataKey, metadataValue);
}

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

function __generator(thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
}

function __createBinding(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}

function __exportStar(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) exports[p] = m[p];
}

function __values(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}

function __read(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spread() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read(arguments[i]));
    return ar;
}

function __spreadArrays() {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
}
function __await(v) {
    return this instanceof __await ? (this.v = v, this) : new __await(v);
}

function __asyncGenerator(thisArg, _arguments, generator) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var g = generator.apply(thisArg, _arguments || []), i, q = [];
    return i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i;
    function verb(n) { if (g[n]) i[n] = function (v) { return new Promise(function (a, b) { q.push([n, v, a, b]) > 1 || resume(n, v); }); }; }
    function resume(n, v) { try { step(g[n](v)); } catch (e) { settle(q[0][3], e); } }
    function step(r) { r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r); }
    function fulfill(value) { resume("next", value); }
    function reject(value) { resume("throw", value); }
    function settle(f, v) { if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]); }
}

function __asyncDelegator(o) {
    var i, p;
    return i = {}, verb("next"), verb("throw", function (e) { throw e; }), verb("return"), i[Symbol.iterator] = function () { return this; }, i;
    function verb(n, f) { i[n] = o[n] ? function (v) { return (p = !p) ? { value: __await(o[n](v)), done: n === "return" } : f ? f(v) : v; } : f; }
}

function __asyncValues(o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
}

function __makeTemplateObject(cooked, raw) {
    if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
    return cooked;
}
function __importStar(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result.default = mod;
    return result;
}

function __importDefault(mod) {
    return (mod && mod.__esModule) ? mod : { default: mod };
}

function __classPrivateFieldGet(receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
}

function __classPrivateFieldSet(receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
}

var tslib_es6 = /*#__PURE__*/Object.freeze({
	__proto__: null,
	__extends: __extends,
	get __assign () { return __assign; },
	__rest: __rest,
	__decorate: __decorate,
	__param: __param,
	__metadata: __metadata,
	__awaiter: __awaiter,
	__generator: __generator,
	__createBinding: __createBinding,
	__exportStar: __exportStar,
	__values: __values,
	__read: __read,
	__spread: __spread,
	__spreadArrays: __spreadArrays,
	__await: __await,
	__asyncGenerator: __asyncGenerator,
	__asyncDelegator: __asyncDelegator,
	__asyncValues: __asyncValues,
	__makeTemplateObject: __makeTemplateObject,
	__importStar: __importStar,
	__importDefault: __importDefault,
	__classPrivateFieldGet: __classPrivateFieldGet,
	__classPrivateFieldSet: __classPrivateFieldSet
});

var require$$0 = /*@__PURE__*/getAugmentedNamespace(tslib_es6);

var CryptoOperation = {};

var hasRequiredCryptoOperation;

function requireCryptoOperation () {
	if (hasRequiredCryptoOperation) return CryptoOperation;
	hasRequiredCryptoOperation = 1;
	Object.defineProperty(CryptoOperation, "__esModule", { value: true });
	
	return CryptoOperation;
}

var Key = {};

var hasRequiredKey;

function requireKey () {
	if (hasRequiredKey) return Key;
	hasRequiredKey = 1;
	Object.defineProperty(Key, "__esModule", { value: true });
	
	return Key;
}

var KeyOperation = {};

var hasRequiredKeyOperation;

function requireKeyOperation () {
	if (hasRequiredKeyOperation) return KeyOperation;
	hasRequiredKeyOperation = 1;
	Object.defineProperty(KeyOperation, "__esModule", { value: true });
	
	return KeyOperation;
}

var MsSubtleCrypto = {};

var hasRequiredMsSubtleCrypto;

function requireMsSubtleCrypto () {
	if (hasRequiredMsSubtleCrypto) return MsSubtleCrypto;
	hasRequiredMsSubtleCrypto = 1;
	Object.defineProperty(MsSubtleCrypto, "__esModule", { value: true });
	
	return MsSubtleCrypto;
}

var MsWindow = {};

var hasRequiredMsWindow;

function requireMsWindow () {
	if (hasRequiredMsWindow) return MsWindow;
	hasRequiredMsWindow = 1;
	Object.defineProperty(MsWindow, "__esModule", { value: true });
	MsWindow.isMsWindow = void 0;
	var msSubtleCryptoMethods = [
	    "decrypt",
	    "digest",
	    "encrypt",
	    "exportKey",
	    "generateKey",
	    "importKey",
	    "sign",
	    "verify"
	];
	function quacksLikeAnMsWindow(window) {
	    return "MSInputMethodContext" in window && "msCrypto" in window;
	}
	/**
	 * Determines if the provided window is (or is like) the window object one would
	 * expect to encounter in Internet Explorer 11.
	 */
	function isMsWindow(window) {
	    if (quacksLikeAnMsWindow(window) && window.msCrypto.subtle !== undefined) {
	        var _a = window.msCrypto, getRandomValues = _a.getRandomValues, subtle_1 = _a.subtle;
	        return msSubtleCryptoMethods
	            .map(function (methodName) { return subtle_1[methodName]; })
	            .concat(getRandomValues)
	            .every(function (method) { return typeof method === "function"; });
	    }
	    return false;
	}
	MsWindow.isMsWindow = isMsWindow;
	
	return MsWindow;
}

(function (exports) {
	Object.defineProperty(exports, "__esModule", { value: true });
	var tslib_1 = require$$0;
	tslib_1.__exportStar(requireCryptoOperation(), exports);
	tslib_1.__exportStar(requireKey(), exports);
	tslib_1.__exportStar(requireKeyOperation(), exports);
	tslib_1.__exportStar(requireMsSubtleCrypto(), exports);
	tslib_1.__exportStar(requireMsWindow(), exports);
	
} (build));

Object.defineProperty(crossPlatformSha256, "__esModule", { value: true });
crossPlatformSha256.Sha256 = void 0;
var ie11Sha256_1 = ie11Sha256;
var webCryptoSha256_1 = webCryptoSha256;
var sha256_js_1 = build$2;
var supports_web_crypto_1 = build$1;
var ie11_detection_1 = build;
var util_locate_window_1 = require$$5;
var Sha256$1 = /** @class */ (function () {
    function Sha256(secret) {
        if ((0, supports_web_crypto_1.supportsWebCrypto)((0, util_locate_window_1.locateWindow)())) {
            this.hash = new webCryptoSha256_1.Sha256(secret);
        }
        else if ((0, ie11_detection_1.isMsWindow)((0, util_locate_window_1.locateWindow)())) {
            this.hash = new ie11Sha256_1.Sha256(secret);
        }
        else {
            this.hash = new sha256_js_1.Sha256(secret);
        }
    }
    Sha256.prototype.update = function (data, encoding) {
        this.hash.update(data, encoding);
    };
    Sha256.prototype.digest = function () {
        return this.hash.digest();
    };
    return Sha256;
}());
crossPlatformSha256.Sha256 = Sha256$1;

(function (exports) {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.WebCryptoSha256 = exports.Ie11Sha256 = void 0;
	var tslib_1 = require$$0$3;
	(0, tslib_1.__exportStar)(crossPlatformSha256, exports);
	var ie11Sha256_1 = ie11Sha256;
	Object.defineProperty(exports, "Ie11Sha256", { enumerable: true, get: function () { return ie11Sha256_1.Sha256; } });
	var webCryptoSha256_1 = webCryptoSha256;
	Object.defineProperty(exports, "WebCryptoSha256", { enumerable: true, get: function () { return webCryptoSha256_1.Sha256; } });
	
} (build$4));

var require$$16 = /*@__PURE__*/getAugmentedNamespace(distEs$6);

function buildQueryString(query) {
    const parts = [];
    for (let key of Object.keys(query).sort()) {
        const value = query[key];
        key = escapeUri(key);
        if (Array.isArray(value)) {
            for (let i = 0, iLen = value.length; i < iLen; i++) {
                parts.push(`${key}=${escapeUri(value[i])}`);
            }
        }
        else {
            let qsEntry = key;
            if (value || typeof value === "string") {
                qsEntry += `=${escapeUri(value)}`;
            }
            parts.push(qsEntry);
        }
    }
    return parts.join("&");
}

function formatUrl$1(request) {
    const { port, query } = request;
    let { protocol, path, hostname } = request;
    if (protocol && protocol.slice(-1) !== ":") {
        protocol += ":";
    }
    if (port) {
        hostname += `:${port}`;
    }
    if (path && path.charAt(0) !== "/") {
        path = `/${path}`;
    }
    let queryString = query ? buildQueryString(query) : "";
    if (queryString && queryString[0] !== "?") {
        queryString = `?${queryString}`;
    }
    return `${protocol}//${hostname}${path}${queryString}`;
}

var distEs = /*#__PURE__*/Object.freeze({
	__proto__: null,
	formatUrl: formatUrl$1
});

var require$$18 = /*@__PURE__*/getAugmentedNamespace(distEs);

const { urlToHttpOptions } = require$$0__default$1["default"];

const {
  ddbDocClient,
  cognitoClient,
  sesV2Client,
  snsClient,
  s3Client,
  ebClient,
  athenaClient,
  cwClient
} = aws$1;

const {
  GetCommand,
  UpdateCommand,
  PutCommand,
  QueryCommand,
  DeleteCommand,
  ScanCommand,
} = require$$1__default["default"];
const {
  GetObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,

  PutObjectCommand,
  CopyObjectCommand,
  HeadObjectCommand,
  SelectObjectContentCommand,
  WriteGetObjectResponseCommand,
} = require$$2__default["default"];
const {
  AdminAddUserToGroupCommand,
  AdminUpdateUserAttributesCommand,
  AddCustomAttributesCommand,
} = require$$5__default["default"];

const {
  CreateConfigurationSetCommand,
  SendEmailCommand,
} = require$$6__default["default"];
const { PublishCommand } = require$$7__default["default"];

const {
  GetQueryExecutionCommand,
  GetQueryResultsCommand,
  StartQueryExecutionCommand,
} = require$$3__default["default"];

const { ListMetricsCommand, GetMetricDataCommand, GetMetricWidgetImageCommand } = require$$9__default["default"];

const { uCfirst } = libUtils$1;
const { PutEventsCommand } = require$$8__default["default"];

const { HttpRequest } = require$$11;
const { SignatureV4 } = require$$12;
const { NodeHttpHandler } = require$$13__default["default"];
const { Sha256 } = build$4;

const { S3RequestPresigner } = require$$15__default["default"];
const { parseUrl } = require$$16;
const { formatUrl } = require$$18;

const {
  CognitoIdentityClient,
  GetIdCommand,
  GetCredentialsForIdentityCommand,
} = require$$19__default["default"];

async function getCredentials({
  idToken,
  userPoolRegion,
  userPoolId,
  userIdPool,
}) {
  //const _currentSession = await Auth.currentSession();
  //const token = currentSession.getIdToken().payload;
  //const userIdPool = localStorage.getItem("LastSessionIdentityPool");
  const provider =
    "cognito-idp." + userPoolRegion + ".amazonaws.com/" + userPoolId;
  //const provider = token["iss"].replace("https://", "");
  let identityParams = {
    IdentityPoolId: userIdPool,
    Logins: {},
  };

  identityParams.Logins[provider] = idToken;
  const cognitoClient = new CognitoIdentityClient({
    region: userIdPool.split(":")[0],
  });
  //console.log(identityParams);
  const cognitoIdentity = await cognitoClient.send(
    new GetIdCommand(identityParams)
  );
  //console.log("COGNITO IDENTITY ", cognitoIdentity);

  let credentialParams = {
    IdentityId: cognitoIdentity.IdentityId,
    Logins: {},
  };

  credentialParams.Logins[provider] = idToken;
  //console.log(credentialParams);
  const cognitoIdentityCredentials = await cognitoClient.send(
    new GetCredentialsForIdentityCommand(credentialParams)
  );
  //console.log("COGNITO IDENTITY CREDS ", cognitoIdentityCredentials);

  const clientCredentials = {
    identityId: cognitoIdentity.IdentityId,
    accessKeyId: cognitoIdentityCredentials.Credentials.AccessKeyId,
    secretAccessKey: cognitoIdentityCredentials.Credentials.SecretKey,
    sessionToken: cognitoIdentityCredentials.Credentials.SessionToken,
    expiration: cognitoIdentityCredentials.Credentials.Expiration,
    authenticated: true,
  };

  return Promise.resolve(clientCredentials);
}
async function awsGetSignedUrl({
  bucket,
  key,
  credentials,
  region,
  expiresIn,
}) {
  const s3ObjectUrl = parseUrl(
    `https://${bucket}.s3.${region}.amazonaws.com/${key}`
  );
  const presigner = new S3RequestPresigner({
    expiresIn,
    credentials,
    region,
    //sha256: Hash.bind(null, "sha256"), // In Node.js
    sha256: Sha256, // In browsers
  });
  // Create a GET request from S3 url.
  const url = await presigner.presign(new HttpRequest(s3ObjectUrl));
  //return presigner.presign(new HttpRequest(s3ObjectUrl));
  return formatUrl(url);
}
async function awsSignedRequest({
  request_api,
  region,
  credentials,
  post_body,
  service,
}) {
  let options = urlToHttpOptions(new URL(request_api));

  //const uri = new URL(request_api);
  //  console.log("URI ",uri);
  /*
  URL {
    href: 'https://localhost:54322/',
    origin: 'https://localhost:54322',
    protocol: 'https:',
    username: '',
    password: '',
    host: 'localhost:54322',
    hostname: 'localhost',
    port: '54322',
    pathname: '/',
    search: '',
    searchParams: URLSearchParams {},
    hash: ''
  }
*/
  /*
  const options={
    hostname: uri.hostname,
    port: uri.port||443,
    headers: { host: uri.host||uri.hostname, "Content-Type": "application/json" },
    method: "POST",
    path: uri.pathname,
    body: JSON.stringify(post_body),
  };
  */
  options.body = JSON.stringify(post_body);
  options.headers = {
    host: options.host || options.hostname,
    "Content-Type": "application/json",
  };
  options.port = options.port || 443;
  options.method = "POST";
  /*  
   httpRequest.headers.host = uri.host;
  httpRequest.headers["Content-Type"] = "application/json";
  httpRequest.method = "POST";
  httpRequest.body = JSON.stringify(post_body);
*/

  console.log("OPTIONS ", options);
  const request = new HttpRequest(options);

  //console.log(request);

  const signer = new SignatureV4({
    credentials: credentials,
    region: region,
    service: service,
    sha256: Sha256,
  });

  console.log(signer);
  const signedRequest = await signer.sign(request);

  const client = new NodeHttpHandler();
  //const { response } = await client.handle(signedRequest);
  //return client.handle(signedRequest);

  const { response } = await client.handle(signedRequest);
  //console.log("STATUS ",response.statusCode );
  //console.log("RESPONSE", response);
  console.log(
    "RESPONSE",
    response.statusCode + " " + response.body.statusMessage
  );

  //console.log(process.env);
  let responseBody = "";
  /*
  return new Promise(
    (resolve) => {
      response.body.on("data", (chunk) => {
        responseBody += chunk;
      });
      response.body.on("end", () => {
        console.log("Response body: " + responseBody);
        client.destroy();
        resolve(responseBody);
      });
    },
    (error) => {
      console.log("Error: " + error);
      client.destroy();
      reject(error);
    }
  );
  */
  try {
    // const res = await nodeHttpHandler.handle(signedHttpRequest);
    const body = await new Promise((resolve, reject) => {
      //let body = "";
      response.body.on("data", (chunk) => {
        responseBody += chunk;
      });
      response.body.on("end", () => {
        client.destroy();
        resolve(responseBody);
      });
      response.body.on("error", (err) => {
        client.destroy();
        reject(err);
      });
    });
    //console.log(body);
  } catch (err) {
    console.error("Error:");
    console.error(err);
    client.destroy();
  }

  //console.log("RES ", responseBody);
  //client.destroy();
  //return responseBody;
}

function ebPutEvents$1(params) {
  return ebClient.send(new PutEventsCommand(params));
}

function getItem$1(params) {
  return ddbDocClient.send(new GetCommand(params));
}
function scanItems$1(params) {
  return ddbDocClient.send(new ScanCommand(params));
}
function updateItem$1(params) {
  /*
    Convert the attribute JavaScript object you are updating to the required
    Amazon  DynamoDB record. The format of values specifies the datatype. The
    following list demonstrates different datatype formatting requirements:
    String: "String",
    NumAttribute: 1,
    BoolAttribute: true,
    ListAttribute: [1, "two", false],
    MapAttribute: { foo: "bar" },
    NullAttribute: null
     */
  /* 
  // Set the parameters
  const params = {
    TableName: "TABLE_NAME",
   
    Key: {
      primaryKey: "VALUE_1", // For example, 'Season': 2.
      sortKey: "VALUE_2", // For example,  'Episode': 1; (only required if table has sort key).
    },
    // Define expressions for the new or updated attributes
    UpdateExpression: "set ATTRIBUTE_NAME_1 = :t, ATTRIBUTE_NAME_2 = :s", // For example, "'set Title = :t, Subtitle = :s'"
    ExpressionAttributeValues: {
      ":t": "NEW_ATTRIBUTE_VALUE_1", // For example ':t' : 'NEW_TITLE'
      ":s": "NEW_ATTRIBUTE_VALUE_2", // For example ':s' : 'NEW_SUBTITLE'
    },
  };
  */
  return ddbDocClient.send(new UpdateCommand(params));
}

function cognitoAddUserToGroup(payload) {
  const params = {
    GroupName: payload.group,
    UserPoolId: payload.pool_id,
    Username: payload.user_id,
  };
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  /*
  console.log(
    cognitoClient.config.credentials().then((res) => {
      console.log("RES ", res);
    })
  );
  */
  return cognitoClient.send(new AdminAddUserToGroupCommand(params));
}
function cognitoUpdateAttributes(payload) {
  const params = {
    UserAttributes: payload.attributes,
    UserPoolId: payload.pool_id,
    Username: payload.user_id,
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return cognitoClient.send(new AdminUpdateUserAttributesCommand(params));
}

function sendEmail(data) {
  ({
    Destination: {
      /* required */
      CcAddresses: [
        /* more items */
      ],
      ToAddresses: data.toEmails,
    },
    Message: {
      /* required */
      Body: {
        /* required */
        /*
      Html: {
        Charset: "UTF-8",
        Data: "HTML_FORMAT_BODY",
      },
      Text: {
        Charset: "UTF-8",
        Data: "TEXT_FORMAT_BODY",
      },
      */
      },
      Subject: {
        Charset: "UTF-8",
        Data: data.subject,
      },
    },
    Source: data.fromEmails, // SENDER_ADDRESS
    ReplyToAddresses: [
      /* more items */
    ],
  });

  let params = {
    FromEmailAddress: data.fromEmails,
    Destination: {
      ToAddresses: data.toEmails,
    },
    Content: {
      Simple: {
        Subject: {
          Data: data.subject,
          Charset: "UTF-8",
        },
        Body: {},
      },
    },
  };

  if (data.hasOwnProperty("htmlBody")) {
    /*
    params.Message.Body.Html = data.htmlBody;
    params.Message.Body.Charset = "UTF-8";
    */
    params.Content.Simple.Body.Html = { Data: data.htmlBody, Charset: "UTF-8" };
  }
  if (data.hasOwnProperty("textBody")) {
    //params.Message.Body.Text = data.textBody;
    //params.Message.Body.Charset = "UTF-8";

    params.Content.Simple.Body.Text = { Data: data.textBody, Charset: "UTF-8" };
  }
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return sesV2Client.send(new SendEmailCommand(params));
}

function sendSMS(phoneNumber, message, options) {
  try {
    if (message.length > 160) {
      return Promise.reject("MESSAGE_TOO_LONG");
    }
    let params = { PhoneNumber: phoneNumber, Message: message };
    console.log(options, typeof options);
    if (typeof options !== "undefined" && typeof options !== null) {
      params.MessageAttributes = {};
      if (typeof options.senderID !== "undefined") {
        params.MessageAttributes["AWS.SNS.SMS.SenderID"] = {
          DataType: "String",
          StringValue: options.senderID,
        };
      }
      if (typeof options.smsType !== "undefined") {
        //Promotional/Transactional
        options.smsType = uCfirst(options.smsType);
        if (["Promotional", "Transactional"].indexOf(options.smsType) === -1) {
          return Promise.reject("NOT_VALID_SMS_TYPE");
        }
        params.MessageAttributes["AWS.SNS.SMS.SMSType"] = {
          DataType: "String",
          StringValue: options.smsType,
        };
      }
    }

    if (
      (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
      process.env.hasOwnProperty("JEST_WORKER_ID")
    ) {
      console.log("PARAMS", params);
    }

    return snsClient.send(new PublishCommand(params));
    //return SNS.publish(params).promise();
    //await saveSMS(data.MessageId,networkID,requestID,params,result);
    //console.log('SMS DELIVERY',data);
  } catch (e) {
    return Promise.reject(e);
  }
}
async function s3ObjectInfo$1(params) {
  try {
    //console.log("PARAMS ", params);
    const info = await s3Client.send(new HeadObjectCommand(params));
    //console.log("INFO ", info);
    return Promise.resolve(info);
  } catch (err) {
    // err.code is now err.name
    // console.log("Error CODE ", typeof err, Object.keys(err));
    // console.log("Error NAME ", err.name);
    // console.log("Error FAULT ", err.$fault);
    // console.log("Error META ", err.$metadata);
    // console.log("Error", err);
    if (err.hasOwnProperty("name") && err.name === "NotFound") {
      return Promise.resolve(false);
    } else {
      return Promise.reject(err);
    }
  }
}

function s3GetObjectStream(params) {
  return s3Client.send(new GetObjectCommand(params));
}

const streamToString = (stream) =>
  new Promise((resolve, reject) => {
    const chunks = [];
    stream.on("data", (chunk) => chunks.push(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });

async function s3GetObject$1(params) {
  try {
    // Get the object} from the Amazon S3 bucket. It is returned as a ReadableStream.
    //s3://prifina-core-352681697435/integrations/fitbit/9G7RZB.json

    const s3Data = await s3Client.send(new GetObjectCommand(params));
    //console.log("S3", s3Data);
    let bodyContents = "";
    if (s3Data && s3Data.hasOwnProperty("Body")) {
      bodyContents = await streamToString(s3Data.Body);
      //console.log(bodyContents);
    }

    return Promise.resolve({ Body: bodyContents });
  } catch (err) {
    console.log("Error", err);
    return Promise.reject(err);
  }
}

function s3PutObject$1(params) {
  return s3Client.send(new PutObjectCommand(params));
}

function s3DeleteObject$1(params) {
  return s3Client.send(new DeleteObjectCommand(params));
}
function s3DeleteObjects$1(params) {
  return s3Client.send(new DeleteObjectsCommand(params));
}
function s3CopyObject$1(params) {
  return s3Client.send(new CopyObjectCommand(params));
}

function s3SelectObject$1(params) {
  return s3Client.send(new SelectObjectContentCommand(params));
}
function s3WriteGetObjectResponse$1(params) {
  return s3Client.send(new WriteGetObjectResponseCommand(params));
}
function athenaGetQueryExecution$1(params) {
  return athenaClient.send(new GetQueryExecutionCommand(params));
}

function athenaGetQueryResults$1(params) {
  return athenaClient.send(new GetQueryResultsCommand(params));
}

function athenaStartQueryExecution$1(params) {
  return athenaClient.send(new StartQueryExecutionCommand(params));
}


function cloudwatchListMetrics(params) {
  return cwClient.send(new ListMetricsCommand(params));
}

function cloudwatchGetMetricsData(params) {
  return cwClient.send(new GetMetricDataCommand(params));
}

function cloudwatchGetMetricImage(params) {
  return cwClient.send(new GetMetricWidgetImageCommand(params));
}


/*
addPrifinaUser({ uuid: "UUID", user_id: "TEST", name: "TRO" }).then((res) => {
  console.log("TEST ", res);
});
*/
/*
cognitoUpdateAttributes({
  attributes: [{ Name: "custom:prifina", Value: "Prifina-id" }],
  pool_id: "us-east-1_Q983m5wFm",
  user_id: "testing",
}).then((res) => {
  console.log("TEST ", res);
});
*/
/*
const msg = {
  fromEmails: '"Prifina"<no-reply@' + process.env.PRIFINA_EMAIL + ">",
  subject: "Your email verification code",
  textBody: "Prifina Email",
  toEmails: ["tro9999@gmail.com"],
};

sendEmail(msg).then((res) => {
  console.log("TEST ", res);
});
*/
/*
sendSMS("+358407077102", "testing sms", {
  senderID: "Prifina",
  smsType: "Transactional",
}).then((res) => {
  console.log("TEST ", res);
});
*/
//s3://prifina-app-data-dev/integrations/5XMCZ6.json
//s3://prifina-core-352681697435-eu-west-1/integrations/fitbit/9G7RZB.json
/*
s3ObjectInfo({
  Bucket: "prifina-core-352681697435-eu-west-1",
  Key: "integrations/fitbit/9G7RZB.json",
}).then((res) => {
  console.log("TEST ", res);
});
*/
/*
s3GetObject({
  Bucket: "prifina-core-352681697435-eu-west-1",
  Key: "integrations/fitbit/9G7RZB.json",
}).then((res) => {
  console.log("TEST ", res);
  console.log("TEST ", typeof res);
  console.log("TEST ", JSON.parse(res.Body.toString()));
});
*/
/*
s3PutObject({
  Bucket: "prifina-app-data-dev",
  Key: "integrations/xxx.json",
  Body: JSON.stringify({ test: "OK" }),
  ContentType: "application/json",
}).then((res) => {
  console.log("TEST ", res);
});
*/
var awsUtils$1 = {
  getItem: getItem$1,
  updateItem: updateItem$1,
  scanItems: scanItems$1,
  sendEmail,
  sendSMS,
  cognitoUpdateAttributes,
  cognitoAddUserToGroup,
  s3ObjectInfo: s3ObjectInfo$1,
  s3GetObject: s3GetObject$1,
  s3PutObject: s3PutObject$1,
  s3DeleteObject: s3DeleteObject$1,
  s3DeleteObjects: s3DeleteObjects$1,
  s3CopyObject: s3CopyObject$1,
  s3SelectObject: s3SelectObject$1,
  s3WriteGetObjectResponse: s3WriteGetObjectResponse$1,
  ebPutEvents: ebPutEvents$1,
  awsSignedRequest,
  athenaGetQueryExecution: athenaGetQueryExecution$1,
  athenaGetQueryResults: athenaGetQueryResults$1,
  athenaStartQueryExecution: athenaStartQueryExecution$1,
  getCredentials,
  awsGetSignedUrl,
  s3GetObjectStream,
  cloudwatchListMetrics,
  cloudwatchGetMetricsData,
  cloudwatchGetMetricImage

};

const {
  getItem,
  updateItem,
  scanItems,
  s3ObjectInfo,
  s3GetObject,
  s3PutObject,
  s3DeleteObject,
  s3DeleteObjects,
  s3CopyObject,
  s3SelectObject,
  ebPutEvents,
  athenaGetQueryExecution,
  athenaGetQueryResults,
  athenaStartQueryExecution,
  s3WriteGetObjectResponse,
} = awsUtils$1;

const { createNonce } = libUtils$1;

function addPrifinaUser(data) {
  const createdAt = new Date().toISOString();
  /*
  const installedApps = JSON.parse(
    '["Settings","DataConsole","AppMarket","SmartSearch","DisplayApp","ProfileCards","DevConsole"]'
  );
  */
  const installedApps = JSON.parse(
    '["Settings","DataConsole","AppMarket","DisplayApp","DevConsole"]'
  );
  const params = {
    TableName: "PrifinaUser",
    Key: { id: data.uuid },
    UpdateExpression:
      "set createdAt=:createdAt,installedApps=:installedApps,cognito_id=:prifina,appProfile=:profile ",
    ExpressionAttributeValues: {
      ":createdAt": createdAt,
      ":installedApps": installedApps,
      ":prifina": data.user_id,
      ":profile": { name: data.name, initials: "" },
    },
    ReturnValues: "ALL_NEW",
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
}

function addVerification(data) {
  const createdAt = new Date().toISOString();
  // expires after 1h
  // data.expiration_date=Math.ceil((Date.now() + ( 1 * 60 * 60 * 1000)) / 1000)
  // expires after 5min
  //expires = Math.ceil((Date.now() + 5 * 60 * 1000) / 1000);
  const expires = Math.ceil((Date.now() + 1 * 60 * 60 * 1000) / 1000);

  const params = {
    TableName: "Verifications",
    Key: { user_code: data.user_code },
    UpdateExpression: "set createdAt=:createdAt,expire=:expires",
    ExpressionAttributeValues: { ":createdAt": createdAt, ":expires": expires },
    ReturnValues: "ALL_NEW",
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
}
function updateNotificationQueue(notificationKey, item, expire = null) {
  // 30mins....
  const ttl = 30;
  const d = Math.ceil(new Date().getTime() / 1000);
  if (expire === null) {
    expire = d + 60 * ttl;
  }
  // expect expire is mins....
  if (expire < d) {
    expire = d + 60 * expire;
  }

  //Math.ceil((new Date().getTime()+(60*60*24*14*1000))/1000),
  const params = {
    TableName: "NotificationQueue",
    Key: { dataSource: notificationKey },
    UpdateExpression: "SET #notification = :notification,#expires=:expires",
    ExpressionAttributeNames: {
      "#expires": "expire",
      "#notification": "notification",
    },
    ExpressionAttributeValues: {
      ":notification": item,
      ":expires": expire,
    },
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
}
function getDataSourceUsers(dataSource = null) {
  let params = {
    TableName: "DataSourceStatus",

    ProjectionExpression: "#id",
    //FilterExpression: "#dataSource = :dataSource",
    ExpressionAttributeNames: {
      "#id": "id",
    },
    ExpressionAttributeValues: {},
  };
  if (dataSource) {
    params.FilterExpression = "#dataSource = :dataSource";
    params.ExpressionAttributeNames["#dataSource"] = "dataSource";
    params.ExpressionAttributeValues[":dataSource"] = dataSource;
  }
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return scanItems(params);
}

function updateUserDataSourceStatus(
  prifinaID,
  source,
  sourceUserID = "",
  attrName,
  attrValue
) {
  const d = new Date().toISOString();
  let ExpressionAttributeValues = {
    ":attrValue": attrValue,
    ":updatedAt": d,
  };
  let ExpressionAttributeNames = {
    "#attrName": attrName,
    "#updatedAt": "updatedAt",
  };
  let UpdateExpression = "SET  #attrName= :attrValue,#updatedAt=:updatedAt";
  if (sourceUserID !== "") {
    ExpressionAttributeValues[":sourceUserID"] = sourceUserID;
    ExpressionAttributeNames["#sourceUserID"] = "sourceUserID";
    UpdateExpression += ",#sourceUserID= :sourceUserID";
  }
  const params = {
    TableName: "DataSourceStatus",
    Key: { id: prifinaID, dataSource: source },
    UpdateExpression: UpdateExpression,
    ExpressionAttributeValues: ExpressionAttributeValues,
    ExpressionAttributeNames: ExpressionAttributeNames,
    ReturnValues: "ALL_NEW",
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
}

function updateUserDataSource(prifinaID, source, status = 1) {
  return new Promise(function (resolve, reject) {
    getItem({
      TableName: "PrifinaUser",
      Key: { id: prifinaID },
    }).then((res, err) => {
      if (err) {
        reject(err);
      } else {
        const d = new Date().toISOString();
        let params = {};
        if (!res.Item.hasOwnProperty("dataSources")) {
          params = {
            TableName: "PrifinaUser",
            Key: { id: prifinaID },
            UpdateExpression:
              "SET #dataSources=:dataSource,#updatedAt=:updatedAt",
            ConditionExpression: "attribute_not_exists(dataSources)",
            ExpressionAttributeNames: {
              "#dataSources": "dataSources",
              "#updatedAt": "modified",
            },
            ExpressionAttributeValues: {
              ":dataSource": { [source]: { status: status } },
              ":updatedAt": d,
            },
          };
        } else {
          params = {
            TableName: "PrifinaUser",
            Key: { id: prifinaID },
            UpdateExpression:
              "SET dataSources.#source = :v,#updatedAt=:updatedAt",
            ExpressionAttributeNames: {
              "#source": source,
              "#updatedAt": "modified",
            },
            ExpressionAttributeValues: {
              ":v": { status: status },
              ":updatedAt": d,
            },
          };
        }
        if (
          (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
          process.env.hasOwnProperty("JEST_WORKER_ID")
        ) {
          console.log("PARAMS", params);
        }

        resolve(updateItem(params));
      }
    });
  });
  /*
  const params = {
    TableName: "PrifinaUser",
    Key: { id: prifinaID },
    UpdateExpression: "SET dataSources.#source = :v,#updatedAt=:updatedAt",
   
    ExpressionAttributeNames: {
      "#source": source,
      "#updatedAt": "modified",
    },
    ExpressionAttributeValues: {
      ":v": { status: status },
      ":updatedAt": d,
    },
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
*/
}

function getS3ObjectInfo(params) {
  /*
  const params = {
    Bucket: bucket,
    Key: file,
  };
  */
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return new Promise(function (resolve, reject) {
    s3ObjectInfo(params).then(
      (res) => {
        //console.log("RESOLVED ", res);
        if (res) {
          resolve(res);
        } else {
          resolve({});
        }
      },
      (error) => {
        //console.log("REJECTED ", error);
        reject(error);
      }
    );
    /*
    s3ObjectInfo(params, function (err, data) {
      if (err) {
        //console.log(err, err.stack);
        //reject(false);
        if (err.code === "NotFound") {
          resolve({});
        } else {
          reject(err);
        }
      } // an error occurred
      else {
        resolve(data);
      }
    });
    */
  });
}
function deleteS3Object(params) {
  /*
  const params = {
    Bucket: bucket,
    Key: file,
  };
  */
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3DeleteObject(params);
}

function deleteS3Objects(s3Bucket, s3Keys) {
  let params = {
    Bucket: s3Bucket,
    Delete: { Objects: [] },
  };
  s3Keys.forEach((k) => {
    params.Delete.Objects.push({ Key: k });
  });

  console.log("PARAMS", params.Delete.Objects[0]);

  return s3DeleteObjects(params);
}
function getS3Object(params) {
  /*
  const params = {
    Bucket: bucket,
    Key: file,
  };
  */
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3GetObject(params);
}
function putS3Object$1(params) {
  /*
  const params = {
    Bucket: bucket,
    Key: file,
    Body:body,
    ContentType:contentType
  };
  
  Metadata: {
    "Content-Type": "application/json",
    "alt-name": "fitbit-access-tokens",
  },
*/
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3PutObject(params);
}
function copyS3Object(params) {
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3CopyObject(params);
}

function selectS3Object(params) {
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3SelectObject(params);
}

function writeGetS3ObjectResponse(params) {
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }
  return s3WriteGetObjectResponse(params);
}
function saveUserData(
  dataBucket,
  dataKey,
  data,
  contentType = "application/json"
) {
  return putS3Object$1({
    Bucket: dataBucket,
    Key: dataKey,
    Body: data,
    ContentType: contentType,
  });
}

function fileExists(bucket, file) {
  const params = {
    Bucket: bucket,
    Key: file,
  };
  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return new Promise(function (resolve, reject) {
    s3ObjectInfo(params).then(
      (res) => {
        //console.log("RESOLVED ", res);
        resolve(res);
      },
      (error) => {
        //console.log("REJECTED ", error);
        reject(error);
      }
    );
    /*

    s3ObjectInfo(params, function (err, data) {
      console.log("FILE EXISTS ", data);

      if (err) {
        console.log("FILE ERROR ");
        console.log(err, err.stack);
        //reject(false);
        if (err.code === "NotFound") {
          resolve({});
        } else {
          reject(err);
        }
      } // an error occurred
      else {
        resolve(true);
      }
    });
    */
  });
}

function addNewEvents(params) {
  return ebPutEvents(params);
}
function getDDBItem(params) {
  return getItem(params);
}
function updateDDBItem(params) {
  return updateItem(params);
}
function scanDDBItems(params) {
  return scanItems(params);
}
function getAthenaQueryResults(params) {
  return athenaGetQueryResults(params);
}
function getAthenaQueryExecution(params) {
  return athenaGetQueryExecution(params);
}
function startAthenaQueryExecution(params) {
  return athenaStartQueryExecution(params);
}

function addNotification$1(data) {
  //const createdAt = new Date().getTime();
  const createdAt = new Date().toISOString();

  const notificationId = createNonce(12);

  const type = data.type;
  const body = data.body;
  const status = data.status;
  const prifinaID = data.prifinaID;
  const eventType = data.event;

  /*
type Notification @aws_iam {
  body: String!
  createdAt: AWSTimestamp!
  notificationId: String!
  owner: String!
  sender: String
  status: Int!
  type: String!
  updatedAt: AWSTimestamp!
}
$util.qr($ctx.args.input.put("createdAt", $util.defaultIfNull($ctx.args.input.createdAt, $util.time.nowEpochMilliSeconds() )))
$util.qr($ctx.args.input.put("updatedAt", $util.defaultIfNull($ctx.args.input.updatedAt, $util.time.nowEpochMilliSeconds() )))
$util.qr($ctx.args.input.put("status", $util.defaultIfNull($ctx.args.input.status, 0)))

## $util.qr($input.put("notificationId", $util.defaultIfNull($input.notificationId, $util.autoId())))

{
  "version": "2017-02-28",
  "operation": "PutItem",
  "key": {
  "notificationId":   $util.dynamodb.toDynamoDBJson($util.defaultIfNull($ctx.args.input.notificationId, $util.autoId()))
  },
  "attributeValues": $util.dynamodb.toMapValuesJson($ctx.args.input)
}

*/

  // expires after 1week
  const expire = Math.ceil((Date.now() + 7 * 24 * 60 * 60 * 1000) / 1000);

  const params = {
    TableName: "Notifications",
    Key: { notificationId: notificationId },
    UpdateExpression:
      "SET   #expire= :expire,#type= :type,#event= :event,#body= :body,#status= :status, #owner= :prifinaID,#updatedAt=:updatedAt,#createdAt=:createdAt",
    ExpressionAttributeValues: {
      ":type": type,
      ":event": eventType,
      ":body": body,
      ":status": status,
      ":prifinaID": prifinaID,
      ":updatedAt": createdAt,
      ":createdAt": createdAt,
      ":expire": expire,
    },
    ExpressionAttributeNames: {
      "#type": "type",
      "#event": "event",
      "#body": "body",
      "#status": "status",
      "#owner": "owner",
      "#updatedAt": "updatedAt",
      "#createdAt": "createdAt",
      "#expire": "expire",
    },
    ReturnValues: "ALL_NEW",
  };

  if (
    (process.env.hasOwnProperty("DEBUG") && process.env.DEBUG) ||
    process.env.hasOwnProperty("JEST_WORKER_ID")
  ) {
    console.log("PARAMS", params);
  }

  return updateItem(params);
}

/*
fileExists(
  "prifina-core-352681697435-eu-west-1",
  "integrations/fitbit/9G7RZB.json"
).then((res) => {
  console.log("TEST ", res);
});
*/
var serviceUtils$1 = {
  addPrifinaUser,
  addVerification,
  updateNotificationQueue,
  getDataSourceUsers,
  updateUserDataSource,
  updateUserDataSourceStatus,
  getS3ObjectInfo,
  deleteS3Object,
  deleteS3Objects,
  getS3Object,
  putS3Object: putS3Object$1,
  copyS3Object,
  selectS3Object,
  saveUserData,
  fileExists,
  addNewEvents,
  getDDBItem,
  updateDDBItem,
  scanDDBItems,
  getAthenaQueryExecution,
  getAthenaQueryResults,
  startAthenaQueryExecution,
  writeGetS3ObjectResponse,
  addNotification: addNotification$1,
};

const { parseJwt, getRequest, postRequest } = libUtils$1;
const { putS3Object, addNotification } = serviceUtils$1;

function getBaseString(httpMethod, apiUrl, p) {
  const oAuthParameters = Object.keys(p)
    .sort()
    .map((k) => {
      return `${k}=${p[k]}`;
    });

  console.log(oAuthParameters);
  return [
    httpMethod,
    encodeURIComponent(apiUrl),
    encodeURIComponent(oAuthParameters.join("&")),
  ].join("&");
}
function getEncodedSignature(encodedBaseString, key, token = "") {
  const CRYPTO = require$$1__default$1["default"];
  const hash = CRYPTO.createHmac("sha1", key + "&" + token)
    .update(encodedBaseString)
    .digest("base64");

  return encodeURIComponent(hash);
}
function getHeaderOAuth(p) {
  const oAuthParameters = Object.keys(p)
    .sort()
    .map((k) => {
      return `${k}="${p[k]}"`;
    });

  //console.log(oAuthParameters);
  return "OAuth " + oAuthParameters.join(", ");
}
function refreshFitbitAccessToken(clientID, clientSecret, refreshToken) {
  try {
    const oAuth =
      "Basic " + Buffer.from(clientID + ":" + clientSecret).toString("base64");
    const parts = ["grant_type=refresh_token", "refresh_token=" + refreshToken];
    console.log(parts.join("&"));
    console.log(oAuth);
    const apiUrl = "https://api.fitbit.com/oauth2/token";
    return postRequest(apiUrl, oAuth, parts.join("&"));
  } catch (e) {
    console.log("ERR ", e);
    return Promise.reject(e);
  }
}

async function checkFitbitToken(tokens, tokenKey, dataBucket) {
  try {
    let jwt = parseJwt(tokens.access_token);
    //console.log("JWT ", jwt);
    jwt.exp = jwt.exp * 1000;
    console.log(jwt);
    const ts = new Date().getTime();
    if (ts > jwt.exp) {
      console.log("GET REFRESH TOKEN...");
      const newTokens = await refreshFitbitAccessToken(
        tokens.ClientId,
        tokens.ClientSecret,
        tokens.refresh_token
      );
      console.log(newTokens);
      let tokenJSON = JSON.parse(newTokens);
      tokenJSON = { ...tokens, ...tokenJSON };

      await putS3Object({
        Bucket: dataBucket,
        Key: tokenKey,
        Body: JSON.stringify(tokenJSON),
        ContentType: "application/json",
      });
      await addNotification({
        type: "FITBIT-TOKEN-UPDATE",
        body: JSON.stringify({
          service: "fitbit",
          action: "new access token received",
        }),
        status: 0,
        event: "DATA-SOURCE",
        prifinaID: tokenJSON.prifinaId,
      });
      return Promise.resolve(tokenJSON);
    }
  } catch (err) {
    await addNotification({
      type: "FITBIT-TOKEN-UPDATE-ERROR",
      body: JSON.stringify({
        service: "fitbit",
        action: "access token refresh failed",
      }),
      status: 0,
      event: "DATA-SOURCE",
      prifinaID: tokens.prifinaId,
    });
    return Promise.reject(err);
  }

  return Promise.resolve(tokens);
}
function refreshOuraAccessToken(clientID, clientSecret, refreshToken) {
  try {
    const oAuth =
      "Basic " + Buffer.from(clientID + ":" + clientSecret).toString("base64");
    const parts = ["grant_type=refresh_token", "refresh_token=" + refreshToken];
    console.log(parts.join("&"));
    console.log(oAuth);
    const apiUrl = "https://api.ouraring.com/oauth/token";
    return postRequest(apiUrl, oAuth, parts.join("&"));
  } catch (e) {
    console.log("ERR ", e);
    return Promise.reject(e);
  }
}

async function checkOuraToken(tokens, tokenKey, dataBucket) {
  try {
    /*
    let jwt = parseJwt(tokens.access_token);
    jwt.exp = jwt.exp * 1000;

    console.log(jwt);
    */
    // Access token is not jwt
    /*
{
  "access_token": "35RXMIU7KUXBQONVFTGH4LNTYXI5UMA7",
  "token_type": "Bearer",
  "expires_in": 86400,
  "refresh_token": "COPMFQPO47Z4LBT3FTHLMUMICX6LFF45",
  "prifinaId": "6145b3af07fa22f66456e20eca49e98bfe35",
  "ClientId": "3OFQV2FZMV566W7Y",
  "ClientSecret": "I6C2JQMDWMVBJ4YZDKZ2FHTZNMOXJQFF",
  "exp": 1636126980888,
  "user_id": "OURA"
}

*/
    if (
      tokens.hasOwnProperty("token_type") &&
      tokens.token_type === "Personal"
    ) {
      return Promise.resolve(tokens);
    }
    //Key: ["integrations", "oura", prifinaID, "tokens"].join("/") + ".json",
    const prifinaID = tokenKey.split("/")[2];

    const ts = new Date().getTime();
    if (ts > tokens.exp) {
      console.log("GET REFRESH TOKEN...");
      const newTokens = await refreshOuraAccessToken(
        tokens.ClientId,
        tokens.ClientSecret,
        tokens.refresh_token
      );
      console.log(newTokens);
      let tokenJSON = JSON.parse(newTokens);
      if (tokenJSON.hasOwnProperty("access_token")) {
        tokenJSON.exp = ts + tokenJSON.expire_in * 1000;
        tokenJSON = { ...tokens, ...tokenJSON };

        await putS3Object({
          Bucket: dataBucket,
          Key: tokenKey,
          Body: JSON.stringify(tokenJSON),
          ContentType: "application/json",
        });

        await addNotification({
          type: "OURA-TOKEN-UPDATE",
          body: JSON.stringify({
            service: "oura",
            action: "new access token received",
          }),
          status: 0,
          event: "DATA-SOURCE",
          prifinaID: prifinaID,
        });

        return Promise.resolve(tokenJSON);
      } else {
        await addNotification({
          type: "OURA-TOKEN-UPDATE-ERROR",
          body: JSON.stringify({
            service: "oura",
            action: "access token refresh failed",
          }),
          status: 0,
          event: "DATA-SOURCE",
          prifinaID: prifinaID,
        });

        return Promise.reject("INVALID_GRANT");
      }
    }
  } catch (err) {
    return Promise.reject(err);
  }

  return Promise.resolve(tokens);
}

var integrationUtils$1 = {
  checkFitbitToken,
  refreshFitbitAccessToken,
  refreshOuraAccessToken,
  checkOuraToken,
  getBaseString,
  getEncodedSignature,
  getHeaderOAuth,
};

/* istanbul ignore file */

const aws = aws$1;
const awsUtils = awsUtils$1;
const libUtils = libUtils$1;
const serviceUtils = serviceUtils$1;
const integrationUtils = integrationUtils$1;

var lib = {
  aws,
  awsUtils,
  libUtils,
  serviceUtils,
  integrationUtils,
};

module.exports = lib;
