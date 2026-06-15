#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <freerdp/api.h>
#include <freerdp/freerdp.h>
#include <freerdp/server/proxy/proxy_config.h>
#include <freerdp/server/proxy/proxy_context.h>
#include <freerdp/server/proxy/proxy_modules_api.h>
#include <freerdp/settings.h>
#include <winpr/sspi.h>
#include <winpr/wtypes.h>

#define TURJMP_PLUGIN_NAME "turjmp"
#define TURJMP_PLUGIN_DESC "Turjmp native RDP session lifecycle plugin"
#define TURJMP_HTTP_MAX_RESPONSE (1024 * 1024)

typedef struct turjmp_module_config
{
	pthread_mutex_t mu;
	bool loaded;
	char* api_base_url;
	char* proxy_auth;
	int max_connections;
	int idle_timeout_seconds;
	struct turjmp_session_state* sessions;
} turjmpModuleConfig;

typedef struct turjmp_session_state
{
	pthread_mutex_t mu;
	proxyPlugin* plugin;
	proxyData* pdata;
	turjmpModuleConfig* module_cfg;
	int64_t session_id;
	char* target_host;
	uint16_t target_port;
	char* target_username;
	char* target_password;
	char* api_base_url;
	char* proxy_auth;
	int idle_timeout_seconds;
	time_t last_activity;
	bool finished;
	bool stop_watchdog;
	bool watchdog_started;
	bool connected_to_target;
	pthread_t watchdog;
	struct turjmp_session_state* next;
} turjmpSessionState;

typedef struct http_response
{
	int status;
	char* body;
} httpResponse;

static void turjmp_log(const char* msg)
{
	fprintf(stderr, "turjmp freerdp plugin: %s\n", msg);
}

static char* turjmp_strdup(const char* value)
{
	if (!value)
		value = "";
	const size_t len = strlen(value);
	char* out = calloc(len + 1, 1);
	if (!out)
		return NULL;
	memcpy(out, value, len);
	return out;
}

static void secure_free(char* value)
{
	if (!value)
		return;
	volatile char* p = value;
	for (size_t i = 0; value[i] != '\0'; i++)
		p[i] = '\0';
	free(value);
}

static int parse_positive_int(const char* value, int fallback)
{
	if (!value || !*value)
		return fallback;
	char* end = NULL;
	const long n = strtol(value, &end, 10);
	if ((end == value) || (n <= 0) || (n > 0x7fffffffL))
		return fallback;
	return (int)n;
}

static bool module_config_load(proxyPlugin* plugin, proxyData* pdata)
{
	if (!plugin || !pdata || !pdata->config)
		return false;
	turjmpModuleConfig* cfg = (turjmpModuleConfig*)plugin->custom;
	if (!cfg)
		return false;

	pthread_mutex_lock(&cfg->mu);
	if (!cfg->loaded)
	{
		const char* api = pf_config_get(pdata->config, "Turjmp", "APIBaseURL");
		const char* auth = pf_config_get(pdata->config, "Turjmp", "ProxyAuth");
		const char* max_connections = pf_config_get(pdata->config, "Turjmp", "MaxConnections");
		const char* idle = pf_config_get(pdata->config, "Turjmp", "IdleTimeoutSeconds");

		cfg->api_base_url = turjmp_strdup(api);
		cfg->proxy_auth = turjmp_strdup(auth);
		cfg->max_connections = parse_positive_int(max_connections, 1);
		cfg->idle_timeout_seconds = parse_positive_int(idle, 3600);
		cfg->loaded = (cfg->api_base_url && cfg->api_base_url[0] && cfg->proxy_auth &&
		               cfg->proxy_auth[0]);
	}
	const bool ok = cfg->loaded;
	pthread_mutex_unlock(&cfg->mu);
	return ok;
}

static char* module_config_api_base_url(proxyPlugin* plugin)
{
	turjmpModuleConfig* cfg = plugin ? (turjmpModuleConfig*)plugin->custom : NULL;
	if (!cfg)
		return NULL;
	pthread_mutex_lock(&cfg->mu);
	char* out = turjmp_strdup(cfg->api_base_url);
	pthread_mutex_unlock(&cfg->mu);
	return out;
}

static char* module_config_proxy_auth(proxyPlugin* plugin)
{
	turjmpModuleConfig* cfg = plugin ? (turjmpModuleConfig*)plugin->custom : NULL;
	if (!cfg)
		return NULL;
	pthread_mutex_lock(&cfg->mu);
	char* out = turjmp_strdup(cfg->proxy_auth);
	pthread_mutex_unlock(&cfg->mu);
	return out;
}

static int module_config_idle_timeout(proxyPlugin* plugin)
{
	turjmpModuleConfig* cfg = plugin ? (turjmpModuleConfig*)plugin->custom : NULL;
	if (!cfg)
		return 3600;
	pthread_mutex_lock(&cfg->mu);
	const int out = cfg->idle_timeout_seconds;
	pthread_mutex_unlock(&cfg->mu);
	return out;
}

static void session_state_free(turjmpSessionState* state)
{
	if (!state)
		return;
	pthread_mutex_destroy(&state->mu);
	free(state->target_host);
	free(state->target_username);
	secure_free(state->target_password);
	free(state->api_base_url);
	secure_free(state->proxy_auth);
	free(state);
}

static void session_list_add(turjmpModuleConfig* cfg, turjmpSessionState* state)
{
	if (!cfg || !state)
		return;
	pthread_mutex_lock(&cfg->mu);
	state->next = cfg->sessions;
	cfg->sessions = state;
	pthread_mutex_unlock(&cfg->mu);
}

static void session_list_remove(turjmpModuleConfig* cfg, turjmpSessionState* state)
{
	if (!cfg || !state)
		return;
	pthread_mutex_lock(&cfg->mu);
	turjmpSessionState** cur = &cfg->sessions;
	while (*cur)
	{
		if (*cur == state)
		{
			*cur = state->next;
			state->next = NULL;
			break;
		}
		cur = &(*cur)->next;
	}
	pthread_mutex_unlock(&cfg->mu);
}

static turjmpSessionState* session_state_get(proxyPlugin* plugin, proxyData* pdata)
{
	if (!plugin || !plugin->mgr || !pdata)
		return NULL;
	return (turjmpSessionState*)plugin->mgr->GetPluginData(plugin->mgr, TURJMP_PLUGIN_NAME, pdata);
}

static bool session_state_set(proxyPlugin* plugin, proxyData* pdata, turjmpSessionState* state)
{
	if (!plugin || !plugin->mgr || !pdata)
		return false;
	return plugin->mgr->SetPluginData(plugin->mgr, TURJMP_PLUGIN_NAME, pdata, state) ? true : false;
}

static void touch_activity(proxyPlugin* plugin, proxyData* pdata)
{
	turjmpSessionState* state = session_state_get(plugin, pdata);
	if (!state)
		return;
	pthread_mutex_lock(&state->mu);
	state->last_activity = time(NULL);
	pthread_mutex_unlock(&state->mu);
}

static char* identity_part_to_utf8(const void* data, uint32_t length, bool unicode)
{
	if (!data || length == 0)
		return turjmp_strdup("");
	if (!unicode)
	{
		char* out = calloc((size_t)length + 1, 1);
		if (!out)
			return NULL;
		memcpy(out, data, length);
		return out;
	}

	const WCHAR* in = (const WCHAR*)data;
	size_t cap = (size_t)length * 4 + 1;
	char* out = calloc(cap, 1);
	if (!out)
		return NULL;
	size_t j = 0;
	for (uint32_t i = 0; i < length; i++)
	{
		uint32_t cp = (uint32_t)in[i];
		if ((cp >= 0xD800) && (cp <= 0xDBFF) && (i + 1 < length))
		{
			const uint32_t low = (uint32_t)in[i + 1];
			if ((low >= 0xDC00) && (low <= 0xDFFF))
			{
				cp = 0x10000u + (((cp - 0xD800u) << 10) | (low - 0xDC00u));
				i++;
			}
		}
		if (cp <= 0x7F)
		{
			out[j++] = (char)cp;
		}
		else if (cp <= 0x7FF)
		{
			out[j++] = (char)(0xC0 | (cp >> 6));
			out[j++] = (char)(0x80 | (cp & 0x3F));
		}
		else if (cp <= 0xFFFF)
		{
			out[j++] = (char)(0xE0 | (cp >> 12));
			out[j++] = (char)(0x80 | ((cp >> 6) & 0x3F));
			out[j++] = (char)(0x80 | (cp & 0x3F));
		}
		else
		{
			out[j++] = (char)(0xF0 | (cp >> 18));
			out[j++] = (char)(0x80 | ((cp >> 12) & 0x3F));
			out[j++] = (char)(0x80 | ((cp >> 6) & 0x3F));
			out[j++] = (char)(0x80 | (cp & 0x3F));
		}
	}
	out[j] = '\0';
	return out;
}

static char* json_escape(const char* value)
{
	if (!value)
		value = "";
	size_t cap = strlen(value) * 6 + 1;
	char* out = calloc(cap, 1);
	if (!out)
		return NULL;
	size_t j = 0;
	for (const unsigned char* p = (const unsigned char*)value; *p; p++)
	{
		switch (*p)
		{
			case '"':
				out[j++] = '\\';
				out[j++] = '"';
				break;
			case '\\':
				out[j++] = '\\';
				out[j++] = '\\';
				break;
			case '\b':
				out[j++] = '\\';
				out[j++] = 'b';
				break;
			case '\f':
				out[j++] = '\\';
				out[j++] = 'f';
				break;
			case '\n':
				out[j++] = '\\';
				out[j++] = 'n';
				break;
			case '\r':
				out[j++] = '\\';
				out[j++] = 'r';
				break;
			case '\t':
				out[j++] = '\\';
				out[j++] = 't';
				break;
			default:
				if (*p < 0x20)
				{
					snprintf(out + j, cap - j, "\\u%04x", *p);
					j += 6;
				}
				else
				{
					out[j++] = (char)*p;
				}
		}
	}
	out[j] = '\0';
	return out;
}

static char* build_start_body(const char* route_username, const char* password)
{
	char* route = json_escape(route_username);
	char* pass = json_escape(password);
	if (!route || !pass)
	{
		free(route);
		secure_free(pass);
		return NULL;
	}
	const char* tmpl = "{\"route_username\":\"%s\",\"password\":\"%s\",\"remote_addr\":\"\"}";
	const int n = snprintf(NULL, 0, tmpl, route, pass);
	char* body = calloc((size_t)n + 1, 1);
	if (body)
		snprintf(body, (size_t)n + 1, tmpl, route, pass);
	free(route);
	secure_free(pass);
	return body;
}

static char* build_finish_body(const char* reason)
{
	char* escaped = json_escape(reason ? reason : "disconnect");
	if (!escaped)
		return NULL;
	const char* tmpl = "{\"reason\":\"%s\"}";
	const int n = snprintf(NULL, 0, tmpl, escaped);
	char* body = calloc((size_t)n + 1, 1);
	if (body)
		snprintf(body, (size_t)n + 1, tmpl, escaped);
	free(escaped);
	return body;
}

typedef struct parsed_url
{
	char* host;
	char* port;
	char* base_path;
} parsedURL;

static void parsed_url_free(parsedURL* u)
{
	if (!u)
		return;
	free(u->host);
	free(u->port);
	free(u->base_path);
	free(u);
}

static parsedURL* parse_http_url(const char* raw)
{
	const char* prefix = "http://";
	if (!raw || strncmp(raw, prefix, strlen(prefix)) != 0)
		return NULL;
	const char* p = raw + strlen(prefix);
	const char* path = strchr(p, '/');
	const char* host_end = path ? path : raw + strlen(raw);
	const char* port = NULL;
	const char* port_end = host_end;
	const char* host_start = p;
	if (*p == '[')
	{
		const char* close = memchr(p, ']', (size_t)(host_end - p));
		if (!close)
			return NULL;
		host_start = p + 1;
		if ((close + 1 < host_end) && close[1] == ':')
			port = close + 2;
		host_end = close;
	}
	else
	{
		const char* colon = memchr(p, ':', (size_t)(host_end - p));
		if (colon)
		{
			host_end = colon;
			port = colon + 1;
		}
	}

	parsedURL* out = calloc(1, sizeof(*out));
	if (!out)
		return NULL;
	const size_t host_len = (size_t)(host_end - host_start);
	out->host = calloc(host_len + 1, 1);
	if (out->host)
		memcpy(out->host, host_start, host_len);
	if (port)
	{
		const size_t port_len = (size_t)(port_end - port);
		out->port = calloc(port_len + 1, 1);
		if (out->port)
			memcpy(out->port, port, port_len);
	}
	else
	{
		out->port = turjmp_strdup("80");
	}
	out->base_path = turjmp_strdup(path ? path : "");
	if (!out->host || !out->port || !out->base_path || !out->host[0])
	{
		parsed_url_free(out);
		return NULL;
	}
	return out;
}

static char* join_path(const char* base, const char* endpoint)
{
	if (!base || !*base || strcmp(base, "/") == 0)
		return turjmp_strdup(endpoint);
	const bool base_slash = base[strlen(base) - 1] == '/';
	const bool endpoint_slash = endpoint && endpoint[0] == '/';
	const char* sep = (base_slash || endpoint_slash) ? "" : "/";
	if (base_slash && endpoint_slash)
		endpoint++;
	const int n = snprintf(NULL, 0, "%s%s%s", base, sep, endpoint);
	char* out = calloc((size_t)n + 1, 1);
	if (out)
		snprintf(out, (size_t)n + 1, "%s%s%s", base, sep, endpoint);
	return out;
}

static int connect_tcp(const char* host, const char* port)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	struct addrinfo* res = NULL;
	if (getaddrinfo(host, port, &hints, &res) != 0)
		return -1;
	int fd = -1;
	for (struct addrinfo* it = res; it; it = it->ai_next)
	{
		fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, it->ai_addr, it->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

static bool send_all(int fd, const char* data, size_t len)
{
	while (len > 0)
	{
		const ssize_t n = send(fd, data, len, 0);
		if (n <= 0)
			return false;
		data += n;
		len -= (size_t)n;
	}
	return true;
}

static char* read_all(int fd)
{
	size_t cap = 8192;
	size_t len = 0;
	char* out = calloc(cap + 1, 1);
	if (!out)
		return NULL;
	for (;;)
	{
		if (len == cap)
		{
			if (cap >= TURJMP_HTTP_MAX_RESPONSE)
				break;
			cap *= 2;
			if (cap > TURJMP_HTTP_MAX_RESPONSE)
				cap = TURJMP_HTTP_MAX_RESPONSE;
			char* grown = realloc(out, cap + 1);
			if (!grown)
			{
				free(out);
				return NULL;
			}
			out = grown;
		}
		const ssize_t n = recv(fd, out + len, cap - len, 0);
		if (n < 0)
		{
			free(out);
			return NULL;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	out[len] = '\0';
	return out;
}

static bool header_contains_chunked(const char* response, const char* body)
{
	const char* p = response;
	while (p && p < body)
	{
		const char* line_end = strstr(p, "\r\n");
		if (!line_end || line_end > body)
			break;
		const size_t len = (size_t)(line_end - p);
		const char key[] = "transfer-encoding:";
		if (len >= sizeof(key) - 1)
		{
			bool match = true;
			for (size_t i = 0; i < sizeof(key) - 1; i++)
			{
				if (tolower((unsigned char)p[i]) != key[i])
				{
					match = false;
					break;
				}
			}
			if (match)
			{
				for (size_t i = sizeof(key) - 1; i < len; i++)
				{
					if (tolower((unsigned char)p[i]) == 'c' &&
					    i + 7 <= len && strncasecmp(p + i, "chunked", 7) == 0)
						return true;
				}
			}
		}
		p = line_end + 2;
	}
	return false;
}

static char* decode_chunked_body(const char* body)
{
	size_t cap = strlen(body) + 1;
	char* out = calloc(cap, 1);
	if (!out)
		return NULL;
	size_t len = 0;
	const char* p = body;
	for (;;)
	{
		char* end = NULL;
		const unsigned long chunk = strtoul(p, &end, 16);
		if (end == p)
			break;
		const char* line_end = strstr(end, "\r\n");
		if (!line_end)
			break;
		p = line_end + 2;
		if (chunk == 0)
			break;
		if (len + chunk >= cap)
		{
			free(out);
			return NULL;
		}
		memcpy(out + len, p, chunk);
		len += chunk;
		p += chunk;
		if (strncmp(p, "\r\n", 2) != 0)
			break;
		p += 2;
	}
	out[len] = '\0';
	return out;
}

static httpResponse http_post_json(const char* base_url, const char* proxy_auth, const char* endpoint,
                                   const char* body)
{
	httpResponse out = { 0 };
	parsedURL* u = parse_http_url(base_url);
	if (!u)
	{
		turjmp_log("only http APIBaseURL is supported by the plugin");
		return out;
	}
	char* path = join_path(u->base_path, endpoint);
	if (!path)
	{
		parsed_url_free(u);
		return out;
	}
	const int fd = connect_tcp(u->host, u->port);
	if (fd < 0)
	{
		free(path);
		parsed_url_free(u);
		return out;
	}

	const size_t body_len = body ? strlen(body) : 0;
	const int n = snprintf(NULL, 0,
	                       "POST %s HTTP/1.1\r\n"
	                       "Host: %s\r\n"
	                       "User-Agent: turjmp-freerdp-plugin/0.1\r\n"
	                       "Content-Type: application/json\r\n"
	                       "Content-Length: %zu\r\n"
	                       "X-Proxy-Auth: %s\r\n"
	                       "Connection: close\r\n"
	                       "\r\n"
	                       "%s",
	                       path, u->host, body_len, proxy_auth ? proxy_auth : "", body ? body : "");
	char* req = calloc((size_t)n + 1, 1);
	if (!req)
	{
		close(fd);
		free(path);
		parsed_url_free(u);
		return out;
	}
	snprintf(req, (size_t)n + 1,
	         "POST %s HTTP/1.1\r\n"
	         "Host: %s\r\n"
	         "User-Agent: turjmp-freerdp-plugin/0.1\r\n"
	         "Content-Type: application/json\r\n"
	         "Content-Length: %zu\r\n"
	         "X-Proxy-Auth: %s\r\n"
	         "Connection: close\r\n"
	         "\r\n"
	         "%s",
	         path, u->host, body_len, proxy_auth ? proxy_auth : "", body ? body : "");
	if (send_all(fd, req, strlen(req)))
	{
		char* response = read_all(fd);
		if (response)
		{
			int status = 0;
			if (sscanf(response, "HTTP/%*s %d", &status) == 1)
				out.status = status;
			char* body_start = strstr(response, "\r\n\r\n");
			if (body_start)
			{
				body_start += 4;
				if (header_contains_chunked(response, body_start))
					out.body = decode_chunked_body(body_start);
				else
					out.body = turjmp_strdup(body_start);
			}
			secure_free(response);
		}
	}
	secure_free(req);
	close(fd);
	free(path);
	parsed_url_free(u);
	return out;
}

static const char* skip_ws(const char* p)
{
	while (p && *p && isspace((unsigned char)*p))
		p++;
	return p;
}

static const char* json_find_value(const char* json, const char* key)
{
	if (!json || !key)
		return NULL;
	const size_t key_len = strlen(key);
	const char* p = json;
	while ((p = strchr(p, '"')) != NULL)
	{
		p++;
		if (strncmp(p, key, key_len) == 0 && p[key_len] == '"')
		{
			p += key_len + 1;
			p = skip_ws(p);
			if (*p == ':')
				return skip_ws(p + 1);
		}
	}
	return NULL;
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static bool append_utf8(char* out, size_t cap, size_t* j, uint32_t cp)
{
	if (cp <= 0x7F)
	{
		if (*j + 1 >= cap)
			return false;
		out[(*j)++] = (char)cp;
	}
	else if (cp <= 0x7FF)
	{
		if (*j + 2 >= cap)
			return false;
		out[(*j)++] = (char)(0xC0 | (cp >> 6));
		out[(*j)++] = (char)(0x80 | (cp & 0x3F));
	}
	else if (cp <= 0xFFFF)
	{
		if (*j + 3 >= cap)
			return false;
		out[(*j)++] = (char)(0xE0 | (cp >> 12));
		out[(*j)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
		out[(*j)++] = (char)(0x80 | (cp & 0x3F));
	}
	else
	{
		if (*j + 4 >= cap)
			return false;
		out[(*j)++] = (char)(0xF0 | (cp >> 18));
		out[(*j)++] = (char)(0x80 | ((cp >> 12) & 0x3F));
		out[(*j)++] = (char)(0x80 | ((cp >> 6) & 0x3F));
		out[(*j)++] = (char)(0x80 | (cp & 0x3F));
	}
	return true;
}

static char* json_get_string(const char* json, const char* key)
{
	const char* p = json_find_value(json, key);
	if (!p || *p != '"')
		return NULL;
	p++;
	size_t cap = strlen(p) + 1;
	char* out = calloc(cap, 1);
	if (!out)
		return NULL;
	size_t j = 0;
	while (*p && *p != '"')
	{
		if (*p == '\\')
		{
			p++;
			switch (*p)
			{
				case '"':
				case '\\':
				case '/':
					out[j++] = *p++;
					break;
				case 'b':
					out[j++] = '\b';
					p++;
					break;
				case 'f':
					out[j++] = '\f';
					p++;
					break;
				case 'n':
					out[j++] = '\n';
					p++;
					break;
				case 'r':
					out[j++] = '\r';
					p++;
					break;
				case 't':
					out[j++] = '\t';
					p++;
					break;
				case 'u':
				{
					if (!p[1] || !p[2] || !p[3] || !p[4])
						goto done;
					int h0 = hex_value(p[1]);
					int h1 = hex_value(p[2]);
					int h2 = hex_value(p[3]);
					int h3 = hex_value(p[4]);
					if (h0 < 0 || h1 < 0 || h2 < 0 || h3 < 0)
						goto done;
					uint32_t cp = (uint32_t)((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
					p += 5;
					if (!append_utf8(out, cap, &j, cp))
						goto done;
					break;
				}
				default:
					goto done;
			}
		}
		else
		{
			out[j++] = *p++;
		}
		if (j + 4 >= cap)
			goto done;
	}
done:
	out[j] = '\0';
	return out;
}

static int64_t json_get_int64(const char* json, const char* key)
{
	const char* p = json_find_value(json, key);
	if (!p)
		return 0;
	return strtoll(p, NULL, 10);
}

static int json_get_int(const char* json, const char* key)
{
	const int64_t n = json_get_int64(json, key);
	if (n <= 0 || n > 65535)
		return 0;
	return (int)n;
}

static bool parse_start_response(const char* body, turjmpSessionState* state)
{
	if (!body || !state)
		return false;
	state->session_id = json_get_int64(body, "session_id");
	state->target_host = json_get_string(body, "address");
	state->target_port = (uint16_t)json_get_int(body, "port");
	state->target_username = json_get_string(body, "username");
	state->target_password = json_get_string(body, "secret");
	if (state->target_port == 0)
		state->target_port = 3389;
	return state->session_id > 0 && state->target_host && state->target_host[0] &&
	       state->target_username && state->target_password;
}

static void finish_session_once(turjmpSessionState* state, const char* reason, bool abort_connection)
{
	if (!state || state->session_id <= 0)
		return;
	pthread_mutex_lock(&state->mu);
	if (state->finished)
	{
		pthread_mutex_unlock(&state->mu);
		return;
	}
	state->finished = true;
	state->stop_watchdog = true;
	const int64_t session_id = state->session_id;
	char* api_base_url = turjmp_strdup(state->api_base_url);
	char* proxy_auth = turjmp_strdup(state->proxy_auth);
	pthread_mutex_unlock(&state->mu);

	char endpoint[160];
	snprintf(endpoint, sizeof(endpoint), "/api/v1/proxy/rdp-native/sessions/%lld/finish",
	         (long long)session_id);
	char* body = build_finish_body(reason);
	if (api_base_url && proxy_auth && body)
	{
		httpResponse resp = http_post_json(api_base_url, proxy_auth, endpoint, body);
		secure_free(resp.body);
	}
	secure_free(body);
	free(api_base_url);
	secure_free(proxy_auth);

	if (abort_connection && state->plugin && state->plugin->mgr && state->pdata)
		state->plugin->mgr->AbortConnect(state->plugin->mgr, state->pdata);
}

static void* idle_watchdog_main(void* arg)
{
	turjmpSessionState* state = (turjmpSessionState*)arg;
	for (;;)
	{
		sleep(1);
		pthread_mutex_lock(&state->mu);
		const bool stop = state->stop_watchdog || state->finished;
		const time_t last = state->last_activity;
		const int timeout = state->idle_timeout_seconds;
		pthread_mutex_unlock(&state->mu);
		if (stop)
			return NULL;
		if (timeout > 0 && time(NULL) - last >= timeout)
		{
			finish_session_once(state, "idle_timeout", true);
			return NULL;
		}
	}
}

static bool start_idle_watchdog(turjmpSessionState* state)
{
	if (!state || state->idle_timeout_seconds <= 0)
		return true;
	if (pthread_create(&state->watchdog, NULL, idle_watchdog_main, state) != 0)
		return false;
	state->watchdog_started = true;
	return true;
}

static BOOL turjmp_server_peer_logon(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	const proxyServerPeerLogon* info = (const proxyServerPeerLogon*)param;
	if (!plugin || !pdata || !info || !info->identity)
		return FALSE;
	if (!module_config_load(plugin, pdata))
	{
		turjmp_log("missing [Turjmp] APIBaseURL or ProxyAuth");
		return FALSE;
	}
	if (session_state_get(plugin, pdata))
		return TRUE;

	const bool unicode = (info->identity->Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE) != 0;
	char* route_username =
	    identity_part_to_utf8(info->identity->User, info->identity->UserLength, unicode);
	char* password =
	    identity_part_to_utf8(info->identity->Password, info->identity->PasswordLength, unicode);
	if (!route_username || !password)
	{
		free(route_username);
		secure_free(password);
		return FALSE;
	}

	turjmpSessionState* state = calloc(1, sizeof(*state));
	if (!state)
	{
		free(route_username);
		secure_free(password);
		return FALSE;
	}
	pthread_mutex_init(&state->mu, NULL);
	state->plugin = plugin;
	state->pdata = pdata;
	state->module_cfg = (turjmpModuleConfig*)plugin->custom;
	state->api_base_url = module_config_api_base_url(plugin);
	state->proxy_auth = module_config_proxy_auth(plugin);
	state->idle_timeout_seconds = module_config_idle_timeout(plugin);
	state->last_activity = time(NULL);

	char* body = build_start_body(route_username, password);
	secure_free(password);
	free(route_username);
	if (!body || !state->api_base_url || !state->proxy_auth)
	{
		secure_free(body);
		session_state_free(state);
		return FALSE;
	}
	httpResponse resp =
	    http_post_json(state->api_base_url, state->proxy_auth,
	                   "/api/v1/proxy/rdp-native/sessions/start", body);
	secure_free(body);
	if (resp.status < 200 || resp.status >= 300 || !parse_start_response(resp.body, state))
	{
		secure_free(resp.body);
		session_state_free(state);
		return FALSE;
	}
	secure_free(resp.body);

	if (!session_state_set(plugin, pdata, state))
	{
		finish_session_once(state, "proxy_shutdown", false);
		session_state_free(state);
		return FALSE;
	}
	session_list_add(state->module_cfg, state);
	if (!start_idle_watchdog(state))
	{
		session_list_remove(state->module_cfg, state);
		finish_session_once(state, "proxy_shutdown", true);
		return FALSE;
	}
	return TRUE;
}

static BOOL turjmp_server_fetch_target_addr(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	proxyFetchTargetEventInfo* event = (proxyFetchTargetEventInfo*)param;
	turjmpSessionState* state = session_state_get(plugin, pdata);
	if (!event || !state || !state->target_host)
		return FALSE;
	event->fetch_method = PROXY_FETCH_TARGET_USE_CUSTOM_ADDR;
	event->target_address = turjmp_strdup(state->target_host);
	event->target_port = state->target_port;
	return event->target_address != NULL;
}

static BOOL turjmp_server_post_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	(void)custom;
	turjmpSessionState* state = session_state_get(plugin, pdata);
	if (!pdata || !pdata->pc || !pdata->pc->settings || !state)
		return FALSE;
	const BOOL user_ok =
	    freerdp_settings_set_string(pdata->pc->settings, FreeRDP_Username, state->target_username);
	const BOOL pass_ok =
	    freerdp_settings_set_string(pdata->pc->settings, FreeRDP_Password, state->target_password);
	touch_activity(plugin, pdata);
	return user_ok && pass_ok;
}

static BOOL turjmp_client_post_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	(void)custom;
	turjmpSessionState* state = session_state_get(plugin, pdata);
	if (!state)
		return TRUE;
	pthread_mutex_lock(&state->mu);
	state->connected_to_target = true;
	pthread_mutex_unlock(&state->mu);
	touch_activity(plugin, pdata);
	return TRUE;
}

static BOOL turjmp_client_uninit_connect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	(void)custom;
	turjmpSessionState* state = session_state_get(plugin, pdata);
	if (!state)
		return TRUE;
	pthread_mutex_lock(&state->mu);
	const bool connected = state->connected_to_target;
	pthread_mutex_unlock(&state->mu);
	if (!connected)
		finish_session_once(state, "target_connect_failed", false);
	return TRUE;
}

static BOOL turjmp_client_login_failure(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	(void)custom;
	finish_session_once(session_state_get(plugin, pdata), "target_login_failed", false);
	return TRUE;
}

static BOOL turjmp_client_post_disconnect(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	(void)custom;
	finish_session_once(session_state_get(plugin, pdata), "disconnect", false);
	return TRUE;
}

static BOOL turjmp_server_session_end(proxyPlugin* plugin, proxyData* pdata, void* custom)
{
	(void)custom;
	turjmpSessionState* state = session_state_get(plugin, pdata);
	if (!state)
		return TRUE;
	finish_session_once(state, "disconnect", false);
	session_list_remove(state->module_cfg, state);
	pthread_mutex_lock(&state->mu);
	state->stop_watchdog = true;
	const bool join = state->watchdog_started && !pthread_equal(pthread_self(), state->watchdog);
	pthread_mutex_unlock(&state->mu);
	if (join)
		pthread_join(state->watchdog, NULL);
	if (plugin && plugin->mgr)
		plugin->mgr->SetPluginData(plugin->mgr, TURJMP_PLUGIN_NAME, pdata, NULL);
	session_state_free(state);
	return TRUE;
}

static BOOL turjmp_activity_filter(proxyPlugin* plugin, proxyData* pdata, void* param)
{
	(void)param;
	touch_activity(plugin, pdata);
	return TRUE;
}

static BOOL turjmp_plugin_unload(proxyPlugin* plugin)
{
	if (!plugin)
		return TRUE;
	turjmpModuleConfig* cfg = (turjmpModuleConfig*)plugin->custom;
	if (cfg)
	{
		pthread_mutex_lock(&cfg->mu);
		turjmpSessionState* state = cfg->sessions;
		cfg->sessions = NULL;
		pthread_mutex_unlock(&cfg->mu);
		while (state)
		{
			turjmpSessionState* next = state->next;
			state->next = NULL;
			finish_session_once(state, "proxy_shutdown", false);
			pthread_mutex_lock(&state->mu);
			state->stop_watchdog = true;
			const bool join = state->watchdog_started && !pthread_equal(pthread_self(), state->watchdog);
			pthread_mutex_unlock(&state->mu);
			if (join)
				pthread_join(state->watchdog, NULL);
			session_state_free(state);
			state = next;
		}
		free(cfg->api_base_url);
		secure_free(cfg->proxy_auth);
		pthread_mutex_destroy(&cfg->mu);
		free(cfg);
	}
	plugin->custom = NULL;
	return TRUE;
}

static BOOL turjmp_proxy_module_entry_point(proxyPluginsManager* plugins_manager, void* userdata)
{
	(void)userdata;
	if (!plugins_manager)
		return FALSE;

	turjmpModuleConfig* cfg = calloc(1, sizeof(*cfg));
	if (!cfg)
		return FALSE;
	pthread_mutex_init(&cfg->mu, NULL);

	proxyPlugin plugin;
	memset(&plugin, 0, sizeof(plugin));
	plugin.name = TURJMP_PLUGIN_NAME;
	plugin.description = TURJMP_PLUGIN_DESC;
	plugin.PluginUnload = turjmp_plugin_unload;
	plugin.ServerPeerLogon = turjmp_server_peer_logon;
	plugin.ServerFetchTargetAddr = turjmp_server_fetch_target_addr;
	plugin.ServerPostConnect = turjmp_server_post_connect;
	plugin.ClientPostConnect = turjmp_client_post_connect;
	plugin.ClientUninitConnect = turjmp_client_uninit_connect;
	plugin.ClientLoginFailure = turjmp_client_login_failure;
	plugin.ClientPostDisconnect = turjmp_client_post_disconnect;
	plugin.ServerSessionEnd = turjmp_server_session_end;
	plugin.KeyboardEvent = turjmp_activity_filter;
	plugin.UnicodeEvent = turjmp_activity_filter;
	plugin.MouseEvent = turjmp_activity_filter;
	plugin.MouseExEvent = turjmp_activity_filter;
	plugin.ClientChannelData = turjmp_activity_filter;
	plugin.ServerChannelData = turjmp_activity_filter;
	plugin.custom = cfg;

	if (!plugins_manager->RegisterPlugin(plugins_manager, &plugin))
	{
		turjmp_plugin_unload(&plugin);
		return FALSE;
	}
	return TRUE;
}

FREERDP_API BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager, void* userdata);

BOOL proxy_module_entry_point(proxyPluginsManager* plugins_manager, void* userdata)
{
	return turjmp_proxy_module_entry_point(plugins_manager, userdata);
}
