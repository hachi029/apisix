--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- 用于生成nginx.conf的模版
return [=[
# Configuration File - Nginx Server Configs
# This is a read-only file, do not try to modify it.
{% if user and user ~= '' then %}
user {* user *};
{% end %}
master_process on;

worker_processes {* worker_processes *};
{% if os_name == "Linux" and enable_cpu_affinity == true then %}
worker_cpu_affinity auto;
{% end %}

# main configuration snippet starts
{% if main_configuration_snippet then %}
{* main_configuration_snippet *}
{% end %}
# main configuration snippet ends

error_log {* error_log *} {* error_log_level or "warn" *};
pid logs/nginx.pid;

worker_rlimit_nofile {* worker_rlimit_nofile *};

events {
    accept_mutex off;
    worker_connections {* event.worker_connections *};
}

worker_rlimit_core  {* worker_rlimit_core *};

worker_shutdown_timeout {* worker_shutdown_timeout *};

env APISIX_PROFILE;
env PATH; # for searching external plugin runner's binary

# reserved environment variables for configuration
env APISIX_DEPLOYMENT_ETCD_HOST;

{% if envs then %}
{% for _, name in ipairs(envs) do %}
env {*name*};
{% end %}
{% end %}

{% if use_apisix_base then %}
thread_pool grpc-client-nginx-module threads=1;

lua {
    {% if enabled_stream_plugins["prometheus"] then %}
    lua_shared_dict prometheus-metrics {* meta.lua_shared_dict["prometheus-metrics"] *};
    {% end %}
}

{% if enabled_stream_plugins["prometheus"] and not enable_http then %}
http {
    lua_package_path  "{*extra_lua_path*}$prefix/deps/share/lua/5.1/?.lua;$prefix/deps/share/lua/5.1/?/init.lua;]=]
                       .. [=[{*apisix_lua_home*}/?.lua;{*apisix_lua_home*}/?/init.lua;;{*lua_path*};";
    lua_package_cpath "{*extra_lua_cpath*}$prefix/deps/lib64/lua/5.1/?.so;]=]
                      .. [=[$prefix/deps/lib/lua/5.1/?.so;;]=]
                      .. [=[{*lua_cpath*};";

    {% if enabled_stream_plugins["prometheus"] then %}

    init_by_lua_block {
        require "resty.core"
        local process = require("ngx.process")
        local ok, err = process.enable_privileged_agent()
        if not ok then
            ngx.log(ngx.ERR, "failed to enable privileged_agent: ", err)
        end
    }

    init_worker_by_lua_block {
        require("apisix.plugins.prometheus.exporter").http_init(true)
    }

    server {
        {% if use_apisix_base then %}
            listen {* prometheus_server_addr *} enable_process=privileged_agent;
        {% else %}
            listen {* prometheus_server_addr *};
        {% end %}

        access_log off;

        location / {
            content_by_lua_block {
                local prometheus = require("apisix.plugins.prometheus.exporter")
                prometheus.export_metrics(true)
            }
        }

        location = /apisix/nginx_status {
            allow 127.0.0.0/24;
            deny all;
            stub_status;
        }
    }
    {% end %}
}
{% end %}

{% end %}

{% if enable_stream then %}
stream {
    lua_package_path  "{*extra_lua_path*}$prefix/deps/share/lua/5.1/?.lua;$prefix/deps/share/lua/5.1/?/init.lua;]=]
                      .. [=[{*apisix_lua_home*}/?.lua;{*apisix_lua_home*}/?/init.lua;;{*lua_path*};";
    lua_package_cpath "{*extra_lua_cpath*}$prefix/deps/lib64/lua/5.1/?.so;]=]
                      .. [=[$prefix/deps/lib/lua/5.1/?.so;;]=]
                      .. [=[{*lua_cpath*};";
    lua_socket_log_errors off;

    {% if max_pending_timers then %}
    lua_max_pending_timers {* max_pending_timers *};
    {% end %}
    {% if max_running_timers then %}
    lua_max_running_timers {* max_running_timers *};
    {% end %}

    lua_shared_dict lrucache-lock-stream {* stream.lua_shared_dict["lrucache-lock-stream"] *};
    lua_shared_dict etcd-cluster-health-check-stream {* stream.lua_shared_dict["etcd-cluster-health-check-stream"] *};
    lua_shared_dict worker-events-stream {* stream.lua_shared_dict["worker-events-stream"] *};

    {% if enabled_discoveries["tars"] then %}
    lua_shared_dict tars-stream {* stream.lua_shared_dict["tars-stream"] *};
    {% end %}

    {% if enabled_stream_plugins["limit-conn"] then %}
    lua_shared_dict plugin-limit-conn-stream {* stream.lua_shared_dict["plugin-limit-conn-stream"] *};
    {% end %}

    # for discovery shared dict
    {% if discovery_shared_dicts then %}
    {% for key, size in pairs(discovery_shared_dicts) do %}
    lua_shared_dict {*key*}-stream {*size*};
    {% end %}
    {% end %}

    resolver {% for _, dns_addr in ipairs(dns_resolver or {}) do %} {*dns_addr*} {% end %} {% if dns_resolver_valid then %} valid={*dns_resolver_valid*}{% end %} ipv6={% if enable_ipv6 then %}on{% else %}off{% end %};
    resolver_timeout {*resolver_timeout*};

    {% if ssl.ssl_trusted_certificate ~= nil then %}
    lua_ssl_trusted_certificate {* ssl.ssl_trusted_certificate *};
    {% end %}

    # for stream logs, off by default
    {% if stream.enable_access_log == true then %}
    log_format main escape={* stream.access_log_format_escape *} '{* stream.access_log_format *}';

    access_log {* stream.access_log *} main buffer=16384 flush=3;
    {% end %}

    # stream configuration snippet starts
    {% if stream_configuration_snippet then %}
    {* stream_configuration_snippet *}
    {% end %}
    # stream configuration snippet ends

    upstream apisix_backend {
        server 127.0.0.1:80;
        balancer_by_lua_block {
            apisix.stream_balancer_phase()
        }
    }

    init_by_lua_block {
        require "resty.core"
        {% if lua_module_hook then %}
        require "{* lua_module_hook *}"
        {% end %}
        apisix = require("apisix")
        local dns_resolver = { {% for _, dns_addr in ipairs(dns_resolver or {}) do %} "{*dns_addr*}", {% end %} }
        local args = {
            dns_resolver = dns_resolver,
        }
        apisix.stream_init(args)
    }

    init_worker_by_lua_block {
        apisix.stream_init_worker()
    }

    {% if (events.module or "") == "lua-resty-events" then %}
    # the server block for lua-resty-events
    server {
        listen unix:{*apisix_lua_home*}/logs/stream_worker_events.sock;
        access_log off;
        content_by_lua_block {
            require("resty.events.compat").run()
        }
    }
    {% end %}

    server {
        {% for _, item in ipairs(stream_proxy.tcp or {}) do %}
        listen {*item.addr*} {% if item.tls then %} ssl {% end %} {% if enable_reuseport then %} reuseport {% end %} {% if proxy_protocol and proxy_protocol.enable_tcp_pp then %} proxy_protocol {% end %};
        {% end %}
        {% for _, addr in ipairs(stream_proxy.udp or {}) do %}
        listen {*addr*} udp {% if enable_reuseport then %} reuseport {% end %};
        {% end %}

        {% if tcp_enable_ssl then %}
        ssl_certificate      {* ssl.ssl_cert *};
        ssl_certificate_key  {* ssl.ssl_cert_key *};

        ssl_certificate_by_lua_block {
            apisix.stream_ssl_phase()
        }
        {% end %}

        {% if proxy_protocol and proxy_protocol.enable_tcp_pp_to_upstream then %}
        proxy_protocol on;
        {% end %}

        preread_by_lua_block {
            apisix.stream_preread_phase()
        }

        proxy_pass apisix_backend;

        {% if use_apisix_base then %}
        set $upstream_sni "apisix_backend";
        proxy_ssl_server_name on;
        proxy_ssl_name $upstream_sni;
        {% end %}

        log_by_lua_block {
            apisix.stream_log_phase()
        }
    }
}
{% end %}

{% if enable_http then %}
http {
    # put extra_lua_path in front of the builtin path
    # so user can override the source code
    lua_package_path  "{*extra_lua_path*}$prefix/deps/share/lua/5.1/?.lua;$prefix/deps/share/lua/5.1/?/init.lua;]=]
                       .. [=[{*apisix_lua_home*}/?.lua;{*apisix_lua_home*}/?/init.lua;;{*lua_path*};";
    lua_package_cpath "{*extra_lua_cpath*}$prefix/deps/lib64/lua/5.1/?.so;]=]
                      .. [=[$prefix/deps/lib/lua/5.1/?.so;;]=]
                      .. [=[{*lua_cpath*};";

    {% if max_pending_timers then %}
    lua_max_pending_timers {* max_pending_timers *};
    {% end %}
    {% if max_running_timers then %}
    lua_max_running_timers {* max_running_timers *};
    {% end %}

    lua_shared_dict internal-status {* http.lua_shared_dict["internal-status"] *};
    lua_shared_dict upstream-healthcheck {* http.lua_shared_dict["upstream-healthcheck"] *};
    lua_shared_dict worker-events {* http.lua_shared_dict["worker-events"] *};
    lua_shared_dict lrucache-lock {* http.lua_shared_dict["lrucache-lock"] *};
    lua_shared_dict balancer-ewma {* http.lua_shared_dict["balancer-ewma"] *};
    lua_shared_dict balancer-ewma-locks {* http.lua_shared_dict["balancer-ewma-locks"] *};
    lua_shared_dict balancer-ewma-last-touched-at {* http.lua_shared_dict["balancer-ewma-last-touched-at"] *};
    lua_shared_dict etcd-cluster-health-check {* http.lua_shared_dict["etcd-cluster-health-check"] *}; # etcd health check

    # for discovery shared dict
    {% if discovery_shared_dicts then %}
    {% for key, size in pairs(discovery_shared_dicts) do %}
    lua_shared_dict {*key*} {*size*};
    {% end %}
    {% end %}

    {% if enabled_discoveries["tars"] then %}
    lua_shared_dict tars {* http.lua_shared_dict["tars"] *};
    {% end %}


    {% if http.lua_shared_dict["plugin-ai-rate-limiting"] then %}
    lua_shared_dict plugin-ai-rate-limiting {* http.lua_shared_dict["plugin-ai-rate-limiting"] *};
    {% else %}
    lua_shared_dict plugin-ai-rate-limiting 10m;
    {% end %}

    {% if http.lua_shared_dict["plugin-ai-rate-limiting"] then %}
    lua_shared_dict plugin-ai-rate-limiting-reset-header {* http.lua_shared_dict["plugin-ai-rate-limiting-reset-header"] *};
    {% else %}
    lua_shared_dict plugin-ai-rate-limiting-reset-header 10m;
    {% end %}

    {% if enabled_plugins["limit-conn"] then %}
    lua_shared_dict plugin-limit-conn {* http.lua_shared_dict["plugin-limit-conn"] *};
    lua_shared_dict plugin-limit-conn-redis-cluster-slot-lock {* http.lua_shared_dict["plugin-limit-conn-redis-cluster-slot-lock"] *};
    {% end %}

    {% if enabled_plugins["limit-req"] then %}
    lua_shared_dict plugin-limit-req-redis-cluster-slot-lock {* http.lua_shared_dict["plugin-limit-req-redis-cluster-slot-lock"] *};
    lua_shared_dict plugin-limit-req {* http.lua_shared_dict["plugin-limit-req"] *};
    {% end %}

    {% if enabled_plugins["limit-count"] then %}
    lua_shared_dict plugin-limit-count {* http.lua_shared_dict["plugin-limit-count"] *};
    lua_shared_dict plugin-limit-count-redis-cluster-slot-lock {* http.lua_shared_dict["plugin-limit-count-redis-cluster-slot-lock"] *};
    lua_shared_dict plugin-limit-count-reset-header {* http.lua_shared_dict["plugin-limit-count"] *};
    {% end %}

    {% if enabled_plugins["prometheus"] and not enabled_stream_plugins["prometheus"] then %}
    lua_shared_dict prometheus-metrics {* http.lua_shared_dict["prometheus-metrics"] *};
    {% end %}

    {% if enabled_plugins["skywalking"] then %}
    lua_shared_dict tracing_buffer {* http.lua_shared_dict.tracing_buffer *}; # plugin: skywalking
    {% end %}

    {% if enabled_plugins["api-breaker"] then %}
    lua_shared_dict plugin-api-breaker {* http.lua_shared_dict["plugin-api-breaker"] *};
    {% end %}

    {% if enabled_plugins["openid-connect"] or enabled_plugins["authz-keycloak"] then %}
    # for openid-connect and authz-keycloak plugin
    lua_shared_dict discovery {* http.lua_shared_dict["discovery"] *}; # cache for discovery metadata documents
    {% end %}

    {% if enabled_plugins["openid-connect"] then %}
    # for openid-connect plugin
    lua_shared_dict jwks {* http.lua_shared_dict["jwks"] *}; # cache for JWKs
    lua_shared_dict introspection {* http.lua_shared_dict["introspection"] *}; # cache for JWT verification results
    {% end %}

    {% if enabled_plugins["cas-auth"] then %}
    lua_shared_dict cas_sessions {* http.lua_shared_dict["cas-auth"] *};
    {% end %}

    {% if enabled_plugins["authz-keycloak"] then %}
    # for authz-keycloak
    lua_shared_dict access-tokens {* http.lua_shared_dict["access-tokens"] *}; # cache for service account access tokens
    {% end %}

    {% if enabled_plugins["ocsp-stapling"] then %}
    lua_shared_dict ocsp-stapling {* http.lua_shared_dict["ocsp-stapling"] *}; # cache for ocsp-stapling
    {% end %}

    {% if enabled_plugins["ext-plugin-pre-req"] or enabled_plugins["ext-plugin-post-req"] then %}
    lua_shared_dict ext-plugin {* http.lua_shared_dict["ext-plugin"] *}; # cache for ext-plugin
    {% end %}

    {% if config_center == "xds" then %}
    lua_shared_dict xds-config  10m;
    lua_shared_dict xds-config-version  1m;
    {% end %}

    # for custom shared dict
    {% if http.custom_lua_shared_dict then %}
    {% for cache_key, cache_size in pairs(http.custom_lua_shared_dict) do %}
    lua_shared_dict {*cache_key*} {*cache_size*};
    {% end %}
    {% end %}

    {% if enabled_plugins["error-log-logger"] then %}
        lua_capture_error_log  10m;
    {% end %}

    lua_ssl_verify_depth 5;
    ssl_session_timeout 86400;

    {% if http.underscores_in_headers then %}
    underscores_in_headers {* http.underscores_in_headers *};
    {%end%}

    lua_socket_log_errors off;

    resolver {% for _, dns_addr in ipairs(dns_resolver or {}) do %} {*dns_addr*} {% end %} {% if dns_resolver_valid then %} valid={*dns_resolver_valid*}{% end %} ipv6={% if enable_ipv6 then %}on{% else %}off{% end %};
    resolver_timeout {*resolver_timeout*};

    lua_http10_buffering off;

    lua_regex_match_limit 100000;
    lua_regex_cache_max_entries 8192;

    {% if http.enable_access_log == false then %}
    access_log off;
    {% else %}
    log_format main escape={* http.access_log_format_escape *} '{* http.access_log_format *}';
    uninitialized_variable_warn off;

    {% if http.access_log_buffer then %}
    access_log {* http.access_log *} main buffer={* http.access_log_buffer *} flush=3;
    {% else %}
    access_log {* http.access_log *} main buffer=16384 flush=3;
    {% end %}
    {% end %}
    open_file_cache  max=1000 inactive=60;
    client_max_body_size {* http.client_max_body_size *};
    keepalive_timeout {* http.keepalive_timeout *};
    client_header_timeout {* http.client_header_timeout *};
    client_body_timeout {* http.client_body_timeout *};
    send_timeout {* http.send_timeout *};
    variables_hash_max_size {* http.variables_hash_max_size *};

    server_tokens off;

    include mime.types;
    charset {* http.charset *};

    {% if http.real_ip_header then %}
    real_ip_header {* http.real_ip_header *};
    {% end %}

    {% if http.real_ip_recursive then %}
    real_ip_recursive {* http.real_ip_recursive *};
    {% end %}

    {% if http.real_ip_from then %}
    {% for _, real_ip in ipairs(http.real_ip_from) do %}
    set_real_ip_from {*real_ip*};
    {% end %}
    {% end %}

    {% if ssl.ssl_trusted_certificate ~= nil then %}
    lua_ssl_trusted_certificate {* ssl.ssl_trusted_certificate *};
    {% end %}
    # http configuration snippet starts
    {% if http_configuration_snippet then %}
    {* http_configuration_snippet *}
    {% end %}
    # http configuration snippet ends

    upstream apisix_backend {
        server 0.0.0.1;

        {% if use_apisix_base then %}
        keepalive {* http.upstream.keepalive *};
        keepalive_requests {* http.upstream.keepalive_requests *};
        keepalive_timeout {* http.upstream.keepalive_timeout *};
        # we put the static configuration above so that we can override it in the Lua code

        balancer_by_lua_block {
            apisix.http_balancer_phase()
        }
        {% else %}
        balancer_by_lua_block {
            apisix.http_balancer_phase()
        }

        keepalive {* http.upstream.keepalive *};
        keepalive_requests {* http.upstream.keepalive_requests *};
        keepalive_timeout {* http.upstream.keepalive_timeout *};
        {% end %}
    }

    {% if enabled_plugins["dubbo-proxy"] then %}
    upstream apisix_dubbo_backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            apisix.http_balancer_phase()
        }

        # dynamical keepalive doesn't work with dubbo as the connection here
        # is managed by ngx_multi_upstream_module
        multi {* dubbo_upstream_multiplex_count *};
        keepalive {* http.upstream.keepalive *};
        keepalive_requests {* http.upstream.keepalive_requests *};
        keepalive_timeout {* http.upstream.keepalive_timeout *};
    }
    {% end %}

    {% if use_apisix_base then %}
    apisix_delay_client_max_body_check on;
    apisix_mirror_on_demand on;
    {% end %}

    {% if wasm then %}
    wasm_vm wasmtime;
    {% end %}

    init_by_lua_block {
        require "resty.core"
        {% if lua_module_hook then %}
        require "{* lua_module_hook *}"
        {% end %}
        apisix = require("apisix")

        local dns_resolver = { {% for _, dns_addr in ipairs(dns_resolver or {}) do %} "{*dns_addr*}", {% end %} }
        local args = {
            dns_resolver = dns_resolver,
        }
        apisix.http_init(args)

        -- set apisix_lua_home into constants module
        -- it may be used by plugins to determine the work path of apisix
        local constants = require("apisix.constants")
        constants.apisix_lua_home = "{*apisix_lua_home*}"
    }

    init_worker_by_lua_block {
        apisix.http_init_worker()
    }

    exit_worker_by_lua_block {
        apisix.http_exit_worker()
    }

    {% if (events.module or "") == "lua-resty-events" then %}
    # the server block for lua-resty-events
    server {
        listen unix:{*apisix_lua_home*}/logs/worker_events.sock;
        access_log off;
        location / {
            content_by_lua_block {
                require("resty.events.compat").run()
            }
        }
    }
    {% end %}

    {% if enable_control then %}
    server {
        listen {* control_server_addr *};

        access_log off;

        location / {
            content_by_lua_block {
                apisix.http_control()
            }
        }
    }
    {% end %}

    {% if enabled_plugins["prometheus"] and prometheus_server_addr then %}
    server {
        {% if use_apisix_base then %}
            listen {* prometheus_server_addr *} enable_process=privileged_agent;
        {% else %}
            listen {* prometheus_server_addr *};
        {% end %}

        access_log off;

        location / {
            content_by_lua_block {
                local prometheus = require("apisix.plugins.prometheus.exporter")
                prometheus.export_metrics()
            }
        }

        location = /apisix/nginx_status {
            allow 127.0.0.0/24;
            deny all;
            stub_status;
        }
    }
    {% end %}

    {% if enable_admin then %}
    server {
        {%if https_admin then%}
        listen {* admin_server_addr *} ssl;

        ssl_certificate      {* admin_api_mtls.admin_ssl_cert *};
        ssl_certificate_key  {* admin_api_mtls.admin_ssl_cert_key *};
        {%if admin_api_mtls.admin_ssl_ca_cert and admin_api_mtls.admin_ssl_ca_cert ~= "" then%}
        ssl_verify_client on;
        ssl_client_certificate {* admin_api_mtls.admin_ssl_ca_cert *};
        {% end %}

        ssl_session_cache    shared:SSL:20m;
        ssl_protocols {* ssl.ssl_protocols *};
        ssl_ciphers {* ssl.ssl_ciphers *};
        ssl_prefer_server_ciphers on;
        {% if ssl.ssl_session_tickets then %}
        ssl_session_tickets on;
        {% else %}
        ssl_session_tickets off;
        {% end %}

        {% else %}
        listen {* admin_server_addr *};
        {%end%}
        log_not_found off;

        # admin configuration snippet starts
        {% if http_admin_configuration_snippet then %}
        {* http_admin_configuration_snippet *}
        {% end %}
        # admin configuration snippet ends

        set $upstream_scheme             'http';
        set $upstream_host               $http_host;
        set $upstream_uri                '';

        location /apisix/admin {
            {%if allow_admin then%}
                {% for _, allow_ip in ipairs(allow_admin) do %}
                allow {*allow_ip*};
                {% end %}
                deny all;
            {%else%}
                allow all;
            {%end%}

            content_by_lua_block {
                apisix.http_admin()
            }
        }
    }
    {% end %}

    {% if deployment_role ~= "control_plane" then %}

    {% if enabled_plugins["proxy-cache"] then %}
    # for proxy cache
    {% for _, cache in ipairs(proxy_cache.zones) do %}
    {% if cache.disk_path and cache.cache_levels and cache.disk_size then %}
    proxy_cache_path {* cache.disk_path *} levels={* cache.cache_levels *} keys_zone={* cache.name *}:{* cache.memory_size *} inactive=1d max_size={* cache.disk_size *} use_temp_path=off;
    {% else %}
    lua_shared_dict {* cache.name *} {* cache.memory_size *};
    {% end %}
    {% end %}

    map $upstream_cache_zone $upstream_cache_zone_info {
    {% for _, cache in ipairs(proxy_cache.zones) do %}
    {% if cache.disk_path and cache.cache_levels and cache.disk_size then %}
        {* cache.name *} {* cache.disk_path *},{* cache.cache_levels *};
    {% end %}
    {% end %}
    }
    {% end %}

    server {
        {% if enable_http2 then %}
        http2 on;
        {% end %}
        {% if enable_http3_in_server_context then %}
        http3 on;
        {% end %}
        {% for _, item in ipairs(node_listen) do %}
        listen {* item.ip *}:{* item.port *} default_server {% if enable_reuseport then %} reuseport {% end %};
        {% end %}
        {% if ssl.enable then %}
        {% for _, item in ipairs(ssl.listen) do %}
        {% if item.enable_http3 then %}
        listen {* item.ip *}:{* item.port *} quic default_server {% if enable_reuseport then %} reuseport {% end %};
        listen {* item.ip *}:{* item.port *} ssl default_server;
        {% else %}
        listen {* item.ip *}:{* item.port *} ssl default_server {% if enable_reuseport then %} reuseport {% end %};
        {% end %}
        {% end %}
        {% end %}
        {% if proxy_protocol and proxy_protocol.listen_http_port then %}
        listen {* proxy_protocol.listen_http_port *} default_server proxy_protocol;
        {% end %}
        {% if proxy_protocol and proxy_protocol.listen_https_port then %}
        listen {* proxy_protocol.listen_https_port *} ssl default_server proxy_protocol;
        {% end %}

        server_name _;

        {% if ssl.enable then %}
        ssl_certificate      {* ssl.ssl_cert *};
        ssl_certificate_key  {* ssl.ssl_cert_key *};
        ssl_session_cache    shared:SSL:20m;
        ssl_session_timeout 10m;

        ssl_protocols {* ssl.ssl_protocols *};
        ssl_ciphers {* ssl.ssl_ciphers *};
        ssl_prefer_server_ciphers on;
        {% if ssl.ssl_session_tickets then %}
        ssl_session_tickets on;
        {% else %}
        ssl_session_tickets off;
        {% end %}
        {% end %}

        {% if ssl.ssl_trusted_certificate ~= nil then %}
        proxy_ssl_trusted_certificate {* ssl.ssl_trusted_certificate *};
        {% end %}

        # opentelemetry_set_ngx_var starts
        {% if opentelemetry_set_ngx_var then %}
        set $opentelemetry_context_traceparent          '';
        set $opentelemetry_trace_id                     '';
        set $opentelemetry_span_id                      '';
        {% end %}
        # opentelemetry_set_ngx_var ends

        # zipkin_set_ngx_var starts
        {% if zipkin_set_ngx_var then %}
        set $zipkin_context_traceparent          '';
        set $zipkin_trace_id                     '';
        set $zipkin_span_id                      '';
        {% end %}
        # zipkin_set_ngx_var ends

        # http server configuration snippet starts
        {% if http_server_configuration_snippet then %}
        {* http_server_configuration_snippet *}
        {% end %}
        # http server configuration snippet ends

        location = /apisix/nginx_status {
            allow 127.0.0.0/24;
            deny all;
            access_log off;
            stub_status;
        }

        {% if ssl.enable then %}
        ssl_client_hello_by_lua_block {
            apisix.http_ssl_client_hello_phase()
        }

        ssl_certificate_by_lua_block {
            apisix.http_ssl_phase()
        }
        {% end %}

        {% if http.proxy_ssl_server_name then %}
        proxy_ssl_name $upstream_host;
        proxy_ssl_server_name on;
        {% end %}

        location / {
            set $upstream_mirror_host        '';
            set $upstream_mirror_uri         '';
            set $upstream_upgrade            '';
            set $upstream_connection         '';

            set $upstream_scheme             'http';
            set $upstream_host               $http_host;
            set $upstream_uri                '';
            set $ctx_ref                     '';

            {% if wasm then %}
            set $wasm_process_req_body       '';
            set $wasm_process_resp_body      '';
            {% end %}

            # http server location configuration snippet starts
            {% if http_server_location_configuration_snippet then %}
            {* http_server_location_configuration_snippet *}
            {% end %}
            # http server location configuration snippet ends

            {% if enabled_plugins["dubbo-proxy"] then %}
            set $dubbo_service_name          '';
            set $dubbo_service_version       '';
            set $dubbo_method                '';
            {% end %}

            access_by_lua_block {
                apisix.http_access_phase()
            }

            proxy_http_version 1.1;
            proxy_set_header   Host              $upstream_host;
            proxy_set_header   Upgrade           $upstream_upgrade;
            proxy_set_header   Connection        $upstream_connection;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_pass_header  Date;

            ### the following x-forwarded-* headers is to send to upstream server

            set $var_x_forwarded_proto      $scheme;
            set $var_x_forwarded_host       $host;
            set $var_x_forwarded_port       $server_port;

            proxy_set_header   X-Forwarded-For      $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto    $var_x_forwarded_proto;
            proxy_set_header   X-Forwarded-Host     $var_x_forwarded_host;
            proxy_set_header   X-Forwarded-Port     $var_x_forwarded_port;

            {% if enabled_plugins["proxy-cache"] then %}
            ###  the following configuration is to cache response content from upstream server

            set $upstream_cache_zone            off;
            set $upstream_cache_key             '';
            set $upstream_cache_bypass          '';
            set $upstream_no_cache              '';

            proxy_cache                         $upstream_cache_zone;
            proxy_cache_valid                   any {% if proxy_cache.cache_ttl then %} {* proxy_cache.cache_ttl *} {% else %} 10s {% end %};
            proxy_cache_min_uses                1;
            proxy_cache_methods                 GET HEAD POST;
            proxy_cache_lock_timeout            5s;
            proxy_cache_use_stale               off;
            proxy_cache_key                     $upstream_cache_key;
            proxy_no_cache                      $upstream_no_cache;
            proxy_cache_bypass                  $upstream_cache_bypass;

            {% end %}

            proxy_pass      $upstream_scheme://apisix_backend$upstream_uri;

            {% if enabled_plugins["proxy-mirror"] then %}
            mirror          /proxy_mirror;
            {% end %}

            header_filter_by_lua_block {
                apisix.http_header_filter_phase()
            }

            body_filter_by_lua_block {
                apisix.http_body_filter_phase()
            }

            log_by_lua_block {
                apisix.http_log_phase()
            }
        }

        location @grpc_pass {

            access_by_lua_block {
                apisix.grpc_access_phase()
            }

            {% if use_apisix_base then %}
            # For servers which obey the standard, when `:authority` is missing,
            # `host` will be used instead. When used with apisix-runtime, we can do
            # better by setting `:authority` directly
            grpc_set_header   ":authority" $upstream_host;
            {% else %}
            grpc_set_header   "Host" $upstream_host;
            {% end %}
            grpc_set_header   Content-Type application/grpc;
            grpc_set_header   TE trailers;
            grpc_socket_keepalive on;
            grpc_pass         $upstream_scheme://apisix_backend;

            {% if enabled_plugins["proxy-mirror"] then %}
            mirror           /proxy_mirror_grpc;
            {% end %}

            header_filter_by_lua_block {
                apisix.http_header_filter_phase()
            }

            body_filter_by_lua_block {
                apisix.http_body_filter_phase()
            }

            log_by_lua_block {
                apisix.http_log_phase()
            }
        }

        {% if enabled_plugins["dubbo-proxy"] then %}
        location @dubbo_pass {
            access_by_lua_block {
                apisix.dubbo_access_phase()
            }

            dubbo_pass_all_headers on;
            dubbo_pass_body on;
            dubbo_pass $dubbo_service_name $dubbo_service_version $dubbo_method apisix_dubbo_backend;

            header_filter_by_lua_block {
                apisix.http_header_filter_phase()
            }

            body_filter_by_lua_block {
                apisix.http_body_filter_phase()
            }

            log_by_lua_block {
                apisix.http_log_phase()
            }
        }
        {% end %}

        {% if enabled_plugins["proxy-mirror"] then %}
        location = /proxy_mirror {
            internal;

            {% if not use_apisix_base then %}
            if ($upstream_mirror_uri = "") {
                return 200;
            }
            {% end %}


            {% if proxy_mirror_timeouts then %}
                {% if proxy_mirror_timeouts.connect then %}
            proxy_connect_timeout {* proxy_mirror_timeouts.connect *};
                {% end %}
                {% if proxy_mirror_timeouts.read then %}
            proxy_read_timeout {* proxy_mirror_timeouts.read *};
                {% end %}
                {% if proxy_mirror_timeouts.send then %}
            proxy_send_timeout {* proxy_mirror_timeouts.send *};
                {% end %}
            {% end %}
            proxy_http_version 1.1;
            proxy_set_header Host $upstream_host;
            proxy_pass $upstream_mirror_uri;
        }
        {% end %}

        {% if enabled_plugins["proxy-mirror"] then %}
        location = /proxy_mirror_grpc {
            internal;

            {% if not use_apisix_base then %}
            if ($upstream_mirror_uri = "") {
                return 200;
            }
            {% end %}


            {% if proxy_mirror_timeouts then %}
                {% if proxy_mirror_timeouts.connect then %}
            grpc_connect_timeout {* proxy_mirror_timeouts.connect *};
                {% end %}
                {% if proxy_mirror_timeouts.read then %}
            grpc_read_timeout {* proxy_mirror_timeouts.read *};
                {% end %}
                {% if proxy_mirror_timeouts.send then %}
            grpc_send_timeout {* proxy_mirror_timeouts.send *};
                {% end %}
            {% end %}
            grpc_pass $upstream_mirror_host;
        }
        {% end %}
    }
    {% end %}

    # http end configuration snippet starts
    {% if http_end_configuration_snippet then %}
    {* http_end_configuration_snippet *}
    {% end %}
    # http end configuration snippet ends
}
{% end %}
]=]
