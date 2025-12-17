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
local get_request      = require("resty.core.base").get_request
local router_new       = require("apisix.utils.router").new
local core             = require("apisix.core")
local apisix_ssl       = require("apisix.ssl")
local secret           = require("apisix.secret")
local ngx_ssl          = require("ngx.ssl")
local config_util      = require("apisix.core.config_util")
local ngx              = ngx
local ipairs           = ipairs
local type             = type
local error            = error
local str_find         = core.string.find
local str_gsub         = string.gsub
local str_lower        = string.lower
local tostring         = tostring
-- = core.config.new("/ssls", {
local ssl_certificates
--为sni创建出来的路由器, = create_router(ssl_certificates.values)
local radixtree_router
-- 为创建radixtree_router时的配置版本号   radixtree_router_ver = ssl_certificates.conf_version
local radixtree_router_ver


local _M = {
    version = 0.1,
    server_name = ngx_ssl.server_name,
}


-- 创建sni路由器，返回创建的路由器
local function create_router(ssl_items)
    local ssl_items = ssl_items or {}

    local route_items = core.table.new(#ssl_items, 0)
    local idx = 0

    -- 遍历所有的ssl元素
    for _, ssl in config_util.iterate_values(ssl_items) do
        -- https://apisix.apache.org/zh/docs/apisix/admin-api/#ssl-body-request-methods
        -- type: client 表示证书是客户端证书，APISIX 访问上游时使用；server 表示证书是服务端证书，APISIX 验证客户端请求时使用。
        if ssl.value ~= nil and ssl.value.type == "server" and
            (ssl.value.status == nil or ssl.value.status == 1) then  -- compatible with old version

            local j = 0
            local sni
            -- snis 非空数组形式，可以匹配多个 SNI。
            if type(ssl.value.snis) == "table" and #ssl.value.snis > 0 then
                sni = core.table.new(0, #ssl.value.snis)
                for _, s in ipairs(ssl.value.snis) do
                    j = j + 1
                    -- reverse, *.example.com -> moc.elpmaxe.*
                    sni[j] = s:reverse()
                end
            else
                sni = ssl.value.sni:reverse()
            end

            idx = idx + 1
            route_items[idx] = {
                -- sni作为path
                paths = sni,
                -- handler: 路由命中会时执行的回调
                handler = function (api_ctx)
                    if not api_ctx then
                        return
                    end
                    -- 设置匹配结果
                    api_ctx.matched_ssl = ssl
                    api_ctx.matched_sni = sni
                end
            }
        end
    end

    core.log.info("route items: ", core.json.delay_encode(route_items, true))
    -- for testing
    if idx > 1 then
        core.log.info("we have more than 1 ssl certs now")
    end
    -- 创建路由
    local router, err = router_new(route_items)
    if not router then
        return nil, err
    end

    return router
end


-- 设置私钥和证书
local function set_pem_ssl_key(sni, cert, pkey)
    local r = get_request()
    if r == nil then
        return false, "no request found"
    end

    -- 证书
    local parsed_cert, err = apisix_ssl.fetch_cert(sni, cert)
    if not parsed_cert then
        return false, "failed to parse PEM cert: " .. err
    end

    -- Sets the SSL certificate chain opaque pointer for the current SSL connection.
    -- https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl.md#set_priv_key
    local ok, err = ngx_ssl.set_cert(parsed_cert)
    if not ok then
        return false, "failed to set PEM cert: " .. err
    end

    -- 获取私钥
    local parsed_pkey, err = apisix_ssl.fetch_pkey(sni, pkey)
    if not parsed_pkey then
        return false, "failed to parse PEM priv key: " .. err
    end

    -- Sets the SSL private key opaque pointer for the current SSL connection.
    -- https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl.md#set_priv_key
    ok, err = ngx_ssl.set_priv_key(parsed_pkey)
    if not ok then
        return false, "failed to set PEM priv key: " .. err
    end

    return true
end
_M.set_pem_ssl_key = set_pem_ssl_key


-- 设置证书和私钥
-- export the set cert/key process so we can hook it in the other plugins
function _M.set_cert_and_key(sni, value)
    -- 设置证书和私钥
    local ok, err = set_pem_ssl_key(sni, value.cert, value.key)
    if not ok then
        return false, err
    end

    -- multiple certificates support.
    if value.certs then
        for i = 1, #value.certs do
            local cert = value.certs[i]
            local key = value.keys[i]

            ok, err = set_pem_ssl_key(sni, cert, key)
            if not ok then
                return false, err
            end
        end
    end

    return true
end


-- apisix.ssl_client_hello_phase() -> .
-- alt_sni 为 sni域名
-- 匹配结果  api_ctx.matched_ssl = ssl ; api_ctx.matched_sni = sni
function _M.match_and_set(api_ctx, match_only, alt_sni)
    local err
    -- 如果路由还未创建或/ssls配置发送了变更，则重建路由
    if not radixtree_router or
       radixtree_router_ver ~= ssl_certificates.conf_version then
        -- 构建sni路由
        radixtree_router, err = create_router(ssl_certificates.values)
        if not radixtree_router then
            return false, "failed to create radixtree router: " .. err
        end
        -- 记录此时配置版本
        radixtree_router_ver = ssl_certificates.conf_version
    end

    local sni = alt_sni
    if not sni then
        -- 获取sni
        sni, err = apisix_ssl.server_name()
        if type(sni) ~= "string" then
            local advise = "please check if the client requests via IP or uses an outdated " ..
                           "protocol. If you need to report an issue, " ..
                           "provide a packet capture file of the TLS handshake."
            return false, "failed to find SNI: " .. (err or advise)
        end
    end

    core.log.debug("sni: ", sni)

    -- sni反转后进行匹配
    local sni_rev = sni:reverse()
    local ok = radixtree_router:dispatch(sni_rev, nil, api_ctx)
    if not ok then
        if not alt_sni then
            -- it is expected that alternative SNI doesn't have a SSL certificate associated
            -- with it sometimes
            core.log.error("failed to find any SSL certificate by SNI: ", sni)
        end
        return false
    end


    if api_ctx.matched_sni == "*" then
        -- wildcard matches everything, no need for further validation
        core.log.info("matched wildcard SSL for SNI: ", sni)
        -- 当一个证书对应多个sni时，matched_sni为一个table
    elseif type(api_ctx.matched_sni) == "table" then
        local matched = false
        for _, msni in ipairs(api_ctx.matched_sni) do
            if sni_rev == msni or not str_find(sni_rev, ".", #msni) then
                matched = true
                break
            end
        end
        if not matched then
            local log_snis = core.json.encode(api_ctx.matched_sni, true)
            if log_snis ~= nil then
                log_snis = str_gsub(log_snis:reverse(), "%[", "%]")
                log_snis = str_gsub(log_snis, "%]", "%[", 1)
            end
            core.log.warn("failed to find any SSL certificate by SNI: ",
                          sni, " matched SNIs: ", log_snis)
            return false
        end
    else
        -- sni为一个string
        if str_find(sni_rev, ".", #api_ctx.matched_sni) then
            core.log.warn("failed to find any SSL certificate by SNI: ",
                          sni, " matched SNI: ", api_ctx.matched_sni:reverse())
            return false
        end
    end

    core.log.info("debug - matched: ", core.json.delay_encode(api_ctx.matched_ssl, true))

    if match_only then
        return true
    end

    -- 重设证书
    ok, err = _M.set(api_ctx.matched_ssl, sni)
    if not ok then
        return false, err
    end

    return true
end

-- 根据sni匹配结果，重置证书
function _M.set(matched_ssl, sni)
    if not matched_ssl then
        return false, "failed to match ssl certificate"
    end
    local ok, err
    if not sni then
        sni, err = apisix_ssl.server_name()
        if type(sni) ~= "string" then
            local advise = "please check if the client requests via IP or uses an outdated " ..
                           "protocol. If you need to report an issue, " ..
                           "provide a packet capture file of the TLS handshake."
            return false, "failed to find SNI: " .. (err or advise)
        end
    end
    -- https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl.md#clear_certs
    ngx_ssl.clear_certs()

    -- 如果matched_ssl.value不是以$开头，则返回 nil
    local new_ssl_value = secret.fetch_secrets(matched_ssl.value, true)
                            or matched_ssl.value

    -- 设置证书和私钥
    ok, err = _M.set_cert_and_key(sni, new_ssl_value)
    if not ok then
        return false, err
    end

    -- 如果是客户端证书
    if matched_ssl.value.client then
        local ca_cert = matched_ssl.value.client.ca
        local depth = matched_ssl.value.client.depth
        -- 客户端证书校验
        if apisix_ssl.support_client_verification() then
            local parsed_cert, err = apisix_ssl.fetch_cert(sni, ca_cert)
            if not parsed_cert then
                return false, "failed to parse client cert: " .. err
            end

            local reject_in_handshake =
                (ngx.config.subsystem == "stream") or
                (matched_ssl.value.client.skip_mtls_uri_regex == nil)
            -- TODO: support passing `trusted_certs` (3rd arg, keep it nil for now)
            -- https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl.md#verify_client
            local ok, err = ngx_ssl.verify_client(parsed_cert, depth, nil,
                reject_in_handshake)
            if not ok then
                return false, err
            end
        end
    end

    return true
end


function _M.ssls()
    if not ssl_certificates then
        return nil, nil
    end

    return ssl_certificates.values, ssl_certificates.conf_version
end


local function ssl_filter(ssl)
    if not ssl.value then
        return
    end

    if ssl.value.sni then
        ssl.value.sni = ngx.re.sub(ssl.value.sni, "\\.$", "", "jo")
        ssl.value.sni = str_lower(ssl.value.sni)
    elseif ssl.value.snis then
        for i, v in ipairs(ssl.value.snis) do
            v = ngx.re.sub(v, "\\.$", "", "jo")
            ssl.value.snis[i] = str_lower(v)
        end
    end
end


-- apisix.http_init_worker() --> apisix.router.http_init_worker() -> .
function _M.init_worker()
    local err
    ssl_certificates, err = core.config.new("/ssls", {
        automatic = true,
        item_schema = core.schema.ssl,
        checker = function (item, schema_type)
            -- schema 校验
            return apisix_ssl.check_ssl_conf(true, item)
        end,
        filter = ssl_filter,
    })
    if not ssl_certificates then
        error("failed to create etcd instance for fetching ssl certificates: "
              .. err)
    end
end


function _M.get_by_id(ssl_id)
    local ssl
    local ssls = core.config.fetch_created_obj("/ssls")
    if ssls then
        ssl = ssls:get(tostring(ssl_id))
    end

    if not ssl then
        return nil
    end

    return ssl.value
end


return _M
