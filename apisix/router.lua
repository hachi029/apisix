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
local require = require
local http_route = require("apisix.http.route")
local apisix_upstream = require("apisix.upstream")
local core    = require("apisix.core")
local str_lower = string.lower
local ipairs  = ipairs


local _M = {version = 0.3}


local function filter(route)
    route.orig_modifiedIndex = route.modifiedIndex

    route.has_domain = false
    if not route.value then
        return
    end

    if route.value.host then
        route.value.host = str_lower(route.value.host)
    elseif route.value.hosts then
        for i, v in ipairs(route.value.hosts) do
            route.value.hosts[i] = str_lower(v)
        end
    end

    apisix_upstream.filter_upstream(route.value.upstream, route)

    core.log.info("filter route: ", core.json.delay_encode(route, true))
end


-- attach common methods if the router doesn't provide its custom implementation
local function attach_http_router_common_methods(http_router)
    -- http_router.routes()返回的是 config_etcd.values
    if http_router.routes == nil then
        http_router.routes = function ()
            if not http_router.user_routes then
                return nil, nil
            end

            local user_routes = http_router.user_routes
            return user_routes.values, user_routes.conf_version
        end
    end

    if http_router.init_worker == nil then
        http_router.init_worker = function (filter)
            http_router.user_routes = http_route.init_worker(filter)
        end
    end
end

-- init_worker
function _M.http_init_worker()
    local conf = core.config.local_conf()
    local router_http_name = "radixtree_uri"
    local router_ssl_name = "radixtree_sni"

    if conf and conf.apisix and conf.apisix.router then
        router_http_name = conf.apisix.router.http or router_http_name
        router_ssl_name = conf.apisix.router.ssl or router_ssl_name
    end

    -- 初始化http路由
    local router_http = require("apisix.http.router." .. router_http_name)
    attach_http_router_common_methods(router_http)
    --会调到 apisix.http.route.init_worker,进而初始化config_etcd.new("/routes", opt)
    router_http.init_worker(filter)
    _M.router_http = router_http

    -- 初始化https路由
    local router_ssl = require("apisix.ssl.router." .. router_ssl_name)
    router_ssl.init_worker()
    _M.router_ssl = router_ssl

    -- 初始化api路由
    _M.api = require("apisix.api_router")
end


function _M.stream_init_worker()
    local router_ssl_name = "radixtree_sni"

    local router_stream = require("apisix.stream.router.ip_port")
    router_stream.stream_init_worker(filter)
    _M.router_stream = router_stream

    local router_ssl = require("apisix.ssl.router." .. router_ssl_name)
    router_ssl.init_worker()
    _M.router_ssl = router_ssl
end


function _M.ssls()
    return _M.router_ssl.ssls()
end
-- 返回的是 config_etcd.values, config_etcd.conf_version
function _M.http_routes()
    if not _M.router_http then
        return nil, nil
    end
    return _M.router_http.routes()
end

function _M.stream_routes()
    -- maybe it's not inited.
    if not _M.router_stream then
        return nil, nil
    end
    return _M.router_stream.routes()
end


-- for test
_M.filter_test = filter


return _M
