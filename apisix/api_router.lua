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
local router = require("apisix.utils.router")
local plugin_mod = require("apisix.plugin")
local core = require("apisix.core")
local ipairs = ipairs
local ngx_header = ngx.header
local type = type


local _M = {}
local match_opts = {}
local has_route_not_under_apisix

-- 插件暴露的api

local fetch_api_router
do
    local routes = {}
 -- 获取已加载插件提供的路由配置，构建一个新的router
function fetch_api_router()
    core.table.clear(routes)

    has_route_not_under_apisix = false

    -- 遍历当前加载的所有插件
    for _, plugin in ipairs(plugin_mod.plugins) do
        local api_fun = plugin.api
        if api_fun then
            local api_routes = api_fun()    -- 获取插件返回的路由配置
            core.log.debug("fetched api routes: ",
                           core.json.delay_encode(api_routes, true))
            for _, route in ipairs(api_routes) do
                if route.uri == nil then
                    core.log.error("got nil uri in api route: ",
                                   core.json.delay_encode(route, true))
                    break
                end

                local typ_uri = type(route.uri)
                if not has_route_not_under_apisix then
                    if typ_uri == "string" then
                        if not core.string.has_prefix(route.uri, "/apisix/") then
                            has_route_not_under_apisix = true
                        end
                    else
                        for _, uri in ipairs(route.uri) do
                            if not core.string.has_prefix(uri, "/apisix/") then
                                has_route_not_under_apisix = true
                                break
                            end
                        end
                    end
                end

                -- 插入到routers配置列表中{}
                core.table.insert(routes, {
                        methods = route.methods,
                        paths = route.uri,
                        handler = function (api_ctx)
                            local code, body = route.handler(api_ctx)   -- handler是插件提供的方法
                            if code or body then
                                if type(body) == "table" and ngx_header["Content-Type"] == nil then
                                    core.response.set_header("Content-Type", "application/json")
                                end

                                core.response.exit(code, body)
                            end
                        end
                    })
            end
        end
    end

    -- 根据配置创建新的router
    return router.new(routes)       -- 默认的radixtree，根据url进行匹配
end

end -- do

-- 是否有插件提供的api，url不以/apisix开头
function _M.has_route_not_under_apisix()
    if has_route_not_under_apisix == nil then
        return true
    end

    return has_route_not_under_apisix
end


function _M.match(api_ctx)
    -- 以plugin_mod.load_times为版本，每次插件reload, 都会重新创建api_router
    local api_router = core.lrucache.global("api_router", plugin_mod.load_times, fetch_api_router)
    if not api_router then
        core.log.error("failed to fetch valid api router")
        return false
    end

    core.table.clear(match_opts)
    match_opts.method = api_ctx.var.request_method

    -- 支持根据url和method进行匹配
    local ok = api_router:dispatch(api_ctx.var.uri, match_opts, api_ctx)
    return ok
end


return _M
