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
local core = require("apisix.core")
local event = require("apisix.core.event")
local get_services = require("apisix.http.service").services
local service_fetch = require("apisix.http.service").get
local ipairs = ipairs
local type = type
local tab_insert = table.insert
local loadstring = loadstring
local pairs = pairs
local cached_router_version
local cached_service_version
local host_router
local only_uri_router


local _M = {version = 0.1}


local function push_host_router(route, host_routes, only_uri_routes)
    if type(route) ~= "table" then
        return
    end

    -- route.script配置项目
    local filter_fun, err
    if route.value.filter_func then
        filter_fun, err = loadstring(
                                "return " .. route.value.filter_func,
                                "router#" .. route.value.id)
        if not filter_fun then
            core.log.error("failed to load filter function: ", err,
                            " route id: ", route.value.id)
            return
        end

        filter_fun = filter_fun()
    end

    --优先使用route配置中的hosts, 否则使用service中的hosts配置项
    local hosts = route.value.hosts
    if not hosts then
        if route.value.host then
            hosts = {route.value.host}
        elseif route.value.service_id then
            local service = service_fetch(route.value.service_id)
            if not service then
                core.log.error("failed to fetch service configuration by ",
                                "id: ", route.value.service_id)
                -- we keep the behavior that missing service won't affect the route matching
            else
                hosts = service.value.hosts
            end
        end
    end

    -- 没有传hosts, 因为host已经在外层匹配过了。
    local radixtree_route = {
        paths = route.value.uris or route.value.uri,
        methods = route.value.methods,
        priority = route.value.priority,
        remote_addrs = route.value.remote_addrs
                       or route.value.remote_addr,
        vars = route.value.vars,
        filter_fun = filter_fun,
        handler = function (api_ctx, match_opts)
            api_ctx.matched_params = nil
            api_ctx.matched_route = route
            api_ctx.curr_req_matched = match_opts.matched
            api_ctx.real_curr_req_matched_path = match_opts.matched._path
        end
    }

    -- 如果没配置hosts, 插入only_uri_routes
    if hosts == nil then
        core.table.insert(only_uri_routes, radixtree_route)
        return
    end

    -- 对每个host主机名，插入对应的路由配置
    for i, host in ipairs(hosts) do
        local host_rev = host:reverse()
        if not host_routes[host_rev] then
            host_routes[host_rev] = {radixtree_route}
        else
            tab_insert(host_routes[host_rev], radixtree_route)
        end
    end
end


local function create_radixtree_router(routes)
    -- key为虚拟主机的reverse。 value为 https://github.com/api7/lua-resty-radixtree#new routes参数
    local host_routes = {} -- group by vhost
    local only_uri_routes = {} -- 没设置host的路由配置
    host_router = nil
    routes = routes or {}

    -- 遍历所有的routes配置，group by host 到host_routes 中
    for _, route in ipairs(routes) do
        local status = core.table.try_read_attr(route, "value", "status")
        -- check the status
        if not status or status == 1 then
            push_host_router(route, host_routes, only_uri_routes)
        end
    end

    --针对每个host, 创建router
    -- create router: host_router
    local host_router_routes = {}
    for host_rev, routes in pairs(host_routes) do
        local sub_router = router.new(routes)       -- sub_router

        core.table.insert(host_router_routes, {
            paths = host_rev,  -- 此处paths传入的是host_rev。 实际路由匹配时，也是先拿host进行匹配
            -- 自定义场景匹配
            filter_fun = function(vars, opts, ...) -- 匹配到后，再由sub_router根据uri进行匹配
                return sub_router:dispatch(vars.uri, opts, ...)
            end,
            handler = function (api_ctx, match_opts)
                api_ctx.real_curr_req_matched_host = match_opts.matched._path
            end
        })
    end

    event.push(event.CONST.BUILD_ROUTER, routes)

    if #host_router_routes > 0 then
        host_router = router.new(host_router_routes)
    end

    -- create router: only_uri_router
    only_uri_router = router.new(only_uri_routes)
    return true
end

function _M.match(api_ctx)
    local user_routes = _M.user_routes
    local _, service_version = get_services()
    -- 当配置发生变更时，重新创建router
    if not cached_router_version or cached_router_version ~= user_routes.conf_version
        or not cached_service_version or cached_service_version ~= service_version
    then
        create_radixtree_router(user_routes.values)
        -- 更新router和service配置版本
        cached_router_version = user_routes.conf_version
        cached_service_version = service_version
    end

    return _M.matching(api_ctx)
end


function _M.matching(api_ctx)
    core.log.info("route match mode: radixtree_host_uri")

    local match_opts = core.tablepool.fetch("route_match_opts", 0, 16)
    match_opts.method = api_ctx.var.request_method
    match_opts.remote_addr = api_ctx.var.remote_addr
    match_opts.vars = api_ctx.var
    match_opts.host = api_ctx.var.host
    match_opts.matched = core.tablepool.fetch("matched_route_record", 0, 4)

    if host_router then
        local host_uri = api_ctx.var.host
        -- dispatch传入的是host_uri:reverse()，现根据host_rev进行匹配，之后在filter_fun中再根据uri进行匹配
        -- 因为uri支持/xx* 的匹配方式，所以这里也天然支持泛域名匹配 *.xxx.com
        local ok = host_router:dispatch(host_uri:reverse(), match_opts, api_ctx, match_opts)
        if ok then
            if api_ctx.real_curr_req_matched_path then
                api_ctx.curr_req_matched._path = api_ctx.real_curr_req_matched_path
                api_ctx.real_curr_req_matched_path = nil
            end
            if api_ctx.real_curr_req_matched_host then
                api_ctx.curr_req_matched._host = api_ctx.real_curr_req_matched_host:reverse()
                api_ctx.real_curr_req_matched_host = nil
            end
            core.tablepool.release("route_match_opts", match_opts)
            return true
        end
    end

    -- 如果host_router未匹配到，再尝试使用only_uri_router匹配
    local ok = only_uri_router:dispatch(api_ctx.var.uri, match_opts, api_ctx, match_opts)
    core.tablepool.release("route_match_opts", match_opts)
    return ok
end


return _M
