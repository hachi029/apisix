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
local core = require("apisix.core")
local base_router = require("apisix.http.route")
local get_services = require("apisix.http.service").services
local cached_router_version     -- 存放etcd /routes配置版本，也就是路由版本。
local cached_service_version    -- 存放etcd /services配置版本，也就是版本。


local _M = {version = 0.2}


--user_routes, err = core.config.new("/routes", {
--    automatic = true,
--    item_schema = core.schema.route,
--    checker = check_route,  -- 自定义的scheme check逻辑
--    filter = filter,
--})
    local uri_routes = {}  --https://github.com/api7/lua-resty-radixtree#new routes参数
    local uri_router  -- lua-resty-radixtree#new 创建出来的router, 真正来执行路由匹配的对象
-- 在首次进行路由匹配时，或发现配置版本发生了变更后，重新创建router
function _M.match(api_ctx)
    local user_routes = _M.user_routes
    local _, service_version = get_services()
    if not cached_router_version or cached_router_version ~= user_routes.conf_version
        or not cached_service_version or cached_service_version ~= service_version
    then
        -- 重新构建router, user_routes 为 core.config.new("/routes",opts)
        uri_router = base_router.create_radixtree_uri_router(user_routes.values,
                                                             uri_routes, false)
        cached_router_version = user_routes.conf_version
        cached_service_version = service_version
    end

    if not uri_router then
        core.log.error("failed to fetch valid `uri` router: ")
        return true
    end

    return _M.matching(api_ctx)
end


function _M.matching(api_ctx)
    core.log.info("route match mode: radixtree_uri")
    return base_router.match_uri(uri_router, api_ctx)
end


return _M
