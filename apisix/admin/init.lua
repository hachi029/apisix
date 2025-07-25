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
local get_uri_args = ngx.req.get_uri_args
local route = require("apisix.utils.router")
local plugin = require("apisix.plugin")
local v3_adapter = require("apisix.admin.v3_adapter")
local utils = require("apisix.admin.utils")
local ngx = ngx
local get_method = ngx.req.get_method
local ngx_time = ngx.time
local ngx_timer_at = ngx.timer.at
local ngx_worker_id = ngx.worker.id
local tonumber = tonumber
local tostring = tostring
local str_lower = string.lower
local reload_event = "/apisix/admin/plugins/reload"
local ipairs = ipairs
local error = error
local type = type


local events
local MAX_REQ_BODY = 1024 * 1024 * 1.5      -- 1.5 MiB


local viewer_methods = {
    get = true,
}


local resources = {
    routes          = require("apisix.admin.routes"),
    services        = require("apisix.admin.services"),
    upstreams       = require("apisix.admin.upstreams"),
    consumers       = require("apisix.admin.consumers"),
    credentials     = require("apisix.admin.credentials"),
    schema          = require("apisix.admin.schema"),
    ssls            = require("apisix.admin.ssl"),
    plugins         = require("apisix.admin.plugins"),
    protos          = require("apisix.admin.proto"),
    global_rules    = require("apisix.admin.global_rules"),
    stream_routes   = require("apisix.admin.stream_routes"),
    plugin_metadata = require("apisix.admin.plugin_metadata"),
    plugin_configs  = require("apisix.admin.plugin_config"),
    consumer_groups = require("apisix.admin.consumer_group"),
    secrets         = require("apisix.admin.secrets"),
}


local _M = {version = 0.4}
local router


local function check_token(ctx)
    local local_conf = core.config.local_conf()

    -- check if admin_key is required
    if local_conf.deployment.admin.admin_key_required == false then
        return true
    end

    local admin_key = core.table.try_read_attr(local_conf, "deployment", "admin", "admin_key")
    if not admin_key then
        return true
    end

    local req_token = ctx.var.arg_api_key or ctx.var.http_x_api_key
                      or ctx.var.cookie_x_api_key
    if not req_token then
        return false, "missing apikey"
    end

    local admin
    for i, row in ipairs(admin_key) do
        if req_token == row.key then
            admin = row
            break
        end
    end

    if not admin then
        return false, "wrong apikey"
    end

    if admin.role == "viewer" and
       not viewer_methods[str_lower(get_method())] then
        return false, "invalid method for role viewer"
    end

    return true
end

-- Set the `apictx` variable and check admin api token, if the check fails, the current
-- request will be interrupted and an error response will be returned.
--
-- NOTE: This is a higher wrapper for `check_token` function.
local function set_ctx_and_check_token()
    local api_ctx = {}
    core.ctx.set_vars_meta(api_ctx)
    ngx.ctx.api_ctx = api_ctx

    local ok, err = check_token(api_ctx)
    if not ok then
        core.log.warn("failed to check token: ", err)
        core.response.exit(401, { error_msg = "failed to check token", description = err })
    end
end


local function strip_etcd_resp(data)
    if type(data) == "table"
        and data.header ~= nil
        and data.header.revision ~= nil
        and data.header.raft_term ~= nil
    then
        -- strip etcd data
        data.header = nil
        data.responses = nil
        data.succeeded = nil

        if data.node then
            data.node.createdIndex = nil
            data.node.modifiedIndex = nil
        end

        data.count = nil
        data.more = nil
        data.prev_kvs = nil

        if data.deleted then
            -- We used to treat the type incorrectly. But for compatibility we follow
            -- the existing type.
            data.deleted = tostring(data.deleted)
        end
    end

    return data
end


local function head()
    core.response.exit(200)
end


local function run()
    set_ctx_and_check_token()

    local uri_segs = core.utils.split_uri(ngx.var.uri)
    core.log.info("uri: ", core.json.delay_encode(uri_segs))

    -- /apisix/admin/schema/route
    local seg_res, seg_id = uri_segs[4], uri_segs[5]
    local seg_sub_path = core.table.concat(uri_segs, "/", 6)
    if seg_res == "schema" and seg_id == "plugins" then
        -- /apisix/admin/schema/plugins/limit-count
        seg_res, seg_id = uri_segs[5], uri_segs[6]
        seg_sub_path = core.table.concat(uri_segs, "/", 7)
    end

    if seg_res == "stream_routes" then
        local local_conf = core.config.local_conf()
        if local_conf.apisix.proxy_mode ~= "stream" and
           local_conf.apisix.proxy_mode ~= "http&stream" then
            core.log.warn("stream mode is disabled, can not add any stream ",
                          "routes")
            core.response.exit(400, {error_msg = "stream mode is disabled, " ..
                               "can not add stream routes"})
        end
    end

    if seg_res == "consumers" and #uri_segs >= 6 and uri_segs[6] == "credentials" then
        seg_sub_path = seg_id .. "/" .. seg_sub_path
        seg_res = uri_segs[6]
        seg_id = uri_segs[7]
    end

    local resource = resources[seg_res]
    if not resource then
        core.response.exit(404, {error_msg = "Unsupported resource type: ".. seg_res})
    end

    local method = str_lower(get_method())
    if not resource[method] then
        core.response.exit(404, {error_msg = "not found"})
    end

    local req_body, err = core.request.get_body(MAX_REQ_BODY)
    if err then
        core.log.error("failed to read request body: ", err)
        core.response.exit(400, {error_msg = "invalid request body: " .. err})
    end

    if req_body then
        local data, err = core.json.decode(req_body)
        if err then
            core.log.error("invalid request body: ", req_body, " err: ", err)
            core.response.exit(400, {error_msg = "invalid request body: " .. err,
                                     req_body = req_body})
        end

        req_body = data
    end

    local uri_args = ngx.req.get_uri_args() or {}
    if uri_args.ttl then
        if not tonumber(uri_args.ttl) then
            core.response.exit(400, {error_msg = "invalid argument ttl: "
                                                 .. "should be a number"})
        end
    end

    -- seg_id : 配置的id, resource: 配置模块，如route
    local code, data
    if seg_res == "schema" or seg_res == "plugins" then
        code, data = resource[method](seg_id, req_body, seg_sub_path, uri_args)
    else
        code, data = resource[method](resource, seg_id, req_body, seg_sub_path, uri_args)
    end

    if code then
        if method == "get" and plugin.enable_data_encryption then
            if seg_res == "consumers" or seg_res == "credentials" then
                utils.decrypt_params(plugin.decrypt_conf, data, core.schema.TYPE_CONSUMER)
            elseif seg_res == "plugin_metadata" then
                utils.decrypt_params(plugin.decrypt_conf, data, core.schema.TYPE_METADATA)
            else
                utils.decrypt_params(plugin.decrypt_conf, data)
            end
        end

        if v3_adapter.enable_v3() then
            core.response.set_header("X-API-VERSION", "v3")
        else
            core.response.set_header("X-API-VERSION", "v2")
        end
        if resource.need_v3_filter then
            data = v3_adapter.filter(data)      --处理分页
        end

        data = strip_etcd_resp(data)

        core.response.exit(code, data)
    end
end


local function get_plugins_list()
    set_ctx_and_check_token()
    local args = get_uri_args()
    local subsystem = args["subsystem"]
    -- If subsystem is passed then it should be either http or stream.
    -- If it is not passed/nil then http will be default.
    subsystem = subsystem or "http"
    if subsystem == "http" or subsystem == "stream" then
        local plugins = resources.plugins.get_plugins_list(subsystem)
        core.response.exit(200, plugins)
    end
    core.response.exit(400,"invalid subsystem passed")
end

-- Handle unsupported request methods for the virtual "reload" plugin
local function unsupported_methods_reload_plugin()
    set_ctx_and_check_token()

    core.response.exit(405, {
        error_msg = "please use PUT method to reload the plugins, "
                    .. get_method() .. " method is not allowed."
    })
end


local function post_reload_plugins()
    set_ctx_and_check_token()

    local success, err = events:post(reload_event, get_method(), ngx_time())
    if not success then
        core.response.exit(503, err)
    end

    core.response.exit(200, "done")
end


local function plugins_eq(old, new)
    local old_set = {}
    for _, p in ipairs(old) do
        old_set[p.name] = p
    end

    local new_set = {}
    for _, p in ipairs(new) do
        new_set[p.name] = p
    end

    return core.table.set_eq(old_set, new_set)
end

-- 同步本地配置文件里的plugins列表到etcd 的/plugins路径
-- reset: 是否先比较etcd在update
local function sync_local_conf_to_etcd(reset)
    local local_conf = core.config.local_conf()

    local plugins = {}      --从local_conf读取到的插件名称放到这张表里
    for _, name in ipairs(local_conf.plugins) do
        core.table.insert(plugins, {
            name = name,
        })
    end

    for _, name in ipairs(local_conf.stream_plugins) do
        core.table.insert(plugins, {
            name = name,
            stream = true,
        })
    end

    if reset then  --如果reset=true, 尝试从etcd中读取，和本地读取plugins比较，不相同才往etcd里设值；否则直接设值
        local res, err = core.etcd.get("/plugins")
        if not res then
            core.log.error("failed to get current plugins: ", err)
            return
        end

        if res.status == 404 then
            -- nothing need to be reset
            return
        end

        if res.status ~= 200 then
            core.log.error("failed to get current plugins, status: ", res.status)
            return
        end

        local stored_plugins = res.body.node.value
        local revision = res.body.node.modifiedIndex
        if plugins_eq(stored_plugins, plugins) then     --本地读取到的和etcd里的相比较， 只是比较插件名称
            core.log.info("plugins not changed, don't need to reset")
            return
        end

        core.log.warn("sync local conf to etcd")

        -- 如果不相同，设置到/plugins里
        local res, err = core.etcd.atomic_set("/plugins", plugins, nil, revision)
        if not res then
            core.log.error("failed to set plugins: ", err)
        end

        return
    end

    core.log.warn("sync local conf to etcd")

    -- need to store all plugins name into one key so that it can be updated atomically
    local res, err = core.etcd.set("/plugins", plugins)
    if not res then
        core.log.error("failed to set plugins: ", err)
    end
end


local function reload_plugins(data, event, source, pid)
    core.log.info("start to hot reload plugins")
    plugin.load()

    if ngx_worker_id() == 0 then
        sync_local_conf_to_etcd()
    end
end


local function schema_validate()
    local uri_segs = core.utils.split_uri(ngx.var.uri)
    core.log.info("uri: ", core.json.delay_encode(uri_segs))

    local seg_res = uri_segs[6]
    local resource = resources[seg_res]
    if not resource then
        core.response.exit(404, {error_msg = "Unsupported resource type: ".. seg_res})
    end

    local req_body, err = core.request.get_body(MAX_REQ_BODY)
    if err then
        core.log.error("failed to read request body: ", err)
        core.response.exit(400, {error_msg = "invalid request body: " .. err})
    end

    if req_body then
        local data, err = core.json.decode(req_body)
        if err then
            core.log.error("invalid request body: ", req_body, " err: ", err)
            core.response.exit(400, {error_msg = "invalid request body: " .. err,
                                     req_body = req_body})
        end

        req_body = data
    end

    local ok, err = core.schema.check(resource.schema, req_body)
    if ok then
        core.response.exit(200)
    end
    core.response.exit(400, {error_msg = err})
end


local uri_route = {
    {
        paths = [[/apisix/admin]],
        methods = {"HEAD"},
        handler = head,
    },
    {
        paths = [[/apisix/admin/*]],
        methods = {"GET", "PUT", "POST", "DELETE", "PATCH"},
        handler = run,
    },
    {
        paths = [[/apisix/admin/plugins/list]],
        methods = {"GET"},
        handler = get_plugins_list,
    },
    {
        paths = [[/apisix/admin/schema/validate/*]],
        methods = {"POST"},
        handler = schema_validate,
    },
    {
        paths = reload_event,
        methods = {"PUT"},
        handler = post_reload_plugins,
    },
    -- Handle methods other than "PUT" on "/plugin/reload" to inform user
    {
        paths = reload_event,
        methods = { "GET", "POST", "DELETE", "PATCH" },
        handler = unsupported_methods_reload_plugin,
    },
}

-- createdIndex/modifiedIndex
function _M.init_worker()
    local local_conf = core.config.local_conf()
    if not local_conf.apisix or not local_conf.apisix.enable_admin then
        return
    end

    router = route.new(uri_route)       --admin api 路由, admin-api监听在专门的一个端口，和业务流量区分开

    -- register reload plugin handler
    events = require("apisix.events")
    -- 插件reload事件监听，当调用/apisix/admin/plugins/reload 时，触发事件，每个worker都会reload_plugins
    events:register(reload_plugins, reload_event, "PUT")

    if ngx_worker_id() == 0 then
        -- check if admin_key is required
        if local_conf.deployment.admin.admin_key_required == false then
            core.log.warn("Admin key is bypassed! ",
                "If you are deploying APISIX in a production environment, ",
                "please enable `admin_key_required` and set a secure admin key!")
        end

        local ok, err = ngx_timer_at(0, function(premature)
            if premature then
                return
            end

            -- try to reset the /plugins to the current configuration in the admin
            -- 同步本地配置文件里的plugins列表到etcd 的/plugins路径
            sync_local_conf_to_etcd(true)
        end)

        if not ok then
            error("failed to sync local configure to etcd: " .. err)
        end
    end
end


function _M.get()
    return router
end


return _M
