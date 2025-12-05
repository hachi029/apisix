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
local require      = require
local yaml         = require("lyaml")
local log          = require("apisix.core.log")
local profile      = require("apisix.core.profile")
local lfs          = require("lfs")
local inspect      = require("inspect")
local jsonschema   = require("jsonschema")
local io           = io
local ngx          = ngx
local re_find      = ngx.re.find
local get_headers  = ngx.req.get_headers
local type         = type
local pairs        = pairs
local setmetatable = setmetatable
local pcall        = pcall
local ipairs       = ipairs
local unpack       = unpack
local debug_yaml_path = profile:yaml_path("debug")
-- conf/debug.yaml 配置文件内容
local debug_yaml
-- conf/debug.yaml 配置文件 上次change 时间
local debug_yaml_ctime


local _M = {version = 0.1}


local config_schema = {
    type = "object",
    properties = {
        basic = {
            properties = {
                enable = {
                    type = "boolean",
                },
            }
        },
        http_filter = {
            properties = {
                enable = {
                    type = "boolean",
                },
                enable_header_name = {
                    type = "string",
                },
            }
        },
        hook_conf = {
            properties = {
                enable = {
                    type = "boolean",
                },
                name = {
                    type = "string",
                },
                log_level = {
                    enum = {"debug", "info", "notice", "warn", "error",
                            "crit", "alert","emerg"},
                },
                is_print_input_args = {
                    type = "boolean",
                },
                is_print_return_value = {
                    type = "boolean",
                },
            }
        },
    },
    required = {"basic", "http_filter", "hook_conf"},
}


-- 读取conf/debug.yaml
local function read_debug_yaml()
    -- 读取文件属性
    local attributes, err = lfs.attributes(debug_yaml_path)
    if not attributes then
        log.notice("failed to fetch ", debug_yaml_path, " attributes: ", err)
        return
    end

    -- 根据文件最后修改时间判断文件内容是否有变化，如有变化则重新加载，如没变化则跳过本次检查
    -- 比较文件修改时间
    -- log.info("change: ", json.encode(attributes))
    local last_change_time = attributes.change
    if debug_yaml_ctime == last_change_time then
        return
    end

    -- 有变化
    local f, err = io.open(debug_yaml_path, "r")
    if not f then
        log.error("failed to open file ", debug_yaml_path, " : ", err)
        return
    end

    -- 由于 APISIX 服务启动后是每秒定期检查该文件， 当可以正常读取到 #END 结尾时，才认为文件处于写完关闭状态
    local found_end_flag
    for i = 1, 10 do
        f:seek('end', -i)

        local end_flag = f:read("*a")
        -- log.info(i, " flag: ", end_flag)
        if re_find(end_flag, [[#END\s*]], "jo") then
            found_end_flag = true
            break
        end
    end

    -- 未结束
    if not found_end_flag then
        f:seek("set")
        local size = f:seek("end")
        f:close()

        if size > 8 then
            log.warn("missing valid end flag in file ", debug_yaml_path)
        end
        return
    end

    -- 已结束
    f:seek('set')
    local yaml_config = f:read("*a")
    f:close()

    -- 解析yaml
    local debug_yaml_new = yaml.load(yaml_config)
    if not debug_yaml_new then
        log.error("failed to parse the content of file " .. debug_yaml_path)
        return
    end

    -- 更新为新的配置
    debug_yaml_new.hooks = debug_yaml_new.hooks or {}
    debug_yaml = debug_yaml_new
    debug_yaml_ctime = last_change_time

    -- 校验yaml配置schema
    -- validate the debug yaml config
    local validator = jsonschema.generate_validator(config_schema)
    local ok, err = validator(debug_yaml)
    if not ok then
        log.error("failed to validate debug config " .. err)
        return
    end

    return true
end


local sync_debug_hooks
do
    local pre_mtime
    -- 记录当前已经被hook了的方法
    local enabled_hooks = {}

local function apply_new_fun(module, fun_name, file_path, hook_conf)
    local log_level = hook_conf.log_level or "warn"

    -- 如果不是方法
    if not module or type(module[fun_name]) ~= "function" then
        log.error("failed to find function [", fun_name,
                  "] in module:", file_path)
        return
    end

    -- 获取原始方法
    local fun = module[fun_name]
    local fun_org
    -- 如果已经被hook了
    if enabled_hooks[fun] then
        -- 获取原始的方法
        fun_org = enabled_hooks[fun].org
        enabled_hooks[fun] = nil
    else
        fun_org = fun
    end

    local t = {fun_org = fun_org}
    local mt = {}

    function mt.__call(self, ...)
        local arg = {...}
        -- http_filter 动态高级调试模式
        -- 动态高级调试模式是基于高级调试模式，可以由单个请求动态开启高级调试模式，根据请求头
        local http_filter = debug_yaml.http_filter
        local api_ctx = ngx.ctx.api_ctx
        -- 如果开启了动态高级调试模式，则enable_by_hook为false
        local enable_by_hook = not (http_filter and http_filter.enable)
        -- api_ctx.enable_dynamic_debug在_M.dynamic_debug()方法中设置。其值取决于http请求的header
        local enable_by_header_filter = (http_filter and http_filter.enable)
                and (api_ctx and api_ctx.enable_dynamic_debug)
        -- 是否打印输入参数
        if hook_conf.is_print_input_args then
            if enable_by_hook or enable_by_header_filter then
                log[log_level]("call require(\"", file_path, "\").", fun_name,
                               "() args:", inspect(arg))
            end
        end

        -- 执行原始方法，并获取返回值
        local ret = {self.fun_org(...)}
        -- 是否打印返回值
        if hook_conf.is_print_return_value then
            if enable_by_hook or enable_by_header_filter then
                log[log_level]("call require(\"", file_path, "\").", fun_name,
                               "() return:", inspect(ret))
            end
        end
        return unpack(ret)
    end

    setmetatable(t, mt)
    -- 记录当前已经被hook了的方法
    enabled_hooks[t] = {
        org = fun_org, new = t, mod = module,
        fun_name = fun_name
    }
    -- 重置为新的包裹方法
    module[fun_name] = t
end


-- 如果检测到conf/debug.yaml 有变更，则执行这个函数
function sync_debug_hooks()
    -- 修改时间
    if not debug_yaml_ctime or debug_yaml_ctime == pre_mtime then
        return
    end

    for _, hook in pairs(enabled_hooks) do
        local m = hook.mod
        local name = hook.fun_name
        m[name] = hook.org
    end

    enabled_hooks = {}

    local hook_conf = debug_yaml.hook_conf
    -- 未开启
    if not hook_conf.enable then
        pre_mtime = debug_yaml_ctime
        return
    end

    local hook_name = hook_conf.name or ""
    local hooks = debug_yaml[hook_name]
    if not hooks then
        pre_mtime = debug_yaml_ctime
        return
    end

    for file_path, fun_names in pairs(hooks) do
        -- 通过require加载模块
        local ok, module = pcall(require, file_path)
        if not ok then
            log.error("failed to load module [", file_path, "]: ", module)

        else
            -- 配置的需要hook的方法
            for _, fun_name in ipairs(fun_names) do
                apply_new_fun(module, fun_name, file_path, hook_conf)
            end
        end
    end

    pre_mtime = debug_yaml_ctime
end

end --do


-- 设置 conf/debug.yaml 即可开启基本调试模式：
--basic:
--  enable: true
--#END
local function sync_debug_status(premature)
    if premature then
        return
    end

    -- 如果conf/debug.yaml 没有修改，直接返回
    if not read_debug_yaml() then
        return
    end

    -- 有变更
    sync_debug_hooks()
end


-- 根据配置判断是否开启动态debug功能
local function check()
    -- 如果未开启动态debug
    if not debug_yaml or not debug_yaml.http_filter then
        return false
    end

    local http_filter = debug_yaml.http_filter
    -- 如果未开启动态debug
    if not http_filter or not http_filter.enable_header_name or not http_filter.enable then
        return false
    end

    return true
end

-- apisix.http_access_phase --> .
function _M.dynamic_debug(api_ctx)
    -- 配置文件中是否开启了动态debug
    if not check() then
        return
    end

    -- 根据请求头确定是否开启动态debug
    if get_headers()[debug_yaml.http_filter.enable_header_name] then
        api_ctx.enable_dynamic_debug = true
    end
end


function _M.enable_debug()
    if not debug_yaml or not debug_yaml.basic then
        return false
    end

    return debug_yaml.basic.enable
end


-- apisix.http_init_worker()
function _M.init_worker()
    local process = require("ngx.process")
    if process.type() ~= "worker" then
        return
    end

    -- https://apisix.apache.org/zh/docs/apisix/next/debug-mode/
    sync_debug_status()
    ngx.timer.every(1, sync_debug_status)
end


return _M
