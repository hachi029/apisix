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
local core = require("apisix.core")
local plugin = require("apisix.plugin")
local batch_processor = require("apisix.utils.batch-processor")
local timer_at = ngx.timer.at
local pairs = pairs
local setmetatable = setmetatable

-- batch-processor-manager 批处理器管理器，管理多个批处理器。
-- https://apisix.apache.org/zh/docs/apisix/batch-processor/
-- 使用方法：
-- batch_processor_manager =  new("http-logger")
-- if batch_processor_manager:add_entry(conf, entry) then   直接调用，添加entry， 如果返回false，表示还没创建
--        return
-- end
-- batch_processor_manager:add_entry_to_new_processor(conf, entry, ctx, func)   -- 新建，fun表示batch处理函数

local _M = {}
local mt = { __index = _M }

-- config = {
--        name = conf.name,     -- 只是一个标识
--        batch_max_size = conf.batch_max_size,       --最大批次大小
--        inactive_timeout = conf.inactive_timeout,   --最新元素在管道里的最长时间
--        buffer_duration = conf.buffer_duration,     --最早元素在管道里的最长时间
--        max_retry_count = conf.max_retry_count,     --失败重试次数。
--        retry_delay = conf.retry_delay,             --每次失败后，延迟几秒后再次执行
--        func = conf.func                            --批处理器，返回 ok, err, first_fail_idx
--    }
-- -- func 执行时机：1）元素个数达到batch_max_size；2）now() - first_element_added_time > buffer_duration
-- -- 3) now() - last_element_added_time > inactive_timeout
function _M.new(name)
    return setmetatable({
        stale_timer_running = false,
        buffers = {},
        total_pushed_entries = 0,
        name = name,
    }, mt)
end

-- 将batch_processor的scheme附加到入参schema上。
-- 比如http-logger的配置scheme将自动包含batch_processor的schema
-- 这样使用批处理器的插件不用重复配置批处理器相关的schema了
function _M:wrap_schema(schema)
    local bp_schema = core.table.deepcopy(batch_processor.schema)
    local properties = schema.properties
    for k, v in pairs(bp_schema.properties) do
        if not properties[k] then
            properties[k] = v
        end
        -- don't touch if the plugin overrides the property
    end

    properties.name.default = self.name
    return schema
end


-- remove stale objects from the memory after timer expires
-- 定期检查batch-processor, 如果batch-processor里没有entry，则释放掉，在下次addEntry时会重新创建。即清理闲置的batch-processor
local function remove_stale_objects(premature, self)
    if premature then
        return
    end

    for key, batch in pairs(self.buffers) do
        if #batch.entry_buffer.entries == 0 and #batch.batch_to_process == 0 then
            core.log.info("removing batch processor stale object, conf: ",
                          core.json.delay_encode(key))
           self.buffers[key] = nil
        end
    end

    self.stale_timer_running = false
end


local check_stale
do
    local interval = 1800

    -- 检查闲置的batch_processor，如有，清理之
    function check_stale(self)
        if not self.stale_timer_running then
            -- run the timer every 30 mins if any log is present
            timer_at(interval, remove_stale_objects, self)
            self.stale_timer_running = true
        end
    end

    function _M.set_check_stale_interval(time)
        interval = time
    end
end


local function total_processed_entries(self)
    local processed_entries = 0
    for _, log_buffer in pairs(self.buffers) do
        processed_entries = processed_entries + log_buffer.processed_entries
    end
    return processed_entries
end

function _M:add_entry(conf, entry, max_pending_entries)
    if max_pending_entries then
        local total_processed_entries_count = total_processed_entries(self)
        if self.total_pushed_entries - total_processed_entries_count > max_pending_entries then
            core.log.error("max pending entries limit exceeded. discarding entry.",
                           " total_pushed_entries: ", self.total_pushed_entries,
                           " total_processed_entries: ", total_processed_entries_count,
                           " max_pending_entries: ", max_pending_entries)
            return
        end
    end
    --每30分钟检查一次stale的batch-processor, 如果batch-processor里没有entry，则释放掉
    check_stale(self)

    local log_buffer = self.buffers[plugin.conf_version(conf)]
    if not log_buffer then
        return false
    end

    log_buffer:push(entry)
    self.total_pushed_entries = self.total_pushed_entries + 1
    return true
end


-- 当add_entry返回false时调用，会创建新的log_buffer
function _M:add_entry_to_new_processor(conf, entry, ctx, func, max_pending_entries)
    if max_pending_entries then
        local total_processed_entries_count = total_processed_entries(self)
        if self.total_pushed_entries - total_processed_entries_count > max_pending_entries then
            core.log.error("max pending entries limit exceeded. discarding entry.",
                           " total_pushed_entries: ", self.total_pushed_entries,
                           " total_processed_entries: ", total_processed_entries_count,
                           " max_pending_entries: ", max_pending_entries)
            return
        end
    end
    ----每30分钟检查一次stale的batch-processor, 如果batch-processor里没有entry，则释放掉
    check_stale(self)

    local config = {
        name = conf.name,
        batch_max_size = conf.batch_max_size,   --
        max_retry_count = conf.max_retry_count, --
        retry_delay = conf.retry_delay,
        buffer_duration = conf.buffer_duration,
        inactive_timeout = conf.inactive_timeout,
        route_id = ctx.var.route_id,
        server_addr = ctx.var.server_addr,
    }

    local log_buffer, err = batch_processor:new(func, config)
    if not log_buffer then
        core.log.error("error when creating the batch processor: ", err)
        return false
    end

    log_buffer:push(entry)
    self.buffers[plugin.conf_version(conf)] = log_buffer
    self.total_pushed_entries = self.total_pushed_entries + 1
    return true
end


return _M
