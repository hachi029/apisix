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
local ipairs = ipairs


local _M = {}

-- 带优先级的负载均衡，相同优先级的node创建一个balancer, 总是优先选择优先级高的balancer.
-- pickers[1] = picker1, pickers[2] = picker2
local function max_priority(a, b)
    return a > b
end

-- up_nodes: up_nodes[node.priority][node.host .. ":" .. node.port] = node.weight
-- picker_mod: roundrobin/chash/ewma/least_conn
function _M.new(up_nodes, upstream, picker_mod)
    local priority_index = up_nodes._priority_index
    core.table.sort(priority_index, max_priority)

    local pickers = core.table.new(#priority_index, 0)
    for i, priority in ipairs(priority_index) do
        local picker, err = picker_mod.new(up_nodes[priority], upstream)   --每个优先级创建一个负载均衡器
        if not picker then
            return nil, "failed to create picker with priority " .. priority .. ": " .. err
        end
        if not picker.before_retry_next_priority then
            return nil, "picker should define 'before_retry_next_priority' to reset ctx"
        end

        pickers[i] = picker
    end

    return {
        upstream = upstream,
        get = function (ctx)
            -- ctx.priority_balancer_picker_idx or 1 优先选择高优先级的picker
            for i = ctx.priority_balancer_picker_idx or 1, #pickers do
                local picker = pickers[i]
                local server, err = picker.get(ctx)
                if server then
                    ctx.priority_balancer_picker_idx = i    --记录了当前选择的是哪个picker
                    return server
                end

                core.log.notice("failed to get server from current priority ",
                                priority_index[i],
                                ", try next one, err: ", err)

                picker.before_retry_next_priority(ctx)
            end

            return nil, "all servers tried"
        end,
        after_balance = function (ctx, before_retry)
            -- 上次选择的是哪个picker
            local priority_balancer_picker = pickers[ctx.priority_balancer_picker_idx]
            if not priority_balancer_picker or
                not priority_balancer_picker.after_balance
            then
                return
            end

            priority_balancer_picker.after_balance(ctx, before_retry)
        end
    }
end


return _M
