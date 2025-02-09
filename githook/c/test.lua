-- main.lua

local logger = require("logger")

-- 配置表
local config = {
    max_task_queue_size = 2000,
    max_workers = 10,
    buffer_size = 8192,
    write_interval = 1000000,
    retry_times = 3,
    retry_delay = 200,
    max_memory_pool_blocks = 200,
    max_reconnect_attempts = 3,
    reconnect_delay = 2000000,
}

-- 创建日志记录器实例
local log = logger.new(config)

-- 记录日志
log:record("Test message")

-- 销毁日志记录器
log:destroy()