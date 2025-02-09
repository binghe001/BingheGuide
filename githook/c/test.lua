-- logger.lua

local logger = {}

-- 日志记录器metatable
local logger_metatable = {
    __gc = function(self)
        local logger_ptr = self.__ptr
        -- 销毁日志记录器
        destroy_logger(logger_ptr)
    end,
}

-- 创建新的日志记录器实例
function logger.new(config)
    local L = luaL_newstate()
    luaL_openlibs(L)

    -- 将配置表压入栈顶
    lua_pushvalue(L, config)

    -- 调用luaopen_logger函数
    local status, result = pcall(luaopen_logger, L)

    if not status then
        error("Failed to initialize logger: " .. result)
    end

    -- 检查结果是否为userdata
    if type(result) ~= 'userdata' then
        error("Logger initialization failed")
    end

    -- 设置metatable
    setmetatable(result, logger_metatable)

    return result
end

-- 记录日志方法
function logger:record(message)
    local logger_ptr = self.__ptr
    -- 在这里实现具体的日志记录逻辑
end

-- 销毁日志记录器方法
function logger:destroy()
    local logger_ptr = self.__ptr
end

return logger