local ffi = require("ffi")
local C = ffi.load("./lua_queue") -- 加载编译后的C模块

-- 定义C结构体
ffi.cdef[[
    typedef struct {
        void** data;
        size_t head;
        size_t tail;
        size_t size;
        pthread_mutex_t lock;
    } lua_queue_t;

    lua_queue_t* lua_queue_new(size_t initial_size);
    void lua_queue_destroy(lua_queue_t* queue);
    int lua_queue_enqueue(lua_queue_t* queue, void* value);
    void* lua_queue_dequeue(lua_queue_t* queue);
    void* lua_queue_peek(lua_queue_t* queue);
    size_t lua_queue_length(lua_queue_t* queue);
]]

-- 创建Lua队列类
local Queue = {}
Queue.__index = Queue

function Queue:new(initial_size)
    local queue = C.lua_queue_new(initial_size)
    if not queue then
        error("Failed to create queue")
    end
    return setmetatable({ handle = queue }, Queue)
end

function Queue:enqueue(value)
    local result = C.lua_queue_enqueue(self.handle, value)
    if result ~= 0 then
        error("Failed to enqueue element")
    end
end

function Queue:dequeue()
    local value = C.lua_queue_dequeue(self.handle)
    if not value then
        error("Queue is empty")
    end
    return value
end

function Queue:peek()
    local value = C.lua_queue_peek(self.handle)
    if not value then
        error("Queue is empty")
    end
    return value
end

function Queue:length()
    return C.lua_queue_length(self.handle)
end

function Queue:destroy()
    C.lua_queue_destroy(self.handle)
end

return Queue