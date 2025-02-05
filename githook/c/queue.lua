local ffi = require("ffi")
local C = ffi.C

-- 定义 C 结构体
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

-- 定义队列类
local Queue = {}
Queue.__index = Queue

function Queue.new(initial_size)
    local self = setmetatable({}, Queue)
    self.queue = C.lua_queue_new(initial_size)
    return self
end

function Queue:__gc()
    if self.queue ~= nil then
        C.lua_queue_destroy(self.queue)
        self.queue = nil
    end
end

function Queue:enqueue(value)
    local result = C.lua_queue_enqueue(self.queue, value)
    return result == 0
end

function Queue:dequeue()
    local value = C.lua_queue_dequeue(self.queue)
    return value ~= nil and value or nil
end

function Queue:peek()
    local value = C.lua_queue_peek(self.queue)
    return value ~= nil and value or nil
end

function Queue:length()
    return C.lua_queue_length(self.queue)
end

return Queue