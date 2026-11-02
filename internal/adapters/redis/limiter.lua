-- One hit in a sliding window (TDD-07 §8). KEYS[1] is the window's sorted set; ARGV are now and
-- the window in microseconds, the limit, and a member unique to this hit. Returns 0 when the hit
-- is counted, else the microseconds until the window has room. A refused hit is not counted.
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])
if count < limit then
  redis.call('ZADD', KEYS[1], now, ARGV[4])
  redis.call('PEXPIRE', KEYS[1], math.ceil(window / 1000))
  return 0
end
-- Room returns when the hit at rank count - limit leaves: the oldest, unless the limit was
-- lowered below what the window already holds.
local freeing = redis.call('ZRANGE', KEYS[1], count - limit, count - limit, 'WITHSCORES')
return tonumber(freeing[2]) + window - now
