cjson = require "cjson.safe"
ck    = require "cookie"
redis = require "resty.redis"

-- We don't need more than this when dealing with sessions
-- TODO: Has to be switched based on dev mode
-- cjson.decode_max_depth(2)

local _M = {}

local redis_host = os.getenv("SESSION_REDIS_SERVICE_HOST")
local redis_port = os.getenv("SESSION_REDIS_SERVICE_PORT")
local sessionCookieKey = os.getenv("SESSION_COOKIE_KEY")

--
-- Respond with raw body
local function return_with_raw(code, body)
    ngx.status = code
    ngx.header["Content-type"] = "application/json; charset=utf-8"
    ngx.say(body)
    ngx.exit(ngx.HTTP_OK)
end

-- Respond with a message
local function return_with(code, msg)
    return_with_raw(code, cjson.encode({message = msg}))
end

-- check the type of a value
-- return nil, type when it doesn't match
local function check_type(val, ty)
    local val_type = type(val)
    if val_type ~= ty then
        return nil, val_type
    else
        return true, nil
    end
end

-- like pcall, but, exits with 500 on error
local function with_500(location, fn, ...)
    local res, err = fn(...)
    if not res then
        ngx.log(ngx.ERR, location, " : ", err)
        return_with(500, "something went wrong")
    else
        return res
    end
end

-- Standard cookie expiration
local function inject_cookie_expiration(cookie, base_domain)
    local val = {
        key     = sessionCookieKey,
        value   = "",
        path    = "/",
        domain  = ("." .. base_domain),
        expires = "Thu, 01 Jan 1970 00:00:00 GMT"
    }

    -- Failed to set the cookie
    with_500("cookie:set", cookie.set, cookie, val)
end

-- Wrapper for redis calls
local function run_query(query)
    local red = redis:new()
    red:set_timeout(1000) -- 1 sec
    -- Establish a connection to redis
    with_500("redis:connect", red.connect, red, redis_host, redis_port)
    -- Set the session value
    local resp = with_500("redis:query", query, red)
    -- place the connection in a pool
    with_500("redis:set_keepalive", red.set_keepalive, red, 10000, 100)
    return resp
end

local function parse_auth_header(auth_header)
    local _, _, token = string.find(auth_header, "Bearer%s+(.+)")
    if not token then
      ngx.status = ngx.HTTP_BAD_REQUEST
      return_with(ngx.HTTP_BAD_REQUEST, "malformed-authorization-header")
    else
      return token
    end
end

local function hasOverlap(listA, listB)
  local hasOverlapF = false
  for _, i in pairs(listA) do
    for _, j in pairs(listB) do
      if i == j then
        hasOverlapF = true
        break
      end
    end
  end
  return hasOverlapF
end

function _M.acme(val_dir)
    local f = assert(io.open(val_dir .. "validation-map.json", "r"))
    local val_map_data = f:read("*all")
    f:close()
    local val_map = with_500("cjson.decode", cjson.decode, val_map_data)
    local val_resp = val_map[ngx.var.request_uri]
    if val_resp then
        ngx.say(val_resp)
    else
        return_with(ngx.HTTP_NOT_FOUND, 'key not found')
    end
end

local function getUserRoles()
  local user_roles = ngx.req.get_headers()["X-Hasura-Allowed-Roles"]
  if type(user_roles) == "string" then
    user_roles = {user_roles}
  end
  return user_roles
end

function _M.authn(base_domain)
    local cookie = ck:new()

    -- Get key from cookie or header
    local key, _ = cookie:get(sessionCookieKey)

    -- distinguish key acquisition from cookie/header
    local is_key_from_cookie = false
    if key then
        is_key_from_cookie = true
    else
        local auth_header = ngx.var.http_authorization
        -- parse Authorization: Bearer <token>
        if auth_header then
            key = parse_auth_header(auth_header)
        end
    end

    -- key is neither in cookie nor header
    if not key then
        -- set anonymous headers and return
        ngx.req.set_header("X-Hasura-role", "anonymous")
        ngx.req.set_header("X-Hasura-Allowed-Roles", "anonymous")
        ngx.req.set_header("X-Hasura-User-Id", "0")
        return
    end

    local query = function(red) return red:get(key) end

    -- Fetch the session
    local resp = run_query(query)

    -- Couldn't find the key
    if resp == ngx.null then
        local ret_msg = ""
        if is_key_from_cookie then
            -- Force the cookie expiration across all subdomains
            inject_cookie_expiration(cookie, base_domain)
            -- Return 302 Temporarily Moved redirect to same url
            return ngx.redirect(ngx.var.request_uri)
        else
            -- Set body if request has token
            ret_msg = "invalid authorization token"
            -- Set www-authenticate
            ngx.header["WWW-Authenticate"] = {"Login", "Bearer"}
            -- Return unautorized response
            return_with(ngx.HTTP_UNAUTHORIZED, ret_msg)
        end
    end

    local sess_hdrs = with_500("cjson.decode", cjson.decode, resp)
    with_500("sess_hdrs type", check_type, sess_hdrs, "table")

    -- In case the user has already requested a role, save it
    local requested_role = ngx.req.get_headers()["X-Hasura-Role"]

    -- Great, time to set headers
    for hdr_name, hdr_value in pairs(sess_hdrs) do
        -- The value should be string or table
        -- with_500("hdr_value type", check_type, hdr_value, "string")
        ngx.req.clear_header(hdr_name)
        ngx.req.set_header(hdr_name, hdr_value)
    end

    -- In case the user has requested a particular header, check if that header is valid
    -- and set that header
    if requested_role then
        local user_roles = getUserRoles()
        if not hasOverlap({requested_role}, user_roles) then
          msg = "invalid x-hasura-role requested: " .. requested_role
          return_with(ngx.HTTP_UNAUTHORIZED, msg)
        end
        -- reset the role header, in case hauthy overwrote it
        ngx.req.clear_header("X-Hasura-Role")
        ngx.req.set_header("X-Hasura-Role", requested_role)
    end

    -- Add a session-id header (only to be used by hauthy)
    ngx.req.set_header("X-Hasura-Session-Id", key)
    ngx.req.clear_header("Authorization")
end

local function redirectWithNext(url)
    local current_uri = ngx.var.scheme .. '://' .. ngx.var.host .. ngx.var.request_uri
    return ngx.redirect(url .. "?" .. ngx.encode_args({redirect_url=current_uri}))
end

function _M.authz(authzPolTxt)
    local authzPol = with_500("cjson.decode.authz", cjson.decode, authzPolTxt)
    local allowedRoles = authzPol["restrictToRoles"]
    local noSessionRedirectUrl = authzPol["noSessionRedirectUrl"]
    local noAccessRedirectUrl = authzPol["noAccessRedirectUrl"]

    local user_roles = getUserRoles()
    local sessionId = ngx.req.get_headers()["X-Hasura-Session-Id"]
    -- when there is no session token
    if not sessionId then
        -- if a noSessionRedirectUrl is configured
        if noSessionRedirectUrl then
            redirectWithNext(noSessionRedirectUrl)
        -- otherwise return an error
        else
            return_with(ngx.HTTP_UNAUTHORIZED, "access restricted")
        end
    else
        -- if there is no overlap
        if not hasOverlap(user_roles,allowedRoles) then
            -- if a redirect url is configured
            if noAccessRedirectUrl then
                redirectWithNext(noAccessRedirectUrl)
            -- otherwise return an error
            else
                return_with(ngx.HTTP_UNAUTHORIZED, "access restricted")
            end
        end
    end

end

return _M
