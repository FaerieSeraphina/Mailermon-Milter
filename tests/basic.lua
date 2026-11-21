
mt.echo("*** MailerMon basic message test ***")

local conn = mt.connect("inet:12345@127.0.0.1")
assert(conn ~= nil, "Connection failed")

assert(mt.conninfo(conn, "localhost", "127.0.0.1") == nil)
assert(mt.getreply(conn) == SMFIR_CONTINUE)

mt.echo("Sending MAIL FROM")

local ok, result = pcall(
    mt.mailfrom, conn, "sender@example.net"
)
mt.echo("MAIL call: " .. tostring(ok) .. " / " .. tostring(result))

if not ok then
    error("MAIL FROM failed: " .. tostring(result))
end

mt.echo("Reading MAIL reply")
local reply = mt.getreply(conn)
mt.echo("MAIL reply: " .. tostring(reply))

mt.echo("Sending RCPT TO")

ok, result = pcall(
    mt.rcptto, conn, "recipient@example.net"
)
mt.echo("RCPT call: " .. tostring(ok) .. " / " .. tostring(result))

if not ok then
    error("RCPT TO failed: " .. tostring(result))
end

reply = mt.getreply(conn)
mt.echo("RCPT reply: " .. tostring(reply))

assert(mt.header(conn, "From", "sender@example.net") == nil)
assert(mt.getreply(conn) == SMFIR_CONTINUE)

assert(mt.header(conn, "Subject", "MailerMon test") == nil)
assert(mt.getreply(conn) == SMFIR_CONTINUE)

mt.echo("Sending end-of-headers")

local ok, result = pcall(mt.eoh, conn)
mt.echo("EOH call: " .. tostring(ok) .. " / " .. tostring(result))
assert(ok, tostring(result))

local reply = mt.getreply(conn)
mt.echo("EOH reply: " .. tostring(reply))
assert(reply == SMFIR_CONTINUE)

mt.echo("Sending end-of-message")

ok, result = pcall(mt.eom, conn)
mt.echo("EOM call: " .. tostring(ok) .. " / " .. tostring(result))
assert(ok, tostring(result))

reply = mt.getreply(conn)
mt.echo("EOM reply: " .. tostring(reply))

assert(reply == SMFIR_CONTINUE)

local ok, result = pcall(
    mt.eom_check, conn, MT_HDRADD, "X-FSMailermon-ID"
)

mt.echo("eom_check success: " .. tostring(ok))
mt.echo("eom_check result: " .. tostring(result))

assert(ok and result, "MailerMon did not add its identity header")
mt.echo("Checking header insertion")

mt.echo("Retrieving identity header")

local get_ok, token = pcall(
    mt.getheader, conn, "X-FSMailermon-ID", 0
)

mt.echo("getheader success: " .. tostring(get_ok))
mt.echo("getheader result: " .. tostring(token))

assert(get_ok and token ~= nil, "Could not retrieve identity header")

mt.echo("Identity token: " .. token)

mt.disconnect(conn)
mt.echo("*** Basic message test passed ***")
