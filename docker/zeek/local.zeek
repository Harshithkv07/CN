# HRT-Agent Zeek policy: JSON conn.log, emitted quickly so triage sees flows in near real time.
@load policy/tuning/json-logs.zeek
@load base/protocols/conn

redef LogAscii::use_json = T;

# Emit connection records promptly instead of buffering for minutes.
redef tcp_attempt_delay = 1 sec;      # a SYN with no reply becomes a (half-open) flow quickly
redef tcp_inactivity_timeout = 5 sec;
redef udp_inactivity_timeout = 5 sec;
redef tcp_close_delay = 1 sec;

# Keep only conn.log in the mounted directory; drop protocol logs we don't consume.
event zeek_init()
    {
    Log::disable_stream(HTTP::LOG);
    Log::disable_stream(DNS::LOG);
    Log::disable_stream(Files::LOG);
    }
