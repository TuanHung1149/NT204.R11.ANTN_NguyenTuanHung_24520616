from common import event, check, finish
from flow_tracker import FlowTracker
from rule_parser import parse_rule
from rule_matcher import match_rule

print("T08 - flow:to_server,established kiem chung bang Flow Tracker that")

tracker = FlowTracker()
C, S = "10.0.0.5", "10.0.0.9"


def feed(ev, t):
    # Dua event qua Flow Tracker roi dung trang thai that lam flow context
    flow = tracker.process(ev, now=t)
    return {
        "flow_id": flow.flow_id,
        "state": flow.state,
        "to_server": flow.direction(ev) == "forward",
        "established": flow.state in ("ESTABLISHED", "CLOSING"),
    }


syn = event(src_ip=C, src_port=52133, dst_ip=S, dst_port=80, flags="S")
synack = event(src_ip=S, src_port=80, dst_ip=C, dst_port=52133, flags="SA")
ack = event(src_ip=C, src_port=52133, dst_ip=S, dst_port=80, flags="A")
req = event(src_ip=C, src_port=52133, dst_ip=S, dst_port=80, flags="PA",
            payload=b"GET /admin HTTP/1.1\r\n")
resp = event(src_ip=S, src_port=80, dst_ip=C, dst_port=52133, flags="PA",
             payload=b"HTTP/1.1 200 OK\r\nadmin area\r\n")

ctx_syn = feed(syn, 1.0)
ctx_synack = feed(synack, 1.1)
ctx_ack = feed(ack, 1.2)
ctx_req = feed(req, 1.3)
ctx_resp = feed(resp, 1.4)

for name, ctx in [("SYN", ctx_syn), ("SYN/ACK", ctx_synack), ("ACK", ctx_ack),
                  ("request", ctx_req), ("response", ctx_resp)]:
    print(f"  {name:9} state={ctx['state']:12} to_server={ctx['to_server']} established={ctx['established']}")

rule = parse_rule('alert tcp any any -> any 80 '
                  '(msg:"admin"; flow:to_server,established; content:"admin"; sid:800001;)')

r_syn = match_rule(rule, syn, ctx_syn)
r_req = match_rule(rule, req, ctx_req)
r_resp = match_rule(rule, resp, ctx_resp)

print(f"  rule voi SYN      : match={r_syn['match']} stage={r_syn['stage']} ({r_syn['reason']})")
print(f"  rule voi request  : match={r_req['match']}")
print(f"  rule voi response : match={r_resp['match']} stage={r_resp['stage']} ({r_resp['reason']})")

check(ctx_ack["state"] == "ESTABLISHED", "bat tay 3 buoc -> ESTABLISHED")
check(r_req["match"], "request to_server + established -> MATCH")
check(not r_syn["match"], "SYN chua established -> NO MATCH")
check(r_syn["stage"] == "flow", "SYN bi loai o buoc flow")
check(not r_resp["match"], "response (to_client) -> NO MATCH")
check(r_resp["stage"] == "header", "response bi loai ngay o header (dst_port != 80)")

# Rule header khop ca hai chieu -> chung minh chinh buoc flow loai to_client
rule_bidir = parse_rule('alert tcp any any <> any any '
                        '(msg:"bidir"; flow:to_server,established; content:"admin"; sid:800003;)')
r_bidir = match_rule(rule_bidir, resp, ctx_resp)
print(f"  rule <> + to_server voi response: match={r_bidir['match']} stage={r_bidir['stage']} ({r_bidir['reason']})")
check(not r_bidir["match"], "header khop ca 2 chieu nhung van NO MATCH")
check(r_bidir["stage"] == "flow", "bi loai dung o buoc flow vi khong phai to_server")

# Rule to_client phai khop chieu nguoc lai
rule_client = parse_rule('alert tcp any 80 -> any any '
                         '(msg:"resp"; flow:to_client,established; content:"admin"; sid:800002;)')
r2 = match_rule(rule_client, resp, ctx_resp)
print(f"  rule to_client voi response: match={r2['match']}")
check(r2["match"], "rule to_client khop goi tra ve")

finish("T08")
