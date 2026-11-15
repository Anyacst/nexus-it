from __future__ import annotations
import hashlib, http.client, json, re, struct, tempfile, threading, unittest
from pathlib import Path
from urllib.parse import urlencode

from nexus_iot.capture import CaptureError, packets
from nexus_iot.evaluate import run
from nexus_iot.pipeline import analyze, sign_manifest, verify_manifest
from nexus_iot.scenarios import MARKER_NAME, build, build_sample_capture
from nexus_iot.web import create_server


def write_rows(path: Path, rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text("".join(json.dumps(x)+"\n" for x in rows),encoding="utf-8")

def sample_event(event_id, ts, device="sensor-A", event="heartbeat", sequence=None):
    r={"event_id":event_id,"timestamp":ts,"device":device,"event":event}
    if sequence is not None:r["sequence"]=sequence
    return r

def make_eth_udp(src="192.0.2.1",dst="198.51.100.2",sport=12345,dport=1883):
    import ipaddress
    udp=struct.pack("!HHHH",sport,dport,8,0)
    ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(udp),1,0,64,17,0,ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed)
    return bytes.fromhex("0200000000020200000000010800")+ip+udp

class PipelineTests(unittest.TestCase):
    def test_hash_manifest_confirmed_and_read_only(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"evidence";out=root/"derived";ev.mkdir()
            a=ev/"sensor-A.jsonl";g=ev/"gateway.jsonl"
            write_rows(a,[sample_event("e-1",105)]);write_rows(g,[{"event_id":"e-1","timestamp":100,"event":"heartbeat"}])
            before=a.read_bytes();digest=hashlib.sha256(before).hexdigest()
            report=analyze(ev,out)
            self.assertEqual(a.read_bytes(),before)
            self.assertEqual(next(x["sha256"] for x in report["evidence_manifest"] if x["relative_path"]=="sensor-A.jsonl"),digest)
            row=next(x for x in report["timeline"] if x["event_id"]=="e-1")
            self.assertEqual(row["label"],"Confirmed")
            self.assertAlmostEqual(report["clock_estimates"]["sensor-A.jsonl"]["offset_seconds"],5)
            self.assertTrue((out/"report.md").exists())

    def test_previous_hash_detects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"evidence";ev.mkdir();out=root/"derived"
            f=ev/"sensor.jsonl";write_rows(f,[sample_event("e-1",100)])
            analyze(ev,out);f.write_text('{"event_id":"e-1","timestamp":100,"device":"sensor-A","event":"edited"}\n',encoding="utf-8")
            report=analyze(ev,out)
            self.assertTrue(any("SHA-256 differs" in x for x in report["validation_issues"]))

    def test_timestamp_shift_and_conflicting_claim_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"e";ev.mkdir();out=root/"o"
            dev=[sample_event(f"e-{i}",100+i+(10 if i>=3 else 0),sequence=i) for i in range(1,5)]
            gw=[{"event_id":f"e-{i}","timestamp":100+i,"event":"heartbeat"} for i in range(1,5)]
            dev[1]["event"]="tampered"
            write_rows(ev/"sensor-A.jsonl",dev);write_rows(ev/"gateway.jsonl",gw)
            report=analyze(ev,out)
            self.assertTrue(any("clock anchors do not fit" in x for x in report["validation_issues"]))
            self.assertTrue(any("conflicting event claims" in x for x in report["validation_issues"]))
            conflict=next(x for x in report["timeline"] if x["event_id"]=="e-2")
            self.assertEqual(conflict["label"],"Single-source")

    def test_stable_clock_step_is_fit_as_two_explicit_segments(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"e";ev.mkdir();device=[];gateway=[]
            for i in range(8):
                eid=f"anchor-{i}";t=1000+i*10;offset=5 if i<4 else 17
                device.append(sample_event(eid,t+offset,"sensor-A","heartbeat",i+1))
                gateway.append({"event_id":eid,"timestamp":t,"event":"heartbeat","peer":"sensor-A"})
            write_rows(ev/"sensor-A.jsonl",device);write_rows(ev/"gateway.jsonl",gateway)
            report=analyze(ev,root/"out");model=report["clock_estimates"]["sensor-A.jsonl"]
            self.assertTrue(model["applied"]);self.assertEqual(len(model["segments"]),2)
            self.assertTrue(any("step change" in x for x in report["validation_issues"]))
            row=next(e for e in report["timeline"] if e["event_id"]=="anchor-7")
            self.assertAlmostEqual(row["timestamp"],1070)

    def test_missing_sequences_are_unknown_not_fabricated(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"e";ev.mkdir()
            write_rows(ev/"sensor-A.jsonl",[sample_event("e-1",100,sequence=1),sample_event("e-3",106,sequence=3)])
            report=analyze(ev,root/"out")
            gaps=[x for x in report["timeline"] if x["label"]=="Unknown gap"]
            self.assertEqual(len(gaps),1);self.assertIn("Unknown",gaps[0]["event"])

    def test_extreme_sequence_gap_is_summarized_without_expanding_range(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"e";ev.mkdir()
            write_rows(ev/"sensor-A.jsonl",[sample_event("first",100,sequence=1),sample_event("last",101,sequence=10**12)])
            report=analyze(ev,root/"out")
            self.assertTrue(any("999999999999" in x for x in report["validation_issues"]))
            gap=next(x for x in report["timeline"] if x["label"]=="Unknown gap")
            self.assertIn("999999999998",gap["event"])

    def test_gateway_witness_of_absent_device_record_is_unknown_gap(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"e";ev.mkdir()
            write_rows(ev/"sensor-A.jsonl",[sample_event("e-1",100)])
            write_rows(ev/"gateway.jsonl",[{"event_id":"e-1","timestamp":100,"event":"boot","peer":"sensor-A"},
                {"event_id":"e-2","timestamp":101,"event":"command","peer":"sensor-A"}])
            report=analyze(ev,root/"out")
            gaps=[x for x in report["timeline"] if x["label"]=="Unknown gap"]
            self.assertTrue(any("e-2" in x["event"] for x in gaps))
            self.assertTrue(any("absence cause is undetermined" in x for x in report["validation_issues"]))

    def test_periodicity_yields_explicit_inferred_hypothesis(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"e";ev.mkdir()
            rows=[sample_event(f"e-{i}",t,"sensor-A","heartbeat",i) for i,t in [(1,0),(2,10),(4,30),(5,40)]]
            write_rows(ev/"sensor-A.jsonl",rows)
            report=analyze(ev,root/"out")
            inferred=[x for x in report["timeline"] if x["label"]=="Inferred"]
            self.assertTrue(inferred)
            self.assertIn("Possible missing periodic",inferred[0]["event"])

    def test_malformed_input_is_reported_and_other_records_survive(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"e";ev.mkdir()
            (ev/"sensor-A.jsonl").write_text('{broken\n'+json.dumps(sample_event("e-1",100))+"\n"+json.dumps(sample_event("e-2",float("nan"))),encoding="utf-8")
            report=analyze(ev,root/"out")
            self.assertEqual(len(report["timeline"]),1)
            self.assertTrue(any("malformed JSON" in x for x in report["validation_issues"]))
            self.assertTrue(any("finite" in x for x in report["validation_issues"]))

    def test_output_must_not_be_inside_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"e";ev.mkdir()
            with self.assertRaises(ValueError):analyze(ev,ev/"out")

class CaptureTests(unittest.TestCase):
    def test_classic_pcap_headers_only(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"demo.pcap";frame=make_eth_udp()
            path.write_bytes(b"\xd4\xc3\xb2\xa1"+struct.pack("<HHIIII",2,4,0,0,65535,1)+struct.pack("<IIII",100,250000,len(frame),len(frame))+frame)
            result=list(packets(path));self.assertEqual(len(result),1)
            self.assertEqual(result[0]["protocol"],"udp");self.assertEqual(result[0]["destination_port"],1883)
            self.assertNotIn("payload",result[0]);self.assertAlmostEqual(result[0]["timestamp"],100.25)

    def test_capture_flow_aggregation_preserves_count_and_time_bounds(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"repeat.pcap";frame=make_eth_udp()
            data=bytearray(b"\xd4\xc3\xb2\xa1"+struct.pack("<HHIIII",2,4,0,0,65535,1))
            for sec,usec in ((100,100000),(100,700000)):
                data.extend(struct.pack("<IIII",sec,usec,len(frame),len(frame))+frame)
            path.write_bytes(data);rows=list(packets(path,aggregate_seconds=1))
            self.assertEqual(len(rows),1);self.assertEqual(rows[0]["packet_count"],2)
            self.assertAlmostEqual(rows[0]["timestamp_start"],100.1);self.assertAlmostEqual(rows[0]["timestamp_end"],100.7)

    def test_pcapng_enhanced_packet_block(self):
        with tempfile.TemporaryDirectory() as td:
            frame=make_eth_udp();pad=frame+b"\x00"*((4-len(frame)%4)%4)
            shb=struct.pack("<II IHHq I",0x0A0D0D0A,28,0x1A2B3C4D,1,0,-1,28)
            idb=struct.pack("<IIHHII",1,20,1,0,65535,20)
            body=struct.pack("<IIIII",0,0,1_500_000, len(frame),len(frame))+pad
            epb=struct.pack("<II",6,12+len(body))+body+struct.pack("<I",12+len(body))
            path=Path(td)/"demo.pcapng";path.write_bytes(shb+idb+epb)
            result=list(packets(path));self.assertEqual(len(result),1);self.assertEqual(result[0]["protocol"],"udp")
            self.assertAlmostEqual(result[0]["timestamp"],1.5)

    def test_ipv4_noninitial_fragment_does_not_get_fake_ports(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"fragment.pcap";frame=bytearray(make_eth_udp());frame[20:22]=b"\x00\x01"
            path.write_bytes(b"\xd4\xc3\xb2\xa1"+struct.pack("<HHIIII",2,4,0,0,65535,1)+struct.pack("<IIII",100,0,len(frame),len(frame))+frame)
            packet=list(packets(path))[0]
            self.assertTrue(packet["is_fragment"]);self.assertIsNone(packet["source_port"]);self.assertIsNone(packet["destination_port"])

    def test_pcapng_obsolete_packet_block_and_interface_timestamp_offset(self):
        with tempfile.TemporaryDirectory() as td:
            frame=make_eth_udp();pad=frame+b"\x00"*((4-len(frame)%4)%4)
            shb=struct.pack("<II IHHq I",0x0A0D0D0A,28,0x1A2B3C4D,1,0,-1,28)
            # if_tsoffset option: code 14, length 8, signed +5 seconds, followed by end option.
            options=struct.pack("<HHqHH",14,8,5,0,0)
            idb_body=struct.pack("<HHI",1,0,65535)+options
            idb_len=8+len(idb_body)+4;idb=struct.pack("<II",1,idb_len)+idb_body+struct.pack("<I",idb_len)
            body=struct.pack("<HHIIII",0,0,0,1_500_000,len(frame),len(frame))+pad
            block_len=8+len(body)+4;pb=struct.pack("<II",2,block_len)+body+struct.pack("<I",block_len)
            path=Path(td)/"packet-block.pcapng";path.write_bytes(shb+idb+pb)
            result=list(packets(path));self.assertEqual(len(result),1);self.assertAlmostEqual(result[0]["timestamp"],6.5)

    def test_bad_capture_fails_clearly(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"bad.pcap";p.write_bytes(b"bad")
            with self.assertRaises(CaptureError):list(packets(p))

    def test_sample_capture_analyzes_as_gateway_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);build_sample_capture(root)
            report=analyze(root/"sample_inputs",root/"derived")
            packets_report=[e for e in report["timeline"] if e["event"]=="network_packet"]
            self.assertEqual(len(packets_report),2)
            self.assertEqual(packets_report[0]["network_summary"]["protocol"],"udp")

    def test_configured_pcap_flow_rule_correlates_with_device_event(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"evidence";ev.mkdir()
            device=[sample_event(f"anchor-{i}",1000+i+5,"sensor-A","heartbeat",i) for i in range(1,4)]
            device.append(sample_event("auth-1",1008,"sensor-A","auth_fail",4))
            gateway=[{"event_id":f"anchor-{i}","timestamp":1000+i,"event":"heartbeat","peer":"sensor-A"} for i in range(1,4)]
            write_rows(ev/"sensor-A.jsonl",device);write_rows(ev/"gateway.jsonl",gateway)
            (ev/"devices.json").write_text(json.dumps({"device_ips":{"sensor-A":"192.0.2.1"},"correlation_rules":[
                {"id":"mqtt-auth","device":"sensor-A","event":"auth_fail","protocol":"udp","direction":"outbound","destination_port":1883,"window_seconds":0.2}]}),encoding="utf-8")
            frame=make_eth_udp(dport=1883)
            capture=ev/"gateway.pcap"
            capture.write_bytes(b"\xd4\xc3\xb2\xa1"+struct.pack("<HHIIII",2,4,0,0,65535,1)+struct.pack("<IIII",1003,0,len(frame),len(frame))+frame)
            report=analyze(ev,root/"derived")
            event=next(x for x in report["timeline"] if x["event_id"]=="auth-1")
            self.assertEqual(event["label"],"Confirmed")
            self.assertTrue(any("matched configured rule mqtt-auth" in x for x in event["supporting_evidence"]))
            self.assertTrue(any(x["relative_path"]=="devices.json" for x in report["evidence_manifest"]))

class IntegrationTests(unittest.TestCase):
    def test_detached_manifest_signature_detects_edits(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"e";ev.mkdir();write_rows(ev/"sensor.jsonl",[sample_event("id",1)])
            key=root/"secret.key";key.write_bytes(b"k"*32);out=root/"out"
            report=analyze(ev,out,signing_key=key);manifest=out/"evidence_manifest.json";signature=out/"evidence_manifest.sig"
            self.assertTrue(verify_manifest(manifest,signature,key))
            manifest.write_text("[]",encoding="utf-8");self.assertFalse(verify_manifest(manifest,signature,key))
            self.assertEqual(len(report["evidence_manifest"]),1)

    def test_evaluator_refuses_to_overwrite_unmarked_user_data(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);user_data=root/"data"/"synthetic";user_data.mkdir(parents=True)
            sentinel=user_data/"keep.txt";sentinel.write_text("user file",encoding="utf-8")
            with self.assertRaises(RuntimeError):run(root)
            self.assertEqual(sentinel.read_text(encoding="utf-8"),"user file")

    def test_regeneration_requires_verified_owned_data_and_explicit_flag(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);dataset=build(root)
            marker=dataset/MARKER_NAME;manifest=json.loads(marker.read_text(encoding="utf-8"))
            manifest["generator_version"]="old-version"
            marker.write_text(json.dumps(manifest),encoding="utf-8")
            with self.assertRaises(RuntimeError):build(root)
            self.assertEqual(build(root,regenerate=True),dataset)
            new_manifest=json.loads(marker.read_text(encoding="utf-8"))
            self.assertNotEqual(new_manifest["generator_version"],"old-version")
            edited=dataset/"evidence"/"E1"/"sensor-A.jsonl"
            edited.write_text(edited.read_text(encoding="utf-8")+"{}\n",encoding="utf-8")
            with self.assertRaises(RuntimeError):build(root,regenerate=True)

    def test_e1_e7_harness_generates_separate_truth_and_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);results=run(root)
            self.assertEqual(len(results),10)
            self.assertFalse(any("truth.json" in f.name for f in (root/"data"/"synthetic"/"evidence"/"E1").rglob("*")))
            metrics=json.loads((root/"derived"/"evaluation"/"metrics.json").read_text())
            self.assertEqual(metrics["scenario_count"],10)
            self.assertEqual(metrics["tamper_detection"]["recall"],1.0)
            self.assertEqual(metrics["tamper_detection"]["false_positive_rate"],0.0)
            self.assertEqual(metrics["clock_anomaly_detection"]["recall"],1.0)
            self.assertEqual(metrics["aggregate"]["mean_unknown_gap_recall"],1.0)
            inference=next(x for x in results if x["condition"]=="T3")
            self.assertEqual(inference["inferred_event_recall"],1.0)
            e6=next(x for x in results if x["condition"]=="E6")
            self.assertGreater(e6["false_positive_events"],0)
            e7=next(x for x in results if x["condition"]=="E7")
            self.assertAlmostEqual(e7["evidence_completeness"],15/17)
            t1=next(x for x in results if x["condition"]=="T1")
            t2=next(x for x in results if x["condition"]=="T2")
            self.assertTrue(t1["tamper_alert"]);self.assertTrue(t2["tamper_alert"])
            run(root)
            metrics2=json.loads((root/"derived"/"evaluation"/"metrics.json").read_text())
            self.assertEqual(metrics2["tamper_detection"]["false_positive_rate"],metrics["tamper_detection"]["false_positive_rate"])

    def test_local_web_get_and_post(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);ev=root/"evidence";ev.mkdir();write_rows(ev/"sensor-A.jsonl",[sample_event("e-1",100)])
            server=create_server("127.0.0.1",0,root);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                conn=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=5)
                conn.request("GET","/");response=conn.getresponse();page=response.read();self.assertEqual(response.status,200);self.assertIn(b"Analyze a case folder",page)
                body=urlencode({"evidence":str(ev)})
                token=re.search(rb"name=csrf_token value='([^']+)'",page).group(1).decode()
                conn.request("POST","/analyze",body,{"Content-Type":"application/x-www-form-urlencoded"})
                response=conn.getresponse();self.assertEqual(response.status,403);response.read()
                body=urlencode({"evidence":str(ev),"csrf_token":token})
                conn.request("POST","/analyze",body,{"Content-Type":"application/x-www-form-urlencoded"})
                response=conn.getresponse();page=response.read();self.assertEqual(response.status,200);self.assertIn(b"Single-source",page)
                conn.request("GET","/report.json");response=conn.getresponse();report=json.loads(response.read());self.assertEqual(len(report["timeline"]),1)
                conn.close()
            finally:server.shutdown();server.server_close();thread.join(timeout=2)

    def test_web_server_rejects_non_loopback_bind(self):
        with self.assertRaises(ValueError):create_server("0.0.0.0",0,Path.cwd())

if __name__=="__main__":unittest.main()
