#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re, shutil, subprocess, sys, tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAP_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*(?:/[a-z0-9]+(?:-[a-z0-9]+)*)*$")
REQ_RE = re.compile(r"^### Requirement:\s*(.+?)\s*$", re.MULTILINE)
SLUG_RE = re.compile(r"[^a-z0-9]+")

class DecisionError(RuntimeError):
    pass

def load_event(path):
    try:
        data=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc:
        raise DecisionError(f"cannot read Decision Event: {exc}") from exc
    if not isinstance(data,dict):
        raise DecisionError("Decision Event root must be a JSON object")
    return data

def accepted_date(value):
    if not isinstance(value,str):
        raise DecisionError("accepted_at must be an ISO-8601 string")
    try:
        parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as exc:
        raise DecisionError("accepted_at must be valid ISO-8601") from exc
    if parsed.tzinfo is None:
        raise DecisionError("accepted_at must include a timezone")
    return parsed.date().strftime("%Y%m%d")

def slug(value,limit=56):
    out=SLUG_RE.sub("-",value.lower()).strip("-")
    if not out:
        raise DecisionError("title/change_name does not produce a valid slug")
    return out[:limit].rstrip("-")

def fingerprint(event):
    keys=("project","title","summary","rationale","behavior_change","non_goals","alternatives","capabilities")
    raw=json.dumps({k:event.get(k) for k in keys},ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()
    return hashlib.sha256(raw).hexdigest()

def knowledge_id(event,fp):
    return f"DRL-DEC-{accepted_date(event['accepted_at'])}-{fp[:8].upper()}"

def make_change_name(event,fp):
    explicit=event.get("change_name")
    if explicit is not None:
        if not isinstance(explicit,str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*",explicit):
            raise DecisionError("change_name must be kebab-case")
        return explicit
    return f"decision-{slug(str(event.get('title','decision')))}-{fp[:6]}"

def req_names(path):
    if not path.is_file():
        return set()
    return {m.group(1).strip() for m in REQ_RE.finditer(path.read_text(encoding="utf-8"))}

def validate_scenarios(req):
    scenarios=req.get("scenarios")
    if not isinstance(scenarios,list) or not scenarios:
        raise DecisionError(f"requirement {req.get('name')!r} must include scenarios")
    for s in scenarios:
        if not isinstance(s,dict):
            raise DecisionError("scenario must be an object")
        for key in ("name","when","then"):
            if not isinstance(s.get(key),str) or not s[key].strip():
                raise DecisionError(f"scenario {key} must be non-empty")

def validate_capability(root,cap):
    if not isinstance(cap,dict):
        raise DecisionError("capability must be an object")
    path,kind=cap.get("path"),cap.get("kind")
    if not isinstance(path,str) or not CAP_RE.fullmatch(path):
        raise DecisionError(f"invalid capability path: {path!r}")
    if kind not in {"existing","new"}:
        raise DecisionError(f"{path}: kind must be existing or new")
    current=root/"openspec"/"specs"/path/"spec.md"
    if kind=="existing" and not current.is_file():
        raise DecisionError(f"{path}: existing capability does not exist")
    if kind=="new" and current.exists():
        raise DecisionError(f"{path}: new capability already exists")
    if kind=="new" and (not isinstance(cap.get("purpose"),str) or len(cap["purpose"].strip())<50):
        raise DecisionError(f"{path}: new capability purpose must be at least 50 characters")
    ops=cap.get("requirements")
    if not isinstance(ops,list) or not ops:
        raise DecisionError(f"{path}: requirement operations are required")
    current_names,added=req_names(current),set()
    for req in ops:
        if not isinstance(req,dict):
            raise DecisionError(f"{path}: requirement operation must be an object")
        op=req.get("operation")
        if op not in {"ADDED","MODIFIED","REMOVED","RENAMED"}:
            raise DecisionError(f"{path}: unsupported operation {op!r}")
        if kind=="new" and op!="ADDED":
            raise DecisionError(f"{path}: new capabilities may contain only ADDED")
        if op in {"ADDED","MODIFIED"}:
            name,text=req.get("name"),req.get("text")
            if not isinstance(name,str) or not name.strip():
                raise DecisionError(f"{path}: {op} needs requirement name")
            if not isinstance(text,str) or ("SHALL" not in text and "MUST" not in text):
                raise DecisionError(f"{path}: {op} {name!r} must contain SHALL or MUST")
            validate_scenarios(req)
            if op=="ADDED":
                if name in current_names or name in added:
                    raise DecisionError(f"{path}: ADDED {name!r} already exists")
                added.add(name)
            elif name not in current_names:
                raise DecisionError(f"{path}: MODIFIED {name!r} does not exist")
        elif op=="REMOVED":
            name=req.get("name")
            if not isinstance(name,str) or name not in current_names:
                raise DecisionError(f"{path}: REMOVED {name!r} does not exist")
            if not req.get("reason") or not req.get("migration"):
                raise DecisionError(f"{path}: REMOVED {name!r} needs reason and migration")
        else:
            old,new=req.get("from"),req.get("to")
            if not isinstance(old,str) or old not in current_names:
                raise DecisionError(f"{path}: RENAMED source {old!r} does not exist")
            if not isinstance(new,str) or not new.strip() or new in current_names:
                raise DecisionError(f"{path}: invalid RENAMED target {new!r}")

def validate_event(root,event):
    allowed={"schema_version","status","accepted_at","project","title","summary","rationale","behavior_change",
             "change_name","non_goals","sources","alternatives","capabilities","tasks"}
    unknown=sorted(set(event)-allowed)
    if unknown:
        raise DecisionError("unknown fields: "+", ".join(unknown))
    if event.get("schema_version")!=1:
        raise DecisionError("schema_version must be 1")
    if event.get("status")!="accepted":
        raise DecisionError("only status=accepted may create an OpenSpec change")
    if event.get("project")!="data-relay-link":
        raise DecisionError("project must be data-relay-link")
    accepted_date(event.get("accepted_at"))
    for key,minlen in (("title",3),("summary",10),("rationale",10)):
        value=event.get(key)
        if not isinstance(value,str) or len(value.strip())<minlen:
            raise DecisionError(f"{key} must contain at least {minlen} characters")
    if not isinstance(event.get("behavior_change"),bool):
        raise DecisionError("behavior_change must be boolean")
    caps=event.get("capabilities",[])
    if not isinstance(caps,list):
        raise DecisionError("capabilities must be an array")
    if event["behavior_change"] and not caps:
        raise DecisionError("behavior_change=true requires capability deltas")
    if not event["behavior_change"] and caps:
        raise DecisionError("behavior_change=false must not include capability deltas")
    for cap in caps:
        validate_capability(root,cap)
    for alt in event.get("alternatives",[]):
        if not isinstance(alt,dict) or alt.get("outcome") not in {"selected","rejected"} or not alt.get("name") or not alt.get("reason"):
            raise DecisionError("invalid alternative")
    for src in event.get("sources",[]):
        if not isinstance(src,dict) or not src.get("type") or not src.get("ref"):
            raise DecisionError("source requires type and ref")
    for task in event.get("tasks",[]):
        if not isinstance(task,dict) or not task.get("description") or not task.get("verification"):
            raise DecisionError("task requires description and verification")

def find_duplicate(root,fp):
    for stored in (root/"openspec"/"changes").glob("**/decision-event.json"):
        try:
            data=json.loads(stored.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data,dict) and data.get("_capture",{}).get("fingerprint")==fp:
            return stored
    return None

def render_requirement(req):
    lines=[f"### Requirement: {req['name']}",req["text"].strip(),""]
    for s in req["scenarios"]:
        lines += [f"#### Scenario: {s['name']}",f"- **WHEN** {s['when']}",f"- **THEN** {s['then']}",""]
    return "\n".join(lines).rstrip()

def render_delta(cap):
    lines=["# Spec Delta",""]
    if cap["kind"]=="new":
        lines += ["## Purpose","",cap["purpose"].strip(),""]
    grouped={op:[] for op in ("ADDED","MODIFIED","REMOVED","RENAMED")}
    for req in cap["requirements"]:
        grouped[req["operation"]].append(req)
    for op in ("ADDED","MODIFIED","REMOVED","RENAMED"):
        if not grouped[op]:
            continue
        lines += [f"## {op} Requirements",""]
        for req in grouped[op]:
            if op in {"ADDED","MODIFIED"}:
                lines += [render_requirement(req),""]
            elif op=="REMOVED":
                lines += [f"### Requirement: {req['name']}",f"**Reason**: {req['reason']}",f"**Migration**: {req['migration']}",""]
            else:
                tick=chr(96)
                lines += [f"- FROM: {tick}### Requirement: {req['from']}{tick}",f"- TO: {tick}### Requirement: {req['to']}{tick}",""]
    return "\n".join(lines).rstrip()+"\n"

def render_proposal(event,kid):
    new=[c for c in event["capabilities"] if c["kind"]=="new"]
    old=[c for c in event["capabilities"] if c["kind"]=="existing"]
    lines=["# Proposal","","## Why","",event["summary"].strip(),"",f"Knowledge ID: {kid}","",
           "## What Changes","",f"- Accepted decision: {event['title'].strip()}",
           f"- Rationale: {event['rationale'].strip()}",
           "- Preserve the accepted decision and rejected alternatives as durable history.",
           "- Do not archive until implementation and validation evidence are complete.","",
           "## Capabilities","","### New Capabilities",""]
    lines += [f"- {c['path']}: {c['purpose'].strip()}" for c in new] if new else ["None."]
    lines += ["","### Modified Capabilities",""]
    lines += [f"- {c['path']}: update accepted behavior per this decision." for c in old] if old else ["None."]
    lines += ["","## Impact","","Planning artifacts and product contract are updated; implementation occurs only during apply."]
    if event.get("non_goals"):
        lines += ["","Explicit non-goals:"]+[f"- {x}" for x in event["non_goals"]]
    return "\n".join(lines).rstrip()+"\n"

def render_design(event,kid):
    lines=["# Design","","## Context","",f"Knowledge ID: {kid}.","",event["summary"].strip(),"",
           "## Goals / Non-Goals","","**Goals:**",
           "- Preserve and implement the explicitly accepted decision without silently expanding scope.",
           "- Keep requirements, rationale, alternatives, implementation, and evidence traceable.","","**Non-Goals:**"]
    lines += [f"- {x}" for x in (event.get("non_goals") or ["No scope beyond the accepted decision."])]
    lines += ["","## Decisions","",f"### Decision: {event['title'].strip()}","",event["rationale"].strip(),""]
    if event.get("alternatives"):
        lines += ["### Alternatives considered",""]+[f"- **{a['name']}** — {a['outcome']}: {a['reason']}" for a in event["alternatives"]]
    if event.get("sources"):
        lines += ["","### Sources",""]
        for s in event["sources"]:
            lines.append(f"- {s['type']}: {s['ref']}"+(f" — {s['note']}" if s.get("note") else ""))
    lines += ["","## Risks / Trade-offs","",
              "- **[Risk] Implementation diverges from the accepted contract.** → Strict validation plus focused tests/E2E before archive.",
              "- **[Risk] Later discussion rewrites rationale.** → Supersede through a new accepted Decision Event."]
    return "\n".join(lines).rstrip()+"\n"

def render_tasks(event):
    tasks=list(event.get("tasks") or [])
    if event["behavior_change"] and not tasks:
        tasks=[
          {"description":"Implement the accepted behavior without broadening scope","verification":"focused unit/regression tests for every changed requirement pass"},
          {"description":"Run relevant real E2E or qualification coverage","verification":"evidence demonstrates the changed externally observable behavior"},
          {"description":"Synchronize affected derived documentation","verification":"derived docs no longer contradict the current OpenSpec contract"}]
    if not tasks:
        tasks=[{"description":"Apply the accepted governance/documentation decision","verification":"the intended artifact exists and strict OpenSpec validation passes"}]
    lines=["# Tasks","","## 1. Accepted decision implementation",""]
    for i,t in enumerate(tasks,1):
        lines.append(f"- [ ] 1.{i} {t['description']}; verify: {t['verification']}.")
    lines += ["","## 2. Closure","",
              "- [ ] 2.1 Run openspec validate --all --strict and verify all specs/changes pass.",
              "- [ ] 2.2 Capture implementation/E2E evidence, then archive only after qualification is complete."]
    return "\n".join(lines).rstrip()+"\n"

def metadata_yaml(event):
    date=accepted_date(event["accepted_at"]); date=f"{date[:4]}-{date[4:6]}-{date[6:]}"
    lines=["schema: spec-driven",f"created: {date}","goal: "+json.dumps(event["summary"].strip(),ensure_ascii=False)]
    if not event["behavior_change"]:
        lines.append("skip_specs: true")
    return "\n".join(lines)+"\n"

def write_change(root,event,name,kid,fp):
    final=root/"openspec"/"changes"/name
    if final.exists():
        raise DecisionError(f"OpenSpec change already exists: {name}")
    tmp_root=Path(tempfile.mkdtemp(prefix=".decision-capture-",dir=root)); tmp=tmp_root/name
    try:
        tmp.mkdir(parents=True)
        (tmp/".openspec.yaml").write_text(metadata_yaml(event),encoding="utf-8")
        (tmp/"proposal.md").write_text(render_proposal(event,kid),encoding="utf-8")
        (tmp/"design.md").write_text(render_design(event,kid),encoding="utf-8")
        (tmp/"tasks.md").write_text(render_tasks(event),encoding="utf-8")
        if event["behavior_change"]:
            for cap in event["capabilities"]:
                out=tmp/"specs"/cap["path"]/"spec.md"; out.parent.mkdir(parents=True,exist_ok=True)
                out.write_text(render_delta(cap),encoding="utf-8")
        stored=dict(event); stored["_capture"]={"knowledge_id":kid,"fingerprint":fp,"change_name":name,"generator":"automation/decision_capture/capture_decision.py"}
        (tmp/"decision-event.json").write_text(json.dumps(stored,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        shutil.move(str(tmp),str(final))
    finally:
        shutil.rmtree(tmp_root,ignore_errors=True)
    return final

def validate_generated(root,name,change_dir):
    try:
        proc=subprocess.run(["openspec","validate",name,"--strict","--json"],cwd=root,capture_output=True,text=True,check=False)
    except OSError as exc:
        shutil.rmtree(change_dir,ignore_errors=True)
        raise DecisionError(f"cannot execute openspec: {exc}") from exc
    if proc.returncode:
        details=(proc.stdout+"\n"+proc.stderr).strip(); shutil.rmtree(change_dir,ignore_errors=True)
        raise DecisionError("generated change failed strict validation:\n"+details)

def capture(root,event_path):
    event=load_event(event_path); validate_event(root,event)
    fp=fingerprint(event); duplicate=find_duplicate(root,fp)
    if duplicate:
        raise DecisionError(f"duplicate accepted decision already captured at {duplicate}")
    kid=knowledge_id(event,fp); name=make_change_name(event,fp)
    change_dir=write_change(root,event,name,kid,fp); validate_generated(root,name,change_dir)
    return {"status":"created","knowledge_id":kid,"fingerprint":fp,"change_name":name,"change_path":str(change_dir)}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event",required=True,type=Path); parser.add_argument("--repo-root",type=Path,default=ROOT)
    args=parser.parse_args(); root=args.repo_root.resolve()
    if not (root/"openspec"/"config.yaml").is_file():
        print(json.dumps({"status":"error","error":"OpenSpec root not initialized"})); return 2
    try:
        result=capture(root,args.event.resolve())
    except DecisionError as exc:
        print(json.dumps({"status":"error","error":str(exc)},ensure_ascii=False)); return 2
    print(json.dumps(result,ensure_ascii=False,indent=2)); return 0

if __name__=="__main__":
    sys.exit(main())
