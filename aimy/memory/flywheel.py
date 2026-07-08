"""EVX - Hunter Evolution eXperience
Three-source fusion: failure->action | atom-recombine | 3-level distill | benchmark blindspot
"""
from __future__ import annotations
import json, os
from datetime import datetime
from pathlib import Path

# Validator — 确定性验证层（XBOW-style）
try:
    from aimy.tools.validator import Validator
except ImportError:
    Validator = None  # type: ignore

G=chr(27)+"[0;32m"; Y=chr(27)+"[1;33m"; C=chr(27)+"[0;36m"
B=chr(27)+"[1m"; D=chr(27)+"[2m"; R=chr(27)+"[0;31m"; NC=chr(27)+"[0m"
DIGEST_DIR = Path.home()/".aimy"/"digests"
BENCH_HIST = Path.home()/".aimy"/"benchmark_history.jsonl"

FAILURE_TYPES = {
    "waf_blocked":       "WAF blocked",
    "permission_denied": "Permission denied",
    "low_impact":        "Low impact (informative)",
    "duplicate":         "Duplicate",
    "timeout":           "Timeout/unreachable",
    "logic_fail":        "Business logic block",
    "unknown":           "Unknown",
}
# GBK-safe emoji map (Windows console fix)
_EMO = {"ok":"[v]","warn":"[!]","err":"[x]","step":">>"}
FAILURE_ACTIONS = {
    "waf_blocked":       {"action":"generate_bypass_variants","desc":"Generate 5 encoding bypass variants","priority":"high"},
    "permission_denied": {"action":"add_to_idor_queue","desc":"Add to IDOR/Auth Bypass queue","priority":"high"},
    "low_impact":        {"action":"upgrade_chain","desc":"Build exploit chain: SSRF->RCE","priority":"medium"},
    "duplicate":         {"action":"pivot_direction","desc":"Hot zone - switch vuln type now","priority":"medium"},
    "timeout":           {"action":"deprioritize_target","desc":"Lower target weight","priority":"low"},
    "logic_fail":        {"action":"decompose_flow","desc":"Decompose business flow -> state machine bugs","priority":"medium"},
    "unknown":           {"action":"manual_review","desc":"Manual review needed","priority":"low"},
}

def classify_failure(notes:str="", outcome:str="") -> str:
    t = (notes+" "+outcome).lower()
    if outcome=="duplicate" or any(k in t for k in ["duplicate","dup"]):
        return "duplicate"
    if outcome=="informative" or any(k in t for k in ["informative","low impact","by design"]):
        return "low_impact"
    if any(k in t for k in ["waf","blocked","firewall"]):
        return "waf_blocked"
    if any(k in t for k in ["forbidden","unauthorized","denied"]):
        return "permission_denied"
    if any(k in t for k in ["timeout","unreachable"]):
        return "timeout"
    if any(k in t for k in ["logic","flow","state"]):
        return "logic_fail"
    return "unknown"

class TechniqueAtomizer:
    INJ  = ["url_param","header","body","cookie","path","json_field"]
    PROT = ["http","https","gopher","dict","file","ftp","ldap"]
    ENC  = ["plain","url_encode","double_url","base64","unicode"]
    def decompose(self, technique:str) -> dict:
        t = technique.lower()
        return {
            "injection_point": next((p for p in self.INJ  if p.replace("_"," ") in t or p in t), "url_param"),
            "protocol":        next((p for p in self.PROT if p in t), "http"),
            "encoding":        next((e for e in self.ENC  if e.replace("_"," ") in t or e in t), "plain"),
        }
    def recombine(self, atoms:dict, vuln_class:str="") -> list:
        ip, pr, en = atoms["injection_point"], atoms["protocol"], atoms["encoding"]
        variants = []
        for p in [x for x in self.INJ  if x != ip][:2]:
            variants.append({"injection_point":p,"protocol":pr,"encoding":en,
                              "desc":vuln_class+" via "+p+" ("+pr+")"})
        for p in [x for x in self.PROT if x != pr][:2]:
            variants.append({"injection_point":ip,"protocol":p,"encoding":en,
                              "desc":vuln_class+" "+p+"://"})
        for enc in [x for x in self.ENC  if x != en][:2]:
            variants.append({"injection_point":ip,"protocol":pr,"encoding":enc,
                              "desc":vuln_class+" "+enc+"-encoded"})
        return variants

class BenchmarkTracker:
    def record(self, suite:str, results:dict) -> None:
        BENCH_HIST.parent.mkdir(parents=True, exist_ok=True)
        entry = {"ts":datetime.now().isoformat(),"suite":suite,"results":results}
        with open(BENCH_HIST,"a",encoding="utf-8") as f:
            f.write(json.dumps(entry,ensure_ascii=False)+chr(10))
    def blind_spots(self, min_rate:float=0.20) -> list:
        if not BENCH_HIST.exists(): return []
        by_class: dict = {}
        for line in BENCH_HIST.read_text(encoding="utf-8").splitlines():
            try:
                for key, ok in json.loads(line).get("results",{}).items():
                    cls = key.split("_")[0].lower()
                    by_class.setdefault(cls,[]).append(bool(ok))
            except Exception: pass
        spots = []
        for cls, outs in by_class.items():
            rate = sum(outs)/len(outs)
            if rate < min_rate:
                spots.append({"class":cls,"rate":round(rate,2),"n":len(outs)})
        return sorted(spots, key=lambda x: x["rate"])
    def summary(self) -> dict:
        if not BENCH_HIST.exists(): return {}
        entries = []
        for line in BENCH_HIST.read_text(encoding="utf-8").splitlines():
            try: entries.append(json.loads(line))
            except Exception: pass
        if not entries: return {}
        r = entries[-1].get("results",{})
        total = len(r); success = sum(1 for v in r.values() if v)
        return {"total":total,"success":success,
                "rate":round(success/total,2) if total else 0.0,"runs":len(entries)}


class EVX:
    def __init__(self, h1_username="", h1_token="", verbose=True):
        self.h1_user  = h1_username or os.environ.get("H1_USERNAME", "")
        self.h1_token = h1_token    or os.environ.get("H1_TOKEN", "")
        self.verbose  = verbose
        self._r: dict = {}
        self._atom  = None  # lazy init via SmartAtomizer
        self._bench = BenchmarkTracker()

    def run(self, skip_h1=False, monthly=False, scene="bounty"):
        self._scene = scene
        self._hdr("EVX - Hunter Evolution eXperience")
        import time; t0 = time.time()
        use_h1 = not skip_h1 and bool(self.h1_user) and bool(self.h1_token)
        self._r["h1_sync"]   = self._h1_sync()          if use_h1 else {"skipped": True}
        self._r["h1_score"]  = self._score_reports()     # NEW: H1 报告评分
        self._r["skill_gate"] = self._skill_quality_gate() # NEW: Skill 质量门
        self._r["self_heal"] = self._gap_self_heal()     # Step 1.5: auto-create missing agents
        self._r["failures"]  = self._failure_analysis()
        self._r["variants"]  = self._atomize_winners()
        self._r["distill"]   = self._distill(monthly)
        self._r["agent_upgrade"] = self._upgrade_agent_knowledge()  # Step 5.5: knowledge→agent
        self._r["bench"]     = self._benchmark()
        self._r["recommend"] = self._recommend()
        self._r["evolution"] = self._code_evolution()  # Step 6.5: 代码自进化
        elapsed = int(time.time() - t0)
        digest  = self._save_digest()
        if self.verbose:
            print(D + "-"*50 + NC)
            print(G+B+"EVX done ("+str(elapsed)+"s)"+NC+"  "+D+"-> "+str(digest)+NC)
        return self._r

    def _h1_sync(self):
        self._step("1","H1 Sync","H1 API + GitHub fresh reports...")
        result = {"synced": 0, "pending": 0, "github_imported": 0}
        try:
            from aimy.memory.h1_sync import sync
            from aimy.memory.feedback import FeedbackDB
            db = FeedbackDB()
            c  = sync(self.h1_user, self.h1_token, db=db, verbose=self.verbose)
            db.close()
            result["synced"] = c.get("synced", 0)
            result["pending"] = c.get("pending", 0)
            self._ok("API synced="+str(c["synced"])+" pending="+str(c["pending"]))
        except Exception as e:
            self._err("H1 API: "+str(e)); result["error"] = str(e)
        # 1.5: GitHub public reports (dmore/hackerone-reports)
        try:
            from aimy.memory.github_sync import sync_h1_reports
            gh = sync_h1_reports(min_upvotes=30, verbose=self.verbose)
            result["github_imported"] = gh.get("imported", 0)
            self._ok("GitHub imported="+str(gh.get("imported",0)))
        except Exception as e:
            self._err("GitHub sync: "+str(e))
        return result

    def _gap_self_heal(self):
        """Step 1.5: 自检缺失的 agent → 自动创建 + 注入 GitHub 技法"""
        self._step("1.5","Self-Heal","check missing agents + inject GitHub techniques...")
        agents_dir = Path.home()/"Desktop"/"彦"/"agents"
        agents_dir.mkdir(parents=True, exist_ok=True)
        required = ["coordinator","idor-hunter","xss-hunter","ssrf-hunter",
                     "sqli-hunter","rce-hunter","business-logic","validator",
                     "report-writer","remediation-agent",
                     "swarm-orchestrator","exploit-chainer","poc-validator",
                     "_scope-guard","recon-advisor","web-hunter",
                     "bizlogic-hunter","jwt-cracker","graphql-hunter",
                     "subdomain-takeover"]
        created = []
        for a in required:
            fp = agents_dir / (a+".md")
            if not fp.exists():
                try:
                    fp.write_text("---\nname: "+a+"\ndescription: auto-generated\ntools: Bash, Read, Write\n---\n# "+a)
                    created.append(a)
                except: pass
        if created:
            self._ok("created "+str(len(created))+" missing agents: "+", ".join(created))
        else:
            self._ok("all agents present")
        # 注入 GitHub 技法到 FeedbackDB（优胜劣汰）
        try:
            import subprocess, sys as _sys
            injector = Path(__file__).parent / "inject_github_compare.py"
            if injector.exists():
                result = subprocess.run([_sys.executable, str(injector)], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    self._ok("GitHub techniques injected")
                else:
                    self._warn(f"inject error: {result.stderr[:100]}")
        except Exception as e:
            self._warn(f"inject skipped: {e}")
        return {"created": created}

    def _score_reports(self):
        """NEW: Step 1.2 — H1 报告 4维评分"""
        self._step("1.2","H1 Score","4-dimension: unexpectedness/elegance/chain/reproducibility...")
        result = {"scored": 0, "exceptional": 0, "noteworthy": 0, "skip": 0, "avg_score": 0.0,
                  "top_reports": [], "error": ""}
        try:
            from aimy.tools.h1_scorer import H1Scorer, ScoredReport, ScoreBreakdown
            from aimy.memory.feedback import FeedbackDB
            db = FeedbackDB()
            # 取最新 100 份报告
            rows = db._conn.execute(
                "SELECT id, technique, vuln_class, outcome, notes FROM reports ORDER BY id DESC LIMIT 100"
            ).fetchall()
            db.close()

            scorer = H1Scorer()
            scored = []
            for row in rows:
                rid, technique, vuln_class, outcome, notes = row
                sr = scorer.score({
                    "id": rid,
                    "title": technique,
                    "vulnerability_information": f"{notes} {outcome}",
                    "category": vuln_class,
                })
                scored.append(sr)

            ranked = scorer.rank(scored)
            summary = scorer.summary(ranked)
            result["scored"] = summary["total"]
            result["exceptional"] = summary["exceptional"]
            result["noteworthy"] = summary["noteworthy"]
            result["skip"] = summary["skip"]
            result["avg_score"] = summary["avg_score"]
            result["top_reports"] = summary.get("top_reports", [])

            scorer.save_ranking(ranked)

            if self.verbose:
                print(f"    ★★★★ exceptional: {summary['exceptional']}")
                print(f"    ★★★  noteworthy:  {summary['noteworthy']}")
                print(f"    ★★   skip:        {summary['skip']}")
                print(f"    均分: {summary['avg_score']}")
            self._ok(f"scored {summary['total']} reports, {summary['exceptional']} exceptional")
        except Exception as e:
            self._err(f"h1 score: {e}")
            result["error"] = str(e)
        return result

    def _skill_quality_gate(self):
        """NEW: Step 1.3 — Skill 质量门"""
        self._step("1.3","Skill Quality Gate","evaluate new techniques for Skill-worthiness...")
        result = {"evaluated": 0, "worth_skill": 0, "skip": 0, "candidates": [], "error": ""}
        try:
            from aimy.tools.skill_quality import SkillQualityGate
            from aimy.memory.feedback import FeedbackDB
            db = FeedbackDB()
            # 取最近 accepted 的技法
            rows = db._conn.execute(
                "SELECT technique, vuln_class, notes FROM reports WHERE outcome='accepted' ORDER BY id DESC LIMIT 30"
            ).fetchall()
            db.close()

            gate = SkillQualityGate()
            candidates = []
            for row in rows:
                technique, vuln_class, notes = row
                candidates.append({
                    "name": technique,
                    "desc": f"{vuln_class}: {notes}",
                    "source": "H1 accepted report",
                })

            decisions = gate.evaluate_many(candidates)
            worth = [d for d in decisions if d.worth_skill]
            skip = [d for d in decisions if not d.worth_skill]

            result["evaluated"] = len(decisions)
            result["worth_skill"] = len(worth)
            result["skip"] = len(skip)
            result["candidates"] = [d.to_dict() for d in worth[:10]]

            # 保存值得写的 Skill 建议
            from pathlib import Path
            output = Path.home() / ".aimy" / "skill_candidates.json"
            output.write_text(
                __import__("json").dumps([d.to_dict() for d in worth], ensure_ascii=False, indent=2),
                encoding="utf-8"
            )

            if self.verbose:
                for d in worth[:5]:
                    print(f"    ★ {d.knowledge_point}")
                if skip:
                    print(f"    ⏭ {len(skip)} 个已有覆盖")
            self._ok(f"evaluated {len(decisions)} techniques, {len(worth)} worth new Skills")
        except Exception as e:
            self._err(f"skill quality gate: {e}")
            result["error"] = str(e)
        return result

    def _failure_analysis(self):
        self._step("2","Failure Analysis","classify -> trigger actions...")
        try:
            from aimy.memory.feedback import FeedbackDB
            db   = FeedbackDB()
            sql  = "SELECT technique,vuln_class,outcome FROM reports WHERE outcome<>'' ORDER BY id DESC LIMIT 200"
            rows = db._conn.execute(sql).fetchall()
            db.close()
            counts = {}
            for _,_,outcome in rows:
                ftype = classify_failure(outcome=outcome)
                counts[ftype] = counts.get(ftype, 0) + 1
            actions = []
            for ftype, cnt in sorted(counts.items(), key=lambda x: -x[1]):
                act = FAILURE_ACTIONS.get(ftype, {})
                actions.append({"failure_type":ftype,"count":cnt,
                                 "action":act.get("action",""),"desc":act.get("desc",""),
                                 "priority":act.get("priority","low")})
                if self.verbose and ftype != "unknown":
                    icon = "[H]" if act.get("priority")=="high" else "[M]" if act.get("priority")=="medium" else "[L]"
                    print("    "+icon+" "+FAILURE_TYPES.get(ftype,ftype)+" x"+str(cnt)+" -> "+act.get("desc",""))
            return actions
        except Exception as e:
            self._err("failure analysis: "+str(e)); return []

    def _atomize_winners(self):
        self._step("3","Technique Atomizer","decompose -> SmartAtomizer (bridge)...")
        try:
            if self._atom is None:
                from aimy.core.bridge import SmartAtomizer
                self._atom = SmartAtomizer()
            from aimy.memory.feedback import FeedbackDB
            db   = FeedbackDB()
            sql  = "SELECT technique,vuln_class FROM reports WHERE outcome='accepted' GROUP BY technique LIMIT 20"
            rows = db._conn.execute(sql).fetchall()
            db.close()
            variants = []
            for tech, vcls in rows:
                atoms = self._atom.decompose(tech, vuln_class=vcls)
                vv    = self._atom.smart_recombine(atoms, vuln_class=vcls)
                variants.extend(vv)
                if self.verbose:
                    print("    ["+vcls+"] "+tech[:40]+" -> "+str(len(vv))+" variants (via reasoning_engine+kg)")
            return variants
        except Exception as e:
            self._warn("SmartAtomizer fallback to classic")
            ta = TechniqueAtomizer()
            self._atom = ta
            # Direct classic decomposition without recursion
            from aimy.memory.feedback import FeedbackDB
            db = FeedbackDB()
            rows = db._conn.execute(
                "SELECT technique,vuln_class FROM reports WHERE outcome='accepted' GROUP BY technique LIMIT 20"
            ).fetchall()
            db.close()
            variants = []
            for tech, vcls in rows:
                atoms = ta.decompose(tech)
                variants.extend(ta.recombine(atoms, vuln_class=vcls))
            return variants

    def _distill(self, monthly=False):
        self._step("4","Knowledge Distill","upgrade payload + skill files...")
        counts = {"upgraded": 0, "skills_upgraded": 0}
        try:
            from aimy.memory.flywheel_learner import compare_and_upgrade
            counts = compare_and_upgrade(verbose=self.verbose)
            self._ok("+"+str(counts.get("upgraded",0))+" payload stubs")
        except Exception as e:
            counts["error"] = str(e)
        # 4.5: upgrade skill SKILL.md files from FeedbackDB
        try:
            from aimy.memory.skill_upgrader import upgrade_skills
            skill_result = upgrade_skills(min_accepted=2, verbose=self.verbose)
            counts["skills_upgraded"] = skill_result["upgraded"]
            self._ok(str(skill_result["upgraded"])+" skill files upgraded")
            # Also upgrade h1飞轮 docs
            try:
                from aimy.memory.skill_upgrader import upgrade_h1_flywheel_docs
                upgrade_h1_flywheel_docs(verbose=self.verbose)
            except Exception:
                pass
        except Exception as e:
            counts["skill_error"] = str(e)
        if monthly:
            print(Y+"Monthly review tasks:"+NC)
            print("  1. Biggest improvement -> write new skill file")
            print("  2. Biggest time waste  -> add to filter blocklist")
            print("  3. Compare benchmark success rate vs last month")
        return counts

    def _upgrade_agent_knowledge(self):
        """Step 5.5: 从 FeedbackDB 提取高命中技法 → 更新 agent payload"""
        self._step("5.5","Agent Knowledge","extract techniques -> update agent files...")
        result = {"upgraded": 0, "errors": 0}
        try:
            from aimy.memory.feedback import FeedbackDB
            from collections import defaultdict
            db = FeedbackDB()
            # 取最近 50 条 accept 记录
            rows = db._conn.execute(
                "SELECT technique,vuln_class FROM reports WHERE outcome='accepted' ORDER BY id DESC LIMIT 50"
            ).fetchall()
            db.close()
            agents_dir = Path.home()/"Desktop"/"彦"/"agents"
            if not agents_dir.exists():
                return result
            # 按漏洞类分组
            by_class = defaultdict(list)
            for tech, vcls in rows:
                by_class[vcls.lower()].append(tech)
            vuln_to_agent = {
                "idor": "idor-hunter", "xss": "xss-hunter", "ssrf": "ssrf-hunter",
                "sqli": "sqli-hunter", "rce": "rce-hunter", "cmdi": "rce-hunter",
                "business logic": "business-logic", "race": "business-logic",
                "jwt": "jwt-cracker", "graphql": "graphql-hunter",
                "subdomain": "subdomain-takeover", "takeover": "subdomain-takeover",
                "recon": "recon-advisor", "web": "web-hunter",
                "chain": "exploit-chainer", "poc": "poc-validator",
            }
            for vcls, techniques in by_class.items():
                agent_name = None
                for k, v in vuln_to_agent.items():
                    if k in vcls:
                        agent_name = v; break
                if not agent_name:
                    continue
                fp = agents_dir / (agent_name+".md")
                if not fp.exists():
                    continue
                # 取 top-3 技法追加到 agent 文件
                top = techniques[:3]
                lines = ["","## Auto-learned techniques (EVX)"]
                for t in top:
                    lines.append("- "+t[:80])
                try:
                    existing = fp.read_text(encoding="utf-8")
                    if "## Auto-learned techniques" not in existing:
                        fp.write_text(existing + "\n".join(lines), encoding="utf-8")
                        result["upgraded"] += 1
                except:
                    result["errors"] += 1
            self._ok(str(result["upgraded"])+" agent files upgraded with top techniques")
        except Exception as e:
            self._err("agent knowledge: "+str(e))
            result["errors"] += 1
        return result

    def _benchmark(self):
        self._step("5","Benchmark Blindspots","measure gaps not scores...")
        summary = self._bench.summary()
        spots   = self._bench.blind_spots()
        if summary:
            self._ok(str(summary.get("success",0))+"/"+str(summary.get("total",0))+
                     " = "+str(int(summary.get("rate",0)*100))+"%  ("+str(summary.get("runs",0))+" runs)")
        else:
            self._warn("No data - run: python run_benchmark.py")
        if spots and self.verbose:
            print(R+"  Blindspots:"+NC)
            for s in spots[:5]:
                print("    "+s["class"].ljust(18)+" rate="+str(int(s["rate"]*100))+"%  (n="+str(s["n"])+")")
        return {"summary": summary, "blind_spots": spots}

    def _recommend(self):
        scene = getattr(self, '_scene', 'bounty')
        rec_labels = {
            "bounty": "bounty priority",
            "pentest": "pentest post-exploit priority",
            "redteam": "redteam kill-chain priority",
        }
        self._step("6","Recommend", rec_labels.get(scene, "this week priority..."))
        rec      = []
        failures = self._r.get("failures", [])
        spots    = self._r.get("bench", {}).get("blind_spots", [])
        for f in [x for x in failures if x.get("priority")=="high"][:2]:
            rec.append({"direction":f["failure_type"],"reason":f["desc"],"priority":"high"})
        for s in spots[:2]:
            rec.append({"direction":s["class"],"reason":"Benchmark blind "+str(int(s["rate"]*100))+"%","priority":"medium"})
        if not rec:
            rec = [{"direction":"ssrf","reason":"high bounty default","priority":"medium"},
                   {"direction":"auth_bypass","reason":"high accept rate","priority":"medium"}]
        if self.verbose:
            print(B+"  Priority:"+NC)
            icons = {"high":"[H]","medium":"[M]","low":"[L]"}
            for r in rec[:5]:
                print("    "+icons.get(r["priority"],"[ ]")+" "+r["direction"].ljust(18)+" "+D+r["reason"]+NC)
        return rec

    def _code_evolution(self):
        """Step 6.5: 代码自进化（场景感知）"""
        scene_name = getattr(self, '_scene', 'bounty')
        scene_labels = {"bounty": "赏金", "pentest": "渗透", "redteam": "对抗"}
        self._step("6.5","Evolution",
                   f"auto-improve code from data ({scene_labels.get(scene_name, scene_name)})...")
        result = {"changes": [], "dry_run": True, "error": "", "scene": scene_name}
        try:
            from aimy.memory.evolution import EvolutionEngine
            ee = EvolutionEngine(verbose=self.verbose, dry_run=False)
            changes = ee.evolve_all()
            result["changes"] = changes
            result["dry_run"] = False
            if self.verbose and changes:
                print(f"    \x1b[1m{len(changes)} 条进化 (已应用) [{scene_labels.get(scene_name, scene_name)}]\x1b[0m")
            self._ok(f"{len(changes)} evolutions applied")
        except Exception as e:
            self._err(f"evolution: {e}")
            result["error"] = str(e)
        return result

    def _save_digest(self):
        DIGEST_DIR.mkdir(parents=True, exist_ok=True)
        from datetime import datetime as _dt
        ts = _dt.now().strftime("%Y%m%d_%H%M%S")
        pt = DIGEST_DIR / ("evx_"+ts+".json")
        pt.write_text(json.dumps({
            "ts":_dt.now().isoformat(),
            "failures":self._r.get("failures",[]),
            "variants_n":len(self._r.get("variants",[])),
            "distill":self._r.get("distill",{}),
            "bench":self._r.get("bench",{}),
            "recommend":self._r.get("recommend",[]),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        return pt

    def _hdr(self, m):
        if self.verbose: print(C+B+m+NC)
    def _step(self, n, name, detail):
        if self.verbose: print(C+"["+str(n)+"] "+B+name+NC+" "+str(detail))
    def _ok(self, m):
        if self.verbose: print("  "+G+"OK"+NC+" "+str(m))
    def _warn(self, m):
        if self.verbose: print("  "+Y+"!"+NC+"  "+str(m))
    def _err(self, m):
        print("  "+R+"ERR"+NC+" "+str(m))


# ── 持续飞轮：累积N条自动触发升级 ──────────────────────────────
_CONTINUOUS_THRESHOLD = 1          # 每条记录立即触发升级（实时模式）
_COUNTER_FILE = Path.home() / ".aimy" / "continuous_counter.json"


def _load_counter() -> dict:
    try:
        return json.loads(_COUNTER_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"since_last_upgrade": 0, "total": 0}


def _save_counter(c: dict) -> None:
    _COUNTER_FILE.parent.mkdir(parents=True, exist_ok=True)
    _COUNTER_FILE.write_text(json.dumps(c, ensure_ascii=False), encoding="utf-8")


def _continuous_upgrade_check(silent: bool = True) -> bool:
    """新记录计数达到阈值时自动触发 Payload 库升级，返回是否触发。"""
    c = _load_counter()
    c["since_last_upgrade"] = c.get("since_last_upgrade", 0) + 1
    c["total"]              = c.get("total", 0) + 1
    _save_counter(c)

    if c["since_last_upgrade"] >= _CONTINUOUS_THRESHOLD:
        try:
            from aimy.memory.flywheel_learner import compare_and_upgrade
            result = compare_and_upgrade(verbose=not silent)
            upgraded = result.get("upgraded", 0)
            c["since_last_upgrade"] = 0
            c["last_upgrade_ts"]    = datetime.now().isoformat()
            _save_counter(c)
            if not silent:
                print(D+"  [EVX continuous] +"+str(upgraded)+" payload stubs upgraded"+NC)
            # Also upgrade skill files
            try:
                from aimy.memory.skill_upgrader import upgrade_skills
                skr = upgrade_skills(min_accepted=2, verbose=not silent)
                if not silent and skr["upgraded"]:
                    print(D+"  [EVX continuous] "+str(skr["upgraded"])+" skill files upgraded"+NC)
                # Also upgrade h1飞轮 docs
                try:
                    from aimy.memory.skill_upgrader import upgrade_h1_flywheel_docs
                    upgrade_h1_flywheel_docs(verbose=not silent)
                except Exception:
                    pass
            except Exception:
                pass
            return True
        except Exception:
            pass
    return False


def record_finding(target, vuln_class, severity, technique,
                   endpoint="", report_id="", bounty=0.0, outcome="", notes="",
                   auto_validate: bool = True):
    """记录一个发现（成功或失败），自动写入三层存储，并触发持续飞轮检查。

    如果 auto_validate=True，会在记录前自动调用 Validator 做确定性验证。
    Validator 验证结果为 rejected → 不记录到 FeedbackDB（防止污染数据）。
    Validator 验证结果为 downgraded → 降级记录。
    """
    # ── Step 0: SimHash 去重检查 (XBOW-style) ──
    try:
        from aimy.tools.dedup import dedup_filter
        if not dedup_filter(technique, endpoint, vuln_class, action="auto"):
            return "dedup_blocked"
    except Exception:
        pass
    # ── Step 0: 自动验证（XBOW-style Validator） ──
    validation = None
    if auto_validate and endpoint and vuln_class.lower() in Validator.METHODS:
        try:
            val = Validator(verbose=False)
            validation = val.validate(
                vuln_class=vuln_class,
                url=endpoint,
                payload=technique,
            )
            if validation.verdict == "confirmed":
                # Validator 通过 → 再加 Canary OOB 双重确认
                canary_ok = False
                oob_classes = {"ssrf","xxe","ssti","cmdi","rce","sqli"}
                if vuln_class.lower() in oob_classes:
                    try:
                        from aimy.tools.canary import validate_with_canary
                        cr = validate_with_canary(vuln_class=vuln_class, url=endpoint, payload=technique)
                        canary_ok = cr.get("verdict") == "confirmed"
                        if canary_ok:
                            notes += " [Canary OOB confirmed]"
                    except Exception:
                        pass
                outcome = outcome or "accepted"
                tag = "Dual" if canary_ok else "Validator"
                notes += f" [{tag} confirmed ({validation.method_used})]"
            elif validation.verdict == "rejected":
                notes += f" [Validator: rejected ({validation.method_used})]"
                if not outcome:
                    return "rejected_by_validator"
            elif validation.verdict == "downgraded":
                severity = "low" if severity == "medium" else severity
                notes += f" [Validator: downgraded ({validation.method_used})]"
        except Exception as e:
            notes += f" [Validator: error ({e})]"

    # 危害提升建议 + 拓展思路
    try:
        from aimy.tools.chain_suggest import attach_to_record
        chain_notes = attach_to_record(technique, vuln_class)
        if chain_notes:
            notes += f" | {chain_notes}"
    except Exception:
        pass

    ftype = classify_failure(notes=notes, outcome=outcome)
    try:
        from aimy.memory.patterns import PatternDB; db=PatternDB()
        db.add(target=target,vuln_class=vuln_class,severity=severity,
               technique=technique,endpoint=endpoint); db.close()
    except Exception: pass
    try:
        from aimy.memory.feedback import FeedbackDB; db=FeedbackDB()
        db.record(technique=technique,vuln_class=vuln_class,report_id=report_id,
                  outcome=outcome,severity=severity,bounty=bounty); db.close()
    except Exception: pass
    try:
        from aimy.memory.journal import HuntJournal
        HuntJournal().record_finding(target=target,vuln_class=vuln_class,
                                     severity=severity,endpoint=endpoint,
                                     summary="["+ftype+"] "+technique)
    except Exception: pass

    # Accepted → 立即升级对应技能文件 + H1评分 + Skill质量门
    if outcome.lower() == "accepted":
        try:
            from aimy.memory.skill_upgrader import upgrade_single
            upgrade_single(technique=technique, vuln_class=vuln_class,
                           outcome=outcome, bounty=bounty, verbose=False)
        except Exception:
            pass

        # ── 自动 H1 评分 + Skill 质量门 ──
        try:
            from aimy.tools.h1_scorer import H1Scorer
            scored = H1Scorer().score({
                "id": report_id or 0,
                "title": technique,
                "vulnerability_information": f"{vuln_class}: {notes}" if notes else vuln_class,
                "category": vuln_class,
                "award": bounty,
            })
            if scored.score.verdict == "exceptional":
                from aimy.tools.skill_quality import SkillQualityGate
                decision = SkillQualityGate().evaluate(technique, notes or vuln_class, "H1 accepted report")
                if decision.worth_skill:
                    import json
                    from pathlib import Path
                    cand_file = Path.home() / ".aimy" / "skill_candidates.json"
                    existing = []
                    if cand_file.exists():
                        existing = json.loads(cand_file.read_text(encoding="utf-8"))
                    # 去重
                    names = {e.get("knowledge_point", "") for e in existing}
                    if decision.knowledge_point not in names:
                        existing.append(decision.to_dict())
                        cand_file.write_text(
                            json.dumps(existing, ensure_ascii=False, indent=2),
                            encoding="utf-8"
                        )
        except Exception:
            pass

    # 持续飞轮：静默检查，达到阈值自动升级
    _continuous_upgrade_check(silent=True)

    # 静默记录到会话指标（会话结束后统一导出）
    _append_session_metric(
        vuln_type=vuln_class,
        domain=target,
        found=(outcome.lower() == "accepted"),
        tool="aimy_detector",
    )

    # 同步写入跨会话经验库（.claude/targets/techniques.jsonl）
    try:
        import json as _json, pathlib as _pl, datetime as _dt
        tech_file = _pl.Path.home() / '.claude' / 'targets' / 'techniques.jsonl'
        tech_file.parent.mkdir(parents=True, exist_ok=True)
        entry = _json.dumps({
            'date':      _dt.datetime.now().strftime('%Y-%m-%d'),
            'technique': technique,
            'vuln_type': ftype,
            'endpoint':  endpoint or target,
            'confidence': 'high' if outcome == 'accepted' else 'medium' if outcome else 'unknown',
            'tool':      'aimy_evx',
            'notes':     f'{vuln_class}/{severity} via {technique[:60]}',
        }, ensure_ascii=False)
        with open(tech_file, 'a', encoding='utf-8') as tf:
            tf.write(entry + chr(10))
    except Exception: pass

    return ftype


def resolve_report(report_id, outcome, severity="", bounty=0.0):
    try:
        from aimy.memory.feedback import FeedbackDB; db=FeedbackDB()
        row=db._conn.execute("SELECT id FROM reports WHERE report_id=?",(report_id,)).fetchone()
        if row: db.resolve(row[0],outcome=outcome,severity=severity,bounty=bounty)
        db.close()
    except Exception: pass


Flywheel = EVX


# ── Internal: session metrics export (silent) ──────────────────────

_SESSION_METRICS_FILE = Path.home() / ".aimy" / "_session_metrics.json"


def _append_session_metric(vuln_type: str, domain: str, found: bool, tool: str) -> None:
    """Silently append one detection result for end-of-session export."""
    import os
    if os.environ.get("AIMY_TELEMETRY_ENABLED", "").lower() != "true":
        return
    try:
        _SESSION_METRICS_FILE.parent.mkdir(parents=True, exist_ok=True)
        records = []
        if _SESSION_METRICS_FILE.exists():
            records = json.loads(_SESSION_METRICS_FILE.read_text(encoding="utf-8"))
        records.append({
            "ts": datetime.now().isoformat(),
            "vt": vuln_type,
            "dm": domain,
            "ok": found,
            "tl": tool,
        })
        if len(records) > 500:
            records = records[-500:]
        _SESSION_METRICS_FILE.write_text(json.dumps(records), encoding="utf-8")
    except Exception:
        pass


def _export_session_metrics() -> None:
    """Session-end: flush metrics to local file, optionally post to GitHub Issue.

    No console output. Failure is silent.
    """
    import os, json as _json, urllib.request as _req, urllib.error as _err
    if not _SESSION_METRICS_FILE.exists():
        return
    try:
        records = _json.loads(_SESSION_METRICS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return
    if not records:
        return

    # Build summary
    total = len(records)
    hits = sum(1 for r in records if r.get("ok"))
    by_type = {}
    for r in records:
        vt = r.get("vt", "unknown")
        by_type[vt] = by_type.get(vt, 0) + 1

    body = "## Session Summary\n\n"
    body += f"total={total} hits={hits} rate={hits/max(total,1)*100:.0f}%\n\n"
    body += "```json\n" + _json.dumps({
        "total_tests": total, "vulnerabilities_found": hits,
        "hit_rate": f"{hits/max(total,1)*100:.0f}%",
        "top_vuln_types": sorted(by_type.items(), key=lambda x: -x[1])[:10],
    }, indent=2) + "\n```"

    # Clear file
    _SESSION_METRICS_FILE.write_text("[]")

    # Try send via GH API
    repo = os.environ.get("AIMY_FEEDBACK_REPO", "shiyue416/AIMY")
    token = os.environ.get("AIMY_FEEDBACK_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        return  # no token, skip silently

    try:
        data = _json.dumps({
            "title": f"[auto] {total} scans, {hits/max(total,1)*100:.0f}% hit",
            "body": body,
            "labels": ["auto"],
        }).encode("utf-8")
        req = _req.Request(
            f"https://api.github.com/repos/{repo}/issues",
            data=data,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
                "User-Agent": "AIMY/3.0",
            },
            method="POST",
        )
        _req.urlopen(req, timeout=15)
    except Exception:
        pass  # silent — network errors are expected and harmless


def _cli():
    import argparse
    ap = argparse.ArgumentParser(description="EVX Hunter Evolution eXperience")
    ap.add_argument("--skip-h1",  action="store_true")
    ap.add_argument("--monthly",  action="store_true")
    ap.add_argument("--h1-user",  default="")
    ap.add_argument("--h1-token", default="")
    ap.add_argument("--quiet",    action="store_true")
    a = ap.parse_args()
    EVX(h1_username=a.h1_user, h1_token=a.h1_token,
        verbose=not a.quiet).run(skip_h1=a.skip_h1, monthly=a.monthly)


if __name__ == "__main__":
    _cli()
