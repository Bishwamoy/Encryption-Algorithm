
from flask import Flask, render_template, request, redirect, url_for, flash
import os, time
from src.crypto_algs import enc_aes_gcm, enc_chacha_poly, enc_aes_ctr_hmac
from src.util import ensure_out, b64, timestamp
from src.net_tools import run_traceroute, enrich_hops_with_geo, normalize_target

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")

SCENARIOS = ["web","wifi","vpn","voip","iot","general"]
ALGOS = [
    ("AES-GCM", "128", lambda m,a: enc_aes_gcm(m,128,a), True),
    ("AES-GCM", "256", lambda m,a: enc_aes_gcm(m,256,a), True),
    ("ChaCha20-Poly1305", "256", lambda m,a: enc_chacha_poly(m,a), True),
    ("AES-CTR+HMAC", "128", lambda m,a: enc_aes_ctr_hmac(m), False),
]

def run_one_algo(fn, msg: bytes, ad: bytes, repeat: int):
    times=[]; last=None
    for _ in range(repeat):
        last = fn(msg, ad)  # all fn are (msg, ad); AES-CTR ignores ad
        times.append(last[5])
    mean = sum(times)/len(times)
    p95  = sorted(times)[int((len(times)-1)*0.95)]
    ct,key,nonce,ad_or_none,tag,_,algo,variant = last
    return {
        "algo": algo, "variant": variant,
        "aead": algo!="AES-CTR+HMAC",
        "mean_ms": round(mean,4), "p95_ms": round(p95,4),
        "ciphertext_b64": b64(ct), "key_b64": b64(key),
        "nonce_b64": (None if nonce is None else b64(nonce)),
        "ad_b64": (None if ad_or_none is None else b64(ad_or_none)),
        "tag_b64": (None if tag is None else b64(tag)),
        "preview": b64(ct)[:80]+"..."
    }

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        mode = request.form.get("mode", "analyze")
        # Input source
        text = (request.form.get("message") or "").strip()
        file = request.files.get("file")
        # Scenarios
        scenario_single = request.form.get("scenario", "web")
        scenarios_multi = request.form.getlist("scenarios")
        # Repeat
        try:
            repeat = int(request.form.get("repeat","15"))
            if repeat < 1: raise ValueError()
        except ValueError:
            flash("Repeat must be a positive integer.", "error")
            return redirect(url_for("index"))

        # Validate message/file
        if (not file or not getattr(file, "filename", "")) and not text:
            flash("Provide a message or upload a file.", "error")
            return redirect(url_for("index"))

        # Load payload
        if file and file.filename:
            msg = file.read()
            src_label = f"file:{file.filename}"
        else:
            msg = text.encode()
            src_label = "message"

        ensure_out()

        # Branch by mode
        if mode == "compare_multi":
            if not scenarios_multi:
                flash("Select at least one scenario in Compare-Multi mode.", "error")
                return redirect(url_for("index"))
            acc = []
            for sc in scenarios_multi:
                if sc not in SCENARIOS:
                    flash(f"Unknown scenario: {sc}", "error")
                    return redirect(url_for("index"))
                ad = f"CN-WEB-{sc}".encode()
                rows = [run_one_algo(fn, msg, ad, repeat) for _,_,fn,_ in ALGOS]
                for r in rows:
                    r2 = dict(r); r2["scenario"]=sc; acc.append(r2)
            return render_template("compare_multi.html", title="Compare-Multi",
                                   scenarios=scenarios_multi, repeat=repeat,
                                   src_label=src_label, msg_len=len(msg), rows=acc)

        elif mode == "analyze":
            sc = scenario_single if scenario_single in SCENARIOS else "web"
            ad = f"CN-WEB-{sc}".encode()
            rows = [run_one_algo(fn, msg, ad, repeat) for _,_,fn,_ in ALGOS]
            return render_template("analyze.html", title="Analysis",
                                   scenario=sc, repeat=repeat,
                                   src_label=src_label, msg_len=len(msg), rows=rows)

        elif mode == "apply":
            sc = scenario_single if scenario_single in SCENARIOS else "web"
            problem = (request.form.get("problem") or "Protect chat over public internet").strip()
            ad = f"CN-APPLY-{sc}".encode()
            rows = [run_one_algo(fn, msg, ad, repeat) for _,_,fn,_ in ALGOS]
            aeads = [r for r in rows if r["aead"]]
            pick = min(aeads, key=lambda r: r["mean_ms"]) if aeads else rows[0]
            return render_template("apply.html", title="Apply",
                                   scenario=sc, repeat=repeat, problem=problem,
                                   src_label=src_label, msg_len=len(msg), rows=rows, pick=pick)

        elif mode == "quick":
            sc = scenario_single if scenario_single in SCENARIOS else "web"
            ad = f"CN-QUICK-{sc}".encode()
            rows = [run_one_algo(fn, msg, ad, repeat) for _,_,fn,_ in ALGOS]
            return render_template("quick.html", title="Quick Encrypt",
                                   scenario=sc, repeat=repeat,
                                   src_label=src_label, msg_len=len(msg), rows=rows)

        else:
            flash("Unknown mode selected.", "error")
            return redirect(url_for("index"))

    # GET: render form
    return render_template("index.html", scenarios=SCENARIOS, title="CN Encryption Workbench")


@app.route("/traceroute", methods=["GET","POST"])
def traceroute():
    rows = None; host=""; max_hops=20; error=None; geo=False
    if request.method == "POST":
        host = (request.form.get("host") or "").strip()
        geo = bool(request.form.get("geo"))
        try:
            max_hops = int(request.form.get("max_hops","20"))
        except:
            max_hops = 20
        if not host:
            error = "Enter a destination host/URL/IP."
        else:
            # host may be full URL or plain host/IP
            res = run_traceroute(host, max_hops)
            if res.get("error"):
                error = res["error"]
            else:
                rows = res.get("hops", [])
                if geo:
                    rows = enrich_hops_with_geo(rows)
    return render_template("traceroute.html", title="Traceroute", host=host, max_hops=max_hops, rows=rows, error=error, geo=geo)
