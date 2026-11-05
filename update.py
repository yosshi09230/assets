"""資産データの自動更新（GitHub Actionsから1時間ごとに実行）。

やること:
  1. data/db.enc をパスワードで復号
  2. ドル円レートを取得
  3. IBKR Flex で保有銘柄・現金を取得（1日1回）
  4. IBKR・Firstrade の株価を取得
  5. Firstrade の配当（現金）と毎月のQQQ積立を反映
  6. 合計を計算して履歴に1点追加し、古い点を間引く
  7. 暗号化して保存

必要な環境変数（GitHub Secrets）:
  DATA_PASSWORD   … ページで使うパスワードと同じもの（必須）
  IBKR_FLEX_TOKEN … IBKRのFlexトークン（任意）
  IBKR_FLEX_QUERY … IBKRのFlexクエリID（任意）
"""
import base64, json, os, sys, time, urllib.request, urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

JST = timezone(timedelta(hours=9))
UA = "Mozilla/5.0 (asset-tracker; personal use)"
ITER = 250000
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "db.enc")


# ---------- 暗号化（ページ側のWebCryptoと同じ形式） ----------
def _key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER)
    return kdf.derive(password.encode("utf-8"))


def decrypt(blob, password):
    o = json.loads(blob)
    salt, iv, ct = (base64.b64decode(o[k]) for k in ("salt", "iv", "ct"))
    return json.loads(AESGCM(_key(password, salt)).decrypt(iv, ct, None).decode("utf-8"))


def encrypt(obj, password):
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(_key(password, salt)).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode("utf-8"), None)
    b = lambda x: base64.b64encode(x).decode()
    return json.dumps({"v": 1, "iter": ITER, "salt": b(salt), "iv": b(iv), "ct": b(ct)})


# ---------- 通信 ----------
def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def log(db, level, msg):
    print(f"[{level}] {msg}")
    db.setdefault("log", []).append({"t": now_iso(), "level": level, "msg": msg})
    db["log"] = db["log"][-80:]


def now_iso():
    return datetime.now(JST).isoformat(timespec="seconds")


# ---------- 価格 ----------
def yahoo_chart(symbol, rng="5d", interval="1h", events=None):
    q = {"range": rng, "interval": interval}
    if events:
        q["events"] = events
    url = f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(symbol)}?" + urllib.parse.urlencode(q)
    return json.loads(http_get(url))["chart"]["result"][0]


def last_price(symbol):
    res = yahoo_chart(symbol)
    p = res.get("meta", {}).get("regularMarketPrice")
    if p:
        return float(p)
    closes = [c for c in res["indicators"]["quote"][0]["close"] if c]
    return float(closes[-1])


def fetch_fx(db):
    try:
        rate, src = last_price("JPY=X"), "Yahoo"
    except Exception as e:
        try:
            rate, src = float(json.loads(http_get("https://open.er-api.com/v6/latest/USD"))["rates"]["JPY"]), "ER-API"
        except Exception as e2:
            log(db, "warn", f"ドル円の取得に失敗（前回値を使用）: {e} / {e2}")
            return
    if db["settings"].get("fx_manual"):
        return
    db["fx"] = {"rate": round(rate, 4), "at": now_iso(), "source": src}


def update_prices(db, positions, label):
    ok, failed = 0, []
    for p in positions:
        if p.get("asset", "STK") not in ("STK", "ETF", "") or not p.get("symbol"):
            continue
        if p.get("currency", "USD") != "USD":
            continue
        try:
            p["price"] = round(last_price(p["symbol"]), 4)
            ok += 1
        except Exception as e:
            failed.append(p["symbol"])
            err = e
    if failed:
        log(db, "warn", f"{label} 株価取得に失敗（前回値を使用）: {', '.join(failed)} / {err}")
    return ok


# ---------- IBKR Flex ----------
def ibkr_flex(db):
    token, query = os.environ.get("IBKR_FLEX_TOKEN"), os.environ.get("IBKR_FLEX_QUERY")
    if not token or not query:
        return
    ib = db["ibkr"]
    today = datetime.now(JST).strftime("%Y-%m-%d")
    if ib.get("flex_at", "") and ib["flex_at"][:10] == today and not os.environ.get("FORCE_FLEX"):
        return
    base = "https://ndcdyn.interactivebrokers.com/AccountManagement/FlexWebService"
    try:
        r = ET.fromstring(http_get(f"{base}/SendRequest?t={token}&q={query}&v=3"))
        if r.findtext("Status") != "Success":
            raise RuntimeError(r.findtext("ErrorMessage") or "SendRequest失敗")
        ref, url = r.findtext("ReferenceCode"), r.findtext("Url") or f"{base}/GetStatement"
        xml = None
        for _ in range(10):
            time.sleep(5)
            raw = http_get(f"{url}?t={token}&q={ref}&v=3", timeout=60)
            root = ET.fromstring(raw)
            if root.tag == "FlexQueryResponse":
                xml = root
                break
            msg = root.findtext("ErrorMessage") or ""
            if "progress" not in msg.lower() and root.findtext("ErrorCode") not in ("1019", "1018"):
                raise RuntimeError(msg or "GetStatement失敗")
        if xml is None:
            raise RuntimeError("レポート作成待ちがタイムアウト")
    except Exception as e:
        log(db, "warn", f"IBKR Flexの取得に失敗（前回値を使用）: {e}")
        return

    positions = []
    for op in xml.iter("OpenPosition"):
        a = op.attrib
        if a.get("levelOfDetail", "SUMMARY").upper() not in ("SUMMARY", ""):
            continue
        f = lambda k: float(a.get(k) or 0)
        positions.append({
            "symbol": a.get("symbol", ""), "name": a.get("description", ""),
            "asset": a.get("assetCategory", "STK"), "currency": a.get("currency", "USD"),
            "qty": f("position"), "unit_cost": f("costBasisPrice"), "price": f("markPrice"),
            "mark_value": f("positionValue"), "fx_to_base": float(a.get("fxRateToBase") or 1),
        })
    cash = None
    for c in xml.iter("CashReportCurrency"):
        if c.attrib.get("currency") == "BASE_SUMMARY":
            cash = float(c.attrib.get("endingCash") or 0)
    nav = None
    for n in xml.iter("EquitySummaryByReportDateInBase"):
        nav = float(n.attrib.get("total") or 0)
    ib["positions"] = positions
    if cash is not None:
        ib["cash"] = cash
    ib["nav"] = nav
    ib["flex_at"] = now_iso()
    log(db, "info", f"IBKR Flex取得: {len(positions)}銘柄, 現金 {ib.get('cash')}")


# ---------- Firstrade（配当と積立の自動反映） ----------
def firstrade_dividends(db):
    ft, st = db["firstrade"], db["settings"]
    since = ft.get("div_processed_until", "1970-01-01")
    done = set(ft.get("div_done", []))
    failed = []
    for p in ft["positions"]:
        if p["qty"] <= 0:
            continue
        try:
            res = yahoo_chart(p["symbol"], rng="3mo", interval="1d", events="div")
        except Exception:
            failed.append(p["symbol"])
            continue
        for ev in (res.get("events", {}).get("dividends", {}) or {}).values():
            d = datetime.fromtimestamp(ev["date"], JST).strftime("%Y-%m-%d")
            key = f"{p['symbol']}|{d}"
            if d <= since or key in done:
                continue
            amt = round(p["qty"] * float(ev["amount"]) * (1 - st.get("div_withholding", 0.1)), 2)
            ft["cash"] = round(ft.get("cash", 0) + amt, 2)
            ft["events"].append({"t": now_iso(), "type": "dividend",
                                 "detail": f"{p['symbol']} 権利落ち{d} 1株${ev['amount']} → 現金+${amt}（推定・税引後）"})
            done.add(key)
    if failed:
        log(db, "warn", f"Firstrade 配当情報の取得に失敗: {', '.join(failed)}")
    # 処理済みの記録は直近120日分だけ持つ
    lim = (datetime.now(JST) - timedelta(days=120)).strftime("%Y-%m-%d")
    ft["div_done"] = sorted(k for k in done if k.split("|")[1] >= lim)


def firstrade_monthly_buy(db):
    ft, st = db["firstrade"], db["settings"]
    us_now = datetime.now(timezone(timedelta(hours=-5)))
    month = us_now.strftime("%Y-%m")
    if ft.get("last_buy_month") == month or us_now.weekday() >= 5:
        return
    sym = st.get("qqq_symbol", "QQQ")
    pos = next((p for p in ft["positions"] if p["symbol"] == sym), None)
    if pos is None:
        pos = {"symbol": sym, "name": sym, "qty": 0, "unit_cost": 0, "price": 0}
        ft["positions"].append(pos)
    try:
        price = last_price(sym)
    except Exception as e:
        log(db, "warn", f"積立用の{sym}価格取得に失敗（次回に再試行）: {e}")
        return
    amount = round(st.get("qqq_monthly_usd", 2000) + ft.get("cash", 0), 2)
    shares = amount / price
    total_cost = pos["qty"] * pos["unit_cost"] + amount
    pos["qty"] = round(pos["qty"] + shares, 5)
    pos["unit_cost"] = round(total_cost / pos["qty"], 5)
    pos["price"] = price
    ft["cash"] = 0
    ft["last_buy_month"] = month
    ft["events"].append({"t": now_iso(), "type": "buy",
                         "detail": f"{month} {sym}積立 ${amount}（入金${st.get('qqq_monthly_usd', 2000)}+配当）÷ ${price:.2f} = {shares:.5f}株（推定）"})
    ft["events"] = ft["events"][-200:]
    log(db, "info", f"Firstrade積立を反映: {sym} {shares:.5f}株")


# ---------- 集計 ----------
def ibkr_value(ib):
    if not ib.get("positions"):
        return float(ib.get("manual_value") or 0)
    v = 0.0
    for p in ib["positions"]:
        rate = (p.get("fx_to_base") or 1) if p.get("currency", "USD") != "USD" else 1
        if p.get("asset", "STK") in ("STK", "ETF") and p.get("price"):
            v += p["qty"] * p["price"] * rate
        else:
            v += p.get("mark_value", 0) * (p.get("fx_to_base") or 1)
    return v + float(ib.get("cash") or 0)


def firstrade_value(ft):
    return sum(p["qty"] * p["price"] for p in ft["positions"]) + float(ft.get("cash") or 0)


def totals(db):
    fx = db["fx"]["rate"]
    ib, ft = ibkr_value(db["ibkr"]), firstrade_value(db["firstrade"])
    parts = {"ibkr": ib, "firstrade": ft, "crypto": 0.0, "usd_cash": 0.0, "jpy": 0.0}
    usd = ib + ft
    for m in db["manual"]:
        if m["currency"] == "USD":
            usd += m["value"]
            parts["crypto" if m["category"] == "crypto" else "usd_cash"] += m["value"]
        else:
            parts["jpy"] += m["value"]
    jpy = usd * fx + parts["jpy"]
    return round(jpy, 2), round(jpy / fx, 2), {k: round(v, 2) for k, v in parts.items()}


def add_point(db):
    jpy, usd, parts = totals(db)
    db["history"].append({"t": now_iso(), "jpy": jpy, "usd": usd, "fx": db["fx"]["rate"], "kind": "auto", "parts": parts})
    # 間引き: 14日より古い自動記録は1日1点（その日の最後）だけ残す
    cutoff = (datetime.now(JST) - timedelta(days=14)).isoformat()
    keep, seen = [], {}
    for i, h in enumerate(db["history"]):
        if h["kind"] == "auto" and h["t"] < cutoff:
            seen[h["t"][:10]] = i
    for i, h in enumerate(db["history"]):
        if h["kind"] == "auto" and h["t"] < cutoff and seen.get(h["t"][:10]) != i:
            continue
        keep.append(h)
    db["history"] = sorted(keep, key=lambda h: h["t"])
    return jpy


def main():
    pw = os.environ.get("DATA_PASSWORD")
    if not pw:
        sys.exit("DATA_PASSWORD が設定されていません（GitHub Secrets を確認）")
    if not os.path.exists(DB_PATH):
        print("data/db.enc がまだありません。ページの初期設定を先に行ってください。")
        return
    with open(DB_PATH, encoding="utf-8") as f:
        db = decrypt(f.read(), pw)

    fetch_fx(db)
    ibkr_flex(db)
    update_prices(db, db["ibkr"].get("positions", []), "IBKR")
    if db["ibkr"].get("positions"):
        db["ibkr"]["live_at"] = now_iso()
    update_prices(db, db["firstrade"]["positions"], "Firstrade")
    firstrade_dividends(db)
    firstrade_monthly_buy(db)
    jpy = add_point(db)
    db["updated_at"] = now_iso()
    print(f"合計 ¥{jpy:,.0f} / ドル円 {db['fx']['rate']}")

    with open(DB_PATH, "w", encoding="utf-8") as f:
        f.write(encrypt(db, pw))


if __name__ == "__main__":
    main()
