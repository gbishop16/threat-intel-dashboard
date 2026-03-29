from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import asyncio
import base64

app = FastAPI(title="Threat Intelligence Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")


async def query_virustotal(client, target, target_type):
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        if target_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        else:
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        resp = await client.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()) if stats else 0,
            }
        elif resp.status_code == 404:
            return {"error": "Not found in VirusTotal database"}
        else:
            return {"error": f"VirusTotal returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


async def query_abuseipdb(client, ip):
    if not ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            return {
                "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country_code": d.get("countryCode", "N/A"),
                "isp": d.get("isp", "N/A"),
                "domain": d.get("domain", "N/A"),
                "is_tor": d.get("isTor", False),
                "usage_type": d.get("usageType", "N/A"),
                "last_reported": d.get("lastReportedAt", None),
            }
        else:
            return {"error": f"AbuseIPDB returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


async def query_shodan(client, ip):
    if not SHODAN_API_KEY:
        return {"error": "Shodan API key not configured"}
    try:
        resp = await client.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": SHODAN_API_KEY}, timeout=10)
        if resp.status_code == 200:
            d = resp.json()
            return {
                "ports": d.get("ports", [])[:20],
                "vulnerabilities": list(d.get("vulns", {}).keys())[:10],
                "hostnames": d.get("hostnames", [])[:5],
                "org": d.get("org", "N/A"),
                "os": d.get("os", "N/A"),
                "tags": d.get("tags", []),
            }
        elif resp.status_code == 404:
            return {"error": "IP not found in Shodan"}
        else:
            return {"error": f"Shodan returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def calculate_risk(vt_result, abuse_result=None, shodan_result=None):
    risk_score = 0
    risk_factors = []
    if abuse_result and "abuse_confidence_score" in abuse_result:
        score = abuse_result["abuse_confidence_score"]
        risk_score = max(risk_score, score)
        if score > 50:
            risk_factors.append(f"High abuse confidence score ({score}%)")
        if abuse_result.get("is_tor"):
            risk_score = max(risk_score, 70)
            risk_factors.append("TOR exit node detected")
    if "malicious" in vt_result and vt_result.get("total", 0) > 0:
        vt_ratio = vt_result["malicious"] / vt_result["total"] * 100
        risk_score = max(risk_score, vt_ratio)
        if vt_result["malicious"] > 0:
            risk_factors.append(f"Flagged malicious by {vt_result['malicious']} VirusTotal engines")
    if shodan_result and "vulnerabilities" in shodan_result and shodan_result["vulnerabilities"]:
        risk_score = max(risk_score, 60)
        risk_factors.append(f"{len(shodan_result['vulnerabilities'])} known CVEs found")
    if risk_score >= 75: level = "CRITICAL"
    elif risk_score >= 50: level = "HIGH"
    elif risk_score >= 25: level = "MEDIUM"
    elif risk_score > 0: level = "LOW"
    else: level = "CLEAN"
    return round(risk_score), level, risk_factors


@app.get("/analyze/ip/{ip}")
async def analyze_ip(ip: str):
    async with httpx.AsyncClient() as client:
        vt, abuse, shodan = await asyncio.gather(
            query_virustotal(client, ip, "ip"),
            query_abuseipdb(client, ip),
            query_shodan(client, ip),
        )
    score, level, factors = calculate_risk(vt, abuse, shodan)
    return {"target": ip, "type": "ip", "risk_score": score, "risk_level": level, "risk_factors": factors, "virustotal": vt, "abuseipdb": abuse, "shodan": shodan}


@app.get("/analyze/url")
async def analyze_url(target: str):
    async with httpx.AsyncClient() as client:
        vt = await query_virustotal(client, target, "url")
    score, level, factors = calculate_risk(vt)
    return {"target": target, "type": "url", "risk_score": score, "risk_level": level, "risk_factors": factors, "virustotal": vt}


@app.get("/health")
async def health():
    return {"status": "ok"}
