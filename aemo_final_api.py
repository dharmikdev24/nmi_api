"""
AEMO MSATS B2M API Wrapper
==========================

Endpoints:
  POST /api/nmi-lookup        Chained: address → all NMIs → full detail per NMI
  POST /api/nmi-status        Direct:  NMI + checksum → detail (parsed JSON)
  POST /api/nmi-discovery     Individual: address → raw AEMO XML
  POST /api/nmi-detail        Individual: NMI + checksum → raw AEMO XML
  GET  /api/audit             Audit log
  GET  /                      Health check + route index
"""

import base64
import concurrent.futures
import json
import logging
import re
import sqlite3
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import requests
from flask import Flask, Response, g, jsonify, request
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("aemo_api")

# ─── App ──────────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app,
     origins=["http://localhost:5173", "https://go.gsync.com.au"],
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])

# ─── Auth & constants ─────────────────────────────────────────────────────────

USERNAME     = "PAGEEPPR"
PASSWORD     = "Gee@12345"
BASE64_CREDS = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
BASE_URL     = "https://apis.preprod.aemo.com.au:9319/NEMRetail/B2MMessagingSync/v1"
CERT_PATH    = "GEEPOWER-NonProd.crt"
KEY_PATH     = "GEEPOWER-NonProd.key"

COMMON_HEADERS = {
    "X-initiatingParticipantID": "GEEPOWER",
    "X-market":                  "NEM",
    "Accept":                    "text/xml",
    "System":                    "MSATS/CATS",
    "Authorization":             f"Basic {BASE64_CREDS}",
}

REGISTER_MEANINGS = {
    "E1": "Import (Consumption)",
    "E2": "Import (Consumption)",
    "B1": "Export (Solar Feed-in)",
    "B2": "Export (Solar Feed-in)",
    "CL1": "Controlled Load",
    "CL2": "Controlled Load",
}

METER_STATUS_LABELS = {
    "C": "Current (Active)",
    "A": "Active",
    "R": "Retired / Replaced",
    "D": "Decommissioned",
}

ACTIVE_STATUSES = {"C"}

# ─── NMIDiscovery parameter spec ──────────────────────────────────────────────

DISCOVERY_PARAM_SPEC = [
    ("jurisdictionCode",        "required",    "State code (NSW, VIC, SA)"),
    ("meterSerialNumber",       "conditional", "Meter serial number"),
    ("deliveryPointIdentifier", "conditional", "Delivery Point Identifier (DPID)"),
    ("stateOrTerritory",        "conditional", "State or territory abbreviation"),
    ("postcode",                "conditional", "Postcode"),
    ("streetName",              "optional",    "Street name"),
    ("houseNumber",             "optional",    "House number"),
    ("suburbOrPlaceOrLocality", "optional",    "Suburb, place or locality"),
    ("streetType",              "optional",    "Street type (AVE, ST, RD)"),
    ("streetSuffix",            "optional",    "Street suffix"),
    ("flatOrUnitNumber",        "optional",    "Flat or unit number"),
    ("buildingOrPropertyName",  "optional",    "Building or property name"),
    ("floorOrLevelNumber",      "optional",    "Floor or level number"),
    ("floorOrLevelType",        "optional",    "Floor or level type"),
    ("lotNumber",               "optional",    "Lot number"),
]

DISCOVERY_ALLOWED_PARAMS     = [p[0] for p in DISCOVERY_PARAM_SPEC]
DISCOVERY_CONDITIONAL_PARAMS = [p[0] for p in DISCOVERY_PARAM_SPEC if p[1] == "conditional"]


def validate_discovery_params(body: dict) -> list:
    errors = []
    if not body.get("jurisdictionCode"):
        errors.append("jurisdictionCode is required (e.g. 'SA', 'NSW', 'VIC').")
    if not any(body.get(p) for p in DISCOVERY_CONDITIONAL_PARAMS):
        errors.append(
            "At least one conditional parameter is required: "
            + ", ".join(DISCOVERY_CONDITIONAL_PARAMS) + "."
        )
    return errors

# ─── Retry session ────────────────────────────────────────────────────────────

def build_session():
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    return session

SESSION = build_session()

# ─── Audit DB ─────────────────────────────────────────────────────────────────

DB_PATH = "audit.db"

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                step            TEXT    NOT NULL,
                transaction_id  TEXT,
                request_params  TEXT,
                upstream_url    TEXT,
                upstream_status INTEGER,
                response_data   TEXT,
                error           TEXT,
                duration_ms     REAL
            )
        """)
        conn.commit()
    logger.info("Audit DB ready: %s", DB_PATH)

def audit_record(step, transaction_id, request_params,
                 upstream_url, upstream_status, response_data, error, duration_ms):
    try:
        db = get_db()
        db.execute(
            """INSERT INTO audit_log
               (timestamp, step, transaction_id, request_params,
                upstream_url, upstream_status, response_data, error, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                step, transaction_id,
                json.dumps(request_params), upstream_url, upstream_status,
                json.dumps(response_data), error, round(duration_ms, 2),
            ),
        )
        db.commit()
    except Exception as exc:
        logger.error("Audit write failed: %s", exc)

# ─── Validation ───────────────────────────────────────────────────────────────

# NMI_RE = re.compile(r"^[A-Z0-9]{10}$", re.IGNORECASE)
# CHECKSUM_RE = re.compile(r"^\d$")

# def validate_nmi(nmi):
#     if not nmi:
#         return "NMI is required."
#     if not NMI_RE.match(str(nmi)):
#         return f"Invalid NMI '{nmi}': must be exactly 10 digits."
#     return None

NMI_RE      = re.compile(r"^[A-Z0-9]{10}$", re.IGNORECASE)
CHECKSUM_RE = re.compile(r"^\d$")

def validate_nmi(nmi):
    if not nmi:
        return "NMI is required."
    if not NMI_RE.match(str(nmi)):
        return f"Invalid NMI '{nmi}': must be exactly 10 alphanumeric characters."
    return None

def validate_checksum(checksum):
    if checksum is None:
        return "Checksum is required."
    if not CHECKSUM_RE.match(str(checksum)):
        return f"Invalid checksum '{checksum}': must be a single digit (0-9)."
    return None

# ─── XML helpers ──────────────────────────────────────────────────────────────

def local_tag(tag):
    """Strip XML namespace prefix."""
    return tag.split("}")[-1] if "}" in tag else tag


def find_in(el, *tags):
    """
    Search for the first matching element WITHIN a specific element subtree only.
    This is the key fix — scoping search to a block prevents bleeding between NMIs.
    """
    for child in el.iter():
        if local_tag(child.tag) in tags:
            return child.text.strip() if child.text else None
    return None


def extract_checksum_from(nmi_el, parent_el):
    """
    Extract checksum for a specific <NMI> element.
    Tries:
      1. Attribute on <NMI> itself:  <NMI checksum="7">4310202282</NMI>
      2. Sibling element in same parent: <NMIChecksum>7</NMIChecksum>
      3. Attribute on any ancestor element
    """
    # Strategy 1: attribute on the <NMI> element
    for attr in ("checksum", "NMIChecksum", "Checksum"):
        val = nmi_el.get(attr)
        if val and val.strip():
            return val.strip()

    # Strategy 2: sibling <NMIChecksum> or <Checksum> in same parent
    for sibling in parent_el:
        lt = local_tag(sibling.tag)
        if lt in ("NMIChecksum", "Checksum") and sibling.text and sibling.text.strip():
            return sibling.text.strip()

    return None

# ─── XML parsers ──────────────────────────────────────────────────────────────

def parse_discovery_xml(xml_text):
    """
    NMIDiscovery response → list of NMI entries, each with its OWN address.

    AEMO wraps each NMI in a separate <NMIStandingData> block. When multiple
    NMIs exist on one address (apartments, sub-meters, dual-occupancy), each
    block has its own <Address> with potentially different house numbers, DPIDs,
    customer types etc.

    Returns:
      {
        "transactionId": "TX-...",
        "nmis": [
          {
            "nmi": "4103154611", "checksum": "2",
            "address": { "houseNumber": "2", "streetName": "LAMBE", ... },
            "customerType": "RESIDENTIAL", "nmiStatus": "A",
            "jurisdictionCode": "NSW"
          },
          {
            "nmi": "4103154629", "checksum": "5",
            "address": { "houseNumber": "4", "streetName": "LAMBE", ... },
            ...
          }
        ]
      }
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ET.ParseError(f"NMIDiscovery XML malformed at {exc.position}: {exc}") from exc

    tx_el = next((el for el in root.iter() if local_tag(el.tag) == "Transaction"), None)
    transaction_id = tx_el.get("initiatingTransactionID") if tx_el is not None else None

    nmis = []
    seen = set()

    # Each <NMIStandingData> block is one property/NMI — scope ALL lookups to it
    for block in root.iter():
        if local_tag(block.tag) != "NMIStandingData":
            continue

        # Find the <NMI> element directly inside this block
        nmi_el = next((c for c in block.iter() if local_tag(c.tag) == "NMI"), None)
        if nmi_el is None or not nmi_el.text:
            continue
        nmi_val = nmi_el.text.strip()
        if not nmi_val or nmi_val in seen:
            continue
        seen.add(nmi_val)

        # Find the immediate parent of nmi_el for sibling checksum search
        nmi_parent = next(
            (p for p in block.iter()
             if any(c is nmi_el for c in p)),
            block
        )
        checksum_val = extract_checksum_from(nmi_el, nmi_parent)

        # Extract address SCOPED to this block only
        address = {
            "houseNumber":             find_in(block, "HouseNumber"),
            "flatOrUnitNumber":        find_in(block, "FlatOrUnitNumber"),
            "streetName":              find_in(block, "StreetName"),
            "streetType":              find_in(block, "StreetType"),
            "streetSuffix":            find_in(block, "StreetSuffix"),
            "suburb":                  find_in(block, "SuburbOrPlaceOrLocality"),
            "state":                   find_in(block, "StateOrTerritory"),
            "postcode":                find_in(block, "PostCode"),
            "deliveryPointIdentifier": find_in(block, "DeliveryPointIdentifier"),
        }

        nmi_status    = find_in(block, "Status")
        customer_type = find_in(block, "CustomerClassificationCode")
        jurisdiction  = find_in(block, "JurisdictionCode")

        nmis.append({
            "nmi":             nmi_val,
            "checksum":        checksum_val,
            "nmiStatus":       nmi_status,
            "customerType":    customer_type,
            "jurisdictionCode": jurisdiction,
            "address":         address,
        })
        logger.info("[parse_discovery] nmi=%s  checksum=%s  house=%s  dpid=%s",
                    nmi_val, checksum_val,
                    address.get("houseNumber"), address.get("deliveryPointIdentifier"))

    # Fallback: XML has no <NMIStandingData> wrapper (older schema or discovery-only response)
    # In this case address info is not in the discovery response — will come from getNMIDetail
    if not nmis:
        logger.debug("[parse_discovery] no NMIStandingData blocks found, doing flat scan")
        for el in root.iter():
            if local_tag(el.tag) != "NMI":
                continue
            nmi_val = el.text.strip() if el.text else None
            if not nmi_val or nmi_val in seen:
                continue
            seen.add(nmi_val)
            parent = next((p for p in root.iter() if any(c is el for c in p)), root)
            checksum_val = extract_checksum_from(el, parent)
            nmis.append({
                "nmi":      nmi_val,
                "checksum": checksum_val,
                "address":  None,   # not available in flat discovery response
            })

    logger.info("[parse_discovery] total NMIs: %d", len(nmis))
    logger.debug("[parse_discovery] raw XML: %s", xml_text[:800])
    return {"transactionId": transaction_id, "nmis": nmis}


def parse_detail_xml(xml_text):
    """
    getNMIDetail response → full structured detail for ONE NMI.

    Scopes meter/register/address extraction to the correct <NMIStandingData>
    block to prevent data bleeding when the response contains multiple blocks.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ET.ParseError(f"getNMIDetail XML malformed at {exc.position}: {exc}") from exc

    # getNMIDetail always returns a single NMI — find its NMIStandingData block
    # (or fall back to root if no wrapper present)
    block = next(
        (el for el in root.iter() if local_tag(el.tag) == "NMIStandingData"),
        root
    )

    # ── Core NMI fields (scoped to block) ────────────────────────────────────
    nmi               = find_in(block, "NMI")
    network_code      = find_in(block, "TransmissionNodeIdentifier")
    customer_type     = find_in(block, "CustomerClassificationCode")
    connection_config = find_in(block, "ConnectionConfiguration")
    nmi_status        = find_in(block, "Status")

    # ── Address (scoped to block) ─────────────────────────────────────────────
    address = {
        "houseNumber":             find_in(block, "HouseNumber"),
        "flatOrUnitNumber":        find_in(block, "FlatOrUnitNumber"),
        "streetName":              find_in(block, "StreetName"),
        "streetType":              find_in(block, "StreetType"),
        "streetSuffix":            find_in(block, "StreetSuffix"),
        "suburb":                  find_in(block, "SuburbOrPlaceOrLocality"),
        "state":                   find_in(block, "StateOrTerritory"),
        "postcode":                find_in(block, "PostCode"),
        "deliveryPointIdentifier": find_in(block, "DeliveryPointIdentifier"),
    }

    # ── Meters & registers (active only, scoped to block) ────────────────────
    meters           = []
    all_registers    = []
    cl_registers     = []
    all_tariff_codes = []
    seen_reg_ids     = set()

    for meter_el in block.iter():
        if local_tag(meter_el.tag) != "Meter":
            continue

        meter_status = None
        meter_serial = None
        reg_config   = None

        for child in meter_el:
            lt = local_tag(child.tag)
            if lt == "SerialNumber" and meter_serial is None:
                meter_serial = child.text.strip() if child.text else None
            if lt == "Status" and meter_status is None:
                meter_status = child.text.strip() if child.text else None
            if lt == "RegisterConfiguration":
                reg_config = child

        # Skip retired / replaced meters
        if meter_status and meter_status not in ACTIVE_STATUSES:
            logger.debug("[parse_detail] skip non-current meter serial=%s status=%s",
                         meter_serial, meter_status)
            continue

        meter_registers = []
        if reg_config is not None:
            for reg_el in reg_config.iter():
                if local_tag(reg_el.tag) != "Register":
                    continue

                reg_id = reg_status = None
                reg_fields = {}
                for child in reg_el:
                    lt = local_tag(child.tag)
                    val = child.text.strip() if child.text else ""
                    reg_fields[lt] = val
                    if lt == "RegisterID": reg_id = val
                    if lt == "Status":     reg_status = val

                if reg_status and reg_status not in ACTIVE_STATUSES:
                    logger.debug("[parse_detail] skip non-current register %s status=%s",
                                 reg_id, reg_status)
                    continue

                if reg_id:
                    entry = {
                        "registerId":    reg_id,
                        "type":          REGISTER_MEANINGS.get(reg_id, "Unknown"),
                        "tariffCode":    reg_fields.get("NetworkTariffCode"),
                        "controlledLoad": reg_fields.get("ControlledLoad", "").upper() == "YES",
                        "status":        reg_status,
                        "networkAdditionalInfo": reg_fields.get("NetworkAdditionalInformation"),
                        "uom":          reg_fields.get("UnitOfMeasure"),
                        "timeOfDay":    reg_fields.get("TimeOfDay"),
                        "multiplier":   reg_fields.get("Multiplier"),
                        "dialFormat":   reg_fields.get("DialFormat"),
                        "suffix":       reg_fields.get("Suffix"),
                    }
                    meter_registers.append(entry)
                    if reg_id not in seen_reg_ids:
                        seen_reg_ids.add(reg_id)
                        all_registers.append(entry)
                        tar = reg_fields.get("NetworkTariffCode")
                        if tar:
                            all_tariff_codes.append(tar)
                        if reg_fields.get("ControlledLoad", "").upper() == "YES":
                            cl_registers.append(reg_id)

        if meter_serial and (meter_registers or meter_status in ACTIVE_STATUSES):
            meters.append({
                "serialNumber": meter_serial,
                "status":       meter_status,
                "statusLabel":  METER_STATUS_LABELS.get(meter_status, meter_status),
                "registers":    meter_registers,
            })

    # Primary tariff = NetworkTariffCode from the import (E*) register
    import_tariffs = [r["tariffCode"] for r in all_registers
                      if r["registerId"].startswith("E") and r["tariffCode"]]
    primary_tariff = import_tariffs[0] if import_tariffs \
        else (all_tariff_codes[0] if all_tariff_codes else None)

    return {
        "nmi":              nmi,
        "networkCode":      network_code,
        "networkTariff":    primary_tariff,
        "customerType":     customer_type,
        "connectionConfig": connection_config,
        "nmiStatus":        nmi_status,
        "address":          address,
        "meters":           meters,
        "registers":        all_registers,
        "controlledLoad": {
            "hasControlledLoad": len(cl_registers) > 0,
            "registers":         cl_registers,
            "billingNote":       "Off-peak / controlled load billing applies"
                                 if cl_registers else "No controlled load registers found",
        },
    }

# ─── Upstream caller ─────────────────────────────────────────────────────────

def call_upstream(endpoint, params, extra_headers=None):
    headers = {**COMMON_HEADERS, **(extra_headers or {})}
    url     = f"{BASE_URL}/{endpoint}"

    for attempt in range(1, 4):
        try:
            resp = SESSION.get(
                url, headers=headers, params=params, timeout=30,
                cert=(CERT_PATH, KEY_PATH) if KEY_PATH else CERT_PATH,
            )
            if resp.status_code == 401:
                return resp, 401, "Invalid credentials — check USERNAME / PASSWORD."
            if resp.status_code == 400:
                return resp, 400, f"AEMO rejected request (400): {resp.text[:300]}"
            resp.raise_for_status()
            return resp, resp.status_code, None

        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as exc:
            wait = 2 ** (attempt - 1)
            logger.warning("Attempt %d/3 failed (%s) — retry in %ds",
                           attempt, type(exc).__name__, wait)
            if attempt < 3:
                time.sleep(wait)
            else:
                return None, 502, f"MSATS unreachable after 3 attempts. Last error: {exc}"

# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT 1  —  CHAINED LOOKUP (address → all NMIs → detail per NMI)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/nmi-lookup", methods=["POST"])
def nmi_lookup():
    """
    POST /api/nmi-lookup

    Step 1: NMIDiscovery  — returns ALL NMIs at the address, each with its own
                            address block (different house numbers, DPIDs etc.)
    Step 2: getNMIDetail  — called once per NMI in parallel for meter/register detail

    Response 200:
    {
      "transactionId": "TX-...",
      "count": 2,
      "results": [
        {
          "nmi": "4103154611", "checksum": "2",
          "address": { "houseNumber": "2", "streetName": "LAMBE", ... },
          "customerType": "RESIDENTIAL", "nmiStatus": "A",
          "network": { "code": "NSN1", "tariff": "EA025" },
          "meters": [...], "registers": [...], "controlledLoad": {...}
        },
        {
          "nmi": "4103154629", "checksum": "5",
          "address": { "houseNumber": "4", ... },   ← different house number
          ...
        }
      ]
    }
    """
    t0   = time.monotonic()
    body = request.get_json(force=True) or {}

    val_errs = validate_discovery_params(body)
    if val_errs:
        return jsonify({"error": "Validation failed", "details": val_errs}), 400

    transaction_id = f"TX-{uuid.uuid4().hex[:12].upper()}"
    logger.info("NMI Lookup START  transactionId=%s", transaction_id)

    discovery_params = {k: body[k] for k in DISCOVERY_ALLOWED_PARAMS if body.get(k)}
    discovery_params["transactionId"] = transaction_id

    # ── Step 1: NMIDiscovery ─────────────────────────────────────────────────
    t1 = time.monotonic()
    d_resp, d_status, d_err = call_upstream("NMIDiscovery", discovery_params)
    step1_ms = (time.monotonic() - t1) * 1000

    if d_err:
        audit_record("step1_NMIDiscovery", transaction_id, discovery_params,
                     f"{BASE_URL}/NMIDiscovery", d_status, {}, d_err, step1_ms)
        return jsonify({"transactionId": transaction_id,
                        "failedStep": "NMIDiscovery", "error": d_err}), \
               (d_status if d_status in (400, 401) else 502)

    try:
        disc = parse_discovery_xml(d_resp.text)
    except ET.ParseError as exc:
        err = str(exc)
        audit_record("step1_NMIDiscovery", transaction_id, discovery_params,
                     f"{BASE_URL}/NMIDiscovery", d_status, {}, err, step1_ms)
        return jsonify({"transactionId": transaction_id,
                        "failedStep": "NMIDiscovery",
                        "error": "Failed to parse NMIDiscovery XML", "detail": err}), 500

    nmi_list = disc.get("nmis", [])
    audit_record("step1_NMIDiscovery", transaction_id, discovery_params,
                 f"{BASE_URL}/NMIDiscovery", d_status,
                 {"nmisFound": len(nmi_list), "nmis": nmi_list}, None, step1_ms)
    logger.info("[Step 1] OK  found %d NMI(s)  %.0fms", len(nmi_list), step1_ms)
    # 🚫 Reject if too many NMIs (ambiguous address)
    if len(nmi_list) > 5:
        msg = (
        f"Please enter a more specific address."
        )

        audit_record(
        "step1_NMIDiscovery_limit_exceeded",
        transaction_id,
        discovery_params,
        f"{BASE_URL}/NMIDiscovery",
        d_status,
        {"nmisFound": len(nmi_list)},
        msg,
        step1_ms
        )

        return jsonify({
        "transactionId": transaction_id,
        "error": "Address too broad",
        "message": msg,
        "nmisFound": len(nmi_list)
        }), 400
    # if not nmi_list:
    #     return jsonify({"transactionId": transaction_id,
    #                     "error": "No NMIs returned by AEMO for the supplied address."}), 404

    # ── Step 2: getNMIDetail per NMI (parallel) ───────────────────────────────

    def fetch_detail(entry: dict) -> dict:
        nmi      = entry.get("nmi")
        checksum = entry.get("checksum")

        # Validate NMI + checksum
        errs = [e for e in (validate_nmi(nmi), validate_checksum(checksum)) if e]
        if errs:
            return {"nmi": nmi, "checksum": checksum,
                    "error": "Validation failed", "details": errs}

        params = {"transactionId": transaction_id, "nmi": nmi, "checksum": checksum}
        t_sub = time.monotonic()
        dr, d2_status, d2_err = call_upstream(
            "getNMIDetail", params, extra_headers={"Content-Type": "text/xml"})
        sub_ms = (time.monotonic() - t_sub) * 1000

        if d2_err:
            audit_record("step2_getNMIDetail", transaction_id, params,
                         f"{BASE_URL}/getNMIDetail", d2_status, {}, d2_err, sub_ms)
            # Return discovery-level address on error so caller has something
            return {"nmi": nmi, "checksum": checksum,
                    "address": entry.get("address"), "error": d2_err}

        try:
            detail = parse_detail_xml(dr.text)
        except ET.ParseError as exc:
            err = str(exc)
            audit_record("step2_getNMIDetail", transaction_id, params,
                         f"{BASE_URL}/getNMIDetail", d2_status, {}, err, sub_ms)
            return {"nmi": nmi, "checksum": checksum,
                    "address": entry.get("address"),
                    "error": "Failed to parse getNMIDetail XML", "detail": err}

        audit_record("step2_getNMIDetail", transaction_id, params,
                     f"{BASE_URL}/getNMIDetail", d2_status, detail, None, sub_ms)
        logger.info("[Step 2] OK  nmi=%s  house=%s  tariff=%s  %.0fms",
                    nmi, detail["address"].get("houseNumber"),
                    detail.get("networkTariff"), sub_ms)

        # Prefer the richer address from getNMIDetail (it may have more fields).
        # Fall back to discovery address if detail address is empty.
        detail_addr = detail["address"]
        disc_addr   = entry.get("address") or {}
        merged_addr = {k: (detail_addr.get(k) or disc_addr.get(k))
                       for k in set(list(detail_addr.keys()) + list(disc_addr.keys()))}

        return {
            "nmi":          nmi,
            "checksum":     checksum,
            "nmiStatus":    detail["nmiStatus"],
            "customerType": detail["customerType"],
            "address":      merged_addr,
            "network": {
                "code":   detail["networkCode"],
                "tariff": detail["networkTariff"],
            },
            # "meters":         detail["meters"],
            "registers":      detail["registers"],
            "controlledLoad": detail["controlledLoad"],
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(nmi_list), 5)) as pool:
        results = list(pool.map(fetch_detail, nmi_list))

    total_ms = (time.monotonic() - t0) * 1000
    logger.info("NMI Lookup DONE  %d NMI(s)  total=%.0fms", len(results), total_ms)

    return jsonify({
        "transactionId": transaction_id,
        "count":         len(results),
        "results":       results,
    }), 200


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT 2  —  NMI STATUS (already have NMI + checksum)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/nmi-status", methods=["POST"])
def nmi_status():
    """
    POST /api/nmi-status
    Required: nmi (10-digit), checksum (single digit)
    Optional: transactionId (auto-generated if omitted)
    """
    t0   = time.monotonic()
    body = request.get_json(force=True) or {}

    nmi      = str(body.get("nmi", "")).strip()
    checksum = str(body.get("checksum", "")).strip()

    val_errors = [e for e in (validate_nmi(nmi), validate_checksum(checksum)) if e]
    if val_errors:
        return jsonify({"error": "Validation failed", "details": val_errors}), 400

    transaction_id = body.get("transactionId") or f"TX-{uuid.uuid4().hex[:12].upper()}"
    logger.info("NMI Status  transactionId=%s  nmi=%s", transaction_id, nmi)

    params = {"transactionId": transaction_id, "nmi": nmi, "checksum": checksum}
    resp, status, err = call_upstream(
        "getNMIDetail", params, extra_headers={"Content-Type": "text/xml"})
    duration_ms = (time.monotonic() - t0) * 1000

    if err:
        audit_record("nmi-status", transaction_id, params,
                     f"{BASE_URL}/getNMIDetail", status, {}, err, duration_ms)
        return jsonify({"error": err, "transactionId": transaction_id}), \
               (status if status in (400, 401) else 502)
    try:
        detail = parse_detail_xml(resp.text)
    except ET.ParseError as exc:
        err = str(exc)
        audit_record("nmi-status", transaction_id, params,
                     f"{BASE_URL}/getNMIDetail", status, {}, err, duration_ms)
        return jsonify({"error": "Failed to parse getNMIDetail XML",
                        "detail": err, "transactionId": transaction_id}), 500

    audit_record("nmi-status", transaction_id, params,
                 f"{BASE_URL}/getNMIDetail", status, detail, None, duration_ms)
    logger.info("NMI Status DONE  %.0fms", duration_ms)

    return jsonify({
        "transactionId": transaction_id,
        "nmi":           nmi,
        "checksum":      checksum,
        "nmiStatus":     detail["nmiStatus"],
        "customerType":  detail["customerType"],
        "address":       detail["address"],
        "network": {
            "code":   detail["networkCode"],
            "tariff": detail["networkTariff"],
        },
        "meters":         detail["meters"],
        "registers":      detail["registers"],
        "controlledLoad": detail["controlledLoad"],
    }), 200


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT 3 & 4  —  RAW XML PASSTHROUGH
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/nmi-discovery", methods=["POST"])
def nmi_discovery_raw():
    t0   = time.monotonic()
    body = request.get_json(force=True) or {}

    val_errs = validate_discovery_params(body)
    if val_errs:
        return jsonify({"error": "Validation failed", "details": val_errs}), 400

    transaction_id = f"TX-{uuid.uuid4().hex[:12].upper()}"
    params = {k: body[k] for k in DISCOVERY_ALLOWED_PARAMS if body.get(k)}
    params["transactionId"] = transaction_id

    resp, status, err = call_upstream("NMIDiscovery", params)
    duration_ms = (time.monotonic() - t0) * 1000

    if err:
        audit_record("nmi-discovery-raw", transaction_id, params,
                     f"{BASE_URL}/NMIDiscovery", status, {}, err, duration_ms)
        return jsonify({"error": err, "transactionId": transaction_id}), \
               (status if status in (400, 401) else 502)

    audit_record("nmi-discovery-raw", transaction_id, params,
                 f"{BASE_URL}/NMIDiscovery", status,
                 {"raw_xml_length": len(resp.text)}, None, duration_ms)
    return Response(resp.text, status=200, mimetype="text/xml")


@app.route("/api/nmi-detail", methods=["POST"])
def nmi_detail_raw():
    t0   = time.monotonic()
    body = request.get_json(force=True) or {}

    missing = [f for f in ("transactionId", "nmi", "checksum")
               if not body.get(f) and body.get(f) != 0]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    transaction_id = body["transactionId"]
    nmi            = str(body["nmi"])
    checksum       = str(body["checksum"])

    val_errors = [e for e in (validate_nmi(nmi), validate_checksum(checksum)) if e]
    if val_errors:
        return jsonify({"error": "Validation failed", "details": val_errors,
                        "transactionId": transaction_id}), 422

    params = {"transactionId": transaction_id, "nmi": nmi, "checksum": checksum}
    resp, status, err = call_upstream(
        "getNMIDetail", params, extra_headers={"Content-Type": "text/xml"})
    duration_ms = (time.monotonic() - t0) * 1000

    if err:
        audit_record("nmi-detail-raw", transaction_id, params,
                     f"{BASE_URL}/getNMIDetail", status, {}, err, duration_ms)
        return jsonify({"error": err, "transactionId": transaction_id}), \
               (status if status in (400, 401) else 502)

    audit_record("nmi-detail-raw", transaction_id, params,
                 f"{BASE_URL}/getNMIDetail", status,
                 {"raw_xml_length": len(resp.text)}, None, duration_ms)
    return Response(resp.text, status=200, mimetype="text/xml")


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT & HEALTH
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/audit", methods=["GET"])
def get_audit():
    step_filter = request.args.get("step")
    tx_filter   = request.args.get("transaction_id")
    limit       = min(int(request.args.get("limit", 100)), 500)

    sql    = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    if step_filter:
        sql += " AND step = ?"
        params.append(step_filter)
    if tx_filter:
        sql += " AND transaction_id = ?"
        params.append(tx_filter)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = get_db().execute(sql, params).fetchall()
    records = []
    for row in rows:
        rec = dict(row)
        for field in ("request_params", "response_data"):
            try:
                rec[field] = json.loads(rec[field]) if rec[field] else None
            except (json.JSONDecodeError, TypeError):
                pass
        records.append(rec)

    return jsonify({"count": len(records), "records": records}), 200


@app.route("/", methods=["GET"])
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":  "ok",
        "service": "AEMO MSATS B2M API Wrapper",
        "endpoints": [
            {"method": "POST", "path": "/api/nmi-lookup",
             "description": "Address → all NMIs → full detail per NMI (chained)"},
            {"method": "POST", "path": "/api/nmi-status",
             "description": "NMI + checksum → full parsed detail"},
            {"method": "POST", "path": "/api/nmi-discovery",
             "description": "Address → raw AEMO XML (NMIDiscovery only)"},
            {"method": "POST", "path": "/api/nmi-detail",
             "description": "NMI + checksum → raw AEMO XML (getNMIDetail only)"},
            {"method": "GET",  "path": "/api/audit",
             "description": "Audit log"},
        ],
    }), 200


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
