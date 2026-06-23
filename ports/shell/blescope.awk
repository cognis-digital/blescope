# blescope BLE pairing-audit core — awk implementation (POSIX, no extensions).
#
# Reads a BLE GATT capture (JSON) on stdin, tokenizes it into a structured form,
# applies the same audit rules / rule-IDs as the Python reference, and prints
# findings as "SEVERITY<TAB>RULE-ID<TAB>title" plus a trailing "##INSECURE n".
#
# This is a focused JSON parser: it understands the blescope capture schema
# (objects, arrays of objects, arrays of strings, scalars). It is deliberately
# small and dependency-free rather than a general JSON library.

function err(msg) { print "PARSE_ERROR " msg > "/dev/stderr"; exit 2 }

# --- tokenizer ------------------------------------------------------------
function tokenize(s,   i, c, n, instr, esc, tok, buf) {
    n = 0
    instr = 0; esc = 0; buf = ""
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (instr) {
            if (esc) { buf = buf c; esc = 0; continue }
            if (c == "\\") { esc = 1; buf = buf c; continue }
            if (c == "\"") { instr = 0; T[++n] = "\"" buf; buf = ""; continue }
            buf = buf c
            continue
        }
        if (c == "\"") { instr = 1; continue }
        if (c == "{" || c == "}" || c == "[" || c == "]" || c == ":" || c == ",") {
            T[++n] = c; continue
        }
        if (c == " " || c == "\t" || c == "\n" || c == "\r") continue
        # bare scalar (number/true/false/null) — accumulate until delimiter
        tok = c
        while (i + 1 <= length(s)) {
            c = substr(s, i + 1, 1)
            if (c ~ /[ \t\n\r,}\]:]/) break
            tok = tok c; i++
        }
        T[++n] = "#" tok
    }
    return n
}

# --- recursive-descent over the token stream -----------------------------
# Stores results into globals: SMP[key], GATT_n, GATT_svc[i], GATT_char[i],
# GATT_props[i] (comma list), ATT_n, ATT_op[i], ATT_char[i], ATT_enc[i],
# DEV[key].

function val_str(t) { return (substr(t,1,1) == "\"") ? substr(t,2) : substr(t,2) }
function is_str(t)  { return substr(t,1,1) == "\"" }

function parse() {
    pos = 1
    if (T[pos] != "{") err("top-level must be object")
    parse_object("")
}

function skip_value(   depth) {
    # advance pos past one complete value
    if (T[pos] == "{") { depth=0; do { if(T[pos]=="{")depth++; if(T[pos]=="}")depth--; pos++ } while(depth>0 && pos<=NTOK); return }
    if (T[pos] == "[") { depth=0; do { if(T[pos]=="[")depth++; if(T[pos]=="]")depth--; pos++ } while(depth>0 && pos<=NTOK); return }
    pos++
}

function parse_object(prefix,   key) {
    pos++  # consume {
    if (T[pos] == "}") { pos++; return }
    while (1) {
        if (!is_str(T[pos])) err("object key must be string")
        key = val_str(T[pos]); pos++
        if (T[pos] != ":") err("expected colon")
        pos++
        parse_member(prefix, key)
        if (T[pos] == ",") { pos++; continue }
        if (T[pos] == "}") { pos++; return }
        err("expected , or }")
    }
}

function parse_member(prefix, key,   fullpath) {
    fullpath = (prefix == "") ? key : prefix "." key
    if (T[pos] == "{") {
        if (fullpath == "smp") parse_smp()
        else if (fullpath == "device") parse_device()
        else skip_value()
    } else if (T[pos] == "[") {
        if (fullpath == "gatt") parse_gatt()
        else if (fullpath == "att_ops") parse_att()
        else skip_value()
    } else {
        # scalar; only the device.* and smp.* scalars matter but those come via
        # their object parsers, so top-level scalars are ignored.
        skip_value()
    }
}

function parse_smp(   key, t) {
    pos++
    if (T[pos] == "}") { pos++; SMP_PRESENT=0; return }
    SMP_PRESENT=1
    while (1) {
        key = val_str(T[pos]); pos++
        pos++  # colon
        t = T[pos]
        if (substr(t,1,1)=="#" || is_str(t)) { SMP[key] = val_str(t); pos++ }
        else skip_value()
        if (T[pos] == ",") { pos++; continue }
        if (T[pos] == "}") { pos++; return }
        err("smp parse")
    }
}

function parse_device(   key, t) {
    pos++
    if (T[pos] == "}") { pos++; return }
    while (1) {
        key = val_str(T[pos]); pos++
        pos++
        t = T[pos]
        if (substr(t,1,1)=="#" || is_str(t)) { DEV[key] = val_str(t); pos++ }
        else skip_value()
        if (T[pos] == ",") { pos++; continue }
        if (T[pos] == "}") { pos++; return }
        err("device parse")
    }
}

function parse_gatt(   key, t, props) {
    pos++  # [
    if (T[pos] == "]") { pos++; return }
    while (1) {
        if (T[pos] != "{") err("gatt entry not object")
        GATT_n++
        GATT_svc[GATT_n]=""; GATT_char[GATT_n]=""; GATT_props[GATT_n]=""
        pos++
        while (1) {
            key = val_str(T[pos]); pos++; pos++
            if (key == "properties" && T[pos] == "[") {
                props = ""
                pos++
                while (T[pos] != "]") {
                    if (is_str(T[pos])) props = props (props==""?"":",") val_str(T[pos])
                    pos++
                    if (T[pos] == ",") pos++
                }
                pos++
                GATT_props[GATT_n] = props
            } else {
                t = T[pos]
                if (key == "service")        GATT_svc[GATT_n]  = val_str(t)
                else if (key == "characteristic") GATT_char[GATT_n] = val_str(t)
                if (substr(t,1,1)=="#" || is_str(t)) pos++
                else skip_value()
            }
            if (T[pos] == ",") { pos++; continue }
            if (T[pos] == "}") { pos++; break }
        }
        if (T[pos] == ",") { pos++; continue }
        if (T[pos] == "]") { pos++; return }
        err("gatt array")
    }
}

function parse_att(   key, t) {
    pos++
    if (T[pos] == "]") { pos++; return }
    while (1) {
        if (T[pos] != "{") err("att entry not object")
        ATT_n++
        ATT_op[ATT_n]=""; ATT_char[ATT_n]=""; ATT_enc[ATT_n]="false"
        pos++
        while (1) {
            key = val_str(T[pos]); pos++; pos++
            t = T[pos]
            if (key == "op")             ATT_op[ATT_n]   = val_str(t)
            else if (key == "characteristic") ATT_char[ATT_n] = val_str(t)
            else if (key == "encrypted") ATT_enc[ATT_n]  = val_str(t)
            if (substr(t,1,1)=="#" || is_str(t)) pos++
            else skip_value()
            if (T[pos] == ",") { pos++; continue }
            if (T[pos] == "}") { pos++; break }
        }
        if (T[pos] == ",") { pos++; continue }
        if (T[pos] == "]") { pos++; return }
        err("att array")
    }
}

# --- helpers --------------------------------------------------------------
function lc(s) { return tolower(s) }

function norm_uuid(s) {
    s = lc(s)
    gsub(/^[ \t]+|[ \t]+$/, "", s)
    gsub(/0x/, "", s)
    gsub(/-/, "", s)
    if (length(s) == 32 && s ~ /00001000800000805f9b34fb$/) s = substr(s, 5, 4)
    if (length(s) > 4 && s ~ /^0000/) s = substr(s, 5, 4)
    return s
}

function is_sensitive(u) { return (u=="2a56"||u=="2a57"||u=="2a58"||u=="fd5b") }

function is_lock(   i, u, name) {
    for (i = 1; i <= GATT_n; i++) {
        u = norm_uuid(GATT_svc[i])
        if (u=="1815"||u=="fd5a"||u=="fd5b") return 1
    }
    name = lc(DEV["name"])
    if (index(name,"lock")||index(name,"door")||index(name,"bolt")||index(name,"latch")) return 1
    return 0
}

function sevrank(s) {
    if (s=="critical") return 0; if (s=="high") return 1
    if (s=="medium") return 2; if (s=="low") return 3; return 4
}

function emit(sev, id, title) {
    NF_n++
    F_sev[NF_n]=sev; F_id[NF_n]=id; F_title[NF_n]=title
}

# --- audit ----------------------------------------------------------------
function audit(   lock, method, mitm, sc, oob, iocap, ks, i, u, op, props, insecure, j, tmp) {
    lock = is_lock()
    if (SMP_PRESENT) {
        method = lc(SMP["method"])
        mitm = (lc(SMP["mitm"]) == "true")
        sc   = (lc(SMP["secure_connections"]) == "true")
        oob  = (lc(SMP["oob"]) == "true")
        iocap = SMP["io_capability"]
        if (method=="just_works" || method=="justworks" || (!mitm && !oob))
            emit(lock?"critical":"high", "SMP-JUSTWORKS", "Just Works pairing (no MITM protection)")
        if (!sc)
            emit(lock?"high":"medium", "SMP-LEGACY", "LE Legacy Pairing (no Secure Connections)")
        if ("max_enc_key_size" in SMP) {
            ks = SMP["max_enc_key_size"] + 0
            if (ks < 16)
                emit(ks<=7?"high":"medium", "SMP-WEAKKEY", "Short encryption key (" ks " bytes)")
        }
        if (iocap == "NoInputNoOutput")
            emit("medium", "SMP-IOCAP", "NoInputNoOutput I/O capability forces Just Works")
        if (lc(SMP["debug_keys"])=="true" || lc(SMP["public_key"])=="debug")
            emit("critical", "SMP-DEBUGKEY", "Bluetooth debug keys in use")
        if (lc(SMP["bonding"])=="true" && !mitm && (method=="just_works"||method=="justworks"||method==""))
            emit("medium", "SMP-WEAKBOND", "Bonding stores an unauthenticated long-term key")
    } else {
        emit("medium", "SMP-NONE", "No pairing/security manager exchange observed")
    }

    for (i = 1; i <= ATT_n; i++) {
        op = lc(ATT_op[i])
        if (op!="write" && op!="write_command" && op!="write_request") continue
        u = norm_uuid(ATT_char[i])
        if (is_sensitive(u) && lc(ATT_enc[i])!="true")
            emit(lock?"critical":"high", "ATT-PLAINTEXT-CTRL", "Plaintext write to control characteristic " u)
    }

    for (i = 1; i <= GATT_n; i++) {
        if (GATT_char[i] == "") continue
        u = norm_uuid(GATT_char[i])
        props = "," lc(GATT_props[i]) ","
        if (is_sensitive(u) && index(props,",write,") && !index(props,",authenticated_write,") && !index(props,",signed_write,"))
            emit(lock?"high":"medium", "GATT-UNAUTH-WRITE", "Unauthenticated writable control characteristic " u)
    }

    # stable sort by severity rank (insertion sort; small N)
    for (i = 2; i <= NF_n; i++) {
        for (j = i; j > 1 && sevrank(F_sev[j]) < sevrank(F_sev[j-1]); j--) {
            tmp=F_sev[j]; F_sev[j]=F_sev[j-1]; F_sev[j-1]=tmp
            tmp=F_id[j];  F_id[j]=F_id[j-1];   F_id[j-1]=tmp
            tmp=F_title[j];F_title[j]=F_title[j-1];F_title[j-1]=tmp
        }
    }

    insecure = 0
    for (i = 1; i <= NF_n; i++) {
        print F_sev[i] "\t" F_id[i] "\t" F_title[i]
        if (F_sev[i] != "info") insecure = 1
    }
    print "##INSECURE " insecure
}

BEGIN { RS = "\002"; GATT_n=0; ATT_n=0; NF_n=0; SMP_PRESENT=0 }
{ RAW = RAW $0 "\n" }
END {
    gsub(/[ \t]*$/, "", RAW)
    NTOK = tokenize(RAW)
    if (NTOK == 0) err("empty")
    parse()
    audit()
}
