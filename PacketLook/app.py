import time
from datetime import datetime, time
import pandas as pd
import streamlit as st
import ipaddress
from google import genai
from google.genai import types
import json
import os
import numpy as np

api_key = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL = "gemini-3.5-flash-lite"

if not api_key:
    try:
        api_key = st.secrets["GEMINI_API_KEY"]
    except Exception:
        api_key = None

if not api_key:
    st.error(
        "Gemini API key is not configured. "
        "Set GEMINI_API_KEY as an environment variable "
        "or add it to .streamlit/secrets.toml."
    )
    st.stop()

gemini_client = genai.Client(
    api_key=api_key
)

# --------------------------------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------------------------------
st.set_page_config(
    page_title="PacketLook",
    page_icon="logo.png",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# --------------------------------------------------------------------------
# CONSTANTS (mirrors the React file's EXAMPLE_MESSAGES / EXAMPLE_PROMPTS / STAT_CARDS)
# --------------------------------------------------------------------------
WELCOME_MESSAGE = """Hello! I'm PacketLook, your AI assistant for network traffic analysis. 
If you'd like an overview of the uploaded network dataset, just ask! You can also ask questions about protocols, top source or destination IPs, services, large packets, time analysis, anomalies, or filter traffic to inspect specific connections. How can I help you today?"""

PACKETLOOK_TOOL_DECLARATIONS = [

    {
        "name": "network_summary",
        "description": (
            "Get an overall summary of the currently uploaded "
            "network traffic dataset, including packet count, "
            "total bytes, unique IPs, protocols, services, "
            "and average packet size."
        ),
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },

    {
        "name": "protocol_analysis",
        "description": (
            "Analyze network traffic by protocol. Use this when "
            "the user asks about TCP, UDP, ICMP, ARP, the most "
            "common protocol, protocol traffic volume, or a "
            "comparison between protocols."
        ),
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },

    {
        "name": "service_analysis",
        "description": (
            "Analyze network traffic by service. Use this when "
            "the user asks about services such as HTTPS, FTP, "
            "Telnet, mDNS, SSDP, or which service generates "
            "the most traffic."
        ),
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },

    {
        "name": "top_source_ips",
        "description": (
            "Find the source IP addresses generating the most "
            "network traffic. Use this for questions such as "
            "'which IP sent the most traffic', 'busiest host', "
            "or 'top source IP'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of IPs to return.",
                    "default": 10
                }
            }
        }
    },

    {
        "name": "top_destination_ips",
        "description": (
            "Find destination IP addresses receiving the most "
            "network traffic."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of IPs to return.",
                    "default": 10
                }
            }
        }
    },

    {
        "name": "external_destinations",
        "description": (
            "Find external destinations contacted by private "
            "source IP addresses."
        ),
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },

    {
        "name": "filter_traffic",
        "description": (
            "Filter the network dataset using source IP, "
            "destination IP, protocol, or service. Use this "
            "when the user asks to show or inspect specific "
            "traffic."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "source_ip": {
                    "type": "string",
                    "description": "Source IP to filter by."
                },
                "destination_ip": {
                    "type": "string",
                    "description": "Destination IP to filter by."
                },
                "protocol": {
                    "type": "string",
                    "description": "Protocol to filter by."
                },
                "service": {
                    "type": "string",
                    "description": "Service to filter by."
                }
            }
        }
    },

    {
        "name": "anomalies",
        "description": (
            "Return anomalies detected by PacketLook's network "
            "analysis engine."
        ),
        "parameters": {
            "type": "object",
            "properties": {}
        }
    },

    {
        "name": "large_packets",
        "description": (
            "Find unusually large packets using the 95th "
            "percentile packet-size threshold."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of packets to return.",
                    "default": 10
                }
            }
        }
    },

    {
        "name": "time_analysis",
        "description": (
            "Analyze network traffic over time and identify "
            "the busiest timestamp."
        ),
        "parameters": {
            "type": "object",
            "properties": {}
        }
    }
]

PACKETLOOK_SYSTEM_INSTRUCTION = """
You are PacketLook, an AI agent specialized in network traffic analysis.

Your job is to analyze ONLY the network traffic dataset currently uploaded
by the user through PacketLook.

The dataset may contain fields such as:
- Date
- Time
- Source IP
- Destination IP
- Protocol
- Service
- Size (Bytes)

==================================================
CORE RULES
==================================================

1. DATASET IS THE SOURCE OF TRUTH

Use PacketLook tools whenever factual information needs to be obtained,
filtered, counted, aggregated, compared, or calculated from the dataset.

Never invent or guess:
- packet counts
- IP addresses
- destination addresses
- protocols
- services
- timestamps
- byte counts
- percentages
- averages
- rankings
- frequencies
- other dataset statistics

If a value comes from the dataset, obtain it through the appropriate
PacketLook tool whenever such a tool is available.

Do not rely on your own arithmetic or estimation when a PacketLook tool
can calculate the value.

==================================================
2. TOOL USAGE
==================================================

Use the most appropriate PacketLook tool for the user's question.

You may call multiple tools when necessary.

Examples:

- Overall dataset questions -> use network_summary
- Questions about counts -> use the appropriate counting/aggregation tool
- Questions about a specific IP -> use the relevant IP analysis tool
- Questions about protocols/services -> use the relevant protocol/service tool
- Questions involving time ranges -> use the relevant time/filter tool

Do not call tools unnecessarily.

Do not repeatedly call the same tool with identical arguments.

A repeated tool call is allowed only when:
- the arguments are meaningfully different, or
- the previous result was insufficient to answer the question.

Once sufficient information has been obtained, STOP calling tools and
answer the user.

==================================================
3. DATASET SCOPE
==================================================

You are analyzing the uploaded dataset only.

Do NOT assume you have access to:
- the user's live network
- network traffic outside the dataset
- external systems
- the entire internet
- threat intelligence databases
- information not returned by PacketLook tools

If the user asks something that requires information outside the dataset,
clearly explain that the available dataset does not contain the required
information.

==================================================
4. FACTS VS SECURITY INTERPRETATION
==================================================

Clearly distinguish between:

A. OBSERVED DATA
Facts directly supported by the dataset.

Examples:
- An IP generated 42,000 bytes.
- TCP accounted for 73% of recorded packets.
- Port/service X appeared 120 times.

B. INTERPRETATION
Reasonable analysis based on the observed data.

Examples:
- This host generated unusually high traffic relative to other hosts.
- This communication pattern may warrant further investigation.

C. SECURITY CONCLUSIONS
Do not automatically classify traffic as malicious, benign, an attack,
or a compromise based only on unusual behavior.

An unusual protocol, service, IP, traffic volume, or communication pattern
is not by itself proof of malicious activity.

Use appropriately cautious language such as:
- "The dataset shows..."
- "This may indicate..."
- "This pattern could warrant investigation..."
- "The available data is insufficient to determine whether..."

==================================================
5. INSUFFICIENT INFORMATION
==================================================

If the dataset or available PacketLook tools do not contain enough
information to answer the question, say so explicitly.

Never fill missing information with assumptions.

If clarification from the user is necessary, ask a concise clarification
question instead of guessing.

==================================================
6. RESPONSE CONTENT
==================================================

When useful, include relevant:
- IP addresses
- source/destination pairs
- protocols
- services
- packet counts
- byte counts
- timestamps
- time ranges

Prefer concise, structured answers.

Use tables or bullet points when they make network-analysis results
easier to understand.

Do not overwhelm the user with unrelated dataset information.

==================================================
7. FOLLOW-UP QUESTIONS AND CONTEXT
==================================================

Use the previous conversation to interpret follow-up questions.

Resolve references such as:
- "it"
- "that IP"
- "that protocol"
- "those packets"
- "the same service"
- "why?"
- "what about it?"
- "how much did it send?"
- "when did this happen?"

using the immediately relevant context from the conversation.

Example:

User:
Which IP generated the most traffic?

Agent:
192.168.32.110 generated the most traffic.

User:
What protocol did it mostly use?

Interpret "it" as 192.168.32.110 and use the appropriate PacketLook
tool to determine the answer.

If multiple entities could reasonably match the reference, do not guess.
Ask the user for clarification.

Maintain conversational continuity, but never allow conversation context
to override actual dataset/tool results.

==================================================
8. CASUAL CONVERSATION
==================================================

If the user sends a conversational message such as:
- "nice"
- "thanks"
- "okay"
- "cool"
- "got it"

do NOT call a PacketLook tool.

Respond naturally and briefly.

==================================================
9. BROAD QUESTIONS
==================================================

For broad questions such as:
- "Tell me about my logs"
- "Give me an overview"
- "What is in this dataset?"
- "Summarize my traffic"

use the network_summary tool first.

After receiving the summary, provide a concise overview of the most
important observed characteristics.

Do not make unsupported security claims.

==================================================
10. TOOL RESULT HANDLING
==================================================

Treat PacketLook tool results as authoritative for facts about the
uploaded dataset.

Do not modify, invent, or silently reinterpret returned values.

If a tool returns no matching records, clearly state that no matching
records were found in the dataset.

If a tool reports incomplete, unavailable, or ambiguous information,
preserve that limitation in the final answer.

==================================================
11. FINAL ANSWER
==================================================

After obtaining enough information from PacketLook tools:

- STOP calling tools.
- Answer the user's actual question directly.
- Clearly distinguish observed facts from interpretation.
- Mention relevant limitations when necessary.
- Do not expose internal tool-selection reasoning.
- Do not describe tool calls unless doing so is useful to explain a result.

Your goal is accurate, concise, dataset-grounded network analysis.

Never fabricate dataset facts.
Never assume information that is not supported by the dataset or
conversation.
"""


# --------------------------------------------------------------------------
# SESSION STATE
# --------------------------------------------------------------------------
defaults = {
    "app_state": "empty",       # empty | uploaded | chat | processing
    "messages": [],
    "show_results": False,
    "dark": False,
    "uploaded_name": None,
    "pending_user_msg": None,   # holds a message waiting for the agent's reply
    "df":None,

    # Network analysis
    "analysis": None,
    "stat_cards": [],
    "traffic_profile": [],
    "anomalies": [],
    "recommendations": [],
    "ai_summary": "",
    "last_tool": None,
    "last_tool_result": None,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

if not st.session_state.messages:
    st.session_state.messages = [{
    "role": "agent",
    "content": WELCOME_MESSAGE,
    "timestamp": datetime.now().strftime("%H:%M:%S"),
    "system_message": True
}]

def reset_session():
    st.session_state.app_state = "empty"
    st.session_state.messages = [{
    "role": "agent",
    "content": WELCOME_MESSAGE,
    "timestamp": datetime.now().strftime("%H:%M:%S"),
    "system_message": True
    }]
    st.session_state.show_results = False
    st.session_state.uploaded_name = None
    st.session_state.pending_user_msg = None
    st.session_state.df = None

    st.session_state.analysis = None
    st.session_state.stat_cards = []
    st.session_state.traffic_profile = []
    st.session_state.anomalies = []
    st.session_state.recommendations = []
    st.session_state.ai_summary = ""
    st.session_state.last_tool = None
    st.session_state.last_tool_result = None


def start_chat():
    st.session_state.app_state = "chat"
    st.session_state.messages = [
        {
            "role": "agent",
            "content": WELCOME_MESSAGE,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "system_message": True
        }
    ]
    st.session_state.show_results = True

    st.session_state.pending_user_msg = None
    st.session_state.last_tool = None
    st.session_state.last_tool_result = None

def format_bytes(value):
    """Convert bytes into readable units."""
    if pd.isna(value):
        return "0 B"

    value = float(value)

    if value >= 1024 ** 3:
        return f"{value / (1024 ** 3):.2f} GB"
    elif value >= 1024 ** 2:
        return f"{value / (1024 ** 2):.2f} MB"
    elif value >= 1024:
        return f"{value / 1024:.2f} KB"
    else:
        return f"{int(value):,} B"


def is_private_ip(ip):
    """Check whether an IP address is private."""
    try:
        return ipaddress.ip_address(str(ip)).is_private
    except (ValueError, TypeError):
        return False


def build_network_analysis(df):

    # ---------------------------------------------------------
    # BASIC STATISTICS
    # ---------------------------------------------------------

    total_packets = len(df)
    total_bytes = df["Size (Bytes)"].sum()
    avg_packet_size = df["Size (Bytes)"].mean()
    unique_sources = df["Source IP"].nunique()
    unique_destinations = df["Destination IP"].nunique()

    unique_ips = pd.concat([
        df["Source IP"],
        df["Destination IP"]
    ]).nunique()

    protocol_count = df["Protocol"].nunique()
    service_count = df["Service"].nunique()


    # ---------------------------------------------------------
    # PROTOCOL ANALYSIS
    # ---------------------------------------------------------

    protocol_stats = (
        df.groupby("Protocol")
        .agg(
            Packets=("Protocol", "size"),
            Bytes=("Size (Bytes)", "sum"),
            Avg_Size=("Size (Bytes)", "mean")
        )
        .sort_values("Packets", ascending=False)
    )

    protocol_percentages = (
        df["Protocol"]
        .value_counts(normalize=True)
        .mul(100)
        .round(1)
    )


    # ---------------------------------------------------------
    # SERVICE ANALYSIS
    # ---------------------------------------------------------

    service_stats = (
        df.groupby("Service")
        .agg(
            Packets=("Service", "size"),
            Bytes=("Size (Bytes)", "sum")
        )
        .sort_values("Packets", ascending=False)
    )


    # ---------------------------------------------------------
    # SOURCE IP ANALYSIS
    # ---------------------------------------------------------

    source_stats = (
        df.groupby("Source IP")
        .agg(
            Packets=("Source IP", "size"),
            Bytes=("Size (Bytes)", "sum")
        )
        .sort_values("Bytes", ascending=False)
    )


    # ---------------------------------------------------------
    # DESTINATION IP ANALYSIS
    # ---------------------------------------------------------

    destination_stats = (
        df.groupby("Destination IP")
        .agg(
            Packets=("Destination IP", "size"),
            Bytes=("Size (Bytes)", "sum")
        )
        .sort_values("Bytes", ascending=False)
    )


    # ---------------------------------------------------------
    # PRIVATE / EXTERNAL TRAFFIC
    # ---------------------------------------------------------

    df = df.copy()

    df["Source Private"] = df["Source IP"].apply(is_private_ip)

    df["Destination Private"] = df["Destination IP"].apply(is_private_ip)

    external_traffic = df[
        df["Source Private"] &
        ~df["Destination Private"]
    ]

    external_destinations = (
        external_traffic["Destination IP"]
        .nunique()
    )


    # ---------------------------------------------------------
    # LARGE PACKET ANALYSIS
    # ---------------------------------------------------------

    packet_sizes = df["Size (Bytes)"].dropna()

    if len(packet_sizes) > 0:

        p95 = packet_sizes.quantile(0.95)

        large_packets = df[
            df["Size (Bytes)"] > p95
        ].sort_values(
            "Size (Bytes)",
            ascending=False
        )

    else:

        p95 = 0
        large_packets = pd.DataFrame()


    # ---------------------------------------------------------
    # TIMESTAMP / TRAFFIC ANALYSIS
    # ---------------------------------------------------------

    df["Timestamp"] = pd.to_datetime(
        df["Date"].astype(str) + " " + df["Time"].astype(str),
        errors="coerce"
    )

    traffic_per_second = (
        df.dropna(subset=["Timestamp"])
        .groupby("Timestamp")
        .agg(
            Packets=("Timestamp", "size"),
            Bytes=("Size (Bytes)", "sum")
        )
    )


    # ---------------------------------------------------------
    # ICMP BURST DETECTION
    # ---------------------------------------------------------

    icmp_count = int(
        (df["Protocol"].astype(str).str.upper() == "ICMP").sum()
    )


    # ---------------------------------------------------------
    # TELNET DETECTION
    # ---------------------------------------------------------

    telnet_mask = (
        df["Service"]
        .astype(str)
        .str.contains(
            "telnet",
            case=False,
            na=False
        )
    )

    telnet_count = int(telnet_mask.sum())


    # ---------------------------------------------------------
    # MISSING VALUES
    # ---------------------------------------------------------

    missing_values = (
        df.isna()
        .sum()
        .sum()
    )


    # ---------------------------------------------------------
    # ANOMALIES
    # ---------------------------------------------------------

    anomalies = []


    if telnet_count > 0:
        anomalies.append({
            "text": f"Telnet traffic detected ({telnet_count:,} packets)",
            "severity": "error"
        })


    if external_destinations > 0:
        anomalies.append({
            "text": (
                f"{external_destinations:,} external "
                f"destination(s) contacted"
            ),
            "severity": "warn"
        })


    if len(large_packets) > 0:
        anomalies.append({
            "text": (
                f"{len(large_packets):,} packets exceed "
                f"the 95th percentile size"
            ),
            "severity": "warn"
        })


    if icmp_count > 0:

        icmp_percentage = (
            icmp_count / total_packets * 100
            if total_packets > 0
            else 0
        )

        if icmp_percentage >= 10:

            anomalies.append({
                "text": (
                    f"High ICMP activity detected "
                    f"({icmp_percentage:.1f}% of packets)"
                ),
                "severity": "warn"
            })


    if missing_values > 0:
        anomalies.append({
            "text": f"{missing_values:,} missing values detected",
            "severity": "warn"
        })


    # ---------------------------------------------------------
    # RECOMMENDATIONS
    # ---------------------------------------------------------

    recommendations = []


    if telnet_count > 0:
        recommendations.append(
            "Review observed Telnet communication"
        )


    if external_destinations > 0:
        recommendations.append(
            "Review external destination connections"
        )


    if len(large_packets) > 0:
        recommendations.append(
            "Investigate unusual packet-size activity"
        )


    if icmp_count > 0:
        recommendations.append(
            "Review ICMP activity and communication frequency"
        )


    if not recommendations:
        recommendations.append(
            "No immediate traffic patterns require review"
        )


    # ---------------------------------------------------------
    # RIGHT-PANEL STATISTICS
    # ---------------------------------------------------------

    stat_cards = [
        {
            "label": "PACKETS",
            "value": f"{total_packets:,}",
            "delta": None,
        },
        {
            "label": "TOTAL_BYTES",
            "value": format_bytes(total_bytes),
            "delta": None,
        },
        {
            "label": "UNIQUE_IPS",
            "value": f"{unique_ips:,}",
            "delta": None,
        },
        {
            "label": "PROTOCOLS",
            "value": f"{protocol_count:,}",
            "delta": None,
        },
    ]


    # ---------------------------------------------------------
    # TRAFFIC PROFILE
    # ---------------------------------------------------------

    traffic_profile = [
        {
            "label": str(protocol),
            "pct": float(pct)
        }
        for protocol, pct
        in protocol_percentages.head(5).items()
    ]


    # ---------------------------------------------------------
    # COMPLETE ANALYSIS OBJECT
    # ---------------------------------------------------------

    analysis = {
        "total_packets": total_packets,
        "total_bytes": int(total_bytes),
        "avg_packet_size": float(avg_packet_size)
        if not pd.isna(avg_packet_size)
        else 0,

        "unique_sources": unique_sources,
        "unique_destinations": unique_destinations,
        "unique_ips": unique_ips,

        "protocol_count": protocol_count,
        "service_count": service_count,

        "protocol_stats": protocol_stats,
        "service_stats": service_stats,
        "source_stats": source_stats,
        "destination_stats": destination_stats,

        "external_traffic": external_traffic,
        "external_destinations": external_destinations,

        "large_packets": large_packets,
        "packet_size_p95": float(p95),

        "traffic_per_second": traffic_per_second,

        "icmp_count": icmp_count,
        "telnet_count": telnet_count,

        "missing_values": int(missing_values),

        "anomalies": anomalies,
        "recommendations": recommendations,
    }


    return {
        "analysis": analysis,
        "stat_cards": stat_cards,
        "traffic_profile": traffic_profile,
        "anomalies": anomalies,
        "recommendations": recommendations,
    }

def handle_upload(uploaded):

    df = process_network_csv(uploaded)

    # ---------------------------------------------------------
    # BASIC VALIDATION
    # ---------------------------------------------------------

    required_columns = [
        "Date",
        "Time",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Service",
        "Size (Bytes)",
    ]

    missing_columns = [
        col for col in required_columns
        if col not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            "Missing required columns: "
            + ", ".join(missing_columns)
        )


    # ---------------------------------------------------------
    # BUILD NETWORK ANALYSIS
    # ---------------------------------------------------------

    result = build_network_analysis(df)


    # ---------------------------------------------------------
    # SAVE EVERYTHING TO SESSION STATE
    # ---------------------------------------------------------

    st.session_state.app_state = "uploaded"
    st.session_state.uploaded_name = uploaded.name
    st.session_state.df = df
    st.session_state.analysis = result["analysis"]
    st.session_state.stat_cards = result["stat_cards"]
    st.session_state.traffic_profile = result["traffic_profile"]
    st.session_state.anomalies = result["anomalies"]
    st.session_state.recommendations = result["recommendations"]
    st.session_state.ai_summary = ""

    return result


def process_network_csv(uploaded_file):
    df = pd.read_csv(uploaded_file)

    # Clean column names
    df.columns = df.columns.str.strip()

    # Convert date/time
    df["Date"] = pd.to_datetime(
        df["Date"],
        format="%d-%m-%Y",
        errors="coerce"
    )

    df["Time"] = pd.to_datetime(
        df["Time"],
        format="%H:%M:%S",
        errors="coerce"
    ).dt.time

    # Numeric conversion
    df["Size (Bytes)"] = pd.to_numeric(
        df["Size (Bytes)"],
        errors="coerce"
    )

    return df

# ==========================================================================
# PACKETLOOK AGENT TOOLS
# ==========================================================================

def tool_network_summary(df):
    """Return a high-level summary of the network dataset."""

    total_packets = len(df)
    total_bytes = df["Size (Bytes)"].sum()
    avg_packet_size = df["Size (Bytes)"].mean()

    unique_ips = pd.concat([
        df["Source IP"],
        df["Destination IP"]
    ]).nunique()

    return {
        "tool": "network_summary",
        "total_packets": int(total_packets),
        "total_bytes": int(total_bytes),
        "total_bytes_formatted": format_bytes(total_bytes),
        "average_packet_size": round(float(avg_packet_size), 2),
        "unique_ips": int(unique_ips),
        "unique_source_ips": int(df["Source IP"].nunique()),
        "unique_destination_ips": int(df["Destination IP"].nunique()),
        "protocols": int(df["Protocol"].nunique()),
        "services": int(df["Service"].nunique()),
    }


def tool_protocol_analysis(df):
    """Analyze protocols by packet count and traffic volume."""

    stats = (
        df.groupby("Protocol")
        .agg(
            packets=("Protocol", "size"),
            bytes=("Size (Bytes)", "sum"),
            average_packet_size=("Size (Bytes)", "mean")
        )
        .sort_values("packets", ascending=False)
    )

    result = []

    for protocol, row in stats.iterrows():
        result.append({
            "protocol": str(protocol),
            "packets": int(row["packets"]),
            "bytes": int(row["bytes"]),
            "bytes_formatted": format_bytes(row["bytes"]),
            "average_packet_size": round(
                float(row["average_packet_size"]), 2
            )
        })

    return {
        "tool": "protocol_analysis",
        "protocols": result
    }


def tool_service_analysis(df):
    """Analyze network services."""

    stats = (
        df.groupby("Service")
        .agg(
            packets=("Service", "size"),
            bytes=("Size (Bytes)", "sum")
        )
        .sort_values("packets", ascending=False)
    )

    result = []

    for service, row in stats.iterrows():
        result.append({
            "service": str(service),
            "packets": int(row["packets"]),
            "bytes": int(row["bytes"]),
            "bytes_formatted": format_bytes(row["bytes"])
        })

    return {
        "tool": "service_analysis",
        "services": result
    }


def tool_top_source_ips(df, limit=10):
    """Find source IPs generating the most traffic."""

    stats = (
        df.groupby("Source IP")
        .agg(
            packets=("Source IP", "size"),
            bytes=("Size (Bytes)", "sum")
        )
        .sort_values("bytes", ascending=False)
        .head(limit)
    )

    result = []

    for ip, row in stats.iterrows():
        result.append({
            "ip": str(ip),
            "packets": int(row["packets"]),
            "bytes": int(row["bytes"]),
            "bytes_formatted": format_bytes(row["bytes"])
        })

    return {
        "tool": "top_source_ips",
        "sources": result
    }


def tool_top_destination_ips(df, limit=10):
    """Find destination IPs receiving the most traffic."""

    stats = (
        df.groupby("Destination IP")
        .agg(
            packets=("Destination IP", "size"),
            bytes=("Size (Bytes)", "sum")
        )
        .sort_values("bytes", ascending=False)
        .head(limit)
    )

    result = []

    for ip, row in stats.iterrows():
        result.append({
            "ip": str(ip),
            "packets": int(row["packets"]),
            "bytes": int(row["bytes"]),
            "bytes_formatted": format_bytes(row["bytes"])
        })

    return {
        "tool": "top_destination_ips",
        "destinations": result
    }


def tool_external_destinations(df):
    """Find external destinations contacted by private source IPs."""

    temp = df.copy()

    temp["Source Private"] = (
        temp["Source IP"].apply(is_private_ip)
    )

    temp["Destination Private"] = (
        temp["Destination IP"].apply(is_private_ip)
    )

    external = temp[
        temp["Source Private"] &
        ~temp["Destination Private"]
    ]

    if external.empty:
        return {
            "tool": "external_destinations",
            "count": 0,
            "destinations": []
        }

    stats = (
        external.groupby("Destination IP")
        .agg(
            packets=("Destination IP", "size"),
            bytes=("Size (Bytes)", "sum")
        )
        .sort_values("bytes", ascending=False)
    )

    result = []

    for ip, row in stats.iterrows():
        result.append({
            "ip": str(ip),
            "packets": int(row["packets"]),
            "bytes": int(row["bytes"]),
            "bytes_formatted": format_bytes(row["bytes"])
        })

    return {
        "tool": "external_destinations",
        "count": len(result),
        "destinations": result
    }


def tool_filter_traffic(df, source_ip=None, destination_ip=None, protocol=None, service=None):
    """Filter network traffic using one or more criteria."""

    filtered = df.copy()

    if source_ip:
        filtered = filtered[
            filtered["Source IP"].astype(str).str.lower()
            == source_ip.lower()
        ]

    if destination_ip:
        filtered = filtered[
            filtered["Destination IP"].astype(str).str.lower()
            == destination_ip.lower()
        ]

    if protocol:
        filtered = filtered[
            filtered["Protocol"].astype(str).str.lower()
            == protocol.lower()
        ]

    if service:
        filtered = filtered[
            filtered["Service"].astype(str).str.lower()
            .str.contains(service.lower(), na=False)
        ]

    return {
        "tool": "filter_traffic",
        "count": len(filtered),
        "total_bytes": int(
            filtered["Size (Bytes)"].sum()
        ) if not filtered.empty else 0,
        "total_bytes_formatted": format_bytes(
            filtered["Size (Bytes)"].sum()
        ) if not filtered.empty else "0 B",
        "rows": dataframe_to_json_safe(
            filtered.head(100)
        )
    }


def tool_anomalies(df):
    """Return anomalies already identified by PacketLook."""

    analysis = st.session_state.get("analysis")

    if analysis is None:
        return {
            "tool": "anomalies",
            "anomalies": []
        }

    return {
        "tool": "anomalies",
        "anomalies": analysis.get("anomalies", [])
    }


def tool_large_packets(df, limit=10):
    """Find unusually large packets."""

    threshold = df["Size (Bytes)"].quantile(0.95)

    packets = (
        df[df["Size (Bytes)"] > threshold]
        .sort_values("Size (Bytes)", ascending=False)
        .head(limit)
    )

    return {
        "tool": "large_packets",
        "threshold": float(threshold),
        "threshold_formatted": format_bytes(threshold),
        "count": int(
            (df["Size (Bytes)"] > threshold).sum()
        ),
        "packets": dataframe_to_json_safe(
            packets
        )
    }


def tool_time_analysis(df):
    """Analyze traffic over time."""

    temp = df.copy()

    temp["Timestamp"] = pd.to_datetime(
        temp["Date"].astype(str)
        + " "
        + temp["Time"].astype(str),
        errors="coerce"
    )

    traffic = (
        temp.dropna(subset=["Timestamp"])
        .groupby("Timestamp")
        .agg(
            packets=("Timestamp", "size"),
            bytes=("Size (Bytes)", "sum")
        )
        .sort_index()
    )

    if traffic.empty:
        return {
            "tool": "time_analysis",
            "count": 0,
            "data": []
        }

    busiest_time = traffic["packets"].idxmax()

    return {
        "tool": "time_analysis",
        "count": len(traffic),
        "busiest_timestamp": str(busiest_time),
        "busiest_packets": int(
            traffic.loc[busiest_time, "packets"]
        ),
        "busiest_bytes": int(
            traffic.loc[busiest_time, "bytes"]
        ),
        "time_data": dataframe_to_json_safe(
            traffic.reset_index()
        )
    }

# ==========================================================================
# PACKETLOOK AGENT ROUTER
# ==========================================================================

def route_query(query):
    """
    Decide which PacketLook tool should handle the user's question.

    This is intentionally rule-based for the first version.
    Later, Gemini will replace this router.
    """

    q = query.lower().strip()

    # ------------------------------------------------------
    # ANOMALIES
    # ------------------------------------------------------

    if any(word in q for word in [
        "anomal",
        "suspicious",
        "unusual",
        "abnormal",
        "risk"
    ]):
        return "anomalies"


    # ------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------

    if any(word in q for word in [
        "summary",
        "summarize",
        "overview",
        "overall",
        "dataset",
        "traffic overview"
    ]):
        return "network_summary"


    # ------------------------------------------------------
    # SOURCE IP
    # ------------------------------------------------------

    if (
        ("source" in q and "ip" in q)
        or "generated the most traffic" in q
        or "sent the most traffic" in q
        or "top source" in q
        or "busiest source" in q
    ):
        return "top_source_ips"


    # ------------------------------------------------------
    # DESTINATION IP
    # ------------------------------------------------------

    if (
        ("destination" in q and "ip" in q)
        or "received the most traffic" in q
        or "top destination" in q
        or "busiest destination" in q
    ):
        return "top_destination_ips"


    # ------------------------------------------------------
    # EXTERNAL TRAFFIC
    # ------------------------------------------------------

    if any(word in q for word in [
        "external",
        "outside",
        "internet",
        "public ip"
    ]):
        return "external_destinations"


    # ------------------------------------------------------
    # PROTOCOL
    # ------------------------------------------------------

    if any(word in q for word in [
        "protocol",
        "tcp",
        "udp",
        "icmp",
        "arp"
    ]):
        return "protocol_analysis"


    # ------------------------------------------------------
    # SERVICE
    # ------------------------------------------------------

    if any(word in q for word in [
        "service",
        "telnet",
        "http",
        "https",
        "ftp",
        "mdns",
        "ssdp"
    ]):
        return "service_analysis"


    # ------------------------------------------------------
    # LARGE PACKETS
    # ------------------------------------------------------

    if any(word in q for word in [
        "large packet",
        "largest packet",
        "packet size",
        "big packet"
    ]):
        return "large_packets"


    # ------------------------------------------------------
    # TIME
    # ------------------------------------------------------

    if any(word in q for word in [
        "time",
        "timestamp",
        "when",
        "busiest",
        "peak",
        "around"
    ]):
        return "time_analysis"


    # ------------------------------------------------------
    # DEFAULT
    # ------------------------------------------------------

    return "network_summary"

def execute_gemini_tool(tool_name, arguments, df):

    arguments = arguments or {}

    if tool_name == "network_summary":
        return tool_network_summary(df)

    elif tool_name == "protocol_analysis":
        return tool_protocol_analysis(df)

    elif tool_name == "service_analysis":
        return tool_service_analysis(df)

    elif tool_name == "top_source_ips":
        limit = int(arguments.get("limit", 10))

        return tool_top_source_ips(
            df,
            limit=limit
        )

    elif tool_name == "top_destination_ips":
        limit = int(arguments.get("limit", 10))

        return tool_top_destination_ips(
            df,
            limit=limit
        )

    elif tool_name == "external_destinations":
        return tool_external_destinations(df)

    elif tool_name == "filter_traffic":

        return tool_filter_traffic(
            df,
            source_ip=arguments.get("source_ip"),
            destination_ip=arguments.get("destination_ip"),
            protocol=arguments.get("protocol"),
            service=arguments.get("service")
        )

    elif tool_name == "anomalies":
        return tool_anomalies(df)

    elif tool_name == "large_packets":

        limit = int(arguments.get("limit", 10))

        return tool_large_packets(
            df,
            limit=limit
        )

    elif tool_name == "time_analysis":
        return tool_time_analysis(df)

    raise ValueError(
        f"Unknown PacketLook tool: {tool_name}"
    )

def generate_agent_response(query, result):
    """Convert tool output into a readable PacketLook response."""

    tool = result["tool"]

    # ==========================================================
    # SUMMARY
    # ==========================================================

    if tool == "network_summary":

        return (
            f"Network summary:\n\n"
            f"• {result['total_packets']:,} packets observed\n"
            f"• {result['total_bytes_formatted']} of total traffic\n"
            f"• {result['unique_ips']:,} unique IP addresses\n"
            f"• {result['protocols']} protocols\n"
            f"• {result['services']} services\n"
            f"• Average packet size: "
            f"{result['average_packet_size']:.1f} bytes"
        )


    # ==========================================================
    # PROTOCOLS
    # ==========================================================

    if tool == "protocol_analysis":

        protocols = result["protocols"]

        if not protocols:
            return "No protocol information was found."

        lines = ["Protocol analysis:\n"]

        for i, p in enumerate(protocols[:5], 1):

            lines.append(
                f"{i}. {p['protocol']} — "
                f"{p['packets']:,} packets, "
                f"{p['bytes_formatted']}"
            )

        return "\n".join(lines)


    # ==========================================================
    # SERVICES
    # ==========================================================

    if tool == "service_analysis":

        services = result["services"]

        if not services:
            return "No service information was found."

        lines = ["Service analysis:\n"]

        for i, s in enumerate(services[:5], 1):

            lines.append(
                f"{i}. {s['service']} — "
                f"{s['packets']:,} packets, "
                f"{s['bytes_formatted']}"
            )

        return "\n".join(lines)


    # ==========================================================
    # SOURCE IPs
    # ==========================================================

    if tool == "top_source_ips":

        sources = result["sources"]

        if not sources:
            return "No source IP traffic was found."

        top = sources[0]

        lines = [
            "Top source IPs by traffic:\n",
            f"1. {top['ip']} — "
            f"{top['bytes_formatted']} "
            f"({top['packets']:,} packets)"
        ]

        for i, source in enumerate(sources[1:5], 2):

            lines.append(
                f"{i}. {source['ip']} — "
                f"{source['bytes_formatted']} "
                f"({source['packets']:,} packets)"
            )

        return "\n".join(lines)


    # ==========================================================
    # DESTINATION IPs
    # ==========================================================

    if tool == "top_destination_ips":

        destinations = result["destinations"]

        if not destinations:
            return "No destination IP traffic was found."

        lines = ["Top destination IPs by traffic:\n"]

        for i, destination in enumerate(
            destinations[:5], 1
        ):

            lines.append(
                f"{i}. {destination['ip']} — "
                f"{destination['bytes_formatted']} "
                f"({destination['packets']:,} packets)"
            )

        return "\n".join(lines)


    # ==========================================================
    # EXTERNAL DESTINATIONS
    # ==========================================================

    if tool == "external_destinations":

        destinations = result["destinations"]

        if not destinations:
            return "No external destinations were detected."

        lines = [
            f"Found {result['count']} external destination(s):\n"
        ]

        for destination in destinations[:10]:

            lines.append(
                f"• {destination['ip']} — "
                f"{destination['bytes_formatted']} "
                f"({destination['packets']:,} packets)"
            )

        return "\n".join(lines)


    # ==========================================================
    # ANOMALIES
    # ==========================================================

    if tool == "anomalies":

        anomalies = result["anomalies"]

        if not anomalies:
            return "No significant anomalies were detected."

        lines = ["Observed anomalies:\n"]

        for anomaly in anomalies:

            lines.append(
                f"• {anomaly['text']}"
            )

        return "\n".join(lines)


    # ==========================================================
    # LARGE PACKETS
    # ==========================================================

    if tool == "large_packets":

        return (
            f"Large-packet analysis:\n\n"
            f"• 95th percentile threshold: "
            f"{result['threshold_formatted']}\n"
            f"• Packets above threshold: "
            f"{result['count']:,}"
        )


    # ==========================================================
    # TIME
    # ==========================================================

    if tool == "time_analysis":

        if result["count"] == 0:
            return "No valid timestamps were available."

        return (
            f"Traffic timing analysis:\n\n"
            f"• Busiest timestamp: "
            f"{result['busiest_timestamp']}\n"
            f"• Packets at that timestamp: "
            f"{result['busiest_packets']:,}\n"
            f"• Traffic volume: "
            f"{format_bytes(result['busiest_bytes'])}"
        )


    return "I couldn't determine the requested analysis."

PACKETLOOK_TOOL = types.Tool(
    function_declarations=PACKETLOOK_TOOL_DECLARATIONS
)

def build_conversation_context():
    """
    Convert PacketLook's stored chat history into a compact
    conversation context for Gemini.
    """

    history = []


    recent_messages = st.session_state.messages[-12:] #don't sent all history

    for message in recent_messages:

        if message.get("system_message"):
            continue

        role = message.get("role")
        content = message.get("content", "")

        if not content:
            continue

        if role == "user":
            history.append(
                types.Content(
                    role="user",
                    parts=[
                        types.Part.from_text(
                            text=content
                        )
                    ]
                )
            )

        elif role == "agent":
            history.append(
                types.Content(
                    role="model",
                    parts=[
                        types.Part.from_text(
                            text=content
                        )
                    ]
                )
            )

    return history

def run_packetlook_agent(user_query, df):

    contents = build_conversation_context()
    # ---------------------------------------------------------
    # First Gemini request
    # ---------------------------------------------------------

    response = gemini_client.models.generate_content(
        model=GEMINI_MODEL,
        contents=contents,
        config=types.GenerateContentConfig(
            system_instruction=PACKETLOOK_SYSTEM_INSTRUCTION,
            tools=[PACKETLOOK_TOOL],
            temperature=0.2
        )
    )

    # ---------------------------------------------------------
    # Tool-calling loop
    # ---------------------------------------------------------

    max_iterations = 8

    for _ in range(max_iterations):

        function_calls = []

        for candidate in response.candidates:

            for part in candidate.content.parts:

                if part.function_call:
                    function_calls.append(
                        part.function_call
                    )

        # -----------------------------------------------------
        # No tool call = final answer
        # -----------------------------------------------------

        if not function_calls:

            return response.text


        # -----------------------------------------------------
        # Add Gemini's response to conversation
        # -----------------------------------------------------

        contents.append(
            response.candidates[0].content
        )


        # -----------------------------------------------------
        # Execute every requested tool
        # -----------------------------------------------------

        tool_response_parts = []

        for function_call in function_calls:

            tool_name = function_call.name

            arguments = dict(
                function_call.args or {}
            )

            # Save for debugging/UI if needed
            st.session_state.last_tool = tool_name

            # Execute your local Python tool
            result = execute_gemini_tool(
                tool_name,
                arguments,
                df
            )

            # Save latest result
            st.session_state.last_tool_result = result

            # Send result back to Gemini
            tool_response_parts.append(
                types.Part.from_function_response(
                    name=tool_name,
                    response=result
                )
            )


        contents.append(
            types.Content(
                role="user",
                parts=tool_response_parts
            )
        )


        # -----------------------------------------------------
        # Ask Gemini to continue
        # -----------------------------------------------------

        response = gemini_client.models.generate_content(
            model=GEMINI_MODEL,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=PACKETLOOK_SYSTEM_INSTRUCTION,
                tools=[PACKETLOOK_TOOL],
                temperature=0.2
            )
        )


    return (
        "I couldn't complete the analysis within the "
        "allowed number of reasoning steps."
    )

def send_message(text: str):
    if not text.strip():
        return
    st.session_state.messages.append(
        {"role": "user", "content": text, "timestamp": datetime.now().strftime("%H:%M:%S")}
    )
    st.session_state.pending_user_msg = text
    st.session_state.app_state = "processing"

def make_json_safe(value):
    """
    Convert Pandas/Python values into JSON-serializable values.
    """

    if pd.isna(value):
        return None

    if isinstance(value, (pd.Timestamp, datetime)):
        return value.isoformat()

    if isinstance(value, time):
        return value.isoformat()

    if isinstance(value, np.integer):
        return int(value)

    if isinstance(value, np.floating):
        return float(value)

    if isinstance(value, np.bool_):
        return bool(value)

    return value

def dataframe_to_json_safe(df):
    """
    Convert a DataFrame into JSON-safe dictionaries.
    """

    records = df.to_dict(orient="records")

    return [
        {
            key: make_json_safe(value)
            for key, value in record.items()
        }
        for record in records
    ]

# --------------------------------------------------------------------------
# THEME / CSS  (mirrors index.css — offset shadows, hard borders, mono type)
# --------------------------------------------------------------------------
dark = st.session_state.dark

BG = "#111110" if dark else "#E8E8E3"
SURFACE = "#1A1A18" if dark else "#F2F2EE"
INK = "#E8E8E3" if dark else "#080808"
BORDER = "#333330" if dark else "#080808"
MUTED = "#8a8a85" if dark else "#777777"
YELLOW = "#FFD21A"
SUCCESS = "#38D66B"
ERROR = "#ff4444"

CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800;900&display=swap');

html, body, [class*="css"] {{
    font-family: 'Inter', sans-serif;
}}
.stApp {{
    background-color: {BG};
    background-image:
        linear-gradient(rgba(8,8,8,0.06) 1px, transparent 1px),
        linear-gradient(90deg, rgba(8,8,8,0.06) 1px, transparent 1px);
    background-size: 24px 24px;
    color: {INK};
}}
#MainMenu, footer, header {{visibility: hidden;}}
.block-container {{
    padding-top: 92px !important;
    padding-bottom: 110px !important;
    max-width: 1400px;
}}

/* =========================================================
   FIXED NAVIGATION HEADER
   ========================================================= */

.st-key-fixed_topbar {{
    position: fixed !important;
    top: 12px;
    left: 50%;
    transform: translateX(-50%);
    width: min(1400px, calc(100vw - 32px));
    z-index: 9999;

    background: {BG};
    padding: 0;
}}

/* Keep the Streamlit column row transparent */
.st-key-fixed_topbar [data-testid="stHorizontalBlock"] {{
    background: transparent !important;
}}

/* Top navigation bar */
.st-key-fixed_topbar .da-topbar {{
    margin-bottom: 0;
}}

/* Navigation buttons */
.st-key-fixed_topbar div.stButton > button {{
    height: 44px !important;
}}

.mono {{ font-family: 'JetBrains Mono', monospace; }}

.da-topbar {{
    display: flex; align-items: center; gap: 18px;
    background: {SURFACE}; border: 2px solid {BORDER};
    padding: 8px 16px; margin-bottom: 18px;
}}
.da-logo {{
    width: 28px; height: 28px; background: {YELLOW}; border: 2px solid #080808;
    display: flex; align-items: center; justify-content: center; flex-shrink: 0;
}}
.da-title {{
    font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 13px;
    letter-spacing: 0.08em; color: {INK};
}}
.da-status-dot {{
    width: 7px; height: 7px; background: {SUCCESS}; border: 1px solid {INK};
    border-radius: 50%; display: inline-block; margin-right: 6px;
}}
.da-status-text {{
    font-family: 'JetBrains Mono', monospace; font-size: 10px; color: {MUTED};
    letter-spacing: 0.06em;
}}

.da-h1 {{
    font-family: 'Inter', sans-serif; font-weight: 900; font-size: 28px;
    color: {INK}; margin: 0; line-height: 1.1;
}}
.da-eyebrow {{
    font-family: 'JetBrains Mono', monospace; font-size: 10px; color: {MUTED};
    letter-spacing: 0.1em; margin-bottom: 4px;
}}
.da-sub {{
    font-family: 'JetBrains Mono', monospace; font-size: 13px; color: {MUTED};
    margin: 6px 0 16px; max-width: 480px;
}}

.da-card {{
    border: 2px solid {BORDER}; background: {SURFACE}; padding: 20px;
    box-shadow: 4px 4px 0px {BORDER};
}}
.da-card-lg {{
    border: 3px solid {BORDER}; background: {SURFACE}; padding: 32px 24px;
    box-shadow: 6px 6px 0px {BORDER};
}}

.da-tag {{
    font-family: 'JetBrains Mono', monospace; font-size: 10px;
    border: 2px solid {BORDER}; padding: 4px 10px; background: {BG};
    color: {INK}; display: inline-block; margin: 3px 4px 0 0;
}}

.da-chip {{
    font-family: 'JetBrains Mono', monospace; font-size: 9px;
    border: 1px solid {BORDER}; padding: 2px 8px; background: {BG}; color: {MUTED};
    display: inline-block;
}}

.da-msg-meta {{
    font-family: 'JetBrains Mono', monospace; font-size: 9px; color: {MUTED};
    letter-spacing: 0.08em; margin-bottom: 4px;
}}
.da-bubble-user {{
    border: 2px solid {BORDER}; padding: 12px 16px; background: {INK};
    color: {BG}; font-family: 'Inter', sans-serif; font-size: 14px;
    line-height: 1.7; white-space: pre-wrap; display: inline-block; max-width: 640px;
}}
.da-bubble-agent {{
    border: 2px solid {BORDER}; padding: 12px 16px; background: {SURFACE};
    color: {INK}; font-family: 'JetBrains Mono', monospace; font-size: 12px;
    line-height: 1.7; white-space: pre-wrap; display: inline-block; max-width: 640px;
    box-shadow: 3px 3px 0px {BORDER};
}}

.da-stat {{
    border: 2px solid {BORDER}; padding: 8px 10px; background: {BG};
    display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;
}}
.da-stat-label {{ font-family: 'JetBrains Mono', monospace; font-size: 8px; color: {MUTED}; letter-spacing: 0.08em; }}
.da-stat-value {{ font-family: 'JetBrains Mono', monospace; font-size: 15px; font-weight: 700; color: {INK}; }}
.da-stat-delta {{
    font-family: 'JetBrains Mono', monospace; font-size: 9px; font-weight: 700;
    padding: 2px 6px; border: 1px solid;
}}

.da-bar-row {{ margin-bottom: 8px; }}
.da-bar-label {{ display: flex; justify-content: space-between; font-family: 'JetBrains Mono', monospace; font-size: 9px; color: {INK}; margin-bottom: 3px; }}
.da-bar-track {{ height: 8px; background: {BG}; border: 1px solid {BORDER}; }}
.da-bar-fill {{ height: 100%; background: {YELLOW}; border-right: 1px solid {BORDER}; }}

.da-list-item {{ display: flex; gap: 8px; margin-bottom: 6px; align-items: flex-start; }}
.da-dot {{ width: 8px; height: 8px; border: 1px solid {BORDER}; flex-shrink: 0; margin-top: 4px; }}
.da-list-text {{ font-family: 'JetBrains Mono', monospace; font-size: 10px; color: {INK}; line-height: 1.4; }}
.da-rec-text {{ font-family: 'Inter', sans-serif; font-size: 11px; color: {INK}; line-height: 1.5; }}
.da-rec-num {{ font-family: 'JetBrains Mono', monospace; font-size: 10px; color: {MUTED}; }}

.da-panel-header {{
    padding: 10px 16px; border: 2px solid {BORDER}; background: {INK};
    margin-bottom: 12px;
}}
.da-panel-header span {{
    font-family: 'JetBrains Mono', monospace; font-size: 10px; color: {SURFACE};
    letter-spacing: 0.12em; font-weight: 700;
}}
.da-section-label {{
    font-family: 'JetBrains Mono', monospace; font-size: 9px; color: {MUTED};
    letter-spacing: 0.1em; margin: 14px 0 8px;
}}

.da-filebar {{
    border: 2px solid {BORDER}; padding: 14px 18px; background: {SURFACE};
    margin-bottom: 16px; display: flex; align-items: center; gap: 12px;
    box-shadow: 4px 4px 0px {BORDER};
}}
.da-check {{
    width: 36px; height: 36px; background: {SUCCESS}; border: 2px solid {BORDER};
    display: flex; align-items: center; justify-content: center; flex-shrink: 0;
    color: {BORDER}; font-weight: 900;
}}

/* Buttons */
div.stButton > button {{
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 700 !important;
    letter-spacing: 0.06em;
    border: 2px solid {BORDER} !important;
    background: {SURFACE} !important;
    color: {INK} !important;
    box-shadow: 3px 3px 0px {BORDER};
    border-radius: 0 !important;
    padding: 6px 14px !important;
}}

div.stButton > button:hover {{
    background: {YELLOW} !important;
    color: #080808 !important;
}}

.da-btn-primary button {{
    background: {YELLOW} !important;
    color: #080808 !important;
}}

@media (max-width: 768px) {{

    .st-key-fixed_topbar {{
        top: 8px;
        width: calc(100vw - 16px);
    }}

    .block-container {{
        padding-top: 82px !important;
        padding-bottom: 100px !important;
    }}

    [data-testid="stChatInput"] {{
        width: calc(100vw - 20px) !important;
        bottom: 10px !important;
    }}
}}

@media (max-width: 650px) {{

    .st-key-fixed_topbar {{
        top: 8px;
        width: calc(100vw - 16px);
    }}

    /* Header row */
    .st-key-fixed_topbar [data-testid="stHorizontalBlock"] {{
        display: flex !important;
        align-items: center !important;
    }}

    /* Logo / status section */
    .st-key-fixed_topbar [data-testid="stHorizontalBlock"]
    > [data-testid="stColumn"]:first-child {{
        flex: 1 !important;
        min-width: 0 !important;
    }}

    /* Right-side buttons container */
    .st-key-fixed_topbar [data-testid="stHorizontalBlock"]
    > [data-testid="stColumn"]:nth-child(2),
    .st-key-fixed_topbar [data-testid="stHorizontalBlock"]
    > [data-testid="stColumn"]:nth-child(3) {{
        flex: 0 0 44px !important;
        width: 44px !important;
        min-width: 44px !important;
    }}

    /* Square buttons */
    .st-key-fixed_topbar
    [data-testid="stColumn"]:nth-child(2) button, .st-key-fixed_topbar[data-testid="stColumn"]:nth-child(3) button {{
        width: 40px !important;
        height: 40px !important;

        min-width: 40px !important;
        max-width: 40px !important;

        padding: 0 !important;
        margin: 0 !important;

        border-radius: 0 !important;

        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
    }}

    /* New session text → compact icon-like label */
    .st-key-fixed_topbar
    [data-testid="stColumn"]:nth-child(2) button {{
        font-size: 0 !important;
    }}

    .st-key-fixed_topbar
    [data-testid="stColumn"]:nth-child(2) button::after {{
        content: "+";
        font-size: 24px !important;
        font-weight: 800 !important;
        line-height: 1 !important;
    }}

    /* Theme button */
    .st-key-fixed_topbar
    [data-testid="stColumn"]:nth-child(3) button {{
        font-size: 18px !important;
    }}
}}

/* =========================================================
   FILE UPLOADER
   ========================================================= */

[data-testid="stFileUploaderDropzone"] {{
    border: 3px solid {BORDER} !important;
    background: {SURFACE} !important;
    border-radius: 0 !important;
}}

/* Uploader text */
[data-testid="stFileUploaderDropzone"] span {{
    color: {INK} !important;
}}

[data-testid="stFileUploaderDropzone"] small {{
    color: {MUTED} !important;
}}

/* Browse button */
[data-testid="stFileUploaderDropzone"] button {{
    background: {SURFACE} !important;
    color: {INK} !important;
    border: 2px solid {BORDER} !important;
    border-radius: 0 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 700 !important;
    box-shadow: 3px 3px 0px {BORDER} !important;
    transition: none !important;
}}

[data-testid="stFileUploaderDropzone"] button * {{
    color: {INK} !important;
}}

/* Browse button hover */
[data-testid="stFileUploaderDropzone"] button:hover {{
    background: {YELLOW} !important;
    color: #080808 !important;
    border-color: {BORDER} !important;
    box-shadow: 3px 3px 0px {BORDER} !important;
    cursor: pointer !important;
}}

[data-testid="stFileUploaderDropzone"] button:hover * {{
    color: #080808 !important;
}}


/* =========================================================
   FIXED CHAT INPUT
   ========================================================= */

[data-testid="stChatInput"] {{
    position: fixed !important;
    bottom: 16px !important;
    left: 50% !important;
    transform: translateX(-50%) !important;
    width: min(1380px, calc(100vw - 40px)) !important;
    z-index: 9998 !important;
    background: #f2f1ec !important;
    border: 2px solid #080808 !important;
    box-shadow: 4px 4px 0px {BORDER} !important;
    border-radius: 0 !important;
}}

[data-testid="stChatInput"] textarea {{
    color: #080808 !important;
    background: #f2f1ec !important;
    caret-color: #080808 !important;
}}

[data-testid="stChatInput"] textarea::placeholder {{
    color: #6b6b6b !important;
    opacity: 1 !important;
}}

/* Chat input wrapper */
[data-testid="stChatInput"] > div {{
    background: #f2f1ec !important;
}}

/* Send button */
[data-testid="stChatInput"] button {{
    color: #080808 !important;
}}

hr {{ border-color: {BORDER}; }}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

# --------------------------------------------------------------------------
# TOP BAR
# --------------------------------------------------------------------------

with st.container(key="fixed_topbar"):

    top_l, top_r1, top_r2 = st.columns([6, 1, 1])

    with top_l:
        st.markdown(
            f"""<div class="da-topbar"><div class="da-logo"><svg width="14" height="14" viewBox="0 0 14 14" fill="none"><rect x="1" y="1" width="5" height="5" fill="#080808"/><rect x="8" y="1" width="5" height="5" fill="#080808"/><rect x="1" y="8" width="5" height="5" fill="#080808"/><rect x="8" y="8" width="5" height="5" fill="#FFD21A" stroke="#080808" stroke-width="1"/></svg></div><span class="da-title">PACKET_LOOK</span><span><span class="da-status-dot"></span><span class="da-status-text">ACTIVE</span></span></div>""", unsafe_allow_html=True,)

    with top_r1:
        if st.button(
            "[ NEW SESSION ]",
            use_container_width=True
        ):
            reset_session()
            st.rerun()

    with top_r2:
        label = "🌙" if dark else "☀"

        if st.button(
            label,
            use_container_width=True
        ):
            st.session_state.dark = not dark
            st.rerun()

# --------------------------------------------------------------------------
# WORKSPACE HEADER
# --------------------------------------------------------------------------
st.markdown('<div class="da-eyebrow">AI_AGENT // NETWORK TRAFFIC ANALYSIS</div>', unsafe_allow_html=True)
st.markdown('<div class="da-h1">Analyze your data.</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="da-sub">Upload your network traffic logs and let PacketLook analyze, investigate, and explain what happened.</div>',
    unsafe_allow_html=True,
)

# --------------------------------------------------------------------------
# LAYOUT: main + optional right analysis panel
# --------------------------------------------------------------------------
if st.session_state.show_results:
    main_col, right_col = st.columns([3, 1], gap="large")
else:
    main_col = st.container()
    right_col = None

# ==========================================================================
# EMPTY STATE
# ==========================================================================
with main_col:
    if st.session_state.app_state == "empty":
        st.markdown('<div class="da-eyebrow">DATA_STREAM // INPUT_MODULE</div>', unsafe_allow_html=True)
        uploaded = st.file_uploader("DROP NETWORK CSV HERE", type=["csv"], accept_multiple_files=False, label_visibility="collapsed")
        if uploaded is not None:
            try:
                handle_upload(uploaded)
                st.rerun()
            except Exception as e:
                st.error(f"Could not process CSV: {e}")

        st.markdown('<div class="mono" style="font-size:10px;color:#777;margin:6px 0 20px;">.CSV files only</div>', unsafe_allow_html=True)

        st.markdown(
            f"""
            <div class="da-card">
                <div class="da-eyebrow">NO DATASET CONNECTED</div>
                <div style="font-family:'Inter',sans-serif;font-size:13px;color:{MUTED};margin-bottom:16px;">
                    Upload a CSV file to start an analysis.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ======================================================================
    # UPLOADED STATE
    # ======================================================================
    elif st.session_state.app_state == "uploaded":
        fname = st.session_state.uploaded_name or "network_data.csv"
        df = st.session_state.df

        row_count = len(df)
        column_count = len(df.columns)
        c1, c2 = st.columns([5, 1])
        with c1:
            st.markdown(
                f"""
                <div class="da-filebar">
                    <div class="da-check">✓</div>
                    <div>
                        <div class="mono" style="font-size:12px;font-weight:700;color:{INK};">{fname}</div>
                        <div class="mono" style="font-size:10px;color:{MUTED};">{row_count:,} rows · {column_count} columns</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with c2:
            if st.button("[ REMOVE ]", use_container_width=True):
                reset_session()
                st.rerun()

        st.markdown(
            f"""
            <div class="da-card-lg">
                <div class="da-eyebrow">DATASET_READY // START_ANALYSIS</div>
                <div style="font-family:'Inter',sans-serif;font-weight:800;font-size:18px;color:{INK};margin-bottom:6px;">
                    Dataset loaded successfully.
                </div>
                <div style="font-family:'Inter',sans-serif;font-size:13px;color:{MUTED};margin-bottom:16px;">
                    The agent has indexed your data. Start asking questions or run an analysis below.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.write("")
        if st.button("[ START_ANALYSIS ]", use_container_width=False):
            start_chat()
            st.rerun()

    # ======================================================================
    # CHAT / PROCESSING STATE
    # ======================================================================
    else:
        fname = st.session_state.uploaded_name or "network_data.csv"
        st.markdown(
            f"""
            <div style="display:flex;align-items:center;gap:10px;padding:8px 4px;
                        border-bottom:2px solid {BORDER};margin-bottom:14px;">
                <span class="mono" style="font-size:10px;color:{MUTED};letter-spacing:0.08em;">
                    NETWORK_INVESTIGATION // ACTIVE
                </span>
                <div style="flex:1;"></div>
                <span class="da-chip"><span class="da-status-dot"></span>{fname}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        for msg in st.session_state.messages:
            is_user = msg["role"] == "user"
            align = "flex-end" if is_user else "flex-start"
            text_align = "right" if is_user else "left"
            bubble_class = "da-bubble-user" if is_user else "da-bubble-agent"
            role_label = "USER" if is_user else "PACKET_LOOK"
            st.markdown(
                f"""
                <div style="display:flex;justify-content:{align};margin-bottom:14px;">
                    <div>
                        <div class="da-msg-meta" style="text-align:{text_align};">
                            {role_label} · {msg['timestamp']}
                        </div>
                        <div class="{bubble_class}">{msg['content']}</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        if st.session_state.app_state == "processing":
            st.markdown(
                f"""
                <div style="display:flex;justify-content:flex-start;margin-bottom:14px;">
                    <div class="mono" style="border:2px solid {BORDER};padding:12px 16px;
                        background:{YELLOW};color:#080808;font-size:11px;font-weight:600;
                        letter-spacing:0.06em;box-shadow:3px 3px 0px {BORDER};">
                        ● ● ● AGENT_PROCESSING // ANALYZING_DATA...
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # status bar
        status_val = "PROCESSING" if st.session_state.app_state == "processing" else "READY"
        status_color = YELLOW if st.session_state.app_state == "processing" else INK
        st.markdown(
            f"""
            <div style="display:flex;gap:20px;padding:6px 4px;border-top:1px solid rgba(8,8,8,0.2);margin-top:6px;">
                <span class="mono" style="font-size:9px;color:{MUTED};">MODEL: <b style="color:{INK};">DATA_ANALYST</b></span>
                <span class="mono" style="font-size:9px;color:{MUTED};">TOOLS: <b style="color:{INK};">CSV / PYTHON / SQL</b></span>
                <span class="mono" style="font-size:9px;color:{MUTED};">STATUS: <b style="color:{status_color};">{status_val}</b></span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # If we're in "processing" state, generate the canned agent reply now.
        if (
            st.session_state.app_state == "processing"
            and st.session_state.pending_user_msg is not None
        ):

            user_query = st.session_state.pending_user_msg

            with st.spinner("Agent is analyzing your data..."):

                df = st.session_state.df

                if df is None:

                    response = (
                        "No network dataset is currently loaded. "
                        "Please upload a CSV file first."
                    )

                else:

                    try:

                        response = run_packetlook_agent(
                            user_query,
                            df
                        )

                    except Exception as e:

                        response = (
                            "I encountered an error while analyzing "
                            f"the dataset: {str(e)}"
                        )



            st.session_state.messages.append(
                {
                    "role": "agent",
                    "content": response,
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                }
            )

            st.session_state.pending_user_msg = None
            st.session_state.app_state = "chat"

            st.rerun()

        user_text = st.chat_input("Ask PacketLook about your network traffic...")
        if user_text:
            send_message(user_text)
            st.rerun()

# ==========================================================================
# RIGHT PANEL — ANALYSIS OUTPUT
# ==========================================================================
if right_col is not None:

    with right_col:

        # =====================================================
        # HEADER
        # =====================================================
        st.markdown('<div class="da-panel-header"><span>NETWORK_INSIGHTS</span></div>', unsafe_allow_html=True)

        # =====================================================
        # STATISTICS
        # =====================================================

        st.markdown('<div class="da-section-label" style="margin-top:0;">STATISTICS</div>', unsafe_allow_html=True)

        for s in st.session_state.stat_cards:
            st.markdown(f"""<div class="da-stat"><div><div class="da-stat-label">{s['label']}</div><div class="da-stat-value">{s['value']}</div></div></div>""", unsafe_allow_html=True)

        # =====================================================
        # TRAFFIC PROFILE
        # =====================================================

        st.markdown(
            '<div class="da-section-label">TRAFFIC_PROFILE</div>', unsafe_allow_html=True)

        for item in st.session_state.traffic_profile:
            pct = min(float(item["pct"]), 100)

            st.markdown(f"""<div class="da-bar-row"><div class="da-bar-label"><span>{item['label']}</span><span style="color:{MUTED};">{pct:.1f}%</span></div><div class="da-bar-track"><div class="da-bar-fill" style="width:{pct}%;"></div></div></div> """, unsafe_allow_html=True)

        # =====================================================
        # ANOMALIES
        # =====================================================

        st.markdown(
            '<div class="da-section-label">ANOMALIES</div>', unsafe_allow_html=True)

        if st.session_state.anomalies:
            for anomaly in st.session_state.anomalies:
                dot_color = (ERROR if anomaly["severity"] == "error" else YELLOW)
                st.markdown(f"""<div class="da-list-item"><div class="da-dot" style="background:{dot_color};"></div><span class="da-list-text">{anomaly['text']}</span></div>""", unsafe_allow_html=True)

        else:

            st.markdown(f"""<div class="da-list-item"><div class="da-dot" style="background:{SUCCESS};"></div><span class="da-list-text">No significant anomalies detected</span></div>""", unsafe_allow_html=True)


        # =====================================================
        # RECOMMENDATIONS
        # =====================================================

        st.markdown('<div class="da-section-label">RECOMMENDATIONS</div>', unsafe_allow_html=True)

        for i, recommendation in enumerate(st.session_state.recommendations):
            st.markdown(f"""<div class="da-list-item"><span class="da-rec-num">{i + 1:02d}.</span><span class="da-rec-text">{recommendation}</span></div>""", unsafe_allow_html=True)