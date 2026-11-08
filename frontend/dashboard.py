import streamlit as st
import pandas as pd
import plotly.express as px
import time
import os

# Set page configuration with Dark layout
st.set_page_config(
    page_title="AI IDS Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Dark Theme, Crisp White Typography, and Modern SOC Styling
st.markdown("""
    <style>
        /* Base page background and typography */
        .stApp {
            background-color: #090D16;
            color: #FFFFFF !important;
        }
        
        /* Force all body text, headings, and labels to bright white */
        p, span, label, h1, h2, h3, h4, h5, h6, .stMarkdown {
            color: #FFFFFF !important;
        }
        
        /* Sidebar styling */
        [data-testid="stSidebar"] {
            background-color: #0F172A;
            border-right: 1px solid #1E293B;
        }

        /* Modernized Metric Card styling */
        div[data-testid="stMetric"] {
            background: linear-gradient(135deg, #1E293B 0%, #0F172A 100%);
            border: 1px solid #334155;
            padding: 18px;
            border-radius: 12px;
            box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.4);
            text-align: center;
        }

        div[data-testid="stMetricLabel"] > label {
            color: #94A3B8 !important;
            font-size: 0.85rem !important;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        div[data-testid="stMetricValue"] > div {
            color: #38BDF8 !important;
            font-size: 2rem !important;
            font-weight: 800;
        }

        /* Customized Streamlit Dataframe container */
        [data-testid="stDataFrame"] {
            background-color: #0F172A;
            border-radius: 10px;
            border: 1px solid #1E293B;
            padding: 5px;
        }

        /* Divider styling */
        hr {
            border-color: #1E293B !important;
            margin: 2rem 0;
        }
    </style>
""", unsafe_allow_html=True)

# Dashboard Header
st.title("🛡️ AI-Based Network Intrusion Detection System")
st.caption("⚡ Live Security Operations & Network Threat Intelligence")

ALERT_FILE = "alerts.csv"

# Sidebar controls
with st.sidebar:
    st.header("⚙️ System Status")
    st.success("● Monitoring Engine Active")
    refresh_rate = st.slider("Refresh Interval (seconds)", min_value=1, max_value=15, value=5)
    st.markdown("---")
    st.caption("Threat Intelligence Engine v2.4")

placeholder = st.empty()

while True:
    with placeholder.container():

        if not os.path.exists(ALERT_FILE):
            st.warning("Waiting for telemetry source (`alerts.csv`)...")
            time.sleep(refresh_rate)
            st.rerun()

        try:
            df = pd.read_csv(ALERT_FILE)
        except Exception:
            st.error("Unable to read `alerts.csv` feed stream.")
            time.sleep(refresh_rate)
            st.rerun()

        if len(df) == 0:
            st.warning("No traffic packets captured yet.")
            time.sleep(refresh_rate)
            st.rerun()

        # ======================
        # TOP METRICS
        # ======================
        total_records = len(df)
        total_attacks = len(df[df["Attack Type"] != "Normal"])
        normal_count = len(df[df["Attack Type"] == "Normal"])
        high_risk = len(df[(df["Risk Level"] == "High") | (df["Risk Level"] == "Critical")])

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Traffic Captured", f"{total_records:,}")
        c2.metric("Detected Attacks", f"{total_attacks:,}")
        c3.metric("Normal Traffic", f"{normal_count:,}")
        c4.metric("High/Critical Risk", f"{high_risk:,}")

        st.divider()

        # ======================
        # LIVE TABLE
        # ======================
        st.subheader("📡 Live Traffic Telemetry Feed")
        st.dataframe(
            df.tail(20),
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        # Global Layout configuration for dark mode Plotly charts
        chart_layout = dict(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#FFFFFF", family="Inter, sans-serif"),
            margin=dict(l=20, r=20, t=30, b=20)
        )

        # ======================
        # ATTACK & RISK CHARTS
        # ======================
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📊 Attack Distribution")
            attack_chart = df["Attack Type"].value_counts().reset_index()
            attack_chart.columns = ["Attack", "Count"]

            fig = px.pie(
                attack_chart,
                names="Attack",
                values="Count",
                hole=0.55,
                template="plotly_dark",
                color_discrete_sequence=["#38BDF8", "#F43F5E", "#F59E0B", "#A855F7", "#10B981"]
            )
            fig.update_layout(**chart_layout)
            fig.update_traces(textposition='outside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("⚠️ Risk Level Breakdown")
            risk_chart = df["Risk Level"].value_counts().reset_index()
            risk_chart.columns = ["Risk", "Count"]

            fig2 = px.bar(
                risk_chart,
                x="Risk",
                y="Count",
                color="Risk",
                template="plotly_dark",
                color_discrete_map={
                    "Low": "#10B981",
                    "Medium": "#F59E0B",
                    "High": "#EF4444",
                    "Critical": "#8B5CF6"
                }
            )
            fig2.update_layout(showlegend=False, **chart_layout)
            fig2.update_xaxes(title_text="", showgrid=False)
            fig2.update_yaxes(title_text="Count", showgrid=True, gridcolor="#1E293B")
            st.plotly_chart(fig2, use_container_width=True)

        st.divider()

        # ======================
        # COUNTRY STATS & TOP IPS
        # ======================
        col3, col4 = st.columns(2)

        with col3:
            st.subheader("🌍 Traffic Origin (Top 10 Countries)")
            country_chart = df["Country"].value_counts().head(10).reset_index()
            country_chart.columns = ["Country", "Count"]

            fig3 = px.bar(
                country_chart,
                x="Count",
                y="Country",
                orientation="h",
                template="plotly_dark",
                color="Count",
                color_continuous_scale="Electric"
            )
            fig3.update_layout(**chart_layout)
            fig3.update_yaxes(autorange="reversed", title_text="", showgrid=False)
            fig3.update_xaxes(title_text="Packet Volume", showgrid=True, gridcolor="#1E293B")
            st.plotly_chart(fig3, use_container_width=True)

        with col4:
            st.subheader("🔥 Top Active Source IPs")
            top_ips = df["Source IP"].value_counts().head(10).reset_index()
            top_ips.columns = ["IP Address", "Packets Sent"]

            st.dataframe(
                top_ips,
                use_container_width=True,
                hide_index=True
            )

    time.sleep(refresh_rate)
    st.rerun()