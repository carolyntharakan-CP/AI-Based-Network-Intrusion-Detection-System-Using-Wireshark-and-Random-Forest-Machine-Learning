# AI-Based-Network-Intrusion-Detection-System-Using-Wireshark-and-Random-Forest-Machine-Learning
# Project Overview
The project focuses on developing an intelligent Network Intrusion Detection System (NIDS) that monitors network traffic and identifies potential cybersecurity threats using machine learning. It combines live network packet capture through Wireshark/TShark with a Random Forest classification model trained using the CICIDS2017 dataset.

The system captures network packets, extracts relevant traffic features, and analyzes them using the trained model to classify network activity as normal or potentially malicious. A Streamlit-based dashboard displays traffic information, detected attack categories, risk levels, and alert logs, making network monitoring easier to understand.

# Aim
To design and develop an AI-based Network Intrusion Detection System that monitors live network traffic, identifies potential network attacks using machine learning, and presents detection results through an interactive dashboard.

# Working Principle
- Dataset Collection: The CICIDS2017 dataset is used to obtain labelled network traffic data containing both normal and attack traffic.

- Model Training: The dataset is processed and used to train a Random Forest machine learning model to distinguish between normal and malicious network activities.

- Live Packet Capture: Wireshark/TShark captures network packets from the selected network interface in real time.

- Feature Extraction: The captured traffic is processed to extract important network characteristics, such as source IP, destination IP, destination port, packet length, and traffic statistics.

- Attack Classification: The extracted features are provided to the trained Random Forest model, which predicts the traffic category.

- Risk Assessment: The system assigns a risk level based on the predicted attack category.

- Dashboard and Alert Logging: The results are displayed through a Streamlit dashboard, where users can monitor network activity, view detected threats, and access recorded alerts.

# Technologies
Python • Wireshark • TShark • CICIDS2017 • Random Forest • Pandas • NumPy • Scikit-learn • Joblib • Streamlit • Plotly • Requests

# Outcome
The project demonstrates how machine learning can be integrated with network packet analysis to improve network security monitoring. By combining live traffic capture, automated classification, and dashboard-based visualization, it provides a practical approach to identifying potentially suspicious network activities.
