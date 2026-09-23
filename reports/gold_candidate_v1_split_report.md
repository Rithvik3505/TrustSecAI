# Gold-Candidate v1 Split Report

Splits are grouped by `base_context_id`.

## train

- Examples: 588
- Base contexts: 84
- IDS labels: {'Bot': 119, 'PortScan': 119, 'FTP-Patator': 133, 'Web Attack - Sql Injection': 84, 'DDoS': 133}
- Confidence bands: {'high': 532, 'medium': 42, 'low': 14}
- Source files: {'Friday-WorkingHours-Morning.pcap_ISCX.csv': 119, 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 119, 'Tuesday-WorkingHours.pcap_ISCX.csv': 133, 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 84, 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 133}

## validation

- Examples: 126
- Base contexts: 18
- IDS labels: {'Bot': 14, 'Web Attack - Sql Injection': 35, 'FTP-Patator': 28, 'PortScan': 28, 'DDoS': 21}
- Confidence bands: {'medium': 7, 'high': 119}
- Source files: {'Friday-WorkingHours-Morning.pcap_ISCX.csv': 14, 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 35, 'Tuesday-WorkingHours.pcap_ISCX.csv': 28, 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 28, 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 21}

## test

- Examples: 133
- Base contexts: 19
- IDS labels: {'Web Attack - Sql Injection': 28, 'Bot': 42, 'FTP-Patator': 14, 'PortScan': 28, 'DDoS': 21}
- Confidence bands: {'high': 126, 'medium': 7}
- Source files: {'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 28, 'Friday-WorkingHours-Morning.pcap_ISCX.csv': 42, 'Tuesday-WorkingHours.pcap_ISCX.csv': 14, 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 28, 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 21}

## Leakage Check

- {'train_validation': [], 'train_test': [], 'validation_test': []}
