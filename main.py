import threading

from sniffer import sniff_and_store_wifi_postgres
from database import Database

from rules import rules

if __name__ == '__main__':
    # Set the configuration parameters
    database = "radar_security"
    user = "postgres"
    password = "12345678"
    host = "127.0.0.1"
    port = "5432"
    table_nids = "nids"
    table_alerts = "alerts"
    iface = "Wi-Fi"
    interval = 15

    db = Database(database, user, password, host, port)

    fields_nids = [
        "id SERIAL PRIMARY KEY",
        "flow_id VARCHAR(50)",
        "timestamp TIMESTAMP DEFAULT NOW()",
        "flow_duration FLOAT",
        "flow_iat_mean FLOAT",
        "fwd_iat_tot FLOAT",
        "subflow_fwd_pkts INT",
        "subflow_fwd_bytes INT",
        "fwd_act_data_pkts INT",
        "fwd_seg_size_min INT",
        "bwd_pkts_count INT",
        "bwd_bytes_per_avg FLOAT",
        "bwd_payload_count INT",
        "bwd_payload_bytes_per_avg FLOAT",
        "bwd_blk_rate_avg FLOAT",
        "bwd_pkts_per_avg FLOAT"
    ]

    fields_alerts = [
        "id SERIAL PRIMARY KEY",
        "timestamp TIMESTAMP DEFAULT NOW()",
        "alert_name TEXT NOT NULL",
        "alert_description TEXT NOT NULL",
        "src_ip TEXT NOT NULL",
        "dst_ip TEXT NOT NULL",
        "src_port INT",
        "dst_port INT"
    ]

    db.create_table(table_nids, fields_nids)
    db.create_table(table_alerts, fields_alerts)

    capture_thread = threading.Thread(target=sniff_and_store_wifi_postgres, args=(db, iface, rules))
    delete_thread_nids = threading.Thread(target=db.delete_old_records, args=(table_nids, interval))

    capture_thread.start()
    delete_thread_nids.start()

    # Wait for the threads to finish
    capture_thread.join()
    delete_thread_nids.join()
