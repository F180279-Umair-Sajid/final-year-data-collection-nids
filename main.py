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
    table = "nids"
    iface = "Wi-Fi"
    interval = 15
    database = Database(database, user, password, host, port)

    table_name = "nids"
    fields = ["id SERIAL PRIMARY KEY", "timestamp TIMESTAMP DEFAULT NOW()", "src_mac VARCHAR(17)",
              "dst_mac VARCHAR(17)", "src_ip VARCHAR(15)", "dst_ip VARCHAR(15)", "protocol VARCHAR(5)", "port INT",
              "packet_size INT"]
    database.create_table(table_name, fields)

    capture_thread = threading.Thread(target=sniff_and_store_wifi_postgres,
                                      args=(database, iface, rules))
    delete_thread = threading.Thread(target=database.delete_old_records_thread,
                                     args=(table, interval))
    capture_thread.start()
    delete_thread.start()

    # Wait for the threads to finish
    capture_thread.join()
    delete_thread.join()
