import psycopg2
import time

class Database:
    def __init__(self, database, user, password, host, port):
        self.conn = psycopg2.connect(database=database, user=user, password=password, host=host, port=port)
        self.cur = self.conn.cursor()

    def create_table(self, table_name, fields):
        self.cur.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({','.join(fields)});")
        self.conn.commit()

    def insert_record(self, table_name, fields, values):
        placeholders = ','.join(['%s'] * len(fields))
        query = f"INSERT INTO {table_name} ({','.join(fields)}) VALUES ({placeholders})"
        self.cur.execute(query, values)
        self.conn.commit()

    def delete_old_records(self, table_name, interval):
        self.cur.execute(f"DELETE FROM {table_name} WHERE timestamp < now() - interval '{interval} seconds';")
        self.conn.commit()

    def delete_old_records_thread(self, table_name, interval):
        while True:
            self.delete_old_records(table_name, interval)
            time.sleep(interval)
