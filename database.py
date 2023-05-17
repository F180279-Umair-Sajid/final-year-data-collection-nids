import psycopg2
import time


class Database:
    def __init__(self, database, user, password, host, port):
        self.conn = psycopg2.connect(database=database, user=user, password=password, host=host, port=port)
        self.cur = self.conn.cursor()

    def create_table(self, table_name, fields):
        self.cur.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({','.join(fields)});")
        self.conn.commit()

    # def create_unique_constraint(self, table_name, column_name):
    #     self.cur.execute(f"ALTER TABLE {table_name} ADD CONSTRAINT unique_{column_name} UNIQUE({column_name});")
    #     self.conn.commit()

    def insert_ip_malicious(self, ip, is_malicious, country, country_code):
        self.cur.execute(
            """
            INSERT INTO ip_malicious (ip_address, is_malicious, country, country_code) 
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (ip_address) DO NOTHING
            """,
            [ip, is_malicious, country, country_code]
        )
        self.conn.commit()

    def insert_record(self, table_name, fields, values):
        placeholders = ','.join(['%s'] * len(values))
        query = f"INSERT INTO {table_name} ({','.join(fields)}) VALUES ({placeholders})"
        self.cur.execute(query, values)
        self.conn.commit()

    def delete_old_records(self, table_name, interval):
        try:
            self.cur.execute(f"DELETE FROM {table_name} WHERE timestamp < now() - interval '{interval} seconds';")
            self.conn.commit()
        except Exception as e:
            print(f"An error occurred: {e}")
            self.conn.rollback()


# Usage:
db = Database("radar_security", "postgres", "12345678", "127.0.0.1", "5432")
# db.create_unique_constraint("ip_malicious", "ip_address")
