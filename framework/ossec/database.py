import common
from exception import OSSECAPIException
from os.path import isfile
import sqlite3
from pymongo import MongoClient

class Connection:
    """
    Represents a connection against a database
    """

    def __init__(self, db_path=common.database_path, collection, busy_sleep=0.001, max_attempts=1000):
        """
        Constructor
        """
        self.db_path = db_path
        self.collection = collection

        self.max_attempts = max_attempts

        self.__conn = MongoClient(self.db_path)[self.collection]

    def __iter__(self):
        """
        Iterating support
        """
        return self.__cur.__iter__()

    def begin(self):
        """
        Begin transaction
        """
        self.__cur.execute('BEGIN')

    def commit(self):
        """
        Commit changes
        """
        self.__conn.commit()

    def execute(self, query, *args):
        """
        Execute query
        :param query: Query string.
        :param args: Query values.
        """
        n_attempts = 0
        while n_attempts <= self.max_attempts:
            try:
                if args:
                    self.__cur.execute(query, *args)
                else:
                    self.__cur.execute(query)

                break

            except sqlite3.OperationalError as e:
                error_text = str(e)
                if error_text == 'database is locked':
                    n_attempts += 1
                else:
                    raise OSSECAPIException(2003, error_text)

            except Exception as e:
                raise OSSECAPIException (2003, str(e))

            if n_attempts > self.max_attempts:
                raise OSSECAPIException(2002, error_text)

    def fetch(self):
        """
        Return next tuple
        """
        return self.__cur.fetchone()

    def vacuum(self):
        """
        Rebuild the entire database: reduce size and defragment
        """
        self.__cur.execute('VACUUM')