import common
from exception import OssecAPIException
from os.path import isfile
from pymongo import MongoClient

class Connection:
    """
    Represents a connection against a database
    """

    def __init__(self, db_path=common.database_path, collection=common.global_db):
        """
        Constructor
        """
        self.db_path = db_path
        self.collection = collection

        self.__mc = MongoClient(self.db_path)
        if collection in self.__mc:
            self.__db = self.__mc[self.collection]
        else:
            self.__db = None            

    def getdb(self):
        return self.__db

    def vacuum(self):
        """
        Rebuild the entire database: reduce size and defragment
        """
        self.__db.command('compact', self.__db.name)