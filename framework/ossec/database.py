import common
from exception import OssecAPIException
from os.path import isfile
from pymongo import MongoClient

class Connection:
    """
    Represents a connection against a database
    """

    def __init__(self, db_path=common.database_path, database=None):
        """
        Constructor
        """
        self.db_path = db_path
        self.database = database

        self.__mc = MongoClient(self.db_path)
        if database in self.getDbsName():
            self.__db = self.__mc[self.database]
        else:
            self.__db = None

    def connect(self, database):
        self.database = database
        if database in self.getDbsName():
            self.__db = self.__mc[self.database]
        else:
            self.__db = None

    def getCol(self, collection):
        if self.__db == None:
            return None
        else:
            if collection in self.__db.collection_names():
                return self.__db[collection]
            else:
                return None

    def getDbsName(self):
        return self.__mc.list_database_names()

    def getDb(self):
        return self.__db

    def vacuum(self):
        """
        Rebuild the entire database: reduce size and defragment
        """
        self.__db.command('compact', self.__db.name)