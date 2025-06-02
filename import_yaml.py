import yaml
import os
 
class AppSettings(object):
    def __new__(cls):
        if not hasattr(cls, "_instance"):
            cls._instance = super(AppSettings, cls).__new__(cls)
        return cls._instance
 
    def __init__(self, config_path=None):
        if getattr(self, '_initialized', False):
            return
 
        if config_path is None:
            # Always look for app_settings.yaml in the same folder as app_settings.py
            current_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(current_dir, "app_settings.yaml")
 
        self._load_app_settings(config_path)
        self._initialized = True
 
    def _load_app_settings(self, config_path):
        # Load the YAML file
        with open(config_path, "r") as file:
            config_data = yaml.safe_load(file)
 
        # Load application settings
        app_settings = config_data.get("APP_SETTING", {})
        self.CLIENT_APP_PATH = app_settings.get("CLIENT_APP_PATH", "client_app")
        self.ALLOWED_HOSTS = app_settings.get("ALLOWED_HOSTS", "*")
        self.DEBUG = app_settings.get("DEBUG", False)
 
        # Load logging configuration
        logging_settings = config_data.get("LOGGING", {})
        self.ENABLE_ROTATING_LOG = logging_settings.get("ENABLED_ROTATING_LOG", True)
        self.ENABLE_CONSOLE_LOG = logging_settings.get("ENABLED_CONSOLE_LOG", True)
        self.LOG_PATH = logging_settings.get("LOG_PATH", "logs")
        self.LOG_FILE = logging_settings.get("LOG_FILE", "petal.log")
        self.LOG_LEVEL = logging_settings.get("LOG_LEVEL", "INFO")
        self.MAX_LOG_SIZE = logging_settings.get("MAX_LOG_SIZE", 100000)
        self.MAX_LOG_FILES = logging_settings.get("MAX_LOG_FILES", 5)
 
        # Load database configuration
        database_settings = config_data.get("DATABASE", {})
        self.DATABASE_SERVER = database_settings.get("SERVER", "postgresql")
        self.DATABASE_HOST = database_settings.get("HOST", "localhost")
        self.DATABASE_PORT = database_settings.get("POSTGRES_PORT", "5432")
        self.DATABASE_NAME = database_settings.get("DATABASE_NAME", "petal_db")
        self.DATABASE_USER = database_settings.get("USERNAME", "postgres")
        self.DATABASE_PASSWORD = database_settings.get("PASSWORD", "root")
 
        # API KEY for the schedular service
        apikey_setting = config_data.get("APIKEY", {})
        self.SERVICE_API_KEY = apikey_setting.get("SERVICE_API_KEY", None)
        self.OPENAI_API_KEY = apikey_setting.get("OPENAI_API_KEY", None)
 
        #API KEY for the OpenAI model
        apikey_setting = config_data.get("APIKEY", {})
        self.OPENAI_API_KEY= apikey_setting.get("OPENAI_API_KEY", None)
 
        # Load seed data files
        self.SEED_DATA_FILES = config_data.get("SEED_DATA_FILES", [])
 
        folder_config = config_data.get("FOLDER_CONFIG", {})
        self.UPLOAD_DIRECTORY = folder_config.get("UPLOAD_DIRECTORY", "upload_folder")
        self.DOWNLOAD_DIRECTORY = folder_config.get("DOWNLOAD_DIRECTORY", "download_folder")
        self.BASE_DOC_STORE_DIRECTORY = folder_config.get("BASE_DOC_STORE_DIRECTORY", "base_doc_store_directory")
 
    def get_database_url(self):
        return f"{self.DATABASE_SERVER}://{self.DATABASE_USER}:{self.DATABASE_PASSWORD}@{self.DATABASE_HOST}:{self.DATABASE_PORT}/{self.DATABASE_NAME}"