import os

#os.environ["POSTGRES_HOST"]="localhost"
#os.environ["POSTGRES_PASSWORD"]="573045"
#os.environ["SERVER_ADDRESS"] = "localhost:8000"
#os.environ["SERVER_PORT"]="8000"
#os.environ["POSTGRES_DATABASE"]="postgres"
#os.environ["POSTGRES_USERNAME"]="postgres"
#os.environ["POSTGRES_PORT"]="5432"


class Environment:
    def __init__(self):
        self.env_values = {
            "SERVER_ADDRESS": None,
            "SERVER_PORT": None,
            "POSTGRES_USERNAME": None,
            "POSTGRES_HOST": None,
            "POSTGRES_PORT": None,
            "POSTGRES_DATABASE": None,
            "POSTGRES_PASSWORD": None,
        }
        for i in self.env_values.keys():
            self.env_values[i]=str(os.environ[i])


    def __repr__(self):
        return self.env_values

    @classmethod
    def set_postgress_conn(cls, arg):
        os.environ["POSTGRES_CONN"] = arg

    @classmethod
    def set_server_adress(cls, arg):
        os.environ["SERVER_PORT"] = arg.split(":")[1]
        os.environ["SERVER_ADDRESS"] = arg

    @classmethod
    def set_server_port(cls, arg):
        os.environ["SERVER_PORT"] = str(arg)

    @classmethod
    def set_postgres_username(cls, arg):
        os.environ["POSTGRES_USERNAME"] = arg

    @classmethod
    def set_postgres_password(cls, arg):
        os.environ["POSTGRES_PASSWORD"] = arg

    @classmethod
    def set_postgres_host(cls, arg):
        os.environ["POSTGRES_HOST"] = arg

    @classmethod
    def set_postgres_port(cls, arg):
        os.environ["POSTGRES_PORT"] = str(arg)

    @classmethod
    def set_postgres_database(cls, arg):
        os.environ["POSTGRES_DATABASE"] = arg


    """def set_postgresql_url(self, url):
        pattern = r'^postgres:\/\/(?P<username>[^:]+):(?P<password>[^@]+)@(?P<host>[^:\/]+):(?P<port>\d+)\/(?P<dbname>.+)$'
        match = re.match(pattern, url)
        if match:
            dct = match.groupdict()
            os.environ["POSTGRES_USERNAME"] = dct["username"]
            os.environ["POSTGRES_PASSWORD"] = dct["password"]
            os.environ["POSTGRES_HOST"] = dct["host"]
            os.environ["POSTGRES_PORT"] = dct["port"]
            os.environ["POSTGRES_DATABASE"] = dct["dbname"]
        else:
            return "No PSQL URL"


    def set_jdbc_url(self, url):
        pattern = r'^jdbc:postgresql:\/\/(?P<host>[^:]+):(?P<port>\d+)\/(?P<dbname>.+)$'
        match = re.match(pattern, url)
        if match:
            dct = match.groupdict()
            os.environ["POSTGRES_HOST"] = dct["host"]
            os.environ["POSTGRES_PORT"] = dct["port"]
            os.environ["POSTGRES_DATABASE"] = dct["dbname"]
        else:
            raise ValueError("Invalid JDBC URL format")


def get_postgres_conn():
    return os.getenv("POSTGRES_CONN")


def get_server_adress():
    return os.getenv("SERVER_ADDRESS")


def get_server_port():
    return os.getenv("SERVER_PORT")


def get_postgres_jdbc_url():
    return os.getenv("POSTGRES_JDBC_URL")


def get_postgres_username():
    return os.getenv("POSTGRES_USERNAME")


def get_postgres_password():
    return os.getenv("POSTGRES_PASSWORD")


def get_posgres_host():
    return os.getenv("POSTGRES_HOST")


def get_posgres_port():
    return os.getenv("POSTGRES_PORT")


def get_posgres_db():
    return os.getenv("POSTGRES_DATABASE")"""





