import config
from app import create_app

app = create_app()

if __name__ == "__main__":
    if config.FlaskConfig.START_FLASK:
        app.run(host=config.ServerLocation.address, port=config.ServerLocation.port)
    else:
        print("START_FLASK env variable not set to True")
