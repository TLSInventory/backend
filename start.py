import config
from app import create_app

app = create_app()


def main():
    print("Start.py - main")

    if config.FlaskConfig.START_FLASK:
        app.run(host=config.ServerLocation.address, port=config.ServerLocation.port)
        return
    
    print("START_FLASK env variable not set to True")


if __name__ == "__main__":
    # This path is not triggered when running from gunicorn
    main()
