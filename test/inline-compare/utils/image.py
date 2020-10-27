import os


def clean(image: str) -> str:
    return os.path.basename(image.replace(":", "_"))
