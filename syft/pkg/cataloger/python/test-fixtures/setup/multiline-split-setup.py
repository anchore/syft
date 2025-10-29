from setuptools import setup

# Example setup.py using multiline string with .split() pattern
# This pattern is commonly seen in projects like mayan-edms

setup(
    name='example-project',
    version='1.0.0',
    install_requires="""
django==4.2.23
CairoSVG==2.7.1
Pillow==11.0.0
requests==2.31.0
celery==5.3.4
""".split(),
    extras_require={
        'dev': """
pytest==7.4.3
black==23.12.1
mypy==1.7.1
""".split(),
    },
)
