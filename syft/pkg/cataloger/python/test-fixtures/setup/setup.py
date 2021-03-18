from setuptools import setup

# Sample setup.py from the pytest project with added comments specific
# to the cataloger

INSTALL_REQUIRES = [
    "py>=1.5.0",
    "packaging",
    "attrs>=17.4.0",
    "more-itertools>=4.0.0",
    'atomicwrites>=1.0;sys_platform=="win32"',  # sys_platform is ignored
    'pathlib2>=2.2.0;python_version=="3.6"',  # python_version is ignored
    'pathlib3==2.2.0;python_version<"3.6"',  # this is caught
    'colorama;sys_platform=="win32"',
    "pluggy>=0.12,<1.0",
    'importlib-metadata>=0.12;python_version<"3.8"',
    "wcwidth",
]


def main():
    setup(
        use_scm_version={"write_to": "src/_pytest/_version.py"},
        setup_requires=["setuptools-scm", "setuptools>=40.0"],
        package_dir={"": "src"},
        extras_require={
            "testing": [
                "argcomplete",
                "hypothesis>=3.56",
                "mock",
                "nose",
                "requests",
                "xmlschema",
            ],
            "checkqa-mypy": [
                "mypy==v0.770",  # this is caught
                " mypy1==v0.770",  # this is caught
                " mypy2 == v0.770", ' mypy3== v0.770',  # this is caught
            ],
        },
        install_requires=INSTALL_REQUIRES,
    )


if __name__ == "__main__":
    main()
