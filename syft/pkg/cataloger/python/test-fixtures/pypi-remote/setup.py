from setuptools import setup

# Sample setup.py from the pytest project with added comments specific
# to the cataloger

INSTALL_REQUIRES = [
    "certifi==2025.10.5",
]


def main():
    setup(
        use_scm_version={"write_to": "src/_pytest/_version.py"},
        setup_requires=["setuptools-scm", "setuptools>=40.0"],
        package_dir={"": "src"},
        extras_require={},
        install_requires=INSTALL_REQUIRES,
    )


if __name__ == "__main__":
    main()
