from setuptools import setup

# Test case to ensure duplicate detection works correctly
# when same dependencies appear in both quoted and unquoted forms

setup(
    name='mixed-format-project',
    version='1.0.0',
    install_requires=[
        # Quoted dependencies (should be caught by pinnedDependency regex)
        "requests==2.31.0",
        "django==4.2.23",
    ] + """
requests==2.31.0
flask==3.0.0
""".split(),
)
