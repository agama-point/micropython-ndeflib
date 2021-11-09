import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="micropython-ndeflib",
    version="0.0.2",
    author="Petr Kracik",
    author_email="petrkr@petrkr.net",
    description="NDEF library for MicroPython based on NDEF library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/agama-point/micropython-ndeflib",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
    ],
    python_requires='>=3.4'
)
