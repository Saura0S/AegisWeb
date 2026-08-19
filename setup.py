from setuptools import setup, find_packages

setup(
    name="aegisweb",
    version="1.0.0",
    description="Enterprise Web Security Auditor & Dual-Report Engine",
    author="Saura0S",
    url="https://github.com/Saura0S/AegisWeb",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "aegisweb": ["templates/*.html"],
    },
    install_requires=[
        "requests>=2.31.0",
        "rich>=13.7.0",
        "jinja2>=3.1.3",
        "dnspython>=2.6.1",
        "urllib3>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "aegisweb=aegisweb.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)