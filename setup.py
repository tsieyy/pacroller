import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pacroller",
    version="0.1.9",
    author="Jerry Xiao, tsieyy",
    author_email="tsieyy@qq.com",
    description="unattended upgrade for archlinux",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tsieyy/pacroller",
    packages=setuptools.find_packages('src'),
    package_dir={'': 'src'},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.12',
    entry_points={
        'console_scripts': [
            'pacroller=pacroller.main:main',
            'pacroller-analyze=pacroller.analyze:main'
        ]
    },
    install_requires=['pyalpm']
)
