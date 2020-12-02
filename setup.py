import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pypefilter",
    version="0.0.3",
    author="Simone Aonzo",
    author_email="simone.aonzo@gmail.com",
    description="PyPEfilter filters out non-native Portable Executable",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/packmad/pypefilter",
    packages=setuptools.find_packages(),
    entry_points = {'console_scripts': ['pypefilter = pypefilter.pypefilter:main']},
    install_requires=['python-magic'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
